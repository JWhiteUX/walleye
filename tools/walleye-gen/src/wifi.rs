//! 802.11 monitor-mode scenarios `wifi` and `wifi_benign` (CONTRACTS §11.1).
//!
//! The capture is what a multi-radio monitor (WiFi Coconut style) hears on
//! channels 1, 6 and 11: radiotap (TSFT, Flags with FCS, Rate, Channel, dBm
//! signal) + 802.11 frames with a correct FCS. Six APs (a 3-node mesh sharing
//! one SSID and security, a WPA3 AP, a WPA2 AP and an open guest network) and
//! 25 clients (every other one with a randomized MAC) probe, authenticate
//! (open system or SAE), associate, run EAPOL 4-way handshakes, exchange
//! protected data and power-save nulls, roam within the mesh, and leave now
//! and then with a normal deauth/disassoc (reason 3/8). Clients of the open
//! network send DNS and HTTP in the clear (LLC/SNAP), so flows exist.
//!
//! `wifi` adds three labelled attacks, each from its own locally
//! administered MAC: a deauth flood claiming the WPA2 AP's BSSID, an open
//! evil twin of that AP on another channel (one kicked client joins it and
//! browses), and a karma AP answering directed probes for any SSID.
//!
//! Frames are generated per actor, sorted by time, then given per-transmitter
//! sequence numbers and FCS. Same seed → byte-identical output.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};

use crate::dns::{self, RData, Rr};
use crate::flow::{Chunk, Close, Msg, TcpFlow, TcpSpec};
use crate::http::{self, Request, Response};
use crate::net::{self, Hop, Mac};
use crate::pcap::PcapWriter;
use crate::rng::Rng;
use crate::scenario::{Labels, Options, Scenario, Summary};

pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
/// Longest capture the Wi-Fi scenarios produce (beacons alone are ~60/s).
pub const MAX_MINUTES: u64 = 30;

const S: i64 = 1_000_000;
const MS: i64 = 1_000;
const TU: i64 = 1_024;
const BEACON_INTERVAL: i64 = 100 * TU;
const BC: Mac = [0xff; 6];

/// Minimum attack volume for a label (CONTRACTS §11.1).
pub const MIN_DEAUTHS_2MIN: usize = 300;
pub const MIN_KARMA_SSIDS: usize = 10;
pub const MIN_TWIN_BEACONS: usize = 10;

const MESH_SSID: &str = "Walleye-Mesh";
pub const TWIN_SSID: &str = "Lighthouse";
const GUEST_SSID: &str = "Dockside-Guest";

/// Networks clients remember (directed probes; karma bait).
const PNL_POOL: &[&str] = &[
    "Airport_Free_WiFi",
    "Hotel-Lobby",
    "CafeNet",
    "Home-2.4G",
    "Office-Corp",
    "Library-Public",
    "Gym-Members",
    "Train-WiFi",
    "Conference-2026",
    "Grandma-House",
    "Studio-5G",
    "Lakeside-Cabin",
    "Metro-Hotspot",
    "Clinic-Guest",
    "Bookshop",
    "Coworking-Hub",
];

/// Hosts the open-network clients browse (documentation names / TEST-NETs).
const SITES: &[(&str, [u8; 4])] = &[
    ("www.example.com", [203, 0, 113, 10]),
    ("news.example.org", [203, 0, 113, 21]),
    ("weather.example.net", [198, 51, 100, 7]),
    ("shop.example.com", [198, 51, 100, 30]),
    ("maps.example.org", [203, 0, 113, 44]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sec {
    Open,
    Wpa2,
    Wpa3,
    Wpa2Wpa3,
}

impl Sec {
    fn pmf_required(self) -> bool {
        self == Sec::Wpa3
    }
}

#[derive(Debug, Clone)]
struct Ap {
    bssid: Mac,
    ssid: String,
    chan: u8,
    sec: Sec,
    signal: i8,
    boot: i64,
    /// Beacons and responses only in `[up, down)`.
    up: i64,
    down: i64,
    /// Answers directed probes for any SSID (karma).
    karma: bool,
    /// Router/gateway behind the AP (DA/SA of client traffic).
    gw: Mac,
    gw_ip: Ipv4Addr,
    net: [u8; 3],
}

#[derive(Debug, Clone)]
struct Client {
    mac: Mac,
    home: usize,
    pnl: Vec<String>,
    signal: i8,
    ip_host: u8,
}

/// One 802.11 frame before sequence numbers and FCS.
struct Frame {
    ts: i64,
    ord: u64,
    chan: u8,
    signal: i8,
    rate: u8,
    bytes: Vec<u8>,
    /// Transmitter whose sequence counter numbers this frame.
    seq_tx: Option<Mac>,
}

struct Probe {
    ts: i64,
    client: usize,
    chan: u8,
    ssid: Option<String>,
}

struct Gen {
    frames: Vec<Frame>,
    ord: u64,
    rng: Rng,
    start: i64,
    end: i64,
    pn: u64,
    probes: Vec<Probe>,
}

fn freq(chan: u8) -> u16 {
    2407 + 5 * u16::from(chan)
}

fn is_unicast(m: &Mac) -> bool {
    m[0] & 1 == 0
}

fn hdr(fc0: u8, fc1: u8, a1: Mac, a2: Mac, a3: Mac) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&[fc0, fc1, 0, 0]);
    v.extend_from_slice(&a1);
    v.extend_from_slice(&a2);
    v.extend_from_slice(&a3);
    v.extend_from_slice(&[0, 0]); // sequence control, filled in later
    v
}

fn ie(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.push(id);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

const RATES: [u8; 8] = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
const EXT_RATES: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];

/// RSN element body: CCMP group/pairwise, the given AKMs, RSN capabilities.
fn rsn(akms: &[u8], caps: u16) -> Vec<u8> {
    let mut r = vec![1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4];
    r.extend_from_slice(&(akms.len() as u16).to_le_bytes());
    for &a in akms {
        r.extend_from_slice(&[0x00, 0x0f, 0xac, a]);
    }
    r.extend_from_slice(&caps.to_le_bytes());
    r
}

fn ap_rsn(sec: Sec) -> Option<Vec<u8>> {
    match sec {
        Sec::Open => None,
        Sec::Wpa2 => Some(rsn(&[2], 0x0000)),
        Sec::Wpa3 => Some(rsn(&[8], 0x00c0)),
        Sec::Wpa2Wpa3 => Some(rsn(&[2, 8], 0x0080)),
    }
}

/// What a client puts in its (re)association request / EAPOL message 2.
fn client_rsn(sec: Sec) -> Option<Vec<u8>> {
    match sec {
        Sec::Open => None,
        Sec::Wpa2 | Sec::Wpa2Wpa3 => Some(rsn(&[2], 0x0000)),
        Sec::Wpa3 => Some(rsn(&[8], 0x00c0)),
    }
}

fn capability(sec: Sec) -> u16 {
    // ESS, short preamble, short slot time, Privacy when secured.
    0x0001 | 0x0020 | 0x0400 | if sec == Sec::Open { 0 } else { 0x0010 }
}

fn bss_body(ap: &Ap, ts: i64, ssid: &str, beacon: bool, dtim: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(&((ts - ap.boot).max(0) as u64).to_le_bytes());
    b.extend_from_slice(&100u16.to_le_bytes());
    b.extend_from_slice(&capability(ap.sec).to_le_bytes());
    ie(&mut b, 0, ssid.as_bytes());
    ie(&mut b, 1, &RATES);
    ie(&mut b, 3, &[ap.chan]);
    if beacon {
        ie(&mut b, 5, &[dtim, 3, 0, 0]);
    }
    ie(&mut b, 42, &[0]);
    ie(&mut b, 50, &EXT_RATES);
    if let Some(r) = ap_rsn(ap.sec) {
        ie(&mut b, 48, &r);
    }
    b
}

/// CRC-32 (IEEE 802.3), as used by the 802.11 FCS.
fn crc32(data: &[u8], table: &[u32; 256]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, e) in t.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *e = c;
    }
    t
}

/// Radiotap header: TSFT, Flags (FCS at end), Rate, Channel, dBm signal.
fn radiotap(out: &mut Vec<u8>, tsft: u64, rate: u8, chan: u8, signal: i8) {
    out.extend_from_slice(&[0, 0, 23, 0]);
    out.extend_from_slice(&0x0000_002fu32.to_le_bytes());
    out.extend_from_slice(&tsft.to_le_bytes()); // 8, 8-aligned
    out.push(0x10); // 16: Flags = FCS at end
    out.push(rate); // 17
    out.extend_from_slice(&freq(chan).to_le_bytes()); // 18
    // 2 GHz + CCK for 1-11 Mb/s, 2 GHz + OFDM otherwise.
    let cflags: u16 = if matches!(rate, 2 | 4 | 11 | 22) {
        0x00a0
    } else {
        0x00c0
    };
    out.extend_from_slice(&cflags.to_le_bytes());
    out.push(signal as u8); // 22
}

impl Gen {
    fn jitter(&mut self, base: i8) -> i8 {
        (i64::from(base) + self.rng.range(0, 6) as i64 - 3).clamp(-95, -20) as i8
    }

    fn push(
        &mut self,
        ts: i64,
        chan: u8,
        signal: i8,
        rate: u8,
        bytes: Vec<u8>,
        seq_tx: Option<Mac>,
    ) {
        if ts < self.start || ts >= self.end {
            return;
        }
        self.ord += 1;
        let signal = self.jitter(signal);
        self.frames.push(Frame {
            ts,
            ord: self.ord,
            chan,
            signal,
            rate,
            bytes,
            seq_tx,
        });
    }

    /// ACK from the receiver of a unicast frame.
    fn ack(&mut self, ts: i64, chan: u8, signal: i8, ra: Mac) {
        let mut v = vec![0xd4, 0x00, 0, 0];
        v.extend_from_slice(&ra);
        let gap = 40 + self.rng.range(0, 200) as i64;
        self.push(ts + gap, chan, signal, 0x0c, v, None);
    }

    /// Management frame (A1 = DA, A2 = SA, A3 = BSSID), ACKed when unicast.
    #[allow(clippy::too_many_arguments)]
    fn mgmt(
        &mut self,
        ts: i64,
        chan: u8,
        signal: i8,
        ack_signal: i8,
        subtype: u8,
        protected: bool,
        a1: Mac,
        a2: Mac,
        a3: Mac,
        body: &[u8],
    ) {
        let mut v = hdr(subtype << 4, if protected { 0x40 } else { 0 }, a1, a2, a3);
        if protected {
            self.ccmp(&mut v, body.len());
        } else {
            v.extend_from_slice(body);
        }
        self.push(ts, chan, signal, 0x02, v, Some(a2));
        if is_unicast(&a1) {
            self.ack(ts, chan, ack_signal, a2);
        }
    }

    /// CCMP header + `n` bytes of ciphertext + 8-byte MIC.
    fn ccmp(&mut self, v: &mut Vec<u8>, n: usize) {
        self.pn += 1 + self.rng.below(3);
        let p = self.pn.to_le_bytes();
        v.extend_from_slice(&[p[0], p[1], 0, 0x20, p[2], p[3], p[4], p[5]]);
        let ct = self.rng.vec(n + 8);
        v.extend_from_slice(&ct);
    }

    /// QoS data frame between `sta` and `ap` (`up` = ToDS).
    #[allow(clippy::too_many_arguments)]
    fn data(
        &mut self,
        ts: i64,
        ap: &Ap,
        sta: Mac,
        sta_signal: i8,
        up: bool,
        far: Mac,
        tid: u8,
        payload: Payload<'_>,
    ) {
        let protected = matches!(payload, Payload::Encrypted(_));
        let fl = (if up { 0x01 } else { 0x02 }) | if protected { 0x40 } else { 0 };
        let mut v = if up {
            hdr(0x88, fl, ap.bssid, sta, far)
        } else {
            hdr(0x88, fl, sta, ap.bssid, far)
        };
        v.extend_from_slice(&[tid, 0]);
        match payload {
            Payload::Encrypted(n) => self.ccmp(&mut v, n),
            Payload::Snap(et, p) => {
                v.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0]);
                v.extend_from_slice(&et.to_be_bytes());
                v.extend_from_slice(p);
            }
        }
        let (tx, sig, ack_sig) = if up {
            (sta, sta_signal, ap.signal)
        } else {
            (ap.bssid, ap.signal, sta_signal)
        };
        self.push(ts, ap.chan, sig, 0x30, v, Some(tx));
        self.ack(ts, ap.chan, ack_sig, tx);
    }

    fn null(&mut self, ts: i64, ap: &Ap, c: &Client, sleep: bool) {
        let fl = 0x01 | if sleep { 0x10 } else { 0 };
        let v = hdr(0x48, fl, ap.bssid, c.mac, ap.bssid);
        self.push(ts, ap.chan, c.signal, 0x30, v, Some(c.mac));
        self.ack(ts, ap.chan, ap.signal, c.mac);
    }
}

enum Payload<'a> {
    Encrypted(usize),
    Snap(u16, &'a [u8]),
}

/// EAPOL-Key frame (802.1X-2004, RSN descriptor, HMAC-SHA1/AES).
fn eapol_key(
    rng: &mut Rng,
    msg: u8,
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    rsn_ie: &[u8],
) -> Vec<u8> {
    let (info, key_len, replay, nonce, mic, data): (u16, u16, u64, [u8; 32], bool, Vec<u8>) =
        match msg {
            1 => (0x008a, 16, 1, *anonce, false, Vec::new()),
            2 => {
                let mut d = vec![48, rsn_ie.len() as u8];
                d.extend_from_slice(rsn_ie);
                (0x010a, 0, 1, *snonce, true, d)
            }
            3 => (0x13ca, 16, 2, *anonce, true, rng.vec(56)),
            _ => (0x030a, 0, 2, [0; 32], true, Vec::new()),
        };
    let mut k = Vec::with_capacity(99 + data.len());
    k.push(2); // descriptor type: RSN
    k.extend_from_slice(&info.to_be_bytes());
    k.extend_from_slice(&key_len.to_be_bytes());
    k.extend_from_slice(&replay.to_be_bytes());
    k.extend_from_slice(&nonce);
    k.extend_from_slice(&[0; 16]); // IV
    k.extend_from_slice(&[0; 8]); // RSC
    k.extend_from_slice(&[0; 8]); // ID
    if mic {
        k.extend_from_slice(&rng.bytes::<16>());
    } else {
        k.extend_from_slice(&[0; 16]);
    }
    k.extend_from_slice(&(data.len() as u16).to_be_bytes());
    k.extend_from_slice(&data);
    let mut e = vec![2, 3];
    e.extend_from_slice(&(k.len() as u16).to_be_bytes());
    e.extend_from_slice(&k);
    e
}

struct World {
    aps: Vec<Ap>,
    clients: Vec<Client>,
    attack: bool,
    flood_start: i64,
    flood_end: i64,
    twin: Option<usize>,
    karma: Option<usize>,
    lighthouse: usize,
    deauther: Mac,
    deauth_times: Vec<i64>,
    karma_ssids: BTreeSet<String>,
}

fn mac_with(rng: &mut Rng, oui: [u8; 3]) -> Mac {
    let t: [u8; 3] = rng.bytes();
    [oui[0], oui[1], oui[2], t[0], t[1], t[2]]
}

/// Locally administered, unicast.
fn random_mac(rng: &mut Rng) -> Mac {
    let mut m: Mac = rng.bytes();
    m[0] = (m[0] & 0xfc) | 0x02;
    m
}

fn mac_text(m: &Mac) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn build_world(opts: &Options, rng: &mut Rng, start: i64, end: i64) -> World {
    let attack = opts.scenario == Scenario::Wifi;
    let dur = end - start;
    let mk_ap = |rng: &mut Rng, oui, ssid: &str, chan, sec, signal, net: [u8; 3]| Ap {
        bssid: mac_with(rng, oui),
        ssid: ssid.to_string(),
        chan,
        sec,
        signal,
        boot: start - (3600 + rng.below(20 * 86_400) as i64) * S,
        up: start,
        down: i64::MAX,
        karma: false,
        gw: mac_with(rng, [0x00, 0x0d, 0xb9]),
        gw_ip: Ipv4Addr::new(net[0], net[1], net[2], 1),
        net,
    };
    let mesh_oui = [0x9c, 0x3d, 0xcf];
    let mut aps = vec![
        mk_ap(rng, mesh_oui, MESH_SSID, 1, Sec::Wpa2Wpa3, -48, [10, 20, 0]),
        mk_ap(rng, mesh_oui, MESH_SSID, 6, Sec::Wpa2Wpa3, -61, [10, 20, 0]),
        mk_ap(
            rng,
            mesh_oui,
            MESH_SSID,
            11,
            Sec::Wpa2Wpa3,
            -70,
            [10, 20, 0],
        ),
        mk_ap(
            rng,
            [0x00, 0x1a, 0x2b],
            "Harbor-5",
            6,
            Sec::Wpa3,
            -55,
            [10, 30, 0],
        ),
        mk_ap(
            rng,
            [0x00, 0x24, 0xa5],
            TWIN_SSID,
            11,
            Sec::Wpa2,
            -52,
            [10, 40, 0],
        ),
        mk_ap(
            rng,
            [0x00, 0x18, 0x0a],
            GUEST_SSID,
            1,
            Sec::Open,
            -58,
            [192, 168, 50],
        ),
    ];
    // The mesh shares one gateway.
    let mesh_gw = aps[0].gw;
    aps[1].gw = mesh_gw;
    aps[2].gw = mesh_gw;
    let lighthouse = 4;
    let guest = 5;

    // 25 clients: 10 mesh, 5 Harbor-5, 5 Lighthouse, 5 guest; odd = randomized.
    let homes: Vec<usize> = (0..25)
        .map(|i| match i % 5 {
            0 | 1 => (i / 5) % 3,
            2 => 3,
            3 => lighthouse,
            _ => guest,
        })
        .collect();
    let ouis = [
        [0xf0, 0x18, 0x98],
        [0x3c, 0x22, 0xfb],
        [0xa4, 0x83, 0xe7],
        [0x00, 0x21, 0x6a],
    ];
    let mut clients = Vec::new();
    for (i, &home) in homes.iter().enumerate() {
        let mac = if i % 2 == 1 {
            random_mac(rng)
        } else {
            let oui = *rng.pick(&ouis);
            mac_with(rng, oui)
        };
        let mut pnl = vec![aps[home].ssid.clone()];
        let n = 1 + rng.below(3) as usize;
        for _ in 0..n {
            let s = rng.pick(PNL_POOL).to_string();
            if !pnl.contains(&s) {
                pnl.push(s);
            }
        }
        clients.push(Client {
            mac,
            home,
            pnl,
            signal: -45 - rng.below(38) as i8,
            ip_host: 10 + i as u8,
        });
    }

    let flood_start = start + dur * 3 / 10;
    let flood_end = flood_start + 100 * S;
    let mut twin = None;
    let mut karma = None;
    let deauther = random_mac(rng);
    if attack {
        let mut t = mk_ap(rng, [0, 0, 0], TWIN_SSID, 1, Sec::Open, -41, [10, 66, 0]);
        t.bssid = random_mac(rng);
        t.gw = t.bssid;
        t.up = flood_start + 60 * S;
        twin = Some(aps.len());
        aps.push(t);
        let mut k = mk_ap(rng, [0, 0, 0], "", 6, Sec::Open, -44, [10, 77, 0]);
        k.bssid = random_mac(rng);
        k.up = start + dur * 2 / 10;
        k.karma = true;
        karma = Some(aps.len());
        aps.push(k);
    }
    World {
        aps,
        clients,
        attack,
        flood_start,
        flood_end,
        twin,
        karma,
        lighthouse,
        deauther,
        deauth_times: Vec::new(),
        karma_ssids: BTreeSet::new(),
    }
}

fn beacons(g: &mut Gen, ap: &Ap) {
    if ap.karma {
        return; // probe responses only
    }
    let mut t = ap.up.max(g.start) + g.rng.below(BEACON_INTERVAL as u64) as i64;
    let mut dtim = 0u8;
    while t < g.end.min(ap.down) {
        let body = bss_body(ap, t, &ap.ssid, true, dtim);
        dtim = (dtim + 2) % 3;
        g.mgmt(
            t, ap.chan, ap.signal, 0, 8, false, BC, ap.bssid, ap.bssid, &body,
        );
        t += BEACON_INTERVAL + g.rng.below(40) as i64;
    }
}

/// One scan: wildcard + directed probes on each channel.
fn scan(g: &mut Gen, ci: usize, c: &Client, mut t: i64, directed: &[String]) -> i64 {
    for chan in [1u8, 6, 11] {
        let mut ssids: Vec<Option<&str>> = vec![None];
        ssids.extend(directed.iter().map(|s| Some(s.as_str())));
        for s in ssids {
            let mut b = Vec::new();
            ie(&mut b, 0, s.unwrap_or("").as_bytes());
            ie(&mut b, 1, &RATES);
            ie(&mut b, 50, &EXT_RATES);
            g.mgmt(t, chan, c.signal, 0, 4, false, BC, c.mac, BC, &b);
            g.probes.push(Probe {
                ts: t,
                client: ci,
                chan,
                ssid: s.map(str::to_string),
            });
            t += 300 + g.rng.below(700) as i64;
        }
        t += 20 * MS;
    }
    t
}

/// Authentication, (re)association, EAPOL, Block Ack setup. Returns the time
/// the link is up.
fn connect(
    g: &mut Gen,
    ap: &Ap,
    c: &Client,
    mut t: i64,
    reassoc_from: Option<Mac>,
    aid: u16,
) -> i64 {
    let sae = ap.sec == Sec::Wpa3;
    let auth = |seq: u16, extra: &[u8]| {
        let mut b = Vec::new();
        b.extend_from_slice(&(if sae { 3u16 } else { 0 }).to_le_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(extra);
        b
    };
    if sae {
        for (seq, from_sta) in [(1u16, true), (1, false), (2, true), (2, false)] {
            let extra = if seq == 1 {
                let mut e = 19u16.to_le_bytes().to_vec();
                e.extend_from_slice(&g.rng.vec(96));
                e
            } else {
                let mut e = 1u16.to_le_bytes().to_vec();
                e.extend_from_slice(&g.rng.vec(32));
                e
            };
            let body = auth(seq, &extra);
            if from_sta {
                g.mgmt(
                    t, ap.chan, c.signal, ap.signal, 11, false, ap.bssid, c.mac, ap.bssid, &body,
                );
            } else {
                g.mgmt(
                    t, ap.chan, ap.signal, c.signal, 11, false, c.mac, ap.bssid, ap.bssid, &body,
                );
            }
            t += 2 * MS + g.rng.below(3000) as i64;
        }
    } else {
        let b = auth(1, &[]);
        g.mgmt(
            t, ap.chan, c.signal, ap.signal, 11, false, ap.bssid, c.mac, ap.bssid, &b,
        );
        t += MS + g.rng.below(2000) as i64;
        let b = auth(2, &[]);
        g.mgmt(
            t, ap.chan, ap.signal, c.signal, 11, false, c.mac, ap.bssid, ap.bssid, &b,
        );
        t += MS + g.rng.below(2000) as i64;
    }
    // (Re)association request / response.
    let mut req = Vec::new();
    req.extend_from_slice(&capability(ap.sec).to_le_bytes());
    req.extend_from_slice(&10u16.to_le_bytes());
    if let Some(prev) = reassoc_from {
        req.extend_from_slice(&prev);
    }
    ie(&mut req, 0, ap.ssid.as_bytes());
    ie(&mut req, 1, &RATES);
    ie(&mut req, 50, &EXT_RATES);
    if let Some(r) = client_rsn(ap.sec) {
        ie(&mut req, 48, &r);
    }
    let (rq, rs) = if reassoc_from.is_some() {
        (2, 3)
    } else {
        (0, 1)
    };
    g.mgmt(
        t, ap.chan, c.signal, ap.signal, rq, false, ap.bssid, c.mac, ap.bssid, &req,
    );
    t += MS + g.rng.below(3000) as i64;
    let mut resp = Vec::new();
    resp.extend_from_slice(&capability(ap.sec).to_le_bytes());
    resp.extend_from_slice(&0u16.to_le_bytes());
    resp.extend_from_slice(&(0xc000 | aid).to_le_bytes());
    ie(&mut resp, 1, &RATES);
    ie(&mut resp, 50, &EXT_RATES);
    g.mgmt(
        t, ap.chan, ap.signal, c.signal, rs, false, c.mac, ap.bssid, ap.bssid, &resp,
    );
    t += 2 * MS + g.rng.below(5000) as i64;
    // EAPOL 4-way handshake.
    if ap.sec != Sec::Open {
        let anonce: [u8; 32] = g.rng.bytes();
        let snonce: [u8; 32] = g.rng.bytes();
        let rsn_ie = client_rsn(ap.sec).unwrap_or_default();
        for msg in 1u8..=4 {
            let key = eapol_key(&mut g.rng, msg, &anonce, &snonce, &rsn_ie);
            let up = msg % 2 == 0;
            g.data(
                t,
                ap,
                c.mac,
                c.signal,
                up,
                ap.bssid,
                7,
                Payload::Snap(0x888e, &key),
            );
            t += 3 * MS + g.rng.below(6000) as i64;
        }
    }
    // Block Ack agreement (action frames), protected by PMF on WPA3.
    let token = (g.rng.below(255) + 1) as u8;
    let mut addba = vec![3, 0, token];
    addba.extend_from_slice(&0x1002u16.to_le_bytes());
    addba.extend_from_slice(&0u16.to_le_bytes());
    addba.extend_from_slice(&0u16.to_le_bytes());
    let pmf = ap.sec.pmf_required();
    g.mgmt(
        t, ap.chan, c.signal, ap.signal, 13, pmf, ap.bssid, c.mac, ap.bssid, &addba,
    );
    t += MS + g.rng.below(2000) as i64;
    let mut resp = vec![3, 1, token];
    resp.extend_from_slice(&0u16.to_le_bytes());
    resp.extend_from_slice(&0x1002u16.to_le_bytes());
    resp.extend_from_slice(&0u16.to_le_bytes());
    g.mgmt(
        t, ap.chan, ap.signal, c.signal, 13, pmf, c.mac, ap.bssid, ap.bssid, &resp,
    );
    t + MS
}

/// Clear-text browsing on an open network: DNS, then an HTTP GET.
fn browse(g: &mut Gen, ap: &Ap, c: &Client, t: i64) -> i64 {
    let (name, ip) = *g.rng.pick(SITES);
    let server = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
    let me = Ipv4Addr::new(ap.net[0], ap.net[1], ap.net[2], c.ip_host);
    let up = Hop {
        src_mac: c.mac,
        dst_mac: ap.gw,
        src: IpAddr::V4(me),
        dst: IpAddr::V4(ap.gw_ip),
        ttl: 64,
    };
    let id = g.rng.next_u16();
    let sport = 49152 + g.rng.below(16000) as u16;
    let mut buf = Vec::new();
    net::udp_frame(
        &mut buf,
        &up,
        id,
        sport,
        53,
        &dns::query(id, name, dns::TYPE_A, false),
    );
    let mut t = t;
    g.data(
        t,
        ap,
        c.mac,
        c.signal,
        true,
        ap.gw,
        0,
        Payload::Snap(0x0800, &buf[14..]),
    );
    t += 4 * MS + g.rng.below(20_000) as i64;
    let ans = [Rr {
        name: name.to_string(),
        ttl: 300,
        data: RData::A(server),
    }];
    let resp = dns::response(id, name, dns::TYPE_A, dns::RCODE_NOERROR, &ans, &[], false);
    net::udp_frame(&mut buf, &up.reverse(64), id, 53, sport, &resp);
    g.data(
        t,
        ap,
        c.mac,
        c.signal,
        false,
        ap.gw,
        0,
        Payload::Snap(0x0800, &buf[14..]),
    );
    t += 2 * MS;

    let c2s = Hop {
        dst: IpAddr::V4(server),
        ..up
    };
    let body = 400 + g.rng.below(6000);
    let uri = format!("/{}", g.rng.string(b"abcdefghijklmnopqrstuvwxyz", 6));
    let req = http::request_head(&Request {
        method: "GET",
        uri: &uri,
        host: name,
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
        extra: &[],
        body_len: 0,
    });
    let resp = http::response_head(&Response {
        status: 200,
        server: "nginx",
        content_type: "text/html",
        body_len: body,
        date_us: t,
        extra: &[],
    });
    let spec = TcpSpec {
        c2s,
        s2c: c2s.reverse(56),
        cport: sport.wrapping_add(1).max(1024),
        sport: 80,
        start_us: t,
        rtt_us: 20_000 + g.rng.below(30_000),
        seg_gap_us: 300,
        msgs: vec![
            Msg::client(1_000, vec![Chunk::Bytes(req)]),
            Msg::server(5_000, vec![Chunk::Bytes(resp), Chunk::Random(body)]),
        ],
        close: Close::ClientFin,
        close_delay_us: 200_000,
    };
    let mut flow = TcpFlow::new(spec, g.rng.fork());
    let mut last = t;
    while flow.peek().is_some() {
        let ts = flow.emit(&mut buf);
        let up = buf.get(6..12) == Some(&c.mac[..]);
        if buf.len() > 14 {
            g.data(
                ts,
                ap,
                c.mac,
                c.signal,
                up,
                ap.gw,
                0,
                Payload::Snap(0x0800, &buf[14..]),
            );
        }
        last = ts;
    }
    last
}

/// A client's whole capture: scan, connect, traffic, departures, roaming.
fn client_life(g: &mut Gen, w: &mut World, ci: usize) {
    let c = w.clients[ci].clone();
    let dur = g.end - g.start;
    let mut t = g.start + g.rng.below((60 * S).min(dur / 4).max(1) as u64) as i64;
    if g.rng.chance(0.2) {
        t += g.rng.below((dur / 2).max(1) as u64) as i64;
    }
    // Normal departures (1-3 over the capture).
    let mut departs: Vec<i64> = (0..1 + g.rng.below(3))
        .map(|_| g.start + g.rng.below(dur.max(1) as u64) as i64)
        .collect();
    departs.sort_unstable();
    let kicked = w.attack && c.home == w.lighthouse;
    let goes_to_twin = kicked && w.twin.is_some() && ci == 3;
    let mut ap_i = c.home;
    let mut prev_bssid: Option<Mac> = None;
    let mut aid = 1 + ci as u16;
    let mut next_depart = departs.into_iter().peekable();
    while t < g.end {
        let mut directed = c.pnl.clone();
        if goes_to_twin && ap_i == w.twin.unwrap_or(0) {
            directed = vec![TWIN_SSID.to_string()];
        }
        t = scan(g, ci, &c, t, &directed);
        let ap = w.aps[ap_i].clone();
        t = connect(
            g,
            &ap,
            &c,
            t + 5 * MS,
            prev_bssid.filter(|b| *b != ap.bssid),
            aid,
        );
        aid = aid % 2000 + 1;
        prev_bssid = Some(ap.bssid);
        // Online until the next departure, the flood or the end.
        while next_depart.peek().is_some_and(|&d| d <= t) {
            next_depart.next();
        }
        let flood_hit = kicked && ap_i == c.home && t < w.flood_start;
        let mut until = next_depart.peek().copied().unwrap_or(g.end);
        if flood_hit {
            until = until.min(w.flood_start + 2 * S);
        }
        let mut next_scan = t + 60 * S + g.rng.below((120 * S) as u64) as i64;
        let mut next_null = t + g.rng.below((40 * S) as u64) as i64;
        while t < until {
            if ap.sec == Sec::Open {
                t = browse(g, &ap, &c, t) + (g.rng.exp(15.0) * S as f64) as i64 + S;
            } else {
                let n = 2 + g.rng.below(7);
                for k in 0..n {
                    let up = k % 2 == 0;
                    let len = if up {
                        60 + g.rng.below(400)
                    } else {
                        100 + g.rng.below(1400)
                    } as usize;
                    g.data(
                        t,
                        &ap,
                        c.mac,
                        c.signal,
                        up,
                        ap.gw,
                        0,
                        Payload::Encrypted(len),
                    );
                    t += 400 + g.rng.below(3000) as i64;
                }
                t += (g.rng.exp(4.0) * S as f64) as i64 + 50 * MS;
            }
            if t >= next_null && t < until {
                g.null(t, &ap, &c, true);
                let wake = t + 100 * MS + g.rng.below(400_000) as i64;
                g.null(wake, &ap, &c, false);
                next_null = t + (20 + g.rng.below(60) as i64) * S;
                t += 600 * MS;
            }
            if t >= next_scan && t < until {
                // Background scan while associated.
                let pnl = c.pnl.clone();
                t = scan(g, ci, &c, t, &pnl);
                next_scan = t + (60 + g.rng.below(180) as i64) * S;
            }
        }
        if t >= g.end {
            break;
        }
        if flood_hit {
            // Kicked by the flood: silent until it stops, then reconnect
            // (the victim the twin lures joins the twin instead).
            t = w.flood_end + S + g.rng.below((4 * S) as u64) as i64;
            if goes_to_twin {
                ap_i = w.twin.unwrap_or(ap_i);
                t = t.max(w.aps[ap_i].up + 5 * S);
            }
            prev_bssid = None;
            continue;
        }
        next_depart.next();
        // Leave: deauth reason 3 or disassoc reason 8 (protected with PMF).
        let (sub, reason) = if g.rng.chance(0.5) {
            (12u8, 3u16)
        } else {
            (10, 8)
        };
        g.mgmt(
            t,
            ap.chan,
            c.signal,
            ap.signal,
            sub,
            ap.sec.pmf_required(),
            ap.bssid,
            c.mac,
            ap.bssid,
            &reason.to_le_bytes(),
        );
        t += (5 + g.rng.below(55) as i64) * S;
        // Mesh clients come back to another node (reassociation).
        if c.home < 3 {
            ap_i = (ap_i + 1) % 3;
        } else {
            prev_bssid = None;
        }
    }
}

/// Probe responses from real APs, the evil twin and the karma AP.
fn answer_probes(g: &mut Gen, w: &mut World) {
    let probes = std::mem::take(&mut g.probes);
    for p in &probes {
        let c = w.clients[p.client].clone();
        for ai in 0..w.aps.len() {
            let ap = w.aps[ai].clone();
            if ap.chan != p.chan || p.ts < ap.up || p.ts >= ap.down {
                continue;
            }
            let ssid = match (&p.ssid, ap.karma) {
                (Some(s), true) => s.clone(),
                (None, true) => continue,
                (Some(s), false) if *s == ap.ssid => s.clone(),
                (Some(_), false) => continue,
                (None, false) => ap.ssid.clone(),
            };
            let delay = if ap.karma {
                300 + g.rng.below(900) as i64
            } else {
                MS + g.rng.below(4000) as i64
            };
            let t = p.ts + delay;
            if ap.karma && t < g.end {
                w.karma_ssids.insert(ssid.clone());
            }
            let body = bss_body(&ap, t, &ssid, false, 0);
            g.mgmt(
                t, ap.chan, ap.signal, c.signal, 5, false, c.mac, ap.bssid, ap.bssid, &body,
            );
        }
    }
}

/// Deauth flood claiming Lighthouse's BSSID: broadcast and unicast to each
/// of its clients, every 250 ms for 100 s, reason 7.
fn deauth_flood(g: &mut Gen, w: &mut World) {
    let ap = w.aps[w.lighthouse].clone();
    let victims: Vec<Client> = w
        .clients
        .iter()
        .filter(|c| c.home == w.lighthouse)
        .cloned()
        .collect();
    let mut t = w.flood_start;
    let mut i = 0usize;
    while t < w.flood_end && t < g.end {
        let (a1, ack_sig) = if i % 2 == 0 || victims.is_empty() {
            (BC, 0)
        } else {
            let v = &victims[(i / 2) % victims.len()];
            (v.mac, v.signal)
        };
        g.mgmt(
            t,
            ap.chan,
            -38,
            ack_sig,
            12,
            false,
            a1,
            w.deauther,
            ap.bssid,
            &7u16.to_le_bytes(),
        );
        w.deauth_times.push(t);
        i += 1;
        t += 250 * MS + g.rng.below(2000) as i64;
    }
}

/// Most deauths inside any 120 s window.
fn max_in_window(times: &[i64], window: i64) -> usize {
    let mut best = 0;
    let mut lo = 0;
    for hi in 0..times.len() {
        while times[hi] - times[lo] > window {
            lo += 1;
        }
        best = best.max(hi - lo + 1);
    }
    best
}

/// Generate a Wi-Fi scenario starting at `start` (µs).
pub fn generate<W: Write>(opts: &Options, start: i64, out: W) -> io::Result<Summary> {
    let minutes = opts.duration_min.clamp(1, MAX_MINUTES) as i64;
    let end = start + minutes * 60 * S;
    let mut rng = Rng::new(opts.seed ^ 0x5749_4649); // "WIFI"
    let mut w = build_world(opts, &mut rng, start, end);
    let mut g = Gen {
        frames: Vec::new(),
        ord: 0,
        rng,
        start,
        end,
        pn: 0,
        probes: Vec::new(),
    };
    for ai in 0..w.aps.len() {
        let ap = w.aps[ai].clone();
        beacons(&mut g, &ap);
    }
    for ci in 0..w.clients.len() {
        client_life(&mut g, &mut w, ci);
    }
    if w.attack {
        deauth_flood(&mut g, &mut w);
    }
    answer_probes(&mut g, &mut w);

    g.frames.sort_by_key(|f| (f.ts, f.ord));
    let table = crc_table();
    let mut seqs: BTreeMap<Mac, u16> = BTreeMap::new();
    let mut writer = PcapWriter::with_link_type(out, LINKTYPE_IEEE802_11_RADIOTAP)?;
    let mut rec = Vec::with_capacity(4096);
    let mut twin_beacons = 0usize;
    let twin_bssid = w.twin.map(|i| w.aps[i].bssid);
    for f in &mut g.frames {
        if let Some(tx) = f.seq_tx {
            let s = seqs.entry(tx).or_insert(0);
            f.bytes[22..24].copy_from_slice(&(*s << 4).to_le_bytes());
            *s = (*s + 1) & 0x0fff;
            if Some(tx) == twin_bssid && f.bytes[0] == 0x80 {
                twin_beacons += 1;
            }
        }
        rec.clear();
        radiotap(&mut rec, (f.ts - start) as u64, f.rate, f.chan, f.signal);
        rec.extend_from_slice(&f.bytes);
        rec.extend_from_slice(&crc32(&f.bytes, &table).to_le_bytes());
        writer.write_packet(f.ts, &rec)?;
    }
    let (bytes, packets, sha256) = writer.finish()?;

    let mut c2 = Vec::new();
    let mut bad = BTreeSet::new();
    let mut evidence = Vec::new();
    if w.attack {
        let flood = max_in_window(&w.deauth_times, 120 * S);
        if flood >= MIN_DEAUTHS_2MIN {
            c2.push(mac_text(&w.deauther));
            bad.insert(TWIN_SSID.to_string());
            evidence.push(format!("deauth flood: {flood} deauths in 120 s"));
        } else {
            evidence.push(format!("deauth flood NOT labelled: only {flood} in 120 s"));
        }
        if let Some(b) = twin_bssid {
            if twin_beacons >= MIN_TWIN_BEACONS {
                c2.push(mac_text(&b));
                bad.insert(TWIN_SSID.to_string());
                evidence.push(format!("evil twin: {twin_beacons} open beacons"));
            } else {
                evidence.push(format!("evil twin NOT labelled: {twin_beacons} beacons"));
            }
        }
        if let Some(k) = w.karma {
            let n = w.karma_ssids.len();
            if n >= MIN_KARMA_SSIDS {
                c2.push(mac_text(&w.aps[k].bssid));
                bad.extend(w.karma_ssids.iter().cloned());
                evidence.push(format!("karma: probe responses for {n} SSIDs"));
            } else {
                evidence.push(format!("karma NOT labelled: only {n} SSIDs"));
            }
        }
    }
    let notes = if w.attack {
        format!(
            "802.11 radiotap, channels 1/6/11, {minutes} min: 6 APs (3-node {MESH_SSID} mesh wpa2/wpa3, Harbor-5 wpa3, {TWIN_SSID} wpa2, {GUEST_SSID} open with clear-text DNS/HTTP), 25 clients (odd ones randomized), normal deauth/disassoc reason 3/8. Attacks: deauth flood from a randomized MAC claiming {TWIN_SSID}'s BSSID (reason 7, broadcast + unicast, 4/s for 100 s, then victims re-handshake); open evil twin of {TWIN_SSID} on channel 1 from a randomized BSSID (one kicked client joins it and browses); karma AP on channel 6 answering directed probes. Emitted: {}.",
            evidence.join("; ")
        )
    } else {
        format!(
            "benign 802.11 radiotap, channels 1/6/11, {minutes} min: 6 APs (3-node {MESH_SSID} mesh sharing SSID and wpa2/wpa3, Harbor-5 wpa3, {TWIN_SSID} wpa2, {GUEST_SSID} open with clear-text DNS/HTTP), 25 clients (odd ones randomized) probing, associating, EAPOL handshakes, protected data, mesh roaming (reassociation), 1-3 normal deauth/disassoc (reason 3/8) per client. FP traps: mesh BSSIDs share one SSID; randomized probing clients."
        )
    };
    Ok(Summary {
        bytes,
        packets,
        sha256: sha256.clone(),
        labels: Labels {
            scenario: opts.scenario.name().to_string(),
            source: format!(
                "walleye-gen seed={} scenario={}",
                opts.seed,
                opts.scenario.name()
            ),
            sha256,
            c2_hosts: c2,
            bad_destinations: bad.into_iter().collect(),
            benign: !w.attack,
            notes,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789", &crc_table()), 0xcbf4_3926);
    }

    #[test]
    fn window_count() {
        assert_eq!(max_in_window(&[0, 1, 2, 100, 101], 10), 3);
        assert_eq!(max_in_window(&[], 10), 0);
    }
}
