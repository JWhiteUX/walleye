//! 802.11 detectors (CONTRACTS §11.3) on synthetic `wifi` row streams.
//!
//! The benign day is shaped after a real 38-minute WiFi Coconut capture: a
//! mesh sharing one SSID and security, a multi-band network, a multi-SSID
//! enterprise AP on sequential BSSIDs, hidden SSIDs, two neighbours with the
//! same factory-default SSID, randomized clients probing for remembered
//! networks, EAPOL handshakes, stations leaving with reason 3/8 a few times
//! an hour, and APs doing housekeeping (50–220 deauths with reason 6/7 over
//! the capture, partly in small clumps). The attacks are added on top:
//! a deauth flood (3,861 frames from a locally administered BSSID with
//! reasons 2/4, peaking ~335/min, then reconnect handshakes), a flood that
//! spoofs a real AP's BSSID, an open evil twin, and a karma AP.

mod common;

use std::collections::{BTreeMap, HashSet};

use common::{Rng, S, T0, repo_allowlist, repo_rules, summary};
use walleye_core::findings::EVIDENCE_CAP;
use walleye_core::sink::MemorySource;
use walleye_core::{Finding, WifiKind, WifiRow};
use walleye_detect::{finding_id, run};

const BCAST: &str = "ff:ff:ff:ff:ff:ff";
const MIN: i64 = 60 * S;
const SPAN: i64 = 38 * MIN;

const MESH: [(&str, u16); 3] = [
    ("e8:00:5e:00:53:88", 1),
    ("e8:00:5e:11:22:30", 6),
    ("e8:00:5e:44:55:60", 11),
];
const CORP_BANDS: [(&str, u16); 2] = [("3c:28:6d:10:20:30", 6), ("3e:28:6d:10:20:31", 36)];
const ENTERPRISE: [(&str, &str, &str); 6] = [
    ("00:1a:1e:aa:bb:c0", "Corp", "wpa2"),
    ("00:1a:1e:aa:bb:c1", "Corp-Guest", "open"),
    ("00:1a:1e:aa:bb:c2", "Corp-IoT", "wpa2"),
    ("00:1a:1e:aa:bb:c3", "Corp-Voice", "wpa2/wpa3"),
    ("00:1a:1e:aa:bb:c4", "Corp-Lab", "wpa3"),
    ("02:1a:1e:aa:bb:c5", "Corp-BYOD", "wpa2"),
];
const HIDDEN: [(&str, &str, u16); 2] = [
    ("9c:3d:cf:01:02:03", "wpa2", 6),
    ("a4:2b:b0:0a:0b:0c", "open", 1),
];
const CAFE: [&str; 2] = ["70:4f:57:00:00:01", "70:4f:57:00:00:02"];
const LINKSYS: [(&str, &str); 2] = [("58:6d:8f:01:01:01", "open"), ("20:aa:4b:02:02:02", "wpa2")];
const HOUSEKEEPERS: [(&str, u64); 4] = [
    ("e8:00:5e:11:22:30", 220),
    ("3c:28:6d:10:20:30", 150),
    ("00:1a:1e:aa:bb:c0", 90),
    ("e8:00:5e:44:55:60", 50),
];
const REMEMBERED: &[&str] = &[
    "MyHome",
    "Starbucks WiFi",
    "AirportFree",
    "Hotel-Guest",
    "Parents",
    "Office5G",
    "Linda's iPhone",
    "TrainWiFi",
    "Library",
    "Gym-Members",
    "eduroam",
    "BeachHouse",
    "xfinitywifi",
    "attwifi",
    "Conference",
    "Lounge",
    "ClinicGuest",
    "HomeNet",
    "CorpNet",
    "Corp-Guest",
];

const FLOODER: &str = "42:00:5e:00:53:9c";
const TWIN: &str = "da:a1:19:00:00:01";
const KARMA: &str = "02:13:37:00:00:01";

fn row(ts: i64, kind: WifiKind) -> WifiRow {
    WifiRow {
        ts,
        frame_no: 0,
        kind,
        protected: false,
        retry: false,
        src: None,
        dst: None,
        tx: None,
        bssid: None,
        channel: None,
        freq_mhz: None,
        signal_dbm: None,
        ssid: None,
        security: None,
        reason: None,
        seq: None,
        len: 100,
    }
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

struct W {
    rows: Vec<WifiRow>,
    rng: Rng,
}

impl W {
    fn new(seed: u64) -> Self {
        Self {
            rows: Vec::new(),
            rng: Rng::new(seed),
        }
    }

    fn beacon(&mut self, ts: i64, bssid: &str, ssid: &str, sec: &str, ch: u16) {
        let mut r = row(ts, WifiKind::Beacon);
        r.src = s(bssid);
        r.tx = s(bssid);
        r.bssid = s(bssid);
        r.dst = s(BCAST);
        r.ssid = s(ssid);
        r.security = s(sec);
        r.channel = Some(ch);
        self.rows.push(r);
    }

    /// Beacons every ~`every` µs over [from, to).
    #[allow(clippy::too_many_arguments)]
    fn beacons(
        &mut self,
        bssid: &str,
        ssid: &str,
        sec: &str,
        ch: u16,
        from: i64,
        to: i64,
        every: i64,
    ) {
        let mut t = from + (self.rng.f() * every as f64) as i64;
        while t < to {
            self.beacon(t, bssid, ssid, sec, ch);
            t += every + (self.rng.range(-0.01, 0.01) * every as f64) as i64;
        }
    }

    fn probe_req(&mut self, ts: i64, client: &str, ssid: &str) {
        let mut r = row(ts, WifiKind::ProbeReq);
        r.src = s(client);
        r.tx = s(client);
        r.dst = s(BCAST);
        r.bssid = s(BCAST);
        r.ssid = s(ssid);
        self.rows.push(r);
    }

    fn probe_resp(&mut self, ts: i64, bssid: &str, client: &str, ssid: &str, sec: &str, ch: u16) {
        let mut r = row(ts, WifiKind::ProbeResp);
        r.src = s(bssid);
        r.tx = s(bssid);
        r.bssid = s(bssid);
        r.dst = s(client);
        r.ssid = s(ssid);
        r.security = s(sec);
        r.channel = Some(ch);
        self.rows.push(r);
    }

    fn deauth(&mut self, ts: i64, tx: &str, dst: &str, bssid: &str, reason: u16, disassoc: bool) {
        self.deauth_from(ts, tx, dst, bssid, reason, disassoc, None);
    }

    /// A deauth heard `offset.1` dB from where `offset.0` is usually heard
    /// (a spoofer somewhere else); `None` = heard like the real `tx`.
    #[allow(clippy::too_many_arguments)]
    fn deauth_from(
        &mut self,
        ts: i64,
        tx: &str,
        dst: &str,
        bssid: &str,
        reason: u16,
        disassoc: bool,
        offset: Option<(&str, i16)>,
    ) {
        let kind = if disassoc {
            WifiKind::Disassoc
        } else {
            WifiKind::Deauth
        };
        let mut r = row(ts, kind);
        r.src = s(tx);
        r.tx = s(tx);
        r.dst = s(dst);
        r.bssid = s(bssid);
        r.reason = Some(reason);
        if let Some((like, o)) = offset {
            r.signal_dbm = Some(base_signal(like) + o + self.rng.int(0, 6) as i16 - 3);
        }
        self.rows.push(r);
    }

    /// A 4-way handshake between `ap` and `client`.
    fn handshake(&mut self, ts: i64, ap: &str, client: &str) {
        for i in 0..4 {
            let mut r = row(ts + i * 3_000, WifiKind::Eapol);
            let (src, dst) = if i % 2 == 0 {
                (ap, client)
            } else {
                (client, ap)
            };
            r.src = s(src);
            r.tx = s(src);
            r.dst = s(dst);
            r.bssid = s(ap);
            self.rows.push(r);
        }
    }

    fn data(&mut self, ts: i64, ap: &str, client: &str) {
        let mut r = row(ts, WifiKind::Data);
        r.protected = true;
        r.src = s(client);
        r.tx = s(client);
        r.dst = s(ap);
        r.bssid = s(ap);
        self.rows.push(r);
    }

    fn build(mut self) -> MemorySource {
        // Every frame is heard at its transmitter's level ± 4 dB unless a
        // builder set it (spoofed deauths).
        for r in &mut self.rows {
            if r.signal_dbm.is_none() {
                let base = r.tx.as_deref().map_or(-70, base_signal);
                r.signal_dbm = Some(base + self.rng.int(0, 8) as i16 - 4);
            }
        }
        self.rows.sort_by_key(|r| r.ts);
        for (i, r) in self.rows.iter_mut().enumerate() {
            r.frame_no = i as u64 + 1;
        }
        MemorySource {
            wifi: self.rows,
            ..Default::default()
        }
    }
}

/// Where the monitor hears a transmitter: a stable −45..−79 dBm per MAC.
fn base_signal(mac: &str) -> i16 {
    let h = mac.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    -45 - (h % 35) as i16
}

fn client_mac(i: usize) -> String {
    // Half the clients use privacy-randomized (locally administered) MACs.
    let first = if i % 2 == 0 { 0xda } else { 0xa4 };
    format!(
        "{first:02x}:5f:{:02x}:10:{:02x}:{:02x}",
        i * 7 % 256,
        i,
        (i * 13) % 256
    )
}

/// The APs a probe for `ssid` gets answers from: (bssid, security, channel).
fn responders(ssid: &str) -> Vec<(&'static str, &'static str, u16)> {
    match ssid {
        "HomeNet" => MESH.iter().map(|(b, c)| (*b, "wpa2", *c)).collect(),
        "CorpNet" => CORP_BANDS
            .iter()
            .map(|(b, c)| (*b, "wpa2/wpa3", *c))
            .collect(),
        _ => ENTERPRISE
            .iter()
            .filter(|(_, sname, _)| *sname == ssid)
            .map(|(b, _, sec)| (*b, *sec, 11))
            .collect(),
    }
}

fn benign_into(w: &mut W, clients: usize) {
    let every = S; // one beacon a second keeps the tests quick
    for (b, ch) in MESH {
        w.beacons(b, "HomeNet", "wpa2", ch, T0, T0 + SPAN, every);
    }
    for (b, ch) in CORP_BANDS {
        w.beacons(b, "CorpNet", "wpa2/wpa3", ch, T0, T0 + SPAN, every);
    }
    for (b, ssid, sec) in ENTERPRISE {
        w.beacons(b, ssid, sec, 11, T0, T0 + SPAN, every);
    }
    for (b, sec, ch) in HIDDEN {
        w.beacons(b, "", sec, ch, T0, T0 + SPAN, every);
    }
    for b in CAFE {
        w.beacons(b, "CafeFree", "open", 1, T0, T0 + SPAN, every);
    }
    for (b, sec) in LINKSYS {
        w.beacons(b, "linksys", sec, 6, T0, T0 + SPAN, every);
    }
    for i in 0..clients {
        let c = client_mac(i);
        let home = if i % 3 == 0 {
            MESH[i % 3].0
        } else {
            CORP_BANDS[i % 2].0
        };
        // Probing: a wildcard plus a few remembered networks every few minutes.
        let mut t = T0 + (w.rng.f() * 120.0 * S as f64) as i64;
        while t < T0 + SPAN {
            w.probe_req(t, &c, "");
            for ap in MESH.iter().map(|(b, c)| (*b, "HomeNet", "wpa2", *c)) {
                w.probe_resp(t + 4_000, ap.0, &c, ap.1, ap.2, ap.3);
            }
            for k in 0..3 {
                let ssid = *w.rng.pick(REMEMBERED);
                let pt = t + (k + 1) * 20_000;
                w.probe_req(pt, &c, ssid);
                for (b, sec, ch) in responders(ssid) {
                    w.probe_resp(pt + 3_000, b, &c, ssid, sec, ch);
                }
            }
            t += (w.rng.range(120.0, 300.0) * S as f64) as i64;
        }
        // Association, handshake, protected data.
        let t0 = T0 + (w.rng.f() * 60.0 * S as f64) as i64;
        w.handshake(t0, home, &c);
        let mut t = t0 + S;
        while t < T0 + SPAN {
            w.data(t, home, &c);
            t += (w.rng.range(5.0, 30.0) * S as f64) as i64;
        }
        // Leaving and coming back a few times an hour (reason 3 / 8).
        for _ in 0..w.rng.int(1, 3) {
            let lt = T0 + (w.rng.f() * SPAN as f64) as i64;
            let disassoc = w.rng.chance(0.5);
            w.deauth(lt, &c, home, home, if disassoc { 8 } else { 3 }, disassoc);
            w.handshake(lt + 2 * S, home, &c);
        }
    }
    // AP housekeeping: reason 6/7 to stale stations, partly in small clumps.
    for (ap, n) in HOUSEKEEPERS {
        let mut sent = 0;
        while sent < n {
            let t = T0 + (w.rng.f() * SPAN as f64) as i64;
            let clump = if w.rng.chance(0.2) {
                w.rng.int(5, 15)
            } else {
                1
            }
            .min(n - sent);
            for k in 0..clump {
                let target = client_mac(w.rng.int(0, 200) as usize);
                let reason = if w.rng.chance(0.5) { 6 } else { 7 };
                w.deauth(t + k as i64 * 200_000, ap, &target, ap, reason, false);
            }
            sent += clump;
        }
    }
    // One AP reboot: broadcast reason 3 plus a unicast to each client.
    let rt = T0 + 20 * MIN;
    let ap = MESH[0].0;
    w.deauth(rt, ap, BCAST, ap, 3, false);
    for i in 0..clients.min(20) {
        w.deauth(rt + i as i64 * 10_000, ap, &client_mac(i), ap, 3, false);
    }
}

fn benign(seed: u64) -> MemorySource {
    let mut w = W::new(seed);
    benign_into(&mut w, 30);
    w.build()
}

/// 3,861 deauth/disassoc frames from a locally administered BSSID that never
/// beacons, reasons 2/4, ~335/min at the peak, against HomeNet clients, then
/// the clients' reconnect handshakes.
fn add_flood(w: &mut W) {
    let start = T0 + 10 * MIN;
    let targets: Vec<String> = (0..8).map(|i| client_mac(i * 3)).collect();
    let total = 3_861u32;
    let per_min = 335.0;
    for i in 0..total {
        let t = start + (f64::from(i) / per_min * MIN as f64) as i64 + w.rng.int(0, 50_000) as i64;
        let dst = if i % 5 < 2 {
            BCAST.to_string()
        } else {
            targets[i as usize % targets.len()].clone()
        };
        let reason = if i % 2 == 0 { 2 } else { 4 };
        w.deauth(t, FLOODER, &dst, FLOODER, reason, i % 10 == 9);
    }
    let end = start + (f64::from(total) / per_min * MIN as f64) as i64;
    for (k, c) in targets.iter().take(3).enumerate() {
        w.handshake(end - 20 * S + k as i64 * S, MESH[0].0, c);
    }
}

/// ≥ 300 deauths in 2 minutes, spoofing the real mesh AP's BSSID.
fn add_spoofed_flood(w: &mut W) -> &'static str {
    let ap = MESH[1].0;
    let start = T0 + 25 * MIN;
    for i in 0..400 {
        let t = start + i * (2 * MIN / 400);
        let dst = if i % 2 == 0 {
            BCAST.to_string()
        } else {
            client_mac((i as usize % 6) * 3 + 1)
        };
        // The attacker is elsewhere: 15 dB louder than the real AP.
        w.deauth_from(t, ap, &dst, ap, 7, false, Some((ap, 15)));
    }
    ap
}

/// Open "HomeNet" from a locally administered BSSID on another channel,
/// appearing five minutes in.
fn add_twin(w: &mut W) {
    w.beacons(TWIN, "HomeNet", "open", 3, T0 + 5 * MIN, T0 + SPAN, S);
}

/// One BSSID answering, right away, every probe for a named network.
fn add_karma(w: &mut W) {
    let probes: Vec<(i64, String, String)> = w
        .rows
        .iter()
        .filter(|r| r.kind == WifiKind::ProbeReq && r.ts >= T0 + 8 * MIN)
        .filter_map(|r| {
            let ssid = r.ssid.clone()?;
            (!ssid.is_empty()).then(|| (r.ts, r.tx.clone().unwrap_or_default(), ssid))
        })
        .collect();
    for (ts, client, ssid) in probes {
        w.probe_resp(ts + 2_000, KARMA, &client, &ssid, "open", 6);
    }
}

fn scenario(seed: u64, attacks: &[fn(&mut W)]) -> MemorySource {
    let mut w = W::new(seed);
    benign_into(&mut w, 30);
    for a in attacks {
        a(&mut w);
    }
    w.build()
}

fn detect(src: &MemorySource) -> Vec<Finding> {
    let f = run(src, &repo_rules(), &repo_allowlist()).expect("run");
    assert_device_findings_valid(src, &f);
    f
}

fn device(f: &[Finding]) -> Vec<&Finding> {
    f.iter().filter(|x| x.entity_type == "device").collect()
}

fn rank(f: &[Finding], mac: &str) -> Option<usize> {
    f.iter()
        .position(|x| x.entity_type == "device" && x.entity == mac)
        .map(|i| i + 1)
}

fn reason<'a>(f: &'a [Finding], mac: &str, rule: &str) -> Option<&'a walleye_core::Reason> {
    f.iter()
        .find(|x| x.entity == mac)
        .and_then(|x| x.reasons.iter().find(|r| r.rule_id == rule))
}

/// Every device finding is well formed, and each reason's evidence frames
/// exist and are the frames that triggered that rule.
fn assert_device_findings_valid(src: &MemorySource, findings: &[Finding]) {
    let by_frame: BTreeMap<u64, &WifiRow> = src.wifi.iter().map(|r| (r.frame_no, r)).collect();
    for f in findings.iter().filter(|f| f.entity_type == "device") {
        assert_eq!(f.finding_id, finding_id("device", &f.entity));
        assert!(f.score > 0.0 && f.score <= 100.0, "score {}", f.score);
        let sum: f64 = f.reasons.iter().map(|r| r.weight).sum();
        assert!((f.score - sum.min(100.0)).abs() < 0.11);
        assert_eq!(f.detector, "wifi");
        assert_eq!(f.attack_technique, f.reasons[0].attack_technique);
        assert!(f.ts_first <= f.ts_last);
        assert!(!common::has_placeholder(&f.title), "{}", f.title);
        for w in f.reasons.windows(2) {
            assert!(w[0].weight >= w[1].weight);
        }
        for r in &f.reasons {
            let e = &r.evidence;
            assert!(e.flow_ids.is_empty(), "device evidence has flows");
            assert!(!e.frame_nos.is_empty());
            assert!(e.frame_nos.len() <= EVIDENCE_CAP);
            assert!(e.total >= e.frame_nos.len() as u64);
            assert_eq!(e.truncated, e.total > e.frame_nos.len() as u64);
            assert!(
                e.frame_nos.windows(2).all(|p| p[0] < p[1]),
                "evidence not sorted"
            );
            assert!(
                !common::has_placeholder(&r.explanation),
                "{}",
                r.explanation
            );
            for fr in &e.frame_nos {
                let row = by_frame
                    .get(fr)
                    .unwrap_or_else(|| panic!("frame {fr} missing"));
                let ok = match r.rule_id.as_str() {
                    "wifi.deauth_flood" => {
                        matches!(row.kind, WifiKind::Deauth | WifiKind::Disassoc)
                            && row.tx.as_deref() == Some(f.entity.as_str())
                            || row.kind == WifiKind::Eapol
                    }
                    "wifi.evil_twin" => matches!(row.kind, WifiKind::Beacon | WifiKind::ProbeResp),
                    "wifi.karma" => {
                        row.kind == WifiKind::ProbeReq
                            || matches!(row.kind, WifiKind::ProbeResp | WifiKind::Beacon)
                                && row.bssid.as_deref() == Some(f.entity.as_str())
                    }
                    other => panic!("unexpected rule {other} on a device"),
                };
                assert!(ok, "{} evidence frame {fr} is {:?}", r.rule_id, row.kind);
            }
        }
    }
}

const SEEDS: [u64; 4] = [1, 2, 7, 42];

#[test]
fn benign_day_has_no_device_findings() {
    for seed in SEEDS {
        let src = benign(seed);
        let f = detect(&src);
        assert!(device(&f).is_empty(), "seed {seed}:\n{}", summary(&f));
        assert!(f.is_empty(), "wifi-only capture produced host findings");
    }
}

#[test]
fn deauth_flood_ranks_flooder_first() {
    for seed in SEEDS {
        let src = scenario(seed, &[add_flood]);
        let f = detect(&src);
        println!("seed {seed}\n{}", summary(&f));
        assert_eq!(rank(&f, FLOODER), Some(1), "seed {seed}:\n{}", summary(&f));
        let r = reason(&f, FLOODER, "wifi.deauth_flood").expect("deauth reason");
        assert_eq!(f[0].attack_technique.as_deref(), Some("T1498"));
        assert!(r.weight >= 70.0, "weight {}", r.weight);
        assert!(r.value >= 300.0, "peak {}", r.value);
        assert!(r.evidence.total >= 3_861 + 12, "deauths + 3 handshakes");
        assert!(r.evidence.truncated);
        assert!(
            r.explanation.contains("3861 deauthentication"),
            "{}",
            r.explanation
        );
        assert!(r.explanation.contains("never beacons"), "{}", r.explanation);
        assert!(
            r.explanation.contains("spoofed_bssid 20"),
            "{}",
            r.explanation
        );
        assert!(!r.explanation.contains(" 0 EAPOL"), "{}", r.explanation);
        // Housekeeping APs stay absent.
        for (ap, _) in HOUSEKEEPERS {
            assert_eq!(rank(&f, ap), None, "housekeeping AP {ap} fired");
        }
        assert_eq!(device(&f).len(), 1, "{}", summary(&f));
    }
}

#[test]
fn spoofed_real_bssid_flood_fires() {
    for seed in SEEDS {
        let mut w = W::new(seed);
        benign_into(&mut w, 30);
        let ap = add_spoofed_flood(&mut w);
        let src = w.build();
        let f = detect(&src);
        assert_eq!(rank(&f, ap), Some(1), "seed {seed}:\n{}", summary(&f));
        let r = reason(&f, ap, "wifi.deauth_flood").expect("reason");
        assert!(r.explanation.contains("\"HomeNet\""), "{}", r.explanation);
        assert!(
            r.explanation.contains("signal_mismatch"),
            "{}",
            r.explanation
        );
        assert!(
            r.explanation.contains("stronger than the beacons"),
            "{}",
            r.explanation
        );
    }
}

#[test]
fn evil_twin_ranks_twin_first() {
    for seed in SEEDS {
        let src = scenario(seed, &[add_twin]);
        let f = detect(&src);
        assert_eq!(rank(&f, TWIN), Some(1), "seed {seed}:\n{}", summary(&f));
        assert_eq!(device(&f).len(), 1, "{}", summary(&f));
        assert_eq!(f[0].attack_technique.as_deref(), Some("T1557"));
        let r = reason(&f, TWIN, "wifi.evil_twin").expect("reason");
        assert!(r.weight >= 80.0, "{}", r.weight);
        assert!(
            r.explanation.contains("\"HomeNet\" as open"),
            "{}",
            r.explanation
        );
        assert!(r.explanation.contains("wpa2"), "{}", r.explanation);
        // The twin's own beacons, plus a few of the original's.
        let ssids: HashSet<&str> = r
            .evidence
            .frame_nos
            .iter()
            .filter_map(|n| src.wifi.get(*n as usize - 1))
            .filter_map(|row| row.ssid.as_deref())
            .collect();
        assert_eq!(ssids, HashSet::from(["HomeNet"]));
    }
}

#[test]
fn karma_ranks_karma_ap_first() {
    for seed in SEEDS {
        let src = scenario(seed, &[add_karma]);
        let f = detect(&src);
        assert_eq!(rank(&f, KARMA), Some(1), "seed {seed}:\n{}", summary(&f));
        let fk = &f[0];
        let r = reason(&f, KARMA, "wifi.karma").expect("reason");
        assert!(r.value >= 10.0, "{}", r.value);
        assert!(r.weight >= 60.0, "{}", r.weight);
        assert!(r.explanation.contains("within 5s"), "{}", r.explanation);
        // Answering "HomeNet" as open also makes it an evil twin: corroboration
        // on one device finding, still capped at 100.
        assert!(
            fk.reasons.iter().any(|r| r.rule_id == "wifi.evil_twin"),
            "{}",
            summary(&f)
        );
        assert!(fk.score <= 100.0);
    }
}

#[test]
fn all_attacks_rank_top_three() {
    for seed in SEEDS {
        let src = scenario(seed, &[add_flood, add_twin, add_karma]);
        let f = detect(&src);
        for mac in [FLOODER, TWIN, KARMA] {
            assert!(
                rank(&f, mac).is_some_and(|r| r <= 3),
                "seed {seed} {mac}:\n{}",
                summary(&f)
            );
        }
        assert_eq!(device(&f).len(), 3, "{}", summary(&f));
        // Stable ids and identical output on a re-run.
        assert_eq!(f, detect(&src));
    }
}

#[test]
fn mesh_multiband_and_cafe_same_security_never_twin() {
    let mut w = W::new(3);
    for (b, ch) in MESH {
        w.beacons(b, "HomeNet", "wpa2", ch, T0, T0 + 10 * MIN, S);
    }
    // A mesh node added later on another channel with another vendor prefix:
    // still the same security, so not a twin.
    w.beacons(
        "f0:9f:c2:00:00:09",
        "HomeNet",
        "wpa2",
        3,
        T0 + 5 * MIN,
        T0 + 10 * MIN,
        S,
    );
    for (b, ch) in CORP_BANDS {
        w.beacons(b, "CorpNet", "wpa2/wpa3", ch, T0, T0 + 10 * MIN, S);
    }
    for b in CAFE {
        w.beacons(b, "CafeFree", "open", 1, T0, T0 + 10 * MIN, S);
    }
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn hidden_and_default_ssids_never_twin() {
    let mut w = W::new(4);
    for (b, sec, ch) in HIDDEN {
        w.beacons(b, "", sec, ch, T0, T0 + 10 * MIN, S);
    }
    // NUL-filled hidden SSIDs after sanitising.
    w.beacons(
        "00:11:22:33:44:55",
        "????????",
        "wpa2",
        6,
        T0,
        T0 + 10 * MIN,
        S,
    );
    w.beacons(
        "02:11:22:33:44:56",
        "????????",
        "open",
        11,
        T0 + 2 * MIN,
        T0 + 10 * MIN,
        S,
    );
    for (b, sec) in LINKSYS {
        w.beacons(b, "linksys", sec, 6, T0, T0 + 10 * MIN, S);
    }
    w.beacons(
        "22:aa:4b:02:02:03",
        "Linksys",
        "open",
        1,
        T0 + 3 * MIN,
        T0 + 10 * MIN,
        S,
    );
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn single_corrupt_open_beacon_is_not_a_twin() {
    let mut w = W::new(5);
    w.beacons(MESH[0].0, "HomeNet", "wpa2", 1, T0, T0 + 10 * MIN, S);
    // Two frames below min_frames (a bad-FCS beacon parsed as open).
    w.beacon(T0 + 5 * MIN, "02:00:5e:00:53:88", "HomeNet", "open", 1);
    w.beacon(T0 + 5 * MIN + S, "02:00:5e:00:53:88", "HomeNet", "open", 1);
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn enterprise_multi_ssid_ap_is_not_karma() {
    let mut w = W::new(6);
    for (b, ssid, sec) in ENTERPRISE {
        w.beacons(b, ssid, sec, 11, T0, T0 + 10 * MIN, S);
    }
    // Clients probe for every enterprise SSID; each answer comes from the
    // BSSID that beacons it, or from a sequential sibling.
    for i in 0..40 {
        let c = client_mac(i);
        for (k, (b, ssid, sec)) in ENTERPRISE.iter().enumerate() {
            let t = T0 + i as i64 * 10 * S + k as i64 * 50_000;
            w.probe_req(t, &c, ssid);
            w.probe_resp(t + 2_000, b, &c, ssid, sec, 11);
            // Sibling answers for the primary SSID too.
            w.probe_resp(t + 3_000, ENTERPRISE[(k + 1) % 6].0, &c, "Corp", "wpa2", 11);
        }
    }
    // Wildcard probes are answered by every AP with its own SSID.
    for i in 0..10 {
        let c = client_mac(100 + i);
        let t = T0 + 7 * MIN + i as i64 * S;
        w.probe_req(t, &c, "");
        for (b, ssid, sec) in ENTERPRISE {
            w.probe_resp(t + 2_000, b, &c, ssid, sec, 11);
        }
    }
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn hidden_probe_responses_are_not_karma() {
    let mut w = W::new(7);
    for i in 0..50 {
        let c = client_mac(i);
        let t = T0 + i as i64 * S;
        w.probe_req(t, &c, "");
        w.probe_resp(t + 2_000, KARMA, &c, "", "open", 6);
    }
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn station_leaving_reasons_are_not_counted() {
    let mut w = W::new(8);
    let ap = MESH[0].0;
    w.beacons(ap, "HomeNet", "wpa2", 1, T0, T0 + 5 * MIN, S);
    // A buggy client roaming in a loop: 300 "I'm leaving" frames in a minute.
    let c = client_mac(1);
    for i in 0..300 {
        let disassoc = i % 2 == 0;
        w.deauth(
            T0 + MIN + i * 200_000,
            &c,
            ap,
            ap,
            if disassoc { 8 } else { 3 },
            disassoc,
        );
    }
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn housekeeping_spread_over_capture_is_quiet() {
    // 220 deauths over 38 minutes (the busiest real AP) plus a clump of 15.
    let mut w = W::new(9);
    let ap = MESH[0].0;
    w.beacons(ap, "HomeNet", "wpa2", 1, T0, T0 + SPAN, S);
    for i in 0..220 {
        let t = T0 + i * (SPAN / 220);
        w.deauth(
            t,
            ap,
            &client_mac(i as usize % 40),
            ap,
            6 + (i % 2) as u16,
            false,
        );
    }
    for i in 0..15 {
        w.deauth(
            T0 + 3 * MIN + i * 100_000,
            ap,
            &client_mac(i as usize),
            ap,
            7,
            false,
        );
    }
    let f = detect(&w.build());
    assert!(f.is_empty(), "{}", summary(&f));
}

#[test]
fn device_findings_do_not_merge_with_host_findings() {
    let sc = common::beacon_scenario(1);
    let wired = run(&sc.src, &repo_rules(), &repo_allowlist()).expect("run");
    assert!(!wired.is_empty());
    let mut mixed = sc.src.clone();
    let wifi = scenario(1, &[add_flood, add_twin]);
    // Frame numbers after the wired frames.
    let base = 10_000_000;
    mixed.wifi = wifi
        .wifi
        .into_iter()
        .map(|mut r| {
            r.frame_no += base;
            r
        })
        .collect();
    let f = run(&mixed, &repo_rules(), &repo_allowlist()).expect("run");
    let hosts: Vec<&Finding> = f.iter().filter(|x| x.entity_type == "host").collect();
    assert_eq!(
        hosts,
        wired.iter().collect::<Vec<_>>(),
        "host findings changed"
    );
    let devs = device(&f);
    assert_eq!(devs.len(), 2);
    for d in devs {
        assert!(d.reasons.iter().all(|r| r.rule_id.starts_with("wifi.")));
        assert!(d.reasons.iter().all(|r| r.evidence.flow_ids.is_empty()));
    }
}

#[test]
fn random_source_flood_does_not_lock_out_a_later_attacker() {
    // 120k one-frame transmitters (mdk4-style random sources) fill the
    // tracking cap; a real flood later must still be seen.
    let mut w = W::new(10);
    let mut rng = Rng::new(10);
    for i in 0..120_000i64 {
        let tx = format!(
            "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            rng.int(0, 255),
            rng.int(0, 255),
            rng.int(0, 255),
            rng.int(0, 255),
            rng.int(0, 255)
        );
        w.deauth(T0 + i * 1_000, &tx, BCAST, &tx, 7, false);
    }
    for i in 0..600 {
        w.deauth(
            T0 + 5 * MIN + i * 100_000,
            FLOODER,
            BCAST,
            FLOODER,
            7,
            false,
        );
    }
    let f = detect(&w.build());
    assert_eq!(rank(&f, FLOODER), Some(1), "{}", summary(&f));
}

#[test]
fn hostile_strings_are_sanitized() {
    let mut w = W::new(11);
    let evil = "Home\u{0}{bssid}\n<script>\u{202e}";
    w.beacons(MESH[0].0, evil, "wpa2", 1, T0, T0 + 5 * MIN, S);
    w.beacons(TWIN, evil, "open", 4, T0 + 2 * MIN, T0 + 5 * MIN, S);
    // Malformed addresses never panic and never become entities.
    let mut r = row(T0 + MIN, WifiKind::Deauth);
    r.tx = s("not-a-mac");
    r.bssid = s("zz:zz:zz:zz:zz:zz");
    w.rows.push(r);
    let src = w.build();
    let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
    assert_eq!(rank(&f, TWIN), Some(1), "{}", summary(&f));
    for x in &f {
        for r in &x.reasons {
            assert!(
                r.explanation
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c == ' ' || "×±…".contains(c)),
                "{:?}",
                r.explanation
            );
        }
        assert!(!x.title.contains('\n'));
    }
}

#[test]
fn benign_day_stays_well_below_min_score() {
    // With every wifi rule's min_score lowered to zero and the volume gates
    // lowered (deauth min_count 10, karma min_ssids 2), the benign day's
    // strongest device reason per rule must stay under 80 % of the shipped
    // min_score: the counter-examples are not passing by a hair.
    let rules = repo_rules();
    let shipped: BTreeMap<String, f64> =
        rules.defs().map(|d| (d.id.clone(), d.min_score)).collect();
    let defs = rules
        .defs()
        .cloned()
        .map(|mut d| {
            if d.detector.starts_with("wifi_") {
                d.min_score = 0.0;
            }
            if d.detector == "wifi_deauth" {
                d.params.insert("min_count".into(), 10.into());
            }
            if d.detector == "wifi_karma" {
                d.params.insert("min_ssids".into(), 2.into());
            }
            d
        })
        .collect();
    let lowered = walleye_detect::RuleSet::from_defs(defs).expect("rules");
    for seed in SEEDS {
        let f = run(&benign(seed), &lowered, &repo_allowlist()).expect("run");
        let mut max: BTreeMap<&str, f64> = BTreeMap::new();
        for x in &f {
            for r in &x.reasons {
                let m = max.entry(r.rule_id.as_str()).or_default();
                *m = m.max(r.weight);
            }
        }
        println!("seed {seed}: {max:?}");
        for (rule, w) in max {
            assert!(
                w < 0.8 * shipped[rule],
                "seed {seed}: {rule} benign max {w} vs min_score {}\n{}",
                shipped[rule],
                summary(&f)
            );
        }
    }
}

// ------------------------------------------------ genuine APs vs spoofers --
//
// Shapes from the real 38-minute WiFi Coconut capture, where the first
// version of the deauth rule ranked three genuine APs.

/// Repo rules with the wifi min_scores at 0, to read a shape's raw points.
fn raw_rules() -> walleye_detect::RuleSet {
    let defs = repo_rules()
        .defs()
        .cloned()
        .map(|mut d| {
            if d.detector.starts_with("wifi_") {
                d.min_score = 0.0;
            }
            d
        })
        .collect();
    walleye_detect::RuleSet::from_defs(defs).expect("rules")
}

/// Raw deauth-rule points for `mac` (0 when the gate never opened).
fn raw_deauth(src: &MemorySource, mac: &str) -> (f64, String) {
    let f = run(src, &raw_rules(), &repo_allowlist()).expect("run");
    reason(&f, mac, "wifi.deauth_flood")
        .map_or((0.0, String::new()), |r| (r.weight, r.explanation.clone()))
}

const AP_A: &str = "26:5a:4c:11:22:33";
const AP_B: &str = "22:5a:4c:11:22:33";
const AP_C: &str = "2a:71:0e:44:55:66";

fn ap_world(w: &mut W) {
    w.beacons(AP_A, "", "wpa2", 11, T0, T0 + SPAN, S);
    w.beacons(AP_B, "NeighbourNet", "wpa2", 11, T0, T0 + SPAN, S);
    w.beacons(AP_C, "", "wpa2", 6, T0, T0 + SPAN, S);
}

/// AP-A: 217 reason-6 deauths in 0.8 min, unicast to 9 of its own clients,
/// heard as loud as its beacons; its sibling AP-B: 125 in under a minute to
/// 5 clients (class-2/3 rejections after a restart).
fn add_rejection_burst(w: &mut W) {
    let start = T0 + 12 * MIN;
    for i in 0..217i64 {
        let c = client_mac(40 + (i as usize % 9));
        w.deauth(start + i * (48 * S / 217), AP_A, &c, AP_A, 6, false);
    }
    for i in 0..125i64 {
        let c = client_mac(60 + (i as usize % 5));
        w.deauth(start + 5 * S + i * (50 * S / 125), AP_B, &c, AP_B, 6, false);
    }
}

/// AP-C: 3,861 deauths to one stuck client over 37.9 min, reasons 2/4,
/// alternating 166 and 38 a minute.
fn add_stuck_client(w: &mut W) {
    let c = client_mac(77);
    let mut i = 0u32;
    for m in 0..38i64 {
        let n = if m % 2 == 0 { 166 } else { 38 };
        for k in 0..n {
            if i == 3_861 {
                return;
            }
            let t = T0 + m * MIN + k * (MIN / n) + 1_000;
            let reason = if i % 16 < 9 { 2 } else { 4 };
            w.deauth(t, AP_C, &c, AP_C, reason, false);
            i += 1;
        }
    }
}

#[test]
fn genuine_ap_rejection_burst_stays_below_min_score() {
    for seed in SEEDS {
        let mut w = W::new(seed);
        ap_world(&mut w);
        add_rejection_burst(&mut w);
        let src = w.build();
        let f = detect(&src);
        assert!(f.is_empty(), "seed {seed}:\n{}", summary(&f));
        for ap in [AP_A, AP_B] {
            let (pts, ex) = raw_deauth(&src, ap);
            println!("seed {seed} {ap}: raw {pts}\n  {ex}");
            assert!(pts < 20.0, "{ap} raw {pts}: {ex}");
            assert!(ex.contains("the real AP likely sent these"), "{ex}");
            assert!(ex.contains("rejections"), "{ex}");
        }
    }
}

#[test]
fn stuck_client_loop_stays_low() {
    for seed in SEEDS {
        let mut w = W::new(seed);
        ap_world(&mut w);
        add_stuck_client(&mut w);
        let src = w.build();
        let f = detect(&src);
        assert!(f.is_empty(), "seed {seed}:\n{}", summary(&f));
        let (pts, ex) = raw_deauth(&src, AP_C);
        println!("seed {seed} stuck client: raw {pts}\n  {ex}");
        assert!(pts < 15.0, "raw {pts}: {ex}");
        assert!(ex.contains("one station over"), "{ex}");
        assert!(ex.contains("3861 deauthentication"), "{ex}");
    }
}

#[test]
fn rejection_burst_without_matching_signal_still_fires() {
    // Same shape as AP-A, but heard 18 dB weaker than AP-A's beacons: someone
    // else sending reason 6 as AP-A. Reason codes alone never suppress.
    let mut w = W::new(12);
    ap_world(&mut w);
    let start = T0 + 12 * MIN;
    for i in 0..217i64 {
        let c = client_mac(40 + (i as usize % 9));
        w.deauth_from(
            start + i * (48 * S / 217),
            AP_A,
            &c,
            AP_A,
            6,
            false,
            Some((AP_A, -18)),
        );
    }
    let f = detect(&w.build());
    assert_eq!(rank(&f, AP_A), Some(1), "{}", summary(&f));
    let r = reason(&f, AP_A, "wifi.deauth_flood").expect("reason");
    assert!(
        r.explanation.contains("signal_mismatch"),
        "{}",
        r.explanation
    );
    assert!(
        r.explanation.contains("weaker than the beacons"),
        "{}",
        r.explanation
    );
}

#[test]
fn spoofed_flood_15db_off_ranks_first_among_genuine_aps() {
    // The genuine-AP shapes and a spoofed flood of the mesh AP, 15 dB louder
    // than its beacons, in one capture: only the spoofed one is a finding.
    for seed in SEEDS {
        let mut w = W::new(seed);
        benign_into(&mut w, 30);
        ap_world(&mut w);
        add_rejection_burst(&mut w);
        add_stuck_client(&mut w);
        let ap = add_spoofed_flood(&mut w);
        let src = w.build();
        let f = detect(&src);
        assert_eq!(rank(&f, ap), Some(1), "seed {seed}:\n{}", summary(&f));
        assert_eq!(device(&f).len(), 1, "seed {seed}:\n{}", summary(&f));
        let r = reason(&f, ap, "wifi.deauth_flood").expect("reason");
        assert!(
            r.explanation.contains("signal_mismatch"),
            "{}",
            r.explanation
        );
        println!("seed {seed}: spoofed {}\n  {}", r.weight, r.explanation);
    }
}

#[test]
fn spoofer_that_never_beacons_still_fires() {
    // Own MAC (never beacons) claiming the mesh AP's BSSID, broadcast and
    // unicast, 300 in 2 minutes: the generator's shape. Signal is compared
    // with the claimed AP's beacons.
    let mut w = W::new(13);
    benign_into(&mut w, 30);
    let ap = MESH[0].0;
    for i in 0..300i64 {
        let dst = if i % 2 == 0 {
            BCAST.to_string()
        } else {
            client_mac((i as usize % 6) * 3)
        };
        w.deauth_from(
            T0 + 15 * MIN + i * (2 * MIN / 300),
            KARMA,
            &dst,
            ap,
            7,
            false,
            Some((ap, -20)),
        );
    }
    let f = detect(&w.build());
    assert_eq!(rank(&f, KARMA), Some(1), "{}", summary(&f));
    let r = reason(&f, KARMA, "wifi.deauth_flood").expect("reason");
    assert!(
        r.explanation.contains("spoofed_bssid 20"),
        "{}",
        r.explanation
    );
    assert!(
        r.explanation.contains("signal_mismatch"),
        "{}",
        r.explanation
    );
    assert!(
        r.explanation.contains("network it claims"),
        "{}",
        r.explanation
    );
}

#[test]
fn spoofer_mixed_into_a_genuine_rejection_burst_still_fires() {
    // AP-A's genuine reason-6 burst, plus 120 broadcast reason-7 frames sent
    // as AP-A from 18 dB louder during the same minute.
    let mut w = W::new(14);
    ap_world(&mut w);
    add_rejection_burst(&mut w);
    let start = T0 + 12 * MIN;
    for i in 0..120i64 {
        w.deauth_from(
            start + 2 * S + i * (45 * S / 120),
            AP_A,
            BCAST,
            AP_A,
            7,
            false,
            Some((AP_A, 18)),
        );
    }
    let f = detect(&w.build());
    assert_eq!(rank(&f, AP_A), Some(1), "{}", summary(&f));
    let r = reason(&f, AP_A, "wifi.deauth_flood").expect("reason");
    assert!(
        r.explanation.contains("someone else is sending as it"),
        "{}",
        r.explanation
    );
    assert!(
        !r.explanation.contains("real AP likely"),
        "{}",
        r.explanation
    );
}

// ----------------------------------------------- security review (H1/M1/M4) --

/// Time budget for a hostile-volume test: generous in debug builds, tight
/// in release (where the review measured the regressions).
fn budget(release_ms: u128) -> u128 {
    if cfg!(debug_assertions) {
        release_ms * 40
    } else {
        release_ms
    }
}

#[test]
fn million_fresh_probes_do_not_sweep_per_row() {
    // H1: 1M distinct (client, SSID) probes at one timestamp keep the probe
    // map full of fresh entries; sweeping on every row was O(100k) each.
    let mut rows = Vec::with_capacity(1_000_000);
    for i in 0..1_000_000u64 {
        let mut r = row(T0, WifiKind::ProbeReq);
        let c = format!(
            "da:{:02x}:{:02x}:{:02x}:00:01",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        );
        r.tx = Some(c.clone());
        r.src = Some(c);
        r.ssid = Some("CafeNet".into());
        r.frame_no = i + 1;
        r.signal_dbm = Some(-60);
        rows.push(r);
    }
    let src = MemorySource {
        wifi: rows,
        ..Default::default()
    };
    let t = std::time::Instant::now();
    let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
    let ms = t.elapsed().as_millis();
    println!("1M fresh probes: {ms} ms");
    assert!(f.is_empty());
    assert!(ms < budget(1_000), "{ms} ms");
}

#[test]
fn many_flooding_transmitters_are_capped_and_cheap() {
    // M1: 20,500 transmitters that each pass the gate fill the deauth map
    // with entries that are never evicted, then 30,000 newcomers arrive one
    // per second. Sweeps back off instead of running 20k-entry retains, and
    // only `max_findings` (200) device findings are reported.
    let mut w = W::new(15);
    for i in 0..20_500i64 {
        let tx = format!(
            "02:aa:{:02x}:{:02x}:{:02x}:01",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        );
        let t0 = T0 + i * 2 * S;
        for k in 0..50 {
            w.deauth(t0 + k * 10_000, &tx, BCAST, &tx, 7, false);
        }
    }
    let late = T0 + 20_500 * 2 * S;
    for i in 0..30_000i64 {
        let tx = format!(
            "02:bb:{:02x}:{:02x}:{:02x}:01",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        );
        w.deauth(late + i * S, &tx, BCAST, &tx, 7, false);
    }
    let src = w.build();
    let t = std::time::Instant::now();
    let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
    let ms = t.elapsed().as_millis();
    println!(
        "20.5k flooders + 30k newcomers: {ms} ms, {} findings",
        f.len()
    );
    assert_eq!(device(&f).len(), 200, "{}", f.len());
    let noted = f
        .iter()
        .flat_map(|x| &x.reasons)
        .filter(|r| r.explanation.contains("not reported: max_findings = 200"))
        .count();
    assert_eq!(noted, 1, "the top finding says how many were dropped");
    assert!(ms < budget(3_000), "{ms} ms");
}

#[test]
fn ssid_quotes_cannot_forge_explanations() {
    // M4: an SSID that closes the quote and appends fake text.
    let evil = r#"Free" ch 6 wpa3 (verified"#;
    let mut w = W::new(16);
    w.beacons(MESH[0].0, evil, "wpa2", 1, T0, T0 + 5 * MIN, S);
    w.beacons(TWIN, evil, "open", 4, T0 + 2 * MIN, T0 + 5 * MIN, S);
    let f = run(&w.build(), &repo_rules(), &repo_allowlist()).expect("run");
    assert_eq!(rank(&f, TWIN), Some(1), "{}", summary(&f));
    let x = &f[0];
    assert!(
        x.title.contains(r#""Free\" ch 6 wpa3 (verified""#),
        "{}",
        x.title
    );
    let r = &x.reasons[0];
    assert!(
        r.explanation
            .contains(r#""Free\" ch 6 wpa3 (verified" as open"#),
        "{}",
        r.explanation
    );
}
