//! 802.11 ingest (CONTRACTS §11.1) over generated radiotap captures
//! (`walleye-gen` scenarios `wifi` and `wifi_benign`): row counts per kind
//! against an independent count of the raw frame-control bytes, open-network
//! IP traffic producing flows, the labelled attacks being visible in the
//! rows, checkpoint/resume, and the decode tree for link type 127.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use walleye_core::{WifiKind, WifiRow};
use walleye_gen::{Options, Scenario, Summary, generate};
use walleye_ingest::{IngestOptions, decode_frame, ingest_bytes};

fn gen_wifi(scenario: Scenario, seed: u64, minutes: u64) -> (Vec<u8>, Summary) {
    let mut opts = Options::new(scenario, seed);
    opts.duration_min = minutes;
    let mut buf = Vec::new();
    let s = generate(&opts, &mut buf).expect("generate");
    (buf, s)
}

fn collect(bytes: &[u8], opts: &IngestOptions) -> CollectSink {
    let mut s = CollectSink::default();
    ingest_bytes(bytes, SHA, &mut s, opts).expect("ingest");
    s
}

/// Independent tally from the raw records: (type, subtype, protected,
/// LLC ethertype) of every frame, reading radiotap's `it_len` only.
fn raw_kinds(pcap: &[u8]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    let mut p = 24;
    while p + 16 <= pcap.len() {
        let n = u32::from_le_bytes(pcap[p + 8..p + 12].try_into().expect("test input")) as usize;
        let rec = &pcap[p + 16..p + 16 + n];
        p += 16 + n;
        let rt = usize::from(u16::from_le_bytes([rec[2], rec[3]]));
        let f = &rec[rt..rec.len() - 4];
        let (ty, st, prot) = ((f[0] >> 2) & 3, f[0] >> 4, f[1] & 0x40 != 0);
        let k = match (ty, st) {
            (1, _) => "control",
            (0, 0) => "assoc_req",
            (0, 1) => "assoc_resp",
            (0, 2) => "reassoc_req",
            (0, 3) => "reassoc_resp",
            (0, 4) => "probe_req",
            (0, 5) => "probe_resp",
            (0, 8) => "beacon",
            (0, 10) => "disassoc",
            (0, 11) => "auth",
            (0, 12) => "deauth",
            (0, 13) => "action",
            (2, s) if s & 4 != 0 => "null",
            (2, _) if !prot && f.get(32..34) == Some(&[0x88, 0x8e][..]) => "eapol",
            (2, _) => "data",
            _ => "other",
        };
        *m.entry(k).or_default() += 1;
    }
    m
}

fn by_kind(rows: &[WifiRow]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for r in rows {
        *m.entry(r.kind.as_str()).or_default() += 1;
    }
    m
}

#[test]
fn wifi_rows_per_kind_match_the_raw_frames_and_open_traffic_makes_flows() {
    let (cap, summary) = gen_wifi(Scenario::Wifi, 7, 10);
    assert_eq!(
        u32::from_le_bytes(cap[20..24].try_into().expect("test input")),
        127
    );
    let s = collect(&cap, &IngestOptions::default());
    let rows = &s.rows;
    let cap_row = s.finished.expect("finished");
    assert_eq!(cap_row.link_type, 127);
    assert_eq!(cap_row.frame_count, summary.packets);
    assert_eq!(rows.frames.len() as u64, summary.packets);

    let mut raw = raw_kinds(&cap);
    let control = raw.remove("control").unwrap_or(0);
    assert!(control > 1000, "ACKs present: {control}");
    assert_eq!(by_kind(&rows.wifi), raw, "rows per kind vs raw frames");
    assert_eq!(rows.wifi.len() + control, rows.frames.len());
    for k in [
        "beacon",
        "probe_req",
        "probe_resp",
        "auth",
        "assoc_req",
        "assoc_resp",
        "reassoc_req",
        "reassoc_resp",
        "deauth",
        "disassoc",
        "action",
        "data",
        "null",
        "eapol",
    ] {
        assert!(raw.get(k).copied().unwrap_or(0) > 0, "scenario has {k}");
    }

    // Frame order, every row with radio info and a sequence number.
    assert!(rows.wifi.windows(2).all(|w| w[0].frame_no < w[1].frame_no));
    assert!(rows.wifi.iter().all(|r| r.channel.is_some()
        && r.freq_mhz.is_some()
        && r.signal_dbm.is_some()
        && r.seq.is_some()
        && r.tx.is_some()));
    // EAPOL and open data are unprotected; the rest of the data is not.
    assert!(
        rows.wifi
            .iter()
            .filter(|r| r.kind == WifiKind::Eapol)
            .all(|r| !r.protected)
    );
    assert!(
        rows.wifi
            .iter()
            .any(|r| r.kind == WifiKind::Data && r.protected)
    );

    // Open-network DNS and HTTP over LLC/SNAP reach the flow pipeline.
    assert!(!rows.flows.is_empty());
    assert!(
        rows.flows
            .iter()
            .any(|f| f.app_proto.as_deref() == Some("dns"))
    );
    assert!(
        rows.flows
            .iter()
            .any(|f| f.app_proto.as_deref() == Some("http"))
    );
    assert!(!rows.dns.is_empty() && !rows.http.is_empty());
    assert!(rows.http.iter().all(|h| h.host.as_deref().is_some_and(
        |h| h.ends_with(".example.com")
            || h.ends_with(".example.org")
            || h.ends_with(".example.net")
    )));
    // Only unprotected data frames carry a flow id.
    let flow_frames: BTreeSet<u64> = rows
        .frames
        .iter()
        .filter(|f| f.flow_id.is_some())
        .map(|f| f.frame_no)
        .collect();
    let open_data: BTreeSet<u64> = rows
        .wifi
        .iter()
        .filter(|r| r.kind == WifiKind::Data && !r.protected)
        .map(|r| r.frame_no)
        .collect();
    assert_eq!(flow_frames, open_data);
}

#[test]
fn labelled_attacks_are_visible_in_the_rows() {
    let (cap, summary) = gen_wifi(Scenario::Wifi, 3, 12);
    let l = &summary.labels;
    assert!(!l.benign);
    assert_eq!(l.c2_hosts.len(), 3, "{}", l.notes);
    for m in &l.c2_hosts {
        assert!(walleye_core::mac::text_is_locally_administered(m), "{m}");
    }
    let (deauther, twin, karma) = (&l.c2_hosts[0], &l.c2_hosts[1], &l.c2_hosts[2]);
    let rows = collect(&cap, &IngestOptions::default()).rows.wifi;
    let tx_is = |r: &WifiRow, m: &str| r.tx.as_deref() == Some(m);

    // Deauth flood: ≥ 300 in two minutes, broadcast and unicast, claiming a
    // BSSID that is not the transmitter's.
    let d: Vec<&WifiRow> = rows
        .iter()
        .filter(|r| r.kind == WifiKind::Deauth && tx_is(r, deauther))
        .collect();
    assert!(d.len() >= 300, "{}", d.len());
    assert!(d.last().expect("test input").ts - d[0].ts <= 120_000_000);
    assert!(
        d.iter()
            .any(|r| r.dst.as_deref() == Some("ff:ff:ff:ff:ff:ff"))
    );
    assert!(
        d.iter()
            .any(|r| r.dst.as_deref() != Some("ff:ff:ff:ff:ff:ff"))
    );
    let claimed = d[0].bssid.clone().expect("test input");
    assert_ne!(&claimed, deauther);
    assert!(d.iter().all(|r| r.reason == Some(7)));
    let real = rows
        .iter()
        .find(|r| r.kind == WifiKind::Beacon && r.bssid.as_deref() == Some(&claimed))
        .expect("claimed BSSID beacons");
    assert_eq!(real.ssid.as_deref(), Some("Lighthouse"));
    assert_eq!(real.security.as_deref(), Some("wpa2"));
    // Victims re-handshake after the flood.
    let last = d.last().expect("test input").ts;
    assert!(rows.iter().any(|r| r.kind == WifiKind::Eapol
        && r.bssid.as_deref() == Some(&claimed)
        && r.ts > last
        && r.ts < last + 60_000_000));

    // Evil twin: open, same SSID, other channel, appears after the original.
    let tb: Vec<&WifiRow> = rows
        .iter()
        .filter(|r| r.kind == WifiKind::Beacon && r.bssid.as_deref() == Some(twin.as_str()))
        .collect();
    assert!(tb.len() >= 10);
    assert!(tb.iter().all(|r| r.ssid.as_deref() == Some("Lighthouse")
        && r.security.as_deref() == Some("open")
        && r.channel != real.channel));
    assert!(tb[0].ts > real.ts);

    // Karma: probe responses for ≥ 10 SSIDs, never a beacon.
    let ks: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.kind == WifiKind::ProbeResp && tx_is(r, karma))
        .filter_map(|r| r.ssid.as_deref())
        .collect();
    assert!(ks.len() >= 10, "{ks:?}");
    assert!(
        !rows
            .iter()
            .any(|r| r.kind == WifiKind::Beacon && tx_is(r, karma))
    );
}

#[test]
fn benign_has_mesh_and_no_attack_patterns() {
    let (cap, summary) = gen_wifi(Scenario::WifiBenign, 5, 8);
    assert!(summary.labels.benign && summary.labels.c2_hosts.is_empty());
    let rows = collect(&cap, &IngestOptions::default()).rows.wifi;
    // Six beaconing BSSIDs; the mesh SSID has three of them, one security.
    let mut aps: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<u16>)> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.kind == WifiKind::Beacon) {
        let e = aps
            .entry(r.ssid.as_deref().expect("test input"))
            .or_default();
        e.0.insert(r.bssid.as_deref().expect("test input"));
        e.1.insert(r.channel.expect("test input"));
    }
    assert_eq!(aps.values().map(|v| v.0.len()).sum::<usize>(), 6);
    assert_eq!(aps["Walleye-Mesh"].0.len(), 3);
    assert_eq!(aps["Walleye-Mesh"].1, BTreeSet::from([1, 6, 11]));
    let mesh_sec: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.ssid.as_deref() == Some("Walleye-Mesh") && r.kind == WifiKind::Beacon)
        .filter_map(|r| r.security.as_deref())
        .collect();
    assert_eq!(mesh_sec.len(), 1);
    let secs: BTreeSet<&str> = rows.iter().filter_map(|r| r.security.as_deref()).collect();
    assert_eq!(secs, BTreeSet::from(["open", "wpa2", "wpa2/wpa3", "wpa3"]));
    // Deauths are few and normal; no one probe-responds for many SSIDs.
    let deauths: Vec<&WifiRow> = rows
        .iter()
        .filter(|r| matches!(r.kind, WifiKind::Deauth | WifiKind::Disassoc))
        .collect();
    assert!(!deauths.is_empty() && deauths.len() < 100);
    assert!(
        deauths
            .iter()
            .all(|r| r.reason.is_none() || matches!(r.reason, Some(3 | 8)))
    );
    let mut per_bssid: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.kind == WifiKind::ProbeResp) {
        per_bssid
            .entry(r.bssid.as_deref().expect("test input"))
            .or_default()
            .insert(r.ssid.as_deref().unwrap_or(""));
    }
    assert!(per_bssid.values().all(|s| s.len() == 1));
    // Half the clients are randomized.
    let clients: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.kind == WifiKind::ProbeReq)
        .filter_map(|r| r.src.as_deref())
        .collect();
    let rand = clients
        .iter()
        .filter(|m| walleye_core::mac::text_is_locally_administered(m))
        .count();
    assert_eq!(clients.len(), 25);
    assert!((10..=15).contains(&rand), "{rand}");
}

#[test]
fn wifi_rows_survive_checkpoint_resume() {
    let (cap, _) = gen_wifi(Scenario::Wifi, 11, 4);
    let opts = IngestOptions {
        checkpoint_bytes: 512 * 1024,
        batch_rows: 1000,
        ..IngestOptions::default()
    };
    let full = collect(&cap, &opts);
    assert!(full.checkpoints.len() >= 4);
    let crash_at = full.checkpoints.len() / 2;
    let mut first = CollectSink {
        crash_after: Some(crash_at),
        ..CollectSink::default()
    };
    ingest_bytes(&cap, SHA, &mut first, &opts).expect_err("simulated crash");
    let cp = first.checkpoints.last().expect("checkpoint").clone();
    let mut second = CollectSink {
        resume_from: Some(cp),
        ..CollectSink::default()
    };
    ingest_bytes(&cap, SHA, &mut second, &opts).expect("resume");
    let mut wifi = first.durable.wifi.clone();
    wifi.extend(second.rows.wifi.iter().cloned());
    assert_eq!(wifi, full.rows.wifi);
    let mut frames = first.durable.frames.clone();
    frames.extend(second.rows.frames.iter().cloned());
    assert_eq!(frames, full.rows.frames);
}

#[test]
fn decode_tree_for_generated_frames_stays_in_range() {
    let (cap, _) = gen_wifi(Scenario::Wifi, 2, 3);
    let mut p = 24;
    let mut seen = BTreeSet::new();
    let mut n = 0;
    while p + 16 <= cap.len() && n < 20_000 {
        let len = u32::from_le_bytes(cap[p + 8..p + 12].try_into().expect("test input")) as usize;
        let rec = &cap[p + 16..p + 16 + len];
        p += 16 + len;
        n += 1;
        let tree = decode_frame(127, rec);
        fn walk(ns: &[walleye_core::ipc::DecodeNode], len: usize, seen: &mut BTreeSet<String>) {
            for x in ns {
                if let Some(r) = x.range {
                    assert!((r.start + r.len) as usize <= len, "{}", x.label);
                }
                if let Some(f) = &x.field {
                    seen.insert(f.clone());
                }
                assert!(x.warning.is_none(), "{}: {:?}", x.label, x.warning);
                walk(&x.children, len, seen);
            }
        }
        walk(&tree, rec.len(), &mut seen);
    }
    for f in [
        "wifi.src",
        "wifi.dst",
        "wifi.bssid",
        "wifi.ssid",
        "wifi.security",
        "wifi.signal",
        "wifi.reason",
        "src_ip",
        "dns.query",
    ] {
        assert!(seen.contains(f), "{f} never set: {seen:?}");
    }
}
