//! 802.11 index (CONTRACTS §11.2): the `wifi` table, the `wifi_aps` /
//! `wifi_clients` views, filters, paging, device timeline, device_frames,
//! autocomplete and `for_each_wifi`. Rows are built directly as `WifiRow`s.

mod wifi_synth;

use std::path::{Path, PathBuf};

use walleye_core::{
    CaptureFormat, CaptureRow, ErrorCode, Evidence, Finding, FrameRow, Reason, WifiApRow,
    WifiClientRow, WifiKind, WifiRow,
    ipc::{LaneKind, QueryRequest, RowSet, Sort, SuggestionKind, TimeRange, TimelineRequest, View},
    sink::{DetectSource, IndexSink, RecordBatch},
};
use walleye_index::{Index, IndexWriter};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "walleye-wifi-test-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).expect("tmp");
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SHA: &str = "1111111111111111222222222222222233333333333333334444444444444444";

// Home AP (WPA2, ch 6), its mesh sibling, an evil twin (open, randomized
// BSSID, ch 11) and three stations.
const AP1: &str = "e8:00:5e:00:53:88";
const AP3: &str = "e8:00:5e:00:53:89";
const TWIN: &str = "42:00:5e:00:53:9c";
const C1: &str = "a4:83:e7:11:22:33";
const C2: &str = "da:a1:19:00:00:01";
const C3: &str = "a4:83:e7:44:55:66";
const BCAST: &str = "ff:ff:ff:ff:ff:ff";
const MCAST: &str = "01:00:5e:00:00:fb";

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

struct B {
    rows: Vec<WifiRow>,
}

impl B {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        ts: i64,
        kind: WifiKind,
        src: &str,
        dst: &str,
        tx: &str,
        bssid: Option<&str>,
        ssid: Option<&str>,
        security: Option<&str>,
        channel: Option<u16>,
        signal: Option<i16>,
        reason: Option<u16>,
    ) {
        let frame_no = self.rows.len() as u64 + 1;
        self.rows.push(WifiRow {
            ts,
            frame_no,
            kind,
            protected: kind == WifiKind::Data,
            retry: false,
            src: s(src),
            dst: s(dst),
            tx: s(tx),
            bssid: bssid.map(str::to_string),
            channel,
            freq_mhz: channel.map(|c| 2407 + 5 * c),
            signal_dbm: signal,
            ssid: ssid.map(str::to_string),
            security: security.map(str::to_string),
            reason,
            seq: Some(frame_no as u16),
            len: 100 + frame_no as u32,
        });
    }
}

const T: i64 = 1_000_000_000;
const SEC: i64 = 1_000_000;

/// The hand-built dataset; frame numbers are 1.. in push order, ts ascends.
fn dataset() -> Vec<WifiRow> {
    use WifiKind as K;
    let mut b = B { rows: Vec::new() };
    let t = |n: i64| T + n * SEC;
    // AP1 beacons: 3 × "HomeNet", 1 hidden; ch 6 (one stray ch 1).
    for (i, (ssid, ch, sig)) in [
        ("HomeNet", 6, -40),
        ("HomeNet", 6, -38),
        ("", 6, -45),
        ("HomeNet", 1, -41),
    ]
    .iter()
    .enumerate()
    {
        b.push(
            t(i as i64),
            K::Beacon,
            AP1,
            BCAST,
            AP1,
            Some(AP1),
            Some(ssid),
            Some("wpa2"),
            Some(*ch),
            Some(*sig),
            None,
        );
    }
    // Mesh sibling: same SSID and security, ch 11.
    b.push(
        t(4),
        K::Beacon,
        AP3,
        BCAST,
        AP3,
        Some(AP3),
        Some("HomeNet"),
        Some("wpa2"),
        Some(11),
        Some(-60),
        None,
    );
    // C1 probes for HomeNet and Cafe; C2 sends a wildcard probe.
    b.push(
        t(5),
        K::ProbeReq,
        C1,
        BCAST,
        C1,
        Some(BCAST),
        Some("HomeNet"),
        None,
        Some(6),
        Some(-50),
        None,
    );
    b.push(
        t(6),
        K::ProbeReq,
        C1,
        BCAST,
        C1,
        Some(BCAST),
        Some("Cafe"),
        None,
        Some(6),
        Some(-52),
        None,
    );
    b.push(
        t(7),
        K::ProbeReq,
        C2,
        BCAST,
        C2,
        Some(BCAST),
        Some(""),
        None,
        Some(6),
        Some(-70),
        None,
    );
    // The twin answers C1's probe (open, ch 11) and beacons once.
    b.push(
        t(8),
        K::ProbeResp,
        TWIN,
        C1,
        TWIN,
        Some(TWIN),
        Some("HomeNet"),
        Some("open"),
        Some(11),
        Some(-30),
        None,
    );
    b.push(
        t(9),
        K::ProbeResp,
        TWIN,
        C1,
        TWIN,
        Some(TWIN),
        Some("HomeNet"),
        Some("open"),
        Some(11),
        Some(-31),
        None,
    );
    // C1 joins AP1: auth, assoc, EAPOL, data both ways, multicast data.
    b.push(
        t(10),
        K::Auth,
        C1,
        AP1,
        C1,
        Some(AP1),
        None,
        None,
        Some(6),
        Some(-49),
        Some(0),
    );
    b.push(
        t(11),
        K::AssocReq,
        C1,
        AP1,
        C1,
        Some(AP1),
        Some("HomeNet"),
        None,
        Some(6),
        Some(-48),
        None,
    );
    b.push(
        t(12),
        K::Eapol,
        AP1,
        C1,
        AP1,
        Some(AP1),
        None,
        None,
        Some(6),
        Some(-39),
        None,
    );
    b.push(
        t(13),
        K::Data,
        C1,
        AP1,
        C1,
        Some(AP1),
        None,
        None,
        Some(6),
        Some(-47),
        None,
    );
    b.push(
        t(14),
        K::Data,
        AP1,
        C1,
        AP1,
        Some(AP1),
        None,
        None,
        Some(6),
        Some(-37),
        None,
    );
    b.push(
        t(15),
        K::Data,
        C1,
        MCAST,
        C1,
        Some(AP1),
        None,
        None,
        Some(6),
        Some(-46),
        None,
    );
    // C3 is only ever a destination of AP3 data (never transmits).
    b.push(
        t(16),
        K::Null,
        AP3,
        C3,
        AP3,
        Some(AP3),
        None,
        None,
        Some(11),
        Some(-61),
        None,
    );
    // Deauth flood from the twin, spoofing AP1's BSSID.
    for i in 0..4 {
        b.push(
            t(20) + i,
            K::Deauth,
            AP1,
            if i % 2 == 0 { BCAST } else { C1 },
            TWIN,
            Some(AP1),
            None,
            None,
            Some(6),
            Some(-29),
            Some(7),
        );
    }
    b.rows
}

fn wifi_capture(rows: &[WifiRow], link_type: u32) -> CaptureRow {
    CaptureRow {
        capture_id: SHA[..16].to_string(),
        path: "/wifi.pcap".into(),
        sha256: SHA.to_string(),
        size_bytes: 10_000,
        format: CaptureFormat::Pcap,
        first_ts: rows.first().map_or(0, |r| r.ts),
        last_ts: rows.last().map_or(0, |r| r.ts),
        link_type,
        frame_count: rows.len() as u64,
    }
}

fn frames_of(rows: &[WifiRow]) -> Vec<FrameRow> {
    rows.iter()
        .map(|w| FrameRow {
            frame_no: w.frame_no,
            ts: w.ts,
            file_offset: 24 + w.frame_no * 300,
            caplen: w.len + 36,
            wirelen: w.len + 36,
            flow_id: None,
            direction: None,
            tcp_flags: None,
            payload_len: 0,
            link_type: Some(127),
        })
        .collect()
}

/// Writes `rows` (split into two batches, second first, to check sorting).
fn build(dir: &Path, rows: &[WifiRow], link_type: u32) -> Index {
    let cap = wifi_capture(rows, link_type);
    let mut w = IndexWriter::create(dir).expect("create");
    w.begin(&cap).expect("begin");
    w.write(RecordBatch::Frames(frames_of(rows)))
        .expect("frames");
    let mid = rows.len() / 2;
    w.write(RecordBatch::Wifi(rows[mid..].to_vec()))
        .expect("wifi 2");
    w.write(RecordBatch::Wifi(rows[..mid].to_vec()))
        .expect("wifi 1");
    w.finish(&cap).expect("finish");
    Index::open(dir).expect("open")
}

fn req(view: View, filter: &str) -> QueryRequest {
    QueryRequest {
        filter: filter.into(),
        view,
        time_range: None,
        hosts: vec![],
        flow_ids: vec![],
        sort: None,
        limit: 1000,
        cursor: None,
    }
}

fn wifi_rows(idx: &Index, filter: &str) -> Vec<WifiRow> {
    match idx.query(&req(View::Wifi, filter)).expect(filter).data {
        RowSet::Wifi(v) => v,
        o => panic!("{o:?}"),
    }
}

fn frames(idx: &Index, filter: &str) -> Vec<u64> {
    wifi_rows(idx, filter).iter().map(|r| r.frame_no).collect()
}

fn aps(idx: &Index, r: &QueryRequest) -> Vec<WifiApRow> {
    match idx.query(r).expect("aps").data {
        RowSet::WifiAps(v) => v,
        o => panic!("{o:?}"),
    }
}

fn clients(idx: &Index, r: &QueryRequest) -> Vec<WifiClientRow> {
    match idx.query(r).expect("clients").data {
        RowSet::WifiClients(v) => v,
        o => panic!("{o:?}"),
    }
}

#[test]
fn wifi_table_roundtrips_in_time_order() {
    let d = TempDir::new("roundtrip");
    let rows = dataset();
    let idx = build(d.path(), &rows, 127);
    assert!(d.path().join("wifi").join("data-0.parquet").exists());
    assert_eq!(wifi_rows(&idx, ""), rows);
    let p = idx.query(&req(View::Wifi, "")).expect("q");
    assert_eq!(p.total, Some(rows.len() as u64));
    assert!(p.sql.expect("sql").contains("FROM wifi WHERE"));
    // DetectSource streams (ts, frame_no) order.
    let mut got = Vec::new();
    idx.for_each_wifi(&mut |r| got.push(r.clone()))
        .expect("stream");
    assert_eq!(got, rows);
}

#[test]
fn access_points_view_matches_the_contract() {
    let d = TempDir::new("aps");
    let idx = build(d.path(), &dataset(), 127);
    let got = aps(&idx, &req(View::WifiAps, ""));
    // Default sort: beacons desc, then bssid.
    let want = vec![
        WifiApRow {
            bssid: AP1.into(),
            ssid: s("HomeNet"),
            channel: Some(6),
            security: s("wpa2"),
            first_ts: T,
            last_ts: T + 20 * SEC + 3,
            beacons: 4,
            // 4 beacons + auth, assoc, eapol, 3 data + 4 deauths (bssid AP1).
            frames: 14,
            // C1 only: the BSSID and the multicast group are not clients.
            clients: 1,
            // tx = AP1 only (the spoofed deauths came from the twin).
            signal_max: Some(-37),
            randomized: false,
            first_frame: 1,
        },
        WifiApRow {
            bssid: AP3.into(),
            ssid: s("HomeNet"),
            channel: Some(11),
            security: s("wpa2"),
            first_ts: T + 4 * SEC,
            last_ts: T + 16 * SEC,
            beacons: 1,
            frames: 2,
            clients: 1,
            signal_max: Some(-60),
            randomized: false,
            first_frame: 5,
        },
        WifiApRow {
            bssid: TWIN.into(),
            ssid: s("HomeNet"),
            channel: Some(11),
            security: s("open"),
            first_ts: T + 8 * SEC,
            last_ts: T + 9 * SEC,
            beacons: 0,
            frames: 2,
            clients: 0,
            signal_max: Some(-30),
            randomized: true,
            first_frame: 9,
        },
    ];
    assert_eq!(got, want);
    // Filters on ap.* fields.
    let one = |f: &str| -> Vec<String> {
        aps(&idx, &req(View::WifiAps, f))
            .into_iter()
            .map(|a| a.bssid)
            .collect()
    };
    assert_eq!(one("ap.security == open"), vec![TWIN]);
    assert_eq!(one("ap.randomized == true"), vec![TWIN]);
    assert_eq!(
        one("ap.ssid ~ \"home*\" and ap.channel == 11"),
        vec![AP3, TWIN]
    );
    assert_eq!(one("mac E8:00:5e:00:53:89"), vec![AP3]);
    assert_eq!(one("ap.bssid == 42-00-5e-00-53-9c"), vec![TWIN]);
    assert_eq!(one("ap.bssid ~ \"e8:00:*\""), vec![AP1, AP3]);
    assert_eq!(one("ap.clients >= 1 and ap.beacons > 1"), vec![AP1]);
}

#[test]
fn clients_view_matches_the_contract() {
    let d = TempDir::new("clients");
    let idx = build(d.path(), &dataset(), 127);
    let got = clients(&idx, &req(View::WifiClients, ""));
    let want = vec![
        WifiClientRow {
            mac: C1.into(),
            randomized: false,
            first_ts: T + 5 * SEC,
            last_ts: T + 20 * SEC + 3,
            // 2 probes, auth, assoc, 2 data.
            frames: 6,
            probed_ssids: vec!["Cafe".into(), "HomeNet".into()],
            bssids: vec![AP1.into()],
            signal_max: Some(-46),
            first_frame: 6,
        },
        WifiClientRow {
            mac: C2.into(),
            randomized: true,
            first_ts: T + 7 * SEC,
            last_ts: T + 7 * SEC,
            frames: 1,
            probed_ssids: vec![],
            bssids: vec![],
            signal_max: Some(-70),
            first_frame: 8,
        },
        WifiClientRow {
            mac: C3.into(),
            randomized: false,
            first_ts: T + 16 * SEC,
            last_ts: T + 16 * SEC,
            frames: 0,
            probed_ssids: vec![],
            bssids: vec![AP3.into()],
            signal_max: None,
            first_frame: 17,
        },
    ];
    assert_eq!(got, want);
    let one = |f: &str| -> Vec<String> {
        clients(&idx, &req(View::WifiClients, f))
            .into_iter()
            .map(|a| a.mac)
            .collect()
    };
    assert_eq!(one("client.probed == Cafe"), vec![C1]);
    assert_eq!(one("client.probed ~ \"home*\""), vec![C1]);
    assert_eq!(one("client.randomized == true"), vec![C2]);
    assert_eq!(one(&format!("client.bssid == \"{AP3}\"")), vec![C3]);
    assert_eq!(one("mac DA:A1:19:00:00:01"), vec![C2]);
    assert_eq!(one("client.frames == 0"), vec![C3]);
}

#[test]
fn wifi_filters_shorthand_and_rejections() {
    let d = TempDir::new("filters");
    let idx = build(d.path(), &dataset(), 127);
    assert_eq!(frames(&idx, "wifi.kind == deauth"), vec![18, 19, 20, 21]);
    assert_eq!(
        frames(
            &idx,
            "wifi.kind in [probe_req, probe_resp] and wifi.channel == 11"
        ),
        vec![9, 10]
    );
    // Bare and quoted MACs, any case, compare lowercase.
    assert_eq!(
        frames(&idx, "wifi.tx == 42:00:5e:00:53:9C"),
        vec![9, 10, 18, 19, 20, 21]
    );
    assert_eq!(
        frames(
            &idx,
            "wifi.tx == \"42:00:5e:00:53:9c\" and wifi.kind == deauth"
        ),
        vec![18, 19, 20, 21]
    );
    // `mac X` matches any address column.
    assert_eq!(
        frames(&idx, &format!("mac {C3}")),
        vec![17],
        "C3 only as dst"
    );
    assert_eq!(frames(&idx, "mac DA:A1:19:00:00:01"), vec![8]);
    assert_eq!(
        frames(&idx, "wifi.ssid ~ \"CAFE\" or wifi.reason == 7"),
        vec![7, 18, 19, 20, 21]
    );
    assert_eq!(
        frames(&idx, "wifi.signal > -35"),
        vec![9, 10, 18, 19, 20, 21]
    );
    assert_eq!(frames(&idx, "not wifi.security == wpa2").len(), 21 - 5);
    assert_eq!(frames(&idx, "wifi.protected == true"), vec![14, 15, 16]);
    assert_eq!(frames(&idx, "wifi.len > 119"), vec![20, 21]);

    // Flow-family fields and IP shorthands do not apply on 802.11 views.
    for view in [View::Wifi, View::WifiAps, View::WifiClients] {
        for bad in [
            "host 10.0.0.5",
            "bytes_up > 1",
            "dns",
            "frame.len > 1",
            "mac nope",
            "mac 1.2.3.4",
            "wifi.src == 10.0.0.1",
        ] {
            let e = idx.query(&req(view, bad)).expect_err(bad);
            assert_eq!(e.code, ErrorCode::InvalidFilter, "{bad} on {view:?}");
            assert!(e.span.is_some(), "{bad}");
        }
        // hosts / flow_ids are invalid arguments on these views.
        let mut r = req(view, "");
        r.hosts = vec!["10.0.0.5".into()];
        assert_eq!(
            idx.query(&r).expect_err("hosts").code,
            ErrorCode::InvalidArgument
        );
        let mut r = req(view, "");
        r.flow_ids = vec![1];
        assert_eq!(
            idx.query(&r).expect_err("flow_ids").code,
            ErrorCode::InvalidArgument
        );
    }
    // wifi fields only on their own view; `mac` not on flow views.
    for (view, f) in [
        (View::WifiAps, "wifi.kind == beacon"),
        (View::Wifi, "ap.beacons > 1"),
        (View::WifiClients, "ap.beacons > 1"),
        (View::Flows, "wifi.kind == beacon"),
        (View::Flows, "mac aa:bb:cc:dd:ee:ff"),
        (View::Frames, "mac aa:bb:cc:dd:ee:ff"),
    ] {
        assert_eq!(
            idx.query(&req(view, f)).expect_err(f).code,
            ErrorCode::InvalidFilter,
            "{f} on {view:?}"
        );
    }
    // Wired views on an 802.11-only capture are empty, not errors.
    assert_eq!(
        idx.query(&req(View::Flows, "")).expect("flows").total,
        Some(0)
    );
}

#[test]
fn time_range_semantics_per_view() {
    let d = TempDir::new("time");
    let idx = build(d.path(), &dataset(), 127);
    let tr = TimeRange {
        start: T + 9 * SEC,
        end: T + 11 * SEC,
    };
    let mut r = req(View::Wifi, "");
    r.time_range = Some(tr);
    match idx.query(&r).expect("wifi").data {
        RowSet::Wifi(v) => {
            assert_eq!(
                v.iter().map(|w| w.frame_no).collect::<Vec<_>>(),
                vec![10, 11]
            )
        }
        o => panic!("{o:?}"),
    }
    // Overlap of [first_ts, last_ts] with [9 s, 11 s): all three APs (the
    // twin's last frame is exactly at 9 s).
    r.view = View::WifiAps;
    let got: Vec<String> = aps(&idx, &r).into_iter().map(|a| a.bssid).collect();
    assert_eq!(got, vec![AP1.to_string(), AP3.into(), TWIN.into()]);
    r.time_range = Some(TimeRange {
        start: T + 17 * SEC,
        end: T + 30 * SEC,
    });
    let got: Vec<String> = aps(&idx, &r).into_iter().map(|a| a.bssid).collect();
    assert_eq!(got, vec![AP1.to_string()]);
    r.view = View::WifiClients;
    let got: Vec<String> = clients(&idx, &r).into_iter().map(|a| a.mac).collect();
    assert_eq!(got, vec![C1.to_string()]);
    r.time_range = Some(TimeRange {
        start: T + 30 * SEC,
        end: T + 20 * SEC,
    });
    assert_eq!(
        idx.query(&r).expect_err("reversed").code,
        ErrorCode::InvalidArgument
    );
}

fn device_finding(entity: &str, score: f64, entity_type: &str) -> Finding {
    Finding {
        finding_id: format!("{entity}-{entity_type}"),
        title: "t".into(),
        detector: "wifi_deauth".into(),
        entity_type: entity_type.into(),
        entity: entity.into(),
        score,
        attack_technique: Some("T1498".into()),
        ts_first: T,
        ts_last: T + 21 * SEC,
        reasons: vec![Reason {
            rule_id: "wifi.deauth_flood".into(),
            signal: "rate".into(),
            value: 1.0,
            unit: None,
            weight: 50.0,
            explanation: "x".into(),
            attack_technique: None,
            evidence: Evidence {
                flow_ids: vec![],
                frame_nos: vec![18],
                truncated: false,
                total: 1,
            },
        }],
        verdict: None,
    }
}

#[test]
fn device_timeline_counts_frames_per_transmitter() {
    let d = TempDir::new("timeline");
    let idx = build(d.path(), &dataset(), 127);
    assert!(idx.device_lanes());
    let findings = vec![
        device_finding(TWIN, 88.0, "device"),
        device_finding(AP1, 99.0, "host"), // not a device finding: ignored
    ];
    let tl = |filter: &str, max_lanes: u32| {
        idx.timeline(
            &TimelineRequest {
                filter: filter.into(),
                time_range: None,
                bucket_ms: 100_000,
                max_lanes,
            },
            &findings,
        )
    };
    let lanes = tl("", 3).expect("timeline");
    assert_eq!(lanes.lane_kind, LaneKind::Device);
    let names: Vec<&str> = lanes.lanes.iter().map(|l| l.host.as_str()).collect();
    // TWIN: 2 + 4 = 6; C1: 6; AP1: 4 beacons + eapol + data = 6 (ties by
    // MAC text); then other.
    assert_eq!(names, vec![TWIN, C1, AP1, "other"]);
    assert_eq!(lanes.lanes[0].total, 6);
    assert_eq!(lanes.lanes[3].total, 3, "AP3 (2) + C2 (1)");
    assert!(lanes.lanes[3].is_other);
    let total: u64 = lanes.lanes.iter().map(|l| l.total).sum();
    assert_eq!(total, 21);
    let twin = &lanes.lanes[0];
    assert_eq!(twin.max_score, Some(88.0));
    assert_eq!(lanes.lanes[2].max_score, None, "host finding is ignored");
    let sum = |f: fn(&walleye_core::ipc::Bucket) -> Option<u32>| -> u32 {
        twin.buckets
            .iter()
            .map(|b| f(b).expect("device bucket"))
            .sum()
    };
    assert_eq!(sum(|b| b.wifi_probe), 2);
    assert_eq!(sum(|b| b.wifi_deauth), 4);
    assert_eq!(sum(|b| b.wifi_mgmt), 0);
    assert_eq!(sum(|b| b.wifi_data), 0);
    for l in &lanes.lanes {
        for b in &l.buckets {
            assert_eq!((b.dns, b.tls, b.http, b.bulk, b.other), (0, 0, 0, 0, 0));
        }
    }
    let ap1 = &lanes.lanes[2];
    let mgmt: u32 = ap1.buckets.iter().filter_map(|b| b.wifi_mgmt).sum();
    let data: u32 = ap1.buckets.iter().filter_map(|b| b.wifi_data).sum();
    assert_eq!((mgmt, data), (4, 2));

    // The filter applies with wifi.* fields.
    let lanes = tl("wifi.kind == deauth", 10).expect("filtered");
    assert_eq!(lanes.lanes.len(), 1);
    assert_eq!(lanes.lanes[0].host, TWIN);
    assert_eq!(
        tl("bytes_up > 1", 10).expect_err("flow field").code,
        ErrorCode::InvalidFilter
    );
}

#[test]
fn wired_capture_keeps_host_lanes_and_empty_wifi_views() {
    let d = TempDir::new("wired");
    let idx = build(d.path(), &[], 1);
    assert!(!idx.device_lanes());
    for v in [View::Wifi, View::WifiAps, View::WifiClients] {
        assert_eq!(idx.query(&req(v, "")).expect("empty").total, Some(0));
    }
    let lanes = idx
        .timeline(
            &TimelineRequest {
                filter: String::new(),
                time_range: None,
                bucket_ms: 1000,
                max_lanes: 5,
            },
            &[],
        )
        .expect("tl");
    assert_eq!(lanes.lane_kind, LaneKind::Host);
    assert!(idx.device_frames(AP1, None).expect("df").is_empty());
    // Detectors call for_each_wifi on every capture: it yields nothing here.
    let mut n = 0;
    idx.for_each_wifi(&mut |_| n += 1).expect("for_each_wifi");
    assert_eq!(n, 0);
    drop(idx);
    // A manifest that lists no `wifi` file at all (written before the table
    // existed) still opens with an empty `wifi` table and empty views.
    let m = d.path().join("manifest.json");
    let mut j: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&m).expect("read")).expect("json");
    j["files"]
        .as_object_mut()
        .expect("files")
        .remove("wifi")
        .expect("wifi entry");
    std::fs::write(&m, serde_json::to_vec(&j).expect("ser")).expect("write");
    let idx = Index::open(d.path()).expect("reopen without wifi entry");
    let mut n = 0;
    idx.for_each_wifi(&mut |_| n += 1).expect("for_each_wifi");
    assert_eq!(n, 0);
    for v in [View::Wifi, View::WifiAps, View::WifiClients] {
        assert_eq!(idx.query(&req(v, "")).expect("empty").total, Some(0));
    }
    // An index of the previous format is reported missing (rebuilt by the
    // engine), never served without its wifi table.
    drop(idx);
    j["version"] = serde_json::json!(2);
    std::fs::write(&m, serde_json::to_vec(&j).expect("ser")).expect("write");
    assert_eq!(
        Index::open(d.path()).err().map(|e| e.code),
        Some(ErrorCode::NotFound)
    );
    // Ethernet link type but only 802.11 rows and no flows → device lanes.
    let d2 = TempDir::new("mixed");
    assert!(build(d2.path(), &dataset(), 1).device_lanes());
}

#[test]
fn device_frames_lists_every_role_with_summaries() {
    let d = TempDir::new("device-frames");
    let idx = build(d.path(), &dataset(), 127);
    let f = idx.device_frames("42:00:5e:00:53:9C", None).expect("twin");
    assert_eq!(
        f.iter().map(|r| r.frame_no).collect::<Vec<_>>(),
        vec![9, 10, 18, 19, 20, 21]
    );
    assert_eq!(f[2].summary, format!("Deauth {TWIN} → {BCAST} reason 7"));
    assert_eq!(f[0].caplen, 109 + 36, "caplen from the frames table");
    assert_eq!(f[0].ts, T + 8 * SEC);
    let ap1 = idx.device_frames(AP1, None).expect("ap1");
    assert_eq!(ap1[0].summary, "Beacon \"HomeNet\" ch 6 wpa2");
    assert_eq!(ap1[2].summary, "Beacon (hidden) ch 6 wpa2");
    // C3 appears only as a destination.
    assert_eq!(
        idx.device_frames(C3, None)
            .expect("c3")
            .iter()
            .map(|r| r.frame_no)
            .collect::<Vec<_>>(),
        vec![17]
    );
    let tr = TimeRange {
        start: T + 20 * SEC + 1,
        end: T + 20 * SEC + 3,
    };
    assert_eq!(
        idx.device_frames(TWIN, Some(tr))
            .expect("range")
            .iter()
            .map(|r| r.frame_no)
            .collect::<Vec<_>>(),
        vec![19, 20]
    );
    for bad in ["", "nope", "1.2.3.4", "aa:bb:cc:dd:ee", "' OR 1=1 --"] {
        assert_eq!(
            idx.device_frames(bad, None).expect_err(bad).code,
            ErrorCode::InvalidArgument
        );
    }
    let rev = TimeRange {
        start: T + 9,
        end: T,
    };
    assert_eq!(
        idx.device_frames(TWIN, Some(rev)).expect_err("rev").code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn device_frames_are_capped() {
    let d = TempDir::new("cap");
    let mut w = IndexWriter::create(d.path()).expect("create");
    let scale = wifi_synth::Scale {
        rows: 30_000,
        aps: 1,
        clients: 3,
        seed: 1,
        checkpoint_rows: 0,
    };
    wifi_synth::generate(&mut w, &scale).expect("gen");
    let idx = Index::open(d.path()).expect("open");
    let only_ap = wifi_synth::mac(0x42, 0);
    let f = idx.device_frames(&only_ap, None).expect("df");
    assert_eq!(f.len(), walleye_core::backend::DEVICE_FRAMES_CAP);
    assert!(f.windows(2).all(|w| w[0].frame_no < w[1].frame_no));
    assert_eq!(f[0].frame_no, 1);
}

#[test]
fn autocomplete_suggests_wifi_kinds_ssids_and_macs() {
    let d = TempDir::new("ac");
    let idx = build(d.path(), &dataset(), 127);
    let labels = |s: &str| -> Vec<String> {
        idx.autocomplete(s, s.len() as u32)
            .expect(s)
            .into_iter()
            .filter(|x| x.kind == SuggestionKind::Value)
            .map(|x| x.label)
            .collect()
    };
    let k = labels("wifi.kind == ");
    for want in ["beacon", "probe_req", "deauth", "eapol"] {
        assert!(k.contains(&want.to_string()), "{k:?}");
    }
    assert_eq!(labels("wifi.kind == de"), vec!["deauth"]);
    assert!(labels("ap.security == ").contains(&"wpa2/wpa3".to_string()));
    let ssid = labels("wifi.ssid == ");
    assert_eq!(ssid.first().map(String::as_str), Some("HomeNet"));
    assert!(labels("ap.ssid == ").contains(&"HomeNet".to_string()));
    assert_eq!(labels("client.probed == \"Ca"), vec!["Cafe"]);
    let macs = labels("mac ");
    assert!(macs.contains(&AP1.to_string()) && macs.contains(&TWIN.to_string()));
    assert_eq!(labels("mac 42"), vec![TWIN]);
    assert!(labels("wifi.bssid == ").contains(&AP1.to_string()));
    // `mac` is offered as a keyword at a term start.
    assert!(
        idx.autocomplete("ma", 2)
            .expect("kw")
            .iter()
            .any(|x| x.label == "mac" && x.kind == SuggestionKind::Keyword)
    );
}

/// Paging over every 802.11 view and several sorts returns exactly the rows
/// of one big page (string keys on wifi_aps / wifi_clients).
#[test]
fn wifi_cursor_pagination_is_stable_for_every_sort() {
    let d = TempDir::new("paging");
    let mut w = IndexWriter::create(d.path()).expect("create");
    let scale = wifi_synth::Scale {
        rows: 60_000,
        aps: 400,
        clients: 1500,
        seed: 3,
        checkpoint_rows: 20_000,
    };
    wifi_synth::generate(&mut w, &scale).expect("gen");
    let idx = Index::open(d.path()).expect("open");
    let cases: &[(View, &str, Option<&str>)] = &[
        (View::Wifi, "", None),
        (View::Wifi, "wifi.kind == beacon", Some("ssid")),
        (View::Wifi, "", Some("signal_dbm")),
        (View::WifiAps, "", None),
        (View::WifiAps, "", Some("ssid")),
        (View::WifiAps, "", Some("channel")),
        (View::WifiAps, "", Some("signal_max")),
        (View::WifiAps, "", Some("randomized")),
        (View::WifiClients, "", None),
        (View::WifiClients, "", Some("signal_max")),
        (View::WifiClients, "", Some("probed_ssids")),
        (
            View::WifiClients,
            "client.randomized == true",
            Some("last_ts"),
        ),
    ];
    let key = |d: &RowSet| -> Vec<String> {
        match d {
            RowSet::Wifi(v) => v.iter().map(|r| r.frame_no.to_string()).collect(),
            RowSet::WifiAps(v) => v.iter().map(|r| r.bssid.clone()).collect(),
            RowSet::WifiClients(v) => v.iter().map(|r| r.mac.clone()).collect(),
            o => panic!("{o:?}"),
        }
    };
    for &(view, filter, col) in cases {
        for desc in [false, true] {
            let mut r = req(view, filter);
            r.sort = col.map(|c| Sort {
                column: c.into(),
                desc,
            });
            r.limit = 10_000;
            let all = idx.query(&r).expect("all");
            let want = key(&all.data);
            let total = all.total.expect("total");
            r.limit = 113;
            let mut got = Vec::new();
            let mut pages = 0;
            loop {
                let p = idx.query(&r).expect("page");
                assert_eq!(p.total, Some(total));
                got.extend(key(&p.data));
                pages += 1;
                match p.next_cursor {
                    Some(c) => r.cursor = Some(c),
                    None => break,
                }
                assert!(pages < 2_000);
            }
            if want.len() < 10_000 {
                assert_eq!(got, want, "{view:?} {col:?} desc={desc}");
            } else {
                assert_eq!(got.len() as u64, total);
            }
            if col.is_none() {
                break;
            }
        }
    }
    // The aggregates are internally consistent at this size.
    let mut r = req(View::WifiAps, "");
    r.limit = 10_000;
    let a = aps(&idx, &r);
    assert_eq!(a.len(), 400);
    let mut r = req(View::WifiClients, "");
    r.limit = 10_000;
    let c = clients(&idx, &r);
    assert_eq!(c.len(), 1500);
    assert!(c.iter().all(|x| x.first_ts <= x.last_ts));
    // Sort allowlist and foreign cursors behave as on other views.
    let mut r = req(View::WifiAps, "");
    r.sort = Some(Sort {
        column: "bssid; DROP TABLE wifi".into(),
        desc: false,
    });
    assert_eq!(
        idx.query(&r).expect_err("sort").code,
        ErrorCode::InvalidArgument
    );
    let mut r = req(View::WifiAps, "");
    r.limit = 5;
    let c = idx.query(&r).expect("p1").next_cursor.expect("more");
    let mut other = req(View::WifiClients, "");
    other.cursor = Some(c);
    assert_eq!(
        idx.query(&other).expect_err("foreign").code,
        ErrorCode::InvalidArgument
    );
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(f64::total_cmp);
    v[(((v.len() as f64) - 1.0) * p).round() as usize]
}

/// Perf gate for the derived views at scale (CONTRACTS §9: p95 < 1 s).
/// `WALLEYE_WIFI_ROWS` (default 2 000 000) rows, ~2 000 APs, ~40 000 clients.
/// Run: `cargo test -p walleye-index --release --test wifi -- --ignored --nocapture`.
#[test]
#[ignore = "slow: builds a 2 M-row 802.11 index"]
fn wifi_views_at_scale() {
    let rows = std::env::var("WALLEYE_WIFI_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000_000u64);
    let d = TempDir::new("scale");
    let t = std::time::Instant::now();
    let mut w = IndexWriter::create(d.path()).expect("create");
    let scale = wifi_synth::Scale {
        rows,
        aps: 2_000,
        clients: 40_000,
        seed: 11,
        checkpoint_rows: 500_000,
    };
    wifi_synth::generate(&mut w, &scale).expect("gen");
    drop(w);
    println!(
        "wrote {rows} wifi rows in {:.1} s",
        t.elapsed().as_secs_f64()
    );
    let t = std::time::Instant::now();
    let idx = Index::open(d.path()).expect("open");
    println!(
        "Index::open (incl. wifi_aps/wifi_clients) {:.0} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    type Case<'a> = (View, &'a str, Option<(&'a str, bool)>);
    let cases: Vec<Case> = vec![
        (View::Wifi, "", None),
        (View::Wifi, "wifi.kind == deauth and wifi.reason == 7", None),
        (View::Wifi, "mac e8:00:00:00:00:2b", None),
        (
            View::Wifi,
            "wifi.ssid ~ \"net-1*\"",
            Some(("signal_dbm", true)),
        ),
        (View::WifiAps, "", None),
        (View::WifiAps, "ap.security == open", Some(("ssid", false))),
        (View::WifiAps, "ap.clients > 10", Some(("signal_max", true))),
        (View::WifiClients, "", None),
        (View::WifiClients, "client.probed ~ \"net-1*\"", None),
        (
            View::WifiClients,
            "client.randomized == true",
            Some(("last_ts", true)),
        ),
    ];
    println!("\n| view | filter | sort | total | p50 ms | p95 ms | max ms |");
    println!("|---|---|---|---:|---:|---:|---:|");
    let mut worst: f64 = 0.0;
    for (view, filter, sort) in cases {
        let mut r = req(view, filter);
        r.limit = 100;
        r.sort = sort.map(|(c, desc)| Sort {
            column: c.into(),
            desc,
        });
        let total = idx.query(&r).expect(filter).total.unwrap_or(0);
        let mut v: Vec<f64> = (0..10)
            .map(|_| {
                let t = std::time::Instant::now();
                idx.query(&r).expect(filter);
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();
        let max = v.iter().cloned().fold(0.0, f64::max);
        let (p50, p95) = (pct(&mut v, 0.5), pct(&mut v, 0.95));
        worst = worst.max(p95);
        println!("| {view:?} | `{filter}` | {sort:?} | {total} | {p50:.1} | {p95:.1} | {max:.1} |");
    }
    let mut v: Vec<f64> = (0..10)
        .map(|_| {
            let t = std::time::Instant::now();
            idx.timeline(
                &TimelineRequest {
                    filter: String::new(),
                    time_range: None,
                    bucket_ms: 1_000,
                    max_lanes: 50,
                },
                &[],
            )
            .expect("tl");
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    let p95 = pct(&mut v, 0.95);
    worst = worst.max(p95);
    println!(
        "| device timeline, 50 lanes | | | | {:.1} | {p95:.1} | |",
        pct(&mut v, 0.5)
    );
    let ap = wifi_synth::mac(0xe8, 1);
    let mut v: Vec<f64> = (0..10)
        .map(|_| {
            let t = std::time::Instant::now();
            idx.device_frames(&ap, None).expect("df");
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    let p95 = pct(&mut v, 0.95);
    worst = worst.max(p95);
    println!(
        "| device_frames(AP) | | | | {:.1} | {p95:.1} | |",
        pct(&mut v, 0.5)
    );
    println!("\nworst p95 {worst:.1} ms (gate < 1000 ms)");
    assert!(worst < 1000.0, "p95 gate");
}
