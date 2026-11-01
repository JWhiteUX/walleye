//! An 802.11-only capture (wifi rows, no flows) through the engine: open,
//! detect, query the Wi-Fi views, device timeline, device_frames, pins and
//! the report. The index is pre-built with `IndexWriter` (independent of the
//! 802.11 ingest work), so the engine finds a complete index and skips ingest.

use std::{path::PathBuf, sync::atomic::AtomicBool};

use walleye_core::{
    Backend, CaptureFormat, CaptureRow, FrameRow, WifiKind, WifiRow,
    ipc::{EvidenceRef, LaneKind, QueryRequest, ReportFormat, RowSet, TimelineRequest, View},
    sink::{IndexSink, RecordBatch},
};
use walleye_engine::{Engine, EngineConfig};
use walleye_index::IndexWriter;

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

const AP: &str = "e8:00:5e:00:53:88";
const STA: &str = "a4:83:e7:11:22:33";
const ATTACKER: &str = "42:00:5e:00:53:9c";
const BCAST: &str = "ff:ff:ff:ff:ff:ff";

fn row(frame_no: u64, kind: WifiKind, src: &str, dst: &str, tx: &str) -> WifiRow {
    let adv = matches!(kind, WifiKind::Beacon | WifiKind::ProbeResp);
    WifiRow {
        ts: 1_700_000_000_000_000 + frame_no as i64 * 100_000,
        frame_no,
        kind,
        protected: kind == WifiKind::Data,
        retry: false,
        src: Some(src.into()),
        dst: Some(dst.into()),
        tx: Some(tx.into()),
        bssid: Some(AP.into()),
        channel: Some(6),
        freq_mhz: Some(2437),
        signal_dbm: Some(-40),
        ssid: adv.then(|| "HomeNet".to_string()),
        security: adv.then(|| "wpa2".to_string()),
        reason: (kind == WifiKind::Deauth).then_some(7),
        seq: Some(frame_no as u16),
        len: 120,
    }
}

fn rows() -> Vec<WifiRow> {
    let mut v = Vec::new();
    let mut n = 0;
    let mut push = |k, s: &str, d: &str, t: &str, v: &mut Vec<WifiRow>| {
        n += 1;
        v.push(row(n, k, s, d, t));
    };
    for _ in 0..20 {
        push(WifiKind::Beacon, AP, BCAST, AP, &mut v);
        push(WifiKind::Data, STA, AP, STA, &mut v);
        push(WifiKind::Data, AP, STA, AP, &mut v);
    }
    for i in 0..40 {
        let dst = if i % 2 == 0 { BCAST } else { STA };
        push(WifiKind::Deauth, AP, dst, ATTACKER, &mut v);
    }
    v
}

#[test]
fn wifi_only_capture_opens_and_serves_wifi_views() {
    let tmp = tempfile::tempdir().expect("tmp");
    // The capture bytes are only hashed (the index below is already complete).
    let pcap = tmp.path().join("wifi.pcap");
    std::fs::write(&pcap, b"walleye 802.11 engine test capture").expect("write");
    let sha = walleye_ingest::hash_file(&pcap, &mut |_| {}).expect("hash");
    let data = tmp.path().join("data");
    let index_dir = data.join("captures").join(&sha[..16]).join("index");
    let wifi = rows();
    let cap = CaptureRow {
        capture_id: sha[..16].to_string(),
        path: pcap.to_string_lossy().into_owned(),
        sha256: sha.clone(),
        size_bytes: 34,
        format: CaptureFormat::Pcap,
        first_ts: wifi[0].ts,
        last_ts: wifi[wifi.len() - 1].ts,
        link_type: 127,
        frame_count: wifi.len() as u64,
    };
    let mut w = IndexWriter::create(&index_dir).expect("writer");
    w.begin(&cap).expect("begin");
    w.write(RecordBatch::Frames(
        wifi.iter()
            .map(|r| FrameRow {
                frame_no: r.frame_no,
                ts: r.ts,
                file_offset: 24 + r.frame_no * 200,
                caplen: 156,
                wirelen: 156,
                flow_id: None,
                direction: None,
                tcp_flags: None,
                payload_len: 0,
                link_type: Some(127),
            })
            .collect(),
    ))
    .expect("frames");
    w.write(RecordBatch::Wifi(wifi.clone())).expect("wifi");
    w.finish(&cap).expect("finish");
    drop(w);

    let engine = Engine::new(EngineConfig::new(&data, rules_dir())).expect("engine");
    let cancel = AtomicBool::new(false);
    let s = engine
        .open_blocking(pcap.to_str().expect("utf8"), &cancel, &mut |p| {
            assert_ne!(
                p.phase,
                walleye_core::ipc::IngestPhase::Indexing,
                "complete index must not be rebuilt"
            );
        })
        .expect("open");
    assert_eq!(s.capture.link_type, 127);

    let q = |view: View, filter: &str| {
        engine
            .query(&QueryRequest {
                filter: filter.into(),
                view,
                time_range: None,
                hosts: vec![],
                flow_ids: vec![],
                sort: None,
                limit: 100,
                cursor: None,
            })
            .expect(filter)
    };
    assert_eq!(q(View::Flows, "").total, Some(0));
    assert_eq!(q(View::Wifi, "").total, Some(wifi.len() as u64));
    assert_eq!(q(View::Wifi, "wifi.kind == deauth").total, Some(40));
    match q(View::WifiAps, "").data {
        RowSet::WifiAps(a) => {
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].bssid, AP);
            assert_eq!(a[0].ssid.as_deref(), Some("HomeNet"));
            assert_eq!((a[0].beacons, a[0].clients), (20, 1));
        }
        o => panic!("{o:?}"),
    }
    match q(View::WifiClients, &format!("mac {STA}")).data {
        RowSet::WifiClients(c) => {
            assert_eq!(c.len(), 1);
            assert_eq!(c[0].bssids, vec![AP.to_string()]);
        }
        o => panic!("{o:?}"),
    }

    let lanes = engine
        .timeline(&TimelineRequest {
            filter: String::new(),
            time_range: None,
            bucket_ms: 1_000,
            max_lanes: 10,
        })
        .expect("timeline");
    assert_eq!(lanes.lane_kind, LaneKind::Device);
    assert_eq!(lanes.lanes[0].host, ATTACKER);

    let df = engine.device_frames(ATTACKER, None).expect("device frames");
    assert_eq!(df.len(), 40);
    assert!(df[0].summary.starts_with("Deauth "), "{}", df[0].summary);
    assert_eq!(df[0].caplen, 156);

    // Pins on 802.11 frames resolve to frames with no flows.
    let pin = engine
        .case_pin(
            &s.case_id,
            &EvidenceRef::Frame {
                frame_no: df[0].frame_no,
            },
            "first deauth",
        )
        .expect("pin");
    assert_eq!(pin.resolved.frame_nos, vec![df[0].frame_no]);
    assert!(pin.resolved.flow_ids.is_empty());
    let report = engine
        .export_report(&s.case_id, ReportFormat::Markdown, None)
        .expect("report");
    assert!(std::path::Path::new(&report).exists());
}
