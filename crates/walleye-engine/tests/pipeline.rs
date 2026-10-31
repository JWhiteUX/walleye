//! End-to-end: generated capture → ingest → index → detect → IOCs → case →
//! exports, through the same `Backend` trait the Tauri commands use.

use std::{path::PathBuf, sync::atomic::AtomicBool};

use walleye_core::{
    Backend, Verdict,
    ipc::{EvidenceRef, IocFormat, QueryRequest, ReportFormat, RowSet, TimelineRequest, View},
};
use walleye_engine::{Engine, EngineConfig};
use walleye_gen::{Options, Scenario};

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

fn make_capture(dir: &std::path::Path, scenario: Scenario, minutes: u64) -> (PathBuf, Vec<String>) {
    let mut opts = Options::new(scenario, 7);
    opts.duration_min = minutes;
    let path = dir.join(format!("{}.pcap", scenario.name()));
    let f = std::fs::File::create(&path).expect("create");
    let sum = walleye_gen::generate(&opts, std::io::BufWriter::new(f)).expect("generate");
    (path, sum.labels.c2_hosts)
}

#[test]
fn beacon_capture_end_to_end() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (pcap, c2) = make_capture(tmp.path(), Scenario::Beacon, 45);
    let engine =
        Engine::new(EngineConfig::new(tmp.path().join("data"), rules_dir())).expect("engine");

    let cancel = AtomicBool::new(false);
    let mut phases = Vec::new();
    let session = engine
        .open_blocking(pcap.to_str().expect("utf8"), &cancel, &mut |p| {
            phases.push(p.phase)
        })
        .expect("open");
    assert_eq!(session.capture.sha256.len(), 64);
    assert!(session.capture.frame_count > 1000);
    assert_eq!(
        phases.last().copied(),
        Some(walleye_core::ipc::IngestPhase::Done)
    );

    // Detection: the labelled C2 host is in the top 5, with evidence.
    let findings = engine.findings(None).expect("findings");
    let rank = findings.iter().position(|f| c2.contains(&f.entity));
    assert!(
        matches!(rank, Some(r) if r < 5),
        "C2 {c2:?} rank {rank:?} in {:?}",
        findings
            .iter()
            .map(|f| (&f.entity, f.score))
            .collect::<Vec<_>>()
    );
    for f in &findings {
        assert!(!f.reasons.is_empty());
        assert!(f.reasons.iter().all(|r| !r.evidence.is_empty()));
    }

    // Every evidence frame reproduces: it decodes from the capture bytes.
    let top = &findings[rank.expect("rank")];
    let frame_no = top.reasons[0].evidence.frame_nos[0];
    let pkt = engine.packet(frame_no).expect("packet");
    assert_eq!(pkt.bytes_hex.len(), pkt.caplen as usize * 2);
    assert!(!pkt.decode_tree.is_empty());

    // Query with a filter, then timeline.
    let page = engine
        .query(&QueryRequest {
            filter: format!("host {}", top.entity),
            view: View::Flows,
            time_range: None,
            hosts: vec![],
            flow_ids: vec![],
            sort: None,
            limit: 50,
            cursor: None,
        })
        .expect("query");
    let RowSet::Flows(rows) = &page.data else {
        panic!("view")
    };
    assert!(!rows.is_empty());
    let lanes = engine
        .timeline(&TimelineRequest {
            filter: String::new(),
            time_range: None,
            bucket_ms: 60_000,
            max_lanes: 10,
        })
        .expect("timeline");
    assert!(
        lanes
            .lanes
            .iter()
            .any(|l| l.host == top.entity && l.max_score.is_some())
    );

    // Case: verdict, pin, note edit, exports carry the SHA-256.
    let case_id = session.case_id.clone();
    engine
        .set_verdict(&top.finding_id, Verdict::Suspicious, "c2")
        .expect("verdict");
    assert_eq!(
        engine.findings(None).expect("f")[rank.expect("r")].verdict,
        Some(Verdict::Suspicious)
    );
    let pin = engine
        .case_pin(
            &case_id,
            &EvidenceRef::Finding {
                finding_id: top.finding_id.clone(),
            },
            "beacon",
        )
        .expect("pin");
    assert!(!pin.resolved.frame_nos.is_empty());
    let edited = engine
        .case_update_note(&case_id, &pin.pin_id, "beacon, confirmed")
        .expect("edit");
    assert_eq!(edited.pin_id, pin.pin_id);
    let case = engine.get_case(&case_id).expect("case");
    assert!(!case.queries.is_empty(), "queries are logged");

    let csv = engine.export_iocs(&case_id, IocFormat::Csv).expect("csv");
    let json =
        std::fs::read_to_string(engine.export_iocs(&case_id, IocFormat::Json).expect("json"))
            .expect("read");
    assert!(json.contains(&session.capture.sha256));
    assert!(std::path::Path::new(&csv).is_file());
    let md = std::fs::read_to_string(
        engine
            .export_report(&case_id, ReportFormat::Markdown, None)
            .expect("md"),
    )
    .expect("read");
    assert!(md.contains(&session.capture.sha256));
    assert!(md.contains(&format!("frames {frame_no}")) || md.contains(&frame_no.to_string()));
    let pdf = std::fs::read(
        engine
            .export_report(&case_id, ReportFormat::Pdf, None)
            .expect("pdf"),
    )
    .expect("read");
    assert!(pdf.starts_with(b"%PDF"));

    // Re-opening the same capture reuses the index (no re-ingest).
    let mut saw_indexing = false;
    engine
        .open_blocking(pcap.to_str().expect("utf8"), &cancel, &mut |p| {
            saw_indexing |= p.phase == walleye_core::ipc::IngestPhase::Indexing
        })
        .expect("reopen");
    assert!(!saw_indexing, "complete index must be reused");
    // Verdicts and pins survive.
    assert_eq!(engine.get_case(&case_id).expect("case").pins.len(), 1);
}

#[test]
fn rejects_bad_paths() {
    let tmp = tempfile::tempdir().expect("tmp");
    let engine =
        Engine::new(EngineConfig::new(tmp.path().join("data"), rules_dir())).expect("engine");
    for p in [
        "",
        "/definitely/not/here.pcap",
        tmp.path().to_str().expect("utf8"),
    ] {
        assert!(engine.open_capture(p).is_err(), "{p:?}");
    }
    let empty = tmp.path().join("empty.pcap");
    std::fs::write(&empty, b"").expect("write");
    assert!(engine.open_capture(empty.to_str().expect("utf8")).is_err());
    let junk = tmp.path().join("junk.pcap");
    std::fs::write(&junk, b"this is not a capture at all").expect("write");
    let err = engine
        .open_blocking(
            junk.to_str().expect("utf8"),
            &AtomicBool::new(false),
            &mut |_| {},
        )
        .expect_err("junk");
    assert_eq!(err.code, walleye_core::ErrorCode::BadCapture, "{err:?}");
}

#[test]
fn saved_queries_persist_and_validate() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cfg = EngineConfig::new(tmp.path().join("data"), rules_dir());
    let e = Engine::new(cfg.clone()).expect("engine");
    let q = walleye_core::ipc::SavedQuery {
        name: "big".into(),
        filter: "bytes > 1MB".into(),
        view: View::Flows,
    };
    e.save_query(&q).expect("save");
    assert!(
        e.save_query(&walleye_core::ipc::SavedQuery {
            filter: "(((".into(),
            ..q.clone()
        })
        .is_err()
    );
    drop(e);
    let e2 = Engine::new(cfg).expect("engine");
    assert_eq!(e2.list_saved_queries().expect("list"), vec![q]);
}
