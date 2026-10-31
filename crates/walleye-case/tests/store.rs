#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

use common::*;
use walleye_case::{CaseStore, store::SCHEMA_VERSION};
use walleye_core::{
    ErrorCode, Evidence, Verdict,
    ipc::{EvidenceRef, QueryLogEntry, TimeRange, View},
};

#[test]
fn pins_round_trip_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let cap = capture();
    let resolved = ev(&[2], &[23]);
    let (a, b, n) = {
        let s = CaseStore::open(dir.path(), &cap).unwrap();
        let a = s
            .pin(&EvidenceRef::Frame { frame_no: 23 }, "staging", &resolved)
            .unwrap();
        let b = s
            .pin(
                &EvidenceRef::Query {
                    filter: "host 10.0.0.23".into(),
                    view: View::Flows,
                    time_range: Some(TimeRange { start: 1, end: 2 }),
                },
                "",
                &ev(&[3, 4], &[100, 110]),
            )
            .unwrap();
        let n = s
            .pin(&EvidenceRef::Note, "Escalated to IR", &Evidence::default())
            .unwrap();
        (a, b, n)
    };
    assert!(dir.path().join("case.sqlite").exists());
    assert_eq!(
        (a.pin_id.as_str(), b.pin_id.as_str(), n.pin_id.as_str()),
        ("pin-1", "pin-2", "pin-3")
    );
    assert_eq!(a.resolved, resolved);

    // reopen: everything is still there, in pin order
    let s = CaseStore::open(dir.path(), &cap).unwrap();
    let c = s.get_case().unwrap();
    assert_eq!(c.case_id, cap.capture_id);
    assert_eq!(c.capture, cap);
    assert_eq!(c.pins, vec![a.clone(), b.clone(), n.clone()]);

    s.unpin("pin-2").unwrap();
    assert_eq!(s.get_case().unwrap().pins, vec![a, n]);
    assert_eq!(s.unpin("pin-2").unwrap_err().code, ErrorCode::NotFound);
    // ids are never reused
    let d = s
        .pin(&EvidenceRef::Flow { flow_id: 3 }, "", &ev(&[3], &[100]))
        .unwrap();
    assert_eq!(d.pin_id, "pin-4");
}

#[test]
fn notes_and_validation() {
    let s = CaseStore::open_in_memory(&capture()).unwrap();
    assert_eq!(
        s.pin(&EvidenceRef::Note, "  ", &Evidence::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        s.pin(
            &EvidenceRef::Frame { frame_no: 1 },
            "",
            &Evidence::default()
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidArgument
    );
    let big = "x".repeat(walleye_case::store::MAX_NOTE_BYTES + 1);
    assert_eq!(
        s.pin(&EvidenceRef::Note, &big, &Evidence::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    // a note never carries evidence, even if some was passed
    let n = s.pin(&EvidenceRef::Note, "hello", &ev(&[1], &[1])).unwrap();
    assert!(n.resolved.is_empty());

    let edited = s.update_note(&n.pin_id, "hello again").unwrap();
    assert_eq!(edited.note, "hello again");
    assert_eq!(edited.pin_id, n.pin_id);
    assert_eq!(
        s.update_note(&n.pin_id, " ").unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        s.update_note("pin-99", "x").unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn hostile_strings_are_stored_verbatim() {
    // Parameterized SQL: quotes and SQL fragments are just data.
    let s = CaseStore::open_in_memory(&capture()).unwrap();
    let evil = "'); DROP TABLE pins; -- \"\u{0}\u{202e}";
    let p = s
        .pin(
            &EvidenceRef::Finding {
                finding_id: evil.into(),
            },
            evil,
            &ev(&[1], &[1]),
        )
        .unwrap();
    s.set_verdict("f1", Verdict::Benign, evil).unwrap();
    s.log_query(&QueryLogEntry {
        filter: evil.into(),
        view: View::Dns,
        time_range: None,
        sql: Some(evil.into()),
        rows: 3,
        at: 5,
    })
    .unwrap();
    let c = s.get_case().unwrap();
    assert_eq!(c.pins, vec![p]);
    assert_eq!(c.pins[0].note, evil);
    assert_eq!(c.verdicts[0].note, evil);
    assert_eq!(c.queries[0].filter, evil);
}

#[test]
fn verdicts_upsert_latest() {
    let s = CaseStore::open_in_memory(&capture()).unwrap();
    s.set_verdict("f1", Verdict::NeedsReview, "").unwrap();
    s.set_verdict("f2", Verdict::Benign, "WSUS").unwrap();
    s.set_verdict("f1", Verdict::Suspicious, "confirmed")
        .unwrap();
    let v = s.verdicts().unwrap();
    assert_eq!(v.len(), 2);
    let f1 = v.iter().find(|e| e.finding_id == "f1").unwrap();
    assert_eq!(
        (f1.verdict, f1.note.as_str()),
        (Verdict::Suspicious, "confirmed")
    );
    assert_eq!(
        s.set_verdict("", Verdict::Benign, "").unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn query_log_keeps_order_and_ranges() {
    let s = CaseStore::open_in_memory(&capture()).unwrap();
    let q1 = QueryLogEntry {
        filter: "host 10.0.0.23".into(),
        view: View::Flows,
        time_range: Some(TimeRange { start: 10, end: 20 }),
        sql: Some("SELECT ? ".into()),
        rows: 61,
        at: 100,
    };
    let q2 = QueryLogEntry {
        filter: "".into(),
        view: View::Tls,
        time_range: None,
        sql: None,
        rows: 0,
        at: 101,
    };
    s.log_query(&q1).unwrap();
    s.log_query(&q2).unwrap();
    assert_eq!(s.queries().unwrap(), vec![q1, q2]);
}

#[test]
fn schema_is_versioned_and_capture_checked() {
    let dir = tempfile::tempdir().unwrap();
    let s = CaseStore::open(dir.path(), &capture()).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    drop(s);
    // another capture's case dir is refused
    let mut other = capture();
    other.sha256 = "b".repeat(64);
    let err = CaseStore::open(dir.path(), &other).err().unwrap();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    // a store from a newer build is refused instead of being corrupted
    {
        let conn = rusqlite::Connection::open(dir.path().join("case.sqlite")).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
    }
    let err = CaseStore::open(dir.path(), &capture()).err().unwrap();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn store_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<CaseStore>();
}
