//! Drives `MockBackend` exactly as Tauri's `invoke` would: a command name and
//! a JSON args object (snake_case keys), deserialized into the command's
//! argument types, then dispatched. Mirrors app/src-tauri/src/commands.rs.
//!
//! Input: first byte selects the command, the rest is the args JSON.
//! Invariant: no panic for any args (in release builds `panic = "abort"`, so a
//! panic in a command kills the app). Export commands are excluded because
//! they write files; they are covered by review instead.
//!
//! The backend is shared across iterations (parsing the 4 MB mock dataset per
//! input would be too slow), so mutating commands accumulate a little state.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use walleye_core::{
    Backend, Verdict,
    ipc::{EvidenceRef, FindingsFilter, QueryRequest, SavedQuery, TimelineRequest},
    mock::MockBackend,
};

fn backend() -> &'static MockBackend {
    static B: OnceLock<MockBackend> = OnceLock::new();
    B.get_or_init(MockBackend::preopened)
}

#[derive(Deserialize)]
struct Path {
    path: String,
}
#[derive(Deserialize)]
struct Job {
    job_id: String,
}
#[derive(Deserialize)]
struct Req<T> {
    req: T,
}
#[derive(Deserialize)]
struct FlowId {
    flow_id: u64,
}
#[derive(Deserialize)]
struct FrameNo {
    frame_no: u64,
}
#[derive(Deserialize)]
struct Auto {
    partial_filter: String,
    cursor_pos: u32,
}
#[derive(Deserialize)]
struct Save {
    query: SavedQuery,
}
#[derive(Deserialize)]
struct Name {
    name: String,
}
#[derive(Deserialize)]
struct Findings {
    filter: Option<FindingsFilter>,
}
#[derive(Deserialize)]
struct SetVerdict {
    finding_id: String,
    verdict: Verdict,
    note: String,
}
#[derive(Deserialize)]
struct CaseId {
    case_id: String,
}
#[derive(Deserialize)]
struct CasePin {
    case_id: String,
    evidence: EvidenceRef,
    note: String,
}
#[derive(Deserialize)]
struct CaseUnpin {
    case_id: String,
    pin_id: String,
}

fn args<T: for<'de> Deserialize<'de>>(json: &[u8]) -> Option<T> {
    serde_json::from_slice(json).ok()
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, json)) = data.split_first() else {
        return;
    };
    let b = backend();
    // Results are ignored: errors are fine, panics are not.
    match sel % 18 {
        0 => {
            if let Some(a) = args::<Path>(json) {
                let _ = b.open_capture(&a.path);
            }
        }
        1 => {
            if let Some(a) = args::<Job>(json) {
                let _ = b.ingest_status(&a.job_id);
            }
        }
        2 => {
            if let Some(a) = args::<Job>(json) {
                let _ = b.cancel_ingest(&a.job_id);
            }
        }
        3 => {
            let _ = b.current_capture();
        }
        4 => {
            if let Some(a) = args::<Req<QueryRequest>>(json) {
                let _ = b.query(&a.req);
            }
        }
        5 => {
            if let Some(a) = args::<Req<TimelineRequest>>(json) {
                let _ = b.timeline(&a.req);
            }
        }
        6 => {
            if let Some(a) = args::<FlowId>(json) {
                let _ = b.flow_frames(a.flow_id);
            }
        }
        7 => {
            if let Some(a) = args::<FrameNo>(json) {
                let _ = b.packet(a.frame_no);
            }
        }
        8 => {
            if let Some(a) = args::<Auto>(json) {
                if let Ok(sugg) = b.autocomplete(&a.partial_filter, a.cursor_pos) {
                    for s in sugg {
                        // The UI splices insert_text into [replace_start, replace_end).
                        assert!(s.replace_start <= s.replace_end, "{s:?}");
                        assert!(s.replace_end as usize <= a.partial_filter.len(), "{s:?}");
                    }
                }
            }
        }
        9 => {
            let _ = b.list_saved_queries();
        }
        10 => {
            if let Some(a) = args::<Save>(json) {
                let _ = b.save_query(&a.query);
            }
        }
        11 => {
            if let Some(a) = args::<Name>(json) {
                let _ = b.delete_saved_query(&a.name);
            }
        }
        12 => {
            if let Some(a) = args::<Findings>(json) {
                let _ = b.findings(a.filter.as_ref());
            }
        }
        13 => {
            if let Some(a) = args::<SetVerdict>(json) {
                let _ = b.set_verdict(&a.finding_id, a.verdict, &a.note);
            }
        }
        14 => {
            if let Some(a) = args::<CaseId>(json) {
                let _ = b.iocs(&a.case_id);
            }
        }
        15 => {
            if let Some(a) = args::<CaseId>(json) {
                let _ = b.get_case(&a.case_id);
            }
        }
        16 => {
            if let Some(a) = args::<CasePin>(json) {
                let _ = b.case_pin(&a.case_id, &a.evidence, &a.note);
            }
        }
        _ => {
            if let Some(a) = args::<CaseUnpin>(json) {
                let _ = b.case_unpin(&a.case_id, &a.pin_id);
            }
        }
    }
});
