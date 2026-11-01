//! Serde deserialization of every IPC argument type from arbitrary JSON, as
//! Tauri does for `invoke(cmd, args)`: each command's args arrive as one JSON
//! object whose keys are the snake_case argument names.
//!
//! Input: first byte selects the type, the rest is JSON.
//! Invariants: no panic; a value that parses re-serializes and parses again;
//! for float-free types the round trip is exact.
#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::{Serialize, de::DeserializeOwned};
use walleye_core::{
    Verdict,
    ipc::{
        EvidenceRef, FindingsFilter, IocFormat, QueryRequest, ReportFormat, SavedQuery, Sort,
        TimeRange, TimelineRequest, View,
    },
};

/// Parse; if OK, re-encode and parse again; compare when `exact`.
fn rt<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(json: &[u8], exact: bool) {
    let Ok(v) = serde_json::from_slice::<T>(json) else {
        return;
    };
    let s = serde_json::to_vec(&v).expect("re-serialize");
    let back: T = serde_json::from_slice(&s).expect("re-parse own output");
    if exact {
        assert_eq!(v, back);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, json)) = data.split_first() else {
        return;
    };
    match sel % 12 {
        0 => rt::<QueryRequest>(json, true),
        1 => rt::<TimelineRequest>(json, true),
        2 => rt::<FindingsFilter>(json, false), // min_score is f64
        3 => rt::<EvidenceRef>(json, true),
        4 => rt::<SavedQuery>(json, true),
        5 => rt::<Sort>(json, true),
        6 => rt::<TimeRange>(json, true),
        7 => rt::<View>(json, true),
        8 => rt::<Verdict>(json, true),
        9 => rt::<IocFormat>(json, true),
        10 => rt::<ReportFormat>(json, true),
        // Whole-args objects, keyed like the Tauri commands.
        _ => {
            #[derive(serde::Deserialize, Serialize, PartialEq, Debug)]
            struct CasePinArgs {
                case_id: String,
                evidence: EvidenceRef,
                note: String,
            }
            rt::<CasePinArgs>(json, true);
        }
    }
});
