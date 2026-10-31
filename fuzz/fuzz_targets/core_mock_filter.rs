//! `mock_parse_filter` (the mock backend's filter check, used by both the
//! Rust and the browser mock until the real compiler lands).
//!
//! Invariants: no panic; an error is `invalid_filter` with a span inside the
//! text (`start <= end <= len`), so the UI can underline it without slicing
//! out of bounds; every returned host is a token of the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use walleye_core::{ErrorCode, mock::mock_parse_filter};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match mock_parse_filter(text) {
        Ok(hosts) => {
            for h in hosts {
                assert!(text.contains(h.as_str()));
            }
        }
        Err(e) => {
            assert_eq!(e.code, ErrorCode::InvalidFilter);
            let span = e.span.expect("invalid_filter carries a span");
            assert!(span.start <= span.end, "span {span:?}");
            assert!(
                span.end as usize <= text.len(),
                "span {span:?} past len {}",
                text.len()
            );
            assert!(text.is_char_boundary(span.start as usize));
            assert!(text.is_char_boundary(span.end as usize));
        }
    }
});
