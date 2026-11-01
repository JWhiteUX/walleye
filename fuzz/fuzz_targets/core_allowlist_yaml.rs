//! `Allowlist::from_yaml` over arbitrary text (rules/allowlist.yaml is
//! user-editable and may be shared between analysts).
//!
//! Invariants: no panic; a list that parses has only valid CIDRs; matching
//! with its own entries never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use walleye_core::{Allowlist, allowlist::parse_cidr};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(list) = Allowlist::from_yaml(text) else {
        return;
    };
    for c in &list.cidrs {
        assert!(
            parse_cidr(&c.cidr).is_some(),
            "accepted bad cidr {:?}",
            c.cidr
        );
    }
    for d in &list.domains {
        // An entry must match its own suffix (unless empty after trimming).
        let s = d.suffix.trim_end_matches('.');
        if !s.is_empty() {
            assert!(
                list.domain(s).is_some(),
                "suffix {s:?} does not match itself"
            );
        }
        let _ = list.domain(&format!("a.{}", d.suffix));
    }
    for j in &list.ja4 {
        assert!(list.ja4(&j.value).is_some());
    }
    let _ = list.ip("10.0.0.1");
    let _ = list.ip("::1");
});
