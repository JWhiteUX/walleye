//! `RuleDef::from_yaml` over arbitrary text (rules/*.yaml load at runtime and
//! can be shared between analysts). Covers YAML anchors/aliases (expansion
//! bombs), deep nesting and odd scalars in `params`.
//!
//! Invariants: no panic, no unbounded memory (libFuzzer -rss_limit_mb), and a
//! parsed rule survives a serialize/parse round trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use walleye_core::rules::RuleDef;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(rule) = RuleDef::from_yaml(text) else {
        return;
    };
    // Round trip through JSON (no float precision games: compare re-encodings).
    let a = serde_json::to_string(&rule).expect("serialize rule");
    let back: RuleDef = serde_json::from_str(&a).expect("reparse rule json");
    let b = serde_json::to_string(&back).expect("serialize again");
    assert_eq!(a, b);
});
