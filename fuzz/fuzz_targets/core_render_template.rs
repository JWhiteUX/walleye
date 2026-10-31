//! `render_template(template, values)`: templates come from rule YAML, values
//! from detectors (capture-derived strings such as domains).
//!
//! Input layout: `template \0 key1 \x01 value1 \0 key2 \x01 value2 ...`.
//! Invariants: no panic; with no `{` the output equals the template; with no
//! values the output equals the template (unknown placeholders stay
//! verbatim); output length is bounded by template + every value inserted
//! once per placeholder.
#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use walleye_core::rules::render_template;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.split('\0');
    let template = parts.next().unwrap_or("");
    let mut values = BTreeMap::new();
    for p in parts {
        let (k, v) = p.split_once('\x01').unwrap_or((p, ""));
        values.insert(k.to_string(), v.to_string());
    }

    let out = render_template(template, &values);
    if !template.contains('{') {
        assert_eq!(out, template);
    }
    assert_eq!(render_template(template, &BTreeMap::new()), template);

    let placeholders = template.matches('{').count();
    let longest = values.values().map(String::len).max().unwrap_or(0);
    assert!(out.len() <= template.len() + placeholders * longest);
});
