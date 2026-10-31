//! Filter language: `walleye_index::filter::parse` then `compile` for every
//! view (CONTRACTS §5, §7).
//!
//! Invariants (the injection checks behind "parameterized SQL only"):
//! * never panics; text over 4 KiB is rejected;
//! * parse errors are `invalid_filter` with a span inside the text;
//! * `?` count == `params.len()`;
//! * once the fixed `ESCAPE '\'` is removed, the SQL has no quote characters
//!   and no numeric tokens, and every word in it is trusted: a registry
//!   identifier (`fields::FIELDS[*].sql`), a table name, or a fixed
//!   keyword/function. Any user value that reached the SQL string would show
//!   up as a quote, a number or an unknown word. (Invariant agreed with
//!   Agent B; it matches the proptest in crates/walleye-index/tests/filter.rs.)
//! * no `;`, `--` or `/*`, so the SQL cannot carry a second statement.
#![no_main]

use std::{collections::HashSet, sync::OnceLock};

use libfuzzer_sys::fuzz_target;
use walleye_core::{ErrorCode, fields::FIELDS, ipc::View};
use walleye_index::filter::{compile, parse};

const VIEWS: [View; 6] = [
    View::Flows,
    View::Dns,
    View::Http,
    View::Tls,
    View::Files,
    View::Frames,
];

const TABLES: &[&str] = &["flows", "dns", "http", "tls", "files", "frames", "flow_id"];
/// The complete fixed vocabulary `filter::compile` emits, per Agent B
/// (2026-10-31), compared case-insensitively. It never emits IS, NULL or CAST;
/// those appear only in `Index::query`'s wrapper SQL, which this target does not
/// see. A word outside this list plus the registry means user text in the SQL.
const KEYWORDS: &[&str] = &[
    "true",
    "false",
    "and",
    "or",
    "not",
    "coalesce",
    "in",
    "select",
    "from",
    "where",
    "ilike",
    "escape",
    "starts_with",
    "wl_ip_num",
    "between",
    "list_contains",
    "list_bool_or",
    "list_transform",
    "lambda",
    "x",
];

fn trusted_words() -> &'static HashSet<String> {
    static W: OnceLock<HashSet<String>> = OnceLock::new();
    W.get_or_init(|| {
        let mut w: HashSet<String> = KEYWORDS.iter().map(|s| s.to_string()).collect();
        w.extend(TABLES.iter().map(|s| s.to_string()));
        for f in FIELDS {
            for word in words(f.sql) {
                w.insert(word.to_ascii_lowercase());
            }
        }
        w
    })
}

/// Identifier-like words (letters, digits, `_`), in order.
fn words(sql: &str) -> impl Iterator<Item = &str> {
    sql.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
}

fn check_sql(sql: &str, n_params: usize) {
    assert_eq!(sql.matches('?').count(), n_params, "sql: {sql}");
    assert!(!sql.contains(';'), "sql: {sql}");
    assert!(!sql.contains("--") && !sql.contains("/*"), "sql: {sql}");
    let stripped = sql.replace("ESCAPE '\\'", " ");
    assert!(
        !stripped.contains('\'') && !stripped.contains('"'),
        "quote outside ESCAPE in sql: {sql}"
    );
    // Non-ASCII anywhere means user text reached the SQL.
    assert!(stripped.is_ascii(), "non-ascii in sql: {sql}");
    // Punctuation compile emits (Agent B): ( ) , = > < ? and `:` in `lambda x:`;
    // plus + - from registry expressions like (ts_end - ts_start).
    for c in stripped.chars() {
        assert!(
            c.is_ascii_alphanumeric()
                || c == '_'
                || c.is_ascii_whitespace()
                || "(),=<>?:+-".contains(c),
            "unexpected char {c:?} in sql: {sql}"
        );
    }
    let trusted = trusted_words();
    for w in words(&stripped) {
        assert!(
            !w.as_bytes()[0].is_ascii_digit() || trusted.contains(&w.to_ascii_lowercase()),
            "numeric token {w:?} in sql: {sql}"
        );
        assert!(
            trusted.contains(&w.to_ascii_lowercase()),
            "untrusted word {w:?} in sql: {sql}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let expr = match parse(text) {
        Ok(e) => e,
        Err(e) => {
            assert_eq!(e.code, ErrorCode::InvalidFilter, "{e:?}");
            if let Some(s) = e.span {
                assert!(s.start <= s.end && s.end as usize <= text.len(), "{s:?}");
            }
            return;
        }
    };
    assert!(
        text.len() <= 4096,
        "accepted {} bytes (limit 4 KiB)",
        text.len()
    );
    for view in VIEWS {
        // compile may legitimately reject (type errors, IPv6 networks that the
        // Index resolves first via filter::resolve_ipv6_nets).
        if let Ok(c) = compile(&expr, view) {
            check_sql(&c.sql, c.params.len());
        }
    }
});
