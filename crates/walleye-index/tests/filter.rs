//! Filter language: grammar, type errors with spans, limits, SQL shape, and
//! property tests (no panic; every literal is a parameter).

use proptest::prelude::*;
use walleye_core::{ErrorCode, fields::FIELDS, ipc::View};
use walleye_index::filter::{
    self, ALL_VIEWS, Compiled, Lit, MAX_DEPTH, MAX_LEN, MAX_TERMS, Param, compile, parse,
};

fn c(text: &str, view: View) -> Compiled {
    let e = parse(text).unwrap_or_else(|e| panic!("parse {text:?}: {e:?}"));
    compile(&e, view).unwrap_or_else(|e| panic!("compile {text:?}: {e:?}"))
}

fn err_span(text: &str) -> (u32, u32, String) {
    let e = parse(text)
        .and_then(|e| compile(&e, View::Flows))
        .expect_err(text);
    assert_eq!(e.code, ErrorCode::InvalidFilter, "{text}");
    let s = e.span.expect("span");
    assert!(
        s.start <= s.end && s.end as usize <= text.len().max(MAX_LEN),
        "{text}: {s:?}"
    );
    (s.start, s.end, e.message)
}

#[test]
fn empty_is_true() {
    assert_eq!(c("", View::Flows).sql, "TRUE");
    assert_eq!(c("   ", View::Dns).sql, "TRUE");
}

#[test]
fn contract_example_compiles() {
    let out = c(
        "host 10.0.0.5 and dns.query ~ \"*.top\" and bytes_up > 1MB and not app_proto == tls",
        View::Flows,
    );
    assert_eq!(
        out.sql,
        "(((src_ip = ?) OR (dst_ip = ?)) AND (flow_id IN (SELECT flow_id FROM dns WHERE (query ILIKE ? ESCAPE '\\'))) AND (bytes_up > ?) AND (NOT coalesce((app_proto = ?), FALSE)))"
    );
    assert_eq!(
        out.params,
        vec![
            Param::Str("10.0.0.5".into()),
            Param::Str("10.0.0.5".into()),
            Param::Str("%.top".into()),
            Param::Int(1 << 20),
            Param::Str("tls".into()),
        ]
    );
}

#[test]
fn juxtaposition_is_and_and_keywords_case_insensitive() {
    assert_eq!(
        c("tcp udp", View::Flows).sql,
        c("tcp AND udp", View::Flows).sql
    );
    assert_eq!(c("NOT tcp OR Host 1.2.3.4", View::Flows).params.len(), 3);
}

#[test]
fn shorthands_and_bare_protocols() {
    assert_eq!(
        c("port 53", View::Flows).sql,
        "((src_port = ?) OR (dst_port = ?))"
    );
    assert_eq!(c("src 10.0.0.1", View::Flows).sql, "(src_ip = ?)");
    assert_eq!(c("dns", View::Flows).params, vec![Param::Str("dns".into())]);
    assert_eq!(c("udp", View::Flows).params, vec![Param::Int(17)]);
    assert_eq!(
        c("proto == icmp6", View::Flows).params,
        vec![Param::Int(58)]
    );
}

#[test]
fn units() {
    assert_eq!(
        c("bytes > 1.5KB", View::Flows).params,
        vec![Param::Int(1536)]
    );
    assert_eq!(
        c("bytes > 2GB", View::Flows).params,
        vec![Param::Int(2 << 30)]
    );
    assert_eq!(
        c("duration > 10m", View::Flows).params,
        vec![Param::Int(600_000_000)]
    );
    assert_eq!(
        c("duration > 250ms", View::Flows).params,
        vec![Param::Int(250_000)]
    );
    assert_eq!(
        c("duration > 3", View::Flows).params,
        vec![Param::Int(3_000_000)]
    );
    assert_eq!(
        c("ts >= \"2024-05-01T00:00:00Z\"", View::Flows).params,
        vec![Param::Int(1_714_521_600_000_000)]
    );
    assert_eq!(
        c("ts >= \"2024-05-01T02:00:00.5+02:00\"", View::Flows).params,
        vec![Param::Int(1_714_521_600_500_000)]
    );
}

#[test]
fn cidr() {
    let o = c(
        "src_ip == 10.0.0.0/8 and not dst_ip == 10.0.0.0/8",
        View::Flows,
    );
    assert!(o.sql.contains("starts_with(src_ip, ?)"), "{}", o.sql);
    assert_eq!(o.params[0], Param::Str("10.".into()));
    let o = c("dst_ip == 172.16.0.0/12", View::Flows);
    assert!(
        o.sql.contains("wl_ip_num(dst_ip) BETWEEN ? AND ?"),
        "{}",
        o.sql
    );
    assert_eq!(
        o.params,
        vec![Param::Int(0xac10_0000), Param::Int(0xac1f_ffff)]
    );
    // Host bits are masked off.
    assert_eq!(
        c("host 10.1.2.3/16", View::Flows).params[0],
        Param::Str("10.1.".into())
    );
    // IPv6 networks need the index to resolve; compile alone refuses them.
    let e = parse("host 2001:db8::/32").expect("parse");
    assert_eq!(
        compile(&e, View::Flows).expect_err("v6").code,
        ErrorCode::InvalidFilter
    );
    let mut e = e;
    filter::resolve_ipv6_nets(&mut e, &mut |_, _, _| Ok(vec!["2001:db8::1".into()]))
        .expect("resolve");
    assert_eq!(compile(&e, View::Flows).expect("compile").params.len(), 2);
}

#[test]
fn glob_escaping() {
    let o = c(r#"http.uri ~ "100%_off\\*?""#, View::Http);
    assert_eq!(o.params, vec![Param::Str(r"100\%\_off\\%_".into())]);
    assert!(o.sql.ends_with(" ILIKE ? ESCAPE '\\')"));
    let o = c(r#"dns.answer ~ "*.evil""#, View::Dns);
    assert!(
        o.sql.starts_with("list_bool_or(list_transform(answers"),
        "{}",
        o.sql
    );
    assert!(
        c("dns.answer == 1.2.3.4", View::Dns)
            .sql
            .contains("list_contains(answers, ?)")
    );
}

#[test]
fn in_lists() {
    let o = c("dns.qtype in [TXT, NULL]", View::Dns);
    assert_eq!(o.sql, "(qtype IN (?, ?))");
    assert_eq!(
        o.params,
        vec![Param::Str("TXT".into()), Param::Str("NULL".into())]
    );
    assert!(
        c("dst_ip in [10.0.0.0/8, 1.2.3.4]", View::Flows)
            .sql
            .contains(" OR ")
    );
}

#[test]
fn cross_table_both_directions() {
    let o = c("bytes_up > 1MB", View::Dns);
    assert_eq!(
        o.sql,
        "(flow_id IN (SELECT flow_id FROM flows WHERE (bytes_up > ?)))"
    );
    let o = c("tls.sni ~ \"*x*\"", View::Http);
    assert!(
        o.sql
            .starts_with("(flow_id IN (SELECT flow_id FROM tls WHERE")
    );
    let o = c("host 1.2.3.4", View::Frames);
    assert!(o.sql.contains("SELECT flow_id FROM flows"));
    assert_eq!(
        c("frame.tcp_flags == 2", View::Frames).sql,
        "(tcp_flags = ?)"
    );
    // frame.* only on frames.
    let e = parse("frame.len > 100").expect("parse");
    assert_eq!(
        compile(&e, View::Flows).expect_err("frames").code,
        ErrorCode::InvalidFilter
    );
}

#[test]
fn type_errors_have_spans() {
    let t = r#"bytes_up ~ "x""#;
    let (s, e, _) = err_span(t);
    assert_eq!(&t[s as usize..e as usize], "~");
    let t = "src_ip > 5";
    let (s, e, _) = err_span(t);
    assert_eq!(&t[s as usize..e as usize], ">");
    let t = "tcp and nosuch.field == 1";
    let (s, e, m) = err_span(t);
    assert_eq!(&t[s as usize..e as usize], "nosuch.field");
    assert!(m.contains("unknown field"));
    let t = "src_ip == banana";
    let (s, e, _) = err_span(t);
    assert_eq!(&t[s as usize..e as usize], "banana");
    let t = "bytes > 1XB";
    let (s, _, _) = err_span(t);
    assert_eq!(s, 8);
    for bad in [
        "(tcp",
        "tcp)",
        "\"open",
        "a = b",
        "dns.query ~ *.top",
        "host",
        "port 70000",
        "tcp and",
        "or tcp",
        "flow_id in [1, 2",
        "flow_id in 1",
        "Dns.Query == x",
        "tls.cert_self_signed == maybe",
        "\"x\" == y",
        "bytes > \"1\"",
        "a \\ b",
    ] {
        err_span(bad);
    }
}

#[test]
fn limits() {
    let long = format!("tcp{}", " ".repeat(MAX_LEN));
    let (s, _, _) = err_span(&long);
    assert_eq!(s as usize, MAX_LEN);
    let deep = format!(
        "{}tcp{}",
        "(".repeat(MAX_DEPTH + 1),
        ")".repeat(MAX_DEPTH + 1)
    );
    assert!(err_span(&deep).2.contains("deeper"));
    let nots = format!("{}tcp", "not ".repeat(MAX_DEPTH + 1));
    assert!(err_span(&nots).2.contains("deeper"));
    let ok = format!(
        "{}tcp{}",
        "(".repeat(MAX_DEPTH - 2),
        ")".repeat(MAX_DEPTH - 2)
    );
    parse(&ok).expect("depth within limit");
    let many = vec!["tcp"; MAX_TERMS + 1].join(" or ");
    assert!(err_span(&many).2.contains("terms"));
    parse(&vec!["tcp"; MAX_TERMS].join(" or ")).expect("terms within limit");
}

#[test]
fn every_field_compiles_on_every_applicable_view() {
    for f in FIELDS {
        let v = match f.ty {
            walleye_core::fields::FieldType::Ip => "1.2.3.4",
            walleye_core::fields::FieldType::Bool => "true",
            walleye_core::fields::FieldType::Proto => "tcp",
            walleye_core::fields::FieldType::Str | walleye_core::fields::FieldType::StrList => {
                "\"x\""
            }
            walleye_core::fields::FieldType::Mac => "\"aa:bb:cc:dd:ee:ff\"",
            _ => "1",
        };
        for view in ALL_VIEWS {
            let text = format!("{} == {v}", f.name);
            let e = parse(&text).expect(&text);
            let r = compile(&e, view);
            use walleye_core::fields::Table as Tb;
            let own = filter::table_of(view);
            let wifi = |t: Tb| matches!(t, Tb::Wifi | Tb::WifiAps | Tb::WifiClients);
            let rejected = if wifi(f.table) || wifi(own) {
                f.table != own
            } else {
                f.table == Tb::Frames && view != View::Frames
            };
            assert_eq!(r.is_err(), rejected, "{text} on {view:?}");
        }
    }
}

// ------------------------------------------------------------ properties

/// SQL vocabulary the compiler may emit: registry expressions, table names,
/// fixed keywords/functions. No literal from the input can appear.
fn assert_sql_safe(sql: &str, params: &[Param]) {
    let stripped = sql.replace("ESCAPE '\\'", "ESCAPE");
    assert!(!stripped.contains('\''), "quote in sql: {sql}");
    assert!(!stripped.contains('"'), "dquote in sql: {sql}");
    let mut vocab: std::collections::HashSet<&str> = [
        "TRUE",
        "FALSE",
        "AND",
        "OR",
        "NOT",
        "coalesce",
        "IN",
        "SELECT",
        "FROM",
        "WHERE",
        "flow_id",
        "ILIKE",
        "ESCAPE",
        "starts_with",
        "wl_ip_num",
        "BETWEEN",
        "list_contains",
        "list_bool_or",
        "list_transform",
        "lambda",
        "x",
        "flows",
        "dns",
        "http",
        "tls",
        "files",
        "frames",
    ]
    .into_iter()
    .collect();
    for f in FIELDS {
        for w in f
            .sql
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        {
            vocab.insert(w);
        }
    }
    for w in stripped.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if !w.is_empty() {
            assert!(vocab.contains(w), "unexpected word {w:?} in {sql}");
        }
    }
    assert_eq!(sql.matches('?').count(), params.len(), "{sql}");
}

fn lit_texts(e: &filter::Expr) -> Vec<String> {
    e.literals()
        .into_iter()
        .filter_map(|l| match l {
            Lit::Str(s) | Lit::Glob(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn value_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z_][a-zA-Z0-9_-]{0,12}",
        "\"([^\"\\\\]|\\\\\"|\\\\\\\\){0,24}\"",
        "[0-9]{1,6}(B|KB|MB|GB|us|ms|s|m|h)?",
        "(10|192|172)\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(/[0-9]{1,2})?",
        Just("true".to_string()),
        Just("'; DROP TABLE flows; --".to_string()),
        Just("\"'); SELECT * FROM read_csv('/etc/passwd'); --\"".to_string()),
    ]
}

fn term_strategy() -> impl Strategy<Value = String> {
    let field = proptest::sample::select(FIELDS.iter().map(|f| f.name).collect::<Vec<_>>());
    let op = proptest::sample::select(vec!["==", "!=", ">", ">=", "<", "<=", "~"]);
    prop_oneof![
        (field.clone(), op, value_strategy()).prop_map(|(f, o, v)| format!("{f} {o} {v}")),
        (field, proptest::collection::vec(value_strategy(), 1..4))
            .prop_map(|(f, vs)| format!("{f} in [{}]", vs.join(", "))),
        value_strategy().prop_map(|v| format!("host {v}")),
        "[0-9]{1,5}".prop_map(|v| format!("port {v}")),
        proptest::sample::select(vec!["dns", "http", "tls", "tcp", "udp", "icmp"])
            .prop_map(str::to_string),
    ]
}

fn filter_strategy() -> impl Strategy<Value = String> {
    term_strategy().prop_recursive(4, 24, 3, |inner| {
        prop_oneof![
            (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("{a} and {b}")),
            (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("({a}) or ({b})")),
            (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("{a} {b}")),
            inner.clone().prop_map(|a| format!("not ({a})")),
            inner.prop_map(|a| format!("!{a}")),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, failure_persistence: None, .. ProptestConfig::default() })]

    /// Arbitrary text never panics parse/compile/autocomplete.
    #[test]
    fn arbitrary_text_never_panics(s in "\\PC{0,200}", cur in 0u32..300) {
        filter::fuzz_parse_compile(&s);
        let _ = filter::autocomplete_static(&s, cur);
    }

    /// Arbitrary bytes-ish text from the filter alphabet never panics.
    #[test]
    fn filter_alphabet_never_panics(s in "[ a-z0-9_.:/\\-()\\[\\],!=<>~\"\\\\*?]{0,120}") {
        filter::fuzz_parse_compile(&s);
    }

    /// Structured filters: when they compile, the SQL holds only vocabulary,
    /// placeholders match params, and no string literal appears in the SQL.
    #[test]
    fn literals_are_always_parameters(text in filter_strategy()) {
        if let Ok(e) = parse(&text) {
            let lits = lit_texts(&e);
            for view in ALL_VIEWS {
                if let Ok(out) = compile(&e, view) {
                    assert_sql_safe(&out.sql, &out.params);
                    // The vocabulary check above is the proof. As a direct
                    // check, literals carrying anything the SQL template can
                    // never contain (digits, quotes, ;, -, *, %, non-ASCII)
                    // must not appear verbatim.
                    for l in &lits {
                        let distinctive = l.chars().any(|c| c.is_ascii_digit() || "'\";-*%".contains(c) || !c.is_ascii());
                        if l.len() >= 3 && distinctive {
                            prop_assert!(!out.sql.contains(l.as_str()), "{:?} in {}", l, out.sql);
                        }
                    }
                }
            }
        }
    }

    /// Glob conversion: the LIKE pattern unescapes back to the glob semantics.
    #[test]
    fn glob_like_roundtrip(g in "[a-z%_\\\\*?.]{0,20}") {
        let like = filter::glob_to_like(&g);
        // Unescaped % and _ come only from * and ?.
        let mut chars = like.chars();
        let mut back = String::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' => back.push(chars.next().expect("escape has a char")),
                '%' => back.push('*'),
                '_' => back.push('?'),
                c => back.push(c),
            }
        }
        prop_assert_eq!(back, g);
    }
}

#[test]
fn injection_attempts_are_parameters() {
    for t in [
        r#"dns.query == "'; DROP TABLE flows; --""#,
        r#"http.uri ~ "') OR 1=1 --""#,
        r#"tls.sni in ["a'b", "c\"d", "e\\f"]"#,
    ] {
        for view in ALL_VIEWS {
            let out = c(t, view);
            assert_sql_safe(&out.sql, &out.params);
            assert!(!out.sql.contains("DROP") && !out.sql.contains("1=1"));
        }
    }
}

#[test]
fn autocomplete_static_contexts() {
    use walleye_core::ipc::SuggestionKind as K;
    let s = filter::autocomplete_static("dns.q", 5);
    assert!(s.iter().any(|x| x.label == "dns.query"
        && x.kind == K::Field
        && x.replace_start == 0
        && x.replace_end == 5));
    let s = filter::autocomplete_static("bytes_up ", 9);
    assert!(s.iter().any(|x| x.label == ">=" && x.kind == K::Operator));
    assert!(!s.iter().any(|x| x.label == "~"));
    let s = filter::autocomplete_static("tls.cert_self_signed == ", 24);
    assert_eq!(
        s.iter().map(|x| x.label.as_str()).collect::<Vec<_>>(),
        vec!["true", "false"]
    );
    let s = filter::autocomplete_static("tcp a", 5);
    assert!(s.iter().any(|x| x.label == "and" && x.kind == K::Keyword));
    // Cursor beyond the text or inside a multi-byte char is clamped.
    let _ = filter::autocomplete_static("dns.query == \"é", 15);
    let _ = filter::autocomplete_static("é", 1);
}
