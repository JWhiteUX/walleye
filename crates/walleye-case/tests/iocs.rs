#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

use common::*;
use proptest::prelude::*;
use walleye_case::{
    defang, extract_iocs,
    ioc::{http_url, ioc_id, is_public_ip, parent_domain},
    normalize, refang,
};
use walleye_core::{Allowlist, Finding, Ioc, IocType, sink::MemorySource};

fn find<'a>(iocs: &'a [Ioc], t: IocType, v: &str) -> Option<&'a Ioc> {
    iocs.iter().find(|i| i.ioc_type == t && i.value == v)
}

// ---------------------------------------------------------------- defang

#[test]
fn defang_examples() {
    assert_eq!(defang(IocType::Ip, "10.0.0.5"), "10[.]0[.]0[.]5");
    assert_eq!(defang(IocType::Ip, "2001:db8::1"), "2001[:]db8[:][:]1");
    assert_eq!(defang(IocType::Domain, "evil.top"), "evil[.]top");
    assert_eq!(
        defang(IocType::Url, "http://cdn-update.top/gate.php?id=7f3a"),
        "hxxp://cdn-update[.]top/gate[.]php?id=7f3a"
    );
    assert_eq!(defang(IocType::Url, "https://a.b/"), "hxxps://a[.]b/");
    assert_eq!(
        defang(IocType::Ja4, "t13d1516h2_8daaf6152771_02713d6af862"),
        "t13d1516h2_8daaf6152771_02713d6af862"
    );
    assert_eq!(refang(IocType::Url, "hxxps://a[.]b/"), "https://a.b/");
}

#[test]
fn defanged_values_are_not_live() {
    for (t, v) in [
        (IocType::Url, "http://evil.example/x"),
        (IocType::Url, "https://1.2.3.4:8443/a.b"),
        (IocType::Domain, "evil.example"),
        (IocType::Ip, "185.199.110.77"),
    ] {
        let d = defang(t, v);
        assert!(!d.contains("http"), "{d}");
        assert!(!d.contains("://") || d.starts_with("hxxp"), "{d}");
        assert!(!d.replace("[.]", "").contains('.'), "{d}");
    }
}

fn arb_type() -> impl Strategy<Value = IocType> {
    prop_oneof![
        Just(IocType::Ip),
        Just(IocType::Domain),
        Just(IocType::Url),
        Just(IocType::Ja4),
        Just(IocType::CertSerial)
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Exact inverse on any string for every type except URL (whose `http`
    /// prefix rewrite is only defined for normalized URLs, tested below).
    #[test]
    fn refang_inverts_defang_on_any_string(t in arb_type(), s in "\\PC*|[.:\\[\\]hxtp]{0,24}") {
        prop_assume!(t != IocType::Url || !s.starts_with("hxxp"));
        prop_assert_eq!(refang(t, &defang(t, &s)), s);
    }

    /// Round trip on every value normalization can produce.
    #[test]
    fn refang_inverts_defang_on_normalized(t in arb_type(), raw in "(https?://)?[a-zA-Z0-9.:\\[\\]/?=&%_-]{1,40}|[0-9]{1,3}(\\.[0-9]{1,3}){3}|[0-9a-f:]{2,39}") {
        if let Some(v) = normalize(t, &raw) {
            let d = defang(t, &v);
            prop_assert_eq!(refang(t, &d), v.clone());
            // defanging is idempotent under normalization of the refanged form
            prop_assert_eq!(normalize(t, &refang(t, &d)), Some(v));
        }
    }

    /// Normalized URLs always round-trip, whatever their path holds.
    #[test]
    fn url_round_trip(https in any::<bool>(), host in "[a-z0-9-]{1,12}(\\.[a-z0-9-]{1,12}){1,3}", path in "\\PC{0,60}") {
        let raw = format!("{}://{host}/{path}", if https { "https" } else { "http" });
        if let Some(v) = normalize(IocType::Url, &raw) {
            let d = defang(IocType::Url, &v);
            prop_assert!(d.starts_with("hxxp"));
            prop_assert!(!d.replace("[.]", "").contains('.'));
            prop_assert_eq!(refang(IocType::Url, &d), v);
        }
    }

    /// Normalized URLs never contain whitespace, controls or quotes.
    #[test]
    fn normalized_urls_are_printable(path in "\\PC{0,80}|[\\x00-\\x7f]{0,80}") {
        if let Some(u) = http_url(Some("evil.example"), None, &format!("/{path}")) {
            prop_assert!(u.bytes().all(|b| (0x21..0x7f).contains(&b) && !b"\"<>\\^`{|}".contains(&b)), "{}", u);
        }
    }
}

// ----------------------------------------------------------- normalization

#[test]
fn normalizes_values() {
    assert_eq!(
        normalize(IocType::Ip, " 185.199.110.77 ").as_deref(),
        Some("185.199.110.77")
    );
    assert_eq!(
        normalize(IocType::Ip, "::ffff:1.2.3.4").as_deref(),
        Some("1.2.3.4")
    );
    assert_eq!(
        normalize(IocType::Ip, "2001:0DB8::0001").as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(
        normalize(IocType::Domain, "CDN-Update.Top.").as_deref(),
        Some("cdn-update.top")
    );
    assert_eq!(normalize(IocType::Domain, "localhost"), None);
    assert_eq!(normalize(IocType::Domain, "printer.local"), None);
    assert_eq!(normalize(IocType::Domain, "1.0.0.10.in-addr.arpa"), None);
    assert_eq!(normalize(IocType::Domain, "evil.top\n## x"), None);
    assert_eq!(normalize(IocType::Domain, "a b.com"), None);
    assert_eq!(normalize(IocType::Domain, "1.2.3.4"), None);
    assert_eq!(
        normalize(IocType::CertSerial, "00:D1:E2").as_deref(),
        Some("00d1e2")
    );
    assert_eq!(normalize(IocType::CertSerial, "zz"), None);
    assert_eq!(normalize(IocType::Ja4, "T13D_X"), Some("t13d_x".into()));
    assert_eq!(normalize(IocType::Ja4, "t13 d"), None);
    assert_eq!(
        normalize(IocType::Url, "HTTP://Evil.Example:80/a b").as_deref(),
        Some("http://evil.example/a%20b")
    );
    assert_eq!(
        normalize(IocType::Url, "https://evil.example:443").as_deref(),
        Some("https://evil.example/")
    );
    assert_eq!(normalize(IocType::Url, "http://u:p@evil.example/"), None);
    assert_eq!(normalize(IocType::Url, "javascript:alert(1)"), None);
    assert_eq!(
        normalize(IocType::Url, "http://[2001:db8::1]:8080/x").as_deref(),
        Some("http://[2001:db8::1]:8080/x")
    );
}

#[test]
fn builds_http_urls() {
    let f = flow(1, 0, "10.0.0.1", "185.199.110.77", 8080, Some("http"), 1);
    assert_eq!(
        http_url(Some("evil.example"), Some(&f), "/x").as_deref(),
        Some("http://evil.example:8080/x")
    );
    assert_eq!(
        http_url(Some("evil.example:80"), Some(&f), "/x").as_deref(),
        Some("http://evil.example/x")
    );
    assert_eq!(
        http_url(None, Some(&f), "/x").as_deref(),
        Some("http://185.199.110.77:8080/x")
    );
    assert_eq!(
        http_url(Some("a.example"), None, "http://b.example/y").as_deref(),
        Some("http://b.example/y")
    );
    assert_eq!(http_url(Some("evil.example"), None, "*"), None);
    assert_eq!(http_url(Some("<script>"), None, "/"), None);
}

#[test]
fn public_ip_and_parent_domain() {
    for ip in [
        "10.1.2.3",
        "192.168.0.1",
        "172.16.5.5",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "224.0.0.251",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fd00::1",
        "0.0.0.0",
    ] {
        assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["8.8.8.8", "185.199.110.77", "2606:4700::1111"] {
        assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert_eq!(parent_domain("a.b.t.exfil-dns.xyz"), "exfil-dns.xyz");
    assert_eq!(parent_domain("www.bbc.co.uk"), "bbc.co.uk");
    assert_eq!(parent_domain("evil.top"), "evil.top");
}

#[test]
fn ioc_id_is_stable_per_contract() {
    // hex16(sha256("ioc\0domain\0cdn-update.top"))
    let id = ioc_id(IocType::Domain, "cdn-update.top");
    assert_eq!(id.len(), 16);
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(id, ioc_id(IocType::Domain, "cdn-update.top"));
    assert_ne!(id, ioc_id(IocType::Ip, "cdn-update.top"));
    use sha2::Digest;
    let d = sha2::Sha256::digest(b"ioc\0domain\0cdn-update.top");
    let want: String = d.iter().take(8).map(|b| format!("{b:02x}")).collect();
    assert_eq!(id, want);
    assert_eq!(ioc_id(IocType::CertSerial, "00"), {
        let d = sha2::Sha256::digest([b"ioc\0cert_serial\0".as_slice(), b"00"].concat());
        d.iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
}

// ---------------------------------------------------------------- extraction

#[test]
fn extracts_scenario_iocs() {
    let (src, findings) = scenario();
    let iocs = extract_iocs(&findings, &src, &allowlist()).unwrap();
    let got: Vec<(IocType, &str)> = iocs
        .iter()
        .map(|i| (i.ioc_type, i.value.as_str()))
        .collect();

    // beacon
    let ip = find(&iocs, IocType::Ip, "185.199.110.77").expect("beacon ip");
    assert_eq!(ip.source_finding_id.as_deref(), Some("f1b2c3d4e5f60001"));
    assert_eq!(ip.evidence.flow_ids, vec![2, 3, 4, 5]);
    assert_eq!(ip.evidence.frame_nos, vec![20, 100, 110, 120]);
    assert!(!ip.allowlisted);
    let dom = find(&iocs, IocType::Domain, "cdn-update.top").expect("beacon domain");
    // SNI + Host frames, plus the DNS lookup (query and answer) found by enrichment
    assert_eq!(dom.evidence.frame_nos, vec![10, 11, 23, 103, 113, 123]);
    assert_eq!(dom.first_seen, T0 + 10_000_000);
    assert_eq!(dom.defanged, "cdn-update[.]top");
    let url = find(
        &iocs,
        IocType::Url,
        "http://cdn-update.top/gate.php?id=7f3a",
    )
    .expect("url");
    assert_eq!(url.defanged, "hxxp://cdn-update[.]top/gate[.]php?id=7f3a");
    assert_eq!(url.evidence.frame_nos, vec![23]);
    assert!(find(&iocs, IocType::Ja4, "t12d190800_d83cc789557e_7af1ed941c26").is_some());
    let serial = find(&iocs, IocType::CertSerial, "00d1e2f3a4b5c6d7").expect("serial");
    assert_eq!(serial.evidence.total, 3);

    // tunnel collapses to its parent and never names the resolver
    let t = find(&iocs, IocType::Domain, "exfil-dns.xyz").expect("tunnel parent");
    assert_eq!(t.evidence.frame_nos, (300..310).collect::<Vec<_>>());
    assert_eq!(t.source_finding_id.as_deref(), Some("f1b2c3d4e5f60002"));
    assert!(
        !got.iter().any(|(_, v)| v.ends_with(".t.exfil-dns.xyz")),
        "{got:?}"
    );
    assert!(
        find(&iocs, IocType::Ip, "8.8.8.8").is_none(),
        "resolver is not an IOC"
    );
    assert!(find(&iocs, IocType::Ip, "10.0.0.2").is_none());

    // allowlisted ones are kept and flagged
    let wu = find(&iocs, IocType::Domain, "fe2.update.microsoft.com").expect("wu domain");
    assert!(wu.allowlisted);
    assert_eq!(wu.allowlist_reason.as_deref(), Some("Microsoft Update"));
    let wu_ip = find(&iocs, IocType::Ip, "13.107.4.50").expect("wu ip");
    assert!(wu_ip.allowlisted);
    let wu_serial = find(&iocs, IocType::CertSerial, "33000001").expect("wu serial");
    assert_eq!(
        wu_serial.allowlist_reason.as_deref(),
        Some("Microsoft Update"),
        "inherits SNI allowlist"
    );

    // noise from unrelated flows is ignored; internal hosts are never IOCs
    assert!(find(&iocs, IocType::Domain, "example.com").is_none());
    assert!(!got.iter().any(|(_, v)| v.starts_with("10.0.0.")));

    // stable ids, no duplicates, never-empty evidence, sorted by first_seen
    let mut ids: Vec<&str> = iocs.iter().map(|i| i.ioc_id.as_str()).collect();
    for i in &iocs {
        assert_eq!(i.ioc_id, ioc_id(i.ioc_type, &i.value));
        assert!(!i.evidence.is_empty(), "{i:?}");
        assert_eq!(refang(i.ioc_type, &i.defanged), i.value);
    }
    assert!(iocs.windows(2).all(|w| w[0].first_seen <= w[1].first_seen));
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), iocs.len());

    // deterministic
    assert_eq!(extract_iocs(&findings, &src, &allowlist()).unwrap(), iocs);
}

#[test]
fn dedupes_across_findings_and_picks_top_source() {
    let (src, mut findings) = scenario();
    // a weaker second finding over the same beacon flows
    let mut weak: Finding = findings[2].clone();
    weak.finding_id = "f000000000000009".into();
    weak.score = 30.0;
    findings.push(weak);
    let iocs = extract_iocs(&findings, &src, &allowlist()).unwrap();
    let ip: Vec<&Ioc> = iocs
        .iter()
        .filter(|i| i.value == "185.199.110.77")
        .collect();
    assert_eq!(ip.len(), 1);
    assert_eq!(ip[0].source_finding_id.as_deref(), Some("f1b2c3d4e5f60001"));
}

#[test]
fn caps_evidence_and_reports_total() {
    let mut src = MemorySource::default();
    let mut frames = Vec::new();
    for id in 1..=250u64 {
        src.flows.push(flow(
            id,
            T0 + id as i64,
            "10.0.0.9",
            "203.0.113.9",
            443,
            Some("tls"),
            id * 10,
        ));
        frames.push(id * 10);
    }
    let f = Finding {
        finding_id: "f9".into(),
        title: "x".into(),
        detector: "beaconing".into(),
        entity_type: "host".into(),
        entity: "10.0.0.9".into(),
        score: 50.0,
        attack_technique: None,
        ts_first: T0,
        ts_last: T0,
        reasons: vec![reason(
            "r",
            "s",
            50.0,
            None,
            ev(&(1..=250).collect::<Vec<_>>(), &frames),
            "e",
        )],
        verdict: None,
    };
    let iocs = extract_iocs(&[f], &src, &Allowlist::default()).unwrap();
    let ip = find(&iocs, IocType::Ip, "203.0.113.9").unwrap();
    assert_eq!(ip.evidence.frame_nos.len(), 200);
    assert_eq!(ip.evidence.frame_nos[0], 10);
    assert!(ip.evidence.truncated);
    assert_eq!(ip.evidence.total, 250);
}

#[test]
fn hostile_rows_never_become_iocs() {
    let mut src = MemorySource::default();
    src.flows
        .push(flow(1, T0, "10.0.0.9", "203.0.113.9", 80, Some("http"), 1));
    src.http
        .push(http(1, 2, T0, "evil.example\r\nX-Injected: 1", "/x"));
    src.http
        .push(http(1, 3, T0, "[x](javascript:alert(1))", "/y"));
    src.flows
        .push(flow(2, T0, "10.0.0.9", "10.0.0.2", 53, Some("dns"), 4));
    src.dns.push(dns(
        2,
        5,
        T0,
        "<img src=x onerror=alert(1)>.top",
        false,
        &[],
    ));
    src.dns
        .push(dns(2, 6, T0, "=HYPERLINK(\"http://x\").top", false, &[]));
    let f = Finding {
        finding_id: "f9".into(),
        title: "x".into(),
        detector: "dns".into(),
        entity_type: "host".into(),
        entity: "10.0.0.9".into(),
        score: 50.0,
        attack_technique: None,
        ts_first: T0,
        ts_last: T0,
        reasons: vec![reason(
            "r",
            "s",
            50.0,
            None,
            ev(&[1, 2], &[2, 3, 5, 6]),
            "e",
        )],
        verdict: None,
    };
    let iocs = extract_iocs(&[f], &src, &Allowlist::default()).unwrap();
    // only the responder IP survives; no domain, URL or junk
    assert_eq!(iocs.len(), 1, "{iocs:?}");
    assert_eq!(iocs[0].value, "203.0.113.9");
}

#[test]
fn no_findings_no_iocs() {
    let (src, _) = scenario();
    assert!(extract_iocs(&[], &src, &allowlist()).unwrap().is_empty());
}

// ----------------------------------------------------- mock dataset (lead's)

#[derive(serde::Deserialize)]
struct MockData {
    flows: Vec<walleye_core::FlowRow>,
    dns: Vec<walleye_core::DnsRow>,
    http: Vec<walleye_core::HttpRow>,
    tls: Vec<walleye_core::TlsRow>,
    findings: Vec<Finding>,
    iocs: Vec<Ioc>,
}

/// On the shared mock dataset, extraction finds every IOC the mock lists
/// (same type, value, defanged form and allowlist flag).
#[test]
fn matches_mock_dataset_iocs() {
    let d: MockData =
        serde_json::from_str(include_str!("../../walleye-core/mock/dataset.json")).unwrap();
    let src = MemorySource {
        capture: None,
        flows: d.flows,
        dns: d.dns,
        http: d.http,
        tls: d.tls,
        wifi: Vec::new(),
    };
    let got = extract_iocs(&d.findings, &src, &allowlist()).unwrap();
    for want in &d.iocs {
        let g = find(&got, want.ioc_type, &want.value)
            .unwrap_or_else(|| panic!("missing {:?} {}", want.ioc_type, want.value));
        assert_eq!(g.defanged, want.defanged, "{}", want.value);
        assert_eq!(g.allowlisted, want.allowlisted, "{}", want.value);
        if want.allowlisted {
            assert!(g.allowlist_reason.is_some());
        }
        assert!(!g.evidence.is_empty());
    }
}
