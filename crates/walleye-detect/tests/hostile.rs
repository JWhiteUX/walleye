//! Hostile and degenerate input: no panics, sane output, safe strings.

mod common;

use common::*;
use walleye_core::Allowlist;
use walleye_core::rules::RuleDef;
use walleye_core::sink::MemorySource;
use walleye_detect::{RuleSet, run};

fn safe_text(s: &str) {
    assert!(
        s.chars()
            .all(|c| c == '…' || c == '×' || c == '±' || (c.is_ascii() && !c.is_ascii_control())),
        "unsafe chars in {s:?}"
    );
}

#[test]
fn empty_source_gives_no_findings() {
    let f = run(
        &MemorySource::default(),
        &repo_rules(),
        &Allowlist::default(),
    )
    .expect("run");
    assert!(f.is_empty());
}

#[test]
fn garbage_names_and_addresses_do_not_panic() {
    let mut sy = Synth::new(5);
    let host = "10.9.9.9";
    let weird = [
        String::new(),
        ".".into(),
        "....".into(),
        "a..b...c".into(),
        "x".repeat(10_000),
        format!("{}.evil.top", "y".repeat(500)),
        "\u{0}\u{1}\u{7f}.bin.top".into(),
        "ünïcødé.例え.テスト".into(),
        "UPPER.Case.COM.".into(),
        "<script>alert(1)</script>.html.top".into(),
        "{src}{dst}.template.top".into(),
        "1.2.3.4".into(),
        "-.-.-".into(),
    ];
    for k in 0..400i64 {
        let q = &weird[(k as usize) % weird.len()];
        let rcode = if k % 3 == 0 { "NXDOMAIN" } else { "NOERROR" };
        let qtype = if k % 2 == 0 { "TXT" } else { "TYPE65280" };
        sy.dns(
            T0 + k * 500_000,
            host,
            &format!("{k}{q}"),
            qtype,
            rcode,
            vec!["\u{0}".repeat(70_000)],
        );
    }
    // Beacon with a hostile SNI and junk addresses.
    for k in 0..60i64 {
        sy.tls(
            T0 + k * 60 * S,
            host,
            "45.33.1.200",
            "\u{1b}[31mred\u{0}.top",
            300,
            900,
        );
        sy.tls(T0 + k * 60 * S, host, "not-an-ip", "x", 300, 900);
        sy.tls(T0 + k * 60 * S, &"9".repeat(5000), "8.8.8.8", "x", 300, 900);
        sy.tls(T0 + k * 60 * S, host, "", "x", 300, 900);
    }
    let mut src = sy.build();
    // DNS rows pointing at flows that do not exist; extreme timestamps.
    let mut d = src.dns[0].clone();
    d.flow_id = 9_999_999;
    src.dns.push(d);
    let mut fl = src.flows[0].clone();
    fl.ts_start = i64::MIN;
    fl.ts_end = i64::MAX;
    src.flows.push(fl);
    let mut fl = src.flows[1].clone();
    fl.ts_start = i64::MAX;
    src.flows.push(fl);

    let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
    assert!(!f.is_empty(), "the hostile host still beacons and tunnels");
    for x in &f {
        safe_text(&x.title);
        assert!(
            x.title.chars().count() < 300,
            "title too long: {}",
            x.title.len()
        );
        for r in &x.reasons {
            safe_text(&r.explanation);
            assert!(r.explanation.len() < 2000, "explanation too long");
            assert!(!r.evidence.is_empty());
            assert!(r.weight.is_finite() && r.value.is_finite());
        }
        assert!(x.score.is_finite());
    }
}

#[test]
fn responses_only_capture_still_detects_tunnel() {
    let mut sc = tunnel_scenario(4);
    sc.src.dns.retain(|d| d.is_response);
    let f = run(&sc.src, &repo_rules(), &repo_allowlist()).expect("run");
    assert_eq!(rank(&f, C2_TUNNEL), Some(1), "{}", summary(&f));
    assert_evidence_valid(&sc.src, &f);
}

#[test]
fn public_only_capture_still_reports_sources() {
    // No RFC1918 sources at all: every source becomes eligible.
    let mut sy = Synth::new(8);
    beacon60(&mut sy, "198.18.0.5", 1.5);
    let f = run(&sy.build(), &repo_rules(), &repo_allowlist()).expect("run");
    assert_eq!(f.first().map(|x| x.entity.as_str()), Some("198.18.0.5"));
}

#[test]
fn disabled_rules_do_nothing() {
    let defs: Vec<RuleDef> = repo_rules()
        .defs()
        .cloned()
        .map(|mut d| {
            d.enabled = false;
            d
        })
        .collect();
    let rs = RuleSet::from_defs(defs).expect("rules");
    let sc = mix_scenario(1);
    assert!(
        run(&sc.src, &rs, &repo_allowlist())
            .expect("run")
            .is_empty()
    );
}

#[test]
fn allowlisted_destination_is_down_weighted_and_says_so() {
    let mut sy = Synth::new(2);
    let host = "10.1.0.77";
    for k in 0..90i64 {
        let t = T0 + k * 60 * S;
        sy.dns(
            t,
            host,
            "check.trusted-vendor.example",
            "A",
            "NOERROR",
            vec!["93.184.216.50".into()],
        );
        sy.tls(
            t + 30_000,
            host,
            "93.184.216.50",
            "check.trusted-vendor.example",
            300,
            900,
        );
    }
    let src = sy.build();
    let rules = repo_rules();
    let none = run(&src, &rules, &Allowlist::default()).expect("run");
    let full = none.first().expect("beacon without allowlist").score;

    let allow = Allowlist::from_yaml(
        "domains:\n  - { suffix: trusted-vendor.example, reason: \"Vendor update check\" }\n",
    )
    .expect("allowlist");
    // Default factor 0.25 pushes the beacon below min_score: suppressed.
    let f = run(&src, &rules, &allow).expect("run");
    assert!(
        f.iter()
            .all(|x| x.reasons.iter().all(|r| r.rule_id != "beacon.periodic")),
        "{}",
        summary(&f)
    );

    // With a milder factor it stays visible, reduced, and explains why.
    let defs: Vec<RuleDef> = rules
        .defs()
        .cloned()
        .map(|mut d| {
            if d.id == "beacon.periodic" {
                d.params
                    .insert("allowlist_factor".into(), serde_json::json!(0.6));
            }
            d
        })
        .collect();
    let f = run(&src, &RuleSet::from_defs(defs).expect("rules"), &allow).expect("run");
    let top = f.first().expect("still reported");
    assert!(top.score < full, "{} !< {full}", top.score);
    let r = &top.reasons[0];
    assert!(
        r.explanation.contains("allowlisted: Vendor update check"),
        "{}",
        r.explanation
    );
}
