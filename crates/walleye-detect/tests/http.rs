//! HTTP-level rules (beacon.http_requests, http.tls_port, http.post_exfil):
//! each detects its synthetic C2 counterpart of a real sample, and each has a
//! benign counter-example that must not raise a finding of that rule.

mod common;

use common::*;
use walleye_core::Finding;
use walleye_detect::run;

const SEEDS: [u64; 3] = [1, 2, 3];

fn office_with(seed: u64, extra: impl FnOnce(&mut Synth)) -> walleye_core::sink::MemorySource {
    let mut sy = Synth::new(seed);
    office(
        &mut sy,
        &Office {
            hosts: office_hosts(12, 40),
            hours: 3.0,
        },
    );
    extra(&mut sy);
    sy.build()
}

fn rules_of(f: &[Finding], host: &str) -> Vec<String> {
    f.iter()
        .filter(|x| x.entity == host)
        .flat_map(|x| x.reasons.iter().map(|r| r.rule_id.clone()))
        .collect()
}

#[test]
fn netsupport_like_single_connection_beacon_ranks_top() {
    for seed in SEEDS {
        let src = office_with(seed, |sy| netsupport_like(sy, "10.1.0.101", 1.5));
        let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
        assert_evidence_valid(&src, &f);
        assert!(
            rank(&f, "10.1.0.101").is_some_and(|r| r <= 2),
            "seed {seed}\n{}",
            summary(&f)
        );
        let rules = rules_of(&f, "10.1.0.101");
        for want in ["beacon.http_requests", "http.tls_port"] {
            assert!(rules.iter().any(|r| r == want), "missing {want}: {rules:?}");
        }
        // Not double-counted with flow-start beaconing (there is one flow).
        assert!(!rules.iter().any(|r| r == "beacon.periodic"));
        let top = f
            .iter()
            .find(|x| x.entity == "10.1.0.101")
            .expect("finding");
        let r = top
            .reasons
            .iter()
            .find(|r| r.rule_id == "beacon.http_requests")
            .expect("reason");
        assert_eq!(r.signal, "request_regularity");
        assert_eq!(r.attack_technique.as_deref(), Some("T1071.001"));
        // Evidence: http rows' frames on the C2 flow.
        for fr in &r.evidence.frame_nos {
            let h = src
                .http
                .iter()
                .find(|h| h.frame_no == *fr)
                .expect("http row");
            assert_eq!(h.host.as_deref(), Some("194.180.191.64"));
        }
        assert_eq!(
            top_fp(&f, "10.1.0.101"),
            top10_fp(&f, &["10.1.0.101".to_string()])
        );
    }
}

fn top_fp(f: &[Finding], c2: &str) -> usize {
    top10_fp(f, &[c2.to_string()])
}

#[test]
fn stealc_like_post_burst_ranks_top() {
    for seed in SEEDS {
        let src = office_with(seed, |sy| stealc_like(sy, "10.1.0.102"));
        let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
        assert_evidence_valid(&src, &f);
        assert!(
            rank(&f, "10.1.0.102").is_some_and(|r| r <= 2),
            "seed {seed}\n{}",
            summary(&f)
        );
        let top = f
            .iter()
            .find(|x| x.entity == "10.1.0.102")
            .expect("finding");
        let r = &top.reasons[0];
        assert_eq!(r.rule_id, "http.post_exfil");
        assert_eq!(r.attack_technique.as_deref(), Some("T1041"));
        assert!(
            r.explanation.contains("/4a815a53876a4172.php"),
            "{}",
            r.explanation
        );
        assert!(top_fp(&f, "10.1.0.102") <= 3);
    }
}

#[test]
fn benign_keepalive_poller_to_named_host_is_not_ranked_as_c2() {
    // Counter-example for beacon.http_requests: a named API polled every
    // 30 s over one keep-alive connection all day.
    for seed in SEEDS {
        let src = office_with(seed, |sy| keepalive_poller(sy, "10.1.0.103", 3.0));
        let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
        assert_evidence_valid(&src, &f);
        assert!(top10_fp(&f, &[]) <= 3, "seed {seed}\n{}", summary(&f));
        // Not reported at all: the named-Host damping keeps even a perfectly
        // regular poller under min_score.
        let rules = rules_of(&f, "10.1.0.103");
        assert!(
            rules.is_empty(),
            "poller reported: {rules:?}\n{}",
            summary(&f)
        );
        // With a milder damping it would surface, damped, saying why.
        let defs: Vec<_> = repo_rules()
            .defs()
            .cloned()
            .map(|mut d| {
                if d.id == "beacon.http_requests" {
                    d.params
                        .insert("named_host_factor".into(), serde_json::json!(0.6));
                }
                d
            })
            .collect();
        let mild = walleye_detect::RuleSet::from_defs(defs).expect("rules");
        let f2 = run(&src, &mild, &repo_allowlist()).expect("run");
        let x = f2
            .iter()
            .find(|x| x.entity == "10.1.0.103")
            .expect("visible when mild");
        assert!(
            x.reasons[0]
                .explanation
                .contains("name host status.saas-dashboard.com")
        );
        // With a real C2 in the same office, the C2 outranks the poller.
        let src = office_with(seed, |sy| {
            keepalive_poller(sy, "10.1.0.103", 3.0);
            netsupport_like(sy, "10.1.0.101", 1.5);
        });
        let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
        let c2 = rank(&f, "10.1.0.101").expect("c2");
        if let Some(p) = rank(&f, "10.1.0.103") {
            assert!(c2 < p, "poller {p} above C2 {c2}\n{}", summary(&f));
        }
    }
}

#[test]
fn benign_chatty_web_app_and_named_upload_do_not_trigger_exfil() {
    // Counter-example for http.post_exfil: an app POSTing analytics every
    // 2-5 s to its named API, and a 30 MB chunked upload to a named host.
    for seed in SEEDS {
        let src = office_with(seed, |sy| chatty_web_app(sy, "10.1.0.104"));
        let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
        assert_evidence_valid(&src, &f);
        let rules = rules_of(&f, "10.1.0.104");
        assert!(
            !rules.iter().any(|r| r == "http.post_exfil"),
            "{rules:?}\n{}",
            summary(&f)
        );
        assert!(top10_fp(&f, &[]) <= 3, "seed {seed}\n{}", summary(&f));
    }
}

#[test]
fn https_and_proxy_connect_on_443_do_not_trigger_tls_port() {
    // Counter-example for http.tls_port: normal HTTPS (TLS rows, no HTTP
    // rows) and proxy CONNECT set-up on 443.
    let mut sy = Synth::new(4);
    let h = "10.1.0.105";
    for k in 0..40i64 {
        sy.tls(
            T0 + k * 97 * S,
            h,
            "151.101.1.1",
            "www.example.org",
            900,
            30_000,
        );
    }
    let reqs: Vec<Req> = (0..20)
        .map(|k| Req {
            dt: k * 13 * S,
            method: "CONNECT",
            host: "www.example.org:443".into(),
            uri: "www.example.org:443".into(),
            up: 200,
            down: 40,
        })
        .collect();
    sy.session(T0, h, "151.101.1.2", 443, reqs);
    let src = sy.build();
    let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
    assert!(
        !rules_of(&f, h).iter().any(|r| r == "http.tls_port"),
        "{}",
        summary(&f)
    );
}

#[test]
fn one_request_per_connection_is_not_double_counted() {
    // A flow-start beacon over plain HTTP (one request per connection) is
    // reported by beacon.periodic only, not again by beacon.http_requests.
    let mut sy = Synth::new(6);
    let h = "10.1.0.106";
    for k in 0..80i64 {
        sy.http(T0 + k * 60 * S, h, "45.77.12.34", "45.77.12.34", 400, 300);
    }
    let src = sy.build();
    let f = run(&src, &repo_rules(), &repo_allowlist()).expect("run");
    let rules = rules_of(&f, h);
    assert!(rules.iter().any(|r| r == "beacon.periodic"), "{rules:?}");
    assert!(
        !rules.iter().any(|r| r == "beacon.http_requests"),
        "{rules:?}"
    );
}
