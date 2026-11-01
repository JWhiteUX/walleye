//! Acceptance properties on synthetic scenarios (the lead verifies the same
//! properties on real captures with `tools/eval` at integration):
//!
//! 1. The known C2 host ranks in the top 5.
//! 2. Top-10 false-positive rate ≤ 30 % on the benign office day.
//! 3. Every finding has ≥ 1 reason, every reason non-empty evidence that
//!    resolves to existing flows / frames.
//!
//! Each property is checked over several seeds so the thresholds are not
//! tuned to one random draw. Run with `--nocapture` to see the rankings.

mod common;

use common::*;
use walleye_detect::run;

const SEEDS: [u64; 5] = [1, 2, 3, 7, 42];

fn detect(sc: &Scenario) -> Vec<walleye_core::Finding> {
    let f = run(&sc.src, &repo_rules(), &repo_allowlist()).expect("run");
    println!(
        "--- {} ({} flows, {} dns rows) ---\n{}",
        sc.name,
        sc.src.flows.len(),
        sc.src.dns.len(),
        summary(&f)
    );
    f
}

fn assert_c2_top5(make: fn(u64) -> Scenario) {
    for seed in SEEDS {
        let sc = make(seed);
        let f = detect(&sc);
        assert_evidence_valid(&sc.src, &f);
        for c2 in &sc.c2_hosts {
            let r = rank(&f, c2);
            assert!(
                r.is_some_and(|r| r <= 5),
                "{} seed {seed}: C2 {c2} rank {r:?}\n{}",
                sc.name,
                summary(&f)
            );
        }
        let fp = top10_fp(&f, &sc.c2_hosts);
        assert!(
            fp <= 3,
            "{} seed {seed}: {fp} FPs in top 10\n{}",
            sc.name,
            summary(&f)
        );
    }
}

#[test]
fn beacon_60s_c2_in_top5() {
    assert_c2_top5(beacon_scenario);
}

#[test]
fn jittered_beacon_c2_in_top5() {
    assert_c2_top5(jitter_scenario);
}

#[test]
fn dns_tunnel_c2_in_top5() {
    assert_c2_top5(tunnel_scenario);
}

#[test]
fn dga_c2_in_top5() {
    assert_c2_top5(dga_scenario);
}

#[test]
fn mix_all_c2_in_top5_and_fp_bounded() {
    assert_c2_top5(mix_scenario);
}

#[test]
fn c2_is_rank_1_on_single_attacker_scenarios() {
    // Stronger than the gate: a lone, unambiguous attacker tops the queue.
    // Not asserted for the ±25 % jittered beacon or DGA: the office's
    // single-host backup agent (600 s ±1 %, not allowlisted) is legitimately
    // more regular, and nothing in flow metadata says it is benign.
    for make in [beacon_scenario, tunnel_scenario] {
        let sc = make(11);
        let f = detect(&sc);
        assert_eq!(
            rank(&f, &sc.c2_hosts[0]),
            Some(1),
            "{}\n{}",
            sc.name,
            summary(&f)
        );
    }
}

#[test]
fn benign_top10_fp_rate_at_most_30pct() {
    for seed in SEEDS {
        let sc = benign(seed);
        let f = detect(&sc);
        assert_evidence_valid(&sc.src, &f);
        let fp = top10_fp(&f, &[]);
        // FP rate over a top-10 list: at most 3 benign hosts may appear.
        assert!(fp <= 3, "benign seed {seed}: {fp}/10 FPs\n{}", summary(&f));
    }
}

#[test]
fn attack_technique_mapping() {
    let sc = mix_scenario(5);
    let f = detect(&sc);
    let tech = |host: &str| {
        f.iter()
            .find(|x| x.entity == host)
            .and_then(|x| x.attack_technique.clone())
    };
    assert_eq!(tech(C2_BEACON).as_deref(), Some("T1071"));
    assert_eq!(tech(C2_JITTER).as_deref(), Some("T1071"));
    // The DGA host also beacons to the name that resolved, so beaconing may
    // top it; the NXDOMAIN reason must still be present and mapped.
    let dga = f.iter().find(|x| x.entity == C2_DGA).expect("dga finding");
    let nx = dga
        .reasons
        .iter()
        .find(|r| r.rule_id == "dns.nxdomain_burst")
        .expect("nxdomain reason");
    assert_eq!(nx.attack_technique.as_deref(), Some("T1568.002"));
    let t = tech(C2_TUNNEL).expect("tunnel finding");
    assert!(t == "T1071.004" || t == "T1048", "tunnel technique {t}");
    let tunnel = f.iter().find(|x| x.entity == C2_TUNNEL).expect("tunnel");
    let rules: Vec<&str> = tunnel.reasons.iter().map(|r| r.rule_id.as_str()).collect();
    for want in ["dns.entropy", "dns.length", "dns.tunnel"] {
        assert!(rules.contains(&want), "tunnel lacks {want}: {rules:?}");
    }
}

#[test]
fn beacon_explanation_names_destination_and_period() {
    let sc = beacon_scenario(3);
    let f = detect(&sc);
    let top = &f[0];
    assert_eq!(top.entity, C2_BEACON);
    assert_eq!(top.detector, "beaconing");
    assert!(top.title.contains("185.199.110.77"), "{}", top.title);
    assert!(top.title.contains("cdn-update.top"), "{}", top.title);
    let r = &top.reasons[0];
    assert_eq!(r.rule_id, "beacon.periodic");
    assert!(r.explanation.contains("every 60"), "{}", r.explanation);
    assert!(r.value < 0.03, "jitter {}", r.value);
    // Evidence: the beacon flows, frame = each flow's first_frame.
    for (fid, fr) in r.evidence.flow_ids.iter().zip(&r.evidence.frame_nos) {
        let flow = sc
            .src
            .flows
            .iter()
            .find(|x| x.flow_id == *fid)
            .expect("flow");
        assert_eq!(flow.first_frame, *fr);
        assert_eq!(flow.dst_ip, "185.199.110.77");
    }
}

#[test]
fn deterministic_across_runs() {
    let sc = mix_scenario(9);
    let a = run(&sc.src, &repo_rules(), &repo_allowlist()).expect("run");
    let b = run(&sc.src, &repo_rules(), &repo_allowlist()).expect("run");
    assert_eq!(a, b);
    let sc2 = mix_scenario(9);
    let c = run(&sc2.src, &repo_rules(), &repo_allowlist()).expect("run");
    assert_eq!(a, c, "same seed must give the same findings");
}
