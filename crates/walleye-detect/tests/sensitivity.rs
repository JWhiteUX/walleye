//! Parameter sensitivity sweep (diagnostic, not a gate). Prints, for each
//! single-parameter change from the shipped defaults, the worst C2 rank over
//! the attack scenarios and the worst benign top-10 FP count over seeds.
//!
//! ```sh
//! cargo test -p walleye-detect --release --test sensitivity -- --ignored --nocapture
//! ```

mod common;

use common::*;
use walleye_core::rules::RuleDef;
use walleye_detect::{RuleSet, run};

fn with(rule: &str, key: &str, val: serde_json::Value) -> RuleSet {
    let defs: Vec<RuleDef> = repo_rules()
        .defs()
        .cloned()
        .map(|mut d| {
            if d.id == rule {
                if key == "min_score" {
                    d.min_score = val.as_f64().unwrap_or(0.0);
                } else {
                    d.params.insert(key.into(), val.clone());
                }
            }
            d
        })
        .collect();
    RuleSet::from_defs(defs).expect("rules")
}

#[test]
#[ignore = "diagnostic sweep; see module docs"]
fn sweep() {
    let allow = repo_allowlist();
    let seeds = [1u64, 2, 3];
    let attacks: Vec<Scenario> = seeds
        .iter()
        .flat_map(|&s| {
            [
                beacon_scenario(s),
                jitter_scenario(s),
                tunnel_scenario(s),
                dga_scenario(s),
                mix_scenario(s),
            ]
        })
        .collect();
    let benigns: Vec<Scenario> = seeds.iter().map(|&s| benign(s)).collect();
    let cases: Vec<(&str, &str, serde_json::Value)> = vec![
        ("-", "-", 0.into()),
        ("beacon.periodic", "prevalence_factor", 0.4.into()),
        ("beacon.periodic", "prevalence_factor", 0.5.into()),
        ("beacon.periodic", "max_jitter", 0.25.into()),
        ("beacon.periodic", "max_jitter", 0.5.into()),
        ("beacon.periodic", "min_score", 25.into()),
        ("beacon.periodic", "min_score", 50.into()),
        ("beacon.periodic", "min_count", 5.into()),
        ("beacon.periodic", "min_count", 16.into()),
        ("dns.entropy", "prevalence_factor", 1.0.into()),
        ("dns.entropy", "min_score", 8.into()),
        ("dns.entropy", "entropy_low", 2.5.into()),
        ("dns.nxdomain_burst", "min_burst", 5.into()),
        ("dns.nxdomain_burst", "min_burst", 30.into()),
        ("dns.subdomain_rate", "min_unique", 8.into()),
    ];
    println!(
        "| rule | param | value | worst C2 rank | worst benign FP/10 | worst attack-scenario FP/10 |"
    );
    println!("|---|---|---|---|---|---|");
    for (rule, key, val) in cases {
        let rs = if rule == "-" {
            repo_rules()
        } else {
            with(rule, key, val.clone())
        };
        let mut worst_rank = 0usize;
        let mut worst_afp = 0usize;
        for sc in &attacks {
            let f = run(&sc.src, &rs, &allow).expect("run");
            for c in &sc.c2_hosts {
                worst_rank = worst_rank.max(rank(&f, c).unwrap_or(999));
            }
            worst_afp = worst_afp.max(top10_fp(&f, &sc.c2_hosts));
        }
        let worst_bfp = benigns
            .iter()
            .map(|sc| top10_fp(&run(&sc.src, &rs, &allow).expect("run"), &[]))
            .max()
            .unwrap_or(0);
        println!("| {rule} | {key} | {val} | {worst_rank} | {worst_bfp} | {worst_afp} |");
    }
}
