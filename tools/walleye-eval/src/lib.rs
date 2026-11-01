//! Detection-quality evaluation (docs/CONTRACTS.md §9). Owner: Agent G.
//!
//! Definitions, exactly as fixed in CONTRACTS.md §9 (gate: known C2 in the
//! top 5 on all labelled samples; top-10 FP ≤ 30% on benign):
//!
//! * Findings are ranked by `score` descending, with no score floor; ties
//!   break on `finding_id` so the ranking is deterministic.
//! * A finding **matches** when its `entity` is in `c2_hosts`.
//! * **C2 rank** is the best (lowest) 1-based rank among matching findings.
//! * **hit@k** is `C2 rank <= k`. Not applicable to benign samples.
//! * **FP rate@10** = findings ranked 1–10 whose entity is not in
//!   `c2_hosts`, divided by a fixed 10. On a `benign` sample every top-10
//!   finding is a false positive, so 3 findings there give 30%.
//! * **Evidence OK** means every finding has at least one reason and every
//!   reason has non-empty evidence (the "evidence or it didn't happen" rule).

use serde::{Deserialize, Serialize};
use walleye_core::findings::Finding;

pub const TOP_N: usize = 10;

/// Ground-truth label file (`*.labels.json`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LabelFile {
    #[serde(default)]
    pub scenario: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub c2_hosts: Vec<String>,
    #[serde(default)]
    pub bad_destinations: Vec<String>,
    #[serde(default)]
    pub benign: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SampleResult {
    pub sample: String,
    pub benign: bool,
    pub findings: usize,
    /// 1-based; `None` when no finding matches.
    pub c2_rank: Option<usize>,
    /// `None` on benign samples.
    pub hit: Option<bool>,
    pub fp_top10: usize,
    pub fp_rate: f64,
    pub evidence_ok: bool,
    /// Entities of the top 3 findings with scores, for the notes column.
    pub top: Vec<(String, f64)>,
}

/// CONTRACTS §9: a finding is a true positive iff its `entity` is exactly
/// one of the labelled `c2_hosts` (`bad_destinations` is informational).
pub fn matches(f: &Finding, labels: &LabelFile) -> bool {
    labels.c2_hosts.contains(&f.entity)
}

/// Findings in queue order: score desc, then `finding_id`.
pub fn ranked(findings: &[Finding]) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = findings.iter().collect();
    v.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    v
}

pub fn evaluate(sample: &str, findings: &[Finding], labels: &LabelFile, k: usize) -> SampleResult {
    let order = ranked(findings);
    let c2_rank = if labels.benign {
        None
    } else {
        order.iter().position(|f| matches(f, labels)).map(|i| i + 1)
    };
    let fp_top10 = order
        .iter()
        .take(TOP_N)
        .filter(|f| labels.benign || !matches(f, labels))
        .count();
    let evidence_ok = findings
        .iter()
        .all(|f| !f.reasons.is_empty() && f.reasons.iter().all(|r| !r.evidence.is_empty()));
    SampleResult {
        sample: sample.to_string(),
        benign: labels.benign,
        findings: findings.len(),
        c2_rank,
        hit: (!labels.benign).then(|| c2_rank.is_some_and(|r| r <= k)),
        fp_top10,
        fp_rate: fp_top10 as f64 / TOP_N as f64,
        evidence_ok,
        top: order
            .iter()
            .take(3)
            .map(|f| (f.entity.clone(), f.score))
            .collect(),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Gates {
    pub k: usize,
    /// Maximum FP rate allowed on benign samples.
    pub max_fp_benign: f64,
}

/// Human-readable gate failures (empty = all gates pass).
pub fn gate_failures(results: &[SampleResult], gates: &Gates) -> Vec<String> {
    let mut out = Vec::new();
    for r in results {
        if r.hit == Some(false) {
            out.push(format!(
                "{}: C2 rank {} is not within top {}",
                r.sample,
                r.c2_rank.map_or("none".to_string(), |x| x.to_string()),
                gates.k
            ));
        }
        if r.benign && r.fp_rate > gates.max_fp_benign + 1e-12 {
            out.push(format!(
                "{}: benign FP rate {:.0}% exceeds {:.0}%",
                r.sample,
                r.fp_rate * 100.0,
                gates.max_fp_benign * 100.0
            ));
        }
        if !r.evidence_ok {
            out.push(format!(
                "{}: a finding has no reasons or a reason has empty evidence",
                r.sample
            ));
        }
    }
    out
}

/// Markdown table ready to paste into docs/BUILD_LOG.md.
pub fn markdown(results: &[SampleResult], k: usize) -> String {
    let mut s = format!(
        "| Sample | Type | Findings | C2 rank | hit@{k} | FP in top 10 | FP rate@10 | Evidence OK | Top findings |\n\
         |---|---|---:|---:|:---:|---:|---:|:---:|---|\n"
    );
    for r in results {
        let rank = if r.benign {
            "n/a".to_string()
        } else {
            r.c2_rank.map_or("none".to_string(), |x| x.to_string())
        };
        let hit = match r.hit {
            None => "n/a",
            Some(true) => "yes",
            Some(false) => "**no**",
        };
        let top = if r.top.is_empty() {
            "—".to_string()
        } else {
            r.top
                .iter()
                .map(|(e, sc)| format!("{e} ({sc:.0})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.0}% | {} | {} |\n",
            r.sample.replace('|', "\\|"),
            if r.benign { "benign" } else { "malicious" },
            r.findings,
            rank,
            hit,
            r.fp_top10,
            r.fp_rate * 100.0,
            if r.evidence_ok { "yes" } else { "**no**" },
            top.replace('|', "\\|"),
        ));
    }
    let mal: Vec<&SampleResult> = results.iter().filter(|r| !r.benign).collect();
    if !mal.is_empty() {
        let hits = mal.iter().filter(|r| r.hit == Some(true)).count();
        s.push_str(&format!(
            "\nhit@{k}: {hits}/{} malicious samples. FP rate@10 = non-matching findings in the top 10 / 10.\n",
            mal.len()
        ));
    } else {
        s.push_str("\nFP rate@10 = non-matching findings in the top 10 / 10.\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use walleye_core::findings::{Evidence, Reason};

    fn finding(entity: &str, score: f64) -> Finding {
        finding_typed("host", entity, score)
    }

    fn finding_typed(entity_type: &str, entity: &str, score: f64) -> Finding {
        Finding {
            finding_id: format!("{entity_type}:{entity}"),
            title: "t".into(),
            detector: "beaconing".into(),
            entity_type: entity_type.into(),
            entity: entity.into(),
            score,
            attack_technique: Some("T1071".into()),
            ts_first: 0,
            ts_last: 1,
            reasons: vec![Reason {
                rule_id: "beacon.periodic".into(),
                signal: "regularity".into(),
                value: 0.9,
                unit: None,
                weight: score,
                explanation: "x".into(),
                attack_technique: None,
                evidence: Evidence {
                    flow_ids: vec![1],
                    frame_nos: vec![1],
                    truncated: false,
                    total: 1,
                },
            }],
            verdict: None,
        }
    }

    fn labels(c2: &[&str], bad: &[&str], benign: bool) -> LabelFile {
        LabelFile {
            c2_hosts: c2.iter().map(|s| s.to_string()).collect(),
            bad_destinations: bad.iter().map(|s| s.to_string()).collect(),
            benign,
            ..LabelFile::default()
        }
    }

    #[test]
    fn rank_and_hit_at_k() {
        let f = vec![
            finding("10.0.0.15", 70.0),
            finding("10.0.0.23", 65.0),
            finding("10.0.0.30", 90.0),
        ];
        let l = labels(&["10.0.0.23"], &[], false);
        let r = evaluate("beacon", &f, &l, 5);
        assert_eq!(r.c2_rank, Some(3));
        assert_eq!(r.hit, Some(true));
        assert_eq!(r.fp_top10, 2);
        assert!((r.fp_rate - 0.2).abs() < 1e-9);
        let r1 = evaluate("beacon", &f, &l, 2);
        assert_eq!(r1.hit, Some(false));
    }

    #[test]
    fn missing_c2_is_a_miss() {
        let f = vec![finding("10.0.0.15", 70.0)];
        let r = evaluate("x", &f, &labels(&["10.0.0.23"], &[], false), 5);
        assert_eq!(r.c2_rank, None);
        assert_eq!(r.hit, Some(false));
    }

    #[test]
    fn benign_counts_every_top10_finding_as_fp() {
        let f: Vec<Finding> = (0..12)
            .map(|i| finding(&format!("10.0.0.{i}"), f64::from(i)))
            .collect();
        let r = evaluate("office", &f, &labels(&[], &[], true), 5);
        assert_eq!(r.fp_top10, 10);
        assert!((r.fp_rate - 1.0).abs() < 1e-9);
        assert_eq!(r.hit, None);
        assert_eq!(r.c2_rank, None);

        let few = vec![finding("10.0.0.15", 40.0), finding("10.0.0.16", 35.0)];
        let r = evaluate("office", &few, &labels(&[], &[], true), 5);
        assert!((r.fp_rate - 0.2).abs() < 1e-9);
        let gates = Gates {
            k: 5,
            max_fp_benign: 0.3,
        };
        assert!(gate_failures(&[r], &gates).is_empty());
    }

    #[test]
    fn ties_break_on_finding_id() {
        let f = vec![finding("10.0.0.9", 50.0), finding("10.0.0.23", 50.0)];
        let order = ranked(&f);
        assert_eq!(order[0].entity, "10.0.0.23"); // "host:10.0.0.23" < "host:10.0.0.9"
    }

    #[test]
    fn only_exact_c2_host_entities_match() {
        let l = labels(&["10.0.0.23"], &["cdn-update.top", "185.199.110.77"], false);
        assert!(matches(&finding_typed("host", "10.0.0.23", 1.0), &l));
        // bad_destinations never count, and no prefix/pair matching.
        assert!(!matches(
            &finding_typed("domain", "cdn-update.top", 1.0),
            &l
        ));
        assert!(!matches(&finding_typed("host", "185.199.110.77", 1.0), &l));
        assert!(!matches(
            &finding_typed("pair", "10.0.0.23->1.2.3.4", 1.0),
            &l
        ));
        assert!(!matches(&finding_typed("host", "10.0.0.230", 1.0), &l));
    }

    #[test]
    fn c2_rank_is_best_rank_and_low_scores_still_count() {
        let f = vec![
            finding("10.0.0.23", 0.5),
            finding("10.0.0.1", 0.1),
            finding("10.0.0.23", 99.0), // duplicate entity, different id below
        ];
        let mut f = f;
        f[2].finding_id = "other".into();
        let r = evaluate("x", &f, &labels(&["10.0.0.23"], &[], false), 5);
        assert_eq!(r.c2_rank, Some(1));
        assert_eq!(r.fp_top10, 1, "no score floor: the 0.1 finding is an FP");
    }

    #[test]
    fn gates_report_misses_fp_and_empty_evidence() {
        let mut bad = finding("10.0.0.1", 10.0);
        bad.reasons[0].evidence = Evidence::default();
        let results = vec![
            evaluate(
                "beacon",
                &[finding("10.0.0.9", 9.0)],
                &labels(&["10.0.0.23"], &[], false),
                5,
            ),
            evaluate(
                "office",
                &(0..4)
                    .map(|i| finding(&format!("10.0.1.{i}"), 1.0))
                    .collect::<Vec<_>>(),
                &labels(&[], &[], true),
                5,
            ),
            evaluate("dga", &[bad], &labels(&["10.0.0.1"], &[], false), 5),
        ];
        let fails = gate_failures(
            &results,
            &Gates {
                k: 5,
                max_fp_benign: 0.3,
            },
        );
        assert_eq!(fails.len(), 3, "{fails:?}");
        assert!(fails[0].contains("beacon"));
        assert!(fails[1].contains("office") && fails[1].contains("40%"));
        assert!(fails[2].contains("evidence"));
    }

    #[test]
    fn markdown_has_header_and_one_row_per_sample() {
        let results = vec![
            evaluate(
                "beacon",
                &[finding("10.0.0.23", 80.0)],
                &labels(&["10.0.0.23"], &[], false),
                5,
            ),
            evaluate("office", &[], &labels(&[], &[], true), 5),
        ];
        let md = markdown(&results, 5);
        let rows: Vec<&str> = md.lines().filter(|l| l.starts_with('|')).collect();
        assert_eq!(rows.len(), 4);
        assert!(rows[0].contains("hit@5"));
        assert!(
            rows[2].starts_with(
                "| beacon | malicious | 1 | 1 | yes | 0 | 0% | yes | 10.0.0.23 (80) |"
            )
        );
        assert!(rows[3].starts_with("| office | benign | 0 | n/a | n/a | 0 | 0% | yes | — |"));
        assert!(md.contains("hit@5: 1/1"));
    }

    #[test]
    fn label_file_parses_contract_example() {
        let j = r#"{"scenario":"beacon","source":"walleye-gen seed=1","sha256":"ab",
                    "c2_hosts":["10.0.0.23"],"bad_destinations":["185.199.110.77","cdn-update.top"],
                    "benign":false,"notes":"60 s ±3% TLS beacon"}"#;
        let l: LabelFile = serde_json::from_str(j).expect("parse");
        assert_eq!(l.c2_hosts, vec!["10.0.0.23"]);
        assert!(!l.benign);
    }
}
