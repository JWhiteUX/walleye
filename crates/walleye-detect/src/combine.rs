//! Combine rule hits into one finding per internal host (CONTRACTS §2).
//!
//! - Per (host, rule) only the strongest hit is kept (one beacon pair, one
//!   domain), so a host with many mildly odd destinations does not add up
//!   to a high score; different rules on the same host do add up, because
//!   corroborating signals (entropy + length + volume on one tunnel domain)
//!   are exactly what should raise confidence.
//! - Reasons are sorted by weight descending; the top one sets `detector`,
//!   `attack_technique` and the title.
//! - `score = min(100, Σ reason.weight)`.

use std::collections::BTreeMap;

use walleye_core::{Finding, Reason, Ts};

use crate::util::{Hosts, finding_id};

/// One rule's contribution to one host.
#[derive(Debug, Clone)]
pub(crate) struct Hit {
    pub(crate) host: u32,
    pub(crate) rule_idx: usize,
    /// "beaconing" | "dns": the finding's `detector` when this hit is on top.
    pub(crate) detector_family: &'static str,
    pub(crate) title: String,
    /// Deterministic tie-break between equal-weight hits (dst or domain).
    pub(crate) tiebreak: String,
    pub(crate) ts_first: Ts,
    pub(crate) ts_last: Ts,
    pub(crate) reason: Reason,
}

fn better(a: &Hit, b: &Hit) -> bool {
    a.reason
        .weight
        .total_cmp(&b.reason.weight)
        .then_with(|| b.tiebreak.cmp(&a.tiebreak))
        .is_gt()
}

pub(crate) fn combine(hits: Vec<Hit>, hosts: &Hosts) -> Vec<Finding> {
    let mut best: BTreeMap<(u32, usize), Hit> = BTreeMap::new();
    for h in hits {
        if h.reason.evidence.is_empty() || h.reason.weight <= 0.0 {
            continue;
        }
        match best.get(&(h.host, h.rule_idx)) {
            Some(cur) if !better(&h, cur) => {}
            _ => {
                best.insert((h.host, h.rule_idx), h);
            }
        }
    }
    let mut per_host: BTreeMap<u32, Vec<Hit>> = BTreeMap::new();
    for ((host, _), h) in best {
        per_host.entry(host).or_default().push(h);
    }
    let mut findings: Vec<Finding> = per_host
        .into_iter()
        .filter_map(|(host, mut hits)| {
            hits.sort_by(|a, b| {
                b.reason
                    .weight
                    .total_cmp(&a.reason.weight)
                    .then_with(|| a.reason.rule_id.cmp(&b.reason.rule_id))
                    .then_with(|| a.tiebreak.cmp(&b.tiebreak))
            });
            let top = hits.first()?;
            let entity = hosts.name(host).to_string();
            let detector = top.detector_family.to_string();
            let score: f64 = hits.iter().map(|h| h.reason.weight).sum::<f64>().min(100.0);
            let score = (score * 10.0).round() / 10.0;
            Some(Finding {
                finding_id: finding_id(&detector, "host", &entity),
                title: top.title.clone(),
                detector,
                entity_type: "host".into(),
                entity,
                score,
                attack_technique: top.reason.attack_technique.clone(),
                ts_first: hits.iter().map(|h| h.ts_first).min().unwrap_or(0),
                ts_last: hits.iter().map(|h| h.ts_last).max().unwrap_or(0),
                reasons: hits.into_iter().map(|h| h.reason).collect(),
                verdict: None,
            })
        })
        .collect();
    findings.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.entity.cmp(&b.entity))
    });
    findings
}
