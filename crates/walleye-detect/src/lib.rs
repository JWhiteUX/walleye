//! Rule loader, beaconing and DNS detectors, scoring. Owner: Agent C.
//!
//! ```text
//! load_rules(dir) ─▶ RuleSet ─┐
//! DetectSource ───────────────┼─▶ run() ─▶ Vec<Finding> (one per internal host, score desc)
//! Allowlist ──────────────────┘
//! ```
//!
//! `run` streams the source with `for_each_*` (flows once, dns once, then
//! tls/http only when a beacon candidate needs a destination name) and keeps
//! bounded per-pair / per-domain state. Every reason carries evidence
//! (flow ids and frame numbers, capped at `EVIDENCE_CAP`).
//!
//! Entities are internal hosts (RFC 1918, CGNAT, link-local, ULA). If a
//! capture contains no internal source at all (e.g. public addresses only),
//! every non-special source address is eligible instead, so a C2 host is
//! never invisible just because of its addressing.

mod beacon;
mod combine;
mod dns;
mod rules;
mod util;

use std::collections::{HashMap, HashSet};

use walleye_core::error::ApiResult;
use walleye_core::sink::DetectSource;
use walleye_core::{Allowlist, Finding};

pub use rules::{DETECTORS, Rule, RuleSet, load_rules};
pub use util::finding_id;

use crate::util::{AddrClass, Hosts};

/// Run every enabled rule over `src` and return per-host findings sorted by
/// score (desc), then entity.
pub fn run(src: &dyn DetectSource, rules: &RuleSet, allow: &Allowlist) -> ApiResult<Vec<Finding>> {
    let mut hosts = Hosts::default();
    let mut bcol = beacon::Collector::default();
    let want_beacon = rules.enabled("beaconing").next().is_some();
    let want_dns = dns::DnsCollector::wanted(rules);
    let mut flow_host: HashMap<u64, u32> = HashMap::new();
    let mut internal: HashSet<u32> = HashSet::new();

    // Pass 1: flows.
    src.for_each_flow(&mut |f| {
        let s = hosts.intern(&f.src_ip);
        let d = hosts.intern(&f.dst_ip);
        if hosts.class(s) == AddrClass::Internal {
            internal.insert(s);
        }
        if want_beacon {
            bcol.observe(&hosts, s, d, f);
        }
        if want_dns {
            flow_host.insert(f.flow_id, s);
        }
    })?;

    let any_internal = !internal.is_empty();
    let entity_ok = |h: u32| match hosts.class(h) {
        AddrClass::Internal => true,
        AddrClass::External => !any_internal,
        AddrClass::Special => false,
    };

    // Beacon candidates (before damping) decide which names we need.
    let mut cands = Vec::new();
    for (idx, rule) in rules.enabled("beaconing") {
        cands.extend(beacon::analyze(&bcol, rule, idx, &entity_ok));
    }
    let mut names = beacon::DstNames::for_candidates(&cands);

    // Pass 2: dns.
    let mut dcol = dns::DnsCollector::new(rules);
    let mut responses = 0u64;
    if want_dns || !names.is_empty() {
        src.for_each_dns(&mut |r| {
            if r.is_response {
                responses += 1;
                if !names.is_empty() {
                    for a in &r.answers {
                        if let Some(id) = hosts.lookup(a) {
                            if names.wants_dst(id) {
                                names.add(id, &r.query);
                            }
                        }
                    }
                }
            }
            if want_dns {
                if let Some(&h) = flow_host.get(&r.flow_id) {
                    dcol.observe(h, r, !r.is_response);
                }
            }
        })?;
    }
    // Captures with responses only (e.g. one-sided taps): treat responses as
    // the query stream.
    if want_dns && dcol.query_rows == 0 && responses > 0 {
        dcol = dns::DnsCollector::new(rules);
        src.for_each_dns(&mut |r| {
            if r.is_response {
                if let Some(&h) = flow_host.get(&r.flow_id) {
                    dcol.observe(h, r, true);
                }
            }
        })?;
    }

    // Pass 3 (only if needed): TLS SNI / HTTP Host for candidate destinations.
    if !names.is_empty() {
        src.for_each_tls(&mut |t| {
            if let (Some(dst), Some(sni)) = (names.dst_of_flow(t.flow_id), t.sni.as_deref()) {
                names.add(dst, sni);
            }
        })?;
        src.for_each_http(&mut |h| {
            if let (Some(dst), Some(host)) = (names.dst_of_flow(h.flow_id), h.host.as_deref()) {
                let host = host.rsplit_once(':').map_or(host, |(h, p)| {
                    if p.bytes().all(|b| b.is_ascii_digit()) {
                        h
                    } else {
                        host
                    }
                });
                if host.parse::<std::net::IpAddr>().is_err() {
                    names.add(dst, host);
                }
            }
        })?;
    }

    let mut hits = Vec::new();
    let cx = beacon::FinalizeCtx {
        hosts: &hosts,
        col: &bcol,
        names: &names,
        allow,
        internal_hosts: internal.len(),
    };
    for c in &cands {
        if let Some(rule) = rules.rules().get(c.rule_idx) {
            hits.extend(beacon::finalize(c, rule, &cx));
        }
    }
    for (idx, rule) in rules.rules().iter().enumerate() {
        if !rule.def.enabled {
            continue;
        }
        match rule.def.detector.as_str() {
            "dns_nxdomain_burst" => {
                dns::analyze_nx(&dcol, &hosts, allow, rule, idx, &entity_ok, &mut hits)
            }
            d if d.starts_with("dns_") => dns::analyze_parents(
                &dcol,
                &hosts,
                allow,
                rule,
                idx,
                &entity_ok,
                internal.len(),
                &mut hits,
            ),
            _ => {}
        }
    }
    let _ = dcol.dropped_parents();
    Ok(combine::combine(hits, &hosts))
}
