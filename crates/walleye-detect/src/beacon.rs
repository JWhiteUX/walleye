//! Beaconing: per (internal src, external dst) pair, the series of flow
//! starts. Starts closer than `merge_gap_s` are one "contact" (a beacon that
//! opens two sockets is still one check-in). Over the contacts we measure:
//!
//! - median inter-arrival interval and jitter = MAD / median (robust to the
//!   odd missed or doubled beacon),
//! - contact count and total duration,
//! - payload uniformity = 1 − coefficient of variation of bytes per flow.
//!
//! Scoring: `regularity` is the gate. The other signals (`count`, `duration`,
//! `payload_uniformity`) are *supporting* evidence and are scaled by the
//! regularity strength, so a long, busy but irregular pair (browsing) cannot
//! reach `min_score` on volume alone.
//!
//! Down-weighting, each said in the explanation: destination allowlisted
//! (the IP, or a name a DNS answer resolved to it; never SNI or HTTP Host,
//! which the client chooses),
//! destination under a rule-level `known_good_suffixes` entry, and
//! destination contacted by a large share of internal hosts (fleet-wide
//! software, not one compromised host).

use std::collections::{BTreeMap, HashMap, HashSet};

use walleye_core::rules::render_template;
use walleye_core::{Allowlist, Evidence, FlowId, FlowRow, FrameNo, Reason, Ts};

use crate::combine::Hit;
use crate::rules::Rule;
use crate::util::{AddrClass, Hosts, display, fmt_num, has_suffix, median, ramp, round1};

/// Contacts stored per pair; beyond this we only count (bounded memory).
const MAX_EVENTS_PER_PAIR: usize = 20_000;
/// Distinct internal sources remembered per destination (prevalence).
const MAX_SRCS_PER_DST: usize = 256;
/// Names remembered per candidate destination.
const MAX_NAMES_PER_DST: usize = 4;

/// Distinct flows remembered per pair when a series is built from requests.
const MAX_FLOWS_PER_PAIR: usize = 4096;

/// One point of a series: a flow start, or an HTTP request inside a flow.
/// `first_frame` is the evidence frame (flow's first frame, or the request's).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ev {
    pub(crate) ts: Ts,
    pub(crate) flow_id: FlowId,
    pub(crate) first_frame: FrameNo,
    pub(crate) bytes: u64,
    pub(crate) dst_port: u16,
}

#[derive(Debug, Default)]
struct Pair {
    events: Vec<Ev>,
    dropped: u64,
    flow_set: HashSet<FlowId>,
}

/// Streaming series per (src, dst): flow starts (flows pass) or HTTP
/// requests (http pass, `tracking_flows`).
#[derive(Debug, Default)]
pub(crate) struct Collector {
    pairs: HashMap<(u32, u32), Pair>,
    /// dst → distinct internal srcs (capped).
    dst_srcs: HashMap<u32, Vec<u32>>,
    track_flows: bool,
}

impl Collector {
    pub(crate) fn observe(&mut self, hosts: &Hosts, src: u32, dst: u32, f: &FlowRow) {
        if hosts.class(dst) != AddrClass::External || hosts.class(src) == AddrClass::Special {
            return;
        }
        if hosts.class(src) == AddrClass::Internal {
            let srcs = self.dst_srcs.entry(dst).or_default();
            if srcs.len() < MAX_SRCS_PER_DST && !srcs.contains(&src) {
                srcs.push(src);
            }
        }
        let pair = self.pairs.entry((src, dst)).or_default();
        if pair.events.len() < MAX_EVENTS_PER_PAIR {
            pair.events.push(Ev {
                ts: f.ts_start,
                flow_id: f.flow_id,
                first_frame: f.first_frame,
                bytes: f.bytes_up.saturating_add(f.bytes_down),
                dst_port: f.dst_port,
            });
        } else {
            pair.dropped += 1;
        }
    }

    /// A collector for request series that also counts distinct flows per
    /// pair (requests per connection).
    pub(crate) fn tracking_flows() -> Self {
        Self {
            track_flows: true,
            ..Default::default()
        }
    }

    /// Add one request-level event (caller has already checked classes).
    pub(crate) fn push(&mut self, src: u32, dst: u32, ev: Ev) {
        let track = self.track_flows;
        let pair = self.pairs.entry((src, dst)).or_default();
        if track && pair.flow_set.len() < MAX_FLOWS_PER_PAIR {
            pair.flow_set.insert(ev.flow_id);
        }
        if pair.events.len() < MAX_EVENTS_PER_PAIR {
            pair.events.push(ev);
        } else {
            pair.dropped += 1;
        }
    }

    pub(crate) fn prevalence(&self, dst: u32) -> usize {
        self.dst_srcs.get(&dst).map_or(0, Vec::len)
    }
}

/// Measured series statistics for one pair under one rule.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub(crate) rule_idx: usize,
    pub(crate) src: u32,
    pub(crate) dst: u32,
    contacts: usize,
    flows: u64,
    /// Distinct flows behind the events (request series only; else 0).
    pub(crate) distinct_flows: u64,
    interval_s: f64,
    jitter: f64,
    duration_s: f64,
    mean_bytes: f64,
    payload_cv: f64,
    dst_port: u16,
    /// (signal, points) before down-weighting.
    points: Vec<(&'static str, f64)>,
    ts_first: Ts,
    ts_last: Ts,
    evidence: Evidence,
}

impl Candidate {
    fn raw_points(&self) -> f64 {
        self.points.iter().map(|(_, p)| p).sum()
    }
}

/// Compute candidates for one rule: pairs whose undamped points reach
/// `min_score` (damping only lowers points, so this is a safe pre-filter).
pub(crate) fn analyze(
    col: &Collector,
    rule: &Rule,
    rule_idx: usize,
    entity_ok: &dyn Fn(u32) -> bool,
) -> Vec<Candidate> {
    let ignore: Vec<u16> = rule
        .nums("ignore_dst_ports")
        .iter()
        .filter(|p| (0.0..=65535.0).contains(*p))
        .map(|p| *p as u16)
        .collect();
    let mut out = Vec::new();
    let mut evs: Vec<Ev> = Vec::new();
    for (&(src, dst), pair) in &col.pairs {
        if !entity_ok(src) {
            continue;
        }
        evs.clear();
        evs.extend(pair.events.iter().filter(|e| !ignore.contains(&e.dst_port)));
        if (evs.len() as f64) < rule.num("min_count") {
            continue;
        }
        evs.sort_by_key(|e| (e.ts, e.flow_id));
        if let Some(mut c) = measure(&evs, pair.dropped, rule, rule_idx, src, dst) {
            c.distinct_flows = pair.flow_set.len() as u64;
            out.push(c);
        }
    }
    out
}

fn measure(
    evs: &[Ev],
    dropped: u64,
    rule: &Rule,
    rule_idx: usize,
    src: u32,
    dst: u32,
) -> Option<Candidate> {
    let merge_us = (rule.num("merge_gap_s") * 1e6) as i64;
    // Contact start times.
    let mut contacts: Vec<Ts> = Vec::new();
    let mut last_ts = i64::MIN;
    for e in evs {
        if contacts.is_empty() || e.ts.saturating_sub(last_ts) > merge_us {
            contacts.push(e.ts);
        }
        last_ts = e.ts;
    }
    let n = contacts.len();
    if (n as f64) < rule.num("min_count") {
        return None;
    }
    let mut intervals: Vec<f64> = contacts
        .windows(2)
        .map(|w| (w[1].saturating_sub(w[0])) as f64 / 1e6)
        .collect();
    let med = median(&mut intervals);
    if med.is_nan()
        || med <= 0.0
        || med < rule.num("min_interval_s")
        || med > rule.num("max_interval_s")
    {
        return None;
    }
    let mut dev: Vec<f64> = intervals.iter().map(|d| (d - med).abs()).collect();
    let jitter = median(&mut dev) / med;
    if jitter > rule.num("max_jitter") {
        return None;
    }
    let duration_s = (contacts[n - 1].saturating_sub(contacts[0])) as f64 / 1e6;
    if duration_s < rule.num("min_duration_s") {
        return None;
    }
    let m = evs.len() as f64;
    let mean_bytes = evs.iter().map(|e| e.bytes as f64).sum::<f64>() / m;
    let var = evs
        .iter()
        .map(|e| (e.bytes as f64 - mean_bytes).powi(2))
        .sum::<f64>()
        / m;
    let payload_cv = if mean_bytes > 0.0 {
        var.sqrt() / mean_bytes
    } else {
        0.0
    };

    let s_reg = 1.0 - ramp(jitter, rule.num("jitter_full"), rule.num("max_jitter"));
    let min_count = rule.num("min_count");
    let count_full = rule.num("count_full").max(min_count + 1.0);
    let s_count = ramp((n as f64).ln(), min_count.ln(), count_full.ln());
    let s_dur = ramp(duration_s, 0.0, rule.num("duration_full_s"));
    let s_pay = 1.0 - ramp(payload_cv, 0.0, rule.num("max_payload_cv"));
    let points = vec![
        ("regularity", rule.weight("regularity") * s_reg),
        ("count", rule.weight("count") * s_count * s_reg),
        ("duration", rule.weight("duration") * s_dur * s_reg),
        (
            "payload_uniformity",
            rule.weight("payload_uniformity") * s_pay * s_reg,
        ),
    ];
    let cand_points: f64 = points.iter().map(|(_, p)| p).sum();
    if cand_points < rule.def.min_score || cand_points <= 0.0 {
        return None;
    }

    // Most common destination port, for the explanation.
    let mut ports: BTreeMap<u16, usize> = BTreeMap::new();
    for e in evs {
        *ports.entry(e.dst_port).or_default() += 1;
    }
    let dst_port = ports
        .iter()
        .max_by_key(|(p, c)| (**c, std::cmp::Reverse(**p)))
        .map_or(0, |(p, _)| *p);

    let mut ev = crate::util::EvAcc::default();
    for e in evs {
        ev.push(e.flow_id, e.first_frame);
    }
    let mut evidence = ev.to_evidence();
    evidence.total = evs.len() as u64 + dropped;
    evidence.truncated = evidence.total as usize > evidence.frame_nos.len();

    Some(Candidate {
        rule_idx,
        src,
        dst,
        contacts: n,
        flows: evs.len() as u64 + dropped,
        distinct_flows: 0,
        interval_s: med,
        jitter,
        duration_s,
        mean_bytes,
        payload_cv,
        dst_port,
        points,
        ts_first: contacts[0],
        ts_last: evs.last().map_or(contacts[n - 1], |e| e.ts),
        evidence,
    })
}

/// Names each candidate destination was seen as (DNS answers, SNI, Host).
///
/// Only names learned from DNS answers (`resolved`) can earn an allowlist or
/// known-good down-weight: SNI and the HTTP Host header are chosen by the
/// client, i.e. by the implant, so `SNI: update.microsoft.com` on a beacon to
/// an unrelated IP must not hide it. All names still label the destination.
#[derive(Debug, Default)]
pub(crate) struct DstNames {
    names: HashMap<u32, Vec<String>>,
    resolved: HashMap<u32, Vec<String>>,
    /// Candidate flow → dst, for SNI / Host lookups.
    flows: HashMap<FlowId, u32>,
}

impl DstNames {
    pub(crate) fn for_candidates(cands: &[Candidate]) -> Self {
        let mut s = Self::default();
        for c in cands {
            s.names.entry(c.dst).or_default();
            for &f in &c.evidence.flow_ids {
                s.flows.insert(f, c.dst);
            }
        }
        s
    }

    pub(crate) fn wants_dst(&self, dst: u32) -> bool {
        self.names.contains_key(&dst)
    }

    pub(crate) fn dst_of_flow(&self, flow_id: FlowId) -> Option<u32> {
        self.flows.get(&flow_id).copied()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub(crate) fn add(&mut self, dst: u32, name: &str) {
        let name = crate::util::normalize_name(name);
        if name.is_empty() {
            return;
        }
        if let Some(v) = self.names.get_mut(&dst) {
            if v.len() < MAX_NAMES_PER_DST && !v.contains(&name) {
                v.push(name);
            }
        }
    }

    /// A name from a DNS answer that resolved to `dst`.
    pub(crate) fn add_resolved(&mut self, dst: u32, name: &str) {
        self.add(dst, name);
        let name = crate::util::normalize_name(name);
        if name.is_empty() || !self.names.contains_key(&dst) {
            return;
        }
        let v = self.resolved.entry(dst).or_default();
        if v.len() < MAX_NAMES_PER_DST && !v.contains(&name) {
            v.push(name);
        }
    }

    fn get(&self, dst: u32) -> &[String] {
        self.names.get(&dst).map_or(&[], Vec::as_slice)
    }

    fn resolved(&self, dst: u32) -> &[String] {
        self.resolved.get(&dst).map_or(&[], Vec::as_slice)
    }
}

/// Context for turning candidates into hits.
pub(crate) struct FinalizeCtx<'a> {
    pub(crate) hosts: &'a Hosts,
    pub(crate) col: &'a Collector,
    pub(crate) names: &'a DstNames,
    pub(crate) allow: &'a Allowlist,
    pub(crate) internal_hosts: usize,
}

/// Per-caller additions to `finalize`: extra names for the destination
/// (e.g. HTTP Host values), extra damping `(factor, note)`, extra template
/// values, and the reason's signal name.
#[derive(Debug, Default)]
pub(crate) struct Extra {
    pub(crate) names: Vec<String>,
    pub(crate) factors: Vec<(f64, String)>,
    pub(crate) values: Vec<(&'static str, String)>,
    pub(crate) signal: Option<&'static str>,
}

pub(crate) fn finalize(
    c: &Candidate,
    rule: &Rule,
    cx: &FinalizeCtx<'_>,
    extra: &Extra,
) -> Option<Hit> {
    let dst_ip = cx.hosts.name(c.dst);
    let mut names: Vec<String> = cx.names.get(c.dst).to_vec();
    for n in &extra.names {
        if !names.contains(n) {
            names.push(n.clone());
        }
    }
    let mut factor = 1.0;
    let mut notes: Vec<String> = Vec::new();

    // Down-weights trust the IP and resolver answers only (see `DstNames`).
    let trusted = cx.names.resolved(c.dst);
    let allow_hit = cx.allow.ip(dst_ip).map(str::to_string).or_else(|| {
        trusted
            .iter()
            .find_map(|n| cx.allow.domain(n).map(str::to_string))
    });
    if let Some(reason) = allow_hit {
        let f = rule.num("allowlist_factor");
        factor *= f;
        notes.push(format!(
            "destination allowlisted: {}; score ×{}",
            display(&reason),
            fmt_num(f, 2)
        ));
    } else if let Some(sfx) = trusted.iter().find_map(|n| {
        rule.strs("known_good_suffixes")
            .iter()
            .find(|s| has_suffix(n, s))
    }) {
        let f = rule.num("known_good_factor");
        factor *= f;
        notes.push(format!(
            "destination is under known-good {}; score ×{}",
            display(sfx),
            fmt_num(f, 2)
        ));
    }
    let prev = cx.col.prevalence(c.dst);
    let need = rule
        .num("prevalence_min_hosts")
        .max(rule.num("prevalence_ratio") * cx.internal_hosts as f64);
    if prev >= 2 && prev as f64 >= need {
        let f = rule.num("prevalence_factor");
        factor *= f;
        notes.push(format!(
            "{prev} of {} internal hosts contact this destination; score ×{}",
            cx.internal_hosts,
            fmt_num(f, 2)
        ));
    }

    for (f, note) in &extra.factors {
        factor *= f;
        notes.push(note.clone());
    }

    let raw = c.raw_points();
    let points = raw * factor;
    if points < rule.def.min_score || points <= 0.0 {
        return None;
    }
    let src_ip = cx.hosts.name(c.src);
    let dst_label = match names.first() {
        Some(n) => format!("{} ({})", display(dst_ip), display(n)),
        None => display(dst_ip),
    };
    let breakdown = c
        .points
        .iter()
        .filter(|(_, p)| *p >= 0.05)
        .map(|(s, p)| format!("{s} {}", fmt_num(p * factor, 1)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut v = BTreeMap::new();
    v.insert("src".into(), display(src_ip));
    v.insert("dst".into(), display(dst_ip));
    v.insert("dst_label".into(), dst_label.clone());
    v.insert(
        "dst_name".into(),
        names
            .first()
            .map_or_else(|| display(dst_ip), |n| display(n)),
    );
    v.insert("dst_port".into(), c.dst_port.to_string());
    v.insert("count".into(), c.contacts.to_string());
    v.insert("flows".into(), c.flows.to_string());
    v.insert("interval_s".into(), fmt_num(c.interval_s, 1));
    v.insert("jitter_pct".into(), fmt_num(c.jitter * 100.0, 1));
    v.insert("duration_min".into(), fmt_num(c.duration_s / 60.0, 0));
    v.insert("mean_bytes".into(), fmt_num(c.mean_bytes, 0));
    v.insert("payload_cv_pct".into(), fmt_num(c.payload_cv * 100.0, 0));
    v.insert("points".into(), fmt_num(points, 1));
    v.insert("breakdown".into(), breakdown);
    v.insert("requests".into(), c.flows.to_string());
    v.insert("conns".into(), c.distinct_flows.to_string());
    for (k, val) in &extra.values {
        v.insert((*k).into(), val.clone());
    }
    let mut explanation = render_template(&rule.def.explanation, &v);
    if !notes.is_empty() {
        explanation.push_str(&format!(" ({})", notes.join("; ")));
    }
    let title = render_template(&rule.def.title, &v);
    Some(Hit {
        host: c.src,
        rule_idx: c.rule_idx,
        detector_family: "beaconing",
        title,
        tiebreak: dst_ip.to_string(),
        ts_first: c.ts_first,
        ts_last: c.ts_last,
        reason: Reason {
            rule_id: rule.def.id.clone(),
            signal: extra.signal.unwrap_or("interval_regularity").into(),
            value: (c.jitter * 10_000.0).round() / 10_000.0,
            unit: Some("ratio".into()),
            weight: round1(points),
            explanation,
            attack_technique: rule.def.attack_technique.clone(),
            evidence: c.evidence.clone(),
        },
    })
}
