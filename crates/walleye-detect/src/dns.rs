//! DNS anomaly detectors. One streaming pass over the `dns` table builds
//! per-(host, registered domain) statistics and per-host NXDOMAIN windows;
//! each rule then scores those statistics.
//!
//! "Registered domain" comes from a small built-in public-suffix heuristic
//! (`util::split_registered`); the "prefix" is everything to its left, i.e.
//! the leftmost labels a tunnel or a CDN controls.
//!
//! | detector             | per            | signals |
//! |----------------------|----------------|---------|
//! | `dns_entropy`        | host × domain  | mean Shannon entropy of unique prefixes |
//! | `dns_length`         | host × domain  | mean query length, longest prefix label |
//! | `dns_subdomain_rate` | host × domain  | unique prefixes per minute, unique/total |
//! | `dns_tunnel`         | host × domain  | TXT/NULL/… query count, query+answer bytes |
//! | `dns_nxdomain_burst` | host           | peak distinct NXDOMAIN registered domains in a sliding window, number of bursts, entropy of the failed names |
//!
//! Hostile input: names are clipped to 253 bytes, case-folded, empty labels
//! dropped; per-domain unique sets, the number of tracked domains and the
//! NXDOMAIN window are all capped.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use walleye_core::rules::render_template;
use walleye_core::{Allowlist, DnsRow, Reason, Ts};

use crate::combine::{Entity, Hit};
use crate::rules::{Rule, RuleSet};
use crate::util::{
    EvAcc, Hosts, display, fmt_num, has_suffix, hash64, normalize_name, ramp, round1,
    shannon_entropy, split_registered,
};

/// Unique prefixes remembered per (host, domain); beyond this the count is
/// reported as "at least".
const UNIQ_CAP: usize = 10_000;
/// (host, domain) entries tracked overall; more are counted and skipped.
const MAX_PARENTS: usize = 250_000;
/// NXDOMAIN window entries per host.
const NX_WINDOW_CAP: usize = 100_000;
/// Unique failed names remembered per host for the entropy signal.
const NX_UNIQ_CAP: usize = 10_000;
/// Per-row cap on answer bytes counted toward tunnel volume.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

const PARENT_DETECTORS: &[&str] = &[
    "dns_entropy",
    "dns_length",
    "dns_subdomain_rate",
    "dns_tunnel",
];

#[derive(Debug, Default)]
struct ParentStats {
    host: u32,
    parent: String,
    example: String,
    queries: u64,
    sum_qlen: u64,
    max_label: usize,
    uniq: HashSet<u64>,
    n_uniq: u64,
    uniq_saturated: bool,
    sum_entropy: f64,
    sum_prefix_len: u64,
    /// Per tunnel qtype (index into `DnsCollector::tun_qtypes`): queries, bytes.
    tun_queries: Vec<u64>,
    tun_bytes: Vec<u64>,
    first_ts: Ts,
    last_ts: Ts,
    ev: EvAcc,
    tun_ev: EvAcc,
}

#[derive(Debug, Clone, Copy)]
struct NxEv {
    ts: Ts,
    flow_id: u64,
    frame_no: u64,
    parent_h: u64,
    added: bool,
}

#[derive(Debug, Default)]
struct NxHost {
    win: VecDeque<NxEv>,
    counts: HashMap<u64, u32>,
    peak: usize,
    bursts: u32,
    in_burst: bool,
    total: u64,
    uniq: HashSet<u64>,
    sum_entropy: f64,
    n_uniq: u64,
    ev: EvAcc,
    first_ts: Ts,
    last_ts: Ts,
    example: String,
}

#[derive(Debug)]
struct NxRule {
    rule_idx: usize,
    window_us: i64,
    min_burst: usize,
    ignore: Vec<String>,
    hosts: HashMap<u32, NxHost>,
}

/// Streaming state for the dns pass.
#[derive(Debug)]
pub(crate) struct DnsCollector {
    /// Suffixes every enabled DNS rule ignores: skipped at collection time.
    common_ignore: Vec<String>,
    tun_qtypes: Vec<String>,
    index: HashMap<(u32, u64), usize>,
    stats: Vec<ParentStats>,
    dropped_parents: u64,
    nx: Vec<NxRule>,
    pub(crate) query_rows: u64,
}

impl DnsCollector {
    pub(crate) fn new(rules: &RuleSet) -> Self {
        let mut lists: Vec<&[String]> = Vec::new();
        let mut tun_qtypes: Vec<String> = Vec::new();
        let mut nx = Vec::new();
        for r in rules.rules().iter().filter(|r| r.def.enabled) {
            if !r.def.detector.starts_with("dns_") {
                continue;
            }
            lists.push(r.strs("ignore_suffixes"));
            if r.def.detector == "dns_tunnel" {
                for q in r.strs("qtypes") {
                    let q = q.to_ascii_uppercase();
                    if !tun_qtypes.contains(&q) {
                        tun_qtypes.push(q);
                    }
                }
            }
        }
        for (idx, r) in rules.enabled("dns_nxdomain_burst") {
            nx.push(NxRule {
                rule_idx: idx,
                window_us: (r.num("window_s") * 1e6) as i64,
                min_burst: r.num("min_burst") as usize,
                ignore: lower(r.strs("ignore_suffixes")),
                hosts: HashMap::new(),
            });
        }
        let common_ignore = match lists.split_first() {
            None => Vec::new(),
            Some((first, rest)) => lower(first)
                .into_iter()
                .filter(|s| {
                    rest.iter()
                        .all(|l| l.iter().any(|x| x.eq_ignore_ascii_case(s)))
                })
                .collect(),
        };
        Self {
            common_ignore,
            tun_qtypes,
            index: HashMap::new(),
            stats: Vec::new(),
            dropped_parents: 0,
            nx,
            query_rows: 0,
        }
    }

    pub(crate) fn wanted(rules: &RuleSet) -> bool {
        rules
            .rules()
            .iter()
            .any(|r| r.def.enabled && r.def.detector.starts_with("dns_"))
    }

    fn entry(&mut self, host: u32, parent: &str, ts: Ts) -> Option<&mut ParentStats> {
        let key = (host, hash64(parent));
        let idx = match self.index.get(&key) {
            Some(&i) => i,
            None => {
                if self.stats.len() >= MAX_PARENTS {
                    self.dropped_parents += 1;
                    return None;
                }
                let i = self.stats.len();
                self.stats.push(ParentStats {
                    host,
                    parent: parent.to_string(),
                    tun_queries: vec![0; self.tun_qtypes.len()],
                    tun_bytes: vec![0; self.tun_qtypes.len()],
                    first_ts: ts,
                    last_ts: ts,
                    ..Default::default()
                });
                self.index.insert(key, i);
                i
            }
        };
        self.stats.get_mut(idx)
    }

    /// Feed one row. `as_query` is true for queries (or for responses when
    /// the capture has no query rows at all).
    pub(crate) fn observe(&mut self, host: u32, row: &DnsRow, as_query: bool) {
        let name = normalize_name(&row.query);
        if name.is_empty() || self.common_ignore.iter().any(|s| has_suffix(&name, s)) {
            return;
        }
        let (prefix, parent) = split_registered(&name);
        let qtype = row.qtype.to_ascii_uppercase();
        let tun_idx = self.tun_qtypes.iter().position(|q| *q == qtype);

        if as_query {
            self.query_rows += 1;
            let Some(st) = self.entry(host, &parent, row.ts) else {
                return;
            };
            st.queries += 1;
            st.sum_qlen += name.len() as u64;
            st.first_ts = st.first_ts.min(row.ts);
            st.last_ts = st.last_ts.max(row.ts);
            st.ev.push(row.flow_id, row.frame_no);
            if st.example.is_empty() || (st.example.len() < 24 && name.len() > st.example.len()) {
                st.example = name.clone();
            }
            if !prefix.is_empty() {
                let longest = prefix.split('.').map(str::len).max().unwrap_or(0);
                st.max_label = st.max_label.max(longest);
                if !st.uniq_saturated && st.uniq.insert(hash64(prefix.as_str())) {
                    st.n_uniq += 1;
                    st.sum_entropy += shannon_entropy(&prefix);
                    st.sum_prefix_len += prefix.len() as u64;
                    if st.uniq.len() >= UNIQ_CAP {
                        st.uniq_saturated = true;
                        st.uniq = HashSet::new();
                    }
                }
            }
            if let Some(i) = tun_idx {
                st.tun_queries[i] += 1;
                st.tun_bytes[i] += name.len() as u64;
                st.tun_ev.push(row.flow_id, row.frame_no);
            }
        }

        if row.is_response {
            if let Some(i) = tun_idx {
                let bytes: usize = row
                    .answers
                    .iter()
                    .map(String::len)
                    .sum::<usize>()
                    .min(MAX_ANSWER_BYTES);
                if bytes > 0 {
                    if let Some(st) = self.entry(host, &parent, row.ts) {
                        st.tun_bytes[i] += bytes as u64;
                    }
                }
            }
            let nx = row
                .rcode
                .as_deref()
                .is_some_and(|r| r.eq_ignore_ascii_case("NXDOMAIN"));
            if nx {
                let parent_h = hash64(parent.as_str());
                for rule in &mut self.nx {
                    if rule.ignore.iter().any(|s| has_suffix(&name, s)) {
                        continue;
                    }
                    nx_observe(rule, host, row, &name, &parent, parent_h);
                }
            }
        }
    }
}

fn lower(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn nx_observe(rule: &mut NxRule, host: u32, row: &DnsRow, name: &str, parent: &str, parent_h: u64) {
    let h = rule.hosts.entry(host).or_default();
    h.total += 1;
    while let Some(front) = h.win.front() {
        if row.ts.saturating_sub(front.ts) > rule.window_us || h.win.len() >= NX_WINDOW_CAP {
            let ph = front.parent_h;
            h.win.pop_front();
            if let Some(c) = h.counts.get_mut(&ph) {
                *c -= 1;
                if *c == 0 {
                    h.counts.remove(&ph);
                }
            }
        } else {
            break;
        }
    }
    h.win.push_back(NxEv {
        ts: row.ts,
        flow_id: row.flow_id,
        frame_no: row.frame_no,
        parent_h,
        added: false,
    });
    *h.counts.entry(parent_h).or_default() += 1;
    let distinct = h.counts.len();
    h.peak = h.peak.max(distinct);
    if h.uniq.len() < NX_UNIQ_CAP && h.uniq.insert(hash64(name)) {
        // Entropy of the label the registrant chose (DGA output).
        let label = parent.split('.').next().unwrap_or("");
        h.sum_entropy += shannon_entropy(label);
        h.n_uniq += 1;
    }
    if distinct >= rule.min_burst {
        if !h.in_burst {
            h.in_burst = true;
            h.bursts += 1;
            if h.ev.total() == 0 {
                h.first_ts = h.win.front().map_or(row.ts, |e| e.ts);
            }
        }
        for e in h.win.iter_mut().filter(|e| !e.added) {
            e.added = true;
            h.ev.push(e.flow_id, e.frame_no);
        }
        h.last_ts = row.ts;
        if h.example.is_empty() {
            h.example = name.to_string();
        }
    } else if distinct * 2 < rule.min_burst {
        h.in_burst = false;
    }
}

/// Per-domain values shared by all host × domain rules.
struct ParentView<'a> {
    st: &'a ParentStats,
    mean_entropy: f64,
    mean_prefix_len: f64,
    mean_len: f64,
    span_min: f64,
}

fn allow_note(allow: &Allowlist, rule: &Rule, names: &[&str]) -> (f64, Option<String>) {
    for n in names {
        if let Some(reason) = allow.domain(n) {
            let f = rule.num("allowlist_factor");
            return (
                f,
                Some(format!(
                    "domain allowlisted: {}; score ×{}",
                    display(reason),
                    fmt_num(f, 2)
                )),
            );
        }
    }
    (1.0, None)
}

/// Score every (host, domain) under one rule.
#[allow(clippy::too_many_arguments)]
pub(crate) fn analyze_parents(
    col: &DnsCollector,
    hosts: &Hosts,
    allow: &Allowlist,
    rule: &Rule,
    rule_idx: usize,
    entity_ok: &dyn Fn(u32) -> bool,
    internal_hosts: usize,
    out: &mut Vec<Hit>,
) {
    if !PARENT_DETECTORS.contains(&rule.def.detector.as_str()) {
        return;
    }
    let ignore = lower(rule.strs("ignore_suffixes"));
    let tun_mask: Vec<bool> = if rule.def.detector == "dns_tunnel" {
        let mine: Vec<String> = rule
            .strs("qtypes")
            .iter()
            .map(|q| q.to_ascii_uppercase())
            .collect();
        col.tun_qtypes.iter().map(|q| mine.contains(q)).collect()
    } else {
        Vec::new()
    };
    // Domain prevalence: how many eligible hosts query each domain.
    let mut prevalence: HashMap<u64, usize> = HashMap::new();
    for st in col
        .stats
        .iter()
        .filter(|s| s.queries > 0 && entity_ok(s.host))
    {
        *prevalence.entry(hash64(st.parent.as_str())).or_default() += 1;
    }
    let need = rule
        .num("prevalence_min_hosts")
        .max(rule.num("prevalence_ratio") * internal_hosts as f64);
    for st in &col.stats {
        if st.queries == 0 || !entity_ok(st.host) {
            continue;
        }
        if ignore.iter().any(|s| has_suffix(&st.parent, s)) {
            continue;
        }
        let n_uniq = st.n_uniq.max(1) as f64;
        let view = ParentView {
            st,
            mean_entropy: if st.n_uniq == 0 {
                0.0
            } else {
                st.sum_entropy / n_uniq
            },
            mean_prefix_len: if st.n_uniq == 0 {
                0.0
            } else {
                st.sum_prefix_len as f64 / n_uniq
            },
            mean_len: st.sum_qlen as f64 / st.queries as f64,
            span_min: (st.last_ts.saturating_sub(st.first_ts)) as f64 / 60e6,
        };
        let scored = match rule.def.detector.as_str() {
            "dns_entropy" => score_entropy(&view, rule),
            "dns_length" => score_length(&view, rule),
            "dns_subdomain_rate" => score_rate(&view, rule),
            "dns_tunnel" => score_tunnel(&view, rule, &tun_mask),
            _ => None,
        };
        let Some(sc) = scored else { continue };
        let (mut factor, note) = allow_note(allow, rule, &[&st.parent, &st.example]);
        let mut notes: Vec<String> = note.into_iter().collect();
        let prev = prevalence
            .get(&hash64(st.parent.as_str()))
            .copied()
            .unwrap_or(0);
        if prev >= 2 && prev as f64 >= need {
            let f = rule.num("prevalence_factor");
            factor *= f;
            notes.push(format!(
                "{prev} of {internal_hosts} internal hosts query this domain; score ×{}",
                fmt_num(f, 2)
            ));
        }
        let points = sc.points.iter().map(|(_, p)| p).sum::<f64>() * factor;
        if points < rule.def.min_score || points <= 0.0 {
            continue;
        }
        let mut v = BTreeMap::new();
        v.insert("src".into(), display(hosts.name(st.host)));
        v.insert("domain".into(), display(&st.parent));
        v.insert("example".into(), display(&st.example));
        v.insert("queries".into(), st.queries.to_string());
        v.insert(
            "unique".into(),
            if st.uniq_saturated {
                format!("{}+", st.n_uniq)
            } else {
                st.n_uniq.to_string()
            },
        );
        v.insert("entropy".into(), fmt_num(view.mean_entropy, 2));
        v.insert("mean_len".into(), fmt_num(view.mean_len, 0));
        v.insert("max_label".into(), st.max_label.to_string());
        v.insert("span_min".into(), fmt_num(view.span_min, 0));
        v.insert("points".into(), fmt_num(points, 1));
        v.insert("breakdown".into(), breakdown(&sc.points, factor));
        for (k, val) in sc.values {
            v.insert(k.into(), val);
        }
        let mut explanation = render_template(&rule.def.explanation, &v);
        if !notes.is_empty() {
            explanation.push_str(&format!(" ({})", notes.join("; ")));
        }
        let evidence = if rule.def.detector == "dns_tunnel" {
            st.tun_ev.to_evidence()
        } else {
            st.ev.to_evidence()
        };
        if evidence.is_empty() {
            continue;
        }
        out.push(Hit {
            entity: Entity::Host(st.host),
            rule_idx,
            detector_family: "dns",
            title: render_template(&rule.def.title, &v),
            tiebreak: st.parent.clone(),
            ts_first: st.first_ts,
            ts_last: st.last_ts,
            reason: Reason {
                rule_id: rule.def.id.clone(),
                signal: sc.signal.into(),
                value: (sc.value * 100.0).round() / 100.0,
                unit: Some(sc.unit.into()),
                weight: round1(points),
                explanation,
                attack_technique: rule.def.attack_technique.clone(),
                evidence,
            },
        });
    }
}

struct Scored {
    signal: &'static str,
    value: f64,
    unit: &'static str,
    points: Vec<(&'static str, f64)>,
    values: Vec<(&'static str, String)>,
}

fn breakdown(points: &[(&str, f64)], factor: f64) -> String {
    points
        .iter()
        .filter(|(_, p)| *p >= 0.05)
        .map(|(s, p)| format!("{s} {}", fmt_num(p * factor, 1)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn score_entropy(v: &ParentView<'_>, rule: &Rule) -> Option<Scored> {
    if (v.st.n_uniq as f64) < rule.num("min_unique")
        || v.mean_prefix_len < rule.num("min_prefix_len")
    {
        return None;
    }
    let s = ramp(
        v.mean_entropy,
        rule.num("entropy_low"),
        rule.num("entropy_high"),
    );
    Some(Scored {
        signal: "subdomain_entropy",
        value: v.mean_entropy,
        unit: "bits",
        points: vec![("entropy", rule.weight("entropy") * s)],
        values: vec![("prefix_len", fmt_num(v.mean_prefix_len, 0))],
    })
}

fn score_length(v: &ParentView<'_>, rule: &Rule) -> Option<Scored> {
    if (v.st.queries as f64) < rule.num("min_queries") {
        return None;
    }
    let s_len = ramp(v.mean_len, rule.num("length_low"), rule.num("length_high"));
    let s_lab = ramp(
        v.st.max_label as f64,
        rule.num("label_low"),
        rule.num("label_high"),
    );
    Some(Scored {
        signal: "query_length",
        value: v.mean_len,
        unit: "chars",
        points: vec![
            ("query_length", rule.weight("query_length") * s_len),
            ("label_length", rule.weight("label_length") * s_lab),
        ],
        values: vec![],
    })
}

fn score_rate(v: &ParentView<'_>, rule: &Rule) -> Option<Scored> {
    let n_uniq = v.st.n_uniq as f64;
    if n_uniq < rule.num("min_unique") {
        return None;
    }
    let span_min = v.span_min.max(rule.num("min_span_s") / 60.0);
    let rate = n_uniq / span_min;
    let ratio = (n_uniq / v.st.queries as f64).min(1.0);
    let s_rate = ramp(rate, rule.num("rate_low"), rule.num("rate_high"));
    let s_ratio = ramp(ratio, rule.num("ratio_low"), rule.num("ratio_high"));
    Some(Scored {
        signal: "unique_subdomain_rate",
        value: rate,
        unit: "per min",
        // A high unique ratio only matters when the rate is high too.
        points: vec![
            ("unique_rate", rule.weight("unique_rate") * s_rate),
            (
                "unique_ratio",
                rule.weight("unique_ratio") * s_ratio * s_rate,
            ),
        ],
        values: vec![
            ("rate_per_min", fmt_num(rate, 1)),
            ("unique_pct", fmt_num(ratio * 100.0, 0)),
        ],
    })
}

fn score_tunnel(v: &ParentView<'_>, rule: &Rule, mask: &[bool]) -> Option<Scored> {
    let (mut q, mut b) = (0u64, 0u64);
    for (i, on) in mask.iter().enumerate() {
        if *on {
            q += v.st.tun_queries.get(i).copied().unwrap_or(0);
            b += v.st.tun_bytes.get(i).copied().unwrap_or(0);
        }
    }
    if (q as f64) < rule.num("min_queries") {
        return None;
    }
    let s_vol = ramp(q as f64, 0.0, rule.num("volume_full"));
    let s_bytes = ramp(b as f64, rule.num("bytes_low"), rule.num("bytes_high"));
    let qtypes = rule.strs("qtypes").join("/");
    Some(Scored {
        signal: "txt_null_volume",
        value: q as f64,
        unit: "count",
        points: vec![
            ("record_volume", rule.weight("record_volume") * s_vol),
            ("byte_volume", rule.weight("byte_volume") * s_bytes),
        ],
        values: vec![
            ("records", q.to_string()),
            ("bytes", b.to_string()),
            ("qtypes", display(&qtypes)),
        ],
    })
}

/// Score NXDOMAIN bursts per host for one rule.
pub(crate) fn analyze_nx(
    col: &DnsCollector,
    hosts: &Hosts,
    allow: &Allowlist,
    rule: &Rule,
    rule_idx: usize,
    entity_ok: &dyn Fn(u32) -> bool,
    out: &mut Vec<Hit>,
) {
    let Some(state) = col.nx.iter().find(|n| n.rule_idx == rule_idx) else {
        return;
    };
    let mut keys: Vec<u32> = state.hosts.keys().copied().collect();
    keys.sort_unstable();
    for host in keys {
        let Some(h) = state.hosts.get(&host) else {
            continue;
        };
        if h.bursts == 0 || h.ev.total() == 0 || !entity_ok(host) {
            continue;
        }
        let mean_entropy = if h.n_uniq == 0 {
            0.0
        } else {
            h.sum_entropy / h.n_uniq as f64
        };
        let s_burst = ramp(h.peak as f64, 0.0, rule.num("burst_full"));
        let s_rep = ramp(f64::from(h.bursts), 0.0, rule.num("repeat_full"));
        let s_ent = ramp(
            mean_entropy,
            rule.num("entropy_low"),
            rule.num("entropy_high"),
        );
        let pts = [
            ("burst", rule.weight("burst") * s_burst),
            ("repeat", rule.weight("repeat") * s_rep * s_burst),
            ("dga_entropy", rule.weight("dga_entropy") * s_ent * s_burst),
        ];
        let (factor, note) = allow_note(allow, rule, &[&h.example]);
        let points = pts.iter().map(|(_, p)| p).sum::<f64>() * factor;
        if points < rule.def.min_score || points <= 0.0 {
            continue;
        }
        let mut v = BTreeMap::new();
        v.insert("src".into(), display(hosts.name(host)));
        v.insert("peak".into(), h.peak.to_string());
        v.insert("window_s".into(), fmt_num(rule.num("window_s"), 0));
        v.insert("bursts".into(), h.bursts.to_string());
        v.insert("nx_total".into(), h.total.to_string());
        v.insert("unique".into(), h.n_uniq.to_string());
        v.insert("entropy".into(), fmt_num(mean_entropy, 2));
        v.insert("example".into(), display(&h.example));
        v.insert("points".into(), fmt_num(points, 1));
        v.insert("breakdown".into(), breakdown(&pts, factor));
        let mut explanation = render_template(&rule.def.explanation, &v);
        if let Some(n) = note {
            explanation.push_str(&format!(" ({n})"));
        }
        out.push(Hit {
            entity: Entity::Host(host),
            rule_idx,
            detector_family: "dns",
            title: render_template(&rule.def.title, &v),
            tiebreak: String::new(),
            ts_first: h.first_ts,
            ts_last: h.last_ts,
            reason: Reason {
                rule_id: rule.def.id.clone(),
                signal: "nxdomain_burst".into(),
                value: h.peak as f64,
                unit: Some("count".into()),
                weight: round1(points),
                explanation,
                attack_technique: rule.def.attack_technique.clone(),
                evidence: h.ev.to_evidence(),
            },
        });
    }
}

impl DnsCollector {
    pub(crate) fn dropped_parents(&self) -> u64 {
        self.dropped_parents
    }
}
