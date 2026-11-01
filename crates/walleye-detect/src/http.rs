//! HTTP-level detectors, fed by the `http` table (one row per request).
//!
//! | detector          | per                 | signals |
//! |-------------------|---------------------|---------|
//! | `http_beaconing`  | src × dst           | periodicity of *requests* on persistent connections (same series maths as `beaconing`) |
//! | `http_tls_port`   | src × dst           | cleartext HTTP request lines on a TLS port (443, 8443, 993, ...), IP-literal Host |
//! | `http_post_exfil` | src × dst × URI     | repeated POSTs to one URI with a C2 tell: IP-literal Host or bulk upload; POST rate |
//!
//! Why each is not a duplicate of something else:
//! - `http_beaconing` only scores pairs whose requests ride on few
//!   connections (`min_requests_per_flow`, default 2) and is dropped for a
//!   pair that `beaconing` already reported, so one behaviour is never
//!   counted twice. It catches RATs that keep one TCP connection open and
//!   POST every N seconds (NetSupport), which flow starts cannot see.
//! - In `http_post_exfil`, repetition and rate are *supporting* signals that
//!   only count alongside a tell (IP-literal Host or upload volume): every web
//!   app POSTs often to its own named API; that alone means nothing.
//!
//! A Host that is a DNS name damps `http_beaconing` and `http_post_exfil`
//! (`named_host_factor`): a C2 that talks to a bare IP with no DNS name is
//! the stronger tell, and named, long-lived API pollers are common and benign.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use walleye_core::rules::render_template;
use walleye_core::{Allowlist, FlowId, HttpRow, Reason, Ts};

use crate::beacon::{self, Ev};
use crate::combine::{Entity, Hit};
use crate::rules::{Rule, RuleSet};
use crate::util::{
    AddrClass, EvAcc, Hosts, clip, display, fmt_num, hash64, normalize_name, ramp, round1,
};

/// (src, dst, URI) entries tracked; more are counted and skipped.
const MAX_URI_ENTRIES: usize = 200_000;
/// Longest URI / Host we keep for display and hashing.
const MAX_URI: usize = 2048;

/// Flow context needed to attribute an HTTP row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FlowMeta {
    pub(crate) src: u32,
    pub(crate) dst: u32,
    pub(crate) dst_port: u16,
}

#[derive(Debug, Default)]
struct PairInfo {
    requests: u64,
    ip_literal: u64,
    named: u64,
    host_names: Vec<String>,
    tls_port_reqs: u64,
    tls_port: u16,
    tls_ev: EvAcc,
    first_ts: Ts,
    last_ts: Ts,
}

#[derive(Debug)]
struct UriStats {
    src: u32,
    dst: u32,
    uri: String,
    host: String,
    ip_literal: bool,
    posts: u64,
    req_bytes: u64,
    first_ts: Ts,
    last_ts: Ts,
    ev: EvAcc,
}

/// Streaming state for the http pass.
#[derive(Debug)]
pub(crate) struct HttpCollector {
    pub(crate) series: beacon::Collector,
    pairs: HashMap<(u32, u32), PairInfo>,
    uri_index: HashMap<(u32, u32, u64), usize>,
    uris: Vec<UriStats>,
    tls_ports: Vec<u16>,
}

/// True if a Host header names no DNS name: empty, an IPv4/IPv6 literal, with
/// or without a port.
pub(crate) fn host_is_ip_literal(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() {
        return true;
    }
    if let Some(rest) = h.strip_prefix('[') {
        return rest
            .split(']')
            .next()
            .is_some_and(|a| a.parse::<IpAddr>().is_ok());
    }
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    match h.rsplit_once(':') {
        Some((a, p)) if p.bytes().all(|b| b.is_ascii_digit()) => a.parse::<IpAddr>().is_ok(),
        _ => false,
    }
}

/// Host header without a port, case-folded.
fn host_name(host: &str) -> String {
    let h = host.trim();
    let h = match h.rsplit_once(':') {
        Some((a, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !a.contains(':') => a,
        _ => h,
    };
    normalize_name(h)
}

impl HttpCollector {
    pub(crate) fn new(rules: &RuleSet) -> Self {
        let mut tls_ports: Vec<u16> = Vec::new();
        for (_, r) in rules.enabled("http_tls_port") {
            for p in r.nums("tls_ports") {
                if (0.0..=65535.0).contains(p) && !tls_ports.contains(&(*p as u16)) {
                    tls_ports.push(*p as u16);
                }
            }
        }
        Self {
            series: beacon::Collector::tracking_flows(),
            pairs: HashMap::new(),
            uri_index: HashMap::new(),
            uris: Vec::new(),
            tls_ports,
        }
    }

    pub(crate) fn wanted(rules: &RuleSet) -> bool {
        rules
            .rules()
            .iter()
            .any(|r| r.def.enabled && r.def.detector.starts_with("http_"))
    }

    pub(crate) fn observe(&mut self, hosts: &Hosts, m: FlowMeta, row: &HttpRow) {
        if hosts.class(m.dst) != AddrClass::External || hosts.class(m.src) == AddrClass::Special {
            return;
        }
        let Some(method) = row.method.as_deref() else {
            return; // response without a parsed request line
        };
        let method = clip(method, 16).to_ascii_uppercase();
        if method == "CONNECT" {
            return; // proxy tunnel set-up, not an application request
        }
        let raw_host = clip(row.host.as_deref().unwrap_or(""), MAX_URI);
        let ip_literal = host_is_ip_literal(raw_host);
        let bytes = row.req_bytes.saturating_add(row.resp_bytes);

        self.series.push(
            m.src,
            m.dst,
            Ev {
                ts: row.ts,
                flow_id: row.flow_id,
                first_frame: row.frame_no,
                bytes,
                dst_port: m.dst_port,
            },
        );

        let p = self.pairs.entry((m.src, m.dst)).or_default();
        if p.requests == 0 {
            p.first_ts = row.ts;
        }
        p.requests += 1;
        p.first_ts = p.first_ts.min(row.ts);
        p.last_ts = p.last_ts.max(row.ts);
        if ip_literal {
            p.ip_literal += 1;
        } else {
            p.named += 1;
            let n = host_name(raw_host);
            if p.host_names.len() < 4 && !n.is_empty() && !p.host_names.contains(&n) {
                p.host_names.push(n);
            }
        }
        if self.tls_ports.contains(&m.dst_port) {
            p.tls_port_reqs += 1;
            p.tls_port = m.dst_port;
            p.tls_ev.push(row.flow_id, row.frame_no);
        }

        if method == "POST" {
            let uri = clip(row.uri.as_deref().unwrap_or(""), MAX_URI);
            // Absolute-form URIs (proxy style) and origin-form name the same resource.
            let path = uri
                .strip_prefix("http://")
                .and_then(|r| r.find('/').map(|i| &r[i..]))
                .unwrap_or(uri);
            let path = path.split('?').next().unwrap_or(path);
            let key = (m.src, m.dst, hash64(path));
            let idx = match self.uri_index.get(&key) {
                Some(&i) => i,
                None => {
                    if self.uris.len() >= MAX_URI_ENTRIES {
                        return;
                    }
                    self.uris.push(UriStats {
                        src: m.src,
                        dst: m.dst,
                        uri: path.to_string(),
                        host: raw_host.to_string(),
                        ip_literal,
                        posts: 0,
                        req_bytes: 0,
                        first_ts: row.ts,
                        last_ts: row.ts,
                        ev: EvAcc::default(),
                    });
                    self.uri_index.insert(key, self.uris.len() - 1);
                    self.uris.len() - 1
                }
            };
            if let Some(u) = self.uris.get_mut(idx) {
                u.posts += 1;
                u.req_bytes = u.req_bytes.saturating_add(row.req_bytes);
                u.ip_literal &= ip_literal;
                u.first_ts = u.first_ts.min(row.ts);
                u.last_ts = u.last_ts.max(row.ts);
                u.ev.push(row.flow_id, row.frame_no);
            }
        }
    }
}

/// Shared damping for allowlist and fleet prevalence.
fn common_factors(
    rule: &Rule,
    allow: &Allowlist,
    dst_ip: &str,
    names: &[String],
    prevalence: usize,
    internal_hosts: usize,
) -> Vec<(f64, String)> {
    let mut out = Vec::new();
    let hit = allow.ip(dst_ip).map(str::to_string).or_else(|| {
        names
            .iter()
            .find_map(|n| allow.domain(n).map(str::to_string))
    });
    if let Some(r) = hit {
        let f = rule.num("allowlist_factor");
        out.push((
            f,
            format!(
                "destination allowlisted: {}; score ×{}",
                display(&r),
                fmt_num(f, 2)
            ),
        ));
    }
    let need = rule
        .num("prevalence_min_hosts")
        .max(rule.num("prevalence_ratio") * internal_hosts as f64);
    if prevalence >= 2 && prevalence as f64 >= need {
        let f = rule.num("prevalence_factor");
        out.push((
            f,
            format!(
                "{prevalence} of {internal_hosts} internal hosts contact this destination; score ×{}",
                fmt_num(f, 2)
            ),
        ));
    }
    out
}

/// Context shared by the HTTP analyses.
pub(crate) struct HttpCtx<'a> {
    pub(crate) col: &'a HttpCollector,
    pub(crate) hosts: &'a Hosts,
    pub(crate) allow: &'a Allowlist,
    pub(crate) flows: &'a beacon::Collector,
    pub(crate) internal_hosts: usize,
}

/// Request-level beacons. `skip` holds (src, dst) pairs `beaconing` already
/// reported, so the same behaviour is not counted twice.
pub(crate) fn analyze_beaconing(
    cx: &HttpCtx<'_>,
    fcx: &beacon::FinalizeCtx<'_>,
    rule: &Rule,
    rule_idx: usize,
    entity_ok: &dyn Fn(u32) -> bool,
    skip: &std::collections::HashSet<(u32, u32)>,
    out: &mut Vec<Hit>,
) {
    let mut cands = beacon::analyze(&cx.col.series, rule, rule_idx, entity_ok);
    cands.sort_by_key(|c| (c.src, c.dst));
    for c in cands {
        if skip.contains(&(c.src, c.dst)) {
            continue;
        }
        let Some(info) = cx.col.pairs.get(&(c.src, c.dst)) else {
            continue;
        };
        let per_flow = info.requests as f64 / (c.distinct_flows.max(1)) as f64;
        if per_flow < rule.num("min_requests_per_flow") {
            continue; // one request per connection: the flow-start series covers it
        }
        let mut extra = beacon::Extra {
            names: info.host_names.clone(),
            signal: Some("request_regularity"),
            ..Default::default()
        };
        if info.named > 0 && info.ip_literal == 0 {
            let f = rule.num("named_host_factor");
            extra.factors.push((
                f,
                format!(
                    "requests name host {}; score ×{}",
                    display(info.host_names.first().map_or("", String::as_str)),
                    fmt_num(f, 2)
                ),
            ));
        }
        extra.values.push((
            "host_kind",
            if info.ip_literal > 0 {
                "a bare IP Host".to_string()
            } else {
                "a named Host".to_string()
            },
        ));
        extra.values.push(("per_conn", fmt_num(per_flow, 1)));
        if let Some(mut h) = beacon::finalize(&c, rule, fcx, &extra) {
            h.tiebreak = cx.hosts.name(c.dst).to_string();
            out.push(h);
        }
    }
}

/// Cleartext HTTP on TLS ports.
pub(crate) fn analyze_tls_port(
    cx: &HttpCtx<'_>,
    rule: &Rule,
    rule_idx: usize,
    entity_ok: &dyn Fn(u32) -> bool,
    out: &mut Vec<Hit>,
) {
    let mut keys: Vec<&(u32, u32)> = cx.col.pairs.keys().collect();
    keys.sort_unstable();
    for &(src, dst) in keys {
        let Some(p) = cx.col.pairs.get(&(src, dst)) else {
            continue;
        };
        if !entity_ok(src) || (p.tls_port_reqs as f64) < rule.num("min_requests") {
            continue;
        }
        let dst_ip = cx.hosts.name(dst);
        let s_clear = ramp(p.tls_port_reqs as f64, 0.0, rule.num("requests_full"));
        let s_ip = if p.ip_literal > 0 && p.named == 0 {
            1.0
        } else {
            0.0
        };
        let pts = [
            ("cleartext", rule.weight("cleartext") * s_clear),
            ("ip_host", rule.weight("ip_host") * s_ip * s_clear),
        ];
        let factors = common_factors(
            rule,
            cx.allow,
            dst_ip,
            &p.host_names,
            cx.flows.prevalence(dst),
            cx.internal_hosts,
        );
        let factor: f64 = factors.iter().map(|(f, _)| f).product();
        let points = pts.iter().map(|(_, p)| p).sum::<f64>() * factor;
        if points < rule.def.min_score || points <= 0.0 {
            continue;
        }
        let mut v = BTreeMap::new();
        v.insert("src".into(), display(cx.hosts.name(src)));
        v.insert("dst".into(), display(dst_ip));
        v.insert("dst_port".into(), p.tls_port.to_string());
        v.insert("requests".into(), p.tls_port_reqs.to_string());
        v.insert(
            "host".into(),
            p.host_names
                .first()
                .map_or_else(|| "a bare IP".to_string(), |h| display(h)),
        );
        v.insert("points".into(), fmt_num(points, 1));
        v.insert("breakdown".into(), breakdown(&pts, factor));
        let mut explanation = render_template(&rule.def.explanation, &v);
        push_notes(&mut explanation, &factors);
        out.push(Hit {
            entity: Entity::Host(src),
            rule_idx,
            detector_family: "http",
            title: render_template(&rule.def.title, &v),
            tiebreak: dst_ip.to_string(),
            ts_first: p.first_ts,
            ts_last: p.last_ts,
            reason: Reason {
                rule_id: rule.def.id.clone(),
                signal: "cleartext_on_tls_port".into(),
                value: p.tls_port_reqs as f64,
                unit: Some("count".into()),
                weight: round1(points),
                explanation,
                attack_technique: rule.def.attack_technique.clone(),
                evidence: p.tls_ev.to_evidence(),
            },
        });
    }
}

/// Repeated POSTs to one URI with a C2 tell.
pub(crate) fn analyze_post_exfil(
    cx: &HttpCtx<'_>,
    rule: &Rule,
    rule_idx: usize,
    entity_ok: &dyn Fn(u32) -> bool,
    out: &mut Vec<Hit>,
) {
    for u in &cx.col.uris {
        if !entity_ok(u.src) || (u.posts as f64) < rule.num("min_posts") {
            continue;
        }
        let dst_ip = cx.hosts.name(u.dst);
        let span_min =
            (u.last_ts.saturating_sub(u.first_ts) as f64 / 60e6).max(rule.num("min_span_s") / 60.0);
        let rate = u.posts as f64 / span_min;
        let s_up = ramp(
            u.req_bytes as f64,
            rule.num("bytes_low"),
            rule.num("bytes_high"),
        );
        let s_ip = if u.ip_literal { 1.0 } else { 0.0 };
        let tell = s_up.max(s_ip);
        let s_rep = ramp(u.posts as f64, 0.0, rule.num("posts_full")) * tell;
        let s_rate = ramp(rate, rule.num("rate_low"), rule.num("rate_high")) * tell;
        let pts = [
            ("upload_volume", rule.weight("upload_volume") * s_up),
            ("ip_host", rule.weight("ip_host") * s_ip),
            ("repeat", rule.weight("repeat") * s_rep),
            ("rate", rule.weight("rate") * s_rate),
        ];
        let names: Vec<String> = if u.ip_literal {
            Vec::new()
        } else {
            vec![host_name(&u.host)]
        };
        let mut factors = common_factors(
            rule,
            cx.allow,
            dst_ip,
            &names,
            cx.flows.prevalence(u.dst),
            cx.internal_hosts,
        );
        if !u.ip_literal {
            let f = rule.num("named_host_factor");
            factors.push((
                f,
                format!(
                    "POSTs name host {}; score ×{}",
                    display(names.first().map_or("", String::as_str)),
                    fmt_num(f, 2)
                ),
            ));
        }
        let factor: f64 = factors.iter().map(|(f, _)| f).product();
        let points = pts.iter().map(|(_, p)| p).sum::<f64>() * factor;
        if points < rule.def.min_score || points <= 0.0 {
            continue;
        }
        let mut v = BTreeMap::new();
        v.insert("src".into(), display(cx.hosts.name(u.src)));
        v.insert("dst".into(), display(dst_ip));
        v.insert(
            "host".into(),
            if u.host.is_empty() {
                display(dst_ip)
            } else {
                display(&u.host)
            },
        );
        v.insert("uri".into(), display(&u.uri));
        v.insert("posts".into(), u.posts.to_string());
        v.insert("bytes".into(), u.req_bytes.to_string());
        v.insert("mb".into(), fmt_num(u.req_bytes as f64 / 1_048_576.0, 1));
        v.insert("rate_per_min".into(), fmt_num(rate, 1));
        v.insert(
            "span_s".into(),
            fmt_num(u.last_ts.saturating_sub(u.first_ts) as f64 / 1e6, 0),
        );
        v.insert("points".into(), fmt_num(points, 1));
        v.insert("breakdown".into(), breakdown(&pts, factor));
        let mut explanation = render_template(&rule.def.explanation, &v);
        push_notes(&mut explanation, &factors);
        out.push(Hit {
            entity: Entity::Host(u.src),
            rule_idx,
            detector_family: "http",
            title: render_template(&rule.def.title, &v),
            tiebreak: format!("{dst_ip} {}", u.uri),
            ts_first: u.first_ts,
            ts_last: u.last_ts,
            reason: Reason {
                rule_id: rule.def.id.clone(),
                signal: "repeated_post".into(),
                value: u.posts as f64,
                unit: Some("count".into()),
                weight: round1(points),
                explanation,
                attack_technique: rule.def.attack_technique.clone(),
                evidence: u.ev.to_evidence(),
            },
        });
    }
}

fn breakdown(points: &[(&str, f64)], factor: f64) -> String {
    points
        .iter()
        .filter(|(_, p)| *p >= 0.05)
        .map(|(s, p)| format!("{s} {}", fmt_num(p * factor, 1)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn push_notes(explanation: &mut String, factors: &[(f64, String)]) {
    if !factors.is_empty() {
        let notes: Vec<&str> = factors.iter().map(|(_, n)| n.as_str()).collect();
        explanation.push_str(&format!(" ({})", notes.join("; ")));
    }
}

/// Map of flow id → context, built in the flows pass.
pub(crate) type FlowMap = HashMap<FlowId, FlowMeta>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literal_hosts() {
        for h in [
            "194.180.191.64",
            "194.180.191.64:443",
            "[2001:db8::1]:80",
            "::1",
            "",
            " ",
        ] {
            assert!(host_is_ip_literal(h), "{h:?}");
        }
        for h in [
            "api.example.com",
            "api.example.com:8080",
            "localhost",
            "1.2.3.4.nip.io",
        ] {
            assert!(!host_is_ip_literal(h), "{h:?}");
        }
        assert_eq!(host_name("API.Example.com:8080"), "api.example.com");
    }
}
