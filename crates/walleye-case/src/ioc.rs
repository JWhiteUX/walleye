//! IOC extraction, normalization, defang and refang.
//!
//! IOCs are anchored on findings: a finding's reasons point at flows and
//! frames, and the rows of those flows (flows/dns/http/tls via
//! [`DetectSource`]) supply the indicator values. Everything read from the
//! capture is hostile input, so each value is normalized and validated before
//! it can become an IOC; values that do not look like a well-formed indicator
//! are dropped rather than repaired.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
};

use sha2::{Digest, Sha256};
use walleye_core::{
    Allowlist, Evidence, Finding, FlowRow, FrameNo, Ioc, IocType, Ts, error::ApiResult,
    findings::EVIDENCE_CAP, sink::DetectSource,
};

/// A parent domain with at least this many distinct child names among the
/// finding-related rows is reported once, as the parent (DNS tunnels and
/// fast-flux subdomains would otherwise produce thousands of IOCs).
pub const SUBDOMAIN_COLLAPSE_MIN: usize = 8;

/// Longest URL (after normalization) kept as an IOC.
pub const MAX_URL_LEN: usize = 4096;

/// snake_case name of an IOC type, as used in `ioc_id` and exports.
pub fn type_name(t: IocType) -> &'static str {
    match t {
        IocType::Ip => "ip",
        IocType::Domain => "domain",
        IocType::Url => "url",
        IocType::Ja4 => "ja4",
        IocType::CertSerial => "cert_serial",
    }
}

/// `hex16(sha256("ioc\0" + type + "\0" + value))` (CONTRACTS §2).
pub fn ioc_id(t: IocType, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ioc\0");
    h.update(type_name(t).as_bytes());
    h.update(b"\0");
    h.update(value.as_bytes());
    let d = h.finalize();
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// defang / refang

/// Defang an IOC value for display and export so it is never live.
///
/// * every `.` becomes `[.]` (IP, domain, URL)
/// * every `:` in an IP becomes `[:]` (IPv6)
/// * a URL's leading `http` becomes `hxxp` (`hxxp://`, `hxxps://`)
/// * JA4 and certificate serials have nothing to defang and pass through.
///
/// [`refang`] is its exact inverse on every value [`normalize`] can produce
/// (and on any string, for the non-URL types).
pub fn defang(ioc_type: IocType, value: &str) -> String {
    match ioc_type {
        IocType::Ip => value.replace('.', "[.]").replace(':', "[:]"),
        IocType::Domain => value.replace('.', "[.]"),
        IocType::Url => {
            let body = value.replace('.', "[.]");
            match body.strip_prefix("http") {
                Some(rest) => format!("hxxp{rest}"),
                None => body,
            }
        }
        IocType::Ja4 | IocType::CertSerial => value.to_string(),
    }
}

/// Inverse of [`defang`]: `refang(t, &defang(t, x)) == x`.
pub fn refang(ioc_type: IocType, defanged: &str) -> String {
    match ioc_type {
        IocType::Ip => defanged.replace("[:]", ":").replace("[.]", "."),
        IocType::Domain => defanged.replace("[.]", "."),
        IocType::Url => {
            let body = match defanged.strip_prefix("hxxp") {
                Some(rest) => format!("http{rest}"),
                None => defanged.to_string(),
            };
            body.replace("[.]", ".")
        }
        IocType::Ja4 | IocType::CertSerial => defanged.to_string(),
    }
}

// ---------------------------------------------------------------------------
// normalization

/// Normalize a raw value of the given type, or `None` when it is not a
/// well-formed indicator.
pub fn normalize(ioc_type: IocType, raw: &str) -> Option<String> {
    match ioc_type {
        IocType::Ip => normalize_ip(raw).map(|ip| ip.to_string()),
        IocType::Domain => normalize_domain(raw),
        IocType::Url => normalize_url(raw),
        IocType::Ja4 => normalize_ja4(raw),
        IocType::CertSerial => normalize_cert_serial(raw),
    }
}

fn normalize_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    let s = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    s.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Suffixes that never name an Internet host.
const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "localhost",
    "arpa",
    "internal",
    "lan",
    "localdomain",
];

fn normalize_domain(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || normalize_ip(&s).is_some() {
        return None;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for l in &labels {
        if l.is_empty()
            || l.len() > 63
            || !l
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.bytes().all(|b| b.is_ascii_digit()) || LOCAL_SUFFIXES.contains(&tld) {
        return None;
    }
    Some(s)
}

fn normalize_ja4(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    let ok = !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    ok.then_some(s)
}

fn normalize_cert_serial(raw: &str) -> Option<String> {
    let s: String = raw
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    let ok = !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then_some(s)
}

/// A host as it appears in a URL authority: a domain or an IP.
enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    fn parse(raw: &str) -> Option<Host> {
        if let Some(ip) = normalize_ip(raw) {
            return Some(Host::Ip(ip));
        }
        normalize_domain(raw).map(Host::Domain)
    }
    fn authority(&self) -> String {
        match self {
            Host::Domain(d) => d.clone(),
            Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
            Host::Ip(ip) => ip.to_string(),
        }
    }
}

/// Split `host[:port]` / `[v6][:port]`.
fn split_host_port(s: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        return match after {
            "" => Some((h, None)),
            p => Some((h, Some(p.strip_prefix(':')?.parse().ok()?))),
        };
    }
    match s.rsplit_once(':') {
        // A bare IPv6 without brackets has several colons: no port.
        Some((h, _)) if h.contains(':') => Some((s, None)),
        Some((h, p)) => Some((h, Some(p.parse().ok()?))),
        None => Some((s, None)),
    }
}

/// Percent-encode bytes that must not appear raw in a URL path/query
/// (controls, space, non-ASCII and a few unsafe ASCII characters). `%` is
/// kept so existing escapes survive unchanged.
fn encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unsafe_byte = b <= 0x20
            || b >= 0x7f
            || matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            );
        if unsafe_byte {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

fn assemble_url(scheme: &str, host: &Host, port: Option<u16>, path: &str) -> Option<String> {
    let default = if scheme == "https" { 443 } else { 80 };
    let port = port.filter(|&p| p != default);
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        encode_path(path)
    } else {
        return None;
    };
    let mut url = format!("{scheme}://{}", host.authority());
    if let Some(p) = port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str(&path);
    (url.len() <= MAX_URL_LEN).then_some(url)
}

/// Normalize an absolute `http(s)://` URL: lowercase scheme and host, strip
/// the default port, percent-encode unsafe path bytes.
fn normalize_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    let (scheme, rest) = s.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, String::new()),
    };
    if authority.contains('@') {
        return None; // userinfo: never part of an indicator we emit
    }
    let (h, port) = split_host_port(authority)?;
    let host = Host::parse(h)?;
    assemble_url(&scheme, &host, port, &path)
}

/// Build the URL of an HTTP request from its Host header, the flow's
/// responder address and the request target.
pub fn http_url(host_header: Option<&str>, flow: Option<&FlowRow>, uri: &str) -> Option<String> {
    let uri = uri.trim();
    let lower = uri
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return normalize_url(uri);
    }
    let (host, port) = match host_header.map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => {
            let (h, p) = split_host_port(h)?;
            (Host::parse(h)?, p.or(flow.map(|f| f.dst_port)))
        }
        None => {
            let f = flow?;
            (Host::Ip(normalize_ip(&f.dst_ip)?), Some(f.dst_port))
        }
    };
    assemble_url("http", &host, port, uri)
}

/// True for addresses that can identify an Internet host (not private,
/// loopback, link-local, multicast, broadcast, CGNAT or unspecified).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00)
        }
    }
}

/// Two-label public suffixes common enough to matter. Without the full
/// Public Suffix List this is an approximation, used only to group
/// subdomains of one parent.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "ne.jp", "or.jp", "co.kr", "com.br", "com.cn", "com.mx", "co.in", "co.za", "com.tr", "com.sg",
    "com.hk", "com.tw", "com.ar", "com.ru",
];

/// Approximate registrable parent ("eTLD+1") of a normalized domain.
pub fn parent_domain(domain: &str) -> &str {
    let dots: Vec<usize> = domain.match_indices('.').map(|(i, _)| i).collect();
    if dots.len() < 2 {
        return domain;
    }
    let last_two = &domain[dots[dots.len() - 2] + 1..];
    let keep = if MULTI_LABEL_SUFFIXES.contains(&last_two) {
        3
    } else {
        2
    };
    if dots.len() < keep {
        return domain;
    }
    &domain[dots[dots.len() - keep] + 1..]
}

// ---------------------------------------------------------------------------
// extraction

#[derive(Default)]
struct Acc {
    frames: BTreeSet<FrameNo>,
    flows: BTreeSet<u64>,
    first_seen: Option<Ts>,
    /// Indexes into the score-ranked findings list.
    findings: BTreeSet<usize>,
    /// Allowlist reason inherited from the row's context (e.g. a URL whose
    /// host is allowlisted). `None` in any sighting clears it.
    context_reason: Option<Option<String>>,
}

impl Acc {
    fn add(&mut self, s: &Sighting) {
        self.frames.insert(s.frame_no);
        self.flows.insert(s.flow_id);
        self.first_seen = Some(self.first_seen.map_or(s.ts, |t| t.min(s.ts)));
        self.findings.extend(s.findings.iter().copied());
        self.context_reason = Some(match self.context_reason.take() {
            None => s.context_reason.clone(),
            Some(prev) => prev.and(s.context_reason.clone()),
        });
    }
    fn merge(&mut self, o: Acc) {
        self.frames.extend(o.frames);
        self.flows.extend(o.flows);
        self.first_seen = match (self.first_seen, o.first_seen) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.findings.extend(o.findings);
        self.context_reason = match (self.context_reason.take(), o.context_reason) {
            (Some(a), Some(b)) => Some(a.and(b)),
            (a, b) => a.or(b),
        };
    }
}

struct Sighting<'a> {
    ts: Ts,
    flow_id: u64,
    frame_no: FrameNo,
    findings: &'a [usize],
    context_reason: Option<String>,
}

/// Cap an id set to `EVIDENCE_CAP`, keeping the earliest.
fn capped<T: Copy>(set: &BTreeSet<T>) -> Vec<T> {
    set.iter().take(EVIDENCE_CAP).copied().collect()
}

fn evidence_of(acc: &Acc) -> Evidence {
    let total = acc.frames.len().max(acc.flows.len()) as u64;
    Evidence {
        flow_ids: capped(&acc.flows),
        frame_nos: capped(&acc.frames),
        truncated: acc.frames.len() > EVIDENCE_CAP || acc.flows.len() > EVIDENCE_CAP,
        total,
    }
}

fn allow_reason(allow: &Allowlist, t: IocType, value: &str) -> Option<String> {
    match t {
        IocType::Ip => allow.ip(value),
        IocType::Domain => allow.domain(value),
        IocType::Ja4 => allow.ja4(value),
        IocType::Url | IocType::CertSerial => None,
    }
    .map(str::to_string)
}

fn host_allow_reason(allow: &Allowlist, host: &str) -> Option<String> {
    allow
        .ip(host)
        .or_else(|| allow.domain(host))
        .map(str::to_string)
}

fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    match split_host_port(auth) {
        Some((h, _)) => h,
        None => auth,
    }
}

/// Extract IOCs from the rows behind `findings`.
///
/// * flows (non-DNS): the public counterparty IP of the finding's host
/// * dns: query names (collapsed to their parent when a parent has
///   [`SUBDOMAIN_COLLAPSE_MIN`] or more distinct children); any DNS lookup in
///   the capture of an extracted domain, or that resolved to an extracted IP,
///   adds its frame as evidence
/// * http: the Host (domain or IP) and the request URL
/// * tls: SNI (domain or IP), JA4, certificate serial
///
/// IOCs are deduplicated by `ioc_id`; evidence merges across findings, and
/// `source_finding_id` is the highest-scoring finding that produced the IOC.
/// Allowlisted IOCs are kept with `allowlisted = true` and the reason.
/// Output is sorted by `first_seen`, then type, then value.
pub fn extract_iocs(
    findings: &[Finding],
    src: &dyn DetectSource,
    allow: &Allowlist,
) -> ApiResult<Vec<Ioc>> {
    // Rank findings so index order = preference for source_finding_id.
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });

    let mut by_flow: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut by_frame: HashMap<FrameNo, Vec<usize>> = HashMap::new();
    for (i, f) in ranked.iter().enumerate() {
        for r in &f.reasons {
            for &id in &r.evidence.flow_ids {
                push_unique(by_flow.entry(id).or_default(), i);
            }
            for &n in &r.evidence.frame_nos {
                push_unique(by_frame.entry(n).or_default(), i);
            }
        }
    }

    let mut accs: Accs = BTreeMap::new();

    // Flows: remote public IPs; keep rows of related flows for the other tables.
    let mut flows: HashMap<u64, FlowRow> = HashMap::new();
    src.for_each_flow(&mut |f| {
        let Some(idx) = by_flow.get(&f.flow_id) else {
            return;
        };
        flows.insert(f.flow_id, f.clone());
        if is_dns_flow(f) {
            return; // the resolver is not an indicator
        }
        // The counterparty of each finding's host (normally the responder).
        let mut per_remote: Vec<(&str, Vec<usize>)> = Vec::new();
        for &i in idx {
            let remote = if f.dst_ip == ranked[i].entity {
                f.src_ip.as_str()
            } else {
                f.dst_ip.as_str()
            };
            match per_remote.iter_mut().find(|(r, _)| *r == remote) {
                Some((_, v)) => v.push(i),
                None => per_remote.push((remote, vec![i])),
            }
        }
        for (remote, fi) in per_remote {
            if let Some(ip) = normalize_ip(remote).filter(|ip| is_public_ip(*ip)) {
                let s = Sighting {
                    ts: f.ts_start,
                    flow_id: f.flow_id,
                    frame_no: f.first_frame,
                    findings: &fi,
                    context_reason: None,
                };
                add(&mut accs, IocType::Ip, ip.to_string(), &s);
            }
        }
    })?;

    let related = |flow_id: u64, frame_no: FrameNo| -> Vec<usize> {
        let mut v: Vec<usize> = by_flow.get(&flow_id).cloned().unwrap_or_default();
        for &i in by_frame.get(&frame_no).map(Vec::as_slice).unwrap_or(&[]) {
            push_unique(&mut v, i);
        }
        v
    };

    // DNS query names (collapsed below).
    let mut dns_domains: BTreeMap<(IocType, String), Acc> = BTreeMap::new();
    src.for_each_dns(&mut |d| {
        let idx = related(d.flow_id, d.frame_no);
        if idx.is_empty() {
            return;
        }
        if let Some(name) = normalize_domain(&d.query) {
            let s = Sighting {
                ts: d.ts,
                flow_id: d.flow_id,
                frame_no: d.frame_no,
                findings: &idx,
                context_reason: None,
            };
            dns_domains
                .entry((IocType::Domain, name))
                .or_default()
                .add(&s);
        }
    })?;
    collapse_subdomains(&mut dns_domains);
    for (k, a) in dns_domains {
        accs.entry(k).or_default().merge(a);
    }

    src.for_each_http(&mut |h| {
        let idx = related(h.flow_id, h.frame_no);
        if idx.is_empty() {
            return;
        }
        let flow = flows.get(&h.flow_id);
        let mk = |reason: Option<String>| Sighting {
            ts: h.ts,
            flow_id: h.flow_id,
            frame_no: h.frame_no,
            findings: &idx,
            context_reason: reason,
        };
        if let Some(host) = h.host.as_deref().and_then(|x| split_host_port(x.trim())) {
            match Host::parse(host.0) {
                Some(Host::Domain(d)) => add(&mut accs, IocType::Domain, d, &mk(None)),
                Some(Host::Ip(ip)) if is_public_ip(ip) => {
                    add(&mut accs, IocType::Ip, ip.to_string(), &mk(None))
                }
                _ => {}
            }
        }
        if let Some(url) = h
            .uri
            .as_deref()
            .and_then(|u| http_url(h.host.as_deref(), flow, u))
        {
            let reason = host_allow_reason(allow, url_host(&url).trim_matches(['[', ']']));
            add(&mut accs, IocType::Url, url, &mk(reason));
        }
    })?;

    src.for_each_tls(&mut |t| {
        let idx = related(t.flow_id, t.frame_no);
        if idx.is_empty() {
            return;
        }
        let mut sni_reason = None;
        let mk = |reason: Option<String>| Sighting {
            ts: t.ts,
            flow_id: t.flow_id,
            frame_no: t.frame_no,
            findings: &idx,
            context_reason: reason,
        };
        if let Some(sni) = t.sni.as_deref() {
            match Host::parse(sni) {
                Some(Host::Domain(d)) => {
                    sni_reason = allow.domain(&d).map(str::to_string);
                    add(&mut accs, IocType::Domain, d, &mk(None));
                }
                Some(Host::Ip(ip)) if is_public_ip(ip) => {
                    sni_reason = allow.ip(&ip.to_string()).map(str::to_string);
                    add(&mut accs, IocType::Ip, ip.to_string(), &mk(None));
                }
                _ => {}
            }
        }
        if let Some(j) = t.ja4.as_deref().and_then(normalize_ja4) {
            add(&mut accs, IocType::Ja4, j, &mk(None));
        }
        if let Some(c) = t.cert_serial.as_deref().and_then(normalize_cert_serial) {
            add(&mut accs, IocType::CertSerial, c, &mk(sni_reason.clone()));
        }
    })?;

    // Enrichment: every lookup of an extracted domain, and every name that
    // resolved to an extracted IP, is evidence too (capture-wide).
    let domains: HashSet<String> = accs
        .keys()
        .filter(|(t, _)| *t == IocType::Domain)
        .map(|(_, v)| v.clone())
        .collect();
    let ips: HashSet<String> = accs
        .keys()
        .filter(|(t, _)| *t == IocType::Ip)
        .map(|(_, v)| v.clone())
        .collect();
    let ip_findings: HashMap<String, Vec<usize>> = accs
        .iter()
        .filter(|((t, _), _)| *t == IocType::Ip)
        .map(|((_, v), a)| (v.clone(), a.findings.iter().copied().collect()))
        .collect();
    let domain_findings: HashMap<String, Vec<usize>> = accs
        .iter()
        .filter(|((t, _), _)| *t == IocType::Domain)
        .map(|((_, v), a)| (v.clone(), a.findings.iter().copied().collect()))
        .collect();
    if !domains.is_empty() || !ips.is_empty() {
        src.for_each_dns(&mut |d| {
            let Some(name) = normalize_domain(&d.query) else {
                return;
            };
            let mut hit: Option<Vec<usize>> = None;
            if domains.contains(&name) {
                hit = domain_findings.get(&name).cloned();
            } else if let Some(parent) = domains.get(parent_domain(&name)) {
                // A child of a collapsed parent: evidence for the parent.
                if let Some(f) = domain_findings.get(parent) {
                    let s = Sighting {
                        ts: d.ts,
                        flow_id: d.flow_id,
                        frame_no: d.frame_no,
                        findings: f,
                        context_reason: None,
                    };
                    if let Some(a) = accs.get_mut(&(IocType::Domain, parent.clone())) {
                        a.add(&s);
                    }
                }
                return;
            }
            if hit.is_none() && d.is_response {
                for ans in &d.answers {
                    if let Some(ip) = normalize_ip(ans) {
                        if let Some(f) = ip_findings.get(&ip.to_string()) {
                            hit = Some(f.clone());
                            break;
                        }
                    }
                }
            }
            if let Some(f) = hit {
                let s = Sighting {
                    ts: d.ts,
                    flow_id: d.flow_id,
                    frame_no: d.frame_no,
                    findings: &f,
                    context_reason: None,
                };
                accs.entry((IocType::Domain, name)).or_default().add(&s);
            }
        })?;
    }

    let mut out: Vec<Ioc> = accs
        .into_iter()
        .map(|((t, value), acc)| {
            let reason =
                allow_reason(allow, t, &value).or_else(|| acc.context_reason.clone().flatten());
            Ioc {
                ioc_id: ioc_id(t, &value),
                ioc_type: t,
                defanged: defang(t, &value),
                source_finding_id: acc
                    .findings
                    .iter()
                    .next()
                    .map(|&i| ranked[i].finding_id.clone()),
                first_seen: acc.first_seen.unwrap_or(0),
                evidence: evidence_of(&acc),
                allowlisted: reason.is_some(),
                allowlist_reason: reason,
                value,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        a.first_seen
            .cmp(&b.first_seen)
            .then_with(|| a.ioc_type.cmp(&b.ioc_type))
            .then_with(|| a.value.cmp(&b.value))
    });
    Ok(out)
}

type Accs = BTreeMap<(IocType, String), Acc>;

fn add(accs: &mut Accs, t: IocType, value: String, s: &Sighting) {
    accs.entry((t, value)).or_default().add(s);
}

fn push_unique(v: &mut Vec<usize>, i: usize) {
    if !v.contains(&i) {
        v.push(i);
    }
}

fn is_dns_flow(f: &FlowRow) -> bool {
    f.app_proto.as_deref() == Some("dns") || f.dst_port == 53 || f.src_port == 53
}

/// Replace the children of any parent with at least
/// [`SUBDOMAIN_COLLAPSE_MIN`] distinct names by the parent itself.
fn collapse_subdomains(domains: &mut BTreeMap<(IocType, String), Acc>) {
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for (_, name) in domains.keys() {
        let p = parent_domain(name);
        if p != name {
            children
                .entry(p.to_string())
                .or_default()
                .push(name.clone());
        }
    }
    for (parent, kids) in children {
        if kids.len() < SUBDOMAIN_COLLAPSE_MIN {
            continue;
        }
        let mut merged = domains
            .remove(&(IocType::Domain, parent.clone()))
            .unwrap_or_default();
        for k in kids {
            if let Some(a) = domains.remove(&(IocType::Domain, k)) {
                merged.merge(a);
            }
        }
        domains.insert((IocType::Domain, parent), merged);
    }
}
