//! Small shared helpers: IP interning, address classes, entropy, a built-in
//! registered-domain heuristic, display sanitising, evidence accumulation and
//! the stable finding id.
//!
//! Everything here treats its input as hostile: strings may be huge, contain
//! control characters, be empty or be nonsense. Nothing panics.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;

use sha2::{Digest, Sha256};
use walleye_core::findings::EVIDENCE_CAP;
use walleye_core::{Evidence, FlowId, FrameNo};

/// Longest IP text we bother parsing (longest canonical IPv6 text is 45).
const MAX_IP_TEXT: usize = 64;
/// DNS names are at most 253 characters; anything longer is cut for analysis.
pub(crate) const MAX_NAME: usize = 253;
/// Longest string we put into a title or explanation.
const MAX_DISPLAY: usize = 96;

/// Address class of an interned IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddrClass {
    /// RFC 1918, CGNAT, link-local, loopback, ULA: a host we report on.
    Internal,
    /// Publicly routable unicast.
    External,
    /// Multicast, broadcast, unspecified, documentation, or unparsable text.
    /// Never a beacon destination or a reported entity.
    Special,
}

/// Interns IP strings to dense `u32` ids so per-pair maps stay small.
/// Ids are assigned in first-seen order, which keeps runs deterministic.
#[derive(Debug, Default)]
pub(crate) struct Hosts {
    ids: HashMap<String, u32>,
    names: Vec<String>,
    classes: Vec<AddrClass>,
}

impl Hosts {
    pub(crate) fn intern(&mut self, ip: &str) -> u32 {
        let key = clip(ip, MAX_IP_TEXT);
        if let Some(&id) = self.ids.get(key) {
            return id;
        }
        let id = self.names.len() as u32;
        self.ids.insert(key.to_string(), id);
        self.names.push(key.to_string());
        self.classes.push(classify(key));
        id
    }

    pub(crate) fn lookup(&self, ip: &str) -> Option<u32> {
        self.ids.get(clip(ip, MAX_IP_TEXT)).copied()
    }

    pub(crate) fn name(&self, id: u32) -> &str {
        self.names.get(id as usize).map_or("?", String::as_str)
    }

    pub(crate) fn class(&self, id: u32) -> AddrClass {
        self.classes
            .get(id as usize)
            .copied()
            .unwrap_or(AddrClass::Special)
    }
}

/// Cut `s` to at most `max` bytes on a char boundary.
pub(crate) fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub(crate) fn classify(ip: &str) -> AddrClass {
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return AddrClass::Special;
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || o[0] >= 240
            {
                AddrClass::Special
            } else if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
            {
                AddrClass::Internal
            } else {
                AddrClass::External
            }
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify(&v4.to_string());
            }
            if v6.is_unspecified()
                || v6.is_multicast()
                || seg0 == 0x2001 && v6.segments()[1] == 0xdb8
            {
                AddrClass::Special
            } else if v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
                AddrClass::Internal
            } else {
                AddrClass::External
            }
        }
    }
}

/// Shannon entropy in bits per symbol over the bytes of `s`, ignoring dots.
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for &b in s.as_bytes() {
        if b != b'.' {
            counts[b as usize] += 1;
            n += 1;
        }
    }
    if n == 0 {
        return 0.0;
    }
    let n = f64::from(n);
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Second-level labels that, under a two-letter ccTLD, form a public suffix
/// (`co.uk`, `com.au`, `ne.jp`, ...). A small built-in heuristic instead of
/// the full Public Suffix List: no network, no large embedded file.
const CC_SECOND_LEVEL: &[&str] = &[
    "ac", "co", "com", "edu", "gov", "net", "org", "ne", "or", "go", "gob", "mil", "nic", "ltd",
    "plc", "sch", "nom", "gen", "biz", "info",
];

/// Multi-label public suffixes outside the ccTLD pattern above.
const EXTRA_SUFFIXES: &[&str] = &["in-addr.arpa", "ip6.arpa", "home.arpa"];

/// Split a DNS name into `(prefix, registered_domain)`, e.g.
/// `a.b.example.co.uk` → (`a.b`, `example.co.uk`). Single-label names return
/// (`""`, name). Empty labels are dropped. Input must already be lowercase.
pub(crate) fn split_registered(name: &str) -> (String, String) {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n <= 1 {
        return (
            String::new(),
            labels.first().copied().unwrap_or("").to_string(),
        );
    }
    let last = labels[n - 1];
    // An all-digit "TLD" means the name is an IPv4 literal: treat it whole.
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return (String::new(), labels.join("."));
    }
    let last_two = format!("{}.{}", labels[n - 2], last);
    let suffix_len = if EXTRA_SUFFIXES.contains(&last_two.as_str())
        || (last.len() == 2 && CC_SECOND_LEVEL.contains(&labels[n - 2]))
    {
        2
    } else {
        1
    };
    let reg_len = (suffix_len + 1).min(n);
    let split = n - reg_len;
    (labels[..split].join("."), labels[split..].join("."))
}

/// Case-fold, trim the trailing dot and clip a hostile DNS name for analysis.
pub(crate) fn normalize_name(q: &str) -> String {
    clip(q, MAX_NAME).trim_end_matches('.').to_ascii_lowercase()
}

/// True if `name` equals `suffix` or ends with `.suffix`.
pub(crate) fn has_suffix(name: &str, suffix: &str) -> bool {
    let s = suffix.trim_matches('.');
    if s.is_empty() {
        return false;
    }
    name == s
        || (name.len() > s.len()
            && name.ends_with(s)
            && name.as_bytes()[name.len() - s.len() - 1] == b'.')
}

/// Render an untrusted string for titles/explanations: printable ASCII only
/// (others become `?`), clipped with an ellipsis. Never markup, never bytes.
pub(crate) fn display(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= MAX_DISPLAY {
            out.push('…');
            break;
        }
        out.push(if c.is_ascii_graphic() || c == ' ' {
            c
        } else {
            '?'
        });
    }
    out
}

/// Deterministic 64-bit hash (SipHash with fixed keys).
pub(crate) fn hash64<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// Collects evidence ids, keeping the first `EVIDENCE_CAP` of each list (rows
/// arrive in time order, so the first are the earliest) and the real total.
#[derive(Debug, Clone, Default)]
pub(crate) struct EvAcc {
    flow_ids: Vec<FlowId>,
    frame_nos: Vec<FrameNo>,
    total: u64,
}

impl EvAcc {
    pub(crate) fn push(&mut self, flow_id: FlowId, frame_no: FrameNo) {
        self.total += 1;
        if self.flow_ids.len() < EVIDENCE_CAP && self.flow_ids.last() != Some(&flow_id) {
            self.flow_ids.push(flow_id);
        }
        if self.frame_nos.len() < EVIDENCE_CAP {
            self.frame_nos.push(frame_no);
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    pub(crate) fn to_evidence(&self) -> Evidence {
        let truncated = self.total as usize > self.frame_nos.len();
        Evidence {
            flow_ids: self.flow_ids.clone(),
            frame_nos: self.frame_nos.clone(),
            truncated,
            total: self.total,
        }
    }
}

/// `hex16(sha256("finding\0" + detector + "\0" + entity_type + "\0" + entity))`
/// per CONTRACTS §2.
pub fn finding_id(detector: &str, entity_type: &str, entity: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"finding\0");
    h.update(detector.as_bytes());
    h.update(b"\0");
    h.update(entity_type.as_bytes());
    h.update(b"\0");
    h.update(entity.as_bytes());
    let digest = h.finalize();
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Linear ramp: 0 at or below `lo`, 1 at or above `hi`.
pub(crate) fn ramp(x: f64, lo: f64, hi: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    if hi <= lo {
        return if x >= hi { 1.0 } else { 0.0 };
    }
    ((x - lo) / (hi - lo)).clamp(0.0, 1.0)
}

/// Median of a slice (sorts it). Empty → 0.
pub(crate) fn median(v: &mut [f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(f64::total_cmp);
    let m = v.len() / 2;
    if v.len() % 2 == 1 {
        v[m]
    } else {
        (v[m - 1] + v[m]) / 2.0
    }
}

/// Round to one decimal place (reason weights and displayed values).
pub(crate) fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Format a float for an explanation: up to `dp` decimals, no trailing zeros.
pub(crate) fn fmt_num(x: f64, dp: usize) -> String {
    let s = format!("{x:.dp$}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        assert_eq!(classify("10.0.0.5"), AddrClass::Internal);
        assert_eq!(classify("172.20.1.1"), AddrClass::Internal);
        assert_eq!(classify("192.168.1.1"), AddrClass::Internal);
        assert_eq!(classify("100.64.0.1"), AddrClass::Internal);
        assert_eq!(classify("fe80::1"), AddrClass::Internal);
        assert_eq!(classify("fd00::1"), AddrClass::Internal);
        assert_eq!(classify("8.8.8.8"), AddrClass::External);
        assert_eq!(classify("2606:4700::1"), AddrClass::External);
        assert_eq!(classify("224.0.0.251"), AddrClass::Special);
        assert_eq!(classify("255.255.255.255"), AddrClass::Special);
        assert_eq!(classify("ff02::fb"), AddrClass::Special);
        assert_eq!(classify("garbage"), AddrClass::Special);
        assert_eq!(classify(""), AddrClass::Special);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
        assert!((shannon_entropy("a.b.c.d") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn registered_domain_heuristic() {
        let s = |n: &str| split_registered(n);
        assert_eq!(s("www.example.com"), ("www".into(), "example.com".into()));
        assert_eq!(
            s("a.b.example.co.uk"),
            ("a.b".into(), "example.co.uk".into())
        );
        assert_eq!(s("example.com"), ("".into(), "example.com".into()));
        assert_eq!(s("wpad"), ("".into(), "wpad".into()));
        assert_eq!(s(""), ("".into(), "".into()));
        assert_eq!(s("..a..b.."), ("".into(), "a.b".into()));
        assert_eq!(
            s("4.3.2.1.in-addr.arpa"),
            ("4.3.2".into(), "1.in-addr.arpa".into())
        );
        assert_eq!(s("1.2.3.4"), ("".into(), "1.2.3.4".into()));
        assert_eq!(
            s("x.t.exfil-dns.xyz"),
            ("x.t".into(), "exfil-dns.xyz".into())
        );
        assert_eq!(s("co.uk"), ("".into(), "co.uk".into()));
    }

    #[test]
    fn suffix_on_label_boundary() {
        assert!(has_suffix("a.microsoft.com", "microsoft.com"));
        assert!(has_suffix("microsoft.com", ".microsoft.com"));
        assert!(!has_suffix("notmicrosoft.com", "microsoft.com"));
        assert!(!has_suffix("x", ""));
    }

    #[test]
    fn display_is_safe() {
        assert_eq!(display("a\u{0}b\n<c>"), "a?b?<c>");
        let long = "x".repeat(10_000);
        assert!(display(&long).chars().count() <= MAX_DISPLAY + 1);
        assert_eq!(clip("héllo", 2), "h");
    }

    #[test]
    fn evidence_caps_and_counts() {
        let mut e = EvAcc::default();
        for i in 0..500u64 {
            e.push(i, i * 2 + 1);
        }
        let ev = e.to_evidence();
        assert_eq!(ev.flow_ids.len(), EVIDENCE_CAP);
        assert_eq!(ev.frame_nos.len(), EVIDENCE_CAP);
        assert!(ev.truncated);
        assert_eq!(ev.total, 500);
        assert_eq!(ev.frame_nos[0], 1);
    }

    #[test]
    fn finding_id_matches_contract() {
        let id = finding_id("beaconing", "host", "10.0.0.23");
        assert_eq!(id.len(), 16);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(id, finding_id("beaconing", "host", "10.0.0.23"));
        assert_ne!(id, finding_id("dns", "host", "10.0.0.23"));
        // Independent computation of the contract formula.
        let d = Sha256::digest(b"finding\0beaconing\0host\x0010.0.0.23");
        let want: String = d[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(id, want);
    }

    #[test]
    fn stats_helpers() {
        assert_eq!(median(&mut []), 0.0);
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&mut [4.0, 1.0, 2.0, 3.0]), 2.5);
        assert_eq!(ramp(5.0, 0.0, 10.0), 0.5);
        assert_eq!(ramp(f64::NAN, 0.0, 1.0), 0.0);
        assert_eq!(fmt_num(60.0, 1), "60");
        assert_eq!(fmt_num(59.84, 1), "59.8");
    }
}
