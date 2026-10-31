//! Known-good allowlist schema (`rules/allowlist.yaml`). Used by walleye-detect
//! to suppress reasons and by walleye-case to flag IOCs. Matching lives here so
//! both crates agree.
//!
//! ```yaml
//! version: 1
//! domains:            # suffix match on label boundaries
//!   - { suffix: windowsupdate.com, reason: "Microsoft Update" }
//! cidrs:
//!   - { cidr: 17.0.0.0/8, reason: "Apple" }
//! ja4:
//!   - { value: t13d1516h2_8daaf6152771_02713d6af862, reason: "Chrome" }
//! ```

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEntry {
    pub suffix: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CidrEntry {
    pub cidr: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueEntry {
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default)]
    pub domains: Vec<DomainEntry>,
    #[serde(default)]
    pub cidrs: Vec<CidrEntry>,
    #[serde(default)]
    pub ja4: Vec<ValueEntry>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("bad cidr {0:?}")]
    BadCidr(String),
}

impl Allowlist {
    /// Parse and validate (every CIDR must parse).
    pub fn from_yaml(text: &str) -> Result<Self, AllowlistError> {
        let a: Allowlist = serde_yaml_ng::from_str(text)?;
        for c in &a.cidrs {
            parse_cidr(&c.cidr).ok_or_else(|| AllowlistError::BadCidr(c.cidr.clone()))?;
        }
        Ok(a)
    }

    /// Returns the matching entry's reason. Case-insensitive; a trailing dot
    /// is ignored; `suffix` matches itself and any subdomain, never a mere
    /// string suffix (`notwindowsupdate.com` does not match).
    pub fn domain(&self, name: &str) -> Option<&str> {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().find_map(|e| {
            let s = e.suffix.trim_end_matches('.').to_ascii_lowercase();
            let hit = n == s
                || (n.len() > s.len()
                    && n.ends_with(&s)
                    && n.as_bytes()[n.len() - s.len() - 1] == b'.');
            hit.then_some(e.reason.as_str())
        })
    }

    pub fn ip(&self, ip: &str) -> Option<&str> {
        let ip: IpAddr = ip.parse().ok()?;
        self.cidrs.iter().find_map(|e| {
            let (net, len) = parse_cidr(&e.cidr)?;
            cidr_contains(net, len, ip).then_some(e.reason.as_str())
        })
    }

    pub fn ja4(&self, fp: &str) -> Option<&str> {
        self.ja4
            .iter()
            .find(|e| e.value.eq_ignore_ascii_case(fp))
            .map(|e| e.reason.as_str())
    }
}

/// Parse "a.b.c.d/n" or "v6::/n"; a bare address means a host route.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a.parse::<IpAddr>().ok()?, l.parse::<u8>().ok()?),
        None => {
            let a = s.parse::<IpAddr>().ok()?;
            (a, if a.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((addr, len))
}

pub fn cidr_contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Allowlist {
        Allowlist::from_yaml(
            "domains:\n  - { suffix: windowsupdate.com, reason: MS }\n\
             cidrs:\n  - { cidr: 17.0.0.0/8, reason: Apple }\n  - { cidr: '2606:4700::/32', reason: CF }\n",
        )
        .expect("parse")
    }

    #[test]
    fn domain_suffix_on_label_boundary() {
        let a = list();
        assert_eq!(a.domain("windowsupdate.com"), Some("MS"));
        assert_eq!(a.domain("Download.WindowsUpdate.com."), Some("MS"));
        assert_eq!(a.domain("notwindowsupdate.com"), None);
    }

    #[test]
    fn cidr_match() {
        let a = list();
        assert_eq!(a.ip("17.1.2.3"), Some("Apple"));
        assert_eq!(a.ip("18.1.2.3"), None);
        assert_eq!(a.ip("2606:4700::1"), Some("CF"));
        assert_eq!(a.ip("not an ip"), None);
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(Allowlist::from_yaml("cidrs:\n  - { cidr: 1.2.3.4/33, reason: x }\n").is_err());
    }

    #[test]
    fn default_file_parses() {
        let text = include_str!("../../../rules/allowlist.yaml");
        Allowlist::from_yaml(text).expect("rules/allowlist.yaml must parse");
    }
}
