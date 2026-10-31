//! Allowlist matching against capture-derived strings (domains, IPs, JA4
//! values from a hostile capture), plus `parse_cidr` / `cidr_contains`.
//!
//! Input: first byte selects the operation, the rest is the string.
//! Invariants: no panic; a parsed network contains its own address; the
//! domain matcher only matches on label boundaries.
#![no_main]

use std::{net::IpAddr, sync::OnceLock};

use libfuzzer_sys::fuzz_target;
use walleye_core::{
    Allowlist,
    allowlist::{cidr_contains, parse_cidr},
};

fn list() -> &'static Allowlist {
    static L: OnceLock<Allowlist> = OnceLock::new();
    L.get_or_init(|| {
        let mut l = Allowlist::from_yaml(include_str!("../../rules/allowlist.yaml"))
            .expect("rules/allowlist.yaml parses");
        // Edge-case entries the default file may not have.
        let extra = Allowlist::from_yaml(
            "domains:\n  - { suffix: example.com., reason: a }\n  - { suffix: COM, reason: b }\n\
             cidrs:\n  - { cidr: 0.0.0.0/0, reason: c }\n  - { cidr: '::/0', reason: d }\n  - { cidr: '2001:db8::/128', reason: e }\n\
             ja4:\n  - { value: t13d1516h2_8daaf6152771_02713d6af862, reason: f }\n",
        )
        .expect("extra parses");
        l.domains.extend(extra.domains);
        l.cidrs.extend(extra.cidrs);
        l.ja4.extend(extra.ja4);
        l
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&op, rest)) = data.split_first() else {
        return;
    };
    let s = String::from_utf8_lossy(rest);
    let l = list();
    match op % 4 {
        0 => {
            if let Some(_reason) = l.domain(&s) {
                // Must be a label-boundary suffix of some entry.
                let n = s.trim_end_matches('.').to_ascii_lowercase();
                let ok = l.domains.iter().any(|e| {
                    let suf = e.suffix.trim_end_matches('.').to_ascii_lowercase();
                    n == suf || n.ends_with(&format!(".{suf}"))
                });
                assert!(ok, "domain {s:?} matched without a label-boundary suffix");
            }
        }
        1 => {
            let _ = l.ip(&s);
        }
        2 => {
            let _ = l.ja4(&s);
        }
        _ => {
            if let Some((net, len)) = parse_cidr(&s) {
                assert!(cidr_contains(net, len, net));
                let other: IpAddr = if net.is_ipv4() {
                    "::1".parse().expect("v6")
                } else {
                    "127.0.0.1".parse().expect("v4")
                };
                assert!(!cidr_contains(net, len, other), "v4/v6 cross match");
            }
        }
    }
});
