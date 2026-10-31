//! Synthetic scenario builders feeding `MemorySource`, for acceptance tests
//! before real captures exist. Deterministic from a seed (splitmix64).
//!
//! The builder records high-level events (a flow, a DNS lookup), then sorts
//! them by time and assigns flow ids and frame numbers in capture order, so
//! the produced tables look like what ingest emits: flows ordered by
//! `ts_start`, dns rows by `ts`, every evidence id resolvable.
//!
//! The scenarios deliberately include hard benign cases: fleet-wide periodic
//! telemetry, allowlisted OS updates, NTP, a single-host periodic backup agent
//! (a realistic false positive), CDN names with hash-like labels, ad-tech
//! random subdomains on every host, reverse-DNS sweeps, Chrome's random
//! NXDOMAIN probes and search-suffix NXDOMAINs.

#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use walleye_core::sink::MemorySource;
use walleye_core::{
    Allowlist, CaptureFormat, CaptureRow, DnsRow, Finding, FlowRow, HttpRow, TlsRow,
};
use walleye_detect::{RuleSet, load_rules};

pub const T0: i64 = 1_773_306_000_000_000; // 2026-03-12 09:00 UTC
pub const S: i64 = 1_000_000;
pub const RESOLVER: &str = "10.1.0.1";

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in [0, 1).
    pub fn f(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f()
    }
    pub fn int(&mut self, lo: u64, hi_incl: u64) -> u64 {
        lo + self.next_u64() % (hi_incl - lo + 1)
    }
    pub fn chance(&mut self, p: f64) -> bool {
        self.f() < p
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[(self.next_u64() % v.len() as u64) as usize]
    }
    /// Exponential with the given mean.
    pub fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.f()).ln()
    }
    /// Roughly log-normal bytes around `median`.
    pub fn lognorm(&mut self, median: f64, spread: f64) -> u64 {
        let n: f64 = (0..4).map(|_| self.f()).sum::<f64>() - 2.0; // ~N(0, 0.58)
        (median * (n * spread).exp()).max(1.0) as u64
    }
    pub fn alnum(&mut self, n: usize, alphabet: &[u8]) -> String {
        (0..n)
            .map(|_| alphabet[(self.next_u64() % alphabet.len() as u64) as usize] as char)
            .collect()
    }
}

pub const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const HEX: &[u8] = b"0123456789abcdef";
pub const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

enum Item {
    Flow {
        ts: i64,
        dur: i64,
        src: String,
        dst: String,
        dport: u16,
        proto: u8,
        app: Option<&'static str>,
        up: u64,
        down: u64,
        pkts: u64,
        sni: Option<String>,
        http_host: Option<String>,
    },
    Dns {
        ts: i64,
        client: String,
        query: String,
        qtype: &'static str,
        rcode: &'static str,
        answers: Vec<String>,
    },
}

impl Item {
    fn ts(&self) -> i64 {
        match self {
            Item::Flow { ts, .. } | Item::Dns { ts, .. } => *ts,
        }
    }
}

pub struct Synth {
    pub rng: Rng,
    items: Vec<Item>,
    /// Per (client, name) last lookup time, to emulate the stub resolver cache.
    cache: HashMap<(String, String), i64>,
}

impl Synth {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::new(seed),
            items: Vec::new(),
            cache: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn flow(
        &mut self,
        ts: i64,
        src: &str,
        dst: &str,
        dport: u16,
        proto: u8,
        app: Option<&'static str>,
        up: u64,
        down: u64,
    ) {
        let pkts = 2 + (up + down) / 1200;
        let pkts = pkts.min(400);
        self.items.push(Item::Flow {
            ts,
            dur: (pkts as i64) * 20_000,
            src: src.into(),
            dst: dst.into(),
            dport,
            proto,
            app,
            up,
            down,
            pkts,
            sni: None,
            http_host: None,
        });
    }

    pub fn tls(&mut self, ts: i64, src: &str, dst: &str, sni: &str, up: u64, down: u64) {
        let pkts = (6 + (up + down) / 1200).min(400);
        self.items.push(Item::Flow {
            ts,
            dur: (pkts as i64) * 20_000,
            src: src.into(),
            dst: dst.into(),
            dport: 443,
            proto: 6,
            app: Some("tls"),
            up,
            down,
            pkts,
            sni: Some(sni.into()),
            http_host: None,
        });
    }

    pub fn http(&mut self, ts: i64, src: &str, dst: &str, host: &str, up: u64, down: u64) {
        let pkts = (5 + (up + down) / 1200).min(400);
        self.items.push(Item::Flow {
            ts,
            dur: (pkts as i64) * 20_000,
            src: src.into(),
            dst: dst.into(),
            dport: 80,
            proto: 6,
            app: Some("http"),
            up,
            down,
            pkts,
            sni: None,
            http_host: Some(host.into()),
        });
    }

    pub fn dns(
        &mut self,
        ts: i64,
        client: &str,
        query: &str,
        qtype: &'static str,
        rcode: &'static str,
        answers: Vec<String>,
    ) {
        self.items.push(Item::Dns {
            ts,
            client: client.into(),
            query: query.into(),
            qtype,
            rcode,
            answers,
        });
    }

    /// A lookup that honours a 300 s client cache (returns true if sent).
    pub fn resolve(&mut self, ts: i64, client: &str, name: &str, ip: &str) -> bool {
        let key = (client.to_string(), name.to_string());
        if let Some(&last) = self.cache.get(&key) {
            if ts - last < 300 * S {
                return false;
            }
        }
        self.cache.insert(key, ts);
        self.dns(ts, client, name, "A", "NOERROR", vec![ip.to_string()]);
        true
    }

    pub fn build(mut self) -> MemorySource {
        self.items.sort_by_key(Item::ts);
        let mut src = MemorySource {
            capture: Some(CaptureRow {
                capture_id: "synthetic0000000".into(),
                path: "/synthetic.pcap".into(),
                sha256: "0".repeat(64),
                size_bytes: 0,
                format: CaptureFormat::Pcap,
                first_ts: self.items.first().map_or(T0, Item::ts),
                last_ts: self.items.last().map_or(T0, Item::ts),
                link_type: 1,
                frame_count: 0,
            }),
            ..Default::default()
        };
        let mut flow_id = 0u64;
        let mut frame = 0u64;
        let mut sport = 40_000u16;
        for it in self.items {
            flow_id += 1;
            sport = if sport >= 65_000 { 40_000 } else { sport + 1 };
            match it {
                Item::Flow {
                    ts,
                    dur,
                    src: s,
                    dst,
                    dport,
                    proto,
                    app,
                    up,
                    down,
                    pkts,
                    sni,
                    http_host,
                } => {
                    let first = frame + 1;
                    frame += pkts;
                    if let Some(sni) = sni {
                        src.tls.push(TlsRow {
                            ts: ts + 30_000,
                            flow_id,
                            frame_no: first + 3,
                            sni: Some(sni),
                            version: Some("1.3".into()),
                            ja4: None,
                            ja4s: None,
                            cert_subject: None,
                            cert_issuer: None,
                            cert_serial: None,
                            cert_self_signed: None,
                            cert_not_before: None,
                            cert_not_after: None,
                        });
                    }
                    if let Some(host) = http_host {
                        src.http.push(HttpRow {
                            ts: ts + 30_000,
                            flow_id,
                            frame_no: first + 3,
                            method: Some("GET".into()),
                            host: Some(host),
                            uri: Some("/".into()),
                            user_agent: None,
                            status: Some(200),
                            resp_frame_no: Some(first + 4),
                            req_bytes: up,
                            resp_bytes: down,
                        });
                    }
                    src.flows.push(FlowRow {
                        flow_id,
                        ts_start: ts,
                        ts_end: ts + dur,
                        src_ip: s,
                        src_port: sport,
                        dst_ip: dst,
                        dst_port: dport,
                        proto,
                        app_proto: app.map(str::to_string),
                        bytes_up: up,
                        bytes_down: down,
                        pkts_up: pkts / 2,
                        pkts_down: pkts - pkts / 2,
                        first_frame: first,
                        last_frame: frame,
                    });
                }
                Item::Dns {
                    ts,
                    client,
                    query,
                    qtype,
                    rcode,
                    answers,
                } => {
                    let first = frame + 1;
                    frame += 2;
                    let trans_id = (flow_id & 0xffff) as u16;
                    let up = 12 + query.len() as u64 + 5;
                    let down = up + answers.iter().map(|a| a.len() as u64 + 12).sum::<u64>();
                    src.dns.push(DnsRow {
                        ts,
                        flow_id,
                        frame_no: first,
                        trans_id,
                        is_response: false,
                        query: query.clone(),
                        qtype: qtype.into(),
                        rcode: None,
                        answers: vec![],
                        ttl: None,
                    });
                    src.dns.push(DnsRow {
                        ts: ts + 20_000,
                        flow_id,
                        frame_no: first + 1,
                        trans_id,
                        is_response: true,
                        query,
                        qtype: qtype.into(),
                        rcode: Some(rcode.into()),
                        answers,
                        ttl: Some(300),
                    });
                    src.flows.push(FlowRow {
                        flow_id,
                        ts_start: ts,
                        ts_end: ts + 20_000,
                        src_ip: client,
                        src_port: sport,
                        dst_ip: RESOLVER.into(),
                        dst_port: 53,
                        proto: 17,
                        app_proto: Some("dns".into()),
                        bytes_up: up,
                        bytes_down: down,
                        pkts_up: 1,
                        pkts_down: 1,
                        first_frame: first,
                        last_frame: first + 1,
                    });
                }
            }
        }
        src.dns.sort_by_key(|d| (d.ts, d.frame_no));
        src.tls.sort_by_key(|d| (d.ts, d.frame_no));
        src.http.sort_by_key(|d| (d.ts, d.frame_no));
        if let Some(c) = src.capture.as_mut() {
            c.frame_count = frame;
        }
        src
    }
}

/// Deterministic public IP for a name (outside allowlisted ranges).
pub fn ip_for(name: &str) -> String {
    let mut h: u64 = 1469598103934665603;
    for b in name.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(1099511628211);
    }
    let a = [23u8, 34, 52, 104, 142, 151, 172, 199][(h % 8) as usize];
    let b = ((h >> 8) % 250) as u8;
    let b = if a == 172 { b | 0x40 } else { b }; // stay out of 172.16/12
    format!("{a}.{b}.{}.{}", (h >> 16) % 250 + 1, (h >> 24) % 250 + 1)
}

const SITES: &[&str] = &[
    "www.google.com",
    "mail.google.com",
    "www.youtube.com",
    "github.com",
    "api.github.com",
    "en.wikipedia.org",
    "outlook.office365.com",
    "teams.microsoft.com",
    "www.bbc.co.uk",
    "www.nytimes.com",
    "app.slack.com",
    "zoom.us",
    "www.amazon.com",
    "www.reddit.com",
    "stackoverflow.com",
    "docs.python.org",
    "www.linkedin.com",
    "news.ycombinator.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "www.atlassian.com",
    "jira.example-corp.com",
    "confluence.example-corp.com",
    "www.salesforce.com",
    "login.microsoftonline.com",
    "www.dropbox.com",
    "drive.google.com",
    "www.theguardian.com",
    "www.espn.com",
    "weather.com",
];

pub struct Office {
    pub hosts: Vec<String>,
    pub hours: f64,
}

/// Normal office browsing + legitimate periodic background traffic for each
/// host in `hosts`. Host index 3 (when present) also runs a single-host
/// periodic backup agent: a realistic, not-allowlisted false positive.
pub fn office(sy: &mut Synth, o: &Office) {
    let end = T0 + (o.hours * 3600.0) as i64 * S;
    let n_hosts = o.hosts.len();
    let chat_hosts = (n_hosts * 6).div_ceil(10);
    for (hi, h) in o.hosts.iter().enumerate() {
        let h = h.as_str();
        let start = T0 + sy.rng.range(0.0, 900.0) as i64 * S;
        // Chrome start-up probes: 3 random single-label names → NXDOMAIN.
        for k in 0..3 {
            let n = sy.rng.int(7, 15) as usize;
            let name = sy.rng.alnum(n, LOWER);
            sy.dns(start + k * 50_000, h, &name, "A", "NXDOMAIN", vec![]);
        }
        // Browsing.
        let mut t = start;
        while t < end {
            t += (sy.rng.exp(70.0) * S as f64) as i64;
            let hour = (t - T0) as f64 / 3600e6;
            if (3.0..3.75).contains(&hour) && sy.rng.chance(0.9) {
                continue; // lunch
            }
            let site = *sy.rng.pick(SITES);
            let ip = ip_for(site);
            sy.resolve(t, h, site, &ip);
            for _ in 0..sy.rng.int(1, 6) {
                let dt = (sy.rng.range(0.05, 20.0) * S as f64) as i64;
                let up = sy.rng.lognorm(1500.0, 1.2);
                let down = sy.rng.lognorm(40_000.0, 2.0);
                sy.tls(t + dt, h, &ip, site, up, down);
            }
            // CDN / third-party fetches.
            for _ in 0..sy.rng.int(0, 4) {
                let dt = (sy.rng.range(0.1, 5.0) * S as f64) as i64;
                let (name, ipn) = match sy.rng.int(0, 5) {
                    0 => {
                        let n = format!(
                            "d{}.cloudfront.net",
                            sy.rng.alnum(13, b"0123456789abcdefghijklmnopqrstuvwxyz")
                        );
                        (n.clone(), ip_for(&n))
                    }
                    1 => {
                        let n = format!("e{}.dscx.akamaiedge.net", sy.rng.int(1000, 9999));
                        (n.clone(), ip_for(&n))
                    }
                    2 => {
                        let n = format!(
                            "rr{}---sn-{}.googlevideo.com",
                            sy.rng.int(1, 8),
                            sy.rng.alnum(8, b"abcdefghijklmnopqrstuvwxyz0123456789-")
                        );
                        (n.clone(), ip_for(&n))
                    }
                    3 => {
                        // Ad-tech sync with random hex subdomains, on every host.
                        let n = format!("{}.sync.adsrv-sync.com", sy.rng.alnum(16, HEX));
                        (n, ip_for("adsrv-sync.com"))
                    }
                    _ => {
                        let n = format!("static{}.cdn-assets.net", sy.rng.int(1, 9));
                        (n.clone(), ip_for(&n))
                    }
                };
                sy.resolve(t + dt, h, &name, &ipn);
                let down = sy.rng.lognorm(20_000.0, 1.5);
                sy.tls(t + dt + 30_000, h, &ipn, &name, 800, down);
            }
            // Occasional typo / dead link.
            if sy.rng.chance(0.01) {
                let n = format!("{}.com", sy.rng.alnum(9, LOWER));
                sy.dns(t, h, &n, "A", "NXDOMAIN", vec![]);
            }
            // Search-suffix retry for a short name.
            if sy.rng.chance(0.02) {
                sy.dns(
                    t,
                    h,
                    "intranet.corp.example-corp.com",
                    "A",
                    "NXDOMAIN",
                    vec![],
                );
                sy.dns(t, h, "wpad.example-corp.com", "A", "NXDOMAIN", vec![]);
            }
        }
        // NTP every 1024 s (ignored port).
        let ntp = format!("162.159.200.{}", 1 + hi % 3);
        let mut t = start;
        while t < end {
            sy.flow(t, h, &ntp, 123, 17, Some("ntp"), 48, 48);
            t += 1024 * S;
        }
        // Windows Update check: hourly ±10%, allowlisted (CIDR + name).
        let mut t = start + 120 * S;
        while t < end {
            sy.resolve(t, h, "fe2.update.microsoft.com", "13.107.4.50");
            let down = sy.rng.lognorm(5000.0, 0.3);
            sy.tls(
                t + 40_000,
                h,
                "13.107.4.50",
                "fe2.update.microsoft.com",
                1800,
                down,
            );
            t += (3600.0 * sy.rng.range(0.9, 1.1)) as i64 * S;
        }
        // Windows telemetry every 900 s ±5% (known-good suffix + fleet-wide).
        let mut t = start + 60 * S;
        while t < end {
            sy.resolve(t, h, "v10.events.data.microsoft.com", "20.42.65.92");
            let up = sy.rng.lognorm(3000.0, 0.2);
            sy.tls(
                t + 40_000,
                h,
                "20.42.65.92",
                "v10.events.data.microsoft.com",
                up,
                700,
            );
            t += (900.0 * sy.rng.range(0.95, 1.05)) as i64 * S;
        }
        // Vendor telemetry every 1800 s ±2% on all hosts (fleet-wide only).
        let mut t = start + 300 * S;
        while t < end {
            sy.resolve(t, h, "telemetry.vendorapp.io", "34.120.5.6");
            sy.tls(
                t + 40_000,
                h,
                "34.120.5.6",
                "telemetry.vendorapp.io",
                900,
                400,
            );
            t += (1800.0 * sy.rng.range(0.98, 1.02)) as i64 * S;
        }
        // Chat presence polling every 30 s ±10% on 60% of hosts.
        if hi < chat_hosts {
            let mut t = start + 10 * S;
            while t < end {
                sy.resolve(t, h, "presence.chatapp.com", "35.186.224.25");
                sy.tls(
                    t + 30_000,
                    h,
                    "35.186.224.25",
                    "presence.chatapp.com",
                    350,
                    200,
                );
                t += (30.0 * sy.rng.range(0.9, 1.1)) as i64 * S;
            }
        }
        // Single-host backup agent every 600 s ±1% (realistic FP).
        if hi == 3 {
            let mut t = start + 30 * S;
            while t < end {
                sy.resolve(t, h, "api.backupco.net", "52.10.20.30");
                let up = sy.rng.lognorm(20_000.0, 0.8);
                sy.tls(t + 40_000, h, "52.10.20.30", "api.backupco.net", up, 1500);
                t += (600.0 * sy.rng.range(0.99, 1.01)) as i64 * S;
            }
        }
        // Internal file server (internal dst) every 300 s.
        let mut t = start;
        while t < end {
            sy.flow(t, h, "10.1.0.2", 445, 6, Some("smb"), 2000, 8000);
            t += 300 * S;
        }
        // mDNS / SSDP multicast.
        let mut t = start;
        while t < end {
            sy.flow(t, h, "224.0.0.251", 5353, 17, None, 80, 0);
            sy.flow(t + S, h, "239.255.255.250", 1900, 17, None, 120, 0);
            t += 120 * S;
        }
        // A handful of SPF/DMARC TXT lookups.
        if hi == 1 {
            for k in 0..5 {
                sy.dns(
                    start + k * 600 * S,
                    h,
                    "_dmarc.example.org",
                    "TXT",
                    "NOERROR",
                    vec!["v=DMARC1; p=none".into()],
                );
            }
        }
        // Reverse-DNS sweep from a monitoring host (ignored suffix: arpa).
        if hi == 0 {
            for k in 0..300 {
                let q = format!("{}.{}.1.10.in-addr.arpa", k % 250, k / 250);
                sy.dns(start + k * S, h, &q, "PTR", "NXDOMAIN", vec![]);
            }
        }
    }
}

pub fn office_hosts(n: usize, base: u8) -> Vec<String> {
    (0..n)
        .map(|i| format!("10.1.0.{}", base as usize + i))
        .collect()
}

/// 60 s ±3 % TLS beacon.
pub fn beacon60(sy: &mut Synth, host: &str, hours: f64) {
    let end = T0 + (hours * 3600.0) as i64 * S;
    let mut t = T0 + 200 * S;
    let mut last_dns = i64::MIN;
    while t < end {
        if t.saturating_sub(last_dns) > 3600 * S {
            sy.dns(
                t,
                host,
                "cdn-update.top",
                "A",
                "NOERROR",
                vec!["185.199.110.77".into()],
            );
            last_dns = t;
        }
        let up = 300 + sy.rng.int(0, 40);
        let down = 900 + sy.rng.int(0, 100);
        sy.tls(
            t + 30_000,
            host,
            "185.199.110.77",
            "cdn-update.top",
            up,
            down,
        );
        t += (60.0 * sy.rng.range(0.97, 1.03) * S as f64) as i64;
    }
}

/// 300 s ±25 % HTTP beacon with missed and doubled check-ins and variable
/// task sizes.
pub fn jittered(sy: &mut Synth, host: &str, hours: f64) {
    let end = T0 + (hours * 3600.0) as i64 * S;
    let mut t = T0 + 500 * S;
    while t < end {
        if !sy.rng.chance(0.04) {
            sy.resolve(t, host, "update-check.info", "45.77.12.34");
            let up = sy.rng.int(400, 700);
            let down = if sy.rng.chance(0.1) {
                sy.rng.int(5_000, 60_000)
            } else {
                sy.rng.int(200, 600)
            };
            sy.http(
                t + 30_000,
                host,
                "45.77.12.34",
                "update-check.info",
                up,
                down,
            );
            if sy.rng.chance(0.05) {
                sy.http(
                    t + 330_000,
                    host,
                    "45.77.12.34",
                    "update-check.info",
                    up,
                    300,
                );
            }
        }
        t += (300.0 * sy.rng.range(0.75, 1.25) * S as f64) as i64;
    }
}

/// DNS tunnel: base32 chunks under t.exfil-dns.xyz, TXT-heavy, in sessions.
pub fn dns_tunnel(sy: &mut Synth, host: &str, hours: f64) {
    let sessions = (hours.max(1.0) as i64).min(4);
    let mut seq = 0u64;
    for s in 0..sessions {
        let mut t = T0 + (900 + s * 3000) * S;
        let end = t + 600 * S;
        while t < end {
            seq += 1;
            let n = sy.rng.int(40, 60) as usize;
            let chunk = sy.rng.alnum(n, B32);
            let q = format!("{chunk}.{seq}.t.exfil-dns.xyz");
            if sy.rng.chance(0.7) {
                let n = sy.rng.int(100, 200) as usize;
                let ans = sy.rng.alnum(n, B32);
                sy.dns(t, host, &q, "TXT", "NOERROR", vec![ans]);
            } else {
                sy.dns(t, host, &q, "A", "NOERROR", vec!["198.51.100.7".into()]);
            }
            t += (sy.rng.range(0.5, 2.5) * S as f64) as i64;
        }
    }
}

/// DGA: every 20 min a burst of 25 random names → NXDOMAIN within 30 s;
/// one name resolves.
pub fn dga(sy: &mut Synth, host: &str, hours: f64) {
    let end = T0 + (hours * 3600.0) as i64 * S;
    let tlds = ["com", "net", "top", "info", "biz"];
    let mut t = T0 + 400 * S;
    while t < end {
        for k in 0..25 {
            let n = sy.rng.int(8, 16) as usize;
            let name = format!("{}.{}", sy.rng.alnum(n, LOWER), sy.rng.pick(&tlds));
            let ts = t + (k as f64 * 1.2 * S as f64) as i64;
            sy.dns(ts, host, &name, "A", "NXDOMAIN", vec![]);
        }
        let n = sy.rng.int(8, 16) as usize;
        let live = format!("{}.top", sy.rng.alnum(n, LOWER));
        sy.dns(
            t + 31 * S,
            host,
            &live,
            "A",
            "NOERROR",
            vec!["91.200.1.2".into()],
        );
        sy.tls(t + 32 * S, host, "91.200.1.2", &live, 600, 3000);
        t += 1200 * S;
    }
}

pub struct Scenario {
    pub name: &'static str,
    pub src: MemorySource,
    pub c2_hosts: Vec<String>,
}

pub const C2_BEACON: &str = "10.1.0.23";
pub const C2_JITTER: &str = "10.1.0.31";
pub const C2_TUNNEL: &str = "10.1.0.17";
pub const C2_DGA: &str = "10.1.0.12";

fn with_attacker(
    seed: u64,
    name: &'static str,
    attacker: &str,
    hours: f64,
    f: fn(&mut Synth, &str, f64),
) -> Scenario {
    let mut sy = Synth::new(seed);
    let mut hosts = office_hosts(9, 40);
    hosts.push(attacker.to_string());
    office(&mut sy, &Office { hosts, hours });
    f(&mut sy, attacker, hours);
    Scenario {
        name,
        src: sy.build(),
        c2_hosts: vec![attacker.to_string()],
    }
}

pub fn benign(seed: u64) -> Scenario {
    let mut sy = Synth::new(seed);
    office(
        &mut sy,
        &Office {
            hosts: office_hosts(20, 40),
            hours: 8.0,
        },
    );
    Scenario {
        name: "benign",
        src: sy.build(),
        c2_hosts: vec![],
    }
}

pub fn beacon_scenario(seed: u64) -> Scenario {
    with_attacker(seed, "beacon60", C2_BEACON, 2.0, beacon60)
}

pub fn jitter_scenario(seed: u64) -> Scenario {
    with_attacker(seed, "jitter300", C2_JITTER, 5.0, jittered)
}

pub fn tunnel_scenario(seed: u64) -> Scenario {
    with_attacker(seed, "dns_tunnel", C2_TUNNEL, 2.0, dns_tunnel)
}

pub fn dga_scenario(seed: u64) -> Scenario {
    with_attacker(seed, "dga", C2_DGA, 2.0, dga)
}

pub fn mix_scenario(seed: u64) -> Scenario {
    let mut sy = Synth::new(seed);
    let mut hosts = office_hosts(20, 40);
    for h in [C2_BEACON, C2_JITTER, C2_TUNNEL, C2_DGA] {
        hosts.push(h.to_string());
    }
    let hours = 5.0;
    office(&mut sy, &Office { hosts, hours });
    beacon60(&mut sy, C2_BEACON, hours);
    jittered(&mut sy, C2_JITTER, hours);
    dns_tunnel(&mut sy, C2_TUNNEL, hours);
    dga(&mut sy, C2_DGA, hours);
    Scenario {
        name: "mix",
        src: sy.build(),
        c2_hosts: [C2_BEACON, C2_JITTER, C2_TUNNEL, C2_DGA]
            .map(String::from)
            .to_vec(),
    }
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn repo_rules() -> RuleSet {
    load_rules(&repo_root().join("rules")).expect("repo rules load")
}

pub fn repo_allowlist() -> Allowlist {
    let text =
        std::fs::read_to_string(repo_root().join("rules/allowlist.yaml")).expect("allowlist");
    Allowlist::from_yaml(&text).expect("allowlist parses")
}

/// 1-based rank of `host` in `findings`, if present.
pub fn rank(findings: &[Finding], host: &str) -> Option<usize> {
    findings
        .iter()
        .position(|f| f.entity == host)
        .map(|i| i + 1)
}

/// False positives among the top 10 (entities not in `c2`).
pub fn top10_fp(findings: &[Finding], c2: &[String]) -> usize {
    findings
        .iter()
        .take(10)
        .filter(|f| !c2.contains(&f.entity))
        .count()
}

pub fn summary(findings: &[Finding]) -> String {
    let mut s = String::new();
    for (i, f) in findings.iter().enumerate().take(12) {
        s.push_str(&format!(
            "#{:<2} {:>5.1} {:<12} {}\n",
            i + 1,
            f.score,
            f.entity,
            f.title
        ));
        for r in &f.reasons {
            s.push_str(&format!(
                "      {:>5.1} {:<20} {}\n",
                r.weight, r.rule_id, r.explanation
            ));
        }
    }
    s
}

/// Assert every finding is well-formed and its evidence resolves.
pub fn assert_evidence_valid(src: &MemorySource, findings: &[Finding]) {
    let flows: HashMap<u64, (u64, u64)> = src
        .flows
        .iter()
        .map(|f| (f.flow_id, (f.first_frame, f.last_frame)))
        .collect();
    let mut frames: BTreeSet<u64> = BTreeSet::new();
    for d in &src.dns {
        frames.insert(d.frame_no);
    }
    for f in &src.flows {
        frames.insert(f.first_frame);
    }
    for f in findings {
        assert!(!f.reasons.is_empty(), "finding {} has no reasons", f.entity);
        assert_eq!(f.entity_type, "host");
        assert_eq!(
            f.finding_id,
            walleye_detect::finding_id(&f.detector, "host", &f.entity)
        );
        assert!(f.score > 0.0 && f.score <= 100.0, "score {}", f.score);
        let sum: f64 = f.reasons.iter().map(|r| r.weight).sum();
        assert!(
            (f.score - sum.min(100.0)).abs() < 0.11,
            "score {} != min(100, {sum})",
            f.score
        );
        assert!(f.ts_first <= f.ts_last);
        for w in f.reasons.windows(2) {
            assert!(w[0].weight >= w[1].weight, "reasons not sorted by weight");
        }
        assert_eq!(f.attack_technique, f.reasons[0].attack_technique);
        for r in &f.reasons {
            let e = &r.evidence;
            assert!(
                !e.is_empty(),
                "empty evidence on {} {}",
                f.entity,
                r.rule_id
            );
            assert!(!e.flow_ids.is_empty() && !e.frame_nos.is_empty());
            assert!(e.flow_ids.len() <= walleye_core::findings::EVIDENCE_CAP);
            assert!(e.frame_nos.len() <= walleye_core::findings::EVIDENCE_CAP);
            assert!(e.total >= e.frame_nos.len() as u64);
            assert_eq!(e.truncated, e.total > e.frame_nos.len() as u64);
            for id in &e.flow_ids {
                assert!(flows.contains_key(id), "flow {id} does not exist");
            }
            for fr in &e.frame_nos {
                assert!(frames.contains(fr), "frame {fr} is not a flow/dns frame");
            }
            assert!(!r.explanation.is_empty());
            assert!(
                !has_placeholder(&r.explanation),
                "unrendered placeholder in {:?}",
                r.explanation
            );
        }
        assert!(
            !has_placeholder(&f.title),
            "unrendered placeholder in title {:?}",
            f.title
        );
    }
}

/// True if `s` still contains a `{name}` template placeholder.
pub fn has_placeholder(s: &str) -> bool {
    let mut rest = s;
    while let Some(i) = rest.find('{') {
        let after = &rest[i + 1..];
        if let Some(j) = after.find('}') {
            let key = &after[..j];
            if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return true;
            }
        }
        rest = after;
    }
    false
}
