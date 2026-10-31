//! Scenarios: a small office network (hosts, resolver, intranet server,
//! gateway) whose hosts run benign behaviours, plus the injected malicious
//! behaviours that each scenario labels.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::dns::{self, RData, Rr};
use crate::flow::{Chunk, Close, Flow, Msg, TcpFlow, TcpSpec, UdpFlow};
use crate::http::{self, Request, Response};
use crate::net::{Hop, Mac};
use crate::pcap::PcapWriter;
use crate::rng::Rng;
use crate::sim::Sim;
use crate::tls::{self, Profile};
use crate::x509::{self, CertSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Office,
    Beacon,
    DnsTunnel,
    Dga,
    Scale,
}

impl Scenario {
    pub fn parse(s: &str) -> Option<Scenario> {
        Some(match s {
            "office" => Scenario::Office,
            "beacon" => Scenario::Beacon,
            "dns_tunnel" => Scenario::DnsTunnel,
            "dga" => Scenario::Dga,
            "scale" => Scenario::Scale,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Scenario::Office => "office",
            Scenario::Beacon => "beacon",
            Scenario::DnsTunnel => "dns_tunnel",
            Scenario::Dga => "dga",
            Scenario::Scale => "scale",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub scenario: Scenario,
    pub seed: u64,
    /// Target size for `scale`, in GiB (2^30 bytes).
    pub size_gb: f64,
    /// Add IPv6 traffic (dual-stack macOS hosts, AAAA answers).
    pub ipv6: bool,
    /// Capture length for the small scenarios.
    pub duration_min: u64,
}

impl Options {
    pub fn new(scenario: Scenario, seed: u64) -> Options {
        Options {
            scenario,
            seed,
            size_gb: 10.0,
            ipv6: false,
            duration_min: 120,
        }
    }
}

/// Ground truth, docs/CONTRACTS.md §9.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Labels {
    pub scenario: String,
    pub source: String,
    pub sha256: String,
    pub c2_hosts: Vec<String>,
    pub bad_destinations: Vec<String>,
    pub benign: bool,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub bytes: u64,
    pub packets: u64,
    pub sha256: String,
    pub labels: Labels,
}

// ---------------------------------------------------------------------------
// Static world data

/// Capture day: Tuesday 2026-03-10, UTC.
fn day_start_us() -> i64 {
    http::days_from_civil(2026, 3, 10) * 86_400 * 1_000_000
}

const S: i64 = 1_000_000;
const MS: u64 = 1_000;

const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const INTRANET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const GW_MAC: Mac = [0x00, 0x1b, 0x54, 0x0a, 0x00, 0x01];
const RESOLVER_MAC: Mac = [0x00, 0x15, 0x5d, 0x0a, 0x00, 0x02];
const INTRANET_MAC: Mac = [0x00, 0x15, 0x5d, 0x0a, 0x00, 0x05];

pub const BEACON_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 23);
pub const BEACON_C2_IP: Ipv4Addr = Ipv4Addr::new(185, 199, 110, 77);
pub const BEACON_C2_NAME: &str = "cdn-update.top";
pub const TUNNEL_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 17);
pub const TUNNEL_ZONE: &str = "t.exfil-dns.xyz";
pub const DGA_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 12);
/// TEST-NET-3, so the label never names a real third party.
pub const DGA_C2_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 45);
pub const WSUS_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 15);

struct SiteDef {
    name: &'static str,
    cnames: &'static [&'static str],
    net: [u8; 2],
    ttl: u32,
    /// Browse popularity (0 = not a browse target).
    weight: u32,
    tls12: bool,
    subs: &'static [&'static str],
}

const fn site(
    name: &'static str,
    cnames: &'static [&'static str],
    net: [u8; 2],
    ttl: u32,
    weight: u32,
    subs: &'static [&'static str],
) -> SiteDef {
    SiteDef {
        name,
        cnames,
        net,
        ttl,
        weight,
        tls12: false,
        subs,
    }
}

const fn site12(name: &'static str, net: [u8; 2], ttl: u32, weight: u32) -> SiteDef {
    SiteDef {
        name,
        cnames: &[],
        net,
        ttl,
        weight,
        tls12: true,
        subs: &[],
    }
}

#[rustfmt::skip]
const SITES: &[SiteDef] = &[
    site("www.google.com", &[], [142, 250], 300, 60, &["www.gstatic.com", "apis.google.com", "ogs.google.com"]),
    site("www.gstatic.com", &[], [142, 250], 300, 0, &[]),
    site("apis.google.com", &["plus.l.google.com"], [142, 250], 300, 0, &[]),
    site("ogs.google.com", &["www3.l.google.com"], [142, 250], 300, 0, &[]),
    site("mail.google.com", &["googlemail.l.google.com"], [142, 250], 300, 25, &["www.gstatic.com", "lh3.googleusercontent.com"]),
    site("lh3.googleusercontent.com", &["googlehosted.l.googleusercontent.com"], [142, 250], 300, 0, &[]),
    site("fonts.googleapis.com", &["googleapis.l.google.com"], [142, 250], 300, 0, &[]),
    site("fonts.gstatic.com", &["gstaticadssl.l.google.com"], [142, 250], 300, 0, &[]),
    site("outlook.office365.com", &["outlook.ms-acdc.office.com"], [52, 96], 30, 40, &["res.cdn.office.net"]),
    site("res.cdn.office.net", &["res-1.cdn.office.net", "res-1.cdn.office.net-c.edgekey.net", "e40491.dscg.akamaiedge.net"], [23, 52], 120, 0, &[]),
    site("www.office.com", &["www.office.com.edgekey.net", "e8652.dscx.akamaiedge.net"], [23, 52], 60, 20, &["res.cdn.office.net", "login.microsoftonline.com"]),
    site("login.microsoftonline.com", &["login.mso.msidentity.com", "ak.privatelink.msidentity.com", "www.tm.ak.prd.aadg.akadns.net"], [20, 190], 300, 10, &[]),
    site("teams.microsoft.com", &["teams.microsoft.com-c-3.edgekey.net", "e14986.dscb.akamaiedge.net"], [23, 58], 60, 35, &["statics.teams.cdn.office.net", "login.microsoftonline.com"]),
    site("statics.teams.cdn.office.net", &["statics.teams.cdn.office.net.edgesuite.net", "a1844.dscd.akamai.net"], [23, 58], 300, 0, &[]),
    site("www.microsoft.com", &["www.microsoft.com-c-3.edgekey.net", "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net", "e13678.dscb.akamaiedge.net"], [23, 45], 300, 8, &[]),
    site("github.com", &[], [140, 82], 60, 15, &["github.githubassets.com", "avatars.githubusercontent.com"]),
    site("github.githubassets.com", &[], [140, 82], 300, 0, &[]),
    site("avatars.githubusercontent.com", &[], [140, 82], 300, 0, &[]),
    site("app.slack.com", &["app.slack.com.cdn.cloudflare.net"], [104, 18], 60, 25, &["a.slack-edge.com", "edgeapi.slack.com"]),
    site("a.slack-edge.com", &["a.slack-edge.com.cdn.cloudflare.net"], [104, 18], 300, 0, &[]),
    site("edgeapi.slack.com", &[], [3, 120], 60, 0, &[]),
    site("en.wikipedia.org", &["dyna.wikimedia.org"], [208, 80], 600, 10, &["upload.wikimedia.org"]),
    site("upload.wikimedia.org", &["upload.eqiad.wikimedia.org"], [208, 80], 600, 0, &[]),
    site("www.bbc.co.uk", &["www.bbc.co.uk.pri.bbc.co.uk", "uk.www.bbc.co.uk.pri.bbc.co.uk"], [151, 101], 300, 8, &["static.files.bbci.co.uk", "ichef.bbci.co.uk"]),
    site("static.files.bbci.co.uk", &["static.files.bbci.co.uk.edgekey.net", "e3891.dscx.akamaiedge.net"], [23, 62], 300, 0, &[]),
    site("ichef.bbci.co.uk", &["ichef.bbci.co.uk.pri.bbci.co.uk"], [151, 101], 300, 0, &[]),
    site("www.nytimes.com", &["nytimes.map.fastly.net"], [151, 101], 60, 6, &["static01.nyt.com", "d1oxyq6jnf9m1b.cloudfront.net"]),
    site("static01.nyt.com", &["nytimes.map.fastly.net"], [151, 101], 60, 0, &[]),
    site("d1oxyq6jnf9m1b.cloudfront.net", &[], [13, 224], 60, 0, &[]),
    site("www.amazon.com", &["tp.47cf2c8c9-frontier.amazon.com", "d3ag4hukkh62yn.cloudfront.net"], [18, 160], 60, 6, &["m.media-amazon.com"]),
    site("m.media-amazon.com", &["m.media-amazon.com.cdn.cloudflare.net"], [18, 160], 60, 0, &[]),
    site("www.linkedin.com", &["www-linkedin-com.l-0005.l-msedge.net", "l-0005.l-msedge.net"], [13, 107], 300, 10, &["static.licdn.com", "media.licdn.com"]),
    site("static.licdn.com", &["static.licdn.com.edgekey.net", "e14024.dscx.akamaiedge.net"], [23, 33], 300, 0, &[]),
    site("media.licdn.com", &["media.licdn.com.edgekey.net", "e14024.dscx.akamaiedge.net"], [23, 33], 300, 0, &[]),
    site("zoom.us", &[], [170, 114], 60, 8, &["st1.zoom.us"]),
    site("st1.zoom.us", &["st1.zoom.us.cdn.cloudflare.net"], [104, 16], 300, 0, &[]),
    site("www.youtube.com", &["youtube-ui.l.google.com"], [142, 250], 300, 8, &["i.ytimg.com", "yt3.ggpht.com"]),
    site("i.ytimg.com", &["ytimg.l.google.com"], [142, 250], 300, 0, &[]),
    site("yt3.ggpht.com", &["photos-ugc.l.googleusercontent.com"], [142, 250], 300, 0, &[]),
    site("rr3---sn-4g5e6nzz.googlevideo.com", &["rr3.sn-4g5e6nzz.googlevideo.com"], [173, 194], 1800, 0, &[]),
    site("docs.google.com", &[], [142, 250], 300, 12, &["www.gstatic.com", "fonts.gstatic.com"]),
    site("www.dropbox.com", &["www-env.dropbox-dns.com"], [162, 125], 60, 4, &["cfl.dropboxstatic.com"]),
    site("cfl.dropboxstatic.com", &["cfl.dropboxstatic.com.cdn.cloudflare.net"], [104, 16], 300, 0, &[]),
    site("stackoverflow.com", &[], [104, 18], 300, 6, &["cdn.sstatic.net"]),
    site("cdn.sstatic.net", &["cdn.sstatic.net.cdn.cloudflare.net"], [104, 18], 300, 0, &[]),
    site("update.googleapis.com", &[], [142, 250], 300, 0, &[]),
    site("clients4.google.com", &["clients.l.google.com"], [142, 250], 300, 0, &[]),
    site("safebrowsing.googleapis.com", &[], [142, 250], 300, 0, &[]),
    site("v10.events.data.microsoft.com", &["global.asimov.events.data.trafficmanager.net", "onedsblobprdwus17.westus.cloudapp.azure.com"], [20, 42], 60, 0, &[]),
    site("settings-win.data.microsoft.com", &["atm-settingsfe-prod-geo2.trafficmanager.net", "settings-prod-wus2-2.westus2.cloudapp.azure.com"], [20, 50], 60, 0, &[]),
    site("fe2cr.update.microsoft.com", &["fe2cr.update.microsoft.com.akadns.net", "glb.cws.prod.dcat.dsp.trafficmanager.net"], [20, 72], 60, 0, &[]),
    site("gateway.icloud.com", &["gateway.fe.apple-dns.net"], [17, 248], 60, 0, &[]),
    site("configuration.apple.com", &["configuration.apple.com.akadns.net"], [17, 253], 300, 0, &[]),
    site("corpbackup.blob.core.windows.net", &["blob.bn9prdstr08a.store.core.windows.net"], [20, 60], 60, 0, &[]),
    site("outlook.office.com", &["outlook.ms-acdc.office.com"], [52, 96], 30, 0, &[]),
    site12("login.salesforce.com", [136, 146], 60, 6),
    site12("portal.payroll-vendor.example", [198, 51], 300, 3),
    // Plain-HTTP endpoints.
    site("ctldl.windowsupdate.com", &["ctldl.windowsupdate.com.delivery.microsoft.com", "wu-b-net.trafficmanager.net"], [13, 107], 300, 0, &[]),
    site("download.windowsupdate.com", &["download.windowsupdate.com.edgesuite.net", "a767.dspw65.akamai.net"], [23, 48], 300, 0, &[]),
    site("www.msftconnecttest.com", &["www.msftncsi.com.edgesuite.net", "a1961.g2.akamai.net"], [23, 215], 300, 0, &[]),
    site("crl3.digicert.com", &["crl3.digicert.com.edgekey.net"], [93, 184], 300, 0, &[]),
    site("ocsp.digicert.com", &["ocsp.edge.digicert.com"], [93, 184], 300, 0, &[]),
    site("captive.apple.com", &["captive.g.aaplimg.com"], [17, 253], 300, 0, &[]),
    site("swcdn.apple.com", &["swcdn.apple.com.akadns.net", "swcdn.g.aaplimg.com"], [17, 253], 300, 0, &[]),
    site("time.windows.com", &["twc.trafficmanager.net"], [168, 61], 300, 0, &[]),
    site("time.apple.com", &["time.g.aaplimg.com"], [17, 253], 300, 0, &[]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Windows,
    Mac,
}

struct Host {
    ip: Ipv4Addr,
    ip6: Option<Ipv6Addr>,
    mac: Mac,
    os: Os,
    browser: Profile,
    ua: &'static str,
    /// name -> (expiry, addresses). Looked up only, never iterated.
    cache: BTreeMap<String, (i64, Vec<IpAddr>)>,
    next_port: u16,
    ttl: u8,
    browse_mean_s: f64,
}

const UA_CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";
const UA_EDGE_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0";
const UA_FIREFOX_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0";
const UA_CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";
const UA_FIREFOX_MAC: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0";
const UA_CRYPTOAPI: &str = "Microsoft-CryptoAPI/10.0";
const UA_DELIVERY: &str = "Microsoft-Delivery-Optimization/10.0";
const UA_NCSI: &str = "Microsoft NCSI";
const UA_CAPTIVE: &str = "CaptiveNetworkSupport-481.100.1 wispr";
const UA_SWUPDATE: &str = "softwareupdated (unknown version) CFNetwork/1568.100.1 Darwin/24.0.0";

#[derive(Debug, Clone, Copy)]
enum Kind {
    Browse,
    Download,
    Telemetry,
    WinUpdateCheck,
    /// The strongly periodic (allowlisted) Windows Update CTL check on 10.0.0.15.
    WsusPeriodic,
    Ntp,
    MailSync,
    Ncsi,
    AppleSync,
    Bulk,
    Beacon,
    Tunnel,
    Dga,
}

/// One HTTP request: (method, uri, user agent, extra headers).
type HttpReq<'a> = (&'a str, &'a str, &'a str, Vec<(&'a str, String)>);

struct Source {
    kind: Kind,
    host: usize,
    next: i64,
    /// Per-source counter (beacon number, tunnel sequence, ...).
    n: u64,
    /// Remaining queries in the current tunnel burst.
    burst_left: u64,
}

struct World {
    rng: Rng,
    hosts: Vec<Host>,
    sites: BTreeMap<&'static str, usize>,
    sources: Vec<Source>,
    spawned: Vec<Flow>,
    ipv6: bool,
    end: i64,
    /// Leaf + intermediate per TLS 1.2 site (built once).
    chains: BTreeMap<String, Vec<Vec<u8>>>,
    dga_domain: String,
}

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn site_v4(name: &str, net: [u8; 2], k: u64) -> Ipv4Addr {
    let h = fnv(name).wrapping_add(k.wrapping_mul(0x9E37_79B9));
    Ipv4Addr::new(net[0], net[1], (h >> 8) as u8, 1 + (h % 253) as u8)
}

fn site_v6(name: &str, k: u64) -> Ipv6Addr {
    let h = fnv(name).wrapping_add(k);
    Ipv6Addr::new(
        0x2001,
        0x0db8,
        0x0400 | ((h >> 48) as u16 & 0xff),
        (h >> 32) as u16,
        0,
        0,
        0,
        (h as u16) | 1,
    )
}

/// SOA zone for a name: last two labels, or three for `co.uk`-style names.
fn zone_of(name: &str) -> String {
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    let take = if n >= 3 && labels[n - 2].len() <= 3 && labels[n - 1].len() == 2 {
        3
    } else {
        2
    };
    labels[n.saturating_sub(take)..].join(".")
}

const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

impl World {
    fn new(opts: &Options, start: i64, end: i64) -> World {
        let mut rng = Rng::new(opts.seed ^ 0x5741_4c4c_4559_4500);
        let n_hosts: u8 = if opts.scenario == Scenario::Scale {
            200
        } else {
            20
        };
        let mut hosts = Vec::new();
        for i in 0..n_hosts {
            let octet = 10 + i;
            let ip = Ipv4Addr::new(10, 0, 0, octet);
            // Hosts with a role in a scenario are Windows; others ~25% macOS.
            let special = [BEACON_HOST, TUNNEL_HOST, DGA_HOST, WSUS_HOST].contains(&ip);
            let os = if !special && rng.chance(0.25) {
                Os::Mac
            } else {
                Os::Windows
            };
            let (browser, ua) = match (os, rng.below(10)) {
                (Os::Windows, 0..=4) => (Profile::Chrome, UA_CHROME_WIN),
                (Os::Windows, 5..=7) => (Profile::Chrome, UA_EDGE_WIN),
                (Os::Windows, _) => (Profile::Firefox, UA_FIREFOX_WIN),
                (Os::Mac, 0..=6) => (Profile::Chrome, UA_CHROME_MAC),
                (Os::Mac, _) => (Profile::Firefox, UA_FIREFOX_MAC),
            };
            let mac = match os {
                Os::Windows => [0xf8, 0xbc, 0x12, 0x0a, 0x00, octet],
                Os::Mac => [0xa4, 0x83, 0xe7, 0x0a, 0x00, octet],
            };
            let ip6 = (opts.ipv6 && os == Os::Mac)
                .then(|| Ipv6Addr::new(0x2001, 0x0db8, 0x0100, 0, 0, 0, 0, u16::from(octet)));
            hosts.push(Host {
                ip,
                ip6,
                mac,
                os,
                browser,
                ua,
                cache: BTreeMap::new(),
                next_port: 49_152 + rng.below(8000) as u16,
                ttl: if os == Os::Windows { 128 } else { 64 },
                browse_mean_s: rng.uniform(60.0, 180.0),
            });
        }
        let sites = SITES.iter().enumerate().map(|(i, s)| (s.name, i)).collect();
        let dga_len = 13 + rng.below(5) as usize;
        let dga_domain = format!(
            "{}.{}",
            rng.string(LETTERS, dga_len),
            ["com", "net", "info", "biz"][rng.below(4) as usize]
        );
        let mut w = World {
            rng,
            hosts,
            sites,
            sources: Vec::new(),
            spawned: Vec::new(),
            ipv6: opts.ipv6,
            end,
            chains: BTreeMap::new(),
            dga_domain,
        };
        w.build_chains();
        w.add_sources(opts.scenario, start);
        w
    }

    fn build_chains(&mut self) {
        let ca_dn: x509::Dn<'_> = &[
            ("C", "US"),
            ("O", "Example Trust Services"),
            ("CN", "Example Public CA G2"),
        ];
        let root_dn: x509::Dn<'_> = &[
            ("C", "US"),
            ("O", "Example Trust Services"),
            ("CN", "Example Root CA"),
        ];
        let corp_dn: x509::Dn<'_> = &[("O", "Example Corp"), ("CN", "Example Corp Issuing CA 1")];
        let inter = x509::certificate(
            &CertSpec {
                subject: ca_dn,
                issuer: root_dn,
                not_before: "240101000000Z",
                not_after: "340101000000Z",
                dns_names: &[],
                is_ca: true,
            },
            &mut self.rng,
        );
        let mut names: Vec<&str> = SITES.iter().filter(|s| s.tls12).map(|s| s.name).collect();
        names.push("intranet.corp.example");
        for name in names {
            let internal = name.ends_with(".corp.example");
            let subject: Vec<(&str, &str)> = vec![("CN", name)];
            let leaf = x509::certificate(
                &CertSpec {
                    subject: &subject,
                    issuer: if internal { corp_dn } else { ca_dn },
                    not_before: "251201000000Z",
                    not_after: "261201235959Z",
                    dns_names: &[name],
                    is_ca: false,
                },
                &mut self.rng,
            );
            let chain = if internal {
                vec![leaf]
            } else {
                vec![leaf, inter.clone()]
            };
            self.chains.insert(name.to_string(), chain);
        }
        // Self-signed C2 certificate (OpenSSL defaults left in place).
        for c2 in [BEACON_C2_NAME.to_string(), self.dga_domain.clone()] {
            let subject: Vec<(&str, &str)> = vec![
                ("C", "AU"),
                ("ST", "Some-State"),
                ("O", "Internet Widgits Pty Ltd"),
                ("CN", &c2),
            ];
            let cert = x509::certificate(
                &CertSpec {
                    subject: &subject,
                    issuer: &subject,
                    not_before: "260301000000Z",
                    not_after: "270301000000Z",
                    dns_names: &[],
                    is_ca: false,
                },
                &mut self.rng,
            );
            self.chains.insert(c2, vec![cert]);
        }
    }

    fn add_sources(&mut self, scenario: Scenario, start: i64) {
        let scale = scenario == Scenario::Scale;
        for h in 0..self.hosts.len() {
            let os = self.hosts[h].os;
            let add = |w: &mut World, kind: Kind, first_s: f64| {
                let next = start + (first_s * S as f64) as i64;
                w.sources.push(Source {
                    kind,
                    host: h,
                    next,
                    n: 0,
                    burst_left: 0,
                });
            };
            let r = self.rng.uniform(0.0, 60.0);
            add(self, Kind::Browse, r);
            let r = self.rng.uniform(0.0, 3600.0);
            add(self, Kind::Download, r);
            let r = self.rng.uniform(0.0, 1024.0);
            add(self, Kind::Ntp, r);
            let r = self.rng.uniform(0.0, 120.0);
            add(self, Kind::MailSync, r);
            match os {
                Os::Windows => {
                    let r = self.rng.uniform(0.0, 300.0);
                    add(self, Kind::Telemetry, r);
                    let r = self.rng.uniform(0.0, 3600.0);
                    add(self, Kind::WinUpdateCheck, r);
                    let r = self.rng.uniform(0.0, 30.0);
                    add(self, Kind::Ncsi, r);
                }
                Os::Mac => {
                    let r = self.rng.uniform(0.0, 600.0);
                    add(self, Kind::AppleSync, r);
                }
            }
            if scale {
                let r = self.rng.uniform(0.0, 1800.0);
                add(self, Kind::Bulk, r);
            }
            let ip = self.hosts[h].ip;
            if ip == WSUS_HOST {
                add(self, Kind::WsusPeriodic, 95.0);
            }
            let malicious = |s: Scenario| scale || scenario == s;
            if ip == BEACON_HOST && malicious(Scenario::Beacon) {
                add(self, Kind::Beacon, 1020.0);
            }
            if ip == TUNNEL_HOST && malicious(Scenario::DnsTunnel) {
                add(self, Kind::Tunnel, 900.0);
            }
            if ip == DGA_HOST && malicious(Scenario::Dga) {
                add(self, Kind::Dga, 600.0);
            }
        }
    }

    // -- addressing ---------------------------------------------------------

    fn hops(&self, h: usize, dst: IpAddr) -> (Hop, Hop) {
        let host = &self.hosts[h];
        let src = match dst {
            IpAddr::V4(_) => IpAddr::V4(host.ip),
            IpAddr::V6(_) => IpAddr::V6(host.ip6.unwrap_or(Ipv6Addr::LOCALHOST)),
        };
        let (dst_mac, back_ttl) = match dst {
            IpAddr::V4(a) if a == RESOLVER => (RESOLVER_MAC, 128),
            IpAddr::V4(a) if a == INTRANET => (INTRANET_MAC, 128),
            other => {
                let s = other.to_string();
                (GW_MAC, 44 + (fnv(&s) % 14) as u8)
            }
        };
        let c2s = Hop {
            src_mac: host.mac,
            dst_mac,
            src,
            dst,
            ttl: host.ttl,
        };
        (c2s, c2s.reverse(back_ttl))
    }

    fn rtt_us(&self, dst: IpAddr) -> u64 {
        match dst {
            IpAddr::V4(a) if a.octets()[0] == 10 => 250 + fnv(&a.to_string()) % 600,
            other => (8 + fnv(&other.to_string()) % 55) * MS,
        }
    }

    fn port(&mut self, h: usize) -> u16 {
        let host = &mut self.hosts[h];
        let p = host.next_port;
        host.next_port = if p >= 65_000 { 49_152 } else { p + 1 };
        p
    }

    // -- DNS -----------------------------------------------------------------

    /// One DNS query/response exchange via the internal resolver.
    #[allow(clippy::too_many_arguments)]
    fn dns_exchange(
        &mut self,
        h: usize,
        t: i64,
        qname: &str,
        qtype: u16,
        rcode: u8,
        answers: &[Rr],
        authority: &[Rr],
        latency_us: u64,
    ) {
        let edns = self.hosts[h].os == Os::Mac;
        let id = self.rng.next_u16();
        let q = dns::query(id, qname, qtype, edns);
        let r = dns::response(id, qname, qtype, rcode, answers, authority, edns);
        let (c2s, s2c) = self.hops(h, IpAddr::V4(RESOLVER));
        let cport = self.port(h);
        let mut rng = self.rng.fork();
        let f = UdpFlow::new(
            c2s,
            s2c,
            cport,
            53,
            t,
            vec![(true, 0, q), (false, latency_us, r)],
            &mut rng,
        );
        self.spawned.push(Flow::Udp(f));
    }

    fn resolver_latency(&mut self) -> u64 {
        if self.rng.chance(0.7) {
            self.rng.range(300, 2500)
        } else {
            self.rng.range(8 * MS, 70 * MS)
        }
    }

    fn soa(zone: &str) -> Rr {
        Rr {
            name: zone.to_string(),
            ttl: 900,
            data: RData::Soa {
                mname: format!("ns1.{zone}"),
                rname: format!("hostmaster.{zone}"),
                serial: 2_026_031_001,
            },
        }
    }

    /// Resolve `name` for host `h` at `t` (A, plus AAAA on dual-stack hosts
    /// and sometimes on Windows). Returns when the answer is usable and the
    /// address to connect to. Uses and fills the host's cache.
    fn resolve(&mut self, h: usize, name: &str, t: i64) -> (i64, IpAddr) {
        if let Some((exp, addrs)) = self.hosts[h].cache.get(name) {
            if *exp > t && !addrs.is_empty() {
                let a = addrs[0];
                return (t, a);
            }
        }
        let (cnames, net, ttl) = match self.sites.get(name) {
            Some(&i) => (SITES[i].cnames, SITES[i].net, SITES[i].ttl),
            None => (&[][..], [10, 0], 300),
        };
        let mut chain: Vec<String> = vec![name.to_string()];
        chain.extend(cnames.iter().map(|s| s.to_string()));
        let last = chain.last().cloned().unwrap_or_default();
        let v4: Vec<Ipv4Addr> = if name == BEACON_C2_NAME {
            vec![BEACON_C2_IP]
        } else if name == self.dga_domain {
            vec![DGA_C2_IP]
        } else if net == [10, 0] {
            vec![INTRANET]
        } else {
            let n = 1 + self.rng.below(4);
            (0..n).map(|k| site_v4(&last, net, k)).collect()
        };
        let mut answers = Vec::new();
        for pair in chain.windows(2) {
            answers.push(Rr {
                name: pair[0].clone(),
                ttl,
                data: RData::Cname(pair[1].clone()),
            });
        }
        let cname_rrs = answers.clone();
        for ip in &v4 {
            answers.push(Rr {
                name: last.clone(),
                ttl,
                data: RData::A(*ip),
            });
        }
        let lat = self.resolver_latency();
        self.dns_exchange(h, t, name, dns::TYPE_A, 0, &answers, &[], lat);
        let mut addrs: Vec<IpAddr> = v4.iter().map(|a| IpAddr::V4(*a)).collect();

        let dual = self.hosts[h].ip6.is_some();
        let has_v6 = self.ipv6 && net[0] != 10 && fnv(name) % 3 != 0;
        if dual || (self.hosts[h].os == Os::Windows && self.rng.chance(0.3)) {
            let mut ans6 = cname_rrs;
            let mut auth = Vec::new();
            if has_v6 {
                for k in 0..2 {
                    ans6.push(Rr {
                        name: last.clone(),
                        ttl,
                        data: RData::Aaaa(site_v6(&last, k)),
                    });
                }
            } else {
                auth.push(Self::soa(&zone_of(&last)));
            }
            let lat6 = self.resolver_latency();
            let t6 = t + self.rng.range(50, 400) as i64;
            self.dns_exchange(h, t6, name, dns::TYPE_AAAA, 0, &ans6, &auth, lat6);
            if dual && has_v6 && self.rng.chance(0.6) {
                addrs.insert(0, IpAddr::V6(site_v6(&last, 0)));
            }
        }
        let exp = t + i64::from(ttl) * S;
        self.hosts[h]
            .cache
            .insert(name.to_string(), (exp, addrs.clone()));
        (t + lat as i64 + self.rng.range(100, 900) as i64, addrs[0])
    }

    // -- sessions --------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn spawn_tcp(
        &mut self,
        h: usize,
        dst: IpAddr,
        dport: u16,
        t: i64,
        msgs: Vec<Msg>,
        close: Close,
        close_delay_us: u64,
    ) {
        let (c2s, s2c) = self.hops(h, dst);
        let rtt = self.rtt_us(dst);
        let seg_gap = if matches!(dst, IpAddr::V4(a) if a.octets()[0] == 10) {
            self.rng.range(12, 30)
        } else {
            self.rng.range(25, 110)
        };
        let cport = self.port(h);
        let rng = self.rng.fork();
        let f = TcpFlow::new(
            TcpSpec {
                c2s,
                s2c,
                cport,
                sport: dport,
                start_us: t,
                rtt_us: rtt,
                seg_gap_us: seg_gap,
                msgs,
                close,
                close_delay_us,
            },
            rng,
        );
        self.spawned.push(Flow::Tcp(Box::new(f)));
    }

    /// A TLS connection: handshake for `profile`, then `exchanges` of
    /// (request bytes, response bytes, think time before the request).
    #[allow(clippy::too_many_arguments)]
    fn tls_session(
        &mut self,
        h: usize,
        sni: &str,
        dst: IpAddr,
        t: i64,
        profile: Profile,
        exchanges: &[(u64, u64, u64)],
        close: Close,
        close_delay_us: u64,
    ) {
        let rtt = self.rtt_us(dst);
        let proc = |w: &mut World| rtt + w.rng.range(300, 4000);
        let ch = tls::client_hello(profile, Some(sni), &mut self.rng);
        let mut msgs = vec![Msg::client(
            self.rng.range(100, 600),
            vec![Chunk::Bytes(ch)],
        )];
        let chain = self.chains.get(sni).cloned();
        let tls12 = profile == Profile::Implant || chain.is_some();
        let mut ex = exchanges.iter();
        if tls12 {
            let chain = chain.unwrap_or_default();
            let flight = tls::server_flight_12(0xc030, &chain, &mut self.rng);
            let d = proc(self);
            msgs.push(Msg::server(d, vec![Chunk::Bytes(flight)]));
            let cf = tls::client_finish_12(&mut self.rng);
            msgs.push(Msg::client(
                self.rng.range(400, 2000),
                vec![Chunk::Bytes(cf)],
            ));
            let sf = tls::server_finish_12(&mut self.rng);
            msgs.push(Msg::server(rtt, vec![Chunk::Bytes(sf)]));
        } else {
            let cipher = if profile == Profile::Schannel {
                0x1302
            } else {
                0x1301
            };
            let flight = tls::server_flight_13(cipher, tls::session_id_len(profile), &mut self.rng);
            let d = proc(self);
            msgs.push(Msg::server(d, vec![Chunk::Bytes(flight)]));
            let fin = tls::client_finish_13(&mut self.rng);
            if let Some(&(req, resp, _)) = ex.next() {
                msgs.push(Msg::client(
                    self.rng.range(300, 1500),
                    vec![Chunk::Bytes(fin), Chunk::TlsData(req.max(30))],
                ));
                let ticket = self.rng.range(200, 300);
                let d = proc(self);
                msgs.push(Msg::server(
                    d,
                    vec![
                        Chunk::TlsData(ticket),
                        Chunk::TlsData(ticket),
                        Chunk::TlsData(resp.max(30)),
                    ],
                ));
            } else {
                msgs.push(Msg::client(
                    self.rng.range(300, 1500),
                    vec![Chunk::Bytes(fin)],
                ));
            }
        }
        for &(req, resp, think) in ex {
            msgs.push(Msg::client(think, vec![Chunk::TlsData(req.max(30))]));
            let d = proc(self);
            msgs.push(Msg::server(d, vec![Chunk::TlsData(resp.max(30))]));
        }
        self.spawn_tcp(h, dst, 443, t, msgs, close, close_delay_us);
    }

    fn browse_exchanges(&mut self, n: u64) -> Vec<(u64, u64, u64)> {
        (0..n)
            .map(|i| {
                let req = self.rng.range(350, 1800);
                let resp = self.rng.lognormal(5000.0, 1.2, 150.0, 1_000_000.0) as u64;
                let think = if i == 0 {
                    0
                } else {
                    self.rng.range(20 * MS, 4000 * MS)
                };
                (req, resp, think)
            })
            .collect()
    }

    fn connect_tls(
        &mut self,
        h: usize,
        name: &str,
        t: i64,
        profile: Profile,
        exchanges: &[(u64, u64, u64)],
    ) {
        let (t1, dst) = self.resolve(h, name, t);
        let close = if self.rng.chance(0.8) {
            Close::ClientFin
        } else {
            Close::ServerFin
        };
        let idle = self.rng.range(200 * MS, 30_000 * MS);
        self.tls_session(h, name, dst, t1, profile, exchanges, close, idle);
    }

    /// Plain HTTP/1.1 exchange(s) on one connection.
    #[allow(clippy::too_many_arguments)]
    fn http_session(
        &mut self,
        h: usize,
        host_name: &str,
        t: i64,
        reqs: &[HttpReq<'_>],
        status: u16,
        ctype: &str,
        body: Option<Vec<u8>>,
        body_len: u64,
        resp_extra: &[(&str, String)],
    ) {
        let (t1, dst) = self.resolve(h, host_name, t);
        let rtt = self.rtt_us(dst);
        let server = if dst == IpAddr::V4(INTRANET) {
            "Microsoft-IIS/10.0"
        } else {
            "ECAcc (nyd/D17E)"
        };
        // ASN.1 payloads get real DER (parsers decode them), not random bytes.
        let body = match (body, ctype) {
            (None, "application/ocsp-response") => {
                Some(x509::ocsp_response("20260310090000Z", &mut self.rng))
            }
            (None, "application/pkix-crl") => {
                let n = self.rng.range(3, 40) as usize;
                let issuer: x509::Dn<'_> = &[
                    ("C", "US"),
                    ("O", "DigiCert Inc"),
                    ("CN", "DigiCert Global Root G2"),
                ];
                Some(x509::crl(issuer, n, &mut self.rng))
            }
            (b, _) => b,
        };
        let mut msgs = Vec::new();
        let mut at = t1;
        for (i, (method, uri, ua, extra)) in reqs.iter().enumerate() {
            let req_body = (*method == "POST"
                && extra.iter().any(|(_, v)| v == "application/ocsp-request"))
            .then(|| x509::ocsp_request(&mut self.rng));
            let head = http::request_head(&Request {
                method,
                uri,
                host: host_name,
                user_agent: ua,
                extra,
                body_len: req_body.as_ref().map_or(0, |b| b.len() as u64),
            });
            let think = if i == 0 {
                self.rng.range(100, 500)
            } else {
                self.rng.range(5 * MS, 300 * MS)
            };
            at += (think + rtt) as i64;
            let mut req_chunks = vec![Chunk::Bytes(head)];
            if let Some(b) = req_body {
                req_chunks.push(Chunk::Bytes(b));
            }
            msgs.push(Msg::client(think, req_chunks));
            let len = body.as_ref().map_or(body_len, |b| b.len() as u64);
            let head = http::response_head(&Response {
                status,
                server,
                content_type: ctype,
                body_len: len,
                date_us: at,
                extra: resp_extra,
            });
            let mut chunks = vec![Chunk::Bytes(head)];
            if status != 304 && status != 204 {
                match &body {
                    Some(b) => chunks.push(Chunk::Bytes(b.clone())),
                    None => chunks.push(Chunk::Random(body_len)),
                }
            }
            let d = rtt + self.rng.range(200, 6000);
            msgs.push(Msg::server(d, chunks));
        }
        let idle = self.rng.range(50 * MS, 15_000 * MS);
        let close = if self.rng.chance(0.7) {
            Close::ClientFin
        } else {
            Close::ServerFin
        };
        self.spawn_tcp(h, dst, 80, t1, msgs, close, idle);
    }

    // -- behaviours --------------------------------------------------------------

    fn run_source(&mut self, i: usize, t: i64) -> Option<i64> {
        let (kind, h) = (self.sources[i].kind, self.sources[i].host);
        let next = match kind {
            Kind::Browse => self.browse(h, t),
            Kind::Download => self.download(h, t),
            Kind::Telemetry => {
                let up = self.rng.range(1500, 9000);
                let down = self.rng.range(90, 400);
                self.connect_tls(
                    h,
                    "v10.events.data.microsoft.com",
                    t,
                    Profile::Schannel,
                    &[(up, down, 0)],
                );
                t + (300.0 * self.rng.uniform(0.5, 1.5) * S as f64) as i64
            }
            Kind::WinUpdateCheck => {
                let ex = [(self.rng.range(900, 2500), self.rng.range(2000, 30_000), 0)];
                self.connect_tls(h, "fe2cr.update.microsoft.com", t, Profile::Schannel, &ex);
                let ex = [(self.rng.range(600, 1200), self.rng.range(1500, 6000), 0)];
                let t2 = t + self.rng.range(S as u64, 5 * S as u64) as i64;
                self.connect_tls(
                    h,
                    "settings-win.data.microsoft.com",
                    t2,
                    Profile::Schannel,
                    &ex,
                );
                t + (3600.0 * self.rng.uniform(0.6, 1.4) * S as f64) as i64
            }
            Kind::WsusPeriodic => {
                let n = self.sources[i].n;
                self.sources[i].n += 1;
                let ims = vec![(
                    "If-Modified-Since",
                    "Tue, 03 Mar 2026 18:02:11 GMT".to_string(),
                )];
                let reqs = [
                    (
                        "GET",
                        "/msdownload/update/v3/static/trustedr/en/authrootstl.cab",
                        UA_CRYPTOAPI,
                        ims.clone(),
                    ),
                    (
                        "GET",
                        "/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab",
                        UA_CRYPTOAPI,
                        ims,
                    ),
                ];
                let (status, len) = if n == 0 { (200, 68_412) } else { (304, 0) };
                self.http_session(
                    h,
                    "ctldl.windowsupdate.com",
                    t,
                    &reqs,
                    status,
                    "application/vnd.ms-cab-compressed",
                    None,
                    len,
                    &[("Cache-Control", "public,max-age=900".to_string())],
                );
                t + (900.0 * self.rng.uniform(0.99, 1.01) * S as f64) as i64
            }
            Kind::Ntp => {
                let (server, t1) = if self.hosts[h].os == Os::Mac {
                    let (t1, a) = self.resolve(h, "time.apple.com", t);
                    (a, t1)
                } else {
                    (IpAddr::V4(RESOLVER), t)
                };
                self.ntp(h, server, t1);
                t + 1024 * S + self.rng.range(0, 50 * MS) as i64
            }
            Kind::MailSync => {
                let dur_s = self.rng.range(20 * 60, 40 * 60);
                let n = dur_s / 45;
                let mut ex = Vec::new();
                for k in 0..n {
                    let think = if k == 0 {
                        0
                    } else {
                        self.rng.range(30 * S as u64, 60 * S as u64)
                    };
                    ex.push((self.rng.range(120, 450), self.rng.range(90, 700), think));
                }
                let profile = self.hosts[h].browser;
                self.connect_tls(h, "outlook.office.com", t, profile, &ex);
                t + (n as i64 * 45 + 40) * S
            }
            Kind::Ncsi => {
                let reqs = [("GET", "/connecttest.txt", UA_NCSI, Vec::new())];
                self.http_session(
                    h,
                    "www.msftconnecttest.com",
                    t,
                    &reqs,
                    200,
                    "text/plain",
                    Some(b"Microsoft Connect Test".to_vec()),
                    0,
                    &[],
                );
                t + (self.rng.exp(3.0 * 3600.0) * S as f64) as i64
            }
            Kind::AppleSync => {
                let ex = [(self.rng.range(500, 3000), self.rng.range(300, 4000), 0)];
                self.connect_tls(h, "gateway.icloud.com", t, Profile::Apple, &ex);
                if self.sources[i].n == 0 {
                    let reqs = [("GET", "/hotspot-detect.html", UA_CAPTIVE, Vec::new())];
                    self.http_session(
                        h,
                        "captive.apple.com",
                        t + 2 * S,
                        &reqs,
                        200,
                        "text/html",
                        Some(
                            b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
                                .to_vec(),
                        ),
                        0,
                        &[],
                    );
                }
                self.sources[i].n += 1;
                t + (600.0 * self.rng.uniform(0.5, 1.5) * S as f64) as i64
            }
            Kind::Bulk => self.bulk(h, t),
            Kind::Beacon => {
                self.beacon(h, t, i);
                t + (60.0 * self.rng.uniform(0.97, 1.03) * S as f64) as i64
            }
            Kind::Tunnel => self.tunnel(h, t, i),
            Kind::Dga => {
                self.dga(h, t);
                t + (300.0 * self.rng.uniform(0.9, 1.1) * S as f64) as i64
            }
        };
        (next < self.end).then_some(next)
    }

    fn browse(&mut self, h: usize, t: i64) -> i64 {
        let weights: Vec<u32> = SITES.iter().map(|s| s.weight).collect();
        let site = &SITES[self.rng.weighted(&weights)];
        let profile = self.hosts[h].browser;
        let n = self.rng.range(1, 4);
        let ex = self.browse_exchanges(n);
        self.connect_tls(h, site.name, t, profile, &ex);
        for sub in site.subs {
            if self.rng.chance(0.6) {
                let n = self.rng.range(1, 3);
                let ex = self.browse_exchanges(n);
                let ts = t + self.rng.range(30 * MS, 400 * MS) as i64;
                self.connect_tls(h, sub, ts, profile, &ex);
            }
        }
        if self.rng.chance(0.03) {
            let ocsp_len = self.rng.range(300, 1600);
            let reqs = [(
                "POST",
                "/",
                self.hosts[h].ua,
                vec![("Content-Type", "application/ocsp-request".to_string())],
            )];
            self.http_session(
                h,
                "ocsp.digicert.com",
                t + 50 * MS as i64,
                &reqs,
                200,
                "application/ocsp-response",
                None,
                ocsp_len,
                &[],
            );
        }
        if self.rng.chance(0.02) {
            let ex = [(self.rng.range(400, 900), self.rng.range(200, 900), 0)];
            self.connect_tls(h, "safebrowsing.googleapis.com", t + S, profile, &ex);
        }
        let mean = self.hosts[h].browse_mean_s;
        t + (self.rng.exp(mean) * S as f64) as i64 + 1
    }

    fn download(&mut self, h: usize, t: i64) -> i64 {
        let os = self.hosts[h].os;
        let ua = self.hosts[h].ua;
        let choice = self.rng.below(if os == Os::Windows { 5 } else { 4 });
        match choice {
            0 | 1 => {
                let files = [
                    (
                        "/share/finance/Q1-2026-forecast.xlsx",
                        "Q1-2026-forecast.xlsx",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    ),
                    (
                        "/share/hr/employee-handbook-2026.pdf",
                        "employee-handbook-2026.pdf",
                        "application/pdf",
                    ),
                    (
                        "/share/eng/release-notes-4.2.docx",
                        "release-notes-4.2.docx",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ),
                ];
                let (uri, fname, ctype) = *self.rng.pick(&files);
                let len = self.rng.lognormal(700_000.0, 1.0, 20_000.0, 12_000_000.0) as u64;
                let reqs = [("GET", uri, ua, Vec::new())];
                self.http_session(
                    h,
                    "intranet.corp.example",
                    t,
                    &reqs,
                    200,
                    ctype,
                    None,
                    len,
                    &[(
                        "Content-Disposition",
                        format!("attachment; filename=\"{fname}\""),
                    )],
                );
            }
            2 => {
                let reqs = [("GET", "/DigiCertGlobalRootG2.crl", UA_CRYPTOAPI, Vec::new())];
                let len = self.rng.range(600, 1400);
                self.http_session(
                    h,
                    "crl3.digicert.com",
                    t,
                    &reqs,
                    200,
                    "application/pkix-crl",
                    None,
                    len,
                    &[],
                );
            }
            3 if os == Os::Mac => {
                let reqs = [(
                    "GET",
                    "/content/downloads/41/22/062-41544-A_8ZQ0K1X9T3/u8w2v6s4/MacOSUpdate.pkm",
                    UA_SWUPDATE,
                    Vec::new(),
                )];
                let len = self
                    .rng
                    .lognormal(2_000_000.0, 0.8, 100_000.0, 20_000_000.0)
                    as u64;
                self.http_session(
                    h,
                    "swcdn.apple.com",
                    t,
                    &reqs,
                    200,
                    "application/octet-stream",
                    None,
                    len,
                    &[],
                );
            }
            _ => {
                let kb = self.rng.range(10_000_000, 99_999_999);
                let uri = format!(
                    "/c/msdownload/update/software/defu/2026/03/am_delta_patch_1.425.{kb}_{:016x}.exe",
                    self.rng.next_u64()
                );
                let reqs = [("GET", uri.as_str(), UA_DELIVERY, Vec::new())];
                let len = self.rng.lognormal(1_500_000.0, 0.9, 50_000.0, 25_000_000.0) as u64;
                self.http_session(
                    h,
                    "download.windowsupdate.com",
                    t,
                    &reqs,
                    200,
                    "application/octet-stream",
                    None,
                    len,
                    &[],
                );
            }
        }
        t + (self.rng.exp(90.0 * 60.0) * S as f64) as i64 + 1
    }

    fn bulk(&mut self, h: usize, t: i64) -> i64 {
        let profile = self.hosts[h].browser;
        match self.rng.below(3) {
            0 => {
                let size = self.rng.lognormal(60e6, 0.8, 20e6, 200e6) as u64;
                // Video: one request, then the stream in 2 MB range responses.
                let mut ex = Vec::new();
                let mut left = size;
                while left > 0 {
                    let part = left.min(2_000_000);
                    ex.push((
                        self.rng.range(600, 1200),
                        part,
                        self.rng.range(MS, 300 * MS),
                    ));
                    left -= part;
                }
                self.connect_tls(h, "rr3---sn-4g5e6nzz.googlevideo.com", t, profile, &ex);
            }
            1 => {
                let size = self.rng.lognormal(80e6, 0.8, 20e6, 256e6) as u64;
                let ex = [(size, self.rng.range(300, 900), 0)];
                self.connect_tls(
                    h,
                    "corpbackup.blob.core.windows.net",
                    t,
                    Profile::Schannel,
                    &ex,
                );
            }
            _ => {
                let len = self.rng.lognormal(40e6, 0.7, 10e6, 120e6) as u64;
                let uri = format!(
                    "/d/msdownload/update/software/updt/2026/03/windows11.0-kb50{:05}-x64_{:016x}.msu",
                    self.rng.below(100_000),
                    self.rng.next_u64()
                );
                let reqs = [("GET", uri.as_str(), UA_DELIVERY, Vec::new())];
                self.http_session(
                    h,
                    "download.windowsupdate.com",
                    t,
                    &reqs,
                    200,
                    "application/octet-stream",
                    None,
                    len,
                    &[],
                );
            }
        }
        t + (self.rng.exp(60.0 * 60.0) * S as f64) as i64 + 1
    }

    fn ntp(&mut self, h: usize, server: IpAddr, t: i64) {
        let mut req = vec![0u8; 48];
        req[0] = 0x23; // LI 0, VN 4, mode 3 (client)
        req[2] = 10;
        req[3] = 0xE9;
        let ntp_secs = ((t / S) + 2_208_988_800) as u32;
        req[40..44].copy_from_slice(&ntp_secs.to_be_bytes());
        req[44..48].copy_from_slice(&self.rng.next_u32().to_be_bytes());
        let mut resp = vec![0u8; 48];
        resp[0] = 0x24; // mode 4 (server)
        resp[1] = 2; // stratum
        resp[2] = 10;
        resp[3] = 0xE9;
        resp[12..16].copy_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        resp[24..32].copy_from_slice(&req[40..48]);
        for off in [16, 32, 40] {
            resp[off..off + 4].copy_from_slice(&ntp_secs.to_be_bytes());
            resp[off + 4..off + 8].copy_from_slice(&self.rng.next_u32().to_be_bytes());
        }
        let (c2s, s2c) = self.hops(h, server);
        let lat = self.rtt_us(server);
        let mut rng = self.rng.fork();
        let f = UdpFlow::new(
            c2s,
            s2c,
            123,
            123,
            t,
            vec![(true, 0, req), (false, lat, resp)],
            &mut rng,
        );
        self.spawned.push(Flow::Udp(f));
    }

    fn beacon(&mut self, h: usize, t: i64, i: usize) {
        let n = self.sources[i].n;
        self.sources[i].n += 1;
        let (t1, dst) = self.resolve(h, BEACON_C2_NAME, t);
        let req = self.rng.range(180, 420);
        let resp = if n % 15 == 7 {
            self.rng.range(2_000, 20_000)
        } else {
            self.rng.range(90, 260)
        };
        let idle = self.rng.range(50 * MS, 300 * MS);
        self.tls_session(
            h,
            BEACON_C2_NAME,
            dst,
            t1,
            Profile::Implant,
            &[(req, resp, 0)],
            Close::ClientFin,
            idle,
        );
    }

    fn tunnel(&mut self, h: usize, t: i64, i: usize) -> i64 {
        if self.sources[i].burst_left == 0 {
            self.sources[i].burst_left = self.rng.range(100, 400);
        }
        self.sources[i].burst_left -= 1;
        let seq = self.sources[i].n;
        self.sources[i].n += 1;
        let n1 = self.rng.range(40, 63) as usize;
        let l1 = self.rng.string(BASE32, n1);
        let qname = if self.rng.chance(0.6) {
            let n2 = self.rng.range(20, 50) as usize;
            let l2 = self.rng.string(BASE32, n2);
            format!("{l1}.{l2}.{seq:04x}.{TUNNEL_ZONE}")
        } else {
            format!("{l1}.{seq:04x}.{TUNNEL_ZONE}")
        };
        let roll = self.rng.below(100);
        let (qtype, data) = if roll < 85 {
            let n = self.rng.range(1, 2);
            let strings = (0..n)
                .map(|_| {
                    let len = self.rng.range(60, 220) as usize;
                    self.rng.string(B64, len).into_bytes()
                })
                .collect();
            (dns::TYPE_TXT, RData::Txt(strings))
        } else if roll < 90 {
            let len = self.rng.range(32, 120) as usize;
            (dns::TYPE_NULL, RData::Null(self.rng.vec(len)))
        } else {
            (
                dns::TYPE_A,
                RData::A(Ipv4Addr::new(198, 51, 100, self.rng.range(1, 254) as u8)),
            )
        };
        let ans = [Rr {
            name: qname.clone(),
            ttl: 0,
            data,
        }];
        let lat = self.rng.range(20 * MS, 90 * MS);
        self.dns_exchange(h, t, &qname, qtype, 0, &ans, &[], lat);
        if self.sources[i].burst_left == 0 {
            t + (self.rng.exp(8.0 * 60.0) * S as f64) as i64 + 30 * S
        } else {
            t + self.rng.range(300 * MS, 1500 * MS) as i64
        }
    }

    fn dga(&mut self, h: usize, t: i64) {
        let n = self.rng.range(25, 60);
        let win_at = self.rng.below(n);
        let tlds = ["com", "net", "org", "info", "biz", "ru", "top", "xyz"];
        let mut at = t;
        for k in 0..n {
            at += self.rng.range(30 * MS, 250 * MS) as i64;
            if k == win_at {
                let name = self.dga_domain.clone();
                self.hosts[h].cache.remove(&name);
                let (t1, dst) = self.resolve(h, &name, at);
                let ex = [(self.rng.range(200, 600), self.rng.range(100, 1500), 0)];
                let idle = self.rng.range(20 * MS, 200 * MS);
                self.tls_session(
                    h,
                    &name,
                    dst,
                    t1 + 5 * MS as i64,
                    Profile::Implant,
                    &ex,
                    Close::ClientFin,
                    idle,
                );
                continue;
            }
            let len = self.rng.range(12, 20) as usize;
            let tld = *self.rng.pick(&tlds);
            let name = format!("{}.{tld}", self.rng.string(LETTERS, len));
            let soa = Rr {
                name: tld.to_string(),
                ttl: 900,
                data: RData::Soa {
                    mname: format!("a.nic.{tld}"),
                    rname: format!("hostmaster.nic.{tld}"),
                    serial: 1_741_600_000,
                },
            };
            let lat = self.rng.range(15 * MS, 80 * MS);
            self.dns_exchange(
                h,
                at,
                &name,
                dns::TYPE_A,
                dns::RCODE_NXDOMAIN,
                &[],
                &[soa],
                lat,
            );
        }
    }
}

fn labels_for(opts: &Options, world: &World, sha256: String) -> Labels {
    let source = format!(
        "walleye-gen seed={} scenario={}",
        opts.seed,
        opts.scenario.name()
    );
    let fp = "10.0.0.15 polls ctldl.windowsupdate.com every 900 s ±1% (allowlisted benign periodic); \
              all hosts NTP every 1024 s; Windows telemetry every 300 s ±50%";
    let (c2, bad, benign, notes): (Vec<String>, Vec<String>, bool, String) = match opts.scenario {
        Scenario::Office => (
            vec![],
            vec![],
            true,
            format!("benign office morning, 20 hosts. FP traps: {fp}"),
        ),
        Scenario::Beacon => (
            vec![BEACON_HOST.to_string()],
            vec![BEACON_C2_IP.to_string(), BEACON_C2_NAME.to_string()],
            false,
            format!(
                "office + 10.0.0.23 TLS 1.2 beacon to cdn-update.top every 60 s ±3%, self-signed cert, implant JA4. {fp}"
            ),
        ),
        Scenario::DnsTunnel => (
            vec![TUNNEL_HOST.to_string()],
            vec![TUNNEL_ZONE.to_string(), "exfil-dns.xyz".to_string()],
            false,
            format!(
                "office + 10.0.0.17 DNS tunnel via resolver 10.0.0.2: bursts of 100-400 base32 queries (85% TXT, 5% NULL, 10% A) under t.exfil-dns.xyz. {fp}"
            ),
        ),
        Scenario::Dga => (
            vec![DGA_HOST.to_string()],
            vec![world.dga_domain.clone(), DGA_C2_IP.to_string()],
            false,
            format!(
                "office + 10.0.0.12 DGA: every 300 s ±10% a burst of 25-60 random-name A queries (NXDOMAIN), one resolves to 203.0.113.45 then TLS. {fp}"
            ),
        ),
        Scenario::Scale => (
            vec![
                BEACON_HOST.to_string(),
                TUNNEL_HOST.to_string(),
                DGA_HOST.to_string(),
            ],
            vec![
                BEACON_C2_IP.to_string(),
                BEACON_C2_NAME.to_string(),
                TUNNEL_ZONE.to_string(),
                world.dga_domain.clone(),
                DGA_C2_IP.to_string(),
            ],
            false,
            format!(
                "scale: 200 hosts, bulk video/backup/update transfers, plus the beacon, DNS tunnel and DGA behaviours; target {} GiB. {fp}",
                opts.size_gb
            ),
        ),
    };
    Labels {
        scenario: opts.scenario.name().to_string(),
        source,
        sha256,
        c2_hosts: c2,
        bad_destinations: bad,
        benign,
        notes,
    }
}

/// Generate the scenario into `out` (a pcap stream).
pub fn generate<W: Write>(opts: &Options, out: W) -> io::Result<Summary> {
    let start = day_start_us()
        + if opts.scenario == Scenario::Scale {
            8 * 3600 * S
        } else {
            9 * 3600 * S
        };
    let (end, limit) = if opts.scenario == Scenario::Scale {
        let bytes = (opts.size_gb * (1u64 << 30) as f64) as u64;
        (i64::MAX, Some(bytes.max(1)))
    } else {
        (start + opts.duration_min as i64 * 60 * S, None)
    };
    let mut world = World::new(opts, start, end);
    let mut sim = Sim::new(PcapWriter::new(out)?);
    let mut queue: BinaryHeap<Reverse<(i64, usize)>> = world
        .sources
        .iter()
        .enumerate()
        .map(|(i, s)| Reverse((s.next, i)))
        .collect();
    loop {
        let until = queue.peek().map_or(i64::MAX, |r| r.0.0);
        if !sim.run_until(until, limit)? {
            break;
        }
        let Some(Reverse((t, i))) = queue.pop() else {
            break;
        };
        if let Some(next) = world.run_source(i, t) {
            queue.push(Reverse((next, i)));
        }
        for f in world.spawned.drain(..) {
            sim.add(f);
        }
    }
    let (bytes, packets, sha256) = sim.writer.finish()?;
    let labels = labels_for(opts, &world, sha256.clone());
    Ok(Summary {
        bytes,
        packets,
        sha256,
        labels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_of_handles_cctlds() {
        assert_eq!(zone_of("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(zone_of("a.b.example.com"), "example.com");
        assert_eq!(zone_of("com"), "com");
    }

    #[test]
    fn scenario_names_roundtrip() {
        for s in [
            Scenario::Office,
            Scenario::Beacon,
            Scenario::DnsTunnel,
            Scenario::Dga,
            Scenario::Scale,
        ] {
            assert_eq!(Scenario::parse(s.name()), Some(s));
        }
        assert_eq!(Scenario::parse("nope"), None);
    }
}
