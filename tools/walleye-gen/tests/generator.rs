//! Acceptance tests for walleye-gen: determinism, well-formedness checked by
//! independent parsers (pcap-parser, etherparse, a separate DNS decoder),
//! scenario content, and bounded `scale` output.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use sha2::{Digest, Sha256};
use walleye_gen::{Options, Scenario, Summary, generate};

fn gen_bytes(scenario: Scenario, seed: u64, minutes: u64) -> (Vec<u8>, Summary) {
    let mut opts = Options::new(scenario, seed);
    opts.duration_min = minutes;
    let mut out = Vec::new();
    let summary = generate(&opts, &mut out).expect("generate");
    (out, summary)
}

struct Pkt {
    ts: i64,
    data: Vec<u8>,
}

/// Read every record with pcap-parser (an implementation we did not write).
fn read_pcap(bytes: &[u8]) -> Vec<Pkt> {
    let mut reader = LegacyPcapReader::new(1 << 20, bytes).expect("pcap header");
    let mut out = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        assert_eq!(h.network.0, 1, "linktype must be Ethernet");
                        assert_eq!(h.version_major, 2);
                    }
                    PcapBlockOwned::Legacy(b) => {
                        assert_eq!(b.caplen, b.origlen);
                        assert_eq!(b.caplen as usize, b.data.len());
                        out.push(Pkt {
                            ts: i64::from(b.ts_sec) * 1_000_000 + i64::from(b.ts_usec),
                            data: b.data.to_vec(),
                        });
                    }
                    PcapBlockOwned::NG(_) => panic!("unexpected pcapng block"),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().expect("refill"),
            Err(e) => panic!("pcap parse error: {e:?}"),
        }
    }
    out
}

/// Internet checksum over `data` must fold to 0xFFFF (i.e. verify).
fn verifies(prefix_sum: u32, data: &[u8]) -> bool {
    let mut s = prefix_sum;
    for c in data.chunks(2) {
        let w = if c.len() == 2 {
            u32::from(c[0]) << 8 | u32::from(c[1])
        } else {
            u32::from(c[0]) << 8
        };
        s += w;
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    s == 0xFFFF
}

fn pseudo(src: &[u8], dst: &[u8], proto: u8, len: usize) -> u32 {
    let mut s = 0u32;
    for c in src.chunks(2).chain(dst.chunks(2)) {
        s += u32::from(c[0]) << 8 | u32::from(c[1]);
    }
    s + u32::from(proto) + (len as u32 & 0xFFFF) + (len as u32 >> 16)
}

/// Independent DNS name decoder with pointer following and loop guard.
fn dns_name(msg: &[u8], mut pos: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = msg[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | msg[pos + 1] as usize;
            assert!(ptr < pos, "pointer must point backwards");
            end.get_or_insert(pos + 2);
            pos = ptr;
            hops += 1;
            assert!(hops < 32, "pointer loop");
            continue;
        }
        assert!(len <= 63);
        labels.push(String::from_utf8(msg[pos + 1..pos + 1 + len].to_vec()).expect("ascii"));
        pos += 1 + len;
    }
    (labels.join("."), end.unwrap_or(pos))
}

#[derive(Default, Debug)]
struct DnsMsg {
    response: bool,
    rcode: u8,
    qname: String,
    qtype: u16,
    answers: usize,
    compressed: bool,
}

fn parse_dns(m: &[u8]) -> DnsMsg {
    let flags = u16::from_be_bytes([m[2], m[3]]);
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let ns = u16::from_be_bytes([m[8], m[9]]) as usize;
    let ar = u16::from_be_bytes([m[10], m[11]]) as usize;
    assert_eq!(qd, 1);
    let (qname, mut p) = dns_name(m, 12);
    let qtype = u16::from_be_bytes([m[p], m[p + 1]]);
    p += 4;
    let mut compressed = false;
    for _ in 0..an + ns + ar {
        if m[p] & 0xC0 == 0xC0 {
            compressed = true;
        }
        let (_, q) = dns_name(m, p);
        p = q;
        let rtype = u16::from_be_bytes([m[p], m[p + 1]]);
        let rdlen = u16::from_be_bytes([m[p + 8], m[p + 9]]) as usize;
        p += 10;
        if rtype == 5 {
            let (_, e) = dns_name(m, p);
            assert_eq!(e, p + rdlen, "CNAME rdlength mismatch");
        }
        p += rdlen;
    }
    assert_eq!(p, m.len(), "DNS message has trailing or missing bytes");
    DnsMsg {
        response: flags & 0x8000 != 0,
        rcode: (flags & 0xF) as u8,
        qname,
        qtype,
        answers: an,
        compressed,
    }
}

#[derive(Default)]
struct Report {
    packets: usize,
    tcp: usize,
    udp: usize,
    syns: usize,
    fins: usize,
    dns: Vec<(i64, IpAddr, DnsMsg)>,
    /// (ts, src, dst, sni-bearing ClientHello?) for TLS handshake records.
    client_hellos: Vec<(i64, IpAddr, IpAddr)>,
    certificates: usize,
    http_requests: Vec<String>,
    syn_times: BTreeMap<(IpAddr, IpAddr), Vec<i64>>,
}

/// Validate every packet and collect what the scenario tests need.
fn validate(bytes: &[u8]) -> Report {
    let pkts = read_pcap(bytes);
    let mut r = Report::default();
    let mut last_ts = i64::MIN;
    for (i, p) in pkts.iter().enumerate() {
        assert!(p.ts >= last_ts, "frame {} out of time order", i + 1);
        last_ts = p.ts;
        let s = SlicedPacket::from_ethernet(&p.data)
            .unwrap_or_else(|e| panic!("frame {}: etherparse: {e:?}", i + 1));
        let (src, dst, l4_off, proto) = match &s.net {
            Some(NetSlice::Ipv4(ip)) => {
                let h = ip.header();
                assert_eq!(
                    h.total_len() as usize,
                    p.data.len() - 14,
                    "frame {} IPv4 len",
                    i + 1
                );
                assert!(
                    verifies(0, &p.data[14..34]),
                    "frame {} IPv4 checksum",
                    i + 1
                );
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                    34,
                    h.protocol().0,
                )
            }
            Some(NetSlice::Ipv6(ip)) => {
                let h = ip.header();
                assert_eq!(
                    h.payload_length() as usize,
                    p.data.len() - 54,
                    "frame {} IPv6 len",
                    i + 1
                );
                (
                    IpAddr::V6(h.source_addr()),
                    IpAddr::V6(h.destination_addr()),
                    54,
                    h.next_header().0,
                )
            }
            other => panic!("frame {}: no IP layer: {other:?}", i + 1),
        };
        let (sb, db) = match (src, dst) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (a.octets().to_vec(), b.octets().to_vec()),
            (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets().to_vec(), b.octets().to_vec()),
            _ => unreachable!(),
        };
        let l4 = &p.data[l4_off..];
        assert!(
            verifies(pseudo(&sb, &db, proto, l4.len()), l4),
            "frame {} L4 checksum",
            i + 1
        );
        r.packets += 1;
        match &s.transport {
            Some(TransportSlice::Tcp(t)) => {
                r.tcp += 1;
                if t.syn() && !t.ack() {
                    r.syns += 1;
                    r.syn_times.entry((src, dst)).or_default().push(p.ts);
                }
                if t.fin() {
                    r.fins += 1;
                }
                let pl = t.payload();
                if pl.len() > 5 && pl[0] == 22 && pl[1] == 3 {
                    match pl[5] {
                        1 => r.client_hellos.push((p.ts, src, dst)),
                        // ServerHello; in TLS 1.2 the next handshake message
                        // (same record here) is the Certificate (type 11).
                        2 if {
                            let sh_len = (usize::from(pl[6]) << 16)
                                | (usize::from(pl[7]) << 8)
                                | usize::from(pl[8]);
                            let next = 5 + 4 + sh_len;
                            pl.len() > next && pl[next] == 11
                        } =>
                        {
                            r.certificates += 1;
                        }
                        _ => {}
                    }
                }
                if t.destination_port() == 80 && !pl.is_empty() {
                    let line = pl.split(|&b| b == b'\r').next().unwrap_or_default();
                    let line = String::from_utf8_lossy(line).to_string();
                    if line.ends_with(" HTTP/1.1") {
                        r.http_requests.push(line);
                    }
                }
            }
            Some(TransportSlice::Udp(u)) => {
                r.udp += 1;
                assert_eq!(u.length() as usize, l4.len(), "frame {} UDP len", i + 1);
                if u.source_port() == 53 || u.destination_port() == 53 {
                    r.dns.push((p.ts, src, parse_dns(u.payload())));
                }
            }
            other => panic!("frame {}: unexpected transport {other:?}", i + 1),
        }
    }
    r
}

fn sha(b: &[u8]) -> String {
    walleye_gen::pcap::hex(&Sha256::digest(b))
}

#[test]
fn same_seed_is_byte_identical_and_seed_matters() {
    let (a, sa) = gen_bytes(Scenario::Beacon, 7, 15);
    let (b, sb) = gen_bytes(Scenario::Beacon, 7, 15);
    assert_eq!(sha(&a), sha(&b));
    assert_eq!(a, b);
    assert_eq!(
        sa.sha256,
        sha(&a),
        "summary hash must be the file's SHA-256"
    );
    assert_eq!(sa.labels, sb.labels);
    let (c, _) = gen_bytes(Scenario::Beacon, 8, 15);
    assert_ne!(sha(&a), sha(&c));
}

#[test]
fn office_is_well_formed_and_realistic() {
    let (bytes, s) = gen_bytes(Scenario::Office, 1, 30);
    let r = validate(&bytes);
    assert_eq!(r.packets as u64, s.packets);
    assert!(r.packets > 5_000, "only {} packets", r.packets);
    assert!(r.tcp > 0 && r.udp > 0);
    assert!(r.syns > 100, "{} TCP connections", r.syns);
    assert!(r.fins >= r.syns, "every closed TCP flow needs FINs");
    assert!(!r.client_hellos.is_empty());
    assert!(
        r.certificates > 0,
        "expected some TLS 1.2 certificate flights"
    );
    // DNS: queries paired with responses, compressed responses, CNAME chains.
    let queries = r.dns.iter().filter(|d| !d.2.response).count();
    let responses = r.dns.iter().filter(|d| d.2.response).count();
    assert_eq!(queries, responses);
    assert!(r.dns.iter().any(|d| d.2.response && d.2.compressed));
    assert!(r.dns.iter().any(|d| d.2.response && d.2.answers >= 3));
    assert!(
        r.dns.iter().any(|d| d.2.qtype == 28),
        "expected AAAA lookups"
    );
    // Periodic benign traffic and plain HTTP.
    assert!(
        r.http_requests
            .iter()
            .any(|l| l.contains("authrootstl.cab"))
    );
    assert!(
        r.http_requests
            .iter()
            .any(|l| l.starts_with("GET /connecttest.txt"))
    );
    assert!(s.labels.benign && s.labels.c2_hosts.is_empty());
    assert_eq!(s.labels.scenario, "office");
}

#[test]
fn beacon_scenario_beacons_every_60s() {
    let (bytes, s) = gen_bytes(Scenario::Beacon, 3, 45);
    let r = validate(&bytes);
    let host = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 23));
    let c2 = IpAddr::V4(Ipv4Addr::new(185, 199, 110, 77));
    let times = r.syn_times.get(&(host, c2)).expect("beacon connections");
    // Starts at +17 min, so ~28 beacons in a 45-minute capture.
    assert!(times.len() >= 20, "{} beacons", times.len());
    let dts: Vec<f64> = times
        .windows(2)
        .map(|w| (w[1] - w[0]) as f64 / 1e6)
        .collect();
    for dt in &dts {
        assert!(
            (57.0..=63.5).contains(dt),
            "interval {dt}s outside 60 s ±3% (+DNS lag): {dts:?}"
        );
    }
    assert!(r.client_hellos.iter().any(|c| c.1 == host && c.2 == c2));
    assert!(r.dns.iter().any(|d| d.2.qname == "cdn-update.top"));
    assert_eq!(s.labels.c2_hosts, vec!["10.0.0.23"]);
    assert!(
        s.labels
            .bad_destinations
            .contains(&"cdn-update.top".to_string())
    );
    assert!(!s.labels.benign);
}

#[test]
fn dns_tunnel_scenario_has_long_txt_queries() {
    let (bytes, s) = gen_bytes(Scenario::DnsTunnel, 4, 25);
    let r = validate(&bytes);
    let host = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 17));
    let tun: Vec<&DnsMsg> = r
        .dns
        .iter()
        .filter(|d| d.1 == host && !d.2.response && d.2.qname.ends_with(".t.exfil-dns.xyz"))
        .map(|d| &d.2)
        .collect();
    assert!(tun.len() >= 100, "{} tunnel queries", tun.len());
    let txt = tun.iter().filter(|d| d.qtype == 16).count();
    assert!(txt * 100 / tun.len() >= 70, "TXT share {txt}/{}", tun.len());
    assert!(
        tun.iter()
            .all(|d| d.qname.len() > 50 && d.qname.len() <= 253)
    );
    let unique: BTreeSet<&str> = tun.iter().map(|d| d.qname.as_str()).collect();
    assert_eq!(unique.len(), tun.len(), "tunnel names should not repeat");
    assert_eq!(s.labels.c2_hosts, vec!["10.0.0.17"]);
}

#[test]
fn dga_scenario_has_nxdomain_bursts_and_one_resolving_domain() {
    let (bytes, s) = gen_bytes(Scenario::Dga, 5, 25);
    let r = validate(&bytes);
    let host = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12));
    let nx = r
        .dns
        .iter()
        .filter(|d| d.2.response && d.2.rcode == 3)
        .count();
    // First burst at +10 min, then every ~300 s: 3 bursts of 25-60 in 25 min.
    assert!(nx >= 60, "{nx} NXDOMAIN responses");
    let win = &s.labels.bad_destinations[0];
    assert!(
        r.dns
            .iter()
            .any(|d| d.2.response && d.2.rcode == 0 && &d.2.qname == win),
        "winning DGA domain {win} never resolved"
    );
    let c2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45));
    assert!(r.syn_times.contains_key(&(host, c2)));
    assert_eq!(s.labels.c2_hosts, vec!["10.0.0.12"]);
}

#[test]
fn ipv6_option_emits_valid_ipv6() {
    let mut opts = Options::new(Scenario::Office, 11);
    opts.duration_min = 15;
    opts.ipv6 = true;
    let mut out = Vec::new();
    generate(&opts, &mut out).expect("generate");
    let pkts = read_pcap(&out);
    let v6 = pkts
        .iter()
        .filter(|p| u16::from_be_bytes([p.data[12], p.data[13]]) == 0x86DD)
        .count();
    assert!(v6 > 0, "no IPv6 packets with --ipv6");
    validate(&out);
}

#[test]
fn scale_stops_at_the_size_budget() {
    let mut opts = Options::new(Scenario::Scale, 1);
    opts.size_gb = 0.02; // ~21 MB
    let mut out = Vec::new();
    let s = generate(&opts, &mut out).expect("generate");
    let limit = (0.02 * (1u64 << 30) as f64) as u64;
    assert!(s.bytes >= limit, "{} < {limit}", s.bytes);
    assert!(s.bytes < limit + 70_000, "overshoot {}", s.bytes - limit);
    assert_eq!(s.bytes as usize, out.len());
    validate(&out);
    assert_eq!(s.labels.c2_hosts.len(), 3);
}

#[test]
fn labels_path_is_beside_the_capture() {
    let p = walleye_gen::labels_path(std::path::Path::new("/x/generated/beacon.pcap"));
    assert_eq!(p, std::path::Path::new("/x/generated/beacon.labels.json"));
}
