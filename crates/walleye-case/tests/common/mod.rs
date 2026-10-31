//! Hand-built fixtures shared by the integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use walleye_core::{
    Allowlist, CaptureFormat, CaptureRow, DnsRow, Evidence, Finding, FlowRow, HttpRow, Reason,
    TlsRow, Verdict,
    ipc::{Case, EvidenceRef, Pin, QueryLogEntry, TimeRange, VerdictEntry, View},
    sink::MemorySource,
};

pub const SHA: &str = "a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0";
pub const T0: i64 = 1_773_306_026_906_498;

pub fn capture() -> CaptureRow {
    CaptureRow {
        capture_id: SHA[..16].to_string(),
        path: "/cases/office-beacon.pcap".into(),
        sha256: SHA.into(),
        size_bytes: 238_862,
        format: CaptureFormat::Pcap,
        first_ts: T0,
        last_ts: T0 + 3_500_070_084,
        link_type: 1,
        frame_count: 2449,
    }
}

pub fn ev(flows: &[u64], frames: &[u64]) -> Evidence {
    Evidence {
        flow_ids: flows.to_vec(),
        frame_nos: frames.to_vec(),
        truncated: false,
        total: flows.len().max(frames.len()) as u64,
    }
}

pub fn flow(
    id: u64,
    ts: i64,
    src: &str,
    dst: &str,
    dport: u16,
    app: Option<&str>,
    first: u64,
) -> FlowRow {
    FlowRow {
        flow_id: id,
        ts_start: ts,
        ts_end: ts + 1_000_000,
        src_ip: src.into(),
        src_port: 50_000 + id as u16,
        dst_ip: dst.into(),
        dst_port: dport,
        proto: if dport == 53 { 17 } else { 6 },
        app_proto: app.map(str::to_string),
        bytes_up: 300,
        bytes_down: 1200,
        pkts_up: 4,
        pkts_down: 4,
        first_frame: first,
        last_frame: first + 7,
    }
}

pub fn dns(flow_id: u64, frame: u64, ts: i64, q: &str, resp: bool, answers: &[&str]) -> DnsRow {
    DnsRow {
        ts,
        flow_id,
        frame_no: frame,
        trans_id: frame as u16,
        is_response: resp,
        query: q.into(),
        qtype: "A".into(),
        rcode: resp.then(|| "NOERROR".to_string()),
        answers: answers.iter().map(|s| s.to_string()).collect(),
        ttl: resp.then_some(60),
    }
}

pub fn tls(flow_id: u64, frame: u64, ts: i64, sni: &str, ja4: &str, serial: &str) -> TlsRow {
    TlsRow {
        ts,
        flow_id,
        frame_no: frame,
        sni: Some(sni.into()),
        version: Some("TLS 1.2".into()),
        ja4: Some(ja4.into()),
        ja4s: None,
        cert_subject: Some(format!("CN={sni}")),
        cert_issuer: Some(format!("CN={sni}")),
        cert_serial: Some(serial.into()),
        cert_self_signed: Some(true),
        cert_not_before: None,
        cert_not_after: None,
    }
}

pub fn http(flow_id: u64, frame: u64, ts: i64, host: &str, uri: &str) -> HttpRow {
    HttpRow {
        ts,
        flow_id,
        frame_no: frame,
        method: Some("GET".into()),
        host: Some(host.into()),
        uri: Some(uri.into()),
        user_agent: Some("Mozilla/5.0".into()),
        status: Some(200),
        resp_frame_no: Some(frame + 2),
        req_bytes: 120,
        resp_bytes: 512,
    }
}

pub fn reason(
    rule: &str,
    signal: &str,
    weight: f64,
    tech: Option<&str>,
    e: Evidence,
    expl: &str,
) -> Reason {
    Reason {
        rule_id: rule.into(),
        signal: signal.into(),
        value: 0.0138,
        unit: Some("ratio".into()),
        weight,
        explanation: expl.into(),
        attack_technique: tech.map(str::to_string),
        evidence: e,
    }
}

/// Beacon (10.0.0.23 → 185.199.110.77 / cdn-update.top over TLS and HTTP),
/// DNS tunnel (10.0.0.17 → many *.t.exfil-dns.xyz) and Windows Update
/// (10.0.0.15, allowlisted).
pub fn scenario() -> (MemorySource, Vec<Finding>) {
    let s = 1_000_000;
    let mut src = MemorySource {
        capture: Some(capture()),
        ..Default::default()
    };
    // beacon: flow 2 HTTP stage, flows 3..=5 TLS beacons; flow 1 is its DNS lookup
    src.flows.push(flow(
        1,
        T0 + 10 * s,
        "10.0.0.23",
        "10.0.0.2",
        53,
        Some("dns"),
        10,
    ));
    src.flows.push(flow(
        2,
        T0 + 11 * s,
        "10.0.0.23",
        "185.199.110.77",
        80,
        Some("http"),
        20,
    ));
    for (i, id) in (3..=5u64).enumerate() {
        src.flows.push(flow(
            id,
            T0 + (60 + 60 * i as i64) * s,
            "10.0.0.23",
            "185.199.110.77",
            443,
            Some("tls"),
            100 + 10 * i as u64,
        ));
    }
    src.dns
        .push(dns(1, 10, T0 + 10 * s, "cdn-update.top", false, &[]));
    src.dns.push(dns(
        1,
        11,
        T0 + 10 * s + 20_000,
        "cdn-update.top",
        true,
        &["185.199.110.77"],
    ));
    src.http.push(http(
        2,
        23,
        T0 + 11 * s,
        "cdn-update.top",
        "/gate.php?id=7f3a",
    ));
    for (i, id) in (3..=5u64).enumerate() {
        src.tls.push(tls(
            id,
            103 + 10 * i as u64,
            T0 + (60 + 60 * i as i64) * s,
            "cdn-update.top",
            "t12d190800_d83cc789557e_7af1ed941c26",
            "00:D1:E2:F3:A4:B5:C6:D7",
        ));
    }
    // tunnel: one DNS flow to a public resolver with 10 distinct subdomains
    src.flows.push(flow(
        10,
        T0 + 200 * s,
        "10.0.0.17",
        "8.8.8.8",
        53,
        Some("dns"),
        300,
    ));
    for n in 0..10u64 {
        src.dns.push(dns(
            10,
            300 + n,
            T0 + (200 + n as i64) * s,
            &format!("q{n:02}x7k.t.exfil-dns.xyz"),
            false,
            &[],
        ));
    }
    // windows update
    src.flows.push(flow(
        20,
        T0 + 5 * s,
        "10.0.0.15",
        "13.107.4.50",
        443,
        Some("tls"),
        5,
    ));
    src.tls.push(tls(
        20,
        7,
        T0 + 5 * s,
        "fe2.update.microsoft.com",
        "t13d1516h2_8daaf6152771_02713d6af862",
        "33000001",
    ));
    // unrelated noise that must not become an IOC
    src.flows.push(flow(
        30,
        T0 + 7 * s,
        "10.0.0.40",
        "93.184.216.34",
        443,
        Some("tls"),
        8,
    ));
    src.tls.push(tls(
        30,
        9,
        T0 + 7 * s,
        "example.com",
        "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
        "0abc",
    ));

    let beacon = Finding {
        finding_id: "f1b2c3d4e5f60001".into(),
        title: "Beaconing to 185.199.110.77 (cdn-update.top)".into(),
        detector: "beaconing".into(),
        entity_type: "host".into(),
        entity: "10.0.0.23".into(),
        score: 92.0,
        attack_technique: Some("T1071".into()),
        ts_first: T0 + 60 * s,
        ts_last: T0 + 180 * s,
        reasons: vec![
            reason(
                "beacon.periodic",
                "interval_regularity",
                46.0,
                Some("T1071"),
                ev(&[3, 4, 5], &[100, 110, 120]),
                "10.0.0.23 contacted 185.199.110.77 3 times, every 60.0s ±1.4%",
            ),
            reason(
                "http.stage",
                "staging_request",
                20.0,
                Some("T1071.001"),
                ev(&[2], &[23]),
                "GET /gate.php?id=7f3a before the first beacon",
            ),
        ],
        verdict: None,
    };
    let tunnel = Finding {
        finding_id: "f1b2c3d4e5f60002".into(),
        title: "DNS tunnel via t.exfil-dns.xyz".into(),
        detector: "dns_tunnel".into(),
        entity_type: "host".into(),
        entity: "10.0.0.17".into(),
        score: 81.0,
        attack_technique: Some("T1071.004".into()),
        ts_first: T0 + 200 * s,
        ts_last: T0 + 209 * s,
        reasons: vec![reason(
            "dns.tunnel",
            "subdomain_entropy",
            40.0,
            Some("T1071.004"),
            ev(&[10], &(300..310).collect::<Vec<_>>()),
            "10 high-entropy subdomains of exfil-dns.xyz",
        )],
        verdict: None,
    };
    let wu = Finding {
        finding_id: "f1b2c3d4e5f60004".into(),
        title: "Periodic connections to Windows Update".into(),
        detector: "beaconing".into(),
        entity_type: "host".into(),
        entity: "10.0.0.15".into(),
        score: 12.0,
        attack_technique: None,
        ts_first: T0 + 5 * s,
        ts_last: T0 + 6 * s,
        reasons: vec![reason(
            "beacon.periodic",
            "interval_regularity",
            12.0,
            None,
            ev(&[20], &[5]),
            "allowlisted destination (Microsoft Update): down-weighted",
        )],
        verdict: None,
    };
    (src, vec![wu, tunnel, beacon])
}

pub fn allowlist() -> Allowlist {
    Allowlist::from_yaml(include_str!("../../../../rules/allowlist.yaml")).expect("allowlist")
}

pub fn case(pins: Vec<Pin>) -> Case {
    Case {
        case_id: capture().capture_id,
        capture: capture(),
        pins,
        verdicts: vec![VerdictEntry {
            finding_id: "f1b2c3d4e5f60001".into(),
            verdict: Verdict::Suspicious,
            note: "Confirmed with the host owner: *not* a sanctioned tool.".into(),
            at: T0 + 4_000_000_000,
        }],
        queries: vec![
            QueryLogEntry {
                filter: "host 10.0.0.23".into(),
                view: View::Flows,
                time_range: None,
                sql: Some("SELECT * FROM flows WHERE (src_ip = ? OR dst_ip = ?) LIMIT ?".into()),
                rows: 61,
                at: T0 + 3_600_000_000,
            },
            QueryLogEntry {
                filter: "host 10.0.0.23".into(),
                view: View::Flows,
                time_range: None,
                sql: Some("SELECT * FROM flows WHERE (src_ip = ? OR dst_ip = ?) LIMIT ?".into()),
                rows: 61,
                at: T0 + 3_601_000_000,
            },
            QueryLogEntry {
                filter: "dns.query ~ \"*.exfil-dns.xyz\" | evil".into(),
                view: View::Dns,
                time_range: Some(TimeRange {
                    start: T0,
                    end: T0 + 600_000_000,
                }),
                sql: None,
                rows: 10,
                at: T0 + 3_602_000_000,
            },
        ],
    }
}

pub fn pins() -> Vec<Pin> {
    vec![
        Pin {
            pin_id: "pin-1".into(),
            evidence: EvidenceRef::Frame { frame_no: 23 },
            note: "Staging request.\nSee the URI.".into(),
            resolved: ev(&[2], &[23]),
            created_at: T0 + 3_700_000_000,
        },
        Pin {
            pin_id: "pin-2".into(),
            evidence: EvidenceRef::Finding {
                finding_id: "f1b2c3d4e5f60001".into(),
            },
            note: String::new(),
            resolved: ev(&[2, 3, 4, 5], &[23, 100, 110, 120]),
            created_at: T0 + 3_701_000_000,
        },
        Pin {
            pin_id: "pin-3".into(),
            evidence: EvidenceRef::Note,
            note: "Escalated to IR. # not a heading [x](http://evil.example) <b>no html</b>".into(),
            resolved: Evidence::default(),
            created_at: T0 + 3_702_000_000,
        },
        Pin {
            pin_id: "pin-4".into(),
            evidence: EvidenceRef::Query {
                filter: "host 10.0.0.17".into(),
                view: View::Dns,
                time_range: None,
            },
            note: String::new(),
            resolved: ev(&[10], &[300, 301]),
            created_at: T0 + 3_703_000_000,
        },
    ]
}

pub fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Compare with a golden file; `UPDATE_GOLDEN=1` rewrites it.
pub fn assert_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden_dir()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {name}; run with UPDATE_GOLDEN=1"));
    assert_eq!(
        actual, expected,
        "golden {name} differs; rerun with UPDATE_GOLDEN=1 and review the diff"
    );
}
