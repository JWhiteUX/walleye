//! Golden tests: five captures built in code, ingested from a real file, with
//! hand-written expectations for the important records plus a full-output
//! golden JSON (`tests/golden/<name>.json`; regenerate with
//! `WALLEYE_UPDATE_GOLDEN=1 cargo test -p walleye-ingest --test golden`).
//!
//! JA4/JA4S expectations were computed independently with `shasum -a 256`
//! over the FoxIO raw strings, not with this crate.

mod common;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use common::fixtures::*;
use common::*;
use walleye_core::{CaptureFormat, CaptureRow, Direction};
use walleye_ingest::{IngestOptions, ingest, ingest_bytes};

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "walleye-ingest-golden-{}-{name}",
        std::process::id()
    ))
}

/// Ingest from a file and from memory; both must agree. Checks the golden.
fn run(name: &str, bytes: &[u8], opts: &IngestOptions) -> (CaptureRow, Rows) {
    let path = temp_path(name);
    std::fs::write(&path, bytes).expect("write fixture");
    let mut sink = CollectSink::default();
    let mut progress_calls = 0;
    let cap = ingest(
        &path,
        SHA,
        &mut sink,
        opts,
        &mut |_| progress_calls += 1,
        &AtomicBool::new(false),
    )
    .expect("ingest");
    std::fs::remove_file(&path).expect("cleanup");
    assert!(progress_calls >= 1);
    assert_eq!(sink.finished.as_ref(), Some(&cap));
    assert_eq!(cap.size_bytes, bytes.len() as u64);
    assert_eq!(cap.capture_id, &SHA[..16]);

    let mut mem = CollectSink::default();
    let cap2 = ingest_bytes(bytes, SHA, &mut mem, opts).expect("ingest_bytes");
    assert_eq!(mem.rows, sink.rows, "file and memory ingest differ");
    assert_eq!(
        CaptureRow {
            path: cap.path.clone(),
            ..cap2.clone()
        },
        cap
    );
    (cap2, sink.rows)
}

fn check_golden(name: &str, cap: &CaptureRow, rows: &Rows) {
    let golden = serde_json::json!({ "capture": cap, "rows": rows });
    let text = serde_json::to_string_pretty(&golden).expect("json") + "\n";
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.json"));
    if std::env::var_os("WALLEYE_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
        std::fs::write(&path, &text).expect("write golden");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing {}; run with WALLEYE_UPDATE_GOLDEN=1",
            path.display()
        )
    });
    assert!(
        want == text,
        "golden mismatch for {name}; rerun with WALLEYE_UPDATE_GOLDEN=1 and review the diff"
    );
}

// ------------------------------------------------------------- 1. DNS

#[test]
fn golden_dns() {
    let (cap, rows) = run("dns", &dns_fixture(), &IngestOptions::default());
    let raw = rows.clone();
    assert_eq!(cap.format, CaptureFormat::Pcap);
    assert_eq!(cap.link_type, 1);
    assert_eq!(cap.frame_count, 15);
    assert_eq!(cap.first_ts, T0);
    assert_eq!(cap.last_ts, T0 + 3_010_000);
    let rows = rows.sorted();
    assert_eq!(rows.flows.len(), 4);
    let f1 = &rows.flows[0];
    assert_eq!(
        (
            f1.src_ip.as_str(),
            f1.src_port,
            f1.dst_ip.as_str(),
            f1.dst_port
        ),
        ("10.0.0.5", 51000, "10.0.0.53", 53)
    );
    assert_eq!((f1.proto, f1.app_proto.as_deref()), (17, Some("dns")));
    assert_eq!(
        (f1.pkts_up, f1.pkts_down, f1.first_frame, f1.last_frame),
        (1, 1, 1, 2)
    );
    let tcpf = &rows.flows[2];
    assert_eq!(
        (tcpf.proto, tcpf.src_port, tcpf.first_frame, tcpf.last_frame),
        (6, 40000, 5, 13)
    );
    assert_eq!(rows.flows[3].src_ip, "2001:db8::5");

    assert_eq!(rows.dns.len(), 8);
    let q = &rows.dns[0];
    assert_eq!(
        (
            q.query.as_str(),
            q.qtype.as_str(),
            q.is_response,
            q.rcode.as_deref()
        ),
        ("www.example.com", "A", false, None)
    );
    let r = &rows.dns[1];
    assert_eq!(r.answers, vec!["cdn.example.com", "93.184.216.34"]);
    assert_eq!(
        (r.trans_id, r.ttl, r.rcode.as_deref(), r.frame_no),
        (0x1111, Some(60), Some("NOERROR"), 2)
    );
    let nx = &rows.dns[3];
    assert_eq!(
        (nx.qtype.as_str(), nx.rcode.as_deref(), nx.ttl),
        ("TXT", Some("NXDOMAIN"), None)
    );
    assert!(nx.answers.is_empty());
    // TCP: the query row points at the frame where the message started.
    let tq = &rows.dns[4];
    assert_eq!(
        (tq.frame_no, tq.query.as_str(), tq.flow_id),
        (8, "example.net", tcpf.flow_id)
    );
    assert_eq!(rows.dns[5].answers, vec!["helloworld"]);
    assert_eq!(rows.dns[5].frame_no, 10);
    assert_eq!(rows.dns[7].answers, vec!["2001:db8::1"]);
    assert_eq!(rows.dns[7].qtype, "AAAA");
    assert!(rows.http.is_empty() && rows.tls.is_empty() && rows.files.is_empty());
    // Frames carry flow ids and directions.
    assert_eq!(rows.frames[1].direction, Some(Direction::Down));
    assert_eq!(rows.frames[4].tcp_flags, Some(SYN));
    assert_eq!(rows.frames[0].file_offset, 24 + 16);
    check_golden("dns", &cap, &raw);
}

// ------------------------------------------------------------- 2. HTTP

#[test]
fn golden_http() {
    let (cap, rows) = run("http", &http_fixture(), &IngestOptions::default());
    let raw = rows.clone();
    assert_eq!(cap.frame_count, 15);
    assert_eq!(rows.flows.len(), 1);
    let f = &rows.flows[0];
    assert_eq!(f.app_proto.as_deref(), Some("http"));
    assert_eq!(
        (f.src_ip.as_str(), f.dst_port, f.pkts_up, f.pkts_down),
        ("10.0.0.5", 80, 8, 7)
    );
    assert_eq!(f.bytes_down, 72 + 3000 + 103 + 139);
    assert_eq!(rows.http.len(), 3);
    let g = &rows.http[0];
    assert_eq!(g.method.as_deref(), Some("GET"));
    assert_eq!(g.host.as_deref(), Some("example.com"));
    assert_eq!(g.uri.as_deref(), Some("/files/report.pdf"));
    assert_eq!(g.user_agent.as_deref(), Some("Walleye-Test/1.0"));
    assert_eq!(
        (
            g.status,
            g.frame_no,
            g.resp_frame_no,
            g.req_bytes,
            g.resp_bytes
        ),
        (Some(200), 4, Some(5), 0, 3000)
    );
    let p = &rows.http[1];
    assert_eq!(
        (
            p.method.as_deref(),
            p.frame_no,
            p.resp_frame_no,
            p.req_bytes,
            p.resp_bytes
        ),
        (Some("POST"), 8, Some(10), 11, 5)
    );
    let d = &rows.http[2];
    assert_eq!(
        (d.uri.as_deref(), d.resp_bytes, d.resp_frame_no),
        (Some("/dl?id=7"), 4, Some(12))
    );

    let files: Vec<_> = rows
        .files
        .iter()
        .map(|f| {
            (
                f.frame_no,
                f.direction,
                f.filename.as_deref(),
                f.mime_type.as_deref(),
                f.size_bytes,
            )
        })
        .collect();
    assert_eq!(
        files,
        vec![
            (
                5,
                Direction::Down,
                Some("report.pdf"),
                Some("application/pdf"),
                Some(3000)
            ),
            (
                8,
                Direction::Up,
                None,
                Some("application/x-www-form-urlencoded"),
                Some(11)
            ),
            (
                10,
                Direction::Down,
                Some("upload"),
                Some("text/plain"),
                Some(5)
            ),
            (
                12,
                Direction::Down,
                Some("payload.bin"),
                Some("application/octet-stream"),
                Some(4)
            ),
        ]
    );
    assert!(rows.files.iter().all(|f| f.source == "http"));
    check_golden("http", &cap, &raw);
}

// ------------------------------------------------------------- 3. TLS

#[test]
fn golden_tls() {
    let (cap, rows) = run("tls", &tls_fixture(), &IngestOptions::default());
    let raw = rows.clone();
    assert_eq!(cap.format, CaptureFormat::Pcapng);
    assert_eq!(cap.link_type, 1);
    let rows = rows.sorted();
    assert_eq!(rows.flows.len(), 3);
    assert!(
        rows.flows
            .iter()
            .all(|f| f.app_proto.as_deref() == Some("tls"))
    );
    assert_eq!(rows.tls.len(), 3);

    let a = &rows.tls[0];
    assert_eq!(a.frame_no, 4, "ClientHello row points at the first segment");
    assert_eq!(a.sni.as_deref(), Some("www.example.org"));
    assert_eq!(a.version.as_deref(), Some("TLS 1.2"));
    assert_eq!(
        a.ja4.as_deref(),
        Some("t12d0308h2_b80a1783d7a2_ff7d91786c24")
    );
    assert_eq!(a.ja4s.as_deref(), Some("t1204h2_c02f_3c554903fe9c"));
    assert_eq!(
        a.cert_subject.as_deref(),
        Some("CN=www.example.org,O=Walleye Test,C=US")
    );
    assert_eq!(a.cert_issuer, a.cert_subject);
    assert_eq!(a.cert_serial.as_deref(), Some("9a3b01"));
    assert_eq!(a.cert_self_signed, Some(true));
    assert_eq!(a.cert_not_before, Some(1_704_067_200_000_000));
    assert_eq!(a.cert_not_after, Some(2_019_686_400_000_000));

    let b = &rows.tls[1];
    assert_eq!(b.sni.as_deref(), Some("api.example.com"));
    assert_eq!(b.version.as_deref(), Some("TLS 1.3"));
    assert_eq!(
        b.ja4.as_deref(),
        Some("t13d0306h2_55b375c5d22e_9d31f6370cac")
    );
    assert_eq!(b.ja4s.as_deref(), Some("t130200_1301_a56c5b993250"));
    assert_eq!(b.cert_subject, None);

    let c = &rows.tls[2];
    assert_eq!(c.sni, None);
    assert_eq!(
        c.version.as_deref(),
        Some("TLS 1.2"),
        "offered max without a ServerHello"
    );
    assert!(
        c.ja4
            .as_deref()
            .is_some_and(|j| j.starts_with("t12i010000_"))
    );
    assert_eq!(c.ja4s, None);
    check_golden("tls", &cap, &raw);
}

// ------------------------------------------------------------- 4. malformed

#[test]
fn golden_malformed() {
    let (cap, rows) = run("malformed", &malformed_fixture(), &IngestOptions::default());
    let raw = rows.clone();
    assert_eq!(cap.frame_count, 12, "cut-off final record is not a frame");
    assert_eq!(rows.frames.len(), 12);
    let no_flow: Vec<u64> = rows
        .frames
        .iter()
        .filter(|f| f.flow_id.is_none())
        .map(|f| f.frame_no)
        .collect();
    assert_eq!(no_flow, vec![1, 2, 3, 4, 11]);
    let rows = rows.sorted();
    // Loop: header parsed, question rejected; garbage DNS: no row; cut: prefix.
    assert_eq!(rows.dns.len(), 2);
    assert_eq!(
        (rows.dns[0].query.as_str(), rows.dns[0].qtype.as_str()),
        ("", "TYPE0")
    );
    assert_eq!(
        (rows.dns[1].query.as_str(), rows.dns[1].answers.len()),
        ("cut.example", 0)
    );
    assert!(
        rows.tls.is_empty(),
        "oversized record yields no ClientHello"
    );
    assert!(rows.http.is_empty(), "unterminated head yields no request");
    let protos: Vec<(u8, Option<&str>)> = rows
        .flows
        .iter()
        .map(|f| (f.proto, f.app_proto.as_deref()))
        .collect();
    assert_eq!(
        protos,
        vec![
            (17, Some("dns")),
            (17, Some("dns")),
            (6, Some("tls")),
            (6, Some("http")),
            (1, None),
            (17, Some("dns"))
        ]
    );
    // Snap-truncated frame keeps its wire length.
    let last = &rows.frames[11];
    assert_eq!(last.wirelen, last.caplen + 6);
    check_golden("malformed", &cap, &raw);
}

// ------------------------------------------------------------- 5. pcapng, many interfaces

#[test]
fn golden_multi_interface() {
    let (cap, rows) = run("multi", &multi_fixture(), &IngestOptions::default());
    let raw = rows.clone();
    assert_eq!(cap.format, CaptureFormat::Pcapng);
    assert_eq!(cap.link_type, 1, "first interface");
    assert_eq!(cap.frame_count, 6);
    let f = &rows.frames;
    assert_eq!(f[0].ts, T0);
    assert_eq!(f[1].ts, T0, "SPB inherits the previous timestamp");
    assert_eq!(f[1].direction, Some(Direction::Down));
    assert_eq!(f[2].ts, T0 + 500, "ns interface converted to µs");
    assert_eq!(f[3].ts, T0 + 120_000_000);
    assert_eq!(f[3].file_offset % 4, 0);
    assert_eq!(f[4].flow_id, None, "undefined interface id");
    assert_eq!(
        f[5].ts,
        T0 + 200_000_000,
        "ms interface in a big-endian section"
    );
    let rows = rows.sorted();
    let flows: Vec<(&str, u16, u64, u64)> = rows
        .flows
        .iter()
        .map(|f| (f.src_ip.as_str(), f.src_port, f.pkts_up, f.pkts_down))
        .collect();
    assert_eq!(
        flows,
        vec![
            ("10.1.0.1", 5000, 1, 1),
            ("10.2.0.1", 7000, 1, 0),
            ("10.2.0.1", 7000, 1, 0),
            ("10.3.0.1", 9, 1, 0)
        ]
    );
    assert_eq!(rows.flows[1].ts_end, T0 + 500);
    assert_eq!(rows.flows[2].ts_start, T0 + 120_000_000);
    check_golden("multi", &cap, &raw);
}
