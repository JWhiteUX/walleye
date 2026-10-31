//! Behaviour of ingest beyond the golden fixtures: resume from checkpoints,
//! flow assembly rules, cancellation, bad input, decode tree, read/hash.

mod common;

use std::sync::atomic::AtomicBool;

use common::fixtures::*;
use common::synth::mixed_pcap;
use common::*;
use walleye_core::{Direction, ErrorCode};
use walleye_ingest::{
    IngestOptions, NullSink, decode_frame, hash_file, ingest, ingest_bytes, read_frame,
};

fn collect(bytes: &[u8], opts: &IngestOptions) -> Rows {
    let mut s = CollectSink::default();
    ingest_bytes(bytes, SHA, &mut s, opts).expect("ingest");
    s.rows
}

fn small_opts() -> IngestOptions {
    IngestOptions {
        checkpoint_bytes: 64 * 1024,
        batch_rows: 97,
        ..IngestOptions::default()
    }
}

#[test]
fn resume_after_crash_matches_uninterrupted_run() {
    let cap = mixed_pcap(7, 64, 3_000_000);
    let opts = small_opts();
    let mut full = CollectSink::default();
    let full_cap = ingest_bytes(&cap, SHA, &mut full, &opts).expect("full");
    let n_cps = full.checkpoints.len();
    assert!(n_cps >= 10, "expected many checkpoints, got {n_cps}");
    assert!(full.rows.flows.len() > 100);
    assert!(!full.rows.tls.is_empty() && !full.rows.http.is_empty() && !full.rows.dns.is_empty());
    // Open flows really do cross checkpoints.
    let cp = &full.checkpoints[n_cps / 2];
    assert!(cp.state.len() > 1000, "state should carry open flows");

    for crash_at in [1, 2, n_cps / 2, n_cps - 1] {
        let mut first = CollectSink {
            crash_after: Some(crash_at),
            ..CollectSink::default()
        };
        let err = ingest_bytes(&cap, SHA, &mut first, &opts).expect_err("simulated crash");
        assert_eq!(err.message, "simulated crash");
        let cp = first.checkpoints.last().expect("checkpoint").clone();
        assert_eq!(
            cp,
            full.checkpoints[crash_at - 1],
            "checkpoints are deterministic"
        );

        let mut second = CollectSink {
            resume_from: Some(cp.clone()),
            ..CollectSink::default()
        };
        let resumed_cap = ingest_bytes(&cap, SHA, &mut second, &opts).expect("resume");
        assert_eq!(resumed_cap, full_cap);
        // Frame numbering continues after the checkpoint.
        assert_eq!(
            second.rows.frames.first().map(|f| f.frame_no),
            Some(cp.frames_emitted + 1)
        );

        let mut combined = first.durable.clone();
        let r = &second.rows;
        combined.frames.extend(r.frames.iter().cloned());
        combined.flows.extend(r.flows.iter().cloned());
        combined.dns.extend(r.dns.iter().cloned());
        combined.http.extend(r.http.iter().cloned());
        combined.tls.extend(r.tls.iter().cloned());
        combined.files.extend(r.files.iter().cloned());
        assert_eq!(
            combined.sorted(),
            full.rows.clone().sorted(),
            "crash at checkpoint {crash_at}"
        );
    }
}

#[test]
fn checkpoint_from_another_version_is_rejected() {
    let cap = http_fixture();
    let mut s = CollectSink {
        resume_from: Some(walleye_core::sink::Checkpoint {
            file_offset: 24,
            frames_emitted: 0,
            next_flow_id: 1,
            state: b"{\"bogus\":1}".to_vec(),
        }),
        ..CollectSink::default()
    };
    let e = ingest_bytes(&cap, SHA, &mut s, &IngestOptions::default()).expect_err("bad state");
    assert_eq!(e.code, ErrorCode::Internal);
}

#[test]
fn initiator_is_syn_sender_even_when_synack_seen_first() {
    let mut t = Tcp::new(([10, 0, 0, 5], 1234), ([10, 0, 0, 9], 80), T0);
    t.handshake();
    t.client(b"x");
    let mut p = Pcap::new(1);
    // Drop the SYN: the SYN-ACK (server → client) is the first packet.
    p.add(&t.frames[1..]);
    let rows = collect(&p.buf, &IngestOptions::default());
    let f = &rows.flows[0];
    assert_eq!(
        (f.src_ip.as_str(), f.src_port, f.pkts_up, f.pkts_down),
        ("10.0.0.5", 1234, 2, 1)
    );
    assert_eq!(rows.frames[0].direction, Some(Direction::Down));

    // Mid-stream pickup (no SYN at all): first packet's sender.
    let mut p = Pcap::new(1);
    p.add(&t.frames[2..]);
    p.packet(T0 + 9000, &t.frames[1].1); // server packet later
    let rows = collect(&p.buf, &IngestOptions::default());
    assert_eq!(rows.flows[0].src_ip, "10.0.0.5");
}

#[test]
fn idle_timeout_and_rst_split_flows() {
    let opts = IngestOptions {
        tcp_idle_timeout_s: 10,
        ..IngestOptions::default()
    };
    let mut p = Pcap::new(1);
    let mut a = Tcp::new(([10, 0, 0, 5], 1111), ([10, 0, 0, 9], 22), T0);
    a.handshake();
    a.client(b"ssh-1");
    p.add(&a.frames);
    // Same tuple 11 s later, no SYN: a new flow because of the idle timeout.
    let mut b = Tcp::new(([10, 0, 0, 5], 1111), ([10, 0, 0, 9], 22), T0 + 11_000_000);
    b.cseq = a.cseq;
    b.sseq = a.sseq;
    b.client(b"more");
    p.add(&b.frames);
    // RST, then an immediate new SYN on the same tuple: a third flow.
    let rst = eth(
        0x0800,
        &ipv4(
            [10, 0, 0, 9],
            [10, 0, 0, 5],
            6,
            &tcp(22, 1111, 1, 0, RST, &[]),
        ),
    );
    p.packet(T0 + 11_100_000, &rst);
    let mut c = Tcp::new(([10, 0, 0, 5], 1111), ([10, 0, 0, 9], 22), T0 + 11_200_000);
    c.handshake();
    p.add(&c.frames);
    let rows = collect(&p.buf, &opts).sorted();
    let counts: Vec<(u64, u64, u64)> = rows
        .flows
        .iter()
        .map(|f| (f.flow_id, f.pkts_up, f.pkts_down))
        .collect();
    assert_eq!(counts, vec![(1, 3, 1), (2, 1, 1), (3, 2, 1)]);
    assert_eq!(rows.flows[0].bytes_up, 5);
}

#[test]
fn retransmissions_and_gaps_do_not_corrupt_http() {
    let mut t = Tcp::new(([10, 0, 0, 5], 50001), ([10, 0, 0, 80], 8080), T0);
    t.handshake();
    t.client(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n");
    t.server(b"HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n");
    t.server(&[1u8; 1000]);
    // Lose 1000 body bytes (a gap), then the rest.
    t.sseq = t.sseq.wrapping_add(1000);
    t.server(&[3u8; 1000]);
    t.client(b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n");
    t.client_retransmit(b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n");
    t.server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    let mut p = Pcap::new(1);
    p.add(&t.frames);
    let rows = collect(&p.buf, &IngestOptions::default());
    let got: Vec<_> = rows
        .http
        .iter()
        .map(|h| (h.uri.clone(), h.status, h.resp_bytes))
        .collect();
    assert_eq!(
        got,
        vec![
            (Some("/a".to_string()), Some(200), 3000),
            (Some("/b".to_string()), Some(404), 0)
        ]
    );
    assert_eq!(rows.flows[0].app_proto.as_deref(), Some("http"));
}

#[test]
fn cancel_stops_without_finish() {
    let cap = mixed_pcap(3, 16, 400_000);
    let path = std::env::temp_dir().join(format!("walleye-ingest-cancel-{}", std::process::id()));
    std::fs::write(&path, &cap).expect("write");
    let mut s = CollectSink::default();
    let cancel = AtomicBool::new(true);
    let e = ingest(
        &path,
        SHA,
        &mut s,
        &IngestOptions::default(),
        &mut |_| {},
        &cancel,
    )
    .expect_err("cancelled");
    std::fs::remove_file(&path).expect("rm");
    assert_eq!(e.code, ErrorCode::Cancelled);
    assert!(s.finished.is_none());
}

#[test]
fn bad_inputs_are_errors_not_panics() {
    let o = IngestOptions::default();
    for bytes in [
        &b""[..],
        b"abc",
        b"not a capture at all",
        &[0xd4, 0xc3, 0xb2, 0xa1, 2, 0],
    ] {
        let e = ingest_bytes(bytes, SHA, &mut NullSink::default(), &o).expect_err("bad");
        assert_eq!(e.code, ErrorCode::BadCapture, "{bytes:?}");
    }
    let e = ingest_bytes(&http_fixture(), "xyz", &mut NullSink::default(), &o).expect_err("sha");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    // Header only: a valid, empty capture.
    let empty = Pcap::new(1).buf;
    let cap = ingest_bytes(&empty, SHA, &mut NullSink::default(), &o).expect("empty ok");
    assert_eq!((cap.frame_count, cap.first_ts, cap.last_ts), (0, 0, 0));
    // Nanosecond pcap.
    let mut ns = Pcap::new_ns(1);
    ns.record(
        1_700_000_000,
        123_456_789,
        &eth_udp4([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, b"z"),
        43,
    );
    let cap = ingest_bytes(&ns.buf, SHA, &mut NullSink::default(), &o).expect("ns");
    assert_eq!(cap.first_ts, 1_700_000_000_123_456);
    let e = ingest(
        std::path::Path::new("/nonexistent/x.pcap"),
        SHA,
        &mut NullSink::default(),
        &o,
        &mut |_| {},
        &AtomicBool::new(false),
    )
    .expect_err("missing");
    assert_eq!(e.code, ErrorCode::Io);
}

fn find<'a>(
    nodes: &'a [walleye_core::ipc::DecodeNode],
    field: &str,
) -> Option<&'a walleye_core::ipc::DecodeNode> {
    for n in nodes {
        if n.field.as_deref() == Some(field) {
            return Some(n);
        }
        if let Some(x) = find(&n.children, field) {
            return Some(x);
        }
    }
    None
}

#[test]
fn decode_tree_has_fields_and_ranges() {
    let q = dns_query(0x1111, "www.example.com", 1);
    let frame = eth_udp4([10, 0, 0, 5], 51000, [10, 0, 0, 53], 53, &q);
    let t = decode_frame(1, &frame);
    let src = find(&t, "src_ip").expect("src_ip");
    assert_eq!(src.value.as_deref(), Some("10.0.0.5"));
    let r = src.range.expect("range");
    assert_eq!((r.start, r.len), (26, 4));
    assert_eq!(&frame[26..30], &[10, 0, 0, 5]);
    let dq = find(&t, "dns.query").expect("dns.query");
    assert_eq!(dq.value.as_deref(), Some("www.example.com"));
    let r = dq.range.expect("range");
    assert_eq!(
        frame[r.start as usize], 3,
        "range starts at the first label"
    );
    assert_eq!(
        find(&t, "dst_port").and_then(|n| n.value.as_deref()),
        Some("53")
    );

    // HTTP request + TLS ClientHello from the fixtures decode with fields.
    let mut h = Tcp::new(([10, 0, 0, 5], 50000), ([1, 2, 3, 4], 80), T0);
    h.client(b"GET /x HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ua\r\n\r\n");
    let t = decode_frame(1, &h.frames[0].1);
    assert_eq!(
        find(&t, "http.host").and_then(|n| n.value.as_deref()),
        Some("example.com")
    );
    assert_eq!(
        find(&t, "http.uri").and_then(|n| n.value.as_deref()),
        Some("/x")
    );
    let flags = find(&t, "frame.tcp_flags").expect("flags");
    assert_eq!(flags.value.as_deref(), Some("0x18 [PSH, ACK]"));

    let mut s = Tcp::new(([10, 0, 0, 5], 50000), ([1, 2, 3, 4], 443), T0);
    s.client(&tls_record(
        22,
        &client_hello(&HelloSpec {
            sni: Some("a.example"),
            alpn: &["h2"],
            ciphers: &[0x1301],
            versions: &[0x0304],
            sig_algs: &[0x0403],
            other_exts: &[],
        }),
    ));
    let t = decode_frame(1, &s.frames[0].1);
    assert_eq!(
        find(&t, "tls.sni").and_then(|n| n.value.as_deref()),
        Some("a.example")
    );
    assert!(
        find(&t, "tls.ja4")
            .and_then(|n| n.value.as_deref())
            .is_some_and(|j| j.starts_with("t13d0104h2_"))
    );

    // Truncated IPv4 gets a warning instead of a panic.
    let t = decode_frame(1, &frame[..20]);
    assert!(t.iter().any(|n| n.warning.is_some()));
    // Raw IP link type.
    let t = decode_frame(101, &frame[14..]);
    assert!(find(&t, "dns.query").is_some());
}

#[test]
fn read_frame_and_hash_file() {
    let bytes = dns_fixture();
    let path = std::env::temp_dir().join(format!("walleye-ingest-read-{}", std::process::id()));
    std::fs::write(&path, &bytes).expect("write");
    let mut s = CollectSink::default();
    ingest(
        &path,
        SHA,
        &mut s,
        &IngestOptions::default(),
        &mut |_| {},
        &AtomicBool::new(false),
    )
    .expect("ingest");
    for f in &s.rows.frames {
        let data = read_frame(&path, f.file_offset, f.caplen).expect("read");
        let start = usize::try_from(f.file_offset).expect("off");
        assert_eq!(data, bytes[start..start + f.caplen as usize]);
    }
    assert!(read_frame(&path, bytes.len() as u64 - 2, 10).is_err());
    assert!(read_frame(&path, 0, u32::MAX).is_err());

    let mut seen = 0;
    let h = hash_file(&path, &mut |n| seen = n).expect("hash");
    std::fs::remove_file(&path).expect("rm");
    assert_eq!(seen, bytes.len() as u64);
    assert_eq!(h.len(), 64);
    // SHA-256("abc") known answer.
    let p2 = std::env::temp_dir().join(format!("walleye-ingest-abc-{}", std::process::id()));
    std::fs::write(&p2, b"abc").expect("write");
    let h = hash_file(&p2, &mut |_| {}).expect("hash");
    std::fs::remove_file(&p2).expect("rm");
    assert_eq!(
        h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Browser-sized ClientHello (X25519MLKEM768 key share, 1216 + 32 bytes) that
/// spans two MSS-sized TCP segments must still yield SNI and JA4; the same
/// segments out of order are dropped (no row), never misparsed.
#[test]
fn clienthello_spanning_two_segments() {
    let mut share = Vec::new();
    share.extend_from_slice(&0x11ecu16.to_be_bytes()); // X25519MLKEM768
    share.extend_from_slice(&1216u16.to_be_bytes());
    share.extend(std::iter::repeat_n(0x42u8, 1216));
    share.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
    share.extend_from_slice(&32u16.to_be_bytes());
    share.extend(std::iter::repeat_n(0x24u8, 32));
    let mut ks = u16::try_from(share.len())
        .expect("len")
        .to_be_bytes()
        .to_vec();
    ks.extend_from_slice(&share);
    let spec = HelloSpec {
        sni: Some("www.google.com"),
        alpn: &["h2", "http/1.1"],
        ciphers: &[0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
        versions: &[0x3a3a, 0x0304, 0x0303],
        sig_algs: &[0x0403, 0x0804, 0x0401],
        other_exts: &[0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x002d],
    };
    let rec = tls_record(22, &client_hello_with(&spec, &[(0x0033, ks)]));
    assert!(rec.len() > 1300, "{}", rec.len());
    let ch = walleye_ingest::parse_tls_client_hello(&rec).expect("parse");
    let want = walleye_ingest::ja4(&ch, 't');

    let build = |reorder: bool| {
        let mut t = Tcp::new(([10, 0, 0, 5], 52000), ([142, 250, 0, 1], 443), T0);
        t.handshake();
        t.client(&rec[..1000]);
        t.client(&rec[1000..]);
        let mut frames = t.frames.clone();
        if reorder {
            frames.swap(3, 4);
        }
        let mut p = Pcap::new(1);
        p.add(&frames);
        collect(&p.buf, &IngestOptions::default())
    };
    let rows = build(false);
    assert_eq!(rows.tls.len(), 1);
    let r = &rows.tls[0];
    assert_eq!(r.sni.as_deref(), Some("www.google.com"));
    assert_eq!(r.ja4.as_deref(), Some(want.as_str()));
    assert!(want.starts_with("t13d0511h2_"), "{want}");
    assert_eq!(
        r.frame_no, 4,
        "row points at the segment where the record starts"
    );

    let rows = build(true);
    assert!(
        rows.tls.is_empty(),
        "out-of-order segments are dropped, not misparsed"
    );
}
