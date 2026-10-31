//! IndexWriter + Index end to end on small hand-built and synthetic data.

mod synth;

use std::path::{Path, PathBuf};

use walleye_core::{
    CaptureFormat, CaptureRow, Direction, DnsRow, ErrorCode, Evidence, Finding, FlowRow, FrameRow,
    HttpRow, Ioc, IocType, Reason, TlsRow,
    ipc::{
        FindingsFilter, QueryRequest, RowSet, Sort, SuggestionKind, TimeRange, TimelineRequest,
        View,
    },
    sink::{Checkpoint, DetectSource, IndexSink, RecordBatch, ResultSink},
};
use walleye_index::{Index, IndexWriter};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "walleye-index-test-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).expect("tmp");
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn capture(sha: &str) -> CaptureRow {
    CaptureRow {
        capture_id: sha[..16].to_string(),
        path: "/x.pcap".into(),
        sha256: sha.to_string(),
        size_bytes: 1000,
        format: CaptureFormat::Pcap,
        first_ts: 1_000_000,
        last_ts: 1_000_000,
        link_type: 1,
        frame_count: 0,
    }
}

const SHA: &str = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd";

fn flow(
    id: u64,
    src: &str,
    dst: &str,
    dport: u16,
    app: Option<&str>,
    ts: i64,
    bytes: u64,
) -> FlowRow {
    FlowRow {
        flow_id: id,
        ts_start: ts,
        ts_end: ts + 5_000_000,
        src_ip: src.into(),
        src_port: 40000 + id as u16,
        dst_ip: dst.into(),
        dst_port: dport,
        proto: if dport == 53 { 17 } else { 6 },
        app_proto: app.map(str::to_string),
        bytes_up: bytes,
        bytes_down: bytes / 2,
        pkts_up: 2,
        pkts_down: 1,
        first_frame: id * 3 - 2,
        last_frame: id * 3,
    }
}

fn frames_for(f: &FlowRow) -> Vec<FrameRow> {
    (0..3)
        .map(|i| FrameRow {
            frame_no: f.first_frame + i,
            ts: f.ts_start + i as i64 * 1000,
            file_offset: 40 + (f.first_frame + i) * 100,
            caplen: 60,
            wirelen: 60,
            flow_id: Some(f.flow_id),
            direction: Some(if i == 1 {
                Direction::Down
            } else {
                Direction::Up
            }),
            tcp_flags: if f.proto == 6 {
                Some([0x02, 0x12, 0x10][i as usize])
            } else {
                None
            },
            payload_len: if i == 2 { 10 } else { 0 },
            link_type: Some(1),
        })
        .collect()
}

type Dataset = (
    Vec<FlowRow>,
    Vec<FrameRow>,
    Vec<DnsRow>,
    Vec<HttpRow>,
    Vec<TlsRow>,
);

/// 6 flows over three hosts, with DNS/HTTP/TLS rows.
fn small_dataset() -> Dataset {
    let flows = vec![
        flow(1, "10.0.0.5", "10.0.0.2", 53, Some("dns"), 1_000_000, 40),
        flow(
            2,
            "10.0.0.5",
            "185.199.110.77",
            443,
            Some("tls"),
            2_000_000,
            2 << 20,
        ),
        flow(
            3,
            "10.0.0.23",
            "185.199.110.77",
            443,
            Some("tls"),
            3_000_000,
            500,
        ),
        flow(
            4,
            "10.0.0.23",
            "93.184.216.34",
            80,
            Some("http"),
            4_000_000,
            20_000,
        ),
        flow(5, "10.0.0.7", "2001:db8::1", 22, None, 5_000_000, 100),
        flow(6, "10.0.0.7", "2001:db9::1", 22, None, 6_000_000, 100),
    ];
    let frames: Vec<FrameRow> = flows.iter().flat_map(frames_for).collect();
    let dns = vec![
        DnsRow {
            ts: 1_000_000,
            flow_id: 1,
            frame_no: 1,
            trans_id: 7,
            is_response: false,
            query: "cdn-update.top".into(),
            qtype: "A".into(),
            rcode: None,
            answers: vec![],
            ttl: None,
        },
        DnsRow {
            ts: 1_001_000,
            flow_id: 1,
            frame_no: 2,
            trans_id: 7,
            is_response: true,
            query: "cdn-update.top".into(),
            qtype: "A".into(),
            rcode: Some("NOERROR".into()),
            answers: vec!["185.199.110.77".into(), "185.199.110.78".into()],
            ttl: Some(60),
        },
    ];
    let http = vec![HttpRow {
        ts: 4_000_000,
        flow_id: 4,
        frame_no: 10,
        method: Some("POST".into()),
        host: Some("example.com".into()),
        uri: Some("/up".into()),
        user_agent: Some("Mozilla/4.0 (compatible; MSIE 8.0)".into()),
        status: Some(404),
        resp_frame_no: Some(11),
        req_bytes: 20_000,
        resp_bytes: 10,
    }];
    let tls = vec![TlsRow {
        ts: 3_000_000,
        flow_id: 3,
        frame_no: 7,
        sni: Some("windowsupdate.com".into()),
        version: Some("TLS 1.2".into()),
        ja4: Some("t12d1516h2_aaa_bbb".into()),
        ja4s: None,
        cert_subject: Some("CN=x".into()),
        cert_issuer: Some("CN=x".into()),
        cert_serial: Some("01".into()),
        cert_self_signed: Some(true),
        cert_not_before: None,
        cert_not_after: None,
    }];
    (flows, frames, dns, http, tls)
}

fn build_small(dir: &Path) -> Index {
    let (flows, frames, dns, http, tls) = small_dataset();
    let mut w = IndexWriter::create(dir).expect("create");
    assert!(w.begin(&capture(SHA)).expect("begin").is_none());
    w.write(RecordBatch::Frames(frames.clone()))
        .expect("frames");
    w.write(RecordBatch::Flows(flows)).expect("flows");
    w.write(RecordBatch::Dns(dns)).expect("dns");
    w.write(RecordBatch::Http(http)).expect("http");
    w.write(RecordBatch::Tls(tls)).expect("tls");
    let mut cap = capture(SHA);
    cap.frame_count = frames.len() as u64;
    cap.last_ts = 6_010_000;
    w.finish(&cap).expect("finish");
    Index::open(dir).expect("open")
}

fn req(view: View, filter: &str) -> QueryRequest {
    QueryRequest {
        filter: filter.into(),
        view,
        time_range: None,
        hosts: vec![],
        flow_ids: vec![],
        sort: None,
        limit: 100,
        cursor: None,
    }
}

fn flow_ids(idx: &Index, filter: &str) -> Vec<u64> {
    match idx.query(&req(View::Flows, filter)).expect(filter).data {
        RowSet::Flows(v) => v.iter().map(|f| f.flow_id).collect(),
        _ => unreachable!(),
    }
}

#[test]
fn writer_creates_layout_and_open_requires_manifest() {
    let d = TempDir::new("layout");
    assert_eq!(
        Index::open(d.path()).err().map(|e| e.code),
        Some(ErrorCode::NotFound)
    );
    let idx = build_small(d.path());
    for t in [
        "frames", "flows", "dns", "http", "tls", "files", "findings", "iocs",
    ] {
        assert!(d.path().join(t).join("data-0.parquet").exists(), "{t}");
    }
    assert!(d.path().join("manifest.json").exists());
    assert!(!d.path().join("checkpoint.json").exists());
    assert_eq!(idx.capture().expect("cap").frame_count, 18);
}

#[test]
fn filters_select_the_right_flows() {
    let d = TempDir::new("filters");
    let idx = build_small(d.path());
    assert_eq!(flow_ids(&idx, ""), vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(flow_ids(&idx, "host 10.0.0.23"), vec![3, 4]);
    assert_eq!(flow_ids(&idx, "bytes_up > 1MB"), vec![2]);
    assert_eq!(flow_ids(&idx, "dns.query ~ \"*.top\""), vec![1]);
    assert_eq!(
        flow_ids(&idx, "dns.query ~ \"*.TOP\""),
        vec![1],
        "glob is case-insensitive"
    );
    assert_eq!(
        flow_ids(&idx, "tls.sni ~ \"*update*\" and bytes_down < 10KB"),
        vec![3]
    );
    assert_eq!(flow_ids(&idx, "http.user_agent ~ \"*MSIE*\""), vec![4]);
    // NULL app_proto counts as "not tls".
    assert_eq!(
        flow_ids(&idx, "not app_proto == tls and proto == tcp"),
        vec![4, 5, 6]
    );
    assert_eq!(flow_ids(&idx, "app_proto != tls"), vec![1, 4, 5, 6]);
    assert_eq!(
        flow_ids(&idx, "src_ip == 10.0.0.0/8 and not dst_ip == 10.0.0.0/8"),
        vec![2, 3, 4, 5, 6]
    );
    assert_eq!(flow_ids(&idx, "dst_ip == 185.199.110.0/23"), vec![2, 3]);
    assert_eq!(flow_ids(&idx, "dst_ip == 2001:db8::/32"), vec![5]);
    assert_eq!(flow_ids(&idx, "host 2001:db8::1"), vec![5]);
    assert_eq!(flow_ids(&idx, "port 443 or port 80"), vec![2, 3, 4]);
    assert_eq!(flow_ids(&idx, "dns.answer == 185.199.110.78"), vec![1]);
    assert_eq!(flow_ids(&idx, "dns.answer ~ \"185.199.*\""), vec![1]);
    assert_eq!(flow_ids(&idx, "duration >= 5s"), vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(flow_ids(&idx, "flow_id in [2, 4, 99]"), vec![2, 4]);
    assert_eq!(
        flow_ids(
            &idx,
            "host 10.0.0.5 and dns.query ~ \"*.top\" and bytes_up > 1MB and not app_proto == tls"
        ),
        Vec::<u64>::new()
    );
    // Cross-table from the other side.
    let p = idx.query(&req(View::Dns, "bytes_up > 10")).expect("dns");
    assert_eq!(p.data.len(), 2);
    let p = idx
        .query(&req(View::Frames, "frame.tcp_flags == 2"))
        .expect("frames");
    assert_eq!(p.data.len(), 5);
    let p = idx
        .query(&req(View::Tls, "tls.cert_self_signed == true"))
        .expect("tls");
    assert_eq!(p.data.len(), 1);
    let p = idx
        .query(&req(
            View::Http,
            "http.method == POST and http.req_bytes > 10KB",
        ))
        .expect("http");
    assert_eq!(p.data.len(), 1);
    let sql = p.sql.expect("sql");
    assert!(!sql.contains("POST") && sql.contains('?'), "{sql}");
}

#[test]
fn scope_hosts_flow_ids_time_range() {
    let d = TempDir::new("scope");
    let idx = build_small(d.path());
    let mut r = req(View::Flows, "");
    r.hosts = vec!["10.0.0.7".into(), "185.199.110.77".into()];
    r.flow_ids = vec![2, 5, 6];
    r.time_range = Some(TimeRange {
        start: 1_500_000,
        end: 5_500_000,
    });
    match idx.query(&r).expect("q").data {
        RowSet::Flows(v) => assert_eq!(v.iter().map(|f| f.flow_id).collect::<Vec<_>>(), vec![2, 5]),
        _ => unreachable!(),
    }
    let mut r = req(View::Frames, "");
    r.hosts = vec!["10.0.0.23".into()];
    r.time_range = Some(TimeRange {
        start: 3_000_000,
        end: 3_001_500,
    });
    assert_eq!(idx.query(&r).expect("frames").data.len(), 2);
    let mut r = req(View::Flows, "");
    r.hosts = vec!["not-an-ip'); DROP".into()];
    assert_eq!(
        idx.query(&r).expect_err("bad host").code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn sort_allowlist_and_limits() {
    let d = TempDir::new("sort");
    let idx = build_small(d.path());
    let mut r = req(View::Flows, "");
    r.sort = Some(Sort {
        column: "bytes_up\" DESC; DROP TABLE flows; --".into(),
        desc: false,
    });
    assert_eq!(
        idx.query(&r).expect_err("inject").code,
        ErrorCode::InvalidArgument
    );
    r.sort = Some(Sort {
        column: "bytes_up".into(),
        desc: true,
    });
    match idx.query(&r).expect("sorted").data {
        RowSet::Flows(v) => assert_eq!(v[0].flow_id, 2),
        _ => unreachable!(),
    }
    r.limit = 0;
    assert_eq!(
        idx.query(&r).expect_err("limit").code,
        ErrorCode::InvalidArgument
    );
    r.limit = 10_001;
    assert!(idx.query(&r).is_err());
    let e = idx
        .query(&req(View::Flows, "bytes_up ~ \"x\""))
        .expect_err("type");
    assert_eq!(e.code, ErrorCode::InvalidFilter);
    assert!(e.span.is_some());
}

fn synth_index(dir: &Path, frames: u64) -> (Index, synth::Stats) {
    let mut w = IndexWriter::create(dir).expect("create");
    let (_, stats) = synth::generate(
        &mut w,
        &synth::Scale {
            frames,
            checkpoint_frames: frames / 4,
            seed: 7,
        },
    )
    .expect("generate");
    (Index::open(dir).expect("open"), stats)
}

fn page_keys(d: &RowSet) -> Vec<(u64, u64)> {
    match d {
        RowSet::Flows(v) => v.iter().map(|f| (f.flow_id, 0)).collect(),
        RowSet::Dns(v) => v
            .iter()
            .map(|r| (r.flow_id, r.frame_no * 1000 + u64::from(r.is_response)))
            .collect(),
        RowSet::Frames(v) => v.iter().map(|f| (f.frame_no, 0)).collect(),
        RowSet::Http(v) => v.iter().map(|r| (r.flow_id, r.frame_no)).collect(),
        RowSet::Tls(v) => v.iter().map(|r| (r.flow_id, r.frame_no)).collect(),
        RowSet::Files(v) => v.iter().map(|r| (r.flow_id, r.frame_no)).collect(),
    }
}

/// Paging with any sort column returns exactly the rows of one big page, in
/// the same order, with no duplicates or gaps.
#[test]
fn cursor_pagination_is_stable_for_every_sort() {
    let d = TempDir::new("paging");
    let (idx, stats) = synth_index(d.path(), 20_000);
    assert_eq!(stats.frames, 20_000);
    let cases: &[(View, &str, &str)] = &[
        (View::Flows, "", "ts_start"),
        (View::Flows, "", "app_proto"),
        (View::Flows, "", "dst_port"),
        (View::Flows, "tcp", "bytes_down"),
        (View::Dns, "", "qtype"),
        (View::Dns, "", "rcode"),
        (View::Dns, "", "answers"),
        (View::Dns, "", "ttl"),
        (View::Frames, "", "tcp_flags"),
        (View::Http, "", "status"),
        (View::Tls, "", "cert_self_signed"),
        (View::Files, "", "size_bytes"),
    ];
    for &(view, filter, col) in cases {
        for desc in [false, true] {
            let mut r = req(view, filter);
            r.sort = Some(Sort {
                column: col.into(),
                desc,
            });
            r.limit = 10_000;
            let all = idx.query(&r).expect("all");
            let want = page_keys(&all.data);
            let total = all.total.expect("total");
            r.limit = 97;
            let mut got = Vec::new();
            let mut pages = 0;
            loop {
                let p = idx.query(&r).expect("page");
                assert_eq!(p.total, Some(total), "{view:?} {col}");
                got.extend(page_keys(&p.data));
                pages += 1;
                match p.next_cursor {
                    Some(c) => r.cursor = Some(c),
                    None => break,
                }
                assert!(pages < 10_000);
            }
            if want.len() < 10_000 {
                assert_eq!(got.len(), want.len(), "{view:?} {col} desc={desc}");
                assert_eq!(got, want, "{view:?} {col} desc={desc}");
            }
        }
    }
}

#[test]
fn cursors_are_bound_and_strictly_decoded() {
    let d = TempDir::new("cursor");
    let (idx, _) = synth_index(d.path(), 5_000);
    let mut r = req(View::Flows, "");
    r.limit = 10;
    let c = idx.query(&r).expect("p1").next_cursor.expect("more");
    let mut other = req(View::Flows, "tcp");
    other.limit = 10;
    other.cursor = Some(c.clone());
    assert_eq!(
        idx.query(&other).expect_err("foreign").code,
        ErrorCode::InvalidArgument
    );
    for bad in [
        "",
        "!!!",
        "eyJ2IjoxfQ",
        &"A".repeat(20_000),
        &c[..c.len() - 3],
    ] {
        r.cursor = Some(bad.to_string());
        assert_eq!(
            idx.query(&r).expect_err(bad).code,
            ErrorCode::InvalidArgument,
            "{bad}"
        );
    }
}

#[test]
fn timeline_buckets_by_initiator() {
    let d = TempDir::new("timeline");
    let idx = build_small(d.path());
    let finding = sample_finding("10.0.0.23", 77.0);
    let lanes = idx
        .timeline(
            &TimelineRequest {
                filter: String::new(),
                time_range: None,
                bucket_ms: 1000,
                max_lanes: 2,
            },
            &[finding],
        )
        .expect("timeline");
    assert_eq!(lanes.bucket_ms, 1000);
    let hosts: Vec<_> = lanes
        .lanes
        .iter()
        .map(|l| (l.host.as_str(), l.is_other, l.total))
        .collect();
    assert_eq!(
        hosts,
        vec![
            ("10.0.0.23", false, 2),
            ("10.0.0.5", false, 2),
            ("other", true, 2)
        ]
    );
    assert_eq!(lanes.lanes[0].max_score, Some(77.0));
    let five = &lanes.lanes[1].buckets;
    assert_eq!(five.len(), 2);
    assert_eq!((five[0].t, five[0].dns), (1_000_000, 1));
    assert_eq!(
        (five[1].t, five[1].bulk, five[1].tls),
        (2_000_000, 1, 0),
        "bulk wins over tls"
    );
    // Widening keeps ≤ 2000 buckets.
    let wide = idx
        .timeline(
            &TimelineRequest {
                filter: "tcp".into(),
                time_range: Some(TimeRange {
                    start: 0,
                    end: 10_000_000_000,
                }),
                bucket_ms: 1,
                max_lanes: 10,
            },
            &[],
        )
        .expect("wide");
    assert!(wide.bucket_ms >= 5_000);
    assert!(
        idx.timeline(
            &TimelineRequest {
                filter: "nope ==".into(),
                time_range: None,
                bucket_ms: 1,
                max_lanes: 1
            },
            &[]
        )
        .is_err()
    );
}

/// Hostile ranges and sizes return errors or results, never panic (the
/// release profile uses panic = "abort").
#[test]
fn extreme_arguments_do_not_panic() {
    let d = TempDir::new("extreme");
    let idx = build_small(d.path());
    let ranges = [
        Some(TimeRange {
            start: i64::MIN,
            end: i64::MAX,
        }),
        Some(TimeRange {
            start: i64::MAX,
            end: i64::MIN,
        }),
        Some(TimeRange { start: 0, end: 0 }),
        None,
    ];
    for tr in ranges {
        for bucket_ms in [0, 1, u64::MAX, 1 << 61] {
            for max_lanes in [0, 1, u32::MAX] {
                let _ = idx.timeline(
                    &TimelineRequest {
                        filter: String::new(),
                        time_range: tr,
                        bucket_ms,
                        max_lanes,
                    },
                    &[],
                );
            }
        }
        for view in walleye_index::filter::ALL_VIEWS {
            let _ = idx.query(&QueryRequest {
                time_range: tr,
                ..req(view, "")
            });
        }
    }
    for id in [0, u64::MAX, 1 << 63] {
        let _ = idx.frame(id);
        let _ = idx.flow(id);
        let _ = idx.flow_frames(id);
    }
    let mut r = req(View::Flows, "");
    r.flow_ids = vec![u64::MAX];
    assert!(idx.query(&r).is_err());
    let f = FindingsFilter {
        min_score: Some(f64::NAN),
        time_range: Some(TimeRange {
            start: i64::MIN,
            end: i64::MAX,
        }),
        ..Default::default()
    };
    let _ = idx.findings(Some(&f));
    for (s, c) in [("", u32::MAX), ("\"", 1), ("\"\\\"", 3), ("é\"é", 2)] {
        let _ = idx.autocomplete(s, c);
    }
}

#[test]
fn frame_and_flow_lookups() {
    let d = TempDir::new("lookup");
    let idx = build_small(d.path());
    let fr = idx.frame(7).expect("frame");
    assert_eq!((fr.flow_id, fr.tcp_flags), (Some(3), Some(0x02)));
    assert_eq!(idx.frame(9999).expect_err("nf").code, ErrorCode::NotFound);
    assert_eq!(idx.flow(4).expect("flow").dst_port, 80);
    let refs = idx.flow_frames(3).expect("ff");
    assert_eq!(
        refs.iter().map(|r| r.frame_no).collect::<Vec<_>>(),
        vec![7, 8, 9]
    );
    assert_eq!(refs[0].summary, "TCP 40003 → 443 [SYN] len=0");
    assert_eq!(refs[1].summary, "TCP 443 → 40003 [SYN, ACK] len=0");
    let dns = idx.flow_frames(1).expect("dns");
    assert_eq!(dns[2].summary, "UDP 40001 → 53 DNS len=10");
    assert_eq!(
        idx.flow_frames(77).expect_err("nf").code,
        ErrorCode::NotFound
    );
}

fn sample_finding(entity: &str, score: f64) -> Finding {
    Finding {
        finding_id: format!("{:0>16}", entity.len()),
        title: "Periodic outbound connections".into(),
        detector: "beaconing".into(),
        entity_type: "host".into(),
        entity: entity.into(),
        score,
        attack_technique: Some("T1071".into()),
        ts_first: 1_000_000,
        ts_last: 9_000_000,
        reasons: vec![Reason {
            rule_id: "beacon.periodic".into(),
            signal: "regularity".into(),
            value: 0.97,
            unit: Some("ratio".into()),
            weight: 50.0,
            explanation: "x contacted y 'quoted' \"twice\"".into(),
            attack_technique: Some("T1071".into()),
            evidence: Evidence {
                flow_ids: vec![3],
                frame_nos: vec![7],
                truncated: false,
                total: 1,
            },
        }],
        verdict: None,
    }
}

#[test]
fn results_roundtrip_and_replace() {
    let d = TempDir::new("results");
    let idx = build_small(d.path());
    assert!(idx.findings(None).expect("empty").is_empty());
    let a = sample_finding("10.0.0.23", 80.0);
    let mut b = sample_finding("10.0.0.5", 40.0);
    b.finding_id = "ffffffffffffffff".into();
    b.detector = "dns_entropy".into();
    idx.put_findings(&[b.clone(), a.clone()]).expect("put");
    assert_eq!(idx.findings(None).expect("all"), vec![a.clone(), b.clone()]);
    let f = FindingsFilter {
        min_score: Some(50.0),
        ..Default::default()
    };
    assert_eq!(idx.findings(Some(&f)).expect("min"), vec![a.clone()]);
    let f = FindingsFilter {
        detector: Some("dns_entropy' OR '1'='1".into()),
        ..Default::default()
    };
    assert!(idx.findings(Some(&f)).expect("inj").is_empty());
    let f = FindingsFilter {
        entity: Some("10.0.0.5".into()),
        time_range: Some(TimeRange {
            start: 0,
            end: 2_000_000,
        }),
        ..Default::default()
    };
    assert_eq!(idx.findings(Some(&f)).expect("entity"), vec![b.clone()]);
    idx.put_findings(std::slice::from_ref(&a)).expect("replace");
    assert_eq!(idx.findings(None).expect("replaced"), vec![a.clone()]);
    let ioc = Ioc {
        ioc_id: "0123456789abcdef".into(),
        ioc_type: IocType::Domain,
        value: "cdn-update.top".into(),
        defanged: "cdn-update[.]top".into(),
        source_finding_id: Some(a.finding_id.clone()),
        first_seen: 1_000_000,
        evidence: Evidence {
            flow_ids: vec![1],
            frame_nos: vec![1, 2],
            truncated: false,
            total: 2,
        },
        allowlisted: false,
        allowlist_reason: None,
    };
    idx.put_iocs(std::slice::from_ref(&ioc)).expect("iocs");
    assert_eq!(idx.iocs().expect("read"), vec![ioc.clone()]);
    drop(idx);
    // Results survive reopening.
    let idx = Index::open(d.path()).expect("reopen");
    assert_eq!(idx.findings(None).expect("persisted"), vec![a]);
    assert_eq!(idx.iocs().expect("persisted"), vec![ioc]);
    assert_eq!(
        std::fs::read_dir(d.path().join("findings"))
            .expect("dir")
            .count(),
        1,
        "old generation removed"
    );
}

#[test]
fn detect_source_streams_in_time_order() {
    let d = TempDir::new("detect");
    let (idx, stats) = synth_index(d.path(), 10_000);
    let mut last = i64::MIN;
    let mut n = 0u64;
    idx.for_each_flow(&mut |f| {
        assert!(f.ts_start >= last);
        last = f.ts_start;
        n += 1;
    })
    .expect("flows");
    assert_eq!(n, stats.flows);
    let mut n = 0u64;
    idx.for_each_dns(&mut |_| n += 1).expect("dns");
    assert_eq!(n, stats.dns);
    let mut n = 0u64;
    idx.for_each_tls(&mut |_| n += 1).expect("tls");
    assert_eq!(n, stats.tls);
    let mut n = 0u64;
    idx.for_each_http(&mut |_| n += 1).expect("http");
    assert_eq!(n, stats.http);
    assert_eq!(
        DetectSource::capture(&idx).expect("cap").frame_count,
        10_000
    );
}

fn count(idx: &Index, view: View) -> u64 {
    idx.query(&QueryRequest {
        limit: 1,
        ..req(view, "")
    })
    .expect("count")
    .total
    .expect("total")
}

/// The sink invariant: after a checkpoint is accepted, everything before it is
/// durable and everything after it is discarded on resume.
#[test]
fn checkpoint_resume_discards_uncommitted_rows() {
    let d = TempDir::new("resume");
    let (flows, frames, dns, _, _) = small_dataset();
    {
        let mut w = IndexWriter::create(d.path()).expect("create");
        assert!(w.begin(&capture(SHA)).expect("begin").is_none());
        w.write(RecordBatch::Frames(frames[..6].to_vec()))
            .expect("w");
        w.write(RecordBatch::Flows(flows[..2].to_vec())).expect("w");
        w.checkpoint(Checkpoint {
            file_offset: 640,
            frames_emitted: 6,
            next_flow_id: 3,
            state: vec![0, 255, 7],
        })
        .expect("cp");
        // Written after the checkpoint, then the process "dies".
        w.write(RecordBatch::Frames(frames[6..].to_vec()))
            .expect("w");
        w.write(RecordBatch::Dns(dns.clone())).expect("w");
        w.checkpoint(Checkpoint {
            file_offset: 9,
            frames_emitted: 9,
            next_flow_id: 9,
            state: vec![],
        })
        .map(|_| ())
        .ok();
        // Simulate a crash mid-segment: an uncommitted segment and a tmp file.
        std::fs::write(d.path().join("frames").join("seg-000099.parquet"), b"junk").expect("junk");
        std::fs::write(d.path().join("dns").join("seg-000001.parquet.tmp"), b"junk").expect("junk");
    }
    // Roll the checkpoint file back to the first checkpoint (as if the
    // second one had not been accepted) by re-running from scratch.
    let d2 = TempDir::new("resume2");
    {
        let mut w = IndexWriter::create(d2.path()).expect("create");
        w.begin(&capture(SHA)).expect("begin");
        w.write(RecordBatch::Frames(frames[..6].to_vec()))
            .expect("w");
        w.write(RecordBatch::Flows(flows[..2].to_vec())).expect("w");
        w.checkpoint(Checkpoint {
            file_offset: 640,
            frames_emitted: 6,
            next_flow_id: 3,
            state: vec![0, 255, 7],
        })
        .expect("cp");
        w.write(RecordBatch::Frames(frames[6..].to_vec()))
            .expect("w");
        w.write(RecordBatch::Dns(dns.clone())).expect("w");
        // Crash before the next checkpoint: staged rows are lost, plus a
        // half-written segment is on disk.
        std::fs::write(d2.path().join("frames").join("seg-000001.parquet"), b"junk").expect("junk");
    }
    let mut w = IndexWriter::create(d2.path()).expect("create");
    let cp = w.begin(&capture(SHA)).expect("begin").expect("resumes");
    assert_eq!(
        (
            cp.file_offset,
            cp.frames_emitted,
            cp.next_flow_id,
            cp.state.clone()
        ),
        (640, 6, 3, vec![0, 255, 7])
    );
    assert!(
        !d2.path().join("frames").join("seg-000001.parquet").exists(),
        "uncommitted segment deleted"
    );
    // Ingest continues from the checkpoint.
    w.write(RecordBatch::Frames(frames[6..].to_vec()))
        .expect("w");
    w.write(RecordBatch::Flows(flows[2..].to_vec())).expect("w");
    w.write(RecordBatch::Dns(dns.clone())).expect("w");
    w.finish(&capture(SHA)).expect("finish");
    let idx = Index::open(d2.path()).expect("open");
    assert_eq!(count(&idx, View::Frames), 18, "no duplicates, no loss");
    assert_eq!(count(&idx, View::Flows), 6);
    assert_eq!(count(&idx, View::Dns), 2);

    // A different capture (sha) never resumes and wipes old data.
    let mut w = IndexWriter::create(d.path()).expect("create");
    let other = "1111111111111111222222222222222233333333333333334444444444444444";
    assert!(w.begin(&capture(other)).expect("begin").is_none());
    w.finish(&capture(other)).expect("finish");
    let idx = Index::open(d.path()).expect("open");
    assert_eq!(count(&idx, View::Frames), 0);
    assert_eq!(idx.capture().expect("cap").sha256, other);
}

#[test]
fn autocomplete_uses_index_values() {
    let d = TempDir::new("ac");
    let idx = build_small(d.path());
    let s = idx.autocomplete("host 10.0.0.2", 13).expect("host");
    let labels: Vec<_> = s
        .iter()
        .filter(|x| x.kind == SuggestionKind::Value)
        .map(|x| x.label.as_str())
        .collect();
    assert!(
        labels.contains(&"10.0.0.23") && labels.contains(&"10.0.0.2"),
        "{labels:?}"
    );
    assert!(
        s.iter()
            .all(|x| x.replace_start == 5 && x.replace_end == 13)
    );
    let s = idx.autocomplete("dns.query == ", 13).expect("vals");
    let v = s
        .iter()
        .find(|x| x.label == "cdn-update.top")
        .expect("value");
    assert_eq!(v.insert_text, "cdn-update.top");
    let s = idx
        .autocomplete("http.user_agent ~ \"Moz", 22)
        .expect("quoted");
    let v = s
        .iter()
        .find(|x| x.kind == SuggestionKind::Value)
        .expect("ua");
    assert_eq!(v.insert_text, "\"Mozilla/4.0 (compatible; MSIE 8.0)\"");
    assert_eq!(v.replace_start, 18);
    let s = idx.autocomplete("tls.sni == ", 11).expect("sni");
    assert!(s.iter().any(|x| x.label == "windowsupdate.com"));
    let s = idx.autocomplete("", 0).expect("empty");
    assert!(s.iter().any(|x| x.kind == SuggestionKind::Field));
    idx.autocomplete("\u{0}\"\\'", 99).expect("hostile");
}

#[test]
fn concurrent_reads() {
    let d = TempDir::new("concurrent");
    let (idx, _) = synth_index(d.path(), 5_000);
    let idx = std::sync::Arc::new(idx);
    let hs: Vec<_> = (0..8)
        .map(|i| {
            let idx = idx.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    let r = QueryRequest {
                        limit: 50,
                        ..req(View::Flows, if i % 2 == 0 { "tcp" } else { "dns" })
                    };
                    assert!(idx.query(&r).expect("q").total.expect("t") > 0);
                }
            })
        })
        .collect();
    for h in hs {
        h.join().expect("thread");
    }
}
