//! Scale: ~1 M flows and ~2 M DNS rows must run in a few seconds with
//! bounded memory. The full-size test is `#[ignore]`d (debug builds are
//! slow); run it with
//!
//! ```sh
//! cargo test -p walleye-detect --release --test scale -- --ignored --nocapture
//! ```
//!
//! The default-run test uses 1/10 of the size and checks the same things.

mod common;

use std::time::Instant;

use common::*;
use walleye_core::sink::MemorySource;
use walleye_core::{DnsRow, FlowRow};
use walleye_detect::run;

/// `n_flows` flows: half web flows from 2 000 internal hosts to 50 000
/// external addresses, half DNS flows (two lookups = 4 rows each), plus
/// one 60 s beacon host that must still rank first.
fn big(n_flows: u64) -> MemorySource {
    let mut rng = Rng::new(99);
    let mut src = MemorySource::default();
    let span_us: i64 = 8 * 3600 * S;
    let step = span_us / n_flows as i64;
    let mut frame = 0u64;
    let beacon_every = (60 * S / step).max(1) as u64;
    let parents: Vec<String> = (0..5000).map(|i| format!("site{i}.com")).collect();
    let mut q = String::new();
    for i in 1..=n_flows {
        let ts = T0 + i as i64 * step;
        let first = frame + 1;
        frame += 4;
        let (src_ip, dst_ip, dport, app) = if i % beacon_every == 0 {
            (
                "10.200.0.1".to_string(),
                "185.199.110.77".to_string(),
                443,
                "tls",
            )
        } else if i % 2 == 0 {
            let h = rng.int(0, 1999);
            let d = rng.int(0, 49_999);
            (
                format!(
                    "10.{}.{}.{}",
                    10 + h / 250 / 250,
                    (h / 250) % 250,
                    h % 250 + 1
                ),
                format!("{}.{}.{}.{}", 23 + d % 100, (d / 100) % 250, d % 250 + 1, 7),
                443,
                "tls",
            )
        } else {
            let h = rng.int(0, 1999);
            (
                format!(
                    "10.{}.{}.{}",
                    10 + h / 250 / 250,
                    (h / 250) % 250,
                    h % 250 + 1
                ),
                RESOLVER.to_string(),
                53,
                "dns",
            )
        };
        if app == "dns" {
            // Two lookups per DNS flow (query + response each) → 4 rows.
            for (k, resp) in [(0u64, false), (1, true), (2, false), (3, true)] {
                if k % 2 == 0 {
                    let p = rng.pick(&parents).clone();
                    let sub = rng.int(0, 40);
                    q = format!("host{sub}.{p}");
                }
                src.dns.push(DnsRow {
                    ts: ts + k as i64 * 20_000,
                    flow_id: i,
                    frame_no: first + k,
                    trans_id: (i & 0xffff) as u16,
                    is_response: resp,
                    query: q.clone(),
                    qtype: "A".into(),
                    rcode: resp.then(|| {
                        if rng.chance(0.02) {
                            "NXDOMAIN"
                        } else {
                            "NOERROR"
                        }
                        .into()
                    }),
                    answers: if resp {
                        vec!["93.184.216.34".into()]
                    } else {
                        vec![]
                    },
                    ttl: resp.then_some(300),
                });
            }
        }
        src.flows.push(FlowRow {
            flow_id: i,
            ts_start: ts,
            ts_end: ts + 50_000,
            src_ip,
            src_port: 50_000,
            dst_ip,
            dst_port: dport,
            proto: if dport == 53 { 17 } else { 6 },
            app_proto: Some(app.into()),
            bytes_up: if dport == 53 {
                40
            } else {
                rng.lognorm(1500.0, 1.0)
            },
            bytes_down: if dport == 53 {
                80
            } else {
                rng.lognorm(30_000.0, 1.5)
            },
            pkts_up: 2,
            pkts_down: 2,
            first_frame: first,
            last_frame: first + 3,
        });
    }
    src
}

fn check(n_flows: u64, max_secs: Option<f64>) {
    let t = Instant::now();
    let src = big(n_flows);
    println!(
        "built {} flows, {} dns rows in {:.2}s",
        src.flows.len(),
        src.dns.len(),
        t.elapsed().as_secs_f64()
    );
    let rules = repo_rules();
    let allow = repo_allowlist();
    let t = Instant::now();
    let f = run(&src, &rules, &allow).expect("run");
    let secs = t.elapsed().as_secs_f64();
    println!("detect: {secs:.2}s, {} findings\n{}", f.len(), summary(&f));
    assert_eq!(
        rank(&f, "10.200.0.1"),
        Some(1),
        "beacon host must rank first at scale"
    );
    assert_evidence_valid(&src, &f[..f.len().min(20)]);
    if let Some(max) = max_secs {
        assert!(secs < max, "detect took {secs:.2}s (limit {max}s)");
    }
}

#[test]
fn scale_100k_flows() {
    check(100_000, None);
}

#[test]
#[ignore = "full size; run in release (see module docs)"]
fn scale_1m_flows_2m_dns() {
    // Release builds only: the limit is meaningless for an unoptimized build.
    let limit = if cfg!(debug_assertions) {
        None
    } else {
        Some(10.0)
    };
    check(1_000_000, limit);
}
