//! Scale benchmark: builds a synthetic index at 10 GB-capture scale through
//! `IndexWriter` (if not already built), then times the queries in
//! `tools/bench/queries.txt` plus timeline/lookup/autocomplete calls.
//!
//! ```text
//! cargo bench -p walleye-index --bench queries
//! WALLEYE_BENCH_FRAMES=14000000   frames to generate (default 14M ≈ 10 GB capture)
//! WALLEYE_BENCH_DIR=<dir>         index dir (default $WALLEYE_FIXTURES/index-bench-<frames>)
//! WALLEYE_BENCH_ITERS=20          timed runs per query (after one warm-up)
//! WALLEYE_BENCH_CLEAN=1           delete the index dir afterwards
//! ```
//! Data stays outside the repo (`$WALLEYE_FIXTURES`, default `~/.walleye-fixtures`).

#[path = "../tests/synth/mod.rs"]
mod synth;

use std::{path::PathBuf, time::Instant};

use walleye_core::ipc::{QueryRequest, TimelineRequest, View};
use walleye_index::{Index, IndexWriter};

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn dir_size(p: &std::path::Path) -> u64 {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                n += dir_size(&path);
            } else if let Ok(m) = e.metadata() {
                n += m.len();
            }
        }
    }
    n
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i.min(v.len() - 1)]
}

/// The view's wire name (`flows`, …, `wifi`, `wifi_aps`, `wifi_clients`).
fn view_of(s: &str) -> Option<View> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

fn time<F: FnMut()>(iters: u64, mut f: F) -> (f64, f64, f64) {
    f();
    let mut v: Vec<f64> = (0..iters)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    let max = v.iter().cloned().fold(0.0, f64::max);
    (pct(&mut v, 0.5), pct(&mut v, 0.95), max)
}

fn main() {
    let frames = env_u64("WALLEYE_BENCH_FRAMES", 14_000_000);
    let iters = env_u64("WALLEYE_BENCH_ITERS", 20).max(1);
    let fixtures = std::env::var("WALLEYE_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join(".walleye-fixtures")
        });
    let dir = std::env::var("WALLEYE_BENCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixtures.join(format!("index-bench-{frames}")));

    if !dir.join("manifest.json").exists() {
        println!("generating {frames} frames into {}", dir.display());
        let t = Instant::now();
        let mut w = IndexWriter::create(&dir).expect("create writer");
        // Checkpoint about every 256 MiB of raw capture (≈ 370k frames).
        let scale = synth::Scale {
            frames,
            checkpoint_frames: 370_000,
            seed: 42,
        };
        let (_, s) = synth::generate(&mut w, &scale).expect("generate");
        let secs = t.elapsed().as_secs_f64();
        println!(
            "generated+indexed in {secs:.1}s: frames={} flows={} dns={} http={} tls={} files={} raw={:.2} GB ({:.0} MB/s of raw capture)",
            s.frames,
            s.flows,
            s.dns,
            s.http,
            s.tls,
            s.files,
            s.raw_bytes as f64 / 1e9,
            s.raw_bytes as f64 / 1e6 / secs
        );
    }
    let t = Instant::now();
    let idx = Index::open(&dir).expect("open index");
    println!("Index::open {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let cap = idx.capture().expect("capture");
    let size = dir_size(&dir);
    println!(
        "index size {:.1} MB; raw capture (24 B header + Σ(16 B record header + caplen)) {:.2} GB; ratio {:.2}%",
        size as f64 / 1e6,
        cap.size_bytes as f64 / 1e9,
        100.0 * size as f64 / cap.size_bytes.max(1) as f64
    );

    let qpath = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/bench/queries.txt");
    let text = std::fs::read_to_string(&qpath).expect("queries.txt");
    println!("\n| # | view | filter | rows (total) | p50 ms | p95 ms | max ms |");
    println!("|---|------|--------|-------------:|-------:|-------:|-------:|");
    let mut worst: f64 = 0.0;
    let mut n = 0;
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let (v, f) = line.split_once('\t').unwrap_or((line, ""));
        let Some(view) = view_of(v.trim()) else {
            continue;
        };
        n += 1;
        let req = QueryRequest {
            filter: f.to_string(),
            view,
            time_range: None,
            hosts: vec![],
            flow_ids: vec![],
            sort: None,
            limit: 100,
            cursor: None,
        };
        let total = idx.query(&req).expect(f).total.unwrap_or(0);
        let (p50, p95, max) = time(iters, || {
            idx.query(&req).expect(f);
        });
        worst = worst.max(p95);
        println!("| {n} | {v} | `{f}` | {total} | {p50:.1} | {p95:.1} | {max:.1} |");
    }

    println!("\n| extra | p50 ms | p95 ms | max ms |");
    println!("|-------|-------:|-------:|-------:|");
    let mut extra = |name: &str, f: &mut dyn FnMut()| {
        let (p50, p95, max) = time(iters, f);
        worst = worst.max(p95);
        println!("| {name} | {p50:.1} | {p95:.1} | {max:.1} |");
    };
    let tl = TimelineRequest {
        filter: String::new(),
        time_range: None,
        bucket_ms: 60_000,
        max_lanes: 50,
    };
    extra(
        "timeline whole capture, 60 s buckets, 50 lanes",
        &mut || {
            idx.timeline(&tl, &[]).expect("timeline");
        },
    );
    let tl2 = TimelineRequest {
        filter: "dns.query ~ \"*.top\"".into(),
        time_range: None,
        bucket_ms: 1,
        max_lanes: 50,
    };
    extra("timeline filtered, widened to 2000 buckets", &mut || {
        idx.timeline(&tl2, &[]).expect("timeline");
    });
    let mid = cap.frame_count / 2;
    extra("frame(n) lookup", &mut || {
        idx.frame(mid).expect("frame");
    });
    let fid = idx.frame(mid).expect("frame").flow_id.unwrap_or(1);
    extra("flow_frames(flow)", &mut || {
        idx.flow_frames(fid).expect("flow_frames");
    });
    extra(
        "autocomplete `dns.query == ` (cached top values)",
        &mut || {
            idx.autocomplete("dns.query == ", 13).expect("ac");
        },
    );
    extra(
        "autocomplete `dns.query == \"cdn` (prefix scan)",
        &mut || {
            idx.autocomplete("dns.query == \"cdn", 17).expect("ac");
        },
    );
    extra("autocomplete `host 10.0.0.` (prefix scan)", &mut || {
        idx.autocomplete("host 10.0.0.", 12).expect("ac");
    });
    // Deep page: follow cursors 20 pages into frames sorted by ts desc.
    let mut req = QueryRequest {
        filter: String::new(),
        view: View::Frames,
        time_range: None,
        hosts: vec![],
        flow_ids: vec![],
        sort: Some(walleye_core::ipc::Sort {
            column: "payload_len".into(),
            desc: true,
        }),
        limit: 1000,
        cursor: None,
    };
    for _ in 0..20 {
        req.cursor = idx.query(&req).expect("page").next_cursor;
    }
    extra(
        "frames sorted by payload_len desc, page 21 via cursor",
        &mut || {
            idx.query(&req).expect("page");
        },
    );
    println!("\nqueries: {n}; worst p95 {worst:.1} ms (gate: < 1000 ms)");

    if std::env::var("WALLEYE_BENCH_CLEAN").is_ok() {
        drop(idx);
        let _ = std::fs::remove_dir_all(&dir);
        println!("removed {}", dir.display());
    }
}
