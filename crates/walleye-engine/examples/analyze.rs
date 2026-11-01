//! Headless end-to-end run, for gates and eval:
//!
//!   cargo run -p walleye-engine --release --example analyze -- \
//!       <capture.pcap> <data_dir> [findings_out.json]
//!
//! Indexes (or reuses) the capture, runs detections, prints timings, the
//! index-to-raw size ratio and the top findings, and optionally writes the
//! findings as JSON for `walleye-eval`.

use std::{path::PathBuf, sync::atomic::AtomicBool, time::Instant};

use walleye_core::Backend;
use walleye_core::ipc::IngestPhase;
use walleye_engine::{Engine, EngineConfig};

fn dir_size(p: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [capture, data, rest @ ..] = args.as_slice() else {
        eprintln!("usage: analyze <capture> <data_dir> [findings.json]");
        std::process::exit(2);
    };
    let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let engine = Engine::new(EngineConfig::new(data, rules))?;
    let t0 = Instant::now();
    let mut marks: Vec<(IngestPhase, f64)> = Vec::new();
    let session = engine.open_blocking(capture, &AtomicBool::new(false), &mut |p| {
        if marks.last().map(|m| m.0) != Some(p.phase) {
            marks.push((p.phase, t0.elapsed().as_secs_f64()));
        }
    })?;
    let total = t0.elapsed().as_secs_f64();
    let cap = &session.capture;
    println!(
        "capture: {} ({} bytes, {} frames)",
        cap.path, cap.size_bytes, cap.frame_count
    );
    println!("sha256: {}", cap.sha256);
    let mut prev = 0.0;
    for (ph, t) in marks.iter().skip(1) {
        println!(
            "  phase {ph:?} started at {t:.2}s (previous phase {:.2}s)",
            t - prev
        );
        prev = *t;
    }
    let idx_dir = PathBuf::from(data)
        .join("captures")
        .join(&cap.capture_id)
        .join("index");
    let idx = dir_size(&idx_dir);
    println!(
        "total: {total:.2}s  ->  {:.1} MB/s overall",
        cap.size_bytes as f64 / 1e6 / total
    );
    println!(
        "index: {} bytes = {:.2}% of raw",
        idx,
        100.0 * idx as f64 / cap.size_bytes.max(1) as f64
    );
    let findings = engine.findings(None)?;
    println!("findings: {}", findings.len());
    for (i, f) in findings.iter().take(10).enumerate() {
        println!(
            "  #{:<2} {:>5.1}  {:<16} {}  ({} reasons)",
            i + 1,
            f.score,
            f.entity,
            f.title,
            f.reasons.len()
        );
    }
    if let Some(out) = rest.first() {
        std::fs::write(out, serde_json::to_vec_pretty(&findings)?)?;
        println!("wrote {out}");
    }
    Ok(())
}
