//! Opens a capture with the real engine and prints a triage summary: timing,
//! row counts per view, the timeline lane kind and the top findings with their
//! reasons. Usage: `triage <capture> <data_dir> [top_n] [findings.json]`; the
//! optional last argument writes all findings as JSON (for `walleye-eval`).
//!
//! Output contains capture-derived strings (addresses, names); keep it out of
//! the repo when the capture is private.

use std::{path::PathBuf, sync::atomic::AtomicBool, time::Instant};

use walleye_core::{
    Backend,
    ipc::{QueryRequest, TimelineRequest, View},
};
use walleye_engine::{Engine, EngineConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (capture, data, top, out) = match args.as_slice() {
        [c, d] => (c, d, 10usize, None),
        [c, d, n] => (c, d, n.parse()?, None),
        [c, d, n, o] => (c, d, n.parse()?, Some(o)),
        _ => {
            eprintln!("usage: triage <capture> <data_dir> [top_n] [findings.json]");
            std::process::exit(2);
        }
    };
    let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let engine = Engine::new(EngineConfig::new(data, rules))?;
    let t0 = Instant::now();
    let s = engine.open_blocking(capture, &AtomicBool::new(false), &mut |_| {})?;
    println!(
        "opened in {:.1} s: {} frames, link type {}, sha256 {}",
        t0.elapsed().as_secs_f64(),
        s.capture.frame_count,
        s.capture.link_type,
        s.capture.sha256
    );
    for view in [
        View::Flows,
        View::Dns,
        View::Http,
        View::Tls,
        View::Wifi,
        View::WifiAps,
        View::WifiClients,
    ] {
        let t = Instant::now();
        let page = engine.query(&QueryRequest {
            filter: String::new(),
            view,
            time_range: None,
            hosts: vec![],
            flow_ids: vec![],
            sort: None,
            limit: 100,
            cursor: None,
        })?;
        println!(
            "  {view:?}: {:?} rows ({:.1} ms)",
            page.total,
            t.elapsed().as_secs_f64() * 1e3
        );
    }
    let t = Instant::now();
    let lanes = engine.timeline(&TimelineRequest {
        filter: String::new(),
        time_range: None,
        bucket_ms: 60_000,
        max_lanes: 20,
    })?;
    println!(
        "  timeline: {:?} lanes x{} ({:.1} ms)",
        lanes.lane_kind,
        lanes.lanes.len(),
        t.elapsed().as_secs_f64() * 1e3
    );
    let findings = engine.findings(None)?;
    println!("findings: {}", findings.len());
    if let Some(o) = out {
        std::fs::write(o, serde_json::to_vec_pretty(&findings)?)?;
    }
    for (i, f) in findings.iter().take(top).enumerate() {
        println!(
            "{:>2}. {:>5.1} {} {} [{}] {}",
            i + 1,
            f.score,
            f.entity_type,
            f.entity,
            f.detector,
            f.title
        );
        for r in &f.reasons {
            println!(
                "      +{:.1} {} ({} frames): {}",
                r.weight, r.signal, r.evidence.total, r.explanation
            );
        }
    }
    Ok(())
}
