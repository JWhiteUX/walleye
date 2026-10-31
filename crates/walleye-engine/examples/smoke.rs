//! Headless smoke run of every backend command, for the network-deny gate
//! (`scripts/netdeny.sh` runs it under a sandbox that kills the process on any
//! socket or DNS lookup):
//!
//!   cargo run -p walleye-engine --release --example smoke -- <capture> <data_dir>
//!
//! Opens the capture (hash, ingest, index, detect), then exercises query on
//! every view, timeline, flow frames, packet decode, autocomplete, saved
//! queries, findings, verdicts, pins, IOCs and all four exports. Exits non-zero
//! if any command fails.

use std::{path::PathBuf, sync::atomic::AtomicBool};

use walleye_core::{
    Backend, Verdict,
    ipc::{EvidenceRef, IocFormat, QueryRequest, ReportFormat, RowSet, TimelineRequest, View},
};
use walleye_engine::{Engine, EngineConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [capture, data] = args.as_slice() else {
        eprintln!("usage: smoke <capture> <data_dir>");
        std::process::exit(2);
    };
    let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let engine = Engine::new(EngineConfig::new(data, rules))?;
    let session = engine.open_blocking(capture, &AtomicBool::new(false), &mut |_| {})?;
    let case_id = session.case_id.clone();
    println!(
        "opened {} sha256 {}",
        session.capture.path, session.capture.sha256
    );

    let mut first_flow = None;
    for view in [View::Flows, View::Dns, View::Http, View::Tls, View::Files] {
        let page = engine.query(&QueryRequest {
            filter: String::new(),
            view,
            time_range: None,
            hosts: vec![],
            flow_ids: vec![],
            sort: None,
            limit: 50,
            cursor: None,
        })?;
        println!("query {view:?}: total {:?}", page.total);
        if let RowSet::Flows(rows) = &page.data {
            first_flow = rows.first().map(|r| r.flow_id);
        }
    }
    let lanes = engine.timeline(&TimelineRequest {
        filter: String::new(),
        time_range: None,
        bucket_ms: 1000,
        max_lanes: 20,
    })?;
    println!("timeline: {} lanes", lanes.lanes.len());
    if let Some(id) = first_flow {
        if let Some(f) = engine.flow_frames(id)?.first() {
            engine.packet(f.frame_no)?;
        }
    }
    engine.packet(1)?;
    println!("packet decode ok");
    engine.autocomplete("ho", 2)?;
    engine.list_saved_queries()?;

    let findings = engine.findings(None)?;
    println!("findings: {}", findings.len());
    if let Some(f) = findings.first() {
        engine.set_verdict(&f.finding_id, Verdict::Suspicious, "smoke")?;
        engine.case_pin(
            &case_id,
            &EvidenceRef::Finding {
                finding_id: f.finding_id.clone(),
            },
            "smoke",
        )?;
    }
    let iocs = engine.iocs(&case_id)?;
    println!("iocs: {}", iocs.len());
    for fmt in [IocFormat::Csv, IocFormat::Json] {
        println!("export {fmt:?}: {}", engine.export_iocs(&case_id, fmt)?);
    }
    for fmt in [ReportFormat::Markdown, ReportFormat::Pdf] {
        println!(
            "report {fmt:?}: {}",
            engine.export_report(&case_id, fmt, None)?
        );
    }
    engine.get_case(&case_id)?;
    println!("smoke: all commands ok");
    Ok(())
}
