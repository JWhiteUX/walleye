//! `walleye-gen --scenario <office|beacon|dns_tunnel|dga|scale|wifi|wifi_benign> --seed <u64>
//! --out <path.pcap> [--size-gb 10] [--ipv6] [--duration-min 120]`
//!
//! Writes the capture and `<stem>.labels.json` beside it. Owner: Agent G.

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use walleye_gen::{Options, Scenario, generate, labels_path};

const USAGE: &str = "usage: walleye-gen --scenario <office|beacon|dns_tunnel|dga|scale|wifi|wifi_benign> --seed <u64> --out <path.pcap> [--size-gb <GiB, default 10, scale only>] [--ipv6] [--duration-min <minutes, default 120; wifi scenarios cap at 30>]";

fn parse_args() -> Result<(Options, PathBuf), String> {
    let mut scenario = None;
    let mut seed = None;
    let mut out = None;
    let mut size_gb = 10.0;
    let mut ipv6 = false;
    let mut duration_min = 120;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--scenario" => {
                let v = val("--scenario")?;
                scenario =
                    Some(Scenario::parse(&v).ok_or_else(|| format!("unknown scenario {v:?}"))?);
            }
            "--seed" => {
                seed = Some(
                    val("--seed")?
                        .parse::<u64>()
                        .map_err(|e| format!("--seed: {e}"))?,
                )
            }
            "--out" => out = Some(PathBuf::from(val("--out")?)),
            "--size-gb" => {
                size_gb = val("--size-gb")?
                    .parse::<f64>()
                    .map_err(|e| format!("--size-gb: {e}"))?;
                if !(size_gb > 0.0 && size_gb <= 1024.0) {
                    return Err("--size-gb must be in (0, 1024]".into());
                }
            }
            "--duration-min" => {
                duration_min = val("--duration-min")?
                    .parse::<u64>()
                    .map_err(|e| format!("--duration-min: {e}"))?
                    .clamp(1, 24 * 60);
            }
            "--ipv6" => ipv6 = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let scenario = scenario.ok_or("--scenario is required")?;
    let seed = seed.ok_or("--seed is required")?;
    let out = out.ok_or("--out is required")?;
    let mut opts = Options::new(scenario, seed);
    opts.size_gb = size_gb;
    opts.ipv6 = ipv6;
    opts.duration_min = duration_min;
    Ok((opts, out))
}

fn run() -> Result<(), String> {
    let (opts, out) = parse_args()?;
    let started = Instant::now();
    let file = File::create(&out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let summary = generate(&opts, BufWriter::with_capacity(8 << 20, file))
        .map_err(|e| format!("write {}: {e}", out.display()))?;
    let lp = labels_path(&out);
    let json = serde_json::to_string_pretty(&summary.labels).map_err(|e| e.to_string())?;
    std::fs::write(&lp, json + "\n").map_err(|e| format!("write {}: {e}", lp.display()))?;
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "{}: {} packets, {} bytes ({:.1} MiB) in {:.1} s ({:.0} MiB/s)\nsha256 {}\nlabels {}",
        out.display(),
        summary.packets,
        summary.bytes,
        summary.bytes as f64 / 1_048_576.0,
        secs,
        summary.bytes as f64 / 1_048_576.0 / secs.max(1e-9),
        summary.sha256,
        lp.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("walleye-gen: {e}");
            }
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
