//! `walleye-eval --findings <findings.json> --labels <labels.json>
//! [--findings ... --labels ...]... [--k 5] [--gate] [--max-fp 0.3]`
//!
//! Prints a Markdown table (one row per findings/labels pair). With
//! `--gate`, exits 1 when any gate fails. Owner: Agent G.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use walleye_core::findings::Finding;
use walleye_eval::{Gates, LabelFile, evaluate, gate_failures, markdown};

const USAGE: &str = "usage: walleye-eval --findings <findings.json> --labels <labels.json> [--findings F --labels L]... [--k 5] [--gate] [--max-fp 0.3]";

struct Args {
    findings: Vec<PathBuf>,
    labels: Vec<PathBuf>,
    k: usize,
    gate: bool,
    max_fp: f64,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        findings: Vec::new(),
        labels: Vec::new(),
        k: 5,
        gate: false,
        max_fp: 0.30,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |n: &str| it.next().ok_or_else(|| format!("{n} needs a value"));
        match arg.as_str() {
            "--findings" => a.findings.push(PathBuf::from(val("--findings")?)),
            "--labels" => a.labels.push(PathBuf::from(val("--labels")?)),
            "--k" => {
                a.k = val("--k")?.parse().map_err(|e| format!("--k: {e}"))?;
                if a.k == 0 {
                    return Err("--k must be >= 1".into());
                }
            }
            "--max-fp" => {
                a.max_fp = val("--max-fp")?
                    .parse()
                    .map_err(|e| format!("--max-fp: {e}"))?;
            }
            "--gate" => a.gate = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if a.findings.is_empty() || a.findings.len() != a.labels.len() {
        return Err("give one --labels per --findings (at least one pair)".into());
    }
    Ok(a)
}

fn sample_name(labels_path: &Path, labels: &LabelFile) -> String {
    let stem = labels_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = stem
        .strip_suffix(".labels.json")
        .or_else(|| stem.strip_suffix(".json"))
        .unwrap_or(&stem)
        .to_string();
    if stem.is_empty() {
        labels.scenario.clone()
    } else {
        stem
    }
}

fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", p.display()))
}

fn run() -> Result<bool, String> {
    let a = parse()?;
    let mut results = Vec::new();
    for (fp, lp) in a.findings.iter().zip(&a.labels) {
        let findings: Vec<Finding> = read_json(fp)?;
        let labels: LabelFile = read_json(lp)?;
        results.push(evaluate(&sample_name(lp, &labels), &findings, &labels, a.k));
    }
    print!("{}", markdown(&results, a.k));
    if a.gate {
        let fails = gate_failures(
            &results,
            &Gates {
                k: a.k,
                max_fp_benign: a.max_fp,
            },
        );
        if fails.is_empty() {
            println!(
                "\nGates: PASS (hit@{} on every malicious sample; benign FP rate@10 <= {:.0}%; evidence on every reason)",
                a.k,
                a.max_fp * 100.0
            );
        } else {
            println!("\nGates: FAIL");
            for f in &fails {
                println!("- {f}");
            }
            return Ok(false);
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            if !e.is_empty() {
                eprintln!("walleye-eval: {e}");
            }
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
