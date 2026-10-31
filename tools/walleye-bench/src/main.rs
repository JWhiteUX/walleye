//! `walleye-bench --index <dir> --queries tools/bench/queries.txt
//! [--iterations 20] [--warmup 2] [--limit 1000] [--gate-ms 1000]`
//!
//! Prints p50/p95/max per query and overall as Markdown; exits 1 when any
//! query fails the p95 gate. `--fake` runs a deterministic stand-in runner
//! (no index needed) so the harness itself can be checked.
//!
//! The real runner needs `--features index` (walleye-index is built in
//! parallel; the lead enables the feature at integration). Owner: Agent G.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use walleye_bench::{BenchConfig, QueryRunner, all_pass, markdown, parse_queries, run_bench};
use walleye_core::ipc::View;

const USAGE: &str = "usage: walleye-bench (--index <dir> | --fake) --queries <queries.txt> [--iterations 20] [--warmup 2] [--limit 1000] [--gate-ms 1000]";

struct Args {
    index: Option<PathBuf>,
    fake: bool,
    queries: PathBuf,
    iterations: usize,
    warmup: usize,
    limit: u32,
    gate_ms: f64,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        index: None,
        fake: false,
        queries: PathBuf::from("tools/bench/queries.txt"),
        iterations: 20,
        warmup: 2,
        limit: 1000,
        gate_ms: 1000.0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |n: &str| it.next().ok_or_else(|| format!("{n} needs a value"));
        match arg.as_str() {
            "--index" => a.index = Some(PathBuf::from(val("--index")?)),
            "--fake" => a.fake = true,
            "--queries" => a.queries = PathBuf::from(val("--queries")?),
            "--iterations" => {
                a.iterations = val("--iterations")?
                    .parse()
                    .map_err(|e| format!("--iterations: {e}"))?;
            }
            "--warmup" => {
                a.warmup = val("--warmup")?
                    .parse()
                    .map_err(|e| format!("--warmup: {e}"))?;
            }
            "--limit" => {
                a.limit = val("--limit")?
                    .parse::<u32>()
                    .map_err(|e| format!("--limit: {e}"))?
                    .clamp(1, 10_000);
            }
            "--gate-ms" => {
                a.gate_ms = val("--gate-ms")?
                    .parse()
                    .map_err(|e| format!("--gate-ms: {e}"))?;
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if a.iterations == 0 {
        return Err("--iterations must be >= 1".into());
    }
    if a.index.is_none() == !a.fake {
        return Err("give exactly one of --index <dir> or --fake".into());
    }
    Ok(a)
}

/// Deterministic stand-in: sleeps a little per query so the table is real.
struct FakeRunner;

impl QueryRunner for FakeRunner {
    fn run(&mut self, _view: View, filter: &str) -> Result<Option<u64>, String> {
        std::thread::sleep(Duration::from_micros(200 + 50 * filter.len() as u64));
        Ok(Some(filter.len() as u64))
    }
}

#[cfg(feature = "index")]
mod real {
    use walleye_bench::QueryRunner;
    use walleye_core::ipc::{QueryRequest, View};

    pub struct IndexRunner {
        pub index: walleye_index::Index,
        pub limit: u32,
    }

    impl QueryRunner for IndexRunner {
        fn run(&mut self, view: View, filter: &str) -> Result<Option<u64>, String> {
            let req = QueryRequest {
                filter: filter.to_string(),
                view,
                time_range: None,
                hosts: Vec::new(),
                flow_ids: Vec::new(),
                sort: None,
                limit: self.limit,
                cursor: None,
            };
            self.index
                .query(&req)
                .map(|page| page.total)
                .map_err(|e| format!("{e:?}"))
        }
    }
}

fn make_runner(a: &Args) -> Result<Box<dyn QueryRunner>, String> {
    if a.fake {
        return Ok(Box::new(FakeRunner));
    }
    #[cfg(feature = "index")]
    {
        let dir = a.index.clone().unwrap_or_default();
        let index = walleye_index::Index::open(&dir)
            .map_err(|e| format!("open index {}: {e:?}", dir.display()))?;
        Ok(Box::new(real::IndexRunner {
            index,
            limit: a.limit,
        }))
    }
    #[cfg(not(feature = "index"))]
    {
        let _ = a.limit;
        Err("built without the `index` feature: rerun with `cargo run -p walleye-bench --release --features index -- --index <dir> ...` (or use --fake)".into())
    }
}

fn run() -> Result<bool, String> {
    let a = parse()?;
    let text = std::fs::read_to_string(&a.queries)
        .map_err(|e| format!("read {}: {e}", a.queries.display()))?;
    let queries = parse_queries(&text)?;
    let mut runner = make_runner(&a)?;
    let results = run_bench(
        runner.as_mut(),
        &queries,
        BenchConfig {
            iterations: a.iterations,
            warmup: a.warmup,
        },
        &mut Instant::now,
    );
    println!(
        "Walleye query benchmark: {} queries x {} timed runs (+{} warmup), limit {}{}\n",
        queries.len(),
        a.iterations,
        a.warmup,
        a.limit,
        if a.fake { " — FAKE runner" } else { "" }
    );
    print!("{}", markdown(&results, a.gate_ms));
    Ok(all_pass(&results, a.gate_ms))
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            if !e.is_empty() {
                eprintln!("walleye-bench: {e}");
            }
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
