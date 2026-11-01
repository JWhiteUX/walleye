//! Query latency benchmark (docs/CONTRACTS.md §9). Owner: Agent G.
//!
//! The timing loop is independent of the index: it drives anything that
//! implements [`QueryRunner`]. `main.rs` provides the real runner over
//! `walleye_index::Index` behind the `index` feature, and a deterministic
//! fake runner for smoke tests.

use std::time::{Duration, Instant};

use walleye_core::ipc::View;

/// One line of `tools/bench/queries.txt`.
#[derive(Debug, Clone, PartialEq)]
pub struct BenchQuery {
    /// 1-based line number in the source file.
    pub line: usize,
    pub view: View,
    pub filter: String,
}

/// Parse `view<TAB>filter` lines. `#` starts a comment line; blank lines
/// are skipped; an empty filter (`flows<TAB>`) means "no filter".
pub fn parse_queries(text: &str) -> Result<Vec<BenchQuery>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (view, filter) = line.split_once('\t').unwrap_or((line, ""));
        let view = parse_view(view.trim())
            .ok_or_else(|| format!("line {}: unknown view {:?}", i + 1, view.trim()))?;
        out.push(BenchQuery {
            line: i + 1,
            view,
            filter: filter.trim().to_string(),
        });
    }
    if out.is_empty() {
        return Err("no queries found".into());
    }
    Ok(out)
}

pub fn parse_view(s: &str) -> Option<View> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

pub fn view_name(v: View) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Something that can execute one benchmark query.
pub trait QueryRunner {
    /// Run the query to completion. Returns the row count if known.
    fn run(&mut self, view: View, filter: &str) -> Result<Option<u64>, String>;
}

impl<F> QueryRunner for F
where
    F: FnMut(View, &str) -> Result<Option<u64>, String>,
{
    fn run(&mut self, view: View, filter: &str) -> Result<Option<u64>, String> {
        self(view, filter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    pub n: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

/// Nearest-rank percentile over sorted samples (`p` in 0..=100).
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

pub fn stats(samples_ms: &[f64]) -> Stats {
    let mut s = samples_ms.to_vec();
    s.sort_by(f64::total_cmp);
    Stats {
        n: s.len(),
        p50_ms: percentile(&s, 50.0),
        p95_ms: percentile(&s, 95.0),
        max_ms: s.last().copied().unwrap_or(f64::NAN),
        mean_ms: if s.is_empty() {
            f64::NAN
        } else {
            s.iter().sum::<f64>() / s.len() as f64
        },
    }
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub query: BenchQuery,
    pub samples_ms: Vec<f64>,
    pub rows: Option<u64>,
    pub error: Option<String>,
}

impl QueryResult {
    pub fn stats(&self) -> Stats {
        stats(&self.samples_ms)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BenchConfig {
    pub iterations: usize,
    /// Untimed runs before measuring (fills OS and DuckDB caches).
    pub warmup: usize,
}

/// Run every query `warmup + iterations` times; time the last `iterations`.
/// A query that errors is recorded once and not retried.
pub fn run_bench(
    runner: &mut dyn QueryRunner,
    queries: &[BenchQuery],
    cfg: BenchConfig,
    clock: &mut dyn FnMut() -> Instant,
) -> Vec<QueryResult> {
    let mut out = Vec::with_capacity(queries.len());
    for q in queries {
        let mut res = QueryResult {
            query: q.clone(),
            samples_ms: Vec::with_capacity(cfg.iterations),
            rows: None,
            error: None,
        };
        for i in 0..cfg.warmup + cfg.iterations {
            let t0 = clock();
            let r = runner.run(q.view, &q.filter);
            let dt: Duration = clock().saturating_duration_since(t0);
            match r {
                Ok(rows) => {
                    res.rows = rows.or(res.rows);
                    if i >= cfg.warmup {
                        res.samples_ms.push(dt.as_secs_f64() * 1000.0);
                    }
                }
                Err(e) => {
                    res.error = Some(e);
                    break;
                }
            }
        }
        out.push(res);
    }
    out
}

fn fmt_ms(v: f64) -> String {
    if v.is_nan() {
        "—".into()
    } else if v >= 100.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

/// Markdown report: one row per query plus an overall row (all timed
/// samples pooled). `gate_ms` marks rows whose p95 is not below it.
pub fn markdown(results: &[QueryResult], gate_ms: f64) -> String {
    let mut s = String::from(
        "| # | View | Filter | Rows | p50 ms | p95 ms | max ms | p95 < gate |\n|---:|---|---|---:|---:|---:|---:|:---:|\n",
    );
    let mut all = Vec::new();
    let mut fails = 0usize;
    for (i, r) in results.iter().enumerate() {
        let st = r.stats();
        let filter = if r.query.filter.is_empty() {
            "*(none)*".to_string()
        } else {
            format!("`{}`", r.query.filter.replace('|', "\\|").replace('`', "'"))
        };
        let ok = r.error.is_none() && st.p95_ms < gate_ms;
        if !ok {
            fails += 1;
        }
        let verdict = match &r.error {
            Some(e) => format!("**error**: {}", e.replace('|', "\\|").replace('\n', " ")),
            None if ok => "yes".into(),
            None => "**no**".into(),
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            view_name(r.query.view),
            filter,
            r.rows.map_or("—".into(), |n| n.to_string()),
            fmt_ms(st.p50_ms),
            fmt_ms(st.p95_ms),
            fmt_ms(st.max_ms),
            verdict
        ));
        all.extend_from_slice(&r.samples_ms);
    }
    let o = stats(&all);
    s.push_str(&format!(
        "| | **overall** | {} samples | | {} | {} | {} | {} |\n",
        o.n,
        fmt_ms(o.p50_ms),
        fmt_ms(o.p95_ms),
        fmt_ms(o.max_ms),
        if fails == 0 {
            "yes".to_string()
        } else {
            format!("**{fails} failing**")
        }
    ));
    s.push_str(&format!(
        "\nGate: p95 < {gate_ms:.0} ms on every query. {} of {} queries pass.\n",
        results.len() - fails,
        results.len()
    ));
    s
}

/// True when every query ran without error and its p95 is below `gate_ms`.
pub fn all_pass(results: &[QueryResult], gate_ms: f64) -> bool {
    results
        .iter()
        .all(|r| r.error.is_none() && r.stats().p95_ms < gate_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn parses_the_committed_query_file() {
        let text = include_str!("../../bench/queries.txt");
        let q = parse_queries(text).expect("parse");
        // BUILD_PROMPT's 20 wired queries plus 6 for the 802.11 views.
        assert_eq!(q.len(), 26);
        assert_eq!(q[0].view, View::Flows);
        assert_eq!(q[0].filter, "");
        assert!(q.iter().any(|x| x.view == View::Frames));
        for v in [View::Wifi, View::WifiAps, View::WifiClients] {
            assert!(q.iter().any(|x| x.view == v), "{v:?}");
        }
        assert!(
            q.iter()
                .any(|x| x.view == View::Wifi && x.filter == "mac 42:00:5e:00:53:9c")
        );
        assert!(q.iter().any(|x| x.filter == "dns.rcode == NXDOMAIN"));
    }

    #[test]
    fn rejects_unknown_views_and_empty_files() {
        assert!(parse_queries("bogus\tx").is_err());
        assert!(parse_queries("# only a comment\n\n").is_err());
        let q = parse_queries("dns\n").expect("view only");
        assert_eq!(q[0].filter, "");
        let q = parse_queries("wifi_aps\t\nwifi_clients\tclient.randomized == true\n")
            .expect("wifi views");
        assert_eq!(q[0].view, View::WifiAps);
        assert_eq!(q[1].view, View::WifiClients);
        assert!(parse_queries("wifi_ap\t").is_err());
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&v, 50.0), 50.0);
        assert_eq!(percentile(&v, 95.0), 95.0);
        assert_eq!(percentile(&v, 100.0), 100.0);
        assert_eq!(percentile(&[7.0], 95.0), 7.0);
        let s = stats(&[3.0, 1.0, 2.0]);
        assert_eq!((s.p50_ms, s.max_ms, s.n), (2.0, 3.0, 3));
    }

    /// Fake clock: each call advances by the duration the fake runner set.
    #[test]
    fn times_a_fake_runner_with_a_fake_clock() {
        let base = Instant::now();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let pending = Rc::new(Cell::new(Duration::ZERO));
        let mut calls = 0usize;
        let p2 = pending.clone();
        let mut runner = move |view: View, filter: &str| -> Result<Option<u64>, String> {
            calls += 1;
            if filter == "boom" {
                return Err("invalid_filter: boom".into());
            }
            // flows queries take 10 ms per call number mod 4; dns takes 900 ms.
            let ms = match view {
                View::Dns => 900,
                _ => 10 * (calls % 4 + 1) as u64,
            };
            p2.set(Duration::from_millis(ms));
            Ok(Some(42))
        };
        let e2 = elapsed.clone();
        let mut clock = move || {
            // Called before and after each run: the "after" call applies the
            // runner's pending duration.
            let now = base + e2.get() + pending.get();
            e2.set(e2.get() + pending.get());
            pending.set(Duration::ZERO);
            now
        };
        let queries =
            parse_queries("flows\t\ndns\tdns.rcode == NXDOMAIN\nhttp\tboom\n").expect("q");
        let res = run_bench(
            &mut runner,
            &queries,
            BenchConfig {
                iterations: 8,
                warmup: 2,
            },
            &mut clock,
        );
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].samples_ms.len(), 8);
        assert!(
            res[0]
                .samples_ms
                .iter()
                .all(|&m| (10.0..=40.0).contains(&m))
        );
        assert_eq!(res[1].stats().p95_ms, 900.0);
        assert_eq!(res[1].rows, Some(42));
        assert!(res[2].error.is_some());
        assert!(res[2].samples_ms.is_empty());

        assert!(!all_pass(&res, 1000.0));
        assert!(all_pass(&res[..2], 1000.0));
        assert!(!all_pass(&res[..2], 500.0));

        let md = markdown(&res, 1000.0);
        assert!(
            md.contains("| 2 | dns | `dns.rcode == NXDOMAIN` | 42 | 900 | 900 | 900 | yes |"),
            "{md}"
        );
        assert!(md.contains("**error**: invalid_filter: boom"));
        assert!(md.contains("**overall** | 16 samples"));
        assert!(md.contains("2 of 3 queries pass"));
    }
}
