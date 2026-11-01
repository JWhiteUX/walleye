//! Parsing throughput: full ingest (reader, flows, DNS/HTTP/TLS parsers,
//! batching, writer thread) into a no-op sink, over a synthetic mixed
//! capture of `WALLEYE_BENCH_MB` MiB (default 1024) generated once into
//! `$TMPDIR/walleye-ingest-bench/` (outside the repo).
//!
//! `cargo bench -p walleye-ingest --bench throughput`
//! The file is deleted after the run unless `WALLEYE_BENCH_KEEP=1`.

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use walleye_ingest::{IngestOptions, NullSink, ingest};

fn generate(path: &Path, bytes: u64) -> std::io::Result<()> {
    let tmp = path.with_extension("partial");
    let mut w = BufWriter::with_capacity(8 << 20, std::fs::File::create(&tmp)?);
    w.write_all(&common::Pcap::new(1).buf)?;
    let mut written = 24u64;
    let mut err = None;
    common::synth::mixed(42, 512, 1_700_000_000_000_000, |ts, f| {
        let mut rec = Vec::with_capacity(16 + f.len());
        rec.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        rec.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        rec.extend_from_slice(&(f.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(f.len() as u32).to_le_bytes());
        rec.extend_from_slice(f);
        if let Err(e) = w.write_all(&rec) {
            err = Some(e);
            return false;
        }
        written += rec.len() as u64;
        written < bytes
    });
    if let Some(e) = err {
        return Err(e);
    }
    w.flush()?;
    drop(w);
    std::fs::rename(&tmp, path)
}

fn bench(c: &mut Criterion) {
    let mb: u64 = std::env::var("WALLEYE_BENCH_MB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let dir: PathBuf = std::env::temp_dir().join("walleye-ingest-bench");
    std::fs::create_dir_all(&dir).expect("bench dir");
    let path = dir.join(format!("mixed-{mb}MiB-v1.pcap"));
    if !path.exists() {
        let t = Instant::now();
        generate(&path, mb << 20).expect("generate bench capture");
        eprintln!("generated {} in {:.1?}", path.display(), t.elapsed());
    }
    let size = std::fs::metadata(&path).expect("stat").len();
    let opts = IngestOptions::default();
    let cancel = AtomicBool::new(false);

    // One instrumented pass for frame/flow counts.
    let t = Instant::now();
    let cap = ingest(
        &path,
        common::SHA,
        &mut NullSink::default(),
        &opts,
        &mut |_| {},
        &cancel,
    )
    .expect("ingest");
    let secs = t.elapsed().as_secs_f64();
    eprintln!(
        "single pass: {} bytes, {} frames in {secs:.2} s = {:.1} MB/s ({:.1} MiB/s)",
        size,
        cap.frame_count,
        size as f64 / secs / 1e6,
        size as f64 / secs / (1024.0 * 1024.0)
    );

    let mut g = c.benchmark_group("ingest");
    g.throughput(Throughput::Bytes(size));
    g.sample_size(10);
    g.warm_up_time(Duration::from_secs(1));
    g.measurement_time(Duration::from_secs(30));
    g.bench_function(format!("mixed_{mb}MiB_null_sink"), |b| {
        b.iter(|| {
            ingest(
                &path,
                common::SHA,
                &mut NullSink::default(),
                &opts,
                &mut |_| {},
                &cancel,
            )
            .expect("ingest")
        });
    });
    g.finish();

    if std::env::var_os("WALLEYE_BENCH_KEEP").is_none() {
        let _ = std::fs::remove_file(&path);
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
