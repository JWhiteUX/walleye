//! Ingest one or more captures into a counting sink and print row counts,
//! TLS SNI/JA4 coverage and throughput. Captures are opened read-only and
//! nothing from them is written anywhere.
//!
//! `cargo run --release -p walleye-ingest --example ingest_stats -- <file.pcap>...`

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use walleye_core::CaptureRow;
use walleye_core::error::ApiResult;
use walleye_core::sink::{Checkpoint, IndexSink, RecordBatch};
use walleye_ingest::{IngestOptions, hash_file, ingest};

#[derive(Default)]
struct Stats {
    frames: u64,
    frames_no_flow: u64,
    flows: u64,
    app: BTreeMap<String, u64>,
    dns: u64,
    http: u64,
    http_status: u64,
    tls: u64,
    tls_sni: u64,
    tls_ja4s: u64,
    tls_cert: u64,
    files: u64,
    wifi: u64,
}

impl IndexSink for Stats {
    fn begin(&mut self, _: &CaptureRow) -> ApiResult<Option<Checkpoint>> {
        Ok(None)
    }
    fn write(&mut self, b: RecordBatch) -> ApiResult<()> {
        match b {
            RecordBatch::Frames(v) => {
                self.frames += v.len() as u64;
                self.frames_no_flow += v.iter().filter(|f| f.flow_id.is_none()).count() as u64;
            }
            RecordBatch::Flows(v) => {
                self.flows += v.len() as u64;
                for f in v {
                    *self
                        .app
                        .entry(f.app_proto.unwrap_or_else(|| "-".into()))
                        .or_default() += 1;
                }
            }
            RecordBatch::Dns(v) => self.dns += v.len() as u64,
            RecordBatch::Http(v) => {
                self.http += v.len() as u64;
                self.http_status += v.iter().filter(|h| h.status.is_some()).count() as u64;
            }
            RecordBatch::Tls(v) => {
                self.tls += v.len() as u64;
                self.tls_sni += v.iter().filter(|t| t.sni.is_some()).count() as u64;
                self.tls_ja4s += v.iter().filter(|t| t.ja4s.is_some()).count() as u64;
                self.tls_cert += v.iter().filter(|t| t.cert_subject.is_some()).count() as u64;
            }
            RecordBatch::Files(v) => self.files += v.len() as u64,
            RecordBatch::Wifi(v) => self.wifi += v.len() as u64,
        }
        Ok(())
    }
    fn checkpoint(&mut self, _: Checkpoint) -> ApiResult<()> {
        Ok(())
    }
    fn finish(&mut self, _: &CaptureRow) -> ApiResult<()> {
        Ok(())
    }
}

fn main() {
    for arg in std::env::args().skip(1) {
        let path = std::path::Path::new(&arg);
        let sha = match hash_file(path, &mut |_| {}) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{arg}: {e}");
                continue;
            }
        };
        let mut st = Stats::default();
        let t = Instant::now();
        let r = ingest(
            path,
            &sha,
            &mut st,
            &IngestOptions::default(),
            &mut |_| {},
            &AtomicBool::new(false),
        );
        let secs = t.elapsed().as_secs_f64();
        match r {
            Ok(cap) => {
                println!(
                    "{}: {} bytes, {} frames ({} without flow), {:.0} MB/s",
                    path.file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default(),
                    cap.size_bytes,
                    st.frames,
                    st.frames_no_flow,
                    cap.size_bytes as f64 / secs / 1e6
                );
                println!("  flows {} by app {:?}", st.flows, st.app);
                println!(
                    "  dns {} | http {} ({} with status) | files {}",
                    st.dns, st.http, st.http_status, st.files
                );
                println!(
                    "  tls {} | with sni {} | with ja4s {} | with cert {}",
                    st.tls, st.tls_sni, st.tls_ja4s, st.tls_cert
                );
            }
            Err(e) => println!("{arg}: error {e}"),
        }
    }
}
