//! Ingest one or more captures into a counting sink and print row counts,
//! TLS SNI/JA4 coverage and throughput. Captures are opened read-only and
//! nothing from them is written anywhere.
//!
//! `cargo run --release -p walleye-ingest --example ingest_stats -- [--decode] <file.pcap>...`
//!
//! `--decode` also builds the decode tree of every frame and reports how many
//! carry warnings and whether any byte range falls outside its frame.

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
    wifi_kinds: BTreeMap<&'static str, u64>,
    wifi_protected: u64,
    wifi_security: BTreeMap<String, u64>,
    wifi_with_channel: u64,
    wifi_with_signal: u64,
    /// (file offset, caplen, link type) per frame, kept for `--decode`.
    refs: Option<Vec<(u64, u32, u32)>>,
}

/// Decode every frame; print warning counts (static messages only) and
/// out-of-range nodes.
fn decode_all(path: &std::path::Path, refs: &[(u64, u32, u32)]) {
    use walleye_core::ipc::DecodeNode;
    fn walk(ns: &[DecodeNode], len: usize, bad: &mut u64, w: &mut BTreeMap<String, u64>) -> bool {
        let mut any = false;
        for n in ns {
            if n.range
                .is_some_and(|r| r.start as usize + r.len as usize > len)
            {
                *bad += 1;
            }
            if let Some(m) = &n.warning {
                *w.entry(m.clone()).or_default() += 1;
                any = true;
            }
            any |= walk(&n.children, len, bad, w);
        }
        any
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return println!("  decode: {e}"),
    };
    let t = Instant::now();
    let (mut warned, mut bad) = (0u64, 0u64);
    let mut msgs = BTreeMap::new();
    for &(off, caplen, lt) in refs {
        let s = off as usize;
        let Some(bytes) = data.get(s..s + caplen as usize) else {
            continue;
        };
        let tree = walleye_ingest::decode_frame(lt, bytes);
        warned += u64::from(walk(&tree, bytes.len(), &mut bad, &mut msgs));
    }
    println!(
        "  decode: {} frames in {:.1} s, {} with warnings, {} out-of-range nodes, warnings {:?}",
        refs.len(),
        t.elapsed().as_secs_f64(),
        warned,
        bad,
        msgs
    );
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
                if let Some(r) = self.refs.as_mut() {
                    r.extend(
                        v.iter()
                            .map(|f| (f.file_offset, f.caplen, f.link_type.unwrap_or(0))),
                    );
                }
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
            RecordBatch::Wifi(v) => {
                self.wifi += v.len() as u64;
                for w in &v {
                    *self.wifi_kinds.entry(w.kind.as_str()).or_default() += 1;
                    self.wifi_protected += u64::from(w.protected);
                    self.wifi_with_channel += u64::from(w.channel.is_some());
                    self.wifi_with_signal += u64::from(w.signal_dbm.is_some());
                    if w.kind == walleye_core::WifiKind::Beacon {
                        *self
                            .wifi_security
                            .entry(w.security.clone().unwrap_or_else(|| "-".into()))
                            .or_default() += 1;
                    }
                }
            }
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let decode = args.iter().any(|a| a == "--decode");
    for arg in args.iter().filter(|a| *a != "--decode") {
        let path = std::path::Path::new(arg);
        let sha = match hash_file(path, &mut |_| {}) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{arg}: {e}");
                continue;
            }
        };
        let mut st = Stats {
            refs: decode.then(Vec::new),
            ..Stats::default()
        };
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
                if st.wifi > 0 {
                    println!(
                        "  wifi {} ({} protected) by kind {:?}",
                        st.wifi, st.wifi_protected, st.wifi_kinds
                    );
                    println!(
                        "  wifi with channel {} | with signal {} | beacons by security {:?}",
                        st.wifi_with_channel, st.wifi_with_signal, st.wifi_security
                    );
                }
                if let Some(refs) = &st.refs {
                    decode_all(path, refs);
                }
            }
            Err(e) => println!("{arg}: error {e}"),
        }
    }
}
