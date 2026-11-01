//! Walleye ingest: streams a pcap/pcapng capture, assembles bidirectional
//! flows and parses DNS, HTTP/1.x and TLS handshakes into index rows.
//!
//! Every parser treats its input as hostile: reads are bounds-checked, length
//! arithmetic is checked or saturating, buffers are capped, and no function in
//! this crate panics on any input (see `tests/robustness.rs`).
//!
//! Public API (CONTRACTS §7): [`IngestOptions`], [`Progress`], [`hash_file`],
//! [`ingest`], [`read_frame`], [`decode_frame`]. Fuzz entry points live in
//! [`fuzz`]; the typed parsers ([`parse_dns`], [`parse_http`],
//! [`parse_tls_client_hello`], ...) are re-exported here.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::AtomicBool;

use sha2::{Digest, Sha256};
use walleye_core::CaptureRow;
use walleye_core::error::ApiResult;
use walleye_core::sink::{CHECKPOINT_BYTES, IndexSink};

pub mod capture;
pub mod decode;
mod decode_wifi;
pub mod dns;
pub mod flow;
pub mod http;
pub mod out;
pub mod packet;
mod pipeline;
pub mod tls;
pub mod util;
pub mod wifi;
pub mod x509;

pub use decode::decode_frame;
pub use dns::{DnsMessage, parse_dns};
pub use http::{HttpHead, parse_http};
pub use tls::{
    ClientHello, ServerHello, ja4, ja4s, parse_tls_client_hello, parse_tls_server_hello,
};
pub use util::ParseError;
pub use x509::{Certificate, parse_certificate};

/// Ingest tuning. Defaults match CONTRACTS §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOptions {
    pub tcp_idle_timeout_s: u32,
    pub udp_idle_timeout_s: u32,
    /// Emit a `Checkpoint` every this many input bytes (0 = never).
    pub checkpoint_bytes: u64,
    /// Rows per `RecordBatch`.
    pub batch_rows: usize,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            tcp_idle_timeout_s: 300,
            udp_idle_timeout_s: 60,
            checkpoint_bytes: CHECKPOINT_BYTES,
            batch_rows: 65_536,
        }
    }
}

/// Reported roughly every 8 MiB of input and once at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub frames: u64,
}

/// Lowercase hex SHA-256 of a file, read in 1 MiB chunks. `progress` gets the
/// cumulative byte count after each chunk.
pub fn hash_file(path: &Path, progress: &mut dyn FnMut(u64)) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut done = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(buf.get(..n).unwrap_or(&[]));
        done += n as u64;
        progress(done);
    }
    Ok(util::hex(&h.finalize()))
}

/// Index a capture into `sink`. The file is opened read-only and streamed
/// through a bounded buffer. If `sink.begin()` returns a checkpoint, ingest
/// resumes from it. A capture whose tail is cut mid-record, or whose framing
/// breaks part-way, is indexed up to that point.
pub fn ingest(
    path: &Path,
    sha256: &str,
    sink: &mut dyn IndexSink,
    opts: &IngestOptions,
    progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> ApiResult<CaptureRow> {
    let f = File::open(path)?;
    let size = f.metadata()?.len();
    let path_text = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string();
    pipeline::run(f, size, &path_text, sha256, sink, opts, progress, cancel)
}

/// Ingest an in-memory capture (tests, fuzzing, small tools).
pub fn ingest_bytes(
    data: &[u8],
    sha256: &str,
    sink: &mut dyn IndexSink,
    opts: &IngestOptions,
) -> ApiResult<CaptureRow> {
    let cancel = AtomicBool::new(false);
    pipeline::run(
        io::Cursor::new(data),
        data.len() as u64,
        "<memory>",
        sha256,
        sink,
        opts,
        &mut |_| {},
        &cancel,
    )
}

/// Largest frame `read_frame` will read.
pub const MAX_FRAME: u32 = capture::MAX_RECORD as u32;

/// Read `caplen` bytes of packet data at `file_offset` (from `FrameRow`).
pub fn read_frame(path: &Path, file_offset: u64, caplen: u32) -> io::Result<Vec<u8>> {
    if caplen > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "caplen too large",
        ));
    }
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(file_offset))?;
    let mut buf = vec![0u8; caplen as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// A sink that discards everything (throughput benchmarks, fuzzing).
#[derive(Debug, Default)]
pub struct NullSink {
    pub batches: u64,
    pub checkpoints: u64,
}

impl IndexSink for NullSink {
    fn begin(&mut self, _: &CaptureRow) -> ApiResult<Option<walleye_core::sink::Checkpoint>> {
        Ok(None)
    }
    fn write(&mut self, _: walleye_core::sink::RecordBatch) -> ApiResult<()> {
        self.batches += 1;
        Ok(())
    }
    fn checkpoint(&mut self, _: walleye_core::sink::Checkpoint) -> ApiResult<()> {
        self.checkpoints += 1;
        Ok(())
    }
    fn finish(&mut self, _: &CaptureRow) -> ApiResult<()> {
        Ok(())
    }
}

/// Byte-slice entry points for `cargo fuzz` (Agent H). Each accepts any input,
/// never panics and discards its result.
#[doc(hidden)]
pub mod fuzz {
    use super::*;

    const SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// Reader + flow assembly + every parser over an in-memory capture.
    pub fn read_capture(bytes: &[u8]) {
        let opts = IngestOptions {
            checkpoint_bytes: 4096,
            batch_rows: 64,
            ..IngestOptions::default()
        };
        let _ = ingest_bytes(bytes, SHA, &mut NullSink::default(), &opts);
    }

    /// DNS message; with `is_tcp`, the input carries 2-byte length prefixes.
    pub fn parse_dns(bytes: &[u8], is_tcp: bool) {
        if is_tcp {
            let mut c = util::Cur::new(bytes);
            while let Ok(m) = c.vec(2) {
                let _ = dns::parse_dns(m);
            }
        } else {
            let _ = dns::parse_dns(bytes);
        }
    }

    pub fn parse_http(bytes: &[u8]) {
        let _ = http::parse_http(bytes);
    }

    pub fn parse_tls_client_hello(bytes: &[u8]) {
        if let Ok(ch) = tls::parse_tls_client_hello(bytes) {
            let _ = tls::ja4(&ch, 't');
        }
    }

    pub fn parse_tls_server_hello(bytes: &[u8]) {
        if let Ok(sh) = tls::parse_tls_server_hello(bytes) {
            let _ = tls::ja4s(&sh, 't');
        }
    }

    pub fn parse_certificate(bytes: &[u8]) {
        let _ = x509::parse_certificate(bytes);
    }

    pub fn decode_frame(link_type: u32, bytes: &[u8]) {
        let _ = super::decode_frame(link_type, bytes);
    }
}
