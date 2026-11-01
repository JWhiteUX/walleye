//! Seams between ingest (Agent A), index (Agent B) and detect (Agent C).
//!
//! Data flow:
//! ```text
//! walleye-ingest ──RecordBatch──▶ IndexSink (walleye-index, Parquet)
//! walleye-index  ──DetectSource──▶ walleye-detect ──Vec<Finding>──▶ ResultSink (walleye-index)
//! walleye-case   ──Vec<Ioc>─────▶ ResultSink (walleye-index)
//! ```

use serde::{Deserialize, Serialize};

use crate::{
    CaptureRow, DnsRow, FileRow, Finding, FlowRow, FrameRow, HttpRow, Ioc, TlsRow, error::ApiResult,
};

/// A batch of rows for one table. Ingest sends batches over a bounded channel
/// to a writer thread that owns the `IndexSink`.
#[derive(Debug, Clone, PartialEq)]
pub enum RecordBatch {
    Frames(Vec<FrameRow>),
    /// Flows are sent when they close (FIN/RST or idle timeout) or at end of
    /// capture. `flow_id` is assigned when the flow opens, so frames can carry
    /// it before the flow row exists.
    Flows(Vec<FlowRow>),
    Dns(Vec<DnsRow>),
    Http(Vec<HttpRow>),
    Tls(Vec<TlsRow>),
    Files(Vec<FileRow>),
}

/// Resume point. Ingest emits one every `CHECKPOINT_BYTES` of input.
///
/// Invariant: when the sink accepts a checkpoint, every batch sent before it
/// is durable, and nothing sent after it is. On resume, ingest seeks to
/// `file_offset`, restores `state`, and continues numbering at
/// `frames_emitted + 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Offset of the next unread record header in the capture file.
    pub file_offset: u64,
    pub frames_emitted: u64,
    pub next_flow_id: u64,
    /// Opaque ingest state (open flows, reassembly buffers). Owned by
    /// walleye-ingest; the sink stores it verbatim.
    pub state: Vec<u8>,
}

/// Default checkpoint spacing.
pub const CHECKPOINT_BYTES: u64 = 256 * 1024 * 1024;

/// Implemented by walleye-index. Not required to be thread-safe beyond `Send`.
pub trait IndexSink: Send {
    /// Called once before any batch. `capture.first_ts/last_ts/frame_count`
    /// are provisional. Returns the last accepted checkpoint if this capture
    /// (same sha256) was partially indexed before; the sink has already
    /// discarded anything written after it.
    fn begin(&mut self, capture: &CaptureRow) -> ApiResult<Option<Checkpoint>>;
    fn write(&mut self, batch: RecordBatch) -> ApiResult<()>;
    fn checkpoint(&mut self, cp: Checkpoint) -> ApiResult<()>;
    /// Final capture row with real counts and time bounds. After this the
    /// index is complete and read-only.
    fn finish(&mut self, capture: &CaptureRow) -> ApiResult<()>;
}

/// Read side used by detectors. Implemented by walleye-index over DuckDB, and
/// by in-memory vectors in tests. Rows arrive ordered by `ts`/`ts_start`.
pub trait DetectSource {
    fn capture(&self) -> ApiResult<CaptureRow>;
    fn for_each_flow(&self, f: &mut dyn FnMut(&FlowRow)) -> ApiResult<()>;
    fn for_each_dns(&self, f: &mut dyn FnMut(&DnsRow)) -> ApiResult<()>;
    fn for_each_http(&self, f: &mut dyn FnMut(&HttpRow)) -> ApiResult<()>;
    fn for_each_tls(&self, f: &mut dyn FnMut(&TlsRow)) -> ApiResult<()>;
}

/// Write side for analysis results. Implemented by walleye-index. Each call
/// replaces the table's previous contents (detection is re-runnable). Takes
/// `&self` so callers holding a shared `Arc<Index>` can use it.
pub trait ResultSink {
    fn put_findings(&self, findings: &[Finding]) -> ApiResult<()>;
    fn put_iocs(&self, iocs: &[Ioc]) -> ApiResult<()>;
}

/// In-memory `DetectSource` for tests and the eval harness.
#[derive(Debug, Clone, Default)]
pub struct MemorySource {
    pub capture: Option<CaptureRow>,
    pub flows: Vec<FlowRow>,
    pub dns: Vec<DnsRow>,
    pub http: Vec<HttpRow>,
    pub tls: Vec<TlsRow>,
}

impl DetectSource for MemorySource {
    fn capture(&self) -> ApiResult<CaptureRow> {
        self.capture
            .clone()
            .ok_or_else(|| crate::ApiError::new(crate::ErrorCode::NoCapture, "no capture"))
    }
    fn for_each_flow(&self, f: &mut dyn FnMut(&FlowRow)) -> ApiResult<()> {
        self.flows.iter().for_each(f);
        Ok(())
    }
    fn for_each_dns(&self, f: &mut dyn FnMut(&DnsRow)) -> ApiResult<()> {
        self.dns.iter().for_each(f);
        Ok(())
    }
    fn for_each_http(&self, f: &mut dyn FnMut(&HttpRow)) -> ApiResult<()> {
        self.http.iter().for_each(f);
        Ok(())
    }
    fn for_each_tls(&self, f: &mut dyn FnMut(&TlsRow)) -> ApiResult<()> {
        self.tls.iter().for_each(f);
        Ok(())
    }
}
