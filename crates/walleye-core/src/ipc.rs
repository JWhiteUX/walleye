//! Tauri IPC request/response types. Each type is exported to
//! `app/src/shared/bindings/<Type>.ts` by `cargo test -p walleye-core`.
//!
//! Command names and argument names are listed in `docs/CONTRACTS.md` §3 and
//! mirrored by `Backend` (backend.rs) and `app/src/shared/ipc.ts`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CaptureRow, Direction, DnsRow, Evidence, FileRow, FlowId, FlowRow, FrameNo, FrameRow, HttpRow,
    TlsRow, Ts, Verdict, WifiApRow, WifiClientRow, WifiRow,
};

/// Opaque ingest job handle.
pub type JobId = String;
/// Case identifier. In the MVP there is one case per capture and
/// `case_id == capture_id`.
pub type CaseId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum IngestPhase {
    Queued,
    /// SHA-256 of the whole file (names the index directory).
    Hashing,
    /// Parsing + writing Parquet. `pct` covers this phase's bytes.
    Indexing,
    /// Running detections and IOC extraction.
    Detecting,
    Done,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IngestStatus {
    pub job_id: JobId,
    pub phase: IngestPhase,
    /// 0..=100 across the whole job.
    pub pct: f64,
    #[ts(type = "number")]
    pub bytes_done: u64,
    #[ts(type = "number")]
    pub bytes_total: u64,
    pub eta_s: Option<f64>,
    pub error: Option<String>,
    /// True when this job continued from a checkpoint.
    pub resumed: bool,
    /// Set once phase is `Done`.
    pub session: Option<CaptureSession>,
}

/// The capture currently open in the app plus its case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CaptureSession {
    pub capture: CaptureRow,
    pub case_id: CaseId,
}

/// Which table a query reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum View {
    Flows,
    Dns,
    Http,
    Tls,
    Files,
    Frames,
    /// 802.11 management and data frames (contract v2).
    Wifi,
    /// Access points, derived from `wifi`.
    WifiAps,
    /// Stations, derived from `wifi`.
    WifiClients,
}

impl View {
    /// Views over the 802.11 tables. Filters on these use only `wifi.*`,
    /// `ap.*` and `client.*` fields; `hosts`/`flow_ids` do not apply.
    pub fn is_wifi(self) -> bool {
        matches!(self, View::Wifi | View::WifiAps | View::WifiClients)
    }
}

/// Half-open `[start, end)` in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TimeRange {
    #[ts(type = "number")]
    pub start: Ts,
    #[ts(type = "number")]
    pub end: Ts,
}

impl TimeRange {
    pub fn contains(&self, t: Ts) -> bool {
        t >= self.start && t < self.end
    }
    /// True when `[a, b]` overlaps this range.
    pub fn overlaps(&self, a: Ts, b: Ts) -> bool {
        a < self.end && b >= self.start
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Sort {
    /// Column name of the view's row type.
    pub column: String,
    pub desc: bool,
}

/// `query` input. The selection's structured parts (time range, hosts, flow
/// ids) travel as fields, never spliced into `filter` text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QueryRequest {
    /// Filter-language text; "" means no filter.
    pub filter: String,
    pub view: View,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub time_range: Option<TimeRange>,
    /// Rows touching any of these IPs (src or dst of the row's flow).
    #[serde(default)]
    #[ts(as = "Option<Vec<String>>", optional)]
    pub hosts: Vec<String>,
    /// Rows belonging to any of these flows.
    #[serde(default)]
    #[ts(as = "Option<Vec<f64>>", optional)]
    pub flow_ids: Vec<FlowId>,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub sort: Option<Sort>,
    /// 1..=10_000.
    pub limit: u32,
    /// Opaque cursor from a previous `Page.next_cursor`.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub cursor: Option<String>,
}

/// Rows of one view, tagged so TypeScript can narrow on `view`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "view", content = "rows", rename_all = "snake_case")]
#[ts(export)]
pub enum RowSet {
    Flows(Vec<FlowRow>),
    Dns(Vec<DnsRow>),
    Http(Vec<HttpRow>),
    Tls(Vec<TlsRow>),
    Files(Vec<FileRow>),
    Frames(Vec<FrameRow>),
    Wifi(Vec<WifiRow>),
    WifiAps(Vec<WifiApRow>),
    WifiClients(Vec<WifiClientRow>),
}

impl RowSet {
    pub fn len(&self) -> usize {
        match self {
            RowSet::Flows(r) => r.len(),
            RowSet::Dns(r) => r.len(),
            RowSet::Http(r) => r.len(),
            RowSet::Tls(r) => r.len(),
            RowSet::Files(r) => r.len(),
            RowSet::Frames(r) => r.len(),
            RowSet::Wifi(r) => r.len(),
            RowSet::WifiAps(r) => r.len(),
            RowSet::WifiClients(r) => r.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Page {
    pub data: RowSet,
    /// Present when more rows follow.
    pub next_cursor: Option<String>,
    /// Exact total when cheap to compute, else null.
    #[ts(type = "number | null")]
    pub total: Option<u64>,
    /// Compiled SQL with `?` placeholders (never values), for "no hidden
    /// magic" and the report's query list.
    pub sql: Option<String>,
    pub elapsed_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TimelineRequest {
    pub filter: String,
    /// null = whole capture.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub time_range: Option<TimeRange>,
    /// Bucket width; the backend may widen it to keep ≤ 2000 buckets.
    #[ts(type = "number")]
    pub bucket_ms: u64,
    /// Top-N hosts by activity get their own lane; the rest go to "other".
    pub max_lanes: u32,
}

/// Event class for timeline marks. `Bulk` = flow with ≥ 1 MiB total bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EventKind {
    Dns,
    Tls,
    Http,
    Bulk,
    Other,
}

/// Counts of flow starts per kind in one bucket. Sparse: empty buckets omitted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Bucket {
    /// Bucket start.
    #[ts(type = "number")]
    pub t: Ts,
    pub dns: u32,
    pub tls: u32,
    pub http: u32,
    pub bulk: u32,
    pub other: u32,
    /// Device lanes (802.11 captures) count **frames**, not flow starts, in
    /// these four fields (absent on host lanes):
    /// management frames other than deauth/disassoc and probes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub wifi_mgmt: Option<u32>,
    /// Probe requests and responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub wifi_probe: Option<u32>,
    /// Data, null and EAPOL frames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub wifi_data: Option<u32>,
    /// Deauthentication and disassociation frames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub wifi_deauth: Option<u32>,
}

/// What a timeline lane is keyed by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LaneKind {
    /// Flow initiator IP (`src_ip`). Wired and IP captures.
    #[default]
    Host,
    /// 802.11 transmitter address (`wifi.tx`). Captures whose link type is
    /// 105 or 127.
    Device,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Lane {
    /// Host IP, or "other" when `is_other`.
    pub host: String,
    pub is_other: bool,
    #[ts(type = "number")]
    pub total: u64,
    /// Highest finding score for this host, if any (for lane badges).
    pub max_score: Option<f64>,
    pub buckets: Vec<Bucket>,
}

/// A host's lane is keyed by the flow initiator (`src_ip`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Lanes {
    #[ts(type = "number")]
    pub bucket_ms: u64,
    pub range: TimeRange,
    /// `device` for 802.11 captures: `Lane.host` is then a MAC address and
    /// buckets use the `wifi_*` counts.
    #[serde(default)]
    pub lane_kind: LaneKind,
    pub lanes: Vec<Lane>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FrameRef {
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    #[ts(type = "number")]
    pub ts: Ts,
    pub caplen: u32,
    pub wirelen: u32,
    pub direction: Option<Direction>,
    pub tcp_flags: Option<u8>,
    pub payload_len: u32,
    /// One-line summary, e.g. "TCP 51234 → 443 [SYN] len=0".
    pub summary: String,
}

/// Byte range inside the frame's bytes, half-open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ByteRange {
    pub start: u32,
    pub len: u32,
}

/// Protocol decode tree node (Wireshark-style).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DecodeNode {
    /// Display label, e.g. "Internet Protocol Version 4" or "TTL: 64".
    pub label: String,
    /// Filter-language field this node maps to, when one exists ("dst_ip").
    pub field: Option<String>,
    /// Raw value as text, when this is a leaf field.
    pub value: Option<String>,
    pub range: Option<ByteRange>,
    /// Set when the layer was truncated or malformed.
    pub warning: Option<String>,
    pub children: Vec<DecodeNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PacketView {
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    #[ts(type = "number")]
    pub ts: Ts,
    pub caplen: u32,
    pub wirelen: u32,
    pub link_type: u32,
    #[ts(type = "number | null")]
    pub flow_id: Option<FlowId>,
    pub decode_tree: Vec<DecodeNode>,
    /// Lowercase hex of the captured bytes, two chars per byte, no spaces.
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FindingsFilter {
    #[serde(default)]
    #[ts(optional = nullable)]
    pub min_score: Option<f64>,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub detector: Option<String>,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub entity: Option<String>,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub time_range: Option<TimeRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum IocFormat {
    Csv,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ReportFormat {
    Markdown,
    Pdf,
}

/// What a case pin points at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum EvidenceRef {
    Frame {
        #[ts(type = "number")]
        frame_no: FrameNo,
    },
    Flow {
        #[ts(type = "number")]
        flow_id: FlowId,
    },
    Finding {
        finding_id: String,
    },
    Ioc {
        ioc_id: String,
    },
    /// A query and its scope, re-runnable from the report.
    Query {
        filter: String,
        view: View,
        time_range: Option<TimeRange>,
    },
    /// Free-text note with no evidence attached. Reports render these as
    /// analyst notes, never as claims.
    Note,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Pin {
    pub pin_id: String,
    pub evidence: EvidenceRef,
    pub note: String,
    /// Frames that reproduce this pin (resolved at pin time).
    pub resolved: Evidence,
    #[ts(type = "number")]
    pub created_at: Ts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct VerdictEntry {
    pub finding_id: String,
    pub verdict: Verdict,
    pub note: String,
    #[ts(type = "number")]
    pub at: Ts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QueryLogEntry {
    pub filter: String,
    pub view: View,
    pub time_range: Option<TimeRange>,
    pub sql: Option<String>,
    #[ts(type = "number")]
    pub rows: u64,
    #[ts(type = "number")]
    pub at: Ts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Case {
    pub case_id: CaseId,
    pub capture: CaptureRow,
    pub pins: Vec<Pin>,
    pub verdicts: Vec<VerdictEntry>,
    pub queries: Vec<QueryLogEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SavedQuery {
    pub name: String,
    pub filter: String,
    pub view: View,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SuggestionKind {
    Field,
    Operator,
    Keyword,
    Value,
    Saved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Suggestion {
    pub label: String,
    /// Text that replaces `[replace_start, replace_end)` of the input.
    pub insert_text: String,
    pub kind: SuggestionKind,
    pub detail: Option<String>,
    pub replace_start: u32,
    pub replace_end: u32,
}
