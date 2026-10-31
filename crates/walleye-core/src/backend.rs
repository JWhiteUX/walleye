//! The IPC surface as a Rust trait. `app/src-tauri` exposes one
//! `#[tauri::command]` per method and forwards to `Arc<dyn Backend>`.
//! `MockBackend` (mock.rs) implements it from `mock/dataset.json`; the real
//! implementation is wired in `app/src-tauri` during integration.

use crate::{
    Finding, Ioc, Verdict,
    error::ApiResult,
    ipc::{
        CaptureSession, Case, EvidenceRef, FindingsFilter, FrameRef, IngestStatus, IocFormat,
        JobId, Lanes, PacketView, Page, Pin, QueryRequest, ReportFormat, SavedQuery, Suggestion,
        TimelineRequest,
    },
};

pub trait Backend: Send + Sync {
    // ---- capture lifecycle -------------------------------------------------
    /// Start (or resume) indexing `path`. Opens the file read-only.
    fn open_capture(&self, path: &str) -> ApiResult<JobId>;
    fn ingest_status(&self, job_id: &str) -> ApiResult<IngestStatus>;
    fn cancel_ingest(&self, job_id: &str) -> ApiResult<()>;
    fn current_capture(&self) -> ApiResult<Option<CaptureSession>>;

    // ---- query -------------------------------------------------------------
    fn query(&self, req: &QueryRequest) -> ApiResult<Page>;
    fn timeline(&self, req: &TimelineRequest) -> ApiResult<Lanes>;
    fn flow_frames(&self, flow_id: u64) -> ApiResult<Vec<FrameRef>>;
    fn packet(&self, frame_no: u64) -> ApiResult<PacketView>;
    fn autocomplete(&self, partial_filter: &str, cursor_pos: u32) -> ApiResult<Vec<Suggestion>>;
    fn list_saved_queries(&self) -> ApiResult<Vec<SavedQuery>>;
    fn save_query(&self, query: &SavedQuery) -> ApiResult<()>;
    fn delete_saved_query(&self, name: &str) -> ApiResult<()>;

    // ---- detections ----------------------------------------------------------
    fn findings(&self, filter: Option<&FindingsFilter>) -> ApiResult<Vec<Finding>>;
    fn set_verdict(&self, finding_id: &str, verdict: Verdict, note: &str) -> ApiResult<()>;

    // ---- IOCs and case -------------------------------------------------------
    fn iocs(&self, case_id: &str) -> ApiResult<Vec<Ioc>>;
    /// Writes into the case's `exports/` dir and returns the absolute path.
    fn export_iocs(&self, case_id: &str, format: IocFormat) -> ApiResult<String>;
    fn get_case(&self, case_id: &str) -> ApiResult<Case>;
    fn case_pin(&self, case_id: &str, evidence: &EvidenceRef, note: &str) -> ApiResult<Pin>;
    fn case_unpin(&self, case_id: &str, pin_id: &str) -> ApiResult<()>;
    /// Replace a pin's note, keeping its id, evidence and position.
    fn case_update_note(&self, case_id: &str, pin_id: &str, note: &str) -> ApiResult<Pin>;
    /// `timeline_png_base64`: optional PNG snapshot of the timeline canvas.
    /// Writes into the case's `exports/` dir and returns the absolute path.
    fn export_report(
        &self,
        case_id: &str,
        format: ReportFormat,
        timeline_png_base64: Option<&str>,
    ) -> ApiResult<String>;
}
