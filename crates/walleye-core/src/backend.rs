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
        TimeRange, TimelineRequest,
    },
};

/// Cap on `device_frames` results.
pub const DEVICE_FRAMES_CAP: usize = 10_000;

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
    /// 802.11 frames (`wifi` rows) where `mac` is src, dst, tx or bssid, in
    /// frame order, inside `time_range` when given. At most
    /// `DEVICE_FRAMES_CAP`, earliest first. `mac` must be a MAC address
    /// (`invalid_argument` otherwise); no 802.11 data → empty.
    fn device_frames(&self, mac: &str, time_range: Option<TimeRange>) -> ApiResult<Vec<FrameRef>>;
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

/// Dispatch a command by name with JSON arguments, exactly as the Tauri
/// commands do (snake_case names and args, CONTRACTS §3). Used by the
/// dev-only HTTP bridge (`tools/walleye-devbridge`) so Playwright can drive
/// the UI against the real engine. The Tauri app does not use this; its
/// commands are explicit in `app/src-tauri/src/commands.rs`.
pub fn dispatch(
    b: &dyn Backend,
    cmd: &str,
    args: serde_json::Value,
) -> ApiResult<serde_json::Value> {
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    use crate::ApiError;
    use crate::ErrorCode;

    fn arg<T: DeserializeOwned>(args: &Value, k: &str) -> ApiResult<T> {
        serde_json::from_value(args.get(k).cloned().unwrap_or(Value::Null))
            .map_err(|e| ApiError::new(ErrorCode::InvalidArgument, format!("argument {k}: {e}")))
    }
    fn out<T: serde::Serialize>(v: ApiResult<T>) -> ApiResult<Value> {
        v.and_then(|v| serde_json::to_value(v).map_err(|e| ApiError::internal(e.to_string())))
    }
    let a = &args;
    match cmd {
        "open_capture" => out(b.open_capture(&arg::<String>(a, "path")?)),
        "ingest_status" => out(b.ingest_status(&arg::<String>(a, "job_id")?)),
        "cancel_ingest" => out(b.cancel_ingest(&arg::<String>(a, "job_id")?)),
        "current_capture" => out(b.current_capture()),
        "query" => out(b.query(&arg(a, "req")?)),
        "timeline" => out(b.timeline(&arg(a, "req")?)),
        "flow_frames" => out(b.flow_frames(arg(a, "flow_id")?)),
        "device_frames" => out(b.device_frames(
            &arg::<String>(a, "mac")?,
            arg::<Option<TimeRange>>(a, "time_range")?,
        )),
        "packet" => out(b.packet(arg(a, "frame_no")?)),
        "autocomplete" => {
            out(b.autocomplete(&arg::<String>(a, "partial_filter")?, arg(a, "cursor_pos")?))
        }
        "list_saved_queries" => out(b.list_saved_queries()),
        "save_query" => out(b.save_query(&arg(a, "query")?)),
        "delete_saved_query" => out(b.delete_saved_query(&arg::<String>(a, "name")?)),
        "findings" => out(b.findings(arg::<Option<FindingsFilter>>(a, "filter")?.as_ref())),
        "set_verdict" => out(b.set_verdict(
            &arg::<String>(a, "finding_id")?,
            arg(a, "verdict")?,
            &arg::<Option<String>>(a, "note")?.unwrap_or_default(),
        )),
        "iocs" => out(b.iocs(&arg::<String>(a, "case_id")?)),
        "export_iocs" => out(b.export_iocs(&arg::<String>(a, "case_id")?, arg(a, "format")?)),
        "get_case" => out(b.get_case(&arg::<String>(a, "case_id")?)),
        "case_pin" => out(b.case_pin(
            &arg::<String>(a, "case_id")?,
            &arg(a, "evidence")?,
            &arg::<Option<String>>(a, "note")?.unwrap_or_default(),
        )),
        "case_unpin" => {
            out(b.case_unpin(&arg::<String>(a, "case_id")?, &arg::<String>(a, "pin_id")?))
        }
        "case_update_note" => out(b.case_update_note(
            &arg::<String>(a, "case_id")?,
            &arg::<String>(a, "pin_id")?,
            &arg::<String>(a, "note")?,
        )),
        "export_report" => out(b.export_report(
            &arg::<String>(a, "case_id")?,
            arg(a, "format")?,
            arg::<Option<String>>(a, "timeline_png_base64")?.as_deref(),
        )),
        other => Err(ApiError::new(
            ErrorCode::InvalidArgument,
            format!("unknown command {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockBackend;

    #[test]
    fn dispatch_matches_direct_calls() {
        let m = MockBackend::preopened();
        let v = dispatch(
            &m,
            "query",
            serde_json::json!({"req": {"filter": "", "view": "flows", "limit": 3}}),
        )
        .expect("query");
        assert_eq!(v["data"]["rows"].as_array().map(Vec::len), Some(3));
        assert!(dispatch(&m, "nope", serde_json::json!({})).is_err());
        assert!(dispatch(&m, "packet", serde_json::json!({"frame_no": "x"})).is_err());
    }
}
