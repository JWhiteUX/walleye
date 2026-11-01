//! IPC commands. The UI calls these with `invoke("<name>", { args })` from
//! `app/src/shared/ipc.ts`. `rename_all = "snake_case"` keeps argument names
//! identical on both sides (Tauri's default would expect camelCase in JS).
//!
//! Every command is `async` and runs the backend call on Tauri's blocking
//! pool, so a slow query never freezes the window (sync commands run on the
//! main thread).

use std::sync::Arc;

use tauri::State;
use walleye_core::{
    ApiError, Backend, Finding, Ioc, Verdict,
    ipc::{
        CaptureSession, Case, EvidenceRef, FindingsFilter, FrameRef, IngestStatus, IocFormat,
        JobId, Lanes, PacketView, Page, Pin, QueryRequest, ReportFormat, SavedQuery, Suggestion,
        TimelineRequest,
    },
};

use crate::AppState;

type R<T> = Result<T, ApiError>;

async fn run<T, F>(state: State<'_, AppState>, f: F) -> R<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn Backend) -> R<T> + Send + 'static,
{
    let b: Arc<dyn Backend> = state.backend.clone();
    tauri::async_runtime::spawn_blocking(move || f(b.as_ref()))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
}

#[tauri::command(rename_all = "snake_case")]
async fn open_capture(state: State<'_, AppState>, path: String) -> R<JobId> {
    run(state, move |b| b.open_capture(&path)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn ingest_status(state: State<'_, AppState>, job_id: String) -> R<IngestStatus> {
    run(state, move |b| b.ingest_status(&job_id)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn cancel_ingest(state: State<'_, AppState>, job_id: String) -> R<()> {
    run(state, move |b| b.cancel_ingest(&job_id)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn current_capture(state: State<'_, AppState>) -> R<Option<CaptureSession>> {
    run(state, |b| b.current_capture()).await
}

#[tauri::command(rename_all = "snake_case")]
async fn query(state: State<'_, AppState>, req: QueryRequest) -> R<Page> {
    run(state, move |b| b.query(&req)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn timeline(state: State<'_, AppState>, req: TimelineRequest) -> R<Lanes> {
    run(state, move |b| b.timeline(&req)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn flow_frames(state: State<'_, AppState>, flow_id: u64) -> R<Vec<FrameRef>> {
    run(state, move |b| b.flow_frames(flow_id)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn packet(state: State<'_, AppState>, frame_no: u64) -> R<PacketView> {
    run(state, move |b| b.packet(frame_no)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn autocomplete(
    state: State<'_, AppState>,
    partial_filter: String,
    cursor_pos: u32,
) -> R<Vec<Suggestion>> {
    run(state, move |b| b.autocomplete(&partial_filter, cursor_pos)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn list_saved_queries(state: State<'_, AppState>) -> R<Vec<SavedQuery>> {
    run(state, |b| b.list_saved_queries()).await
}

#[tauri::command(rename_all = "snake_case")]
async fn save_query(state: State<'_, AppState>, query: SavedQuery) -> R<()> {
    run(state, move |b| b.save_query(&query)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn delete_saved_query(state: State<'_, AppState>, name: String) -> R<()> {
    run(state, move |b| b.delete_saved_query(&name)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn findings(state: State<'_, AppState>, filter: Option<FindingsFilter>) -> R<Vec<Finding>> {
    run(state, move |b| b.findings(filter.as_ref())).await
}

#[tauri::command(rename_all = "snake_case")]
async fn set_verdict(
    state: State<'_, AppState>,
    finding_id: String,
    verdict: Verdict,
    note: String,
) -> R<()> {
    run(state, move |b| b.set_verdict(&finding_id, verdict, &note)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn iocs(state: State<'_, AppState>, case_id: String) -> R<Vec<Ioc>> {
    run(state, move |b| b.iocs(&case_id)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn export_iocs(state: State<'_, AppState>, case_id: String, format: IocFormat) -> R<String> {
    run(state, move |b| b.export_iocs(&case_id, format)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn get_case(state: State<'_, AppState>, case_id: String) -> R<Case> {
    run(state, move |b| b.get_case(&case_id)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn case_pin(
    state: State<'_, AppState>,
    case_id: String,
    evidence: EvidenceRef,
    note: String,
) -> R<Pin> {
    run(state, move |b| b.case_pin(&case_id, &evidence, &note)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn case_unpin(state: State<'_, AppState>, case_id: String, pin_id: String) -> R<()> {
    run(state, move |b| b.case_unpin(&case_id, &pin_id)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn case_update_note(
    state: State<'_, AppState>,
    case_id: String,
    pin_id: String,
    note: String,
) -> R<Pin> {
    run(state, move |b| b.case_update_note(&case_id, &pin_id, &note)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn export_report(
    state: State<'_, AppState>,
    case_id: String,
    format: ReportFormat,
    timeline_png_base64: Option<String>,
) -> R<String> {
    run(state, move |b| {
        b.export_report(&case_id, format, timeline_png_base64.as_deref())
    })
    .await
}

/// Every command the UI may call. Adding one here also requires a matching
/// entry in `app/src/shared/ipc.ts` and docs/CONTRACTS.md §3.
pub fn handler() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        open_capture,
        ingest_status,
        cancel_ingest,
        current_capture,
        query,
        timeline,
        flow_frames,
        packet,
        autocomplete,
        list_saved_queries,
        save_query,
        delete_saved_query,
        findings,
        set_verdict,
        iocs,
        export_iocs,
        get_case,
        case_pin,
        case_unpin,
        case_update_note,
        export_report,
    ]
}
