//! The real `Backend`: wires walleye-ingest → walleye-index → walleye-detect
//! → walleye-case behind the IPC contract (docs/CONTRACTS.md §3, §7, §8).
//! Owner: lead.
//!
//! On-disk layout under `data_dir` (CONTRACTS §8):
//! `captures/<capture_id>/{capture.json, index/, case/{case.sqlite, exports/}}`
//! and `saved_queries.json`. The capture file itself is only ever opened
//! read-only and is never copied or written next to.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use walleye_case::{CaseStore, ReportInput};
use walleye_core::{
    ApiError, Backend, CaptureRow, ErrorCode, Evidence, Finding, Ioc, Ts, Verdict,
    error::ApiResult,
    ipc::{
        CaptureSession, Case, EvidenceRef, FindingsFilter, FrameRef, IngestPhase, IngestStatus,
        IocFormat, JobId, Lanes, PacketView, Page, Pin, QueryLogEntry, QueryRequest, ReportFormat,
        SavedQuery, Suggestion, SuggestionKind, TimelineRequest,
    },
};
use walleye_index::{Index, IndexWriter};
use walleye_ingest::IngestOptions;

/// Where things live.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// `<data_dir>` from CONTRACTS §8.
    pub data_dir: PathBuf,
    /// Directory holding the rule YAML files and `allowlist.yaml`.
    pub rules_dir: PathBuf,
    pub ingest: IngestOptions,
}

impl EngineConfig {
    pub fn new(data_dir: impl Into<PathBuf>, rules_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            rules_dir: rules_dir.into(),
            ingest: IngestOptions::default(),
        }
    }
}

/// Maximum saved queries kept (and size of each), so the file stays small.
const MAX_SAVED: usize = 500;
const MAX_SAVED_FILTER: usize = 4096;

/// Progress of `open_blocking`, reported as it goes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Progress {
    pub phase: IngestPhase,
    /// 0..=100 across the whole job.
    pub pct: f64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub eta_s: Option<f64>,
    /// True when indexing continued from a checkpoint.
    pub resumed: bool,
}

struct Job {
    status: Mutex<IngestStatus>,
    cancel: AtomicBool,
}

/// An indexed, analysed capture with its case.
struct Opened {
    session: CaptureSession,
    path: PathBuf,
    index: Index,
    case: Mutex<CaseStore>,
    case_dir: PathBuf,
    /// Detection results (also in the index), for timeline lane badges.
    findings: Vec<Finding>,
}

type Current = Arc<RwLock<Option<Arc<Opened>>>>;

pub struct Engine {
    cfg: Arc<EngineConfig>,
    jobs: Mutex<HashMap<String, Arc<Job>>>,
    current: Current,
    saved: Mutex<Vec<SavedQuery>>,
    next_job: AtomicU64,
}

fn now_us() -> Ts {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as Ts)
        .unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn io_err(what: &str, e: std::io::Error) -> ApiError {
    ApiError::new(ErrorCode::Io, format!("{what}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Validate a user-supplied capture path: must exist and be a regular,
/// non-empty file. Returns the canonical path.
fn check_capture_path(path: &str) -> ApiResult<PathBuf> {
    if path.trim().is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidArgument, "empty path"));
    }
    let p = Path::new(path)
        .canonicalize()
        .map_err(|e| ApiError::new(ErrorCode::NotFound, format!("capture: {e}")))?;
    let meta = fs::metadata(&p).map_err(|e| io_err("capture", e))?;
    if !meta.is_file() {
        return Err(ApiError::new(
            ErrorCode::InvalidArgument,
            "capture path is not a regular file",
        ));
    }
    if meta.len() == 0 {
        return Err(ApiError::new(
            ErrorCode::BadCapture,
            "capture file is empty",
        ));
    }
    Ok(p)
}

/// Write `bytes` to `path` atomically (temp file + rename).
fn write_atomic(path: &Path, bytes: &[u8]) -> ApiResult<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| io_err("write", e))?;
    fs::rename(&tmp, path).map_err(|e| io_err("rename", e))
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> ApiResult<Self> {
        fs::create_dir_all(cfg.data_dir.join("captures")).map_err(|e| io_err("data dir", e))?;
        let saved = Self::load_saved(&cfg.data_dir);
        Ok(Self {
            cfg: Arc::new(cfg),
            jobs: Mutex::new(HashMap::new()),
            current: Arc::new(RwLock::new(None)),
            saved: Mutex::new(saved),
            next_job: AtomicU64::new(1),
        })
    }

    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    fn load_saved(data_dir: &Path) -> Vec<SavedQuery> {
        fs::read(data_dir.join("saved_queries.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<SavedQuery>>(&b).ok())
            .map(|mut v| {
                v.truncate(MAX_SAVED);
                v
            })
            .unwrap_or_default()
    }

    fn store_saved(&self, v: &[SavedQuery]) -> ApiResult<()> {
        let bytes = serde_json::to_vec_pretty(v).map_err(|e| ApiError::internal(e.to_string()))?;
        write_atomic(&self.cfg.data_dir.join("saved_queries.json"), &bytes)
    }

    fn opened(&self) -> ApiResult<Arc<Opened>> {
        self.current
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| ApiError::new(ErrorCode::NoCapture, "no capture is open"))
    }

    fn opened_case(&self, case_id: &str) -> ApiResult<Arc<Opened>> {
        let o = self.opened()?;
        if o.session.case_id != case_id {
            return Err(ApiError::not_found(format!("case {case_id}")));
        }
        Ok(o)
    }

    /// Index (or resume, or reuse) and analyse a capture synchronously, then
    /// make it the current capture. Used by the IPC job thread and by
    /// headless tools (eval, bench). `report` receives status updates.
    pub fn open_blocking(
        &self,
        path: &str,
        cancel: &AtomicBool,
        report: &mut dyn FnMut(&Progress),
    ) -> ApiResult<CaptureSession> {
        open_pipeline(&self.cfg, &self.current, path, cancel, report)
    }

    fn resolve(&self, o: &Opened, ev: &EvidenceRef) -> ApiResult<Evidence> {
        Ok(match ev {
            EvidenceRef::Frame { frame_no } => {
                let fr = o.index.frame(*frame_no)?;
                Evidence {
                    flow_ids: fr.flow_id.into_iter().collect(),
                    frame_nos: vec![*frame_no],
                    truncated: false,
                    total: 1,
                }
            }
            EvidenceRef::Flow { flow_id } => {
                let f = o.index.flow(*flow_id)?;
                Evidence {
                    flow_ids: vec![*flow_id],
                    frame_nos: vec![f.first_frame],
                    truncated: false,
                    total: 1,
                }
            }
            EvidenceRef::Finding { finding_id } => {
                let f = o
                    .index
                    .findings(None)?
                    .into_iter()
                    .find(|f| &f.finding_id == finding_id)
                    .ok_or_else(|| ApiError::not_found(format!("finding {finding_id}")))?;
                merge(f.reasons.iter().map(|r| &r.evidence))
            }
            EvidenceRef::Ioc { ioc_id } => o
                .index
                .iocs()?
                .into_iter()
                .find(|i| &i.ioc_id == ioc_id)
                .map(|i| i.evidence)
                .ok_or_else(|| ApiError::not_found(format!("ioc {ioc_id}")))?,
            EvidenceRef::Query { .. } | EvidenceRef::Note => Evidence::default(),
        })
    }

    fn findings_with_verdicts(
        &self,
        o: &Opened,
        filter: Option<&FindingsFilter>,
    ) -> ApiResult<Vec<Finding>> {
        let verdicts: HashMap<String, Verdict> = lock(&o.case)
            .verdicts()?
            .into_iter()
            .map(|v| (v.finding_id, v.verdict))
            .collect();
        let mut out = o.index.findings(filter)?;
        for f in &mut out {
            f.verdict = verdicts.get(&f.finding_id).copied();
        }
        Ok(out)
    }
}

/// Hash → index (or resume, or reuse) → detect → IOCs → open case, then make
/// it the current capture.
/// One open at a time per process: two jobs on the same capture would run two
/// writers (or a writer and `replace_findings`) on one index directory and
/// delete each other's files.
static OPEN_LOCK: Mutex<()> = Mutex::new(());

fn open_pipeline(
    cfg: &EngineConfig,
    current: &Current,
    path: &str,
    cancel: &AtomicBool,
    report: &mut dyn FnMut(&Progress),
) -> ApiResult<CaptureSession> {
    let _serial = OPEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = check_capture_path(path)?;
    let total = fs::metadata(&path).map_err(|e| io_err("capture", e))?.len();

    // 1. Hash (0–10 %). Names the capture directory.
    report(&Progress {
        phase: IngestPhase::Hashing,
        pct: 0.0,
        bytes_done: 0,
        bytes_total: total,
        eta_s: None,
        resumed: false,
    });
    let sha256 = walleye_ingest::hash_file(&path, &mut |done| {
        report(&Progress {
            phase: IngestPhase::Hashing,
            pct: 10.0 * done as f64 / total.max(1) as f64,
            bytes_done: done,
            bytes_total: total,
            eta_s: None,
            resumed: false,
        });
    })
    .map_err(|e| io_err("hash capture", e))?;
    if cancel.load(Ordering::Relaxed) {
        return Err(ApiError::new(ErrorCode::Cancelled, "cancelled"));
    }
    let capture_id = sha256.get(..16).unwrap_or(&sha256).to_string();
    // Re-opening the capture that is already open returns the live session:
    // rebuilding would replace the findings files its views are reading.
    let live = current
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .filter(|o| o.session.capture.sha256 == sha256)
        .map(|o| o.session.clone());
    if let Some(session) = live {
        report(&Progress {
            phase: IngestPhase::Done,
            pct: 100.0,
            bytes_done: total,
            bytes_total: total,
            eta_s: None,
            resumed: false,
        });
        return Ok(session);
    }
    let cap_dir = cfg.data_dir.join("captures").join(&capture_id);
    let index_dir = cap_dir.join("index");
    let case_dir = cap_dir.join("case");

    // 2. Index (10–85 %), unless a complete index already exists.
    let index = match Index::open(&index_dir) {
        Ok(ix) => ix,
        Err(e) if e.code == ErrorCode::NotFound => {
            let resumed = index_dir.join("checkpoint.json").exists();
            let mut writer = IndexWriter::create(&index_dir)?;
            let t0 = Instant::now();
            walleye_ingest::ingest(
                &path,
                &sha256,
                &mut writer,
                &cfg.ingest,
                &mut |p| {
                    let frac = p.bytes_done as f64 / p.bytes_total.max(1) as f64;
                    let secs = t0.elapsed().as_secs_f64();
                    let eta = (frac > 0.01).then(|| secs * (1.0 - frac) / frac);
                    report(&Progress {
                        phase: IngestPhase::Indexing,
                        pct: 10.0 + 75.0 * frac,
                        bytes_done: p.bytes_done,
                        bytes_total: p.bytes_total,
                        eta_s: eta,
                        resumed,
                    });
                },
                cancel,
            )?;
            drop(writer);
            Index::open(&index_dir)?
        }
        Err(e) => return Err(e),
    };
    let capture = index.capture()?;

    // 3. Detect + IOCs (85–100 %). Always re-run: cheap, and picks up
    //    rule or allowlist changes.
    report(&Progress {
        phase: IngestPhase::Detecting,
        pct: 85.0,
        bytes_done: total,
        bytes_total: total,
        eta_s: None,
        resumed: false,
    });
    let rules = walleye_detect::load_rules(&cfg.rules_dir)?;
    let allow = walleye_case::load_allowlist(&cfg.rules_dir.join("allowlist.yaml"))?;
    let findings = walleye_detect::run(&index, &rules, &allow)?;
    index.replace_findings(&findings)?;
    report(&Progress {
        phase: IngestPhase::Detecting,
        pct: 93.0,
        bytes_done: total,
        bytes_total: total,
        eta_s: None,
        resumed: false,
    });
    let iocs = walleye_case::extract_iocs(&findings, &index, &allow)?;
    index.replace_iocs(&iocs)?;

    // 4. Case store and capture.json.
    fs::create_dir_all(&case_dir).map_err(|e| io_err("case dir", e))?;
    let case = CaseStore::open(&case_dir, &capture)?;
    let cap_json =
        serde_json::to_vec_pretty(&capture).map_err(|e| ApiError::internal(e.to_string()))?;
    write_atomic(&cap_dir.join("capture.json"), &cap_json)?;

    let session = CaptureSession {
        case_id: capture.capture_id.clone(),
        capture,
    };
    let opened = Arc::new(Opened {
        session: session.clone(),
        path,
        index,
        case: Mutex::new(case),
        case_dir,
        findings,
    });
    *current.write().unwrap_or_else(|p| p.into_inner()) = Some(opened);
    report(&Progress {
        phase: IngestPhase::Done,
        pct: 100.0,
        bytes_done: total,
        bytes_total: total,
        eta_s: Some(0.0),
        resumed: false,
    });
    Ok(session)
}

fn merge<'a>(evs: impl Iterator<Item = &'a Evidence>) -> Evidence {
    let (mut sf, mut sn) = (HashSet::new(), HashSet::new());
    let mut out = Evidence::default();
    for e in evs {
        out.total += e.total;
        out.truncated |= e.truncated;
        out.flow_ids
            .extend(e.flow_ids.iter().filter(|x| sf.insert(**x)));
        out.frame_nos
            .extend(e.frame_nos.iter().filter(|x| sn.insert(**x)));
    }
    out
}

impl Backend for Engine {
    fn open_capture(&self, path: &str) -> ApiResult<JobId> {
        // Validate up front so obvious mistakes fail the call, not the job.
        let canonical = check_capture_path(path)?;
        let id = format!("job-{}", self.next_job.fetch_add(1, Ordering::Relaxed));
        let total = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
        let job = Arc::new(Job {
            status: Mutex::new(IngestStatus {
                job_id: id.clone(),
                phase: IngestPhase::Queued,
                pct: 0.0,
                bytes_done: 0,
                bytes_total: total,
                eta_s: None,
                error: None,
                resumed: false,
                session: None,
            }),
            cancel: AtomicBool::new(false),
        });
        lock(&self.jobs).insert(id.clone(), job.clone());

        let (cfg, current) = (self.cfg.clone(), self.current.clone());
        let path = canonical.to_string_lossy().into_owned();
        std::thread::Builder::new()
            .name(format!("walleye-{id}"))
            .spawn(move || {
                let j = job.clone();
                // A panic in ingest (a parser bug on a hostile capture) must
                // end the job as `failed`, not leave it "indexing" forever.
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    open_pipeline(&cfg, &current, &path, &job.cancel, &mut |p: &Progress| {
                        let mut st = lock(&j.status);
                        st.phase = p.phase;
                        st.pct = (p.pct * 10.0).round() / 10.0;
                        st.bytes_done = p.bytes_done;
                        st.bytes_total = p.bytes_total;
                        st.eta_s = p.eta_s;
                        st.resumed |= p.resumed;
                    })
                }))
                .unwrap_or_else(|_| {
                    Err(ApiError::internal(
                        "ingest crashed on this capture (internal error); the capture may be malformed",
                    ))
                });
                let mut st = lock(&job.status);
                match res {
                    Ok(session) => {
                        st.phase = IngestPhase::Done;
                        st.pct = 100.0;
                        st.session = Some(session);
                    }
                    Err(e) if e.code == ErrorCode::Cancelled => {
                        st.phase = IngestPhase::Cancelled;
                        st.error = Some(e.message);
                    }
                    Err(e) => {
                        st.phase = IngestPhase::Failed;
                        st.error = Some(e.message);
                    }
                }
            })
            .map_err(|e| ApiError::internal(format!("spawn: {e}")))?;
        Ok(id)
    }

    fn ingest_status(&self, job_id: &str) -> ApiResult<IngestStatus> {
        let j = lock(&self.jobs)
            .get(job_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found(format!("job {job_id}")))?;
        Ok(lock(&j.status).clone())
    }

    fn cancel_ingest(&self, job_id: &str) -> ApiResult<()> {
        let j = lock(&self.jobs)
            .get(job_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found(format!("job {job_id}")))?;
        j.cancel.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn current_capture(&self) -> ApiResult<Option<CaptureSession>> {
        Ok(self.opened().ok().map(|o| o.session.clone()))
    }

    fn query(&self, req: &QueryRequest) -> ApiResult<Page> {
        let o = self.opened()?;
        let page = o.index.query(req)?;
        // The query log feeds the report's "queries used"; a logging failure
        // must not fail the query itself.
        let _ = lock(&o.case).log_query(&QueryLogEntry {
            filter: logged_filter(req),
            view: req.view,
            time_range: req.time_range,
            sql: page.sql.clone(),
            rows: page.data.len() as u64,
            at: now_us(),
        });
        Ok(page)
    }

    fn timeline(&self, req: &TimelineRequest) -> ApiResult<Lanes> {
        let o = self.opened()?;
        o.index.timeline(req, &o.findings)
    }

    fn flow_frames(&self, flow_id: u64) -> ApiResult<Vec<FrameRef>> {
        self.opened()?.index.flow_frames(flow_id)
    }

    fn packet(&self, frame_no: u64) -> ApiResult<PacketView> {
        let o = self.opened()?;
        let fr = o.index.frame(frame_no)?;
        let bytes = walleye_ingest::read_frame(&o.path, fr.file_offset, fr.caplen)
            .map_err(|e| io_err("read frame", e))?;
        let link_type = fr.link_type.unwrap_or(o.session.capture.link_type);
        Ok(PacketView {
            frame_no,
            ts: fr.ts,
            caplen: fr.caplen,
            wirelen: fr.wirelen,
            link_type,
            flow_id: fr.flow_id,
            decode_tree: walleye_ingest::decode_frame(link_type, &bytes),
            bytes_hex: hex(&bytes),
        })
    }

    fn autocomplete(&self, partial: &str, cursor_pos: u32) -> ApiResult<Vec<Suggestion>> {
        let mut out = match self.opened() {
            Ok(o) => o.index.autocomplete(partial, cursor_pos)?,
            Err(_) => Vec::new(),
        };
        let cur = (cursor_pos as usize).min(partial.len());
        let prefix = partial.get(..cur).unwrap_or("");
        if !prefix.contains(char::is_whitespace) {
            let p = prefix.to_lowercase();
            out.extend(
                lock(&self.saved)
                    .iter()
                    .filter(|s| s.name.to_lowercase().starts_with(&p))
                    .map(|s| Suggestion {
                        label: s.name.clone(),
                        insert_text: s.filter.clone(),
                        kind: SuggestionKind::Saved,
                        detail: Some(s.filter.clone()),
                        replace_start: 0,
                        replace_end: partial.len() as u32,
                    }),
            );
        }
        out.truncate(50);
        Ok(out)
    }

    fn list_saved_queries(&self) -> ApiResult<Vec<SavedQuery>> {
        Ok(lock(&self.saved).clone())
    }

    fn save_query(&self, query: &SavedQuery) -> ApiResult<()> {
        let name = query.name.trim();
        if name.is_empty() || name.len() > 200 {
            return Err(ApiError::new(
                ErrorCode::InvalidArgument,
                "name must be 1–200 characters",
            ));
        }
        if query.filter.len() > MAX_SAVED_FILTER {
            return Err(ApiError::new(ErrorCode::InvalidArgument, "filter too long"));
        }
        walleye_index::filter::parse(&query.filter)?;
        let mut saved = lock(&self.saved);
        saved.retain(|s| s.name != name);
        if saved.len() >= MAX_SAVED {
            return Err(ApiError::new(
                ErrorCode::InvalidArgument,
                "too many saved queries",
            ));
        }
        saved.push(SavedQuery {
            name: name.to_string(),
            ..query.clone()
        });
        self.store_saved(&saved)
    }

    fn delete_saved_query(&self, name: &str) -> ApiResult<()> {
        let mut saved = lock(&self.saved);
        saved.retain(|s| s.name != name);
        self.store_saved(&saved)
    }

    fn findings(&self, filter: Option<&FindingsFilter>) -> ApiResult<Vec<Finding>> {
        let o = self.opened()?;
        self.findings_with_verdicts(&o, filter)
    }

    fn set_verdict(&self, finding_id: &str, verdict: Verdict, note: &str) -> ApiResult<()> {
        let o = self.opened()?;
        if !o.findings.iter().any(|f| f.finding_id == finding_id) {
            return Err(ApiError::not_found(format!("finding {finding_id}")));
        }
        lock(&o.case).set_verdict(finding_id, verdict, note)
    }

    fn iocs(&self, case_id: &str) -> ApiResult<Vec<Ioc>> {
        self.opened_case(case_id)?.index.iocs()
    }

    fn export_iocs(&self, case_id: &str, format: IocFormat) -> ApiResult<String> {
        let o = self.opened_case(case_id)?;
        let iocs = o.index.iocs()?;
        let p = walleye_case::export_iocs(
            &iocs,
            &o.session.capture,
            format,
            &o.case_dir.join("exports"),
        )?;
        Ok(p.to_string_lossy().into_owned())
    }

    fn get_case(&self, case_id: &str) -> ApiResult<Case> {
        lock(&self.opened_case(case_id)?.case).get_case()
    }

    fn case_pin(&self, case_id: &str, evidence: &EvidenceRef, note: &str) -> ApiResult<Pin> {
        let o = self.opened_case(case_id)?;
        let resolved = self.resolve(&o, evidence)?;
        lock(&o.case).pin(evidence, note, &resolved)
    }

    fn case_unpin(&self, case_id: &str, pin_id: &str) -> ApiResult<()> {
        lock(&self.opened_case(case_id)?.case).unpin(pin_id)
    }

    fn case_update_note(&self, case_id: &str, pin_id: &str, note: &str) -> ApiResult<Pin> {
        lock(&self.opened_case(case_id)?.case).update_note(pin_id, note)
    }

    fn export_report(
        &self,
        case_id: &str,
        format: ReportFormat,
        timeline_png_base64: Option<&str>,
    ) -> ApiResult<String> {
        let o = self.opened_case(case_id)?;
        let png = timeline_png_base64
            .filter(|s| !s.is_empty())
            .map(walleye_case::decode_timeline_png)
            .transpose()?;
        let case = lock(&o.case).get_case()?;
        let findings = self.findings_with_verdicts(&o, None)?;
        let iocs = o.index.iocs()?;
        let input = ReportInput {
            capture: &o.session.capture,
            case: &case,
            findings: &findings,
            iocs: &iocs,
            timeline_png: png.as_deref(),
        };
        let p = walleye_case::export_report(&input, format, &o.case_dir.join("exports"))?;
        Ok(p.to_string_lossy().into_owned())
    }
}

/// Convenience for tools: capture row of the open capture.
pub fn capture_of(e: &Engine) -> ApiResult<CaptureRow> {
    Ok(e.opened()?.session.capture.clone())
}

/// The filter as the report shows it: the text the analyst typed, plus the
/// structured `hosts`/`flow_ids` selection (timeline lanes, brushes, pivots)
/// written as equivalent filter syntax, so "queries used" states the real scope.
fn logged_filter(req: &QueryRequest) -> String {
    let mut parts = Vec::new();
    if !req.filter.trim().is_empty() {
        parts.push(format!("({})", req.filter.trim()));
    }
    if !req.hosts.is_empty() {
        let hosts: Vec<String> = req.hosts.iter().map(|h| format!("host {h}")).collect();
        parts.push(if hosts.len() == 1 {
            hosts[0].clone()
        } else {
            format!("({})", hosts.join(" or "))
        });
    }
    if !req.flow_ids.is_empty() {
        const SHOWN: usize = 20;
        let ids: Vec<String> = req
            .flow_ids
            .iter()
            .take(SHOWN)
            .map(u64::to_string)
            .collect();
        let more = req.flow_ids.len().saturating_sub(SHOWN);
        let tail = if more > 0 {
            format!(", … {more} more")
        } else {
            String::new()
        };
        parts.push(format!("flow_id in [{}{tail}]", ids.join(", ")));
    }
    if req.hosts.is_empty() && req.flow_ids.is_empty() {
        return req.filter.clone();
    }
    parts.join(" and ")
}

#[cfg(test)]
mod logged_filter_tests {
    use super::*;

    fn req(filter: &str, hosts: &[&str], flow_ids: &[u64]) -> QueryRequest {
        QueryRequest {
            filter: filter.into(),
            view: walleye_core::ipc::View::Flows,
            time_range: None,
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            flow_ids: flow_ids.to_vec(),
            sort: None,
            limit: 10,
            cursor: None,
        }
    }

    #[test]
    fn selection_is_written_into_the_logged_filter() {
        assert_eq!(logged_filter(&req("dns", &[], &[])), "dns");
        assert_eq!(logged_filter(&req("", &["10.0.0.5"], &[])), "host 10.0.0.5");
        assert_eq!(
            logged_filter(&req("port 80", &["10.0.0.5", "10.0.0.6"], &[3])),
            "(port 80) and (host 10.0.0.5 or host 10.0.0.6) and flow_id in [3]"
        );
        let many: Vec<u64> = (1..=25).collect();
        assert!(logged_filter(&req("", &[], &many)).ends_with(", 20, … 5 more]"));
    }
}
