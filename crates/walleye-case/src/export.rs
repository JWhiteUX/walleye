//! IOC exports: CSV (RFC 4180) and JSON. Both carry the capture's SHA-256 and
//! each IOC's frame numbers. Values are exported defanged by default.

use std::path::{Path, PathBuf};

use serde::Serialize;
use walleye_core::{ApiError, CaptureRow, Evidence, Ioc, error::ApiResult, ipc::IocFormat};

use crate::{ioc::type_name, timefmt};

/// How indicator values are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Write the defanged form (default). `false` writes live values, for
    /// feeding tools that cannot refang.
    pub defang: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self { defang: true }
    }
}

pub const CSV_HEADER: [&str; 14] = [
    "ioc_id",
    "type",
    "indicator",
    "defanged",
    "first_seen",
    "first_seen_us",
    "allowlisted",
    "allowlist_reason",
    "source_finding_id",
    "evidence_total",
    "evidence_truncated",
    "frame_nos",
    "flow_ids",
    "capture_sha256",
];

/// One CSV cell: neutralize spreadsheet formulas, then quote per RFC 4180.
///
/// A cell starting with `=`, `+`, `-`, `@`, TAB or CR is prefixed with `'`
/// so spreadsheet apps treat it as text (OWASP CSV injection guidance).
pub fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter().map(T::to_string).collect::<Vec<_>>().join(" ")
}

fn indicator(i: &Ioc, opts: ExportOptions) -> &str {
    if opts.defang { &i.defanged } else { &i.value }
}

/// Render the CSV text. Lines end with CRLF (RFC 4180).
pub fn iocs_csv(iocs: &[Ioc], capture: &CaptureRow, opts: ExportOptions) -> String {
    let mut out = CSV_HEADER.join(",");
    out.push_str("\r\n");
    for i in iocs {
        let row = [
            i.ioc_id.clone(),
            type_name(i.ioc_type).to_string(),
            indicator(i, opts).to_string(),
            opts.defang.to_string(),
            timefmt::iso(i.first_seen),
            i.first_seen.to_string(),
            i.allowlisted.to_string(),
            i.allowlist_reason.clone().unwrap_or_default(),
            i.source_finding_id.clone().unwrap_or_default(),
            i.evidence.total.to_string(),
            i.evidence.truncated.to_string(),
            join(&i.evidence.frame_nos),
            join(&i.evidence.flow_ids),
            capture.sha256.clone(),
        ];
        let cells: Vec<String> = row.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&cells.join(","));
        out.push_str("\r\n");
    }
    out
}

#[derive(Serialize)]
struct JsonCapture<'a> {
    capture_id: &'a str,
    sha256: &'a str,
    path: &'a str,
    size_bytes: u64,
    first_ts: i64,
    last_ts: i64,
    frame_count: u64,
}

#[derive(Serialize)]
struct JsonIoc<'a> {
    ioc_id: &'a str,
    #[serde(rename = "type")]
    ioc_type: &'static str,
    indicator: &'a str,
    first_seen: String,
    first_seen_us: i64,
    allowlisted: bool,
    allowlist_reason: Option<&'a str>,
    source_finding_id: Option<&'a str>,
    evidence: &'a Evidence,
}

#[derive(Serialize)]
struct JsonExport<'a> {
    format: &'static str,
    version: u32,
    generator: String,
    defanged: bool,
    capture: JsonCapture<'a>,
    iocs: Vec<JsonIoc<'a>>,
}

/// Render the JSON text (pretty, trailing newline).
pub fn iocs_json(iocs: &[Ioc], capture: &CaptureRow, opts: ExportOptions) -> ApiResult<String> {
    let doc = JsonExport {
        format: "walleye-iocs",
        version: 1,
        generator: format!("walleye {}", env!("CARGO_PKG_VERSION")),
        defanged: opts.defang,
        capture: JsonCapture {
            capture_id: &capture.capture_id,
            sha256: &capture.sha256,
            path: &capture.path,
            size_bytes: capture.size_bytes,
            first_ts: capture.first_ts,
            last_ts: capture.last_ts,
            frame_count: capture.frame_count,
        },
        iocs: iocs
            .iter()
            .map(|i| JsonIoc {
                ioc_id: &i.ioc_id,
                ioc_type: type_name(i.ioc_type),
                indicator: indicator(i, opts),
                first_seen: timefmt::iso(i.first_seen),
                first_seen_us: i.first_seen,
                allowlisted: i.allowlisted,
                allowlist_reason: i.allowlist_reason.as_deref(),
                source_finding_id: i.source_finding_id.as_deref(),
                evidence: &i.evidence,
            })
            .collect(),
    };
    let mut s =
        serde_json::to_string_pretty(&doc).map_err(|e| ApiError::internal(e.to_string()))?;
    s.push('\n');
    Ok(s)
}

/// Write `bytes` to `dir/name` via a temporary file and rename, so a reader
/// never sees a half-written export. Returns the absolute path.
pub(crate) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> ApiResult<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let dir = std::fs::canonicalize(dir)?;
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, bytes)?;
    let path = dir.join(name);
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Contract entry point (CONTRACTS §7): defanged export into `out_dir`
/// (`iocs.csv` / `iocs.json`).
pub fn export_iocs(
    iocs: &[Ioc],
    capture: &CaptureRow,
    format: IocFormat,
    out_dir: &Path,
) -> ApiResult<PathBuf> {
    export_iocs_with(iocs, capture, format, out_dir, ExportOptions::default())
}

pub fn export_iocs_with(
    iocs: &[Ioc],
    capture: &CaptureRow,
    format: IocFormat,
    out_dir: &Path,
    opts: ExportOptions,
) -> ApiResult<PathBuf> {
    match format {
        IocFormat::Csv => write_atomic(
            out_dir,
            "iocs.csv",
            iocs_csv(iocs, capture, opts).as_bytes(),
        ),
        IocFormat::Json => write_atomic(
            out_dir,
            "iocs.json",
            iocs_json(iocs, capture, opts)?.as_bytes(),
        ),
    }
}
