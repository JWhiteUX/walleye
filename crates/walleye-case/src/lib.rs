//! walleye-case: IOC extraction (defang, dedupe, allowlist), IOC exports,
//! the per-capture case store (pins, notes, verdicts, query log) and report
//! export (Markdown and PDF). API per `docs/CONTRACTS.md` §7.

pub mod export;
pub mod ioc;
pub mod pdf;
pub mod report;
pub mod store;
pub mod timefmt;

use std::path::Path;

pub use export::{ExportOptions, export_iocs, export_iocs_with};
pub use ioc::{defang, extract_iocs, normalize, refang};
pub use report::{ReportInput, decode_timeline_png, export_report};
pub use store::CaseStore;

use walleye_core::{Allowlist, ApiError, ErrorCode, error::ApiResult};

/// Largest allowlist file accepted.
pub const MAX_ALLOWLIST_BYTES: u64 = 4 * 1024 * 1024;

/// Load and validate `rules/allowlist.yaml` (or a user copy).
pub fn load_allowlist(path: &Path) -> ApiResult<Allowlist> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_ALLOWLIST_BYTES {
        return Err(ApiError::new(
            ErrorCode::InvalidArgument,
            "allowlist file is too large",
        ));
    }
    let text = std::fs::read_to_string(path)?;
    Allowlist::from_yaml(&text)
        .map_err(|e| ApiError::new(ErrorCode::InvalidArgument, format!("allowlist: {e}")))
}
