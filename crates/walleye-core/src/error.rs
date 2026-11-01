use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ErrorCode {
    /// Filter text failed to parse or type-check. `span` points at the problem.
    InvalidFilter,
    InvalidArgument,
    NotFound,
    /// No capture is open yet.
    NoCapture,
    /// File is not pcap/pcapng or is corrupt beyond recovery.
    BadCapture,
    Io,
    Cancelled,
    Internal,
}

/// Byte span into a filter string, half-open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

/// The only error type that crosses IPC. Messages must not include raw
/// capture bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS, thiserror::Error)]
#[error("{code:?}: {message}")]
#[ts(export)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub span: Option<Span>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            span: None,
        }
    }
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, what)
    }
    pub fn invalid_filter(message: impl Into<String>, span: Span) -> Self {
        Self {
            code: ErrorCode::InvalidFilter,
            message: message.into(),
            span: Some(span),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, e.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
