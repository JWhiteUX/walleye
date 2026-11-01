//! Row types for the index tables. One Parquet dataset per table, exposed as a
//! DuckDB view of the same name. Column names and order match these structs.
//!
//! IP addresses are canonical text (`std::net::IpAddr` Display). Optional
//! columns are NULL in Parquet and `null` over IPC.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{FlowId, FrameNo, Ts};

/// Capture file container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum CaptureFormat {
    Pcap,
    Pcapng,
}

/// `captures` table: one row per indexed capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CaptureRow {
    /// First 16 hex chars of `sha256`. Names the index directory.
    pub capture_id: String,
    /// Absolute path the capture was opened from (informational only).
    pub path: String,
    /// Lowercase hex SHA-256 of the whole capture file.
    pub sha256: String,
    #[ts(type = "number")]
    pub size_bytes: u64,
    pub format: CaptureFormat,
    #[ts(type = "number")]
    pub first_ts: Ts,
    #[ts(type = "number")]
    pub last_ts: Ts,
    /// LINKTYPE_* value of the first interface (1 = Ethernet).
    pub link_type: u32,
    #[ts(type = "number")]
    pub frame_count: u64,
}

/// Direction of a frame relative to its flow. `Up` is initiator → responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum Direction {
    Up,
    Down,
}

/// `frames` table: one row per packet record in the capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FrameRow {
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    #[ts(type = "number")]
    pub ts: Ts,
    /// Byte offset of the packet *data* (after the record header) in the
    /// capture file, so `packet()` can read `caplen` bytes without re-parsing.
    #[ts(type = "number")]
    pub file_offset: u64,
    pub caplen: u32,
    pub wirelen: u32,
    /// NULL for frames that do not belong to an IP flow (ARP, malformed, ...).
    #[ts(type = "number | null")]
    pub flow_id: Option<FlowId>,
    pub direction: Option<Direction>,
    /// TCP flags byte (FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20).
    pub tcp_flags: Option<u8>,
    /// Transport payload length in bytes (0 when none or unknown).
    pub payload_len: u32,
    /// LINKTYPE_* of the interface this frame came from (pcapng may mix
    /// link types). NULL means "use `CaptureRow.link_type`".
    #[serde(default)]
    pub link_type: Option<u32>,
}

/// `flows` table: one row per bidirectional flow (5-tuple + idle timeout).
/// `src` is the initiator (first packet seen, or SYN sender).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FlowRow {
    #[ts(type = "number")]
    pub flow_id: FlowId,
    #[ts(type = "number")]
    pub ts_start: Ts,
    #[ts(type = "number")]
    pub ts_end: Ts,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    /// IANA protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6).
    pub proto: u8,
    /// Detected application protocol: "dns", "http", "tls", or NULL.
    pub app_proto: Option<String>,
    #[ts(type = "number")]
    pub bytes_up: u64,
    #[ts(type = "number")]
    pub bytes_down: u64,
    #[ts(type = "number")]
    pub pkts_up: u64,
    #[ts(type = "number")]
    pub pkts_down: u64,
    #[ts(type = "number")]
    pub first_frame: FrameNo,
    #[ts(type = "number")]
    pub last_frame: FrameNo,
}

/// `dns` table: one row per DNS message (query or response), Zeek dns.log-like.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DnsRow {
    #[ts(type = "number")]
    pub ts: Ts,
    #[ts(type = "number")]
    pub flow_id: FlowId,
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    pub trans_id: u16,
    pub is_response: bool,
    /// Query name, lowercased, no trailing dot.
    pub query: String,
    /// Mnemonic ("A", "AAAA", "TXT", "NULL", ...) or "TYPE<n>".
    pub qtype: String,
    /// Mnemonic ("NOERROR", "NXDOMAIN", ...) or "RCODE<n>". NULL on queries.
    pub rcode: Option<String>,
    /// Answer RDATA as text (addresses, names, TXT strings); empty on queries.
    pub answers: Vec<String>,
    /// Minimum TTL across answers.
    pub ttl: Option<u32>,
}

/// `http` table: one row per HTTP/1.x request, paired with its response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct HttpRow {
    #[ts(type = "number")]
    pub ts: Ts,
    #[ts(type = "number")]
    pub flow_id: FlowId,
    /// Frame carrying the request line.
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    pub method: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub user_agent: Option<String>,
    pub status: Option<u16>,
    /// Frame carrying the status line, when seen.
    #[ts(type = "number | null")]
    pub resp_frame_no: Option<FrameNo>,
    #[ts(type = "number")]
    pub req_bytes: u64,
    #[ts(type = "number")]
    pub resp_bytes: u64,
}

/// `tls` table: one row per TLS handshake (ClientHello seen).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TlsRow {
    #[ts(type = "number")]
    pub ts: Ts,
    #[ts(type = "number")]
    pub flow_id: FlowId,
    /// Frame carrying the ClientHello.
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    pub sni: Option<String>,
    /// Negotiated version, e.g. "TLS 1.3"; offered max if no ServerHello.
    pub version: Option<String>,
    /// JA4 client fingerprint (FoxIO spec).
    pub ja4: Option<String>,
    /// JA4S server fingerprint (FoxIO spec).
    pub ja4s: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    /// Lowercase hex, no separators.
    pub cert_serial: Option<String>,
    pub cert_self_signed: Option<bool>,
    #[ts(type = "number | null")]
    pub cert_not_before: Option<Ts>,
    #[ts(type = "number | null")]
    pub cert_not_after: Option<Ts>,
}

/// `files` table: file-transfer *metadata* only (no carving). One row per
/// transferred object seen in HTTP bodies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileRow {
    #[ts(type = "number")]
    pub ts: Ts,
    #[ts(type = "number")]
    pub flow_id: FlowId,
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    /// Carrier protocol, "http" in the MVP.
    pub source: String,
    pub direction: Direction,
    /// From Content-Disposition or the URI's last path segment.
    pub filename: Option<String>,
    /// Declared Content-Type (not sniffed).
    pub mime_type: Option<String>,
    /// Declared Content-Length, or observed body bytes.
    #[ts(type = "number | null")]
    pub size_bytes: Option<u64>,
}
