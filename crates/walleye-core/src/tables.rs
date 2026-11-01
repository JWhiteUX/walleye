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

/// 802.11 frame class for the `wifi` table (contract v2). Control frames
/// (ACK, RTS, CTS, block-ack) are not rows: they stay in `frames` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum WifiKind {
    Beacon,
    ProbeReq,
    ProbeResp,
    Auth,
    Deauth,
    AssocReq,
    AssocResp,
    ReassocReq,
    ReassocResp,
    Disassoc,
    Action,
    /// Any other management subtype (ATIM, timing advert, reserved).
    MgmtOther,
    /// Data or QoS data with a payload (protected or not).
    Data,
    /// Null / QoS null (power-save signalling, no payload).
    Null,
    /// Unprotected data frame carrying EAPOL (WPA handshake, 802.1X).
    Eapol,
}

impl WifiKind {
    /// snake_case name, as stored in Parquet and typed in filters.
    pub fn as_str(self) -> &'static str {
        match self {
            WifiKind::Beacon => "beacon",
            WifiKind::ProbeReq => "probe_req",
            WifiKind::ProbeResp => "probe_resp",
            WifiKind::Auth => "auth",
            WifiKind::Deauth => "deauth",
            WifiKind::AssocReq => "assoc_req",
            WifiKind::AssocResp => "assoc_resp",
            WifiKind::ReassocReq => "reassoc_req",
            WifiKind::ReassocResp => "reassoc_resp",
            WifiKind::Disassoc => "disassoc",
            WifiKind::Action => "action",
            WifiKind::MgmtOther => "mgmt_other",
            WifiKind::Data => "data",
            WifiKind::Null => "null",
            WifiKind::Eapol => "eapol",
        }
    }

    pub const ALL: [WifiKind; 15] = [
        WifiKind::Beacon,
        WifiKind::ProbeReq,
        WifiKind::ProbeResp,
        WifiKind::Auth,
        WifiKind::Deauth,
        WifiKind::AssocReq,
        WifiKind::AssocResp,
        WifiKind::ReassocReq,
        WifiKind::ReassocResp,
        WifiKind::Disassoc,
        WifiKind::Action,
        WifiKind::MgmtOther,
        WifiKind::Data,
        WifiKind::Null,
        WifiKind::Eapol,
    ];

    pub fn parse(s: &str) -> Option<WifiKind> {
        WifiKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// `wifi` table: one row per 802.11 management or data frame (link types 105
/// and 127). MAC addresses are lowercase `aa:bb:cc:dd:ee:ff`.
///
/// Addresses follow the 802.11 address fields resolved by ToDS/FromDS:
/// `src` = SA, `dst` = DA, `tx` = TA (differs from SA only on WDS/mesh),
/// `bssid` = BSSID when the frame carries one (None on 4-address frames).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WifiRow {
    #[ts(type = "number")]
    pub ts: Ts,
    #[ts(type = "number")]
    pub frame_no: FrameNo,
    pub kind: WifiKind,
    /// Protected Frame bit (payload encrypted).
    pub protected: bool,
    pub retry: bool,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub tx: Option<String>,
    pub bssid: Option<String>,
    /// Channel number: DS Parameter Set element when present, else from the
    /// radiotap frequency.
    pub channel: Option<u16>,
    /// Radiotap channel frequency.
    pub freq_mhz: Option<u16>,
    /// Radiotap antenna signal (dBm).
    pub signal_dbm: Option<i16>,
    /// SSID element (beacon, probe request/response, (re)assoc request),
    /// sanitized to printable text; "" = hidden/wildcard.
    pub ssid: Option<String>,
    /// Beacon/probe-response security: "open", "wep", "wpa", "wpa2",
    /// "wpa3", "wpa2/wpa3", "owe". None on other kinds.
    pub security: Option<String>,
    /// Reason code (deauth, disassoc) or status code (auth, assoc/reassoc
    /// response).
    pub reason: Option<u16>,
    /// Sequence number (12 bits).
    pub seq: Option<u16>,
    /// 802.11 frame length (without radiotap).
    pub len: u32,
}

/// `wifi_aps` view: one row per BSSID that sent a beacon or probe response.
/// Derived from `wifi` by the index (not written by ingest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WifiApRow {
    pub bssid: String,
    /// Most frequent non-empty SSID advertised; None = hidden only.
    pub ssid: Option<String>,
    /// Most frequent channel.
    pub channel: Option<u16>,
    /// Most frequent security value.
    pub security: Option<String>,
    #[ts(type = "number")]
    pub first_ts: Ts,
    #[ts(type = "number")]
    pub last_ts: Ts,
    #[ts(type = "number")]
    pub beacons: u64,
    /// All `wifi` rows whose `bssid` is this BSSID.
    #[ts(type = "number")]
    pub frames: u64,
    /// Distinct unicast stations seen in data frames of this BSS.
    #[ts(type = "number")]
    pub clients: u64,
    pub signal_max: Option<i16>,
    /// Locally administered address bit set (randomized or spoofed).
    pub randomized: bool,
    #[ts(type = "number")]
    pub first_frame: FrameNo,
}

/// `wifi_clients` view: one row per station (non-AP unicast address that sent
/// a probe request or a data frame). Derived from `wifi` by the index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WifiClientRow {
    pub mac: String,
    pub randomized: bool,
    #[ts(type = "number")]
    pub first_ts: Ts,
    #[ts(type = "number")]
    pub last_ts: Ts,
    /// Frames this station transmitted.
    #[ts(type = "number")]
    pub frames: u64,
    /// Distinct non-empty SSIDs it probed for, sorted.
    pub probed_ssids: Vec<String>,
    /// Distinct BSSIDs it exchanged data or (re)association frames with, sorted.
    pub bssids: Vec<String>,
    pub signal_max: Option<i16>,
    #[ts(type = "number")]
    pub first_frame: FrameNo,
}
