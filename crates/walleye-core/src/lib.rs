//! Walleye shared contract crate.
//!
//! Everything that crosses a crate or process boundary lives here: table row
//! types (Parquet/DuckDB schemas), findings and IOCs, the Tauri IPC request and
//! response types (exported to TypeScript with ts-rs), the ingest → index sink
//! trait, the detection rule and allowlist schemas, the filter field registry,
//! and a mock backend that serves `mock/dataset.json`.
//!
//! `docs/CONTRACTS.md` is the prose version of this crate. Change either only
//! through the lead.

pub mod allowlist;
pub mod backend;
pub mod error;
pub mod fields;
pub mod findings;
pub mod ipc;
pub mod mac;
pub mod mock;
pub mod rules;
pub mod sink;
pub mod tables;
pub mod text;

pub use allowlist::Allowlist;
pub use backend::Backend;
pub use error::{ApiError, ErrorCode};
pub use findings::{Evidence, Finding, Ioc, IocType, Reason, Verdict};
pub use tables::*;

/// Microseconds since the Unix epoch, UTC. Every `ts`, `ts_*`, `first_seen`
/// column and IPC timestamp uses this unit. Fits in a JS number until year 2255.
pub type Ts = i64;

/// 1-based frame number in capture order, as Wireshark shows it.
pub type FrameNo = u64;

/// Flow identifier, assigned sequentially from 1 by ingest. Always < 2^53 so it
/// survives the trip through a JS number.
pub type FlowId = u64;

/// Contract version. Bump when a breaking change lands in this crate.
pub const CONTRACT_VERSION: u32 = 2;

/// 802.11 without a radio header (LINKTYPE_IEEE802_11).
pub const LINKTYPE_IEEE802_11: u32 = 105;
/// 802.11 with a radiotap header (LINKTYPE_IEEE802_11_RADIOTAP), as written by
/// the WiFi Coconut and most monitor-mode tools.
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;

/// True for link types whose frames go to the `wifi` table.
pub fn is_wifi_link_type(link_type: u32) -> bool {
    matches!(
        link_type,
        LINKTYPE_IEEE802_11 | LINKTYPE_IEEE802_11_RADIOTAP
    )
}
