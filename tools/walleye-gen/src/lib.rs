//! Deterministic synthetic capture generator for Walleye fixtures
//! (docs/CONTRACTS.md §9). Owner: Agent G.
//!
//! Output is classic pcap (Ethernet, µs timestamps). Every packet is
//! well-formed: real TCP handshakes and teardowns, correct IP/UDP/TCP
//! lengths and checksums, DNS wire format with name compression, HTTP/1.1,
//! and TLS ClientHello/ServerHello/Certificate records. The same seed always
//! produces byte-identical output.

pub mod dns;
pub mod flow;
pub mod http;
pub mod net;
pub mod pcap;
pub mod rng;
pub mod scenario;
pub mod sim;
pub mod tls;
pub mod x509;

pub use scenario::{Labels, Options, Scenario, Summary, generate};

/// `<stem>.labels.json` beside `out` (`beacon.pcap` -> `beacon.labels.json`).
pub fn labels_path(out: &std::path::Path) -> std::path::PathBuf {
    let stem = out
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capture".to_string());
    out.with_file_name(format!("{stem}.labels.json"))
}
