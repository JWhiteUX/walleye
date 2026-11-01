//! `walleye_ingest::decode_frame(link_type, bytes)` (CONTRACTS §7), which builds
//! the packet pane's decode tree for one frame.
//!
//! Input: 4 bytes of link type (little endian), then the frame bytes. The link
//! type is folded onto the common values so most inputs reach a real decoder.
//! Invariants: never panics; every `range` lies inside the frame, so the hex
//! highlight in the UI cannot index out of bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use walleye_core::ipc::DecodeNode;

fn check(nodes: &[DecodeNode], len: usize, depth: usize) {
    assert!(depth < 256, "decode tree deeper than 256");
    for n in nodes {
        if let Some(r) = n.range {
            let end = r.start as u64 + r.len as u64;
            assert!(
                end <= len as u64,
                "range {r:?} past frame len {len} at {:?}",
                n.label
            );
        }
        check(&n.children, len, depth + 1);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Ethernet, raw IP, Linux SLL, SLL2, loopback/null, IPv4, IPv6, raw IP
    // (old), 802.11, 802.11 + radiotap, or the raw value.
    let link_type = match raw % 11 {
        0 => 1,
        1 => 101,
        2 => 113,
        3 => 276,
        4 => 0,
        5 => 228,
        6 => 229,
        7 => 12,
        8 => 105,
        9 => 127,
        _ => raw,
    };
    let bytes = &data[4..];
    let tree = walleye_ingest::decode_frame(link_type, bytes);
    check(&tree, bytes.len(), 0);
});
