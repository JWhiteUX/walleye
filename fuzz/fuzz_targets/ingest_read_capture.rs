//! Whole pipeline on an in-memory capture: pcap/pcapng reader, flow assembly
//! and every protocol parser, into a sink that drops batches.
//! Needs `walleye_ingest::fuzz::read_capture(&[u8])` (feature "ingest").
//! Invariant: never panics, never hangs (libFuzzer -timeout), bounded memory.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    walleye_ingest::fuzz::read_capture(data);
});
