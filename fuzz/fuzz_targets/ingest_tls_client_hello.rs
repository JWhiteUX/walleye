//! TLS ClientHello (record layer + handshake), SNI and JA4 inputs.
//! Needs `walleye_ingest::fuzz::parse_tls_client_hello(&[u8])`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    walleye_ingest::fuzz::parse_tls_client_hello(data);
});
