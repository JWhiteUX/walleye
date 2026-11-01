//! TLS ServerHello (record layer + handshake), JA4S inputs.
//! Needs `walleye_ingest::fuzz::parse_tls_server_hello(&[u8])`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    walleye_ingest::fuzz::parse_tls_server_hello(data);
});
