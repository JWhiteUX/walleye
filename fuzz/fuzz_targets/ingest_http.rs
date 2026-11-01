//! HTTP/1.x request and response heads (request line, status line, headers,
//! Content-Length / Content-Disposition for the `files` table).
//! Needs `walleye_ingest::fuzz::parse_http(&[u8])`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    walleye_ingest::fuzz::parse_http(data);
});
