//! DNS message parser (UDP payload, or TCP with the 2-byte length prefix).
//! Needs `walleye_ingest::fuzz::parse_dns(&[u8], is_tcp: bool)`.
//! Covers name compression loops, pointer chains and label length overflow.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&flag, msg)) = data.split_first() else {
        return;
    };
    walleye_ingest::fuzz::parse_dns(msg, flag & 1 == 1);
});
