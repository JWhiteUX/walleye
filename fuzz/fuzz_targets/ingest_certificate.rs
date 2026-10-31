//! X.509 certificate (DER) field extraction: subject, issuer, serial,
//! validity, self-signed flag.
//! Needs `walleye_ingest::fuzz::parse_certificate(&[u8])`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    walleye_ingest::fuzz::parse_certificate(data);
});
