//! Robustness: every parser, fed every prefix of valid inputs, random bytes
//! and mutated valid inputs, must return without panicking.
//!
//! This is a deterministic stand-in until Agent H's `cargo fuzz` targets
//! (which call `walleye_ingest::fuzz::*`) run. Default budget is a quick
//! iteration count; set `WALLEYE_ROBUST_SECS=<n>` to run each target for n
//! seconds instead (use `--release`).

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use common::fixtures::*;
use common::synth::Rng;
use common::*;
use walleye_ingest::{IngestOptions, fuzz};

type Target = (&'static str, fn(&[u8]));

fn targets() -> Vec<Target> {
    vec![
        ("read_capture", fuzz::read_capture),
        ("parse_dns_udp", |b| fuzz::parse_dns(b, false)),
        ("parse_dns_tcp", |b| fuzz::parse_dns(b, true)),
        ("parse_http", fuzz::parse_http),
        ("parse_tls_client_hello", fuzz::parse_tls_client_hello),
        ("parse_tls_server_hello", fuzz::parse_tls_server_hello),
        ("parse_certificate", fuzz::parse_certificate),
        ("decode_frame", |b| {
            for lt in [0, 1, 12, 101, 108, 113, 228, 229, 276] {
                fuzz::decode_frame(lt, b);
            }
        }),
    ]
}

fn captures() -> Vec<Vec<u8>> {
    vec![
        dns_fixture(),
        http_fixture(),
        tls_fixture(),
        malformed_fixture(),
        multi_fixture(),
    ]
}

/// Frame bytes of every packet in the fixtures.
fn frames() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for cap in captures() {
        let mut s = CollectSink::default();
        walleye_ingest::ingest_bytes(&cap, SHA, &mut s, &IngestOptions::default()).expect("ingest");
        for f in &s.rows.frames {
            let a = usize::try_from(f.file_offset).expect("off");
            out.push(cap[a..a + f.caplen as usize].to_vec());
        }
    }
    out
}

fn payload_seeds() -> Vec<Vec<u8>> {
    let name = [(OID_C, "US"), (OID_CN, "seed.example")];
    let cert = der_cert(&name, &name, &[1, 2, 3], "240101000000Z", "250101000000Z");
    let ch = client_hello(&HelloSpec {
        sni: Some("seed.example"),
        alpn: &["h2"],
        ciphers: &[0x1301, 0xc02f],
        versions: &[0x0304],
        sig_algs: &[0x0403],
        other_exts: &[0x0017, 0x0033],
    });
    vec![
        dns_query(1, "a.b.example.com", 1),
        dns_response(2, "a.example", 1, 0, &[(1, 5, vec![1, 2, 3, 4]), (16, 5, b"\x03abc".to_vec()), (5, 9, vec![1, b'x', 0xc0, 0x0c])]),
        with_len_prefix(&dns_query(3, "tcp.example", 16)),
        b"GET /x?y=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename*=UTF-8''a.zip\r\n\r\n".to_vec(),
        tls_record(22, &ch),
        tls_record(22, &server_hello(0x1301, true, &[0x002b, 0x0033, 0x0010])),
        cert.clone(),
        tls_record(22, &certificate_msg(&cert)),
    ]
}

fn run_one(name: &str, f: fn(&[u8]), input: &[u8]) {
    if let Err(e) = catch_unwind(AssertUnwindSafe(|| f(input))) {
        let shown: String = input
            .iter()
            .take(4096)
            .map(|b| format!("{b:02x}"))
            .collect();
        eprintln!("PANIC in {name} on {} bytes: {shown}", input.len());
        resume_unwind(e);
    }
}

fn mutate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut v = seeds[rng.below(seeds.len() as u64) as usize].clone();
    for _ in 0..=rng.below(6) {
        let len = v.len() as u64;
        match rng.below(8) {
            0 if len > 0 => {
                let i = rng.below(len) as usize;
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len) as usize;
                v[i] = [0x00, 0xff, 0x7f, 0x80, 0xc0, 0x3f][rng.below(6) as usize];
            }
            2 => v.truncate(rng.below(len + 1) as usize),
            3 if len > 0 => {
                // Overwrite a 16-bit length-like field.
                let i = rng.below(len) as usize;
                let x = [0u16, 1, 0x7fff, 0xffff, 0x4000][rng.below(5) as usize].to_be_bytes();
                v[i] = x[0];
                if i + 1 < v.len() {
                    v[i + 1] = x[1];
                }
            }
            4 if len > 0 => {
                let a = rng.below(len) as usize;
                let b = (a + rng.below(64) as usize).min(v.len());
                let chunk = v[a..b].to_vec();
                let at = rng.below(v.len() as u64 + 1) as usize;
                v.splice(at..at, chunk);
            }
            5 if len > 0 => {
                let a = rng.below(len) as usize;
                let b = (a + rng.below(64) as usize).min(v.len());
                v.drain(a..b);
            }
            6 => {
                let other = &seeds[rng.below(seeds.len() as u64) as usize];
                let cut = rng.below(other.len() as u64 + 1) as usize;
                v.extend_from_slice(&other[cut..]);
            }
            _ => {
                let n = rng.below(32) as usize;
                v.extend((0..n).map(|_| rng.next() as u8));
            }
        }
    }
    v
}

#[test]
fn every_prefix_of_valid_inputs() {
    let caps = captures();
    let frames = frames();
    let payloads = payload_seeds();
    for (name, f) in targets() {
        let seeds: &[Vec<u8>] = match name {
            "read_capture" => &caps,
            "decode_frame" => &frames,
            _ => &payloads,
        };
        for s in seeds {
            // Captures are long: step through prefixes, always including the ends.
            let step = if name == "read_capture" { 7 } else { 1 };
            for n in (0..=s.len()).step_by(step).chain([s.len()]) {
                run_one(name, f, &s[..n]);
            }
        }
    }
}

#[test]
fn random_and_mutated_inputs() {
    let budget = std::env::var("WALLEYE_ROBUST_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs);
    let caps = captures();
    let frames = frames();
    let payloads = payload_seeds();
    let mut all: Vec<Vec<u8>> = payloads.clone();
    all.extend(frames.iter().cloned());
    for (ti, (name, f)) in targets().into_iter().enumerate() {
        let seeds: &[Vec<u8>] = match name {
            "read_capture" => &caps,
            "decode_frame" => &frames,
            _ => &all,
        };
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (ti as u64 + 1));
        let start = Instant::now();
        let default_iters: u64 = if name == "read_capture" { 300 } else { 4000 };
        let mut i = 0u64;
        loop {
            let done = match budget {
                Some(b) => start.elapsed() >= b,
                None => i >= default_iters,
            };
            if done {
                break;
            }
            let input = if i % 5 == 0 && name != "read_capture" {
                let n = rng.below(600) as usize;
                (0..n).map(|_| rng.next() as u8).collect()
            } else {
                mutate(&mut rng, seeds)
            };
            run_one(name, f, &input);
            i += 1;
        }
        eprintln!(
            "robustness: {name}: {i} inputs in {:.1?}, no panics",
            start.elapsed()
        );
    }
}

/// Write seed corpora for `cargo fuzz` when `WALLEYE_DUMP_SEEDS=<dir>` is set:
/// `<dir>/<target>/seed-<n>`. No-op otherwise.
#[test]
fn dump_fuzz_seeds() {
    let Some(dir) = std::env::var_os("WALLEYE_DUMP_SEEDS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let write = |target: &str, seeds: &[Vec<u8>]| {
        let d = dir.join(target);
        std::fs::create_dir_all(&d).expect("mkdir");
        for (i, s) in seeds.iter().enumerate() {
            std::fs::write(d.join(format!("seed-{i}")), s).expect("write seed");
        }
    };
    write("read_capture", &captures());
    // The decode_frame target maps its first byte to a link type; 1 = Ethernet.
    let frames: Vec<Vec<u8>> = frames()
        .into_iter()
        .map(|f| [vec![1u8], f].concat())
        .collect();
    write("decode_frame", &frames);
    let p = payload_seeds();
    // The parse_dns target's first byte selects UDP (even) or TCP (odd).
    write(
        "parse_dns",
        &[
            [vec![0], p[0].clone()].concat(),
            [vec![0], p[1].clone()].concat(),
            [vec![1], p[2].clone()].concat(),
        ],
    );
    write("parse_http", &p[3..5]);
    write("parse_tls_client_hello", &p[5..6]);
    write("parse_tls_server_hello", &p[6..7]);
    write("parse_certificate", &p[7..9]);
}

/// cargo-fuzz finding (fuzz/repro/ingest_decode_frame): an IPv4 header length
/// past the end of the frame produced an "Options" range outside the frame.
#[test]
fn decode_ranges_stay_inside_the_frame() {
    fn check(nodes: &[walleye_core::ipc::DecodeNode], len: usize) {
        for n in nodes {
            if let Some(r) = n.range {
                assert!(
                    r.start as usize + r.len as usize <= len,
                    "{r:?} past {len} at {}",
                    n.label
                );
            }
            check(&n.children, len);
        }
    }
    for raw in [
        &include_bytes!("../../../fuzz/repro/ingest_decode_frame/ipv4-ihl-past-frame.bin")[..],
        &include_bytes!("../../../fuzz/repro/ingest_decode_frame/http-uri-escaped-len.bin")[..],
    ] {
        let (lt, frame) = raw.split_at(4);
        let lt = u32::from_le_bytes(lt.try_into().expect("4 bytes"));
        // The fuzz target folds the link type onto common values; try them all.
        for link in [lt, 1, 101, 0, 113, 276] {
            check(&walleye_ingest::decode_frame(link, frame), frame.len());
        }
    }
}
