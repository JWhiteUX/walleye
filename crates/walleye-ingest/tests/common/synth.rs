//! Deterministic synthetic traffic: many concurrent HTTP, TLS and DNS
//! sessions interleaved frame by frame, so flows straddle checkpoints.

use super::*;

/// xorshift64* PRNG (deterministic, no dependencies).
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

fn session(rng: &mut Rng, idx: u64) -> Vec<Vec<u8>> {
    let host = [10, 0, (idx >> 8) as u8 & 0x3f, idx as u8];
    let sport = 20_000 + (idx % 40_000) as u16;
    let ts = 0; // timestamps are assigned at emission
    match rng.below(10) {
        // Bulk HTTP download: 20–60 KiB in 1448-byte segments.
        0..=3 => {
            let mut t = Tcp::new((host, sport), ([93, 184, 216, (idx % 200) as u8], 80), ts);
            t.handshake();
            t.client(format!("GET /f/{idx}.bin HTTP/1.1\r\nHost: cdn{}.example.com\r\nUser-Agent: synth\r\n\r\n", idx % 50).as_bytes());
            let body = 20_480 + rng.below(40_960) as usize;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {body}\r\n\r\n"
            );
            let mut stream = head.into_bytes();
            stream.resize(stream.len() + body, 0x5a);
            for seg in stream.chunks(1448) {
                t.server(seg);
            }
            t.close();
            t.frames.into_iter().map(|(_, f)| f).collect()
        }
        // TLS 1.3 handshake + application data.
        4..=7 => {
            let mut t = Tcp::new((host, sport), ([151, 101, (idx % 250) as u8, 1], 443), ts);
            t.handshake();
            let sni = format!("svc{}.example.org", idx % 300);
            t.client(&tls_record(
                22,
                &client_hello(&HelloSpec {
                    sni: Some(&sni),
                    alpn: &["h2", "http/1.1"],
                    ciphers: &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
                    versions: &[0x0304, 0x0303],
                    sig_algs: &[0x0403, 0x0804, 0x0401],
                    other_exts: &[0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0033, 0x002d],
                }),
            ));
            let mut fl = tls_record(22, &server_hello(0x1301, true, &[0x002b, 0x0033]));
            fl.extend(tls_record(20, &[1]));
            t.server(&fl);
            for _ in 0..(4 + rng.below(12)) {
                t.server(&tls_record(23, &[0xa5; 1400]));
                t.client(&tls_record(23, &[0x5a; 120]));
            }
            t.close();
            t.frames.into_iter().map(|(_, f)| f).collect()
        }
        // DNS over UDP.
        _ => {
            let name = format!("h{}.example.net", rng.below(5000));
            let id = rng.below(65_536) as u16;
            let q = eth_udp4(host, sport, [10, 0, 0, 53], 53, &dns_query(id, &name, 1));
            let r = dns_response(
                id,
                &name,
                1,
                0,
                &[(1, 300, vec![198, 51, 100, (idx % 250) as u8])],
            );
            let r = eth_udp4([10, 0, 0, 53], 53, host, sport, &r);
            vec![q, r]
        }
    }
}

/// Emit frames from `concurrency` interleaved sessions until `emit` returns
/// false. Timestamps advance 20 µs per frame from `t0`.
pub fn mixed(seed: u64, concurrency: usize, t0: i64, mut emit: impl FnMut(i64, &[u8]) -> bool) {
    let mut rng = Rng(seed | 1);
    let mut next_idx = 0u64;
    let mut live: Vec<std::collections::VecDeque<Vec<u8>>> = Vec::new();
    let mut ts = t0;
    loop {
        while live.len() < concurrency {
            live.push(session(&mut rng, next_idx).into());
            next_idx += 1;
        }
        let i = rng.below(live.len() as u64) as usize;
        if let Some(f) = live[i].pop_front() {
            if !emit(ts, &f) {
                return;
            }
            ts += 20;
        }
        if live[i].is_empty() {
            live.swap_remove(i);
        }
    }
}

/// An in-memory mixed capture of about `bytes` bytes.
pub fn mixed_pcap(seed: u64, concurrency: usize, bytes: usize) -> Vec<u8> {
    let mut p = Pcap::new(1);
    mixed(seed, concurrency, 1_700_000_000_000_000, |ts, f| {
        p.packet(ts, f);
        p.buf.len() < bytes
    });
    p.buf
}
