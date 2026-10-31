//! Deterministic synthetic rows, written straight through `IndexSink`, for
//! tests and the scale benchmark while real ingest is not available.
//!
//! Shape at `frames = 14M` (≈ a 10 GB capture): ~1M flows (≈50% DNS with
//! 4 messages each → ~2M DNS rows, ~30% TLS, ~10% HTTP, ~10% other), 2 h span,
//! ~1000 internal hosts (Zipf-like skew), ~30k external addresses (2% IPv6),
//! long-lived and bulk flows, and the specific values the benchmark queries
//! look for (10.0.0.23, 10.0.0.5, *.top, *update*, MSIE, NXDOMAIN, TXT/NULL,
//! self-signed certs, t12 JA4, 4xx/5xx, large POSTs, SYN frames).
#![allow(dead_code)]

use walleye_core::{
    CaptureFormat, CaptureRow, Direction, DnsRow, FileRow, FlowRow, FrameRow, HttpRow, TlsRow,
    error::ApiResult,
    sink::{Checkpoint, IndexSink, RecordBatch},
};

pub struct Scale {
    pub frames: u64,
    /// Emit a checkpoint every this many frames (0 = never).
    pub checkpoint_frames: u64,
    pub seed: u64,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub frames: u64,
    pub flows: u64,
    pub dns: u64,
    pub http: u64,
    pub tls: u64,
    pub files: u64,
    /// Bytes of the pcap this frame set represents: 24-byte global header +
    /// Σ(16-byte record header + caplen).
    pub raw_bytes: u64,
}

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    pub fn next(&mut self) -> u64 {
        // SplitMix64
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi.saturating_sub(lo).max(1))
    }
    pub fn pct(&mut self, p: u64) -> bool {
        self.below(100) < p
    }
    pub fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

const WORDS: &[&str] = &[
    "alpha",
    "cloud",
    "update",
    "cdn",
    "mail",
    "login",
    "api",
    "static",
    "img",
    "video",
    "news",
    "shop",
    "secure",
    "portal",
    "files",
    "sync",
    "edge",
    "metrics",
    "auth",
    "store",
    "docs",
    "chat",
    "media",
    "assets",
    "web",
    "app",
    "data",
    "push",
    "telemetry",
    "search",
];
const TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "de", "uk", "top", "xyz", "info",
];
const UAS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "curl/8.5.0",
    "Microsoft-CryptoAPI/10.0",
    "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50",
];

fn domain(r: &mut Rng) -> String {
    let n = r.below(100_000);
    if n % 100 == 7 {
        // Tunnel-like deep names (unique labels, 4+ dots).
        return format!(
            "{:x}.{:x}.{:x}.t.exfil-dns.xyz",
            r.next() >> 16,
            r.next() >> 24,
            r.next() >> 40
        );
    }
    let mut h = Rng::new(n);
    let tld = if h.pct(1) {
        "top"
    } else {
        TLDS[h.below(TLDS.len() as u64) as usize]
    };
    let a = WORDS[h.below(WORDS.len() as u64) as usize];
    let b = WORDS[h.below(WORDS.len() as u64) as usize];
    match h.below(4) {
        0 => format!("{a}.{b}{n}.{tld}"),
        1 => format!("{a}{n}.{tld}"),
        2 => format!("{b}.{a}.{b}{}.{tld}", n % 997),
        _ => format!("{a}-{b}{n}.{tld}"),
    }
}

fn internal(r: &mut Rng) -> String {
    // Zipf-ish: low indices are much busier.
    let u = r.unit();
    let i = (u * u * u * 1000.0) as u64;
    format!("10.0.{}.{}", i / 250, i % 250 + 1)
}

fn external(r: &mut Rng) -> String {
    let n = r.below(30_000);
    if n % 50 == 0 {
        return format!("2001:db8:{:x}::{:x}", n % 7, n);
    }
    let mut h = Rng::new(n.wrapping_mul(7919));
    format!(
        "{}.{}.{}.{}",
        h.range(11, 223),
        h.below(256),
        h.below(256),
        h.range(1, 255)
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Dns,
    Tls,
    Http,
    Other,
}

struct Flow {
    row: FlowRow,
    kind: Kind,
    budget: u32,
    n: u32,
    slow: bool,
    query: String,
}

pub struct Gen<'a> {
    sink: &'a mut dyn IndexSink,
    r: Rng,
    t: i64,
    dt: f64,
    next_flow: u64,
    frame_no: u64,
    offset: u64,
    pub stats: Stats,
    frames: Vec<FrameRow>,
    flows: Vec<FlowRow>,
    dns: Vec<DnsRow>,
    http: Vec<HttpRow>,
    tls: Vec<TlsRow>,
    files: Vec<FileRow>,
}

const T0: i64 = 1_714_000_000_000_000;
const SPAN_US: f64 = 7_200.0 * 1e6;
const BATCH: usize = 65_536;

impl<'a> Gen<'a> {
    fn new_flow(&mut self) -> Flow {
        let r = &mut self.r;
        let roll = r.below(100);
        let kind = match roll {
            0..=49 => Kind::Dns,
            50..=79 => Kind::Tls,
            80..=89 => Kind::Http,
            _ => Kind::Other,
        };
        let src = internal(r);
        let (dst, dport, proto, app) = match kind {
            Kind::Dns => (
                if r.pct(80) {
                    "10.0.0.2".to_string()
                } else {
                    "8.8.8.8".to_string()
                },
                53,
                17,
                Some("dns"),
            ),
            Kind::Tls => (external(r), 443, 6, Some("tls")),
            Kind::Http => (
                external(r),
                if r.pct(90) { 80 } else { 8080 },
                6,
                Some("http"),
            ),
            Kind::Other => {
                let p = [6u8, 17, 1][r.below(3) as usize];
                (external(r), r.range(1, 65535) as u16, p, None)
            }
        };
        let budget = match kind {
            Kind::Dns => 4,
            Kind::Other => r.range(1, 20) as u32,
            _ => {
                let b = r.below(100);
                if b < 94 {
                    r.range(6, 24) as u32
                } else if b < 99 {
                    r.range(24, 120) as u32
                } else {
                    r.range(700, 1500) as u32
                }
            }
        };
        let slow = kind == Kind::Tls && r.pct(1);
        self.next_flow += 1;
        let query = if kind == Kind::Dns {
            domain(&mut self.r)
        } else {
            String::new()
        };
        Flow {
            row: FlowRow {
                flow_id: self.next_flow,
                ts_start: self.t,
                ts_end: self.t,
                src_ip: src,
                src_port: self.r.range(1024, 65535) as u16,
                dst_ip: dst,
                dst_port: dport,
                proto,
                app_proto: app.map(str::to_string),
                bytes_up: 0,
                bytes_down: 0,
                pkts_up: 0,
                pkts_down: 0,
                first_frame: 0,
                last_frame: 0,
            },
            kind,
            budget,
            n: 0,
            slow,
            query,
        }
    }

    fn emit_frame(&mut self, f: &mut Flow) -> ApiResult<()> {
        self.frame_no += 1;
        self.t += (self.dt * (0.5 + self.r.unit())) as i64 + 1;
        let i = f.n;
        f.n += 1;
        let r = &mut self.r;
        let (dir, flags, payload): (Direction, Option<u8>, u32) = match f.kind {
            Kind::Dns => (
                if i % 2 == 0 {
                    Direction::Up
                } else {
                    Direction::Down
                },
                None,
                if i % 2 == 0 {
                    30 + f.query.len() as u32
                } else {
                    60 + r.below(200) as u32
                },
            ),
            Kind::Tls | Kind::Http => match i {
                0 => (Direction::Up, Some(0x02), 0),
                1 => (Direction::Down, Some(0x12), 0),
                2 => (Direction::Up, Some(0x10), 0),
                3 => (
                    Direction::Up,
                    Some(0x18),
                    if f.kind == Kind::Tls {
                        517
                    } else {
                        300 + r.below(400) as u32
                    },
                ),
                _ => {
                    // Some bulk flows are uploads.
                    let up = if f.budget > 600 && f.row.flow_id % 4 == 0 {
                        r.pct(90)
                    } else {
                        r.pct(35)
                    };
                    let full = f.budget > 600 || r.pct(50);
                    (
                        if up { Direction::Up } else { Direction::Down },
                        Some(if r.pct(3) && i + 1 == f.budget {
                            0x11
                        } else {
                            0x18
                        }),
                        if full { 1448 } else { r.below(400) as u32 },
                    )
                }
            },
            Kind::Other => (
                if r.pct(50) {
                    Direction::Up
                } else {
                    Direction::Down
                },
                if f.row.proto == 6 {
                    Some([0x02u8, 0x10, 0x18, 0x04][r.below(4) as usize])
                } else {
                    None
                },
                r.below(600) as u32,
            ),
        };
        let hdr = match f.row.proto {
            6 => 66,
            17 => 42,
            _ => 42,
        };
        let caplen = (payload + hdr).min(1514);
        self.offset += 16;
        let file_offset = self.offset;
        self.offset += u64::from(caplen);
        self.stats.raw_bytes += 16 + u64::from(caplen);
        if f.n == 1 {
            f.row.first_frame = self.frame_no;
            f.row.ts_start = self.t;
        }
        f.row.last_frame = self.frame_no;
        f.row.ts_end = self.t;
        match dir {
            Direction::Up => {
                f.row.bytes_up += u64::from(payload);
                f.row.pkts_up += 1;
            }
            Direction::Down => {
                f.row.bytes_down += u64::from(payload);
                f.row.pkts_down += 1;
            }
        }
        self.frames.push(FrameRow {
            frame_no: self.frame_no,
            ts: self.t,
            file_offset,
            caplen,
            wirelen: caplen,
            flow_id: Some(f.row.flow_id),
            direction: Some(dir),
            tcp_flags: flags,
            payload_len: payload,
        });
        self.app_rows(f, i)?;
        if self.frames.len() >= BATCH {
            self.flush()?;
        }
        Ok(())
    }

    fn app_rows(&mut self, f: &Flow, i: u32) -> ApiResult<()> {
        let r = &mut self.r;
        let ts = self.t;
        let flow_id = f.row.flow_id;
        let frame_no = self.frame_no;
        match (f.kind, i) {
            (Kind::Dns, _) => {
                let resp = i % 2 == 1;
                let qtype = if f.row.flow_id % 97 == 0 || f.query.ends_with("exfil-dns.xyz") {
                    if f.row.flow_id % 3 == 0 {
                        "NULL"
                    } else {
                        "TXT"
                    }
                } else if i < 2 {
                    "A"
                } else {
                    "AAAA"
                };
                let nx = f.query.len() % 20 == 3;
                let answers = if resp && !nx && qtype == "A" {
                    (0..r.range(1, 4)).map(|_| external(r)).collect()
                } else {
                    Vec::new()
                };
                self.dns.push(DnsRow {
                    ts,
                    flow_id,
                    frame_no,
                    trans_id: (flow_id as u16).wrapping_add((i / 2) as u16),
                    is_response: resp,
                    query: f.query.clone(),
                    qtype: qtype.to_string(),
                    rcode: resp.then(|| if nx { "NXDOMAIN" } else { "NOERROR" }.to_string()),
                    ttl: (resp && !answers.is_empty()).then(|| r.range(30, 3600) as u32),
                    answers,
                });
                self.stats.dns += 1;
            }
            (Kind::Tls, 3) => {
                let sni = domain(r);
                let self_signed = r.pct(1);
                let v12 = r.pct(15);
                let ja4 = format!(
                    "{}d{:02}{:02}h2_{:012x}_{:012x}",
                    if v12 { "t12" } else { "t13" },
                    r.range(8, 20),
                    r.range(5, 18),
                    r.below(40) * 0x12_3456_789a,
                    r.below(400) * 0x0a_bcde_f123
                );
                self.tls.push(TlsRow {
                    ts,
                    flow_id,
                    frame_no,
                    sni: if r.pct(97) { Some(sni.clone()) } else { None },
                    version: Some(if v12 { "TLS 1.2" } else { "TLS 1.3" }.to_string()),
                    ja4: Some(ja4),
                    ja4s: Some(format!("t130200_1301_{:012x}", r.below(50) * 0x77_7777)),
                    cert_subject: Some(format!("CN={sni}")),
                    cert_issuer: Some(if self_signed {
                        format!("CN={sni}")
                    } else {
                        "CN=R3, O=Let's Encrypt".to_string()
                    }),
                    cert_serial: Some(format!("{:032x}", r.next() as u128 * 0x1_0000_0001)),
                    cert_self_signed: Some(self_signed),
                    cert_not_before: Some(ts - 30 * 86_400_000_000),
                    cert_not_after: Some(ts + 60 * 86_400_000_000),
                });
                self.stats.tls += 1;
            }
            (Kind::Http, 3) => {
                let post = r.pct(15);
                let status =
                    [200u16, 200, 200, 200, 204, 301, 304, 404, 403, 500][r.below(10) as usize];
                let ua = if r.pct(1) {
                    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)".to_string()
                } else {
                    UAS[r.below(UAS.len() as u64) as usize].to_string()
                };
                let uri = format!(
                    "/{}/{}.{}",
                    WORDS[r.below(30) as usize],
                    r.below(100_000),
                    ["html", "js", "png", "php", "exe"][r.below(5) as usize]
                );
                self.http.push(HttpRow {
                    ts,
                    flow_id,
                    frame_no,
                    method: Some(if post { "POST" } else { "GET" }.to_string()),
                    host: Some(domain(r)),
                    uri: Some(uri.clone()),
                    user_agent: Some(ua),
                    status: Some(status),
                    resp_frame_no: Some(frame_no + 1),
                    req_bytes: if post { r.range(100, 60_000) } else { 0 },
                    resp_bytes: r.range(0, 200_000),
                });
                self.stats.http += 1;
                if r.pct(20) {
                    self.files.push(FileRow {
                        ts,
                        flow_id,
                        frame_no: frame_no + 1,
                        source: "http".into(),
                        direction: Direction::Down,
                        filename: uri.rsplit('/').next().map(str::to_string),
                        mime_type: Some("application/octet-stream".into()),
                        size_bytes: Some(r.range(100, 5_000_000)),
                    });
                    self.stats.files += 1;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn flush(&mut self) -> ApiResult<()> {
        self.stats.frames += self.frames.len() as u64;
        self.stats.flows += self.flows.len() as u64;
        use std::mem::take;
        let batches = [
            RecordBatch::Frames(take(&mut self.frames)),
            RecordBatch::Flows(take(&mut self.flows)),
            RecordBatch::Dns(take(&mut self.dns)),
            RecordBatch::Http(take(&mut self.http)),
            RecordBatch::Tls(take(&mut self.tls)),
            RecordBatch::Files(take(&mut self.files)),
        ];
        for b in batches {
            self.sink.write(b)?;
        }
        Ok(())
    }
}

/// Generates `scale.frames` frames through `sink` (begin → writes/checkpoints → finish).
pub fn generate(sink: &mut dyn IndexSink, scale: &Scale) -> ApiResult<(CaptureRow, Stats)> {
    let mut capture = CaptureRow {
        capture_id: format!("{:016x}", scale.seed),
        path: "/synthetic/scale.pcap".into(),
        sha256: format!("{:016x}{}", scale.seed, "0".repeat(48)),
        size_bytes: 0,
        format: CaptureFormat::Pcap,
        first_ts: T0,
        last_ts: T0,
        link_type: 1,
        frame_count: 0,
    };
    let resumed = sink.begin(&capture)?;
    assert!(resumed.is_none(), "synthetic generator starts fresh");
    let mut g = Gen {
        sink,
        r: Rng::new(scale.seed),
        t: T0,
        dt: SPAN_US / scale.frames.max(1) as f64,
        next_flow: 0,
        frame_no: 0,
        offset: 24,
        stats: Stats::default(),
        frames: Vec::new(),
        flows: Vec::new(),
        dns: Vec::new(),
        http: Vec::new(),
        tls: Vec::new(),
        files: Vec::new(),
    };
    g.stats.raw_bytes = 24;
    let w = 4000usize.min(scale.frames.max(1) as usize);
    let mut slots: Vec<Flow> = (0..w).map(|_| g.new_flow()).collect();
    while g.frame_no < scale.frames {
        let mut s = g.r.below(w as u64) as usize;
        if slots[s].slow && g.r.pct(97) {
            s = g.r.below(w as u64) as usize;
        }
        g.emit_frame(&mut slots[s])?;
        if slots[s].n >= slots[s].budget {
            let done = std::mem::replace(&mut slots[s], g.new_flow());
            g.flows.push(done.row);
        }
        if scale.checkpoint_frames > 0 && g.frame_no % scale.checkpoint_frames == 0 {
            g.flush()?;
            let cp = Checkpoint {
                file_offset: g.offset,
                frames_emitted: g.frame_no,
                next_flow_id: g.next_flow + 1,
                state: g.frame_no.to_le_bytes().to_vec(),
            };
            g.sink.checkpoint(cp)?;
        }
    }
    for f in slots {
        if f.n > 0 {
            g.flows.push(f.row);
        }
    }
    g.flush()?;
    capture.last_ts = g.t;
    capture.frame_count = g.frame_no;
    capture.size_bytes = g.stats.raw_bytes;
    let stats = g.stats.clone();
    g.sink.finish(&capture)?;
    Ok((capture, stats))
}
