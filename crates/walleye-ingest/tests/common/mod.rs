//! Deterministic pcap/pcapng writer, packet builders and a collecting sink,
//! shared by the integration tests and the throughput bench.
#![allow(dead_code)]

pub mod fixtures;
pub mod synth;

use serde::Serialize;
use walleye_core::error::ApiResult;
use walleye_core::sink::{Checkpoint, IndexSink, RecordBatch};
use walleye_core::{ApiError, CaptureRow, DnsRow, FileRow, FlowRow, FrameRow, HttpRow, TlsRow};

pub const SHA: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// ---------------------------------------------------------------- writers

/// Legacy pcap, little-endian, microsecond timestamps.
pub struct Pcap {
    pub buf: Vec<u8>,
}

impl Pcap {
    pub fn new(link_type: u32) -> Self {
        Self::with_magic(link_type, 0xa1b2_c3d4)
    }
    /// Nanosecond-resolution variant.
    pub fn new_ns(link_type: u32) -> Self {
        Self::with_magic(link_type, 0xa1b2_3c4d)
    }
    fn with_magic(link_type: u32, magic: u32) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&magic.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&262_144u32.to_le_bytes());
        buf.extend_from_slice(&link_type.to_le_bytes());
        Self { buf }
    }
    /// `frac` is µs (or ns for `new_ns`).
    pub fn record(&mut self, sec: u32, frac: u32, data: &[u8], wirelen: u32) {
        self.buf.extend_from_slice(&sec.to_le_bytes());
        self.buf.extend_from_slice(&frac.to_le_bytes());
        self.buf
            .extend_from_slice(&u32::try_from(data.len()).expect("len").to_le_bytes());
        self.buf.extend_from_slice(&wirelen.to_le_bytes());
        self.buf.extend_from_slice(data);
    }
    pub fn packet(&mut self, ts_us: i64, data: &[u8]) {
        let sec = u32::try_from(ts_us / 1_000_000).expect("ts");
        let us = u32::try_from(ts_us % 1_000_000).expect("ts");
        let wl = u32::try_from(data.len()).expect("len");
        self.record(sec, us, data, wl);
    }
    /// Packet captured with a snap length shorter than the wire length.
    pub fn packet_snap(&mut self, ts_us: i64, data: &[u8], snap: usize) {
        let sec = u32::try_from(ts_us / 1_000_000).expect("ts");
        let us = u32::try_from(ts_us % 1_000_000).expect("ts");
        let wl = u32::try_from(data.len()).expect("len");
        self.record(sec, us, &data[..snap.min(data.len())], wl);
    }
    pub fn add(&mut self, frames: &[(i64, Vec<u8>)]) {
        for (ts, d) in frames {
            self.packet(*ts, d);
        }
    }
}

/// pcapng writer; each section may be little- or big-endian.
pub struct Pcapng {
    pub buf: Vec<u8>,
    be: bool,
}

impl Pcapng {
    pub fn new() -> Self {
        let mut s = Self {
            buf: Vec::new(),
            be: false,
        };
        s.section(false);
        s
    }
    fn u16(&self, v: u16) -> [u8; 2] {
        if self.be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
    fn u32(&self, v: u32) -> [u8; 4] {
        if self.be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
    fn block(&mut self, ty: u32, body: &[u8]) {
        let pad = (4 - body.len() % 4) % 4;
        let len = u32::try_from(12 + body.len() + pad).expect("len");
        let mut b = Vec::new();
        b.extend_from_slice(&self.u32(ty));
        b.extend_from_slice(&self.u32(len));
        b.extend_from_slice(body);
        b.extend(std::iter::repeat_n(0u8, pad));
        b.extend_from_slice(&self.u32(len));
        self.buf.extend_from_slice(&b);
    }
    /// Start a new section (SHB).
    pub fn section(&mut self, big_endian: bool) {
        self.be = big_endian;
        let mut body = Vec::new();
        body.extend_from_slice(&self.u32(0x1a2b_3c4d));
        body.extend_from_slice(&self.u16(1));
        body.extend_from_slice(&self.u16(0));
        body.extend_from_slice(&(-1i64).to_le_bytes());
        self.block(0x0a0d_0d0a, &body);
    }
    /// Interface Description Block; `tsresol` is the raw if_tsresol option.
    pub fn idb(&mut self, link_type: u16, tsresol: Option<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&self.u16(link_type));
        body.extend_from_slice(&self.u16(0));
        body.extend_from_slice(&self.u32(262_144));
        if let Some(r) = tsresol {
            body.extend_from_slice(&self.u16(9));
            body.extend_from_slice(&self.u16(1));
            body.extend_from_slice(&[r, 0, 0, 0]);
            body.extend_from_slice(&self.u16(0));
            body.extend_from_slice(&self.u16(0));
        }
        self.block(1, &body);
    }
    /// Enhanced Packet Block; `ts` in the interface's units.
    pub fn epb(&mut self, if_id: u32, ts: u64, data: &[u8]) {
        let mut body = Vec::new();
        body.extend_from_slice(&self.u32(if_id));
        body.extend_from_slice(&self.u32((ts >> 32) as u32));
        body.extend_from_slice(&self.u32(ts as u32));
        let n = u32::try_from(data.len()).expect("len");
        body.extend_from_slice(&self.u32(n));
        body.extend_from_slice(&self.u32(n));
        body.extend_from_slice(data);
        let pad = (4 - data.len() % 4) % 4;
        body.extend(std::iter::repeat_n(0u8, pad));
        self.block(6, &body);
    }
    /// Simple Packet Block (no interface id, no timestamp).
    pub fn spb(&mut self, data: &[u8]) {
        let mut body = Vec::new();
        body.extend_from_slice(&self.u32(u32::try_from(data.len()).expect("len")));
        body.extend_from_slice(data);
        self.block(3, &body);
    }
    /// Name Resolution Block (skipped by the reader).
    pub fn nrb(&mut self) {
        let body = [0u8; 4];
        self.block(4, &body);
    }
}

impl Default for Pcapng {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- packets

pub const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
pub const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

pub fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + payload.len());
    v.extend_from_slice(&MAC_B);
    v.extend_from_slice(&MAC_A);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        s += u32::from(w);
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).expect("len");
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, proto, 0, 0]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let c = checksum(&h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

pub fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&u16::try_from(payload.len()).expect("len").to_be_bytes());
    h.push(next);
    h.push(64);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(payload);
    h
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(20 + payload.len());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&seq.to_be_bytes());
    h.extend_from_slice(&ack.to_be_bytes());
    h.push(0x50);
    h.push(flags);
    h.extend_from_slice(&65535u16.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    h.extend_from_slice(payload);
    h
}

pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(8 + payload.len());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&u16::try_from(8 + payload.len()).expect("len").to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(payload);
    h
}

pub fn eth_udp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    eth(0x0800, &ipv4(src, dst, 17, &udp(sport, dport, payload)))
}

/// A scripted TCP connection over Ethernet/IPv4. Each call appends one frame.
pub struct Tcp {
    pub c: ([u8; 4], u16),
    pub s: ([u8; 4], u16),
    pub cseq: u32,
    pub sseq: u32,
    pub ts: i64,
    pub step_us: i64,
    pub frames: Vec<(i64, Vec<u8>)>,
}

impl Tcp {
    pub fn new(c: ([u8; 4], u16), s: ([u8; 4], u16), ts: i64) -> Self {
        Self {
            c,
            s,
            cseq: 1000,
            sseq: 5000,
            ts,
            step_us: 1000,
            frames: Vec::new(),
        }
    }
    fn push(&mut self, from_client: bool, flags: u8, payload: &[u8]) {
        let (src, dst, seq, ack) = if from_client {
            (self.c, self.s, self.cseq, self.sseq)
        } else {
            (self.s, self.c, self.sseq, self.cseq)
        };
        let f = eth(
            0x0800,
            &ipv4(
                src.0,
                dst.0,
                6,
                &tcp(src.1, dst.1, seq, ack, flags, payload),
            ),
        );
        self.frames.push((self.ts, f));
        self.ts += self.step_us;
    }
    pub fn handshake(&mut self) {
        self.push(true, SYN, &[]);
        self.cseq += 1;
        self.push(false, SYN | ACK, &[]);
        self.sseq += 1;
        self.push(true, ACK, &[]);
    }
    pub fn client(&mut self, payload: &[u8]) {
        self.push(true, PSH | ACK, payload);
        self.cseq = self
            .cseq
            .wrapping_add(u32::try_from(payload.len()).expect("len"));
    }
    pub fn server(&mut self, payload: &[u8]) {
        self.push(false, PSH | ACK, payload);
        self.sseq = self
            .sseq
            .wrapping_add(u32::try_from(payload.len()).expect("len"));
    }
    /// Re-send `payload` as if it started `back` bytes before the current seq.
    pub fn client_retransmit(&mut self, payload: &[u8]) {
        let saved = self.cseq;
        self.cseq = saved.wrapping_sub(u32::try_from(payload.len()).expect("len"));
        self.push(true, PSH | ACK, payload);
        self.cseq = saved;
    }
    pub fn close(&mut self) {
        self.push(true, FIN | ACK, &[]);
        self.cseq += 1;
        self.push(false, FIN | ACK, &[]);
        self.sseq += 1;
        self.push(true, ACK, &[]);
    }
}

// ---------------------------------------------------------------- DNS

pub fn dns_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for l in name.split('.').filter(|l| !l.is_empty()) {
        v.push(u8::try_from(l.len()).expect("label"));
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

fn dns_header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
    let mut v = Vec::new();
    for x in [id, flags, qd, an, 0, 0] {
        v.extend_from_slice(&x.to_be_bytes());
    }
    v
}

pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut v = dns_header(id, 0x0100, 1, 0);
    v.extend_from_slice(&dns_name(name));
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v
}

/// Response whose answers all use a pointer to the question name (offset 12).
pub fn dns_response(
    id: u16,
    name: &str,
    qtype: u16,
    rcode: u8,
    answers: &[(u16, u32, Vec<u8>)],
) -> Vec<u8> {
    let flags = 0x8180 | u16::from(rcode & 0x0f);
    let mut v = dns_header(id, flags, 1, u16::try_from(answers.len()).expect("n"));
    v.extend_from_slice(&dns_name(name));
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    for (ty, ttl, rdata) in answers {
        v.extend_from_slice(&[0xc0, 0x0c]);
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&u16::try_from(rdata.len()).expect("rd").to_be_bytes());
        v.extend_from_slice(rdata);
    }
    v
}

pub fn with_len_prefix(msg: &[u8]) -> Vec<u8> {
    let mut v = u16::try_from(msg.len())
        .expect("len")
        .to_be_bytes()
        .to_vec();
    v.extend_from_slice(msg);
    v
}

// ---------------------------------------------------------------- TLS

pub fn tls_record(ct: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![ct, 3, 1];
    v.extend_from_slice(&u16::try_from(payload.len()).expect("len").to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub fn handshake(ty: u8, body: &[u8]) -> Vec<u8> {
    let n = u32::try_from(body.len()).expect("len").to_be_bytes();
    let mut v = vec![ty, n[1], n[2], n[3]];
    v.extend_from_slice(body);
    v
}

fn ext(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ty.to_be_bytes().to_vec();
    v.extend_from_slice(&u16::try_from(data.len()).expect("len").to_be_bytes());
    v.extend_from_slice(data);
    v
}

fn u16s(list: &[u16]) -> Vec<u8> {
    list.iter().flat_map(|x| x.to_be_bytes()).collect()
}

fn vec16(b: &[u8]) -> Vec<u8> {
    let mut v = u16::try_from(b.len()).expect("len").to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

pub struct HelloSpec<'a> {
    pub sni: Option<&'a str>,
    pub alpn: &'a [&'a str],
    pub ciphers: &'a [u16],
    pub versions: &'a [u16],
    pub sig_algs: &'a [u16],
    /// Extra empty-bodied extensions, in order.
    pub other_exts: &'a [u16],
}

/// ClientHello handshake message (not wrapped in a record).
pub fn client_hello(s: &HelloSpec<'_>) -> Vec<u8> {
    client_hello_with(s, &[])
}

/// ClientHello with extra extensions carrying data (e.g. a 1216-byte
/// X25519MLKEM768 key_share, as Chrome and Firefox send), appended last.
pub fn client_hello_with(s: &HelloSpec<'_>, extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut b = vec![3, 3];
    b.extend_from_slice(&[0x11; 32]);
    b.push(32);
    b.extend_from_slice(&[0x22; 32]);
    b.extend_from_slice(&vec16(&u16s(s.ciphers)));
    b.extend_from_slice(&[1, 0]);
    let mut exts = Vec::new();
    exts.extend(ext(0x0a0a, &[])); // GREASE first, as browsers do
    if let Some(sni) = s.sni {
        let mut entry = vec![0];
        entry.extend_from_slice(&vec16(sni.as_bytes()));
        exts.extend(ext(0, &vec16(&entry)));
    }
    for &e in s.other_exts {
        exts.extend(ext(e, &[]));
    }
    if !s.alpn.is_empty() {
        let mut l = Vec::new();
        for p in s.alpn {
            l.push(u8::try_from(p.len()).expect("alpn"));
            l.extend_from_slice(p.as_bytes());
        }
        exts.extend(ext(0x0010, &vec16(&l)));
    }
    if !s.sig_algs.is_empty() {
        exts.extend(ext(0x000d, &vec16(&u16s(s.sig_algs))));
    }
    if !s.versions.is_empty() {
        let v = u16s(s.versions);
        let mut d = vec![u8::try_from(v.len()).expect("v")];
        d.extend_from_slice(&v);
        exts.extend(ext(0x002b, &d));
    }
    for (ty, data) in extra {
        exts.extend(ext(*ty, data));
    }
    b.extend_from_slice(&vec16(&exts));
    handshake(1, &b)
}

/// ServerHello handshake message.
pub fn server_hello(cipher: u16, version13: bool, exts_in_order: &[u16]) -> Vec<u8> {
    let mut b = vec![3, 3];
    b.extend_from_slice(&[0x33; 32]);
    b.push(0);
    b.extend_from_slice(&cipher.to_be_bytes());
    b.push(0);
    let mut exts = Vec::new();
    for &e in exts_in_order {
        if e == 0x002b && version13 {
            exts.extend(ext(e, &[3, 4]));
        } else if e == 0x0010 {
            exts.extend(ext(e, &vec16(&[2, b'h', b'2'])));
        } else {
            exts.extend(ext(e, &[]));
        }
    }
    b.extend_from_slice(&vec16(&exts));
    handshake(2, &b)
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 128 {
        v.push(n as u8);
    } else if n < 256 {
        v.extend_from_slice(&[0x81, n as u8]);
    } else {
        v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn der_name(parts: &[([u8; 3], &str)]) -> Vec<u8> {
    let mut seq = Vec::new();
    for (oid, val) in parts {
        let atv = [der(0x06, oid), der(0x0c, val.as_bytes())].concat();
        seq.extend(der(0x31, &der(0x30, &atv)));
    }
    der(0x30, &seq)
}

pub const OID_CN: [u8; 3] = [0x55, 0x04, 0x03];
pub const OID_O: [u8; 3] = [0x55, 0x04, 0x0a];
pub const OID_C: [u8; 3] = [0x55, 0x04, 0x06];

/// A structurally valid X.509 certificate with a dummy key and signature.
pub fn der_cert(
    subject: &[([u8; 3], &str)],
    issuer: &[([u8; 3], &str)],
    serial: &[u8],
    nb: &str,
    na: &str,
) -> Vec<u8> {
    let alg = der(
        0x30,
        &[
            der(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11]),
            vec![5, 0],
        ]
        .concat(),
    );
    let validity = der(
        0x30,
        &[der(0x17, nb.as_bytes()), der(0x17, na.as_bytes())].concat(),
    );
    let spki = der(0x30, &[alg.clone(), der(0x03, &[0, 1, 2, 3])].concat());
    let tbs = der(
        0x30,
        &[
            der(0xa0, &der(0x02, &[2])),
            der(0x02, serial),
            alg.clone(),
            der_name(issuer),
            validity,
            der_name(subject),
            spki,
        ]
        .concat(),
    );
    der(0x30, &[tbs, alg, der(0x03, &[0, 0xde, 0xad])].concat())
}

pub fn certificate_msg(der: &[u8]) -> Vec<u8> {
    let n = u32::try_from(der.len()).expect("len").to_be_bytes();
    let mut entry = vec![n[1], n[2], n[3]];
    entry.extend_from_slice(der);
    let m = u32::try_from(entry.len()).expect("len").to_be_bytes();
    let mut body = vec![m[1], m[2], m[3]];
    body.extend_from_slice(&entry);
    handshake(11, &body)
}

// ---------------------------------------------------------------- sink

/// Every row the ingest produced, by table, in emission order.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct Rows {
    pub frames: Vec<FrameRow>,
    pub flows: Vec<FlowRow>,
    pub dns: Vec<DnsRow>,
    pub http: Vec<HttpRow>,
    pub tls: Vec<TlsRow>,
    pub files: Vec<FileRow>,
}

impl Rows {
    pub fn add(&mut self, b: &RecordBatch) {
        match b.clone() {
            RecordBatch::Frames(v) => self.frames.extend(v),
            RecordBatch::Flows(v) => self.flows.extend(v),
            RecordBatch::Dns(v) => self.dns.extend(v),
            RecordBatch::Http(v) => self.http.extend(v),
            RecordBatch::Tls(v) => self.tls.extend(v),
            RecordBatch::Files(v) => self.files.extend(v),
        }
    }
    /// Order-independent form (the index sorts rows itself).
    pub fn sorted(mut self) -> Self {
        self.flows.sort_by_key(|f| f.flow_id);
        self.dns.sort_by_key(|r| (r.frame_no, r.flow_id));
        self.http.sort_by_key(|r| (r.frame_no, r.flow_id));
        self.tls.sort_by_key(|r| (r.frame_no, r.flow_id));
        self.files.sort_by_key(|r| (r.frame_no, r.flow_id));
        self
    }
}

/// Records everything; can simulate a crash after N checkpoints and a resume.
#[derive(Default)]
pub struct CollectSink {
    pub rows: Rows,
    pub checkpoints: Vec<Checkpoint>,
    pub begun: Option<CaptureRow>,
    pub finished: Option<CaptureRow>,
    pub resume_from: Option<Checkpoint>,
    /// Fail every call after this many checkpoints were accepted.
    pub crash_after: Option<usize>,
    /// Rows durable at the last accepted checkpoint.
    pub durable: Rows,
    pub pending: Vec<RecordBatch>,
}

impl CollectSink {
    fn crashed(&self) -> bool {
        self.crash_after
            .is_some_and(|n| self.checkpoints.len() >= n)
    }
}

impl IndexSink for CollectSink {
    fn begin(&mut self, capture: &CaptureRow) -> ApiResult<Option<Checkpoint>> {
        self.begun = Some(capture.clone());
        Ok(self.resume_from.clone())
    }
    fn write(&mut self, batch: RecordBatch) -> ApiResult<()> {
        if self.crashed() {
            return Err(ApiError::internal("simulated crash"));
        }
        self.rows.add(&batch);
        self.pending.push(batch);
        Ok(())
    }
    fn checkpoint(&mut self, cp: Checkpoint) -> ApiResult<()> {
        if self.crashed() {
            return Err(ApiError::internal("simulated crash"));
        }
        for b in self.pending.drain(..) {
            self.durable.add(&b);
        }
        self.checkpoints.push(cp);
        Ok(())
    }
    fn finish(&mut self, capture: &CaptureRow) -> ApiResult<()> {
        self.finished = Some(capture.clone());
        Ok(())
    }
}
