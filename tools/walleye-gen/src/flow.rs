//! Lazy per-flow packet emitters. A flow is a script of application
//! messages; the emitter turns it into a real TCP conversation (handshake,
//! MSS-sized segments with correct seq/ack, delayed ACKs, teardown) or a
//! list of UDP datagrams, one packet at a time. Payload bytes are produced
//! on demand, so a 200 MB transfer costs a few hundred bytes of memory.

use std::collections::VecDeque;

use crate::net::{self, ACK, FIN, Hop, PSH, RST, SYN, TcpHdr};
use crate::rng::Rng;
use crate::tls::CT_APPDATA;

pub const MSS: usize = 1460;
/// Largest TLS record body we emit in a `TlsData` stream (16 KiB + AEAD tag).
const TLS_MAX_BODY: u64 = 16_384 + 17;

/// A piece of message payload.
#[derive(Debug, Clone)]
pub enum Chunk {
    /// Literal bytes (headers, handshakes, DNS, small bodies).
    Bytes(Vec<u8>),
    /// `n` pseudo-random bytes (opaque bodies).
    Random(u64),
    /// `n` bytes of TLS application-data records (headers + random bodies).
    TlsData(u64),
}

impl Chunk {
    pub fn len(&self) -> u64 {
        match self {
            Chunk::Bytes(b) => b.len() as u64,
            Chunk::Random(n) | Chunk::TlsData(n) => *n,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One application message in one direction.
#[derive(Debug, Clone)]
pub struct Msg {
    pub from_client: bool,
    /// Delay after the previous packet before this message starts.
    pub delay_us: u64,
    pub chunks: Vec<Chunk>,
}

impl Msg {
    pub fn client(delay_us: u64, chunks: Vec<Chunk>) -> Msg {
        Msg {
            from_client: true,
            delay_us,
            chunks,
        }
    }
    pub fn server(delay_us: u64, chunks: Vec<Chunk>) -> Msg {
        Msg {
            from_client: false,
            delay_us,
            chunks,
        }
    }
}

/// Sequential reader over a message's chunks.
struct Reader {
    chunks: VecDeque<Chunk>,
    off: u64,
    /// Total length (header + body) of the TLS record in progress; 0 = none.
    tls_rec_len: u64,
    /// Bytes of that record already produced.
    tls_pos: u64,
    remaining: u64,
}

fn fill_random(out: &mut Vec<u8>, n: u64, rng: &mut Rng) {
    let start = out.len();
    out.resize(start + n as usize, 0);
    rng.fill(&mut out[start..]);
}

impl Reader {
    fn new(chunks: Vec<Chunk>) -> Reader {
        let remaining = chunks.iter().map(Chunk::len).sum();
        Reader {
            chunks: chunks.into_iter().filter(|c| !c.is_empty()).collect(),
            off: 0,
            tls_rec_len: 0,
            tls_pos: 0,
            remaining,
        }
    }

    fn read(&mut self, out: &mut Vec<u8>, max: usize, rng: &mut Rng) {
        let mut want = (max as u64).min(self.remaining);
        while want > 0 {
            let Some(chunk) = self.chunks.front() else {
                break;
            };
            let clen = chunk.len();
            let left_in_chunk = clen - self.off;
            let mut take = want.min(left_in_chunk);
            match chunk {
                Chunk::Bytes(b) => {
                    let s = self.off as usize;
                    out.extend_from_slice(&b[s..s + take as usize]);
                }
                Chunk::Random(_) => fill_random(out, take, rng),
                Chunk::TlsData(_) => {
                    if self.tls_rec_len == 0 {
                        // Start a record. Keep any remainder >= 6 bytes so it
                        // can hold a header plus one body byte.
                        let rest = left_in_chunk;
                        let body = if rest <= 5 {
                            0
                        } else if rest - 5 <= TLS_MAX_BODY {
                            rest - 5
                        } else if rest - 5 - TLS_MAX_BODY < 6 {
                            rest - 5 - 6
                        } else {
                            TLS_MAX_BODY
                        };
                        if body > 0 {
                            self.tls_rec_len = body + 5;
                            self.tls_pos = 0;
                        }
                    }
                    if self.tls_rec_len == 0 {
                        // Degenerate (< 6 byte) stream: opaque bytes.
                        fill_random(out, take, rng);
                    } else {
                        take = take.min(self.tls_rec_len - self.tls_pos);
                        let body = self.tls_rec_len - 5;
                        let hdr = [CT_APPDATA, 3, 3, (body >> 8) as u8, body as u8];
                        let mut done = 0u64;
                        while done < take && self.tls_pos + done < 5 {
                            out.push(hdr[(self.tls_pos + done) as usize]);
                            done += 1;
                        }
                        fill_random(out, take - done, rng);
                        self.tls_pos += take;
                        if self.tls_pos == self.tls_rec_len {
                            self.tls_rec_len = 0;
                            self.tls_pos = 0;
                        }
                    }
                }
            }
            self.off += take;
            self.remaining -= take;
            want -= take;
            if self.off == clen {
                self.chunks.pop_front();
                self.off = 0;
                self.tls_rec_len = 0;
                self.tls_pos = 0;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Close {
    ClientFin,
    ServerFin,
    ServerRst,
    /// Leave the connection open (long-lived or cut off by the capture end).
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Syn,
    SynAck,
    HsAck,
    Data,
    Fin1,
    Fin2,
    LastAck,
    Done,
}

pub struct TcpFlow {
    c2s: Hop,
    s2c: Hop,
    cport: u16,
    sport: u16,
    seq_c: u32,
    seq_s: u32,
    msgs: VecDeque<Msg>,
    cur: Option<(bool, Reader)>,
    phase: Phase,
    t: i64,
    rtt_us: u64,
    seg_gap_us: u64,
    segs_since_ack: u32,
    ack_due: Option<bool>,
    last_from_client: bool,
    close: Close,
    close_delay_us: u64,
    ip_id_c: u16,
    ip_id_s: u16,
    rng: Rng,
}

pub struct TcpSpec {
    pub c2s: Hop,
    pub s2c: Hop,
    pub cport: u16,
    pub sport: u16,
    pub start_us: i64,
    pub rtt_us: u64,
    /// Gap between back-to-back segments of one message.
    pub seg_gap_us: u64,
    pub msgs: Vec<Msg>,
    pub close: Close,
    /// Idle time after the last message before teardown starts.
    pub close_delay_us: u64,
}

impl TcpFlow {
    pub fn new(spec: TcpSpec, mut rng: Rng) -> TcpFlow {
        TcpFlow {
            c2s: spec.c2s,
            s2c: spec.s2c,
            cport: spec.cport,
            sport: spec.sport,
            seq_c: rng.next_u32(),
            seq_s: rng.next_u32(),
            msgs: spec.msgs.into(),
            cur: None,
            phase: Phase::Syn,
            t: spec.start_us,
            rtt_us: spec.rtt_us.max(100),
            seg_gap_us: spec.seg_gap_us.max(1),
            segs_since_ack: 0,
            ack_due: None,
            last_from_client: true,
            close: spec.close,
            close_delay_us: spec.close_delay_us,
            ip_id_c: rng.next_u16(),
            ip_id_s: rng.next_u16(),
            rng,
        }
    }

    pub fn peek(&self) -> Option<i64> {
        (self.phase != Phase::Done).then_some(self.t)
    }

    fn send(
        &mut self,
        buf: &mut Vec<u8>,
        from_client: bool,
        flags: u8,
        opts: &[u8],
        payload: &[u8],
    ) {
        let (hop, ip_id, sport, dport, seq, ack, window) = if from_client {
            self.ip_id_c = self.ip_id_c.wrapping_add(1);
            (
                self.c2s,
                self.ip_id_c,
                self.cport,
                self.sport,
                self.seq_c,
                self.seq_s,
                if flags & SYN != 0 { 64_240 } else { 513 },
            )
        } else {
            self.ip_id_s = self.ip_id_s.wrapping_add(1);
            (
                self.s2c,
                self.ip_id_s,
                self.sport,
                self.cport,
                self.seq_s,
                self.seq_c,
                if flags & SYN != 0 { 65_535 } else { 501 },
            )
        };
        let ack = if flags & ACK != 0 { ack } else { 0 };
        net::tcp_frame(
            buf,
            &hop,
            ip_id,
            &TcpHdr {
                sport,
                dport,
                seq,
                ack,
                flags,
                window,
                options: opts,
            },
            payload,
        );
        let adv = payload.len() as u32 + u32::from(flags & (SYN | FIN) != 0);
        if from_client {
            self.seq_c = self.seq_c.wrapping_add(adv);
        } else {
            self.seq_s = self.seq_s.wrapping_add(adv);
        }
    }

    fn small_gap(&mut self) -> u64 {
        self.rng.range(20, 150)
    }

    /// Build the next packet into `buf`; returns its timestamp. Afterwards
    /// `peek()` is the exact time of the following packet.
    pub fn emit(&mut self, buf: &mut Vec<u8>) -> i64 {
        let ts = self.emit_inner(buf);
        self.settle();
        ts
    }

    /// Apply non-emitting transitions (message delays, idle before close)
    /// so that `self.t` is the time of the next packet, not of a wait.
    fn settle(&mut self) {
        if self.phase != Phase::Data || self.ack_due.is_some() || self.cur.is_some() {
            return;
        }
        loop {
            match self.msgs.pop_front() {
                Some(m) => {
                    self.t += m.delay_us as i64;
                    let reader = Reader::new(m.chunks);
                    if reader.remaining > 0 {
                        self.cur = Some((m.from_client, reader));
                        return;
                    }
                }
                None => {
                    self.t += self.close_delay_us as i64;
                    self.phase = match self.close {
                        Close::Open => Phase::Done,
                        Close::ServerRst => Phase::LastAck,
                        _ => Phase::Fin1,
                    };
                    return;
                }
            }
        }
    }

    fn emit_inner(&mut self, buf: &mut Vec<u8>) -> i64 {
        loop {
            let now = self.t;
            match self.phase {
                Phase::Done => return now,
                Phase::Syn => {
                    self.send(buf, true, SYN, &net::SYN_OPTS, &[]);
                    self.phase = Phase::SynAck;
                    self.t += self.rtt_us as i64;
                    return now;
                }
                Phase::SynAck => {
                    self.send(buf, false, SYN | ACK, &net::SYNACK_OPTS, &[]);
                    self.phase = Phase::HsAck;
                    self.t += self.small_gap() as i64;
                    return now;
                }
                Phase::HsAck => {
                    self.send(buf, true, ACK, &[], &[]);
                    self.phase = Phase::Data;
                    self.t += self.small_gap() as i64;
                    return now;
                }
                Phase::Data => {
                    if let Some(receiver_is_client) = self.ack_due.take() {
                        self.send(buf, receiver_is_client, ACK, &[], &[]);
                        self.t += self.small_gap() as i64;
                        return now;
                    }
                    if self.cur.is_none() {
                        match self.msgs.pop_front() {
                            Some(m) => {
                                self.t += m.delay_us as i64;
                                self.cur = Some((m.from_client, Reader::new(m.chunks)));
                                continue;
                            }
                            None => {
                                self.t += self.close_delay_us as i64;
                                self.phase = match self.close {
                                    Close::Open => Phase::Done,
                                    Close::ServerRst => Phase::LastAck,
                                    _ => Phase::Fin1,
                                };
                                continue;
                            }
                        }
                    }
                    let mut payload = Vec::with_capacity(MSS);
                    let (from_client, last) = {
                        let Some((from_client, reader)) = self.cur.as_mut() else {
                            continue;
                        };
                        reader.read(&mut payload, MSS, &mut self.rng);
                        (*from_client, reader.remaining == 0)
                    };
                    if payload.is_empty() {
                        self.cur = None;
                        continue;
                    }
                    let flags = if last { ACK | PSH } else { ACK };
                    self.send(buf, from_client, flags, &[], &payload);
                    self.last_from_client = from_client;
                    self.segs_since_ack += 1;
                    if last || self.segs_since_ack >= 2 {
                        self.segs_since_ack = 0;
                        self.ack_due = Some(!from_client);
                        self.t += self.small_gap() as i64;
                    } else {
                        self.t += self.seg_gap_us as i64;
                    }
                    if last {
                        self.cur = None;
                    }
                    return now;
                }
                Phase::Fin1 => {
                    let by_client = self.close != Close::ServerFin;
                    self.send(buf, by_client, FIN | ACK, &[], &[]);
                    self.phase = Phase::Fin2;
                    self.t += if by_client {
                        self.rtt_us as i64
                    } else {
                        self.small_gap() as i64
                    };
                    return now;
                }
                Phase::Fin2 => {
                    let by_client = self.close != Close::ServerFin;
                    self.send(buf, !by_client, FIN | ACK, &[], &[]);
                    self.phase = Phase::LastAck;
                    self.t += if by_client {
                        self.small_gap() as i64
                    } else {
                        self.rtt_us as i64
                    };
                    return now;
                }
                Phase::LastAck => {
                    if self.close == Close::ServerRst {
                        self.send(buf, false, RST | ACK, &[], &[]);
                    } else {
                        let by_client = self.close != Close::ServerFin;
                        self.send(buf, by_client, ACK, &[], &[]);
                    }
                    self.phase = Phase::Done;
                    return now;
                }
            }
        }
    }
}

/// A UDP conversation: datagrams with delays, alternating as scripted.
pub struct UdpFlow {
    c2s: Hop,
    s2c: Hop,
    cport: u16,
    sport: u16,
    pkts: VecDeque<(bool, u64, Vec<u8>)>,
    t: i64,
    ip_id_c: u16,
    ip_id_s: u16,
}

impl UdpFlow {
    /// `pkts`: (from_client, delay before this datagram, payload).
    pub fn new(
        c2s: Hop,
        s2c: Hop,
        cport: u16,
        sport: u16,
        start_us: i64,
        pkts: Vec<(bool, u64, Vec<u8>)>,
        rng: &mut Rng,
    ) -> UdpFlow {
        let mut f = UdpFlow {
            c2s,
            s2c,
            cport,
            sport,
            pkts: pkts.into(),
            t: start_us,
            ip_id_c: rng.next_u16(),
            ip_id_s: rng.next_u16(),
        };
        if let Some((_, d, _)) = f.pkts.front() {
            f.t += *d as i64;
        }
        f
    }

    pub fn peek(&self) -> Option<i64> {
        (!self.pkts.is_empty()).then_some(self.t)
    }

    pub fn emit(&mut self, buf: &mut Vec<u8>) -> i64 {
        let now = self.t;
        if let Some((from_client, _, payload)) = self.pkts.pop_front() {
            if from_client {
                self.ip_id_c = self.ip_id_c.wrapping_add(1);
                net::udp_frame(
                    buf,
                    &self.c2s,
                    self.ip_id_c,
                    self.cport,
                    self.sport,
                    &payload,
                );
            } else {
                self.ip_id_s = self.ip_id_s.wrapping_add(1);
                net::udp_frame(
                    buf,
                    &self.s2c,
                    self.ip_id_s,
                    self.sport,
                    self.cport,
                    &payload,
                );
            }
        }
        if let Some((_, d, _)) = self.pkts.front() {
            self.t += *d as i64;
        }
        now
    }
}

pub enum Flow {
    Tcp(Box<TcpFlow>),
    Udp(UdpFlow),
}

impl Flow {
    pub fn peek(&self) -> Option<i64> {
        match self {
            Flow::Tcp(f) => f.peek(),
            Flow::Udp(f) => f.peek(),
        }
    }

    pub fn emit(&mut self, buf: &mut Vec<u8>) -> i64 {
        match self {
            Flow::Tcp(f) => f.emit(buf),
            Flow::Udp(f) => f.emit(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk TLS records in `stream`; returns the record count.
    fn records(stream: &[u8]) -> usize {
        let mut p = 0;
        let mut n = 0;
        while p < stream.len() {
            assert_eq!(&stream[p..p + 3], &[CT_APPDATA, 3, 3], "bad header at {p}");
            let len = usize::from(u16::from_be_bytes([stream[p + 3], stream[p + 4]]));
            assert!(len > 0 && len <= TLS_MAX_BODY as usize);
            p += 5 + len;
            n += 1;
        }
        assert_eq!(p, stream.len(), "records must tile the stream exactly");
        n
    }

    #[test]
    fn tls_data_frames_correctly_across_any_read_size() {
        for total in [6u64, 30, 16_389, 16_390, 16_391, 16_400, 50_000, 200_003] {
            for step in [1usize, 7, 1460, 4096] {
                let mut r = Reader::new(vec![Chunk::TlsData(total)]);
                let mut rng = Rng::new(total ^ step as u64);
                let mut out = Vec::new();
                while r.remaining > 0 {
                    r.read(&mut out, step, &mut rng);
                }
                assert_eq!(out.len() as u64, total);
                assert!(records(&out) >= 1);
            }
        }
    }

    #[test]
    fn mixed_chunks_keep_order_and_length() {
        let mut r = Reader::new(vec![
            Chunk::Bytes(b"HEAD".to_vec()),
            Chunk::Random(10),
            Chunk::Bytes(b"TAIL".to_vec()),
        ]);
        let mut rng = Rng::new(1);
        let mut out = Vec::new();
        while r.remaining > 0 {
            r.read(&mut out, 3, &mut rng);
        }
        assert_eq!(out.len(), 18);
        assert_eq!(&out[..4], b"HEAD");
        assert_eq!(&out[14..], b"TAIL");
    }
}
