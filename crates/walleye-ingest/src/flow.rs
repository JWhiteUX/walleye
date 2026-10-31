//! Bidirectional flow assembly (5-tuple + idle timeout) and dispatch of
//! in-order stream bytes to the application parsers.
//!
//! * Initiator (`src`) = SYN sender; a flow first seen at its SYN-ACK is
//!   attributed to the SYN-ACK's receiver; otherwise the first packet's sender.
//! * A flow closes on idle timeout, or `LINGER_US` after RST / both FINs (so
//!   trailing ACKs still attach), or when a new SYN reuses a closed tuple.
//! * TCP payload is delivered in sequence order without full reassembly:
//!   retransmitted bytes are dropped, holes are reported to the parser as a gap.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use walleye_core::{Direction, DnsRow, FlowRow, FrameNo, Ts};

use crate::dns::{DnsMessage, parse_dns, qtype_name, rcode_name};
use crate::http::{HttpConn, looks_like_request, looks_like_response};
use crate::out::{Ctx, Out};
use crate::packet::{ACK, FIN, PROTO_TCP, PROTO_UDP, PacketInfo, RST, SYN};
use crate::tls::{TlsConn, looks_like_tls};

/// Keep a closed TCP flow this long for trailing packets.
pub const LINGER_US: i64 = 2_000_000;
/// Sweep for expired flows at most this often (capture time).
const SWEEP_EVERY_US: i64 = 1_000_000;
/// Undetected TCP flows give up after this many payload segments.
const DETECT_TRIES: u8 = 4;
const MAX_DNS_TCP_BUF: usize = 65_537;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    proto: u8,
    a: IpAddr,
    ap: u16,
    b: IpAddr,
    bp: u16,
}

impl FlowKey {
    fn new(proto: u8, s: IpAddr, sp: u16, d: IpAddr, dp: u16) -> Self {
        if (s, sp) <= (d, dp) {
            Self {
                proto,
                a: s,
                ap: sp,
                b: d,
                bp: dp,
            }
        } else {
            Self {
                proto,
                a: d,
                ap: dp,
                b: s,
                bp: sp,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProto {
    Dns,
    Http,
    Tls,
}

impl AppProto {
    pub fn name(self) -> &'static str {
        match self {
            AppProto::Dns => "dns",
            AppProto::Http => "http",
            AppProto::Tls => "tls",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsTcp {
    bufs: [Vec<u8>; 2],
    starts: [(FrameNo, Ts); 2],
    dead: [bool; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum App {
    /// TCP flow whose protocol is not known yet.
    Detecting(u8),
    /// Not a protocol we parse.
    Ignored,
    DnsUdp,
    DnsTcp(Box<DnsTcp>),
    Http(Box<HttpConn>),
    Tls(Box<TlsConn>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: u64,
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub ts_start: Ts,
    pub ts_end: Ts,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub pkts_up: u64,
    pub pkts_down: u64,
    pub first_frame: FrameNo,
    pub last_frame: FrameNo,
    pub app_proto: Option<AppProto>,
    pub app: App,
    /// Next expected TCP sequence number per direction (0 = up).
    next_seq: [Option<u32>; 2],
    fin: [bool; 2],
    rst: bool,
}

impl Flow {
    fn closed(&self) -> bool {
        self.rst || (self.fin[0] && self.fin[1])
    }

    fn row(&self) -> FlowRow {
        FlowRow {
            flow_id: self.id,
            ts_start: self.ts_start,
            ts_end: self.ts_end,
            src_ip: self.src.to_string(),
            src_port: self.sport,
            dst_ip: self.dst.to_string(),
            dst_port: self.dport,
            proto: self.proto,
            app_proto: self.app_proto.map(|a| a.name().to_string()),
            bytes_up: self.bytes_up,
            bytes_down: self.bytes_down,
            pkts_up: self.pkts_up,
            pkts_down: self.pkts_down,
            first_frame: self.first_frame,
            last_frame: self.last_frame,
        }
    }

    /// Emit the flow row and anything its parsers still hold.
    fn close(&mut self, out: &mut Out) {
        match &mut self.app {
            App::Http(h) => h.finish(out),
            App::Tls(t) => t.finish(out),
            _ => {}
        }
        self.app = App::Ignored;
        out.flows.push(self.row());
    }
}

/// Serializable flow-table state for checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTableState {
    pub flows: Vec<Flow>,
    pub next_id: u64,
    pub last_sweep: Ts,
    pub max_ts: Ts,
}

/// Live (unexpired) flows kept in memory. A hostile capture of SYNs with a
/// constant timestamp never expires anything, so without a cap every packet
/// adds a flow (security review: ~12× the file size in RAM). When full, the
/// least recently active 10 % are closed early; a closed flow that sees more
/// packets continues as a new flow row.
pub const MAX_LIVE_FLOWS: usize = 500_000;

pub struct FlowTable {
    map: HashMap<FlowKey, Flow>,
    pub next_id: u64,
    tcp_timeout_us: i64,
    udp_timeout_us: i64,
    last_sweep: Ts,
    max_ts: Ts,
}

impl FlowTable {
    pub fn new(tcp_idle_timeout_s: u32, udp_idle_timeout_s: u32) -> Self {
        Self {
            map: HashMap::new(),
            next_id: 1,
            tcp_timeout_us: i64::from(tcp_idle_timeout_s) * 1_000_000,
            udp_timeout_us: i64::from(udp_idle_timeout_s) * 1_000_000,
            last_sweep: i64::MIN,
            max_ts: i64::MIN,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn save(&self) -> FlowTableState {
        let mut flows: Vec<Flow> = self.map.values().cloned().collect();
        flows.sort_by_key(|f| f.id);
        FlowTableState {
            flows,
            next_id: self.next_id,
            last_sweep: self.last_sweep,
            max_ts: self.max_ts,
        }
    }

    pub fn restore(&mut self, s: FlowTableState) {
        self.next_id = s.next_id;
        self.last_sweep = s.last_sweep;
        self.max_ts = s.max_ts;
        self.map = s
            .flows
            .into_iter()
            .map(|f| (FlowKey::new(f.proto, f.src, f.sport, f.dst, f.dport), f))
            .collect();
    }

    /// Close the least recently active tenth of the table. Bulk eviction keeps
    /// the cost amortized O(log n) per new flow.
    fn evict_oldest(&mut self, out: &mut Out) {
        let mut ends: Vec<(Ts, u64, FlowKey)> =
            self.map.iter().map(|(k, f)| (f.ts_end, f.id, *k)).collect();
        let n = (ends.len() / 10).max(1);
        ends.select_nth_unstable_by_key(n - 1, |e| (e.0, e.1));
        for (_, _, k) in ends.into_iter().take(n) {
            if let Some(mut f) = self.map.remove(&k) {
                f.close(out);
            }
        }
    }

    fn timeout(&self, proto: u8) -> i64 {
        if proto == PROTO_TCP {
            self.tcp_timeout_us
        } else {
            self.udp_timeout_us
        }
    }

    fn expired(&self, f: &Flow, now: Ts) -> bool {
        let idle = now.saturating_sub(f.ts_end);
        idle > self.timeout(f.proto) || (f.closed() && idle > LINGER_US)
    }

    /// Account one packet; returns its flow id and direction.
    pub fn packet(
        &mut self,
        frame_no: FrameNo,
        ts: Ts,
        p: &PacketInfo<'_>,
        out: &mut Out,
    ) -> (u64, Direction) {
        let key = FlowKey::new(p.proto, p.src, p.sport, p.dst, p.dport);
        let flags = p.tcp.map_or(0, |t| t.flags);
        let fresh_syn = flags & (SYN | ACK) == SYN;
        if let Some(f) = self.map.get(&key) {
            let reuse = fresh_syn && f.closed();
            if reuse || self.expired(f, ts) {
                if let Some(mut old) = self.map.remove(&key) {
                    old.close(out);
                }
            }
        }
        if self.map.len() >= MAX_LIVE_FLOWS && !self.map.contains_key(&key) {
            self.evict_oldest(out);
        }
        let next_id = &mut self.next_id;
        let f = self.map.entry(key).or_insert_with(|| {
            let id = *next_id;
            *next_id += 1;
            // SYN-ACK first: the receiver sent the SYN.
            let swap = flags & (SYN | ACK) == (SYN | ACK);
            let (src, sport, dst, dport) = if swap {
                (p.dst, p.dport, p.src, p.sport)
            } else {
                (p.src, p.sport, p.dst, p.dport)
            };
            let app = initial_app(p.proto, sport, dport);
            Flow {
                id,
                proto: p.proto,
                src,
                sport,
                dst,
                dport,
                ts_start: ts,
                ts_end: ts,
                bytes_up: 0,
                bytes_down: 0,
                pkts_up: 0,
                pkts_down: 0,
                first_frame: frame_no,
                last_frame: frame_no,
                app_proto: match app {
                    App::DnsUdp | App::DnsTcp(_) => Some(AppProto::Dns),
                    _ => None,
                },
                app,
                next_seq: [None, None],
                fin: [false, false],
                rst: false,
            }
        });
        let dir = if (p.src, p.sport) == (f.src, f.sport) {
            Direction::Up
        } else {
            Direction::Down
        };
        let d = usize::from(dir == Direction::Down);
        let len = u64::from(p.payload_len);
        if dir == Direction::Up {
            f.pkts_up += 1;
            f.bytes_up = f.bytes_up.saturating_add(len);
        } else {
            f.pkts_down += 1;
            f.bytes_down = f.bytes_down.saturating_add(len);
        }
        f.ts_end = f.ts_end.max(ts);
        f.ts_start = f.ts_start.min(ts);
        f.last_frame = frame_no;
        if flags & FIN != 0 {
            f.fin[d] = true;
        }
        if flags & RST != 0 {
            f.rst = true;
        }
        let ctx = Ctx {
            flow_id: f.id,
            frame_no,
            ts,
        };
        match p.proto {
            PROTO_UDP => {
                if matches!(f.app, App::DnsUdp)
                    && let Ok(m) = parse_dns(p.payload)
                {
                    out.dns.push(dns_row(&m, ctx));
                }
            }
            PROTO_TCP => {
                if let Some(t) = p.tcp {
                    tcp_payload(f, dir, t.seq, flags, p, ctx, out);
                }
            }
            _ => {}
        }
        (ctx.flow_id, dir)
    }

    /// Close idle flows. Cheap to call per packet: it scans the table at most
    /// once per second of capture time.
    pub fn maybe_sweep(&mut self, ts: Ts, out: &mut Out) {
        self.max_ts = self.max_ts.max(ts);
        if self.last_sweep != i64::MIN
            && self.max_ts.saturating_sub(self.last_sweep) < SWEEP_EVERY_US
        {
            return;
        }
        self.last_sweep = self.max_ts;
        let now = self.max_ts;
        let (tcp_t, udp_t) = (self.tcp_timeout_us, self.udp_timeout_us);
        let mut expired: Vec<FlowKey> = Vec::new();
        for (k, f) in &self.map {
            let idle = now.saturating_sub(f.ts_end);
            let t = if f.proto == PROTO_TCP { tcp_t } else { udp_t };
            if idle > t || (f.closed() && idle > LINGER_US) {
                expired.push(*k);
            }
        }
        // Deterministic output order regardless of hash iteration order.
        let mut closed: Vec<Flow> = expired.iter().filter_map(|k| self.map.remove(k)).collect();
        closed.sort_by_key(|f| f.id);
        for mut f in closed {
            f.close(out);
        }
    }

    /// End of capture: close every open flow, in flow-id order.
    pub fn finish_all(&mut self, out: &mut Out) {
        let mut flows: Vec<Flow> = self.map.drain().map(|(_, f)| f).collect();
        flows.sort_by_key(|f| f.id);
        for mut f in flows {
            f.close(out);
        }
    }
}

fn initial_app(proto: u8, sport: u16, dport: u16) -> App {
    let dns_port = sport == 53 || dport == 53;
    match proto {
        PROTO_UDP if dns_port => App::DnsUdp,
        PROTO_UDP => App::Ignored,
        PROTO_TCP if dns_port => App::DnsTcp(Box::default()),
        PROTO_TCP => App::Detecting(0),
        _ => App::Ignored,
    }
}

pub fn dns_row(m: &DnsMessage, ctx: Ctx) -> DnsRow {
    let q = m.questions.first();
    DnsRow {
        ts: ctx.ts,
        flow_id: ctx.flow_id,
        frame_no: ctx.frame_no,
        trans_id: m.id,
        is_response: m.is_response,
        query: q.map(|q| q.name.clone()).unwrap_or_default(),
        qtype: q.map_or_else(|| "TYPE0".to_string(), |q| qtype_name(q.qtype)),
        rcode: m.is_response.then(|| rcode_name(m.rcode)),
        answers: capped_answers(m),
        ttl: m.answers.iter().map(|a| a.ttl).min(),
    }
}

/// Sequence-order delivery for one TCP segment, then dispatch.
fn tcp_payload(
    f: &mut Flow,
    dir: Direction,
    seq: u32,
    flags: u8,
    p: &PacketInfo<'_>,
    ctx: Ctx,
    out: &mut Out,
) {
    if matches!(f.app, App::Ignored) {
        return;
    }
    let d = usize::from(dir == Direction::Down);
    let wire_len = p.payload_len;
    let captured = p
        .payload
        .get(..(wire_len as usize).min(p.payload.len()))
        .unwrap_or(&[]);
    let (data_seq, data) = if flags & SYN != 0 {
        (seq.wrapping_add(1), captured)
    } else {
        (seq, captured)
    };
    let mut gap = 0u64;
    let mut skip = 0usize;
    match f.next_seq[d] {
        None => {}
        Some(n) => {
            let diff = data_seq.wrapping_sub(n) as i32;
            if diff > 0 {
                gap = u64::from(diff.unsigned_abs());
            } else if diff < 0 {
                let overlap = diff.unsigned_abs();
                if overlap >= wire_len {
                    return; // pure retransmission (or keep-alive)
                }
                skip = overlap as usize;
            }
        }
    }
    let end = data_seq.wrapping_add(wire_len);
    if flags & SYN != 0 || wire_len > 0 || f.next_seq[d].is_none() {
        f.next_seq[d] = Some(end);
    }
    if wire_len == 0 {
        return;
    }
    let data = data.get(skip..).unwrap_or(&[]);
    // Bytes on the wire but not captured (snap length) count as a gap after.
    let missing = u64::from(wire_len).saturating_sub(skip as u64 + data.len() as u64);

    if let App::Detecting(tries) = f.app {
        if data.is_empty() {
            return;
        }
        let app = if (dir == Direction::Up && looks_like_request(data))
            || (dir == Direction::Down && looks_like_response(data))
        {
            Some((AppProto::Http, App::Http(Box::default())))
        } else if looks_like_tls(data) {
            Some((AppProto::Tls, App::Tls(Box::default())))
        } else {
            None
        };
        match app {
            Some((name, app)) => {
                f.app_proto = Some(name);
                f.app = app;
                gap = 0; // parsing starts here
            }
            None => {
                f.app = if tries + 1 >= DETECT_TRIES {
                    App::Ignored
                } else {
                    App::Detecting(tries + 1)
                };
                return;
            }
        }
    }
    match &mut f.app {
        App::Http(h) => {
            h.feed(dir, data, gap, ctx, out);
            if missing > 0 {
                h.feed(dir, &[], missing, ctx, out);
            }
        }
        App::Tls(t) => {
            t.feed(dir, data, gap, ctx, out);
            if missing > 0 {
                t.feed(dir, &[], missing, ctx, out);
            }
        }
        App::DnsTcp(dt) => {
            dns_tcp_feed(dt, d, data, gap + missing, ctx, out);
        }
        _ => {}
    }
}

fn dns_tcp_feed(dt: &mut DnsTcp, d: usize, data: &[u8], gap: u64, ctx: Ctx, out: &mut Out) {
    if dt.dead[d] {
        return;
    }
    if gap > 0 && data.is_empty() {
        dt.dead[d] = true;
        return;
    }
    if gap > 0 {
        dt.bufs[d].clear();
    }
    if dt.bufs[d].is_empty() {
        dt.starts[d] = (ctx.frame_no, ctx.ts);
    }
    if dt.bufs[d].len() + data.len() > MAX_DNS_TCP_BUF * 2 {
        dt.dead[d] = true;
        dt.bufs[d] = Vec::new();
        return;
    }
    dt.bufs[d].extend_from_slice(data);
    let mut used = 0usize;
    loop {
        let buf = dt.bufs[d].get(used..).unwrap_or(&[]);
        let (Some(&hi), Some(&lo)) = (buf.first(), buf.get(1)) else {
            break;
        };
        let n = usize::from(u16::from_be_bytes([hi, lo]));
        let Some(msg) = buf.get(2..2 + n) else { break };
        let (frame_no, ts) = dt.starts[d];
        if let Ok(m) = parse_dns(msg) {
            out.dns.push(dns_row(
                &m,
                Ctx {
                    flow_id: ctx.flow_id,
                    frame_no,
                    ts,
                },
            ));
        }
        used += 2 + n;
        dt.starts[d] = (ctx.frame_no, ctx.ts);
    }
    dt.bufs[d].drain(..used);
}

/// Rendered answer text kept per DNS row. A hostile response can render 64
/// answers of ~1 KiB each (`\001` escapes) from a few hundred wire bytes;
/// without a cap, rows outgrow the capture ~50× in memory (security review).
pub const MAX_ROW_ANSWER_BYTES: usize = 4096;

fn capped_answers(m: &crate::dns::DnsMessage) -> Vec<String> {
    let mut used = 0usize;
    let mut out = Vec::new();
    for d in m.answers.iter().filter_map(|a| a.data.as_deref()) {
        if used + d.len() > MAX_ROW_ANSWER_BYTES {
            break;
        }
        used += d.len();
        out.push(d.to_string());
    }
    out
}
