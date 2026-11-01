//! Ethernet / IPv4 / IPv6 / TCP / UDP frame builders with correct lengths
//! and checksums.

use std::net::IpAddr;

pub type Mac = [u8; 6];

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_IPV6: u16 = 0x86DD;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Layer 2/3 addressing of one direction of a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    pub src_mac: Mac,
    pub dst_mac: Mac,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
}

impl Hop {
    pub fn reverse(&self, ttl: u8) -> Hop {
        Hop {
            src_mac: self.dst_mac,
            dst_mac: self.src_mac,
            src: self.dst,
            dst: self.src,
            ttl,
        }
    }
}

/// Ones'-complement sum accumulator (RFC 1071).
fn sum16(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(0, data))
}

fn pseudo_sum(src: &IpAddr, dst: &IpAddr, proto: u8, len: usize) -> u32 {
    let mut acc = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum16(acc, &s.octets());
            acc = sum16(acc, &d.octets());
            acc += u32::from(proto);
            acc += len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum16(acc, &s.octets());
            acc = sum16(acc, &d.octets());
            acc = sum16(acc, &(len as u32).to_be_bytes());
            acc += u32::from(proto);
        }
        _ => {}
    }
    acc
}

/// Writes Ethernet + IP header for an L4 segment of `l4_len` bytes and
/// returns the offset of the L4 header within `buf`.
fn l2l3(buf: &mut Vec<u8>, hop: &Hop, proto: u8, l4_len: usize, ip_id: u16, df: bool) -> usize {
    buf.clear();
    buf.extend_from_slice(&hop.dst_mac);
    buf.extend_from_slice(&hop.src_mac);
    match (hop.src, hop.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            buf.extend_from_slice(&ETH_IPV4.to_be_bytes());
            let start = buf.len();
            let total = (20 + l4_len) as u16;
            buf.push(0x45);
            buf.push(0x00);
            buf.extend_from_slice(&total.to_be_bytes());
            buf.extend_from_slice(&ip_id.to_be_bytes());
            buf.extend_from_slice(if df { &[0x40, 0x00] } else { &[0x00, 0x00] });
            buf.push(hop.ttl);
            buf.push(proto);
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            let c = checksum(&buf[start..start + 20]);
            buf[start + 10..start + 12].copy_from_slice(&c.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            buf.extend_from_slice(&ETH_IPV6.to_be_bytes());
            buf.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
            buf.extend_from_slice(&(l4_len as u16).to_be_bytes());
            buf.push(proto);
            buf.push(hop.ttl);
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
        }
        _ => panic!("mixed IPv4/IPv6 hop"),
    }
    buf.len()
}

#[derive(Debug, Clone, Copy)]
pub struct TcpHdr<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: &'a [u8],
}

/// Build a full Ethernet/IP/TCP frame into `buf` (cleared first).
pub fn tcp_frame(buf: &mut Vec<u8>, hop: &Hop, ip_id: u16, h: &TcpHdr<'_>, payload: &[u8]) {
    debug_assert!(h.options.len() % 4 == 0);
    let hlen = 20 + h.options.len();
    let l4_len = hlen + payload.len();
    let off = l2l3(buf, hop, PROTO_TCP, l4_len, ip_id, true);
    buf.extend_from_slice(&h.sport.to_be_bytes());
    buf.extend_from_slice(&h.dport.to_be_bytes());
    buf.extend_from_slice(&h.seq.to_be_bytes());
    buf.extend_from_slice(&h.ack.to_be_bytes());
    buf.push(((hlen / 4) as u8) << 4);
    buf.push(h.flags);
    buf.extend_from_slice(&h.window.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    buf.extend_from_slice(h.options);
    buf.extend_from_slice(payload);
    let acc = sum16(
        pseudo_sum(&hop.src, &hop.dst, PROTO_TCP, l4_len),
        &buf[off..],
    );
    let c = fold(acc);
    buf[off + 16..off + 18].copy_from_slice(&c.to_be_bytes());
}

/// Build a full Ethernet/IP/UDP frame into `buf` (cleared first).
pub fn udp_frame(buf: &mut Vec<u8>, hop: &Hop, ip_id: u16, sport: u16, dport: u16, payload: &[u8]) {
    let l4_len = 8 + payload.len();
    let off = l2l3(buf, hop, PROTO_UDP, l4_len, ip_id, false);
    buf.extend_from_slice(&sport.to_be_bytes());
    buf.extend_from_slice(&dport.to_be_bytes());
    buf.extend_from_slice(&(l4_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(payload);
    let acc = sum16(
        pseudo_sum(&hop.src, &hop.dst, PROTO_UDP, l4_len),
        &buf[off..],
    );
    let mut c = fold(acc);
    if c == 0 {
        c = 0xFFFF;
    }
    buf[off + 6..off + 8].copy_from_slice(&c.to_be_bytes());
}

/// SYN options: MSS 1460, NOP, WS 8, NOP, NOP, SACK permitted.
pub const SYN_OPTS: [u8; 12] = [2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2];
/// SYN-ACK options: MSS 1460, NOP, NOP, SACK permitted, NOP, WS 7.
pub const SYNACK_OPTS: [u8; 12] = [2, 4, 0x05, 0xB4, 1, 1, 4, 2, 1, 3, 3, 7];

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rfc1071_example() {
        // RFC 1071 section 3 example data sums to 0xddf2 before complement.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2);
    }

    #[test]
    fn ipv4_header_checksum_verifies() {
        let hop = Hop {
            src_mac: [2, 0, 0, 0, 0, 1],
            dst_mac: [2, 0, 0, 0, 0, 2],
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            dst: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ttl: 64,
        };
        let mut buf = Vec::new();
        udp_frame(&mut buf, &hop, 7, 5353, 53, b"hello");
        assert_eq!(checksum(&buf[14..34]), 0);
        assert_eq!(buf.len(), 14 + 20 + 8 + 5);
    }
}
