//! L2–L4 extraction for the ingest hot path, using `etherparse`'s lax slicer
//! (tolerates frames cut short by the snap length).

use std::net::IpAddr;

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, TransportSlice};

pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW_OLD: u32 = 12;
pub const LINKTYPE_RAW_OPENBSD: u32 = 14;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LOOP: u32 = 108;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// TCP flag bits.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    pub seq: u32,
    pub flags: u8,
}

/// The parts of a packet that flow assembly needs.
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub tcp: Option<TcpInfo>,
    /// Captured transport payload (may be shorter than `payload_len`).
    pub payload: &'a [u8],
    /// Transport payload length on the wire, from the IP/UDP length fields.
    pub payload_len: u32,
}

/// Strip the link layer and slice from the network layer down.
pub fn slice_link(link_type: u32, data: &[u8]) -> Option<LaxSlicedPacket<'_>> {
    match link_type {
        LINKTYPE_ETHERNET => LaxSlicedPacket::from_ethernet(data).ok(),
        LINKTYPE_RAW | LINKTYPE_RAW_OLD | LINKTYPE_RAW_OPENBSD | LINKTYPE_IPV4 | LINKTYPE_IPV6 => {
            LaxSlicedPacket::from_ip(data).ok()
        }
        LINKTYPE_NULL | LINKTYPE_LOOP => LaxSlicedPacket::from_ip(data.get(4..)?).ok(),
        LINKTYPE_LINUX_SLL => {
            let proto = u16::from_be_bytes([*data.get(14)?, *data.get(15)?]);
            Some(LaxSlicedPacket::from_ether_type(
                EtherType(proto),
                data.get(16..)?,
            ))
        }
        LINKTYPE_LINUX_SLL2 => {
            let proto = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            Some(LaxSlicedPacket::from_ether_type(
                EtherType(proto),
                data.get(20..)?,
            ))
        }
        _ => None,
    }
}

/// Largest transport payload passed to stream parsers from one frame. Real
/// segments (including TSO/GRO captures with IPv4 `total_len = 0`) stay well
/// under it; a hostile record that claims 64 MiB of payload does not.
pub const MAX_SEGMENT: usize = 256 * 1024;

fn clamp_segment(p: &[u8]) -> &[u8] {
    p.get(..p.len().min(MAX_SEGMENT)).unwrap_or(p)
}

/// Extract addresses, ports and payload. `None` for non-IP frames, IP
/// fragments and frames too short to carry their transport header.
pub fn parse_packet(link_type: u32, data: &[u8]) -> Option<PacketInfo<'_>> {
    let pkt = slice_link(link_type, data)?;
    let (src, dst, ip_payload) = match pkt.net.as_ref()? {
        LaxNetSlice::Ipv4(v4) => {
            let h = v4.header();
            let p = v4.payload();
            let declared = if p.incomplete {
                usize::from(h.total_len()).saturating_sub(usize::from(h.ihl()) * 4)
            } else {
                p.payload.len()
            };
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                (p, declared),
            )
        }
        LaxNetSlice::Ipv6(v6) => {
            let h = v6.header();
            let p = v6.payload();
            let declared = if p.incomplete {
                usize::from(h.payload_length()).saturating_sub(v6.extensions().slice().len())
            } else {
                p.payload.len()
            };
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                (p, declared),
            )
        }
        LaxNetSlice::Arp(_) => return None,
    };
    let (ipp, declared) = ip_payload;
    if ipp.fragmented {
        return None;
    }
    let proto = ipp.ip_number.0;
    let to_u32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    match pkt.transport.as_ref() {
        Some(TransportSlice::Tcp(tcp)) => {
            let hl = tcp.header_slice().len();
            let flags = tcp.header_slice().get(13).copied().unwrap_or(0);
            Some(PacketInfo {
                src,
                dst,
                proto: PROTO_TCP,
                sport: tcp.source_port(),
                dport: tcp.destination_port(),
                tcp: Some(TcpInfo {
                    seq: tcp.sequence_number(),
                    flags,
                }),
                payload: clamp_segment(tcp.payload()),
                payload_len: to_u32(declared.saturating_sub(hl)),
            })
        }
        Some(TransportSlice::Udp(udp)) => Some(PacketInfo {
            src,
            dst,
            proto: PROTO_UDP,
            sport: udp.source_port(),
            dport: udp.destination_port(),
            tcp: None,
            payload: clamp_segment(udp.payload()),
            payload_len: to_u32(declared.saturating_sub(8)),
        }),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) | None => {
            // TCP/UDP whose header did not fit: not a usable flow packet.
            if proto == PROTO_TCP || proto == PROTO_UDP {
                return None;
            }
            Some(PacketInfo {
                src,
                dst,
                proto,
                sport: 0,
                dport: 0,
                tcp: None,
                payload: ipp.payload,
                payload_len: to_u32(declared),
            })
        }
    }
}
