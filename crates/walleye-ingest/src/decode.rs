//! Wireshark-style decode tree for one frame (packet pane). Every node's
//! `range` indexes into the frame bytes; `field` names a filter field from
//! `walleye_core::fields` when one exists. Never panics: truncated or
//! malformed layers become nodes with a `warning`.

use std::net::{Ipv4Addr, Ipv6Addr};

use walleye_core::ipc::{ByteRange, DecodeNode};

use crate::dns::{parse_dns, qtype_name, rcode_name};
use crate::http::{StartLine, looks_like_request, looks_like_response, parse_http};
use crate::packet::*;
use crate::tls;
use crate::util::{ParseError, escape_bytes, sub};

/// Filter field names used in decode trees (all exist in `fields::FIELDS`).
pub const DECODE_FIELDS: &[&str] = &[
    F_SRC_IP,
    F_DST_IP,
    F_SRC_PORT,
    F_DST_PORT,
    F_PROTO,
    F_TCP_FLAGS,
    F_FRAME_LEN,
    F_DNS_QUERY,
    F_DNS_QTYPE,
    F_DNS_RCODE,
    F_DNS_ANSWER,
    F_DNS_TTL,
    F_DNS_IS_RESPONSE,
    F_HTTP_METHOD,
    F_HTTP_URI,
    F_HTTP_HOST,
    F_HTTP_UA,
    F_HTTP_STATUS,
    F_TLS_SNI,
    F_TLS_VERSION,
    F_TLS_JA4,
    F_TLS_JA4S,
    F_TLS_SUBJECT,
    F_TLS_ISSUER,
    F_TLS_SERIAL,
    F_TLS_SELF_SIGNED,
    crate::decode_wifi::F_WIFI_SRC,
    crate::decode_wifi::F_WIFI_DST,
    crate::decode_wifi::F_WIFI_TX,
    crate::decode_wifi::F_WIFI_BSSID,
    crate::decode_wifi::F_WIFI_SSID,
    crate::decode_wifi::F_WIFI_SECURITY,
    crate::decode_wifi::F_WIFI_CHANNEL,
    crate::decode_wifi::F_WIFI_FREQ,
    crate::decode_wifi::F_WIFI_SIGNAL,
    crate::decode_wifi::F_WIFI_REASON,
    crate::decode_wifi::F_WIFI_PROTECTED,
    crate::decode_wifi::F_WIFI_RETRY,
];
const F_SRC_IP: &str = "src_ip";
const F_DST_IP: &str = "dst_ip";
const F_SRC_PORT: &str = "src_port";
const F_DST_PORT: &str = "dst_port";
const F_PROTO: &str = "proto";
const F_TCP_FLAGS: &str = "frame.tcp_flags";
const F_FRAME_LEN: &str = "frame.len";
const F_DNS_QUERY: &str = "dns.query";
const F_DNS_QTYPE: &str = "dns.qtype";
const F_DNS_RCODE: &str = "dns.rcode";
const F_DNS_ANSWER: &str = "dns.answer";
const F_DNS_TTL: &str = "dns.ttl";
const F_DNS_IS_RESPONSE: &str = "dns.is_response";
const F_HTTP_METHOD: &str = "http.method";
const F_HTTP_URI: &str = "http.uri";
const F_HTTP_HOST: &str = "http.host";
const F_HTTP_UA: &str = "http.user_agent";
const F_HTTP_STATUS: &str = "http.status";
const F_TLS_SNI: &str = "tls.sni";
const F_TLS_VERSION: &str = "tls.version";
const F_TLS_JA4: &str = "tls.ja4";
const F_TLS_JA4S: &str = "tls.ja4s";
const F_TLS_SUBJECT: &str = "tls.cert_subject";
const F_TLS_ISSUER: &str = "tls.cert_issuer";
const F_TLS_SERIAL: &str = "tls.cert_serial";
const F_TLS_SELF_SIGNED: &str = "tls.cert_self_signed";

const MAX_TLS_RECORDS: usize = 16;
const MAX_LIST: usize = 64;

pub(crate) fn range(start: usize, len: usize) -> Option<ByteRange> {
    Some(ByteRange {
        start: u32::try_from(start).ok()?,
        len: u32::try_from(len).ok()?,
    })
}

pub(crate) fn tree(label: impl Into<String>, start: usize, len: usize) -> DecodeNode {
    DecodeNode {
        label: label.into(),
        field: None,
        value: None,
        range: range(start, len),
        warning: None,
        children: Vec::new(),
    }
}

pub(crate) fn leaf(
    name: &str,
    field: Option<&str>,
    value: String,
    start: usize,
    len: usize,
) -> DecodeNode {
    DecodeNode {
        label: format!("{name}: {value}"),
        field: field.map(str::to_string),
        value: Some(value),
        range: range(start, len),
        warning: None,
        children: Vec::new(),
    }
}

pub(crate) fn warn(mut n: DecodeNode, w: &str) -> DecodeNode {
    n.warning = Some(w.to_string());
    n
}

fn u8_at(b: &[u8], o: usize) -> Option<u8> {
    b.get(o).copied()
}
fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Decode a frame. `link_type` is the LINKTYPE_* of the frame's interface.
pub fn decode_frame(link_type: u32, bytes: &[u8]) -> Vec<DecodeNode> {
    let mut nodes = vec![leaf(
        "Frame length",
        Some(F_FRAME_LEN),
        format!("{} bytes captured", bytes.len()),
        0,
        bytes.len(),
    )];
    match link_type {
        LINKTYPE_ETHERNET => ethernet(bytes, &mut nodes),
        LINKTYPE_RAW | LINKTYPE_RAW_OLD | LINKTYPE_RAW_OPENBSD | LINKTYPE_IPV4 | LINKTYPE_IPV6 => {
            ip_by_version(bytes, 0, &mut nodes)
        }
        LINKTYPE_NULL | LINKTYPE_LOOP => {
            let Some(fam) = sub(bytes, 0, 4) else {
                nodes.push(warn(tree("Null/Loopback", 0, bytes.len()), "truncated"));
                return nodes;
            };
            let v = if link_type == LINKTYPE_LOOP {
                u32::from_be_bytes([fam[0], fam[1], fam[2], fam[3]])
            } else {
                // Host byte order of the capturing machine: accept either.
                let le = u32::from_le_bytes([fam[0], fam[1], fam[2], fam[3]]);
                if le < 256 {
                    le
                } else {
                    u32::from_be_bytes([fam[0], fam[1], fam[2], fam[3]])
                }
            };
            let mut n = tree("Null/Loopback", 0, 4);
            n.children.push(leaf("Family", None, v.to_string(), 0, 4));
            nodes.push(n);
            ip_by_version(bytes, 4, &mut nodes);
        }
        LINKTYPE_LINUX_SLL => {
            let Some(proto) = u16_at(bytes, 14) else {
                nodes.push(warn(
                    tree("Linux cooked capture", 0, bytes.len()),
                    "truncated",
                ));
                return nodes;
            };
            let mut n = tree("Linux cooked capture v1", 0, 16);
            n.children
                .push(leaf("Protocol", None, format!("0x{proto:04x}"), 14, 2));
            nodes.push(n);
            ethertype(proto, bytes, 16, &mut nodes);
        }
        LINKTYPE_LINUX_SLL2 => {
            let (Some(proto), true) = (u16_at(bytes, 0), bytes.len() >= 20) else {
                nodes.push(warn(
                    tree("Linux cooked capture v2", 0, bytes.len()),
                    "truncated",
                ));
                return nodes;
            };
            let mut n = tree("Linux cooked capture v2", 0, 20);
            n.children
                .push(leaf("Protocol", None, format!("0x{proto:04x}"), 0, 2));
            nodes.push(n);
            ethertype(proto, bytes, 20, &mut nodes);
        }
        walleye_core::LINKTYPE_IEEE802_11 | walleye_core::LINKTYPE_IEEE802_11_RADIOTAP => {
            crate::decode_wifi::decode(link_type, bytes, &mut nodes)
        }
        other => nodes.push(warn(
            tree(format!("Link type {other}"), 0, bytes.len()),
            "link type not decoded",
        )),
    }
    nodes
}

fn ethernet(b: &[u8], nodes: &mut Vec<DecodeNode>) {
    let (Some(dst), Some(src), Some(mut ty)) = (sub(b, 0, 6), sub(b, 6, 6), u16_at(b, 12)) else {
        nodes.push(warn(tree("Ethernet II", 0, b.len()), "truncated"));
        return;
    };
    let mut n = tree("Ethernet II", 0, 14);
    n.children.push(leaf("Destination", None, mac(dst), 0, 6));
    n.children.push(leaf("Source", None, mac(src), 6, 6));
    n.children
        .push(leaf("Type", None, format!("0x{ty:04x}"), 12, 2));
    nodes.push(n);
    let mut off = 14usize;
    for _ in 0..4 {
        if !matches!(ty, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        let (Some(tci), Some(inner)) = (u16_at(b, off), u16_at(b, off + 2)) else {
            nodes.push(warn(
                tree("802.1Q VLAN", off, b.len().saturating_sub(off)),
                "truncated",
            ));
            return;
        };
        let mut v = tree(format!("802.1Q VLAN, ID {}", tci & 0x0fff), off, 4);
        v.children
            .push(leaf("ID", None, (tci & 0x0fff).to_string(), off, 2));
        v.children
            .push(leaf("Type", None, format!("0x{inner:04x}"), off + 2, 2));
        nodes.push(v);
        ty = inner;
        off += 4;
    }
    ethertype(ty, b, off, nodes);
}

pub(crate) fn ethertype(ty: u16, b: &[u8], off: usize, nodes: &mut Vec<DecodeNode>) {
    match ty {
        0x0800 => ipv4(b, off, nodes),
        0x86dd => ipv6(b, off, nodes),
        0x0806 => arp(b, off, nodes),
        _ => {
            if off < b.len() {
                nodes.push(tree(
                    format!("Data ({} bytes)", b.len() - off),
                    off,
                    b.len() - off,
                ));
            }
        }
    }
}

fn ip_by_version(b: &[u8], off: usize, nodes: &mut Vec<DecodeNode>) {
    match u8_at(b, off).map(|v| v >> 4) {
        Some(4) => ipv4(b, off, nodes),
        Some(6) => ipv6(b, off, nodes),
        _ => nodes.push(warn(
            tree("Raw IP", off, b.len().saturating_sub(off)),
            "not an IPv4/IPv6 packet",
        )),
    }
}

fn arp(b: &[u8], off: usize, nodes: &mut Vec<DecodeNode>) {
    let Some(opcode) = u16_at(b, off + 6) else {
        nodes.push(warn(
            tree(
                "Address Resolution Protocol",
                off,
                b.len().saturating_sub(off),
            ),
            "truncated",
        ));
        return;
    };
    let mut n = tree(
        "Address Resolution Protocol",
        off,
        b.len().saturating_sub(off).min(28),
    );
    let op = match opcode {
        1 => "request".to_string(),
        2 => "reply".to_string(),
        o => o.to_string(),
    };
    n.children.push(leaf("Opcode", None, op, off + 6, 2));
    if let (Some(sha), Some(spa), Some(tpa)) =
        (sub(b, off + 8, 6), sub(b, off + 14, 4), sub(b, off + 24, 4))
    {
        n.children
            .push(leaf("Sender MAC", None, mac(sha), off + 8, 6));
        n.children.push(leaf(
            "Sender IP",
            None,
            Ipv4Addr::new(spa[0], spa[1], spa[2], spa[3]).to_string(),
            off + 14,
            4,
        ));
        n.children.push(leaf(
            "Target IP",
            None,
            Ipv4Addr::new(tpa[0], tpa[1], tpa[2], tpa[3]).to_string(),
            off + 24,
            4,
        ));
    } else {
        n.warning = Some("truncated".into());
    }
    nodes.push(n);
}

fn ipv4(b: &[u8], off: usize, nodes: &mut Vec<DecodeNode>) {
    let Some(h) = sub(b, off, 20) else {
        nodes.push(warn(
            tree(
                "Internet Protocol Version 4",
                off,
                b.len().saturating_sub(off),
            ),
            "truncated header",
        ));
        return;
    };
    let ihl = usize::from(h[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([h[2], h[3]]));
    let frag = u16::from_be_bytes([h[6], h[7]]);
    let proto = h[9];
    let src = Ipv4Addr::new(h[12], h[13], h[14], h[15]);
    let dst = Ipv4Addr::new(h[16], h[17], h[18], h[19]);
    let mut n = tree(
        format!("Internet Protocol Version 4, Src: {src}, Dst: {dst}"),
        off,
        ihl.max(20).min(b.len() - off),
    );
    let c = &mut n.children;
    c.push(leaf("Header length", None, format!("{ihl} bytes"), off, 1));
    c.push(leaf("Total length", None, total.to_string(), off + 2, 2));
    c.push(leaf(
        "Identification",
        None,
        format!("0x{:04x}", u16::from_be_bytes([h[4], h[5]])),
        off + 4,
        2,
    ));
    let mf = frag & 0x2000 != 0;
    let frag_off = usize::from(frag & 0x1fff) * 8;
    c.push(leaf(
        "Flags",
        None,
        format!(
            "{}{}",
            if frag & 0x4000 != 0 { "DF " } else { "" },
            if mf { "MF" } else { "" }
        )
        .trim()
        .to_string(),
        off + 6,
        1,
    ));
    c.push(leaf(
        "Fragment offset",
        None,
        frag_off.to_string(),
        off + 6,
        2,
    ));
    c.push(leaf("Time to live", None, h[8].to_string(), off + 8, 1));
    c.push(leaf(
        "Protocol",
        Some(F_PROTO),
        proto_name(proto),
        off + 9,
        1,
    ));
    c.push(leaf(
        "Header checksum",
        None,
        format!("0x{:04x}", u16::from_be_bytes([h[10], h[11]])),
        off + 10,
        2,
    ));
    c.push(leaf("Source", Some(F_SRC_IP), src.to_string(), off + 12, 4));
    c.push(leaf(
        "Destination",
        Some(F_DST_IP),
        dst.to_string(),
        off + 16,
        4,
    ));
    if ihl < 20 {
        nodes.push(warn(n, "header length below 20"));
        return;
    }
    if off + ihl > b.len() {
        // Every range must stay inside the frame (fuzz: ingest_decode_frame).
        nodes.push(warn(n, "header length past end of frame"));
        return;
    }
    if ihl > 20 {
        n.children.push(tree(
            format!("Options ({} bytes)", ihl - 20),
            off + 20,
            ihl - 20,
        ));
    }
    let start = off + ihl;
    let mut end = if total >= ihl {
        off.saturating_add(total)
    } else {
        b.len()
    };
    if total == 0 {
        end = b.len(); // TSO captures report 0
    }
    if end > b.len() {
        n.warning = Some(format!(
            "truncated: {} of {} bytes captured",
            b.len() - off,
            total
        ));
        end = b.len();
    }
    nodes.push(n);
    if start > end {
        return;
    }
    if frag_off > 0 {
        nodes.push(tree(
            format!("Fragment data ({} bytes)", end - start),
            start,
            end - start,
        ));
        return;
    }
    transport(proto, b, start, end, mf, nodes);
}

fn ipv6(b: &[u8], off: usize, nodes: &mut Vec<DecodeNode>) {
    let Some(h) = sub(b, off, 40) else {
        nodes.push(warn(
            tree(
                "Internet Protocol Version 6",
                off,
                b.len().saturating_sub(off),
            ),
            "truncated header",
        ));
        return;
    };
    let plen = usize::from(u16::from_be_bytes([h[4], h[5]]));
    let mut next = h[6];
    let mut a = [0u8; 16];
    a.copy_from_slice(&h[8..24]);
    let src = Ipv6Addr::from(a);
    a.copy_from_slice(&h[24..40]);
    let dst = Ipv6Addr::from(a);
    let mut n = tree(
        format!("Internet Protocol Version 6, Src: {src}, Dst: {dst}"),
        off,
        40,
    );
    n.children
        .push(leaf("Payload length", None, plen.to_string(), off + 4, 2));
    n.children.push(leaf(
        "Next header",
        Some(F_PROTO),
        proto_name(next),
        off + 6,
        1,
    ));
    n.children
        .push(leaf("Hop limit", None, h[7].to_string(), off + 7, 1));
    n.children
        .push(leaf("Source", Some(F_SRC_IP), src.to_string(), off + 8, 16));
    n.children.push(leaf(
        "Destination",
        Some(F_DST_IP),
        dst.to_string(),
        off + 24,
        16,
    ));
    let mut end = if plen == 0 { b.len() } else { off + 40 + plen };
    if end > b.len() {
        n.warning = Some("truncated payload".into());
        end = b.len();
    }
    let mut pos = off + 40;
    let mut fragmented = false;
    for _ in 0..8 {
        let len = match next {
            0 | 43 | 60 => u8_at(b, pos + 1).map(|l| (usize::from(l) + 1) * 8),
            44 => {
                let fo = u16_at(b, pos + 2).unwrap_or(0);
                fragmented = fo & 0xfff8 != 0 || fo & 1 != 0;
                Some(8)
            }
            51 => u8_at(b, pos + 1).map(|l| (usize::from(l) + 2) * 4),
            _ => break,
        };
        let (Some(len), Some(nh)) = (len, u8_at(b, pos)) else {
            n.warning = Some("truncated extension header".into());
            nodes.push(n);
            return;
        };
        n.children.push(tree(
            format!("Extension header {} ({len} bytes)", next),
            pos,
            len.min(b.len().saturating_sub(pos)),
        ));
        next = nh;
        pos = pos.saturating_add(len);
    }
    nodes.push(n);
    if pos > end {
        return;
    }
    if fragmented {
        nodes.push(tree(
            format!("Fragment data ({} bytes)", end - pos),
            pos,
            end - pos,
        ));
        return;
    }
    transport(next, b, pos, end, false, nodes);
}

fn proto_name(p: u8) -> String {
    match p {
        PROTO_ICMP => "ICMP (1)".into(),
        PROTO_TCP => "TCP (6)".into(),
        PROTO_UDP => "UDP (17)".into(),
        PROTO_ICMPV6 => "ICMPv6 (58)".into(),
        _ => p.to_string(),
    }
}

fn tcp_flags_text(f: u8) -> String {
    let names = [
        (0x80, "CWR"),
        (0x40, "ECE"),
        (0x20, "URG"),
        (0x10, "ACK"),
        (0x08, "PSH"),
        (0x04, "RST"),
        (0x02, "SYN"),
        (0x01, "FIN"),
    ];
    let set: Vec<&str> = names
        .iter()
        .rev()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| *n)
        .collect();
    format!("0x{f:02x} [{}]", set.join(", "))
}

fn transport(
    proto: u8,
    b: &[u8],
    start: usize,
    end: usize,
    more_frags: bool,
    nodes: &mut Vec<DecodeNode>,
) {
    let seg = b.get(start..end).unwrap_or(&[]);
    match proto {
        PROTO_TCP => {
            let Some(h) = sub(b, start, 20).filter(|_| seg.len() >= 20) else {
                nodes.push(warn(
                    tree("Transmission Control Protocol", start, seg.len()),
                    "truncated header",
                ));
                return;
            };
            let sport = u16::from_be_bytes([h[0], h[1]]);
            let dport = u16::from_be_bytes([h[2], h[3]]);
            let hl = usize::from(h[12] >> 4) * 4;
            let flags = h[13];
            let plen = seg.len().saturating_sub(hl);
            let mut n = tree(
                format!(
                    "Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Len: {plen}"
                ),
                start,
                hl.clamp(20, seg.len()),
            );
            let c = &mut n.children;
            c.push(leaf(
                "Source port",
                Some(F_SRC_PORT),
                sport.to_string(),
                start,
                2,
            ));
            c.push(leaf(
                "Destination port",
                Some(F_DST_PORT),
                dport.to_string(),
                start + 2,
                2,
            ));
            c.push(leaf(
                "Sequence number",
                None,
                u32_at(h, 4).unwrap_or(0).to_string(),
                start + 4,
                4,
            ));
            c.push(leaf(
                "Acknowledgment number",
                None,
                u32_at(h, 8).unwrap_or(0).to_string(),
                start + 8,
                4,
            ));
            c.push(leaf(
                "Header length",
                None,
                format!("{hl} bytes"),
                start + 12,
                1,
            ));
            c.push(leaf(
                "Flags",
                Some(F_TCP_FLAGS),
                tcp_flags_text(flags),
                start + 13,
                1,
            ));
            c.push(leaf(
                "Window",
                None,
                u16::from_be_bytes([h[14], h[15]]).to_string(),
                start + 14,
                2,
            ));
            c.push(leaf(
                "Checksum",
                None,
                format!("0x{:04x}", u16::from_be_bytes([h[16], h[17]])),
                start + 16,
                2,
            ));
            if hl < 20 || hl > seg.len() {
                nodes.push(warn(n, "bad header length"));
                return;
            }
            if hl > 20 {
                n.children.push(tree(
                    format!("Options ({} bytes)", hl - 20),
                    start + 20,
                    hl - 20,
                ));
            }
            nodes.push(n);
            let ps = start + hl;
            if ps < end {
                nodes.push(tree(
                    format!("TCP payload ({} bytes)", end - ps),
                    ps,
                    end - ps,
                ));
                app(b, ps, end, sport, dport, true, nodes);
            }
        }
        PROTO_UDP => {
            let Some(h) = sub(b, start, 8).filter(|_| seg.len() >= 8) else {
                nodes.push(warn(
                    tree("User Datagram Protocol", start, seg.len()),
                    "truncated header",
                ));
                return;
            };
            let sport = u16::from_be_bytes([h[0], h[1]]);
            let dport = u16::from_be_bytes([h[2], h[3]]);
            let ulen = usize::from(u16::from_be_bytes([h[4], h[5]]));
            let mut n = tree(
                format!("User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}"),
                start,
                8,
            );
            n.children.push(leaf(
                "Source port",
                Some(F_SRC_PORT),
                sport.to_string(),
                start,
                2,
            ));
            n.children.push(leaf(
                "Destination port",
                Some(F_DST_PORT),
                dport.to_string(),
                start + 2,
                2,
            ));
            n.children
                .push(leaf("Length", None, ulen.to_string(), start + 4, 2));
            n.children.push(leaf(
                "Checksum",
                None,
                format!("0x{:04x}", u16::from_be_bytes([h[6], h[7]])),
                start + 6,
                2,
            ));
            let mut pend = end;
            if ulen >= 8 && start + ulen < end {
                pend = start + ulen;
            } else if ulen >= 8 && start + ulen > end && !more_frags {
                n.warning = Some("truncated datagram".into());
            }
            nodes.push(n);
            let ps = start + 8;
            if ps < pend && !more_frags {
                app(b, ps, pend, sport, dport, false, nodes);
            }
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let name = if proto == PROTO_ICMP {
                "Internet Control Message Protocol"
            } else {
                "Internet Control Message Protocol v6"
            };
            let (Some(t), Some(code)) = (u8_at(seg, 0), u8_at(seg, 1)) else {
                nodes.push(warn(tree(name, start, seg.len()), "truncated"));
                return;
            };
            let mut n = tree(name, start, seg.len());
            n.children.push(leaf("Type", None, t.to_string(), start, 1));
            n.children
                .push(leaf("Code", None, code.to_string(), start + 1, 1));
            nodes.push(n);
        }
        p => {
            if !seg.is_empty() {
                nodes.push(tree(
                    format!("IP protocol {p} payload ({} bytes)", seg.len()),
                    start,
                    seg.len(),
                ));
            }
        }
    }
}

fn app(
    b: &[u8],
    start: usize,
    end: usize,
    sport: u16,
    dport: u16,
    tcp: bool,
    nodes: &mut Vec<DecodeNode>,
) {
    let data = b.get(start..end).unwrap_or(&[]);
    if sport == 53 || dport == 53 {
        if tcp {
            let Some(len) = u16_at(data, 0) else { return };
            let msg = data.get(2..).unwrap_or(&[]);
            let mut n = dns_node(msg, start + 2);
            n.children
                .insert(0, leaf("Length", None, len.to_string(), start, 2));
            if msg.len() < usize::from(len) {
                n.warning = Some("message continues in a later segment".into());
            }
            nodes.push(n);
        } else {
            nodes.push(dns_node(data, start));
        }
    } else if tcp && (looks_like_request(data) || looks_like_response(data)) {
        nodes.push(http_node(data, start));
    } else if tcp && matches!(data, [20..=23, 3, ..]) {
        nodes.push(tls_node(data, start));
    }
}

fn dns_node(msg: &[u8], base: usize) -> DecodeNode {
    let mut n = tree("Domain Name System", base, msg.len());
    let m = match parse_dns(msg) {
        Ok(m) => m,
        Err(e) => return warn(n, &e.to_string()),
    };
    let c = &mut n.children;
    c.push(leaf(
        "Transaction ID",
        None,
        format!("0x{:04x}", m.id),
        base,
        2,
    ));
    c.push(leaf(
        "Response",
        Some(F_DNS_IS_RESPONSE),
        m.is_response.to_string(),
        base + 2,
        2,
    ));
    if m.is_response {
        c.push(leaf(
            "Reply code",
            Some(F_DNS_RCODE),
            rcode_name(m.rcode),
            base + 3,
            1,
        ));
    }
    c.push(leaf("Questions", None, m.qdcount.to_string(), base + 4, 2));
    c.push(leaf("Answer RRs", None, m.ancount.to_string(), base + 6, 2));
    for q in &m.questions {
        let mut qn = tree(
            format!("Query: {} {}", q.name, qtype_name(q.qtype)),
            base + q.span.0,
            q.span.1,
        );
        qn.children.push(leaf(
            "Name",
            Some(F_DNS_QUERY),
            q.name.clone(),
            base + q.span.0,
            q.span.1.saturating_sub(4),
        ));
        qn.children.push(leaf(
            "Type",
            Some(F_DNS_QTYPE),
            qtype_name(q.qtype),
            base + q.span.0 + q.span.1.saturating_sub(4),
            2,
        ));
        n.children.push(qn);
    }
    for a in &m.answers {
        let data = a.data.clone().unwrap_or_else(|| "(not decoded)".into());
        let mut an = tree(
            format!("Answer: {} {} {}", a.name, qtype_name(a.rtype), data),
            base + a.span.0,
            a.span.1,
        );
        an.children
            .push(leaf("Name", None, a.name.clone(), base + a.span.0, 0));
        an.children.push(leaf(
            "TTL",
            Some(F_DNS_TTL),
            a.ttl.to_string(),
            base + a.span.0,
            0,
        ));
        if a.data.is_some() {
            an.children.push(leaf(
                "Data",
                Some(F_DNS_ANSWER),
                data,
                base + a.span.0,
                a.span.1,
            ));
        }
        n.children.push(an);
    }
    if m.truncated {
        n.warning = Some("message truncated or malformed".into());
    }
    n
}

fn http_node(data: &[u8], base: usize) -> DecodeNode {
    let mut n = tree("Hypertext Transfer Protocol", base, data.len());
    let (head, partial) = match parse_http(data) {
        Ok(h) => (h, false),
        Err(ParseError::Truncated) => {
            // Head continues in a later segment: decode the lines present.
            let cut = data.iter().rposition(|&c| c == b'\n').map_or(0, |p| p + 1);
            let mut tmp = data.get(..cut).unwrap_or(&[]).to_vec();
            tmp.extend_from_slice(b"\r\n");
            match parse_http(&tmp) {
                Ok(h) => (h, true),
                Err(e) => return warn(n, &e.to_string()),
            }
        }
        Err(e) => return warn(n, &e.to_string()),
    };
    let first = head.line_spans.first().copied().unwrap_or((0, 0));
    match &head.start {
        StartLine::Request {
            method,
            uri,
            version,
        } => {
            let mut l = tree(format!("{method} {uri} {version}"), base + first.0, first.1);
            // Byte ranges come from the raw line: `method`/`uri` are escaped
            // for display, so their string lengths can exceed the wire bytes
            // (fuzz: ingest_decode_frame).
            let line = data.get(first.0..first.0 + first.1).unwrap_or(&[]);
            let m_len = line.iter().position(|&c| c == b' ').unwrap_or(line.len());
            let rest = line.get(m_len + 1..).unwrap_or(&[]);
            let u_len = rest
                .iter()
                .position(|&c| c == b' ' || c == b'\r' || c == b'\n')
                .unwrap_or(rest.len());
            l.children.push(leaf(
                "Method",
                Some(F_HTTP_METHOD),
                method.clone(),
                base + first.0,
                m_len,
            ));
            l.children.push(leaf(
                "URI",
                Some(F_HTTP_URI),
                uri.clone(),
                base + first.0 + (m_len + 1).min(line.len()),
                u_len,
            ));
            n.children.push(l);
        }
        StartLine::Response {
            version,
            status,
            reason,
        } => {
            let mut l = tree(
                format!("{version} {status} {reason}"),
                base + first.0,
                first.1,
            );
            let line = data.get(first.0..first.0 + first.1).unwrap_or(&[]);
            let v_len = line.iter().position(|&c| c == b' ').unwrap_or(line.len());
            let s_start = (v_len + 1).min(line.len());
            l.children.push(leaf(
                "Status code",
                Some(F_HTTP_STATUS),
                status.to_string(),
                base + first.0 + s_start,
                3.min(line.len() - s_start),
            ));
            n.children.push(l);
        }
    }
    for ((name, value), span) in head.headers.iter().zip(head.line_spans.iter().skip(1)) {
        let field = match name.to_ascii_lowercase().as_str() {
            "host" => Some(F_HTTP_HOST),
            "user-agent" => Some(F_HTTP_UA),
            _ => None,
        };
        let mut h = leaf(name, field, value.clone(), base + span.0, span.1);
        h.label = format!("{name}: {value}");
        n.children.push(h);
    }
    if partial {
        n.warning = Some("header continues in a later segment".into());
    } else if head.head_len < data.len() {
        let bl = data.len() - head.head_len;
        n.children.push(tree(
            format!("Body ({bl} bytes in this segment)"),
            base + head.head_len,
            bl,
        ));
    }
    n
}

fn tls_node(data: &[u8], base: usize) -> DecodeNode {
    let mut n = tree("Transport Layer Security", base, data.len());
    let mut pos = 0usize;
    for _ in 0..MAX_TLS_RECORDS {
        let (Some(ct), Some(ver), Some(len)) = (
            u8_at(data, pos),
            u16_at(data, pos + 1),
            u16_at(data, pos + 3),
        ) else {
            break;
        };
        let len = usize::from(len);
        let kind = match ct {
            tls::CT_CCS => "Change Cipher Spec",
            tls::CT_ALERT => "Alert",
            tls::CT_HANDSHAKE => "Handshake",
            tls::CT_APPDATA => "Application Data",
            _ => "Unknown",
        };
        let avail = data.len().saturating_sub(pos + 5);
        let mut r = tree(
            format!("TLS Record: {kind}"),
            base + pos,
            (len + 5).min(data.len() - pos),
        );
        r.children
            .push(leaf("Content type", None, ct.to_string(), base + pos, 1));
        r.children.push(leaf(
            "Record version",
            None,
            tls::version_name(ver),
            base + pos + 1,
            2,
        ));
        r.children
            .push(leaf("Length", None, len.to_string(), base + pos + 3, 2));
        if avail < len {
            r.warning = Some("record continues in a later segment".into());
        }
        if ct == tls::CT_HANDSHAKE {
            let frag = data.get(pos + 5..pos + 5 + len.min(avail)).unwrap_or(&[]);
            handshake_nodes(frag, base + pos + 5, avail < len, &mut r);
        }
        n.children.push(r);
        if avail < len || !matches!(ct, 20..=23) {
            break;
        }
        pos += 5 + len;
    }
    n
}

fn handshake_nodes(frag: &[u8], base: usize, partial: bool, r: &mut DecodeNode) {
    let (Some(ty), Some(hlen)) = (
        u8_at(frag, 0),
        u32_at(frag, 0).map(|v| (v & 0x00ff_ffff) as usize),
    ) else {
        return;
    };
    let body = frag
        .get(4..4 + hlen.min(frag.len().saturating_sub(4)))
        .unwrap_or(&[]);
    let complete = body.len() == hlen;
    let name = match ty {
        1 => "Client Hello",
        2 => "Server Hello",
        11 => "Certificate",
        12 => "Server Key Exchange",
        14 => "Server Hello Done",
        16 => "Client Key Exchange",
        _ => "Handshake message",
    };
    let mut h = tree(format!("Handshake: {name}"), base, frag.len().min(hlen + 4));
    h.children
        .push(leaf("Handshake type", None, ty.to_string(), base, 1));
    h.children
        .push(leaf("Length", None, hlen.to_string(), base + 1, 3));
    let whole = (base, frag.len().min(hlen + 4));
    if !complete {
        h.warning = Some(
            if partial {
                "message continues in a later segment"
            } else {
                "truncated"
            }
            .into(),
        );
    } else {
        match ty {
            1 => match tls::client_hello_body(body) {
                Ok(ch) => {
                    h.children.push(leaf(
                        "Version (offered)",
                        Some(F_TLS_VERSION),
                        tls::version_name(ch.max_version()),
                        base + 4,
                        2,
                    ));
                    h.children.push(leaf(
                        "Cipher suites",
                        None,
                        ch.ciphers.len().to_string(),
                        whole.0,
                        whole.1,
                    ));
                    if let Some(s) = &ch.sni {
                        h.children.push(leaf(
                            "Server name",
                            Some(F_TLS_SNI),
                            s.clone(),
                            whole.0,
                            whole.1,
                        ));
                    }
                    if !ch.alpn.is_empty() {
                        let a: Vec<String> = ch
                            .alpn
                            .iter()
                            .take(MAX_LIST)
                            .map(|p| escape_bytes(p, 64))
                            .collect();
                        h.children
                            .push(leaf("ALPN", None, a.join(","), whole.0, whole.1));
                    }
                    h.children.push(leaf(
                        "JA4",
                        Some(F_TLS_JA4),
                        tls::ja4(&ch, 't'),
                        whole.0,
                        whole.1,
                    ));
                }
                Err(e) => h.warning = Some(e.to_string()),
            },
            2 => match tls::server_hello_body(body) {
                Ok(sh) => {
                    h.children.push(leaf(
                        "Version (negotiated)",
                        Some(F_TLS_VERSION),
                        tls::version_name(sh.version()),
                        base + 4,
                        2,
                    ));
                    h.children.push(leaf(
                        "Cipher suite",
                        None,
                        format!("0x{:04x}", sh.cipher),
                        whole.0,
                        whole.1,
                    ));
                    h.children.push(leaf(
                        "JA4S",
                        Some(F_TLS_JA4S),
                        tls::ja4s(&sh, 't'),
                        whole.0,
                        whole.1,
                    ));
                }
                Err(e) => h.warning = Some(e.to_string()),
            },
            11 => match tls::leaf_certificate(body).and_then(crate::x509::parse_certificate) {
                Ok(c) => {
                    h.children.push(leaf(
                        "Subject",
                        Some(F_TLS_SUBJECT),
                        c.subject,
                        whole.0,
                        whole.1,
                    ));
                    h.children.push(leaf(
                        "Issuer",
                        Some(F_TLS_ISSUER),
                        c.issuer,
                        whole.0,
                        whole.1,
                    ));
                    h.children.push(leaf(
                        "Serial",
                        Some(F_TLS_SERIAL),
                        c.serial,
                        whole.0,
                        whole.1,
                    ));
                    h.children.push(leaf(
                        "Self-signed",
                        Some(F_TLS_SELF_SIGNED),
                        c.self_signed.to_string(),
                        whole.0,
                        whole.1,
                    ));
                }
                Err(e) => h.warning = Some(e.to_string()),
            },
            _ => {}
        }
    }
    r.children.push(h);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_fields_exist_in_registry() {
        for f in DECODE_FIELDS {
            assert!(walleye_core::fields::field(f).is_some(), "{f}");
        }
    }

    #[test]
    fn empty_and_unknown() {
        assert_eq!(decode_frame(1, &[]).len(), 2);
        assert!(decode_frame(9999, &[1, 2, 3])[1].warning.is_some());
    }
}
