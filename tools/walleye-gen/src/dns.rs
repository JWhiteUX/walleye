//! DNS wire format (RFC 1035) with name compression in responses.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_NULL: u16 = 10;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Txt(Vec<Vec<u8>>),
    Null(Vec<u8>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
    },
}

impl RData {
    pub fn rtype(&self) -> u16 {
        match self {
            RData::A(_) => TYPE_A,
            RData::Aaaa(_) => TYPE_AAAA,
            RData::Cname(_) => TYPE_CNAME,
            RData::Txt(_) => TYPE_TXT,
            RData::Null(_) => TYPE_NULL,
            RData::Soa { .. } => TYPE_SOA,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rr {
    pub name: String,
    pub ttl: u32,
    pub data: RData,
}

/// Builds one DNS message. Names written through `name()` are compressed
/// against every suffix already in the message.
struct Writer {
    buf: Vec<u8>,
    compress: bool,
    seen: HashMap<String, u16>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn name(&mut self, name: &str) {
        let name = name.trim_end_matches('.');
        let labels: Vec<&str> = if name.is_empty() {
            Vec::new()
        } else {
            name.split('.').collect()
        };
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".").to_ascii_lowercase();
            if self.compress {
                if let Some(&off) = self.seen.get(&suffix) {
                    self.u16(0xC000 | off);
                    return;
                }
                if self.buf.len() < 0x3FFF {
                    self.seen.insert(suffix, self.buf.len() as u16);
                }
            }
            let l = labels[i].as_bytes();
            debug_assert!(!l.is_empty() && l.len() <= 63, "bad label {:?}", labels[i]);
            self.buf.push(l.len() as u8);
            self.buf.extend_from_slice(l);
        }
        self.buf.push(0);
    }

    fn rr(&mut self, rr: &Rr) {
        self.name(&rr.name);
        self.u16(rr.data.rtype());
        self.u16(CLASS_IN);
        self.u32(rr.ttl);
        let len_at = self.buf.len();
        self.u16(0);
        match &rr.data {
            RData::A(ip) => self.buf.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => self.buf.extend_from_slice(&ip.octets()),
            RData::Cname(n) => self.name(n),
            RData::Txt(strings) => {
                for s in strings {
                    debug_assert!(s.len() <= 255);
                    self.buf.push(s.len() as u8);
                    self.buf.extend_from_slice(s);
                }
            }
            RData::Null(b) => self.buf.extend_from_slice(b),
            RData::Soa {
                mname,
                rname,
                serial,
            } => {
                self.name(mname);
                self.name(rname);
                self.u32(*serial);
                self.u32(7200); // refresh
                self.u32(900); // retry
                self.u32(1_209_600); // expire
                self.u32(300); // minimum
            }
        }
        let rdlen = (self.buf.len() - len_at - 2) as u16;
        self.buf[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
}

/// A standard recursive query (RD set), with an EDNS0 OPT record when `edns`.
pub fn query(id: u16, qname: &str, qtype: u16, edns: bool) -> Vec<u8> {
    let mut w = Writer {
        buf: Vec::with_capacity(64),
        compress: false,
        seen: HashMap::new(),
    };
    w.u16(id);
    w.u16(0x0100);
    w.u16(1);
    w.u16(0);
    w.u16(0);
    w.u16(u16::from(edns));
    w.name(qname);
    w.u16(qtype);
    w.u16(CLASS_IN);
    if edns {
        opt(&mut w);
    }
    w.buf
}

fn opt(w: &mut Writer) {
    w.buf.push(0); // root name
    w.u16(41); // OPT
    w.u16(1232); // UDP payload size
    w.u32(0); // ext rcode, version, flags
    w.u16(0); // rdlen
}

/// A recursive response (QR, RD, RA) with compression.
pub fn response(
    id: u16,
    qname: &str,
    qtype: u16,
    rcode: u8,
    answers: &[Rr],
    authority: &[Rr],
    edns: bool,
) -> Vec<u8> {
    let mut w = Writer {
        buf: Vec::with_capacity(256),
        compress: true,
        seen: HashMap::new(),
    };
    w.u16(id);
    w.u16(0x8180 | u16::from(rcode & 0x0F));
    w.u16(1);
    w.u16(answers.len() as u16);
    w.u16(authority.len() as u16);
    w.u16(u16::from(edns));
    w.name(qname);
    w.u16(qtype);
    w.u16(CLASS_IN);
    for rr in answers {
        w.rr(rr);
    }
    for rr in authority {
        w.rr(rr);
    }
    if edns {
        opt(&mut w);
    }
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_compresses_repeated_names() {
        let ans = vec![
            Rr {
                name: "www.example.com".into(),
                ttl: 60,
                data: RData::Cname("edge.example.com".into()),
            },
            Rr {
                name: "edge.example.com".into(),
                ttl: 60,
                data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            },
        ];
        let msg = response(1, "www.example.com", TYPE_A, 0, &ans, &[], false);
        // The answer owner name is a pointer to the question name at offset 12.
        let q_end = 12 + "www.example.com".len() + 2 + 4;
        assert_eq!(&msg[q_end..q_end + 2], &[0xC0, 12]);
        // Uncompressed it would be much longer.
        assert!(msg.len() < 12 + 21 + 4 + 2 * (17 + 10) + 18 + 4);
    }
}
