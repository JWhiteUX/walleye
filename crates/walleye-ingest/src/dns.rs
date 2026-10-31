//! Hand-written DNS message parser (RFC 1035), hostile-input safe.
//!
//! Name decompression only follows pointers that point strictly backwards
//! (so loops are impossible), at most `MAX_JUMPS` times, and stops at 255
//! encoded bytes. Questions and answers are capped.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::util::{Cur, ParseError, ParseResult};

const MAX_JUMPS: usize = 32;
const MAX_NAME: usize = 255;
pub const MAX_QUESTIONS: usize = 8;
pub const MAX_ANSWERS: usize = 64;
const MAX_TXT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Lowercase, no trailing dot, non-printable bytes escaped as `\DDD`.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte offset and length of the question in the message.
    pub span: (usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    /// RDATA as text (address, name, TXT strings); `None` for types not rendered.
    pub data: Option<String>,
    pub span: (usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    /// True if the message ended early or a record was malformed; the parsed
    /// prefix is still returned.
    pub truncated: bool,
}

/// Parse a DNS message (without the TCP length prefix).
pub fn parse_dns(msg: &[u8]) -> ParseResult<DnsMessage> {
    let mut c = Cur::new(msg);
    let id = c.u16()?;
    let flags = c.u16()?;
    let qdcount = c.u16()?;
    let ancount = c.u16()?;
    let nscount = c.u16()?;
    let arcount = c.u16()?;
    let mut m = DnsMessage {
        id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0f) as u8,
        rcode: (flags & 0x0f) as u8,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
        questions: Vec::new(),
        answers: Vec::new(),
        truncated: false,
    };
    for _ in 0..qdcount {
        let start = c.pos();
        let q = (|| -> ParseResult<DnsQuestion> {
            let name = read_name(msg, &mut c)?;
            let qtype = c.u16()?;
            let qclass = c.u16()?;
            Ok(DnsQuestion {
                name,
                qtype,
                qclass,
                span: (start, c.pos() - start),
            })
        })();
        match q {
            Ok(q) if m.questions.len() < MAX_QUESTIONS => m.questions.push(q),
            Ok(_) => {}
            Err(_) => {
                m.truncated = true;
                return Ok(m);
            }
        }
    }
    for _ in 0..ancount {
        if m.answers.len() >= MAX_ANSWERS {
            break;
        }
        let start = c.pos();
        match read_rr(msg, &mut c) {
            Ok(mut a) => {
                a.span = (start, c.pos() - start);
                m.answers.push(a);
            }
            Err(_) => {
                m.truncated = true;
                break;
            }
        }
    }
    Ok(m)
}

fn read_rr<'a>(msg: &'a [u8], c: &mut Cur<'a>) -> ParseResult<DnsAnswer> {
    let name = read_name(msg, c)?;
    let rtype = c.u16()?;
    let class = c.u16()?;
    let ttl = c.u32()?;
    let rdlen = usize::from(c.u16()?);
    let rdata_start = c.pos();
    let rdata = c.take(rdlen)?;
    let data = match rtype {
        1 => <[u8; 4]>::try_from(rdata)
            .ok()
            .map(|a| Ipv4Addr::from(a).to_string()),
        28 => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|a| Ipv6Addr::from(a).to_string()),
        // NS, CNAME, PTR, DNAME: a single (possibly compressed) name.
        2 | 5 | 12 | 39 => {
            let mut rc = Cur::at(msg, rdata_start);
            read_name(msg, &mut rc).ok()
        }
        // MX: preference + name.
        15 => {
            let mut rc = Cur::at(msg, rdata_start.saturating_add(2));
            if rdlen >= 3 {
                read_name(msg, &mut rc).ok()
            } else {
                None
            }
        }
        // TXT: one or more character-strings, concatenated.
        16 => {
            let mut rc = Cur::new(rdata);
            let mut s = String::new();
            while let Ok(part) = rc.vec(1) {
                if s.len() >= MAX_TXT {
                    break;
                }
                s.push_str(&crate::util::escape_bytes(part, MAX_TXT - s.len()));
            }
            Some(s)
        }
        _ => None,
    };
    Ok(DnsAnswer {
        name,
        rtype,
        class,
        ttl,
        data,
        span: (0, 0),
    })
}

/// Read a possibly compressed domain name starting at the cursor. The cursor
/// ends after the name's in-place encoding (after the first pointer).
pub fn read_name<'a>(msg: &'a [u8], c: &mut Cur<'a>) -> ParseResult<String> {
    let mut out = String::new();
    let mut pos = c.pos();
    let mut end_after: Option<usize> = None;
    let mut jumps = 0usize;
    let mut encoded = 0usize;
    // Pointers must go strictly backwards from the lowest offset visited.
    let mut floor = pos;
    loop {
        let len = *msg.get(pos).ok_or(ParseError::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let n = usize::from(len);
                let label = msg.get(pos + 1..pos + 1 + n).ok_or(ParseError::Truncated)?;
                encoded += n + 1;
                if encoded > MAX_NAME {
                    return Err(ParseError::Malformed("dns name too long"));
                }
                if !out.is_empty() {
                    out.push('.');
                }
                push_label(&mut out, label);
                pos += 1 + n;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1).ok_or(ParseError::Truncated)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(lo);
                if end_after.is_none() {
                    end_after = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS || target >= floor {
                    return Err(ParseError::Malformed("bad dns compression pointer"));
                }
                floor = target;
                pos = target;
            }
            _ => return Err(ParseError::Malformed("bad dns label type")),
        }
    }
    let end = end_after.unwrap_or(pos);
    *c = Cur::at(msg, end);
    Ok(out)
}

fn push_label(out: &mut String, label: &[u8]) {
    for &b in label {
        match b {
            b'.' => out.push_str("\\."),
            b'\\' => out.push_str("\\\\"),
            0x21..=0x7e => out.push(char::from(b.to_ascii_lowercase())),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
}

pub fn qtype_name(t: u16) -> String {
    let s = match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        10 => "NULL",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        _ => return format!("TYPE{t}"),
    };
    s.to_string()
}

pub fn rcode_name(r: u8) -> String {
    let s = match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => return format!("RCODE{r}"),
    };
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [id, flags, qd, an, 0, 0] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        v
    }

    #[test]
    fn compressed_answer() {
        let mut m = header(0x1234, 0x8180, 1, 2);
        m.extend_from_slice(b"\x03WWW\x07example\x03com\x00\x00\x01\x00\x01");
        // CNAME www -> cdn.example.com (cdn + pointer to "example.com" at 16)
        m.extend_from_slice(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03cdn\xc0\x10");
        // A cdn.example.com -> 1.2.3.4 (pointer to cdn label at 45)
        m.extend_from_slice(b"\xc0\x2d\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\x01\x02\x03\x04");
        let d = parse_dns(&m).expect("parse");
        assert!(d.is_response);
        assert_eq!(d.questions[0].name, "www.example.com");
        assert_eq!(d.answers[0].data.as_deref(), Some("cdn.example.com"));
        assert_eq!(d.answers[1].name, "cdn.example.com");
        assert_eq!(d.answers[1].data.as_deref(), Some("1.2.3.4"));
        assert_eq!(d.answers[1].ttl, 30);
        assert!(!d.truncated);
    }

    #[test]
    fn pointer_loop_rejected() {
        let mut m = header(1, 0, 1, 0);
        m.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01"); // points at itself
        let d = parse_dns(&m).expect("header ok");
        assert!(d.truncated);
        assert!(d.questions.is_empty());
        // Forward pointer is also rejected.
        let mut m = header(1, 0, 1, 0);
        m.extend_from_slice(b"\xc0\x20\x00\x01\x00\x01");
        assert!(parse_dns(&m).expect("hdr").truncated);
    }

    #[test]
    fn name_escaping_and_limits() {
        let mut m = header(1, 0, 1, 0);
        m.extend_from_slice(b"\x03a.\x01\x00\x00\x01\x00\x01");
        let d = parse_dns(&m).expect("parse");
        assert_eq!(d.questions[0].name, "a\\.\\001");
        let mut m = header(1, 0, 1, 0);
        for _ in 0..5 {
            m.push(63);
            m.extend_from_slice(&[b'a'; 63]);
        }
        m.push(0);
        assert!(parse_dns(&m).expect("hdr").truncated);
    }

    #[test]
    fn short_header() {
        assert_eq!(parse_dns(&[0; 11]), Err(ParseError::Truncated));
    }
}
