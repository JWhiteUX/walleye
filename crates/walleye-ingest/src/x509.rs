//! Minimal, bounds-checked DER walk of an X.509 certificate: subject, issuer,
//! serial, validity and a self-signed check (issuer == subject, byte for
//! byte; signatures are not verified).

use std::fmt::Write as _;

use crate::util::{Cur, ParseError, ParseResult, days_from_civil, escape_bytes, hex};

const MAX_RDNS: usize = 64;
const MAX_VALUE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// RFC 4514 order (most specific first), e.g. `CN=example.com,O=Org,C=US`.
    pub subject: String,
    pub issuer: String,
    /// Lowercase hex of the serial's content octets (leading sign byte dropped).
    pub serial: String,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub self_signed: bool,
}

/// One DER TLV: tag, content, and the whole encoding.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

pub fn read_tlv<'a>(c: &mut Cur<'a>) -> ParseResult<Tlv<'a>> {
    let start = c.pos();
    let tag = c.u8()?;
    if tag & 0x1f == 0x1f {
        return Err(ParseError::Unsupported("high-tag-number form"));
    }
    let first = c.u8()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(ParseError::Malformed("der length"));
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | usize::from(c.u8()?);
        }
        l
    };
    let content = c.take(len)?;
    let raw = c.span(start, c.pos());
    Ok(Tlv { tag, content, raw })
}

fn expect<'a>(c: &mut Cur<'a>, tag: u8) -> ParseResult<Tlv<'a>> {
    let t = read_tlv(c)?;
    if t.tag != tag {
        return Err(ParseError::Malformed("unexpected der tag"));
    }
    Ok(t)
}

/// Parse a DER certificate.
pub fn parse_certificate(der: &[u8]) -> ParseResult<Certificate> {
    let mut c = Cur::new(der);
    let cert = expect(&mut c, 0x30)?;
    let mut cc = Cur::new(cert.content);
    let tbs = expect(&mut cc, 0x30)?;
    let mut t = Cur::new(tbs.content);
    let mut next = read_tlv(&mut t)?;
    if next.tag == 0xa0 {
        next = read_tlv(&mut t)?; // explicit version
    }
    if next.tag != 0x02 {
        return Err(ParseError::Malformed("certificate serial"));
    }
    let serial_bytes = match next.content {
        [0, rest @ ..] if !rest.is_empty() => rest,
        b => b,
    };
    let serial = hex(serial_bytes.get(..64).unwrap_or(serial_bytes));
    let _sig_alg = expect(&mut t, 0x30)?;
    let issuer = expect(&mut t, 0x30)?;
    let validity = expect(&mut t, 0x30)?;
    let subject = expect(&mut t, 0x30)?;
    let mut v = Cur::new(validity.content);
    let not_before = read_tlv(&mut v)
        .ok()
        .and_then(|x| parse_time(x.tag, x.content));
    let not_after = read_tlv(&mut v)
        .ok()
        .and_then(|x| parse_time(x.tag, x.content));
    Ok(Certificate {
        subject: name_to_string(subject.content),
        issuer: name_to_string(issuer.content),
        serial,
        not_before,
        not_after,
        self_signed: issuer.raw == subject.raw,
    })
}

/// RFC 4514 string of a Name (SEQUENCE OF RDN), reversed to most-specific
/// first. Unparseable parts are skipped.
pub fn name_to_string(seq: &[u8]) -> String {
    let mut rdns: Vec<String> = Vec::new();
    let mut c = Cur::new(seq);
    while !c.is_empty() && rdns.len() < MAX_RDNS {
        let Ok(set) = read_tlv(&mut c) else { break };
        if set.tag != 0x31 {
            continue;
        }
        let mut sc = Cur::new(set.content);
        let mut parts = Vec::new();
        while !sc.is_empty() {
            let Ok(atv) = read_tlv(&mut sc) else { break };
            let mut ac = Cur::new(atv.content);
            let (Ok(oid), Ok(val)) = (read_tlv(&mut ac), read_tlv(&mut ac)) else {
                continue;
            };
            if oid.tag != 0x06 {
                continue;
            }
            let key = attr_name(oid.content);
            parts.push(format!(
                "{key}={}",
                escape_rdn(&string_value(val.tag, val.content))
            ));
        }
        if !parts.is_empty() {
            rdns.push(parts.join("+"));
        }
    }
    rdns.reverse();
    rdns.join(",")
}

fn attr_name(oid: &[u8]) -> String {
    let s = match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x09] => "STREET",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x55, 0x04, 0x11] => "postalCode",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        _ => return oid_to_string(oid),
    };
    s.to_string()
}

/// Dotted-decimal OID text; arcs that overflow u64 stop the decode.
pub fn oid_to_string(b: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &x in b.iter().take(64) {
        if v > (u64::MAX >> 7) {
            break;
        }
        v = (v << 7) | u64::from(x & 0x7f);
        if x & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b) = if v < 40 {
                    (0, v)
                } else if v < 80 {
                    (1, v - 40)
                } else {
                    (2, v - 80)
                };
                arcs.push(a);
                arcs.push(b);
            } else {
                arcs.push(v);
            }
            v = 0;
        }
    }
    let mut s = String::new();
    for (i, a) in arcs.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        let _ = write!(s, "{a}");
    }
    s
}

fn string_value(tag: u8, b: &[u8]) -> String {
    match tag {
        // UTF8String
        0x0c => {
            let s = String::from_utf8_lossy(b.get(..MAX_VALUE).unwrap_or(b));
            s.chars().filter(|c| !c.is_control()).collect()
        }
        // BMPString (UTF-16BE)
        0x1e => {
            let units: Vec<u16> = b
                .chunks_exact(2)
                .take(MAX_VALUE)
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&units)
                .chars()
                .filter(|c| !c.is_control())
                .collect()
        }
        // PrintableString, IA5String, T61String, VisibleString, others
        _ => escape_bytes(b, MAX_VALUE),
    }
}

fn escape_rdn(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for (i, ch) in v.chars().enumerate() {
        let lead = i == 0 && (ch == '#' || ch == ' ');
        if lead || matches!(ch, ',' | '+' | '"' | '<' | '>' | ';' | '=') {
            s.push('\\');
        }
        s.push(ch);
    }
    if s.ends_with(' ') {
        s.pop();
        s.push_str("\\ ");
    }
    s
}

fn digits(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    b.iter().try_fold(0u32, |a, &d| {
        a.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

/// UTCTime (`YYMMDDHHMM[SS]Z`) or GeneralizedTime (`YYYYMMDDHHMM[SS]Z`) to µs.
pub fn parse_time(tag: u8, b: &[u8]) -> Option<i64> {
    let b = b.strip_suffix(b"Z")?;
    let (year, rest) = match tag {
        0x17 => {
            let yy = digits(b.get(..2)?)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, b.get(2..)?)
        }
        0x18 => (digits(b.get(..4)?)?, b.get(4..)?),
        _ => return None,
    };
    let rest = rest.split(|&c| c == b'.').next()?; // drop fractional seconds
    let f = |i: usize| digits(rest.get(i..i + 2)?);
    let (mo, d, h, mi) = (f(0)?, f(2)?, f(4)?, f(6)?);
    let s = if rest.len() >= 10 { f(8)? } else { 0 };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(i64::from(year), mo, d);
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s);
    secs.checked_mul(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(parse_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(
            parse_time(0x17, b"491231235959Z"),
            Some(2_524_607_999_000_000)
        );
        assert_eq!(
            parse_time(0x18, b"20240229120000Z"),
            Some(1_709_208_000_000_000)
        );
        assert_eq!(parse_time(0x17, b"701301000000Z"), None);
        assert_eq!(parse_time(0x17, b"7001"), None);
    }

    #[test]
    fn oids() {
        assert_eq!(
            oid_to_string(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]),
            "1.2.840.113549"
        );
        assert_eq!(attr_name(&[0x55, 0x04, 0x03]), "CN");
    }

    #[test]
    fn tlv_bounds() {
        assert!(read_tlv(&mut Cur::new(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff])).is_err());
        assert!(read_tlv(&mut Cur::new(&[0x30, 0x80])).is_err());
        assert!(parse_certificate(&[0x30, 0x03, 0x30, 0x01, 0x02]).is_err());
    }
}
