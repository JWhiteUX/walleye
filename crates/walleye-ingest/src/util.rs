//! Bounds-checked byte reading and text helpers shared by every parser.
//!
//! Every read goes through [`Cur`], which returns [`ParseError::Truncated`]
//! instead of panicking. Length arithmetic uses checked operations.

use std::fmt::Write as _;

/// Error returned by the protocol parsers. Never contains raw capture bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("truncated input")]
    Truncated,
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

pub type ParseResult<T> = Result<T, ParseError>;

/// Forward-only cursor over a byte slice.
#[derive(Debug, Clone)]
pub struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }
    /// Bytes `start..end` of the underlying buffer (empty if out of range).
    pub fn span(&self, start: usize, end: usize) -> &'a [u8] {
        self.buf.get(start..end).unwrap_or(&[])
    }
    pub fn take(&mut self, n: usize) -> ParseResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    pub fn skip(&mut self, n: usize) -> ParseResult<()> {
        self.take(n).map(|_| ())
    }
    pub fn u8(&mut self) -> ParseResult<u8> {
        let b = *self.buf.get(self.pos).ok_or(ParseError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    pub fn u16(&mut self) -> ParseResult<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u24(&mut self) -> ParseResult<u32> {
        let s = self.take(3)?;
        Ok(u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
    pub fn u32(&mut self) -> ParseResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// A sub-slice prefixed by a big-endian length of `len_bytes` (1, 2 or 3).
    pub fn vec(&mut self, len_bytes: u8) -> ParseResult<&'a [u8]> {
        let n = match len_bytes {
            1 => usize::from(self.u8()?),
            2 => usize::from(self.u16()?),
            _ => self.u24()? as usize,
        };
        self.take(n)
    }
}

/// Bounds-checked sub-slice (`None` instead of a panic).
pub fn sub(b: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    b.get(start..start.checked_add(len)?)
}

/// Render untrusted bytes as printable text: printable ASCII is kept, every
/// other byte becomes `\xHH`. Output is capped at `max` input bytes.
pub fn escape_bytes(b: &[u8], max: usize) -> String {
    let b = b.get(..max.min(b.len())).unwrap_or(b);
    let mut s = String::with_capacity(b.len());
    for &c in b {
        if (0x20..0x7f).contains(&c) && c != b'\\' {
            s.push(char::from(c));
        } else if c == b'\\' {
            s.push_str("\\\\");
        } else {
            let _ = write!(s, "\\x{c:02x}");
        }
    }
    s
}

/// Lowercase hex, two chars per byte.
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        let _ = write!(s, "{c:02x}");
    }
    s
}

/// ASCII case-insensitive prefix test.
pub fn starts_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Position of the first occurrence of `needle` in `hay`.
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let d = i64::from(d);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_never_panics() {
        let mut c = Cur::new(&[1, 2, 3]);
        assert_eq!(c.u16(), Ok(0x0102));
        assert_eq!(c.u16(), Err(ParseError::Truncated));
        assert_eq!(c.take(usize::MAX), Err(ParseError::Truncated));
        assert_eq!(c.u8(), Ok(3));
        assert_eq!(c.u8(), Err(ParseError::Truncated));
    }

    #[test]
    fn civil() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
    }

    #[test]
    fn escape() {
        assert_eq!(escape_bytes(b"a\x00b\\", 10), "a\\x00b\\\\");
        assert_eq!(escape_bytes(b"abcdef", 3), "abc");
    }
}
