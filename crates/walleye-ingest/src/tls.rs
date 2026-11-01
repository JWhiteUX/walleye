//! TLS handshake parsing (ClientHello, ServerHello, Certificate) and the JA4 /
//! JA4S fingerprints, per the FoxIO specification
//! (<https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>).
//!
//! Verified vectors (see tests): the spec's example
//! `t13d1516h2_8daaf6152771_e5627efa2ab1` and JA4S `t130200_1301_a56c5b993250`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walleye_core::{Direction, TlsRow};

use crate::out::{Ctx, Out};
use crate::util::{Cur, ParseError, ParseResult, escape_bytes};
use crate::x509;

const MAX_RECORD_BUF: usize = 256 * 1024;
const MAX_HS_BUF: usize = 128 * 1024;
const MAX_RECORD_LEN: usize = 16384 + 2048;

pub const CT_CCS: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPDATA: u8 = 23;

pub const EXT_SNI: u16 = 0x0000;
pub const EXT_SIG_ALGS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub session_id_len: usize,
    pub ciphers: Vec<u16>,
    /// Extension types in wire order (GREASE included).
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub supported_versions: Vec<u16>,
    pub sig_algs: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub supported_version: Option<u16>,
    pub alpn: Option<Vec<u8>>,
}

impl ClientHello {
    /// Highest offered version (supported_versions, else legacy).
    pub fn max_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }
}

impl ServerHello {
    pub fn version(&self) -> u16 {
        self.supported_version.unwrap_or(self.legacy_version)
    }
}

/// GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ..., 0xfafa.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

pub fn version_name(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        _ => format!("0x{v:04x}"),
    }
}

fn ja4_version(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn ja4_alpn(first: Option<&[u8]>) -> String {
    let Some(a) = first.filter(|a| !a.is_empty()) else {
        return "00".into();
    };
    let (f, l) = (
        a.first().copied().unwrap_or(0),
        a.last().copied().unwrap_or(0),
    );
    if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
        format!("{}{}", char::from(f), char::from(l))
    } else {
        let h = format!("{f:02x}{l:02x}");
        let mut c = h.chars();
        let first = c.next().unwrap_or('0');
        let last = c.last().unwrap_or('0');
        format!("{first}{last}")
    }
}

fn hash12(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    crate::util::hex(d.get(..6).unwrap_or(&[]))
}

fn hex_list(v: &[u16]) -> String {
    v.iter()
        .map(|x| format!("{x:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// JA4 fingerprint. `transport` is `'t'` (TCP), `'q'` (QUIC) or `'d'` (DTLS).
pub fn ja4(ch: &ClientHello, transport: char) -> String {
    let (a, b, c) = ja4_parts(ch, transport);
    let b = if b.is_empty() {
        "000000000000".to_string()
    } else {
        hash12(&b)
    };
    let c = if c.is_empty() {
        "000000000000".to_string()
    } else {
        hash12(&c)
    };
    format!("{a}_{b}_{c}")
}

/// JA4_r (raw, unhashed) form, useful for debugging and tests.
pub fn ja4_raw(ch: &ClientHello, transport: char) -> String {
    let (a, b, c) = ja4_parts(ch, transport);
    format!("{a}_{b}_{c}")
}

fn ja4_parts(ch: &ClientHello, transport: char) -> (String, String, String) {
    let ciphers: Vec<u16> = ch
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts: Vec<u16> = ch
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let sni = if ch.extensions.contains(&EXT_SNI) {
        'd'
    } else {
        'i'
    };
    let a = format!(
        "{transport}{}{sni}{:02}{:02}{}",
        ja4_version(ch.max_version()),
        ciphers.len().min(99),
        exts.len().min(99),
        ja4_alpn(ch.alpn.first().map(Vec::as_slice)),
    );
    let mut sorted_c = ciphers;
    sorted_c.sort_unstable();
    let mut sorted_e: Vec<u16> = exts
        .into_iter()
        .filter(|e| *e != EXT_SNI && *e != EXT_ALPN)
        .collect();
    sorted_e.sort_unstable();
    let mut c = hex_list(&sorted_e);
    let sigs: Vec<u16> = ch
        .sig_algs
        .iter()
        .copied()
        .filter(|s| !is_grease(*s))
        .collect();
    if !sigs.is_empty() && !c.is_empty() {
        c.push('_');
        c.push_str(&hex_list(&sigs));
    }
    (a, hex_list(&sorted_c), c)
}

/// JA4S fingerprint (extensions in wire order, not sorted).
pub fn ja4s(sh: &ServerHello, transport: char) -> String {
    let (a, b, c) = ja4s_parts(sh, transport);
    let c = if c.is_empty() {
        "000000000000".to_string()
    } else {
        hash12(&c)
    };
    format!("{a}_{b}_{c}")
}

pub fn ja4s_raw(sh: &ServerHello, transport: char) -> String {
    let (a, b, c) = ja4s_parts(sh, transport);
    format!("{a}_{b}_{c}")
}

fn ja4s_parts(sh: &ServerHello, transport: char) -> (String, String, String) {
    let a = format!(
        "{transport}{}{:02}{}",
        ja4_version(sh.version()),
        sh.extensions.len().min(99),
        ja4_alpn(sh.alpn.as_deref()),
    );
    (a, format!("{:04x}", sh.cipher), hex_list(&sh.extensions))
}

/// Parse a ClientHello handshake body (after the 4-byte handshake header).
pub fn client_hello_body(b: &[u8]) -> ParseResult<ClientHello> {
    let mut c = Cur::new(b);
    let mut ch = ClientHello {
        legacy_version: c.u16()?,
        ..ClientHello::default()
    };
    c.skip(32)?;
    ch.session_id_len = c.vec(1)?.len();
    let cs = c.vec(2)?;
    if cs.len() % 2 != 0 {
        return Err(ParseError::Malformed("cipher suite list"));
    }
    ch.ciphers = cs
        .chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect();
    c.vec(1)?; // compression methods
    if c.is_empty() {
        return Ok(ch);
    }
    let mut ec = Cur::new(c.vec(2)?);
    while !ec.is_empty() {
        let ty = ec.u16()?;
        let data = ec.vec(2)?;
        ch.extensions.push(ty);
        let mut d = Cur::new(data);
        match ty {
            EXT_SNI => {
                if let Ok(list) = d.vec(2) {
                    let mut l = Cur::new(list);
                    while let (Ok(kind), Ok(name)) = (l.u8(), l.vec(2)) {
                        if kind == 0 {
                            ch.sni = Some(escape_bytes(name, 255).to_ascii_lowercase());
                            break;
                        }
                    }
                }
            }
            EXT_ALPN => {
                if let Ok(list) = d.vec(2) {
                    let mut l = Cur::new(list);
                    while let Ok(p) = l.vec(1) {
                        if ch.alpn.len() < 16 {
                            ch.alpn.push(p.to_vec());
                        }
                    }
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                if let Ok(list) = d.vec(1) {
                    ch.supported_versions = list
                        .chunks_exact(2)
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                }
            }
            EXT_SIG_ALGS => {
                if let Ok(list) = d.vec(2) {
                    ch.sig_algs = list
                        .chunks_exact(2)
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Ok(ch)
}

/// Parse a ServerHello handshake body.
pub fn server_hello_body(b: &[u8]) -> ParseResult<ServerHello> {
    let mut c = Cur::new(b);
    let mut sh = ServerHello {
        legacy_version: c.u16()?,
        ..ServerHello::default()
    };
    c.skip(32)?;
    c.vec(1)?;
    sh.cipher = c.u16()?;
    c.u8()?;
    if c.is_empty() {
        return Ok(sh);
    }
    let mut ec = Cur::new(c.vec(2)?);
    while !ec.is_empty() {
        let ty = ec.u16()?;
        let data = ec.vec(2)?;
        sh.extensions.push(ty);
        let mut d = Cur::new(data);
        match ty {
            EXT_SUPPORTED_VERSIONS => sh.supported_version = d.u16().ok(),
            EXT_ALPN => {
                if let Ok(list) = d.vec(2) {
                    sh.alpn = Cur::new(list).vec(1).ok().map(<[u8]>::to_vec);
                }
            }
            _ => {}
        }
    }
    Ok(sh)
}

/// The DER of the first (leaf) certificate in a TLS 1.0–1.2 Certificate body.
pub fn leaf_certificate(body: &[u8]) -> ParseResult<&[u8]> {
    let mut c = Cur::new(body);
    let list = c.vec(3)?;
    Cur::new(list).vec(3)
}

/// Concatenate the handshake-layer bytes of every complete record in `b`.
fn handshake_bytes(b: &[u8]) -> ParseResult<Vec<u8>> {
    let mut c = Cur::new(b);
    let mut hs = Vec::new();
    while c.remaining() >= 5 {
        let ct = c.u8()?;
        c.u16()?;
        let frag = c.vec(2)?;
        if ct != CT_HANDSHAKE {
            break;
        }
        if hs.len() + frag.len() > MAX_HS_BUF {
            break;
        }
        hs.extend_from_slice(frag);
    }
    if hs.is_empty() {
        return Err(ParseError::Malformed("no handshake record"));
    }
    Ok(hs)
}

fn first_handshake(b: &[u8], want: u8) -> ParseResult<ClientOrServer> {
    let hs = handshake_bytes(b)?;
    let mut c = Cur::new(&hs);
    let ty = c.u8()?;
    let body = c.vec(3)?;
    if ty != want {
        return Err(ParseError::Malformed("unexpected handshake type"));
    }
    Ok(match want {
        1 => ClientOrServer::Client(client_hello_body(body)?),
        _ => ClientOrServer::Server(server_hello_body(body)?),
    })
}

enum ClientOrServer {
    Client(ClientHello),
    Server(ServerHello),
}

/// Parse the ClientHello in TLS record-layer bytes (as seen on the wire).
pub fn parse_tls_client_hello(records: &[u8]) -> ParseResult<ClientHello> {
    match first_handshake(records, 1)? {
        ClientOrServer::Client(ch) => Ok(ch),
        ClientOrServer::Server(_) => Err(ParseError::Malformed("not a client hello")),
    }
}

/// Parse the ServerHello in TLS record-layer bytes.
pub fn parse_tls_server_hello(records: &[u8]) -> ParseResult<ServerHello> {
    match first_handshake(records, 2)? {
        ClientOrServer::Server(sh) => Ok(sh),
        ClientOrServer::Client(_) => Err(ParseError::Malformed("not a server hello")),
    }
}

/// True if the bytes start with a TLS handshake record (SSL 3.0 – TLS 1.3).
pub fn looks_like_tls(b: &[u8]) -> bool {
    matches!(b, [CT_HANDSHAKE, 3, 0..=4, _, _, 1 | 2, ..])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TDir {
    rec: Vec<u8>,
    hs: Vec<u8>,
    done: bool,
    frame: u64,
    ts: i64,
}

/// TLS handshake state for one TCP connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConn {
    dirs: [TDir; 2],
    row: Option<TlsRow>,
    offered: Option<String>,
}

impl TlsConn {
    pub fn feed(&mut self, dir: Direction, data: &[u8], gap: u64, ctx: Ctx, out: &mut Out) {
        let d = usize::from(dir == Direction::Down);
        if self.dirs[d].done {
            return;
        }
        if gap > 0 {
            self.dir_done(d, out);
            return;
        }
        let td = &mut self.dirs[d];
        if td.rec.is_empty() {
            td.frame = ctx.frame_no;
            td.ts = ctx.ts;
        }
        if td.rec.len() + data.len() > MAX_RECORD_BUF {
            self.dir_done(d, out);
            return;
        }
        td.rec.extend_from_slice(data);
        let mut consumed = 0usize;
        loop {
            let rec = self.dirs[d].rec.get(consumed..).unwrap_or(&[]);
            let mut c = Cur::new(rec);
            let (Ok(ct), Ok(_ver), Ok(len)) = (c.u8(), c.u16(), c.u16()) else {
                break;
            };
            let len = usize::from(len);
            if len > MAX_RECORD_LEN {
                self.dir_done(d, out);
                return;
            }
            let Ok(frag) = c.take(len) else { break };
            if ct != CT_HANDSHAKE {
                // CCS, alert, application data or junk: handshake is over.
                self.dir_done(d, out);
                return;
            }
            let frag = frag.to_vec();
            consumed += 5 + len;
            if self.dirs[d].hs.len() + frag.len() > MAX_HS_BUF {
                self.dir_done(d, out);
                return;
            }
            self.dirs[d].hs.extend_from_slice(&frag);
            self.handshakes(d, ctx, out);
            if self.dirs[d].done {
                return;
            }
        }
        let td = &mut self.dirs[d];
        td.rec.drain(..consumed.min(td.rec.len()));
        if consumed > 0 && !td.rec.is_empty() {
            td.frame = ctx.frame_no;
            td.ts = ctx.ts;
        }
    }

    fn handshakes(&mut self, d: usize, ctx: Ctx, out: &mut Out) {
        // A real handshake flight is a handful of messages; thousands of
        // empty ones in one record would make the drain below quadratic.
        const MAX_MESSAGES_PER_CALL: usize = 64;
        let mut seen = 0usize;
        loop {
            seen += 1;
            if seen > MAX_MESSAGES_PER_CALL {
                self.dir_done(d, out);
                return;
            }
            let hs = &self.dirs[d].hs;
            let mut c = Cur::new(hs);
            let (Ok(ty), Ok(body)) = (c.u8(), c.vec(3)) else {
                return;
            };
            let body = body.to_vec();
            let used = c.pos();
            self.dirs[d].hs.drain(..used);
            match (d, ty) {
                (0, 1) => {
                    let Ok(ch) = client_hello_body(&body) else {
                        self.dir_done(d, out);
                        return;
                    };
                    if let Some(r) = self.row.take() {
                        out.tls.push(r);
                    }
                    let version = version_name(ch.max_version());
                    self.offered = Some(version.clone());
                    self.row = Some(TlsRow {
                        ts: self.dirs[0].ts,
                        flow_id: ctx.flow_id,
                        frame_no: self.dirs[0].frame,
                        sni: ch.sni.clone(),
                        version: Some(version),
                        ja4: Some(ja4(&ch, 't')),
                        ja4s: None,
                        cert_subject: None,
                        cert_issuer: None,
                        cert_serial: None,
                        cert_self_signed: None,
                        cert_not_before: None,
                        cert_not_after: None,
                    });
                }
                (1, 2) => {
                    let Ok(sh) = server_hello_body(&body) else {
                        self.dir_done(d, out);
                        return;
                    };
                    let v = sh.version();
                    if let Some(r) = self.row.as_mut() {
                        r.version = Some(version_name(v));
                        r.ja4s = Some(ja4s(&sh, 't'));
                    }
                    if v == 0x0304 {
                        // Certificates are encrypted in TLS 1.3.
                        self.dir_done(d, out);
                        return;
                    }
                }
                (1, 11) => {
                    if let Some(cert) = leaf_certificate(&body)
                        .ok()
                        .and_then(|der| x509::parse_certificate(der).ok())
                        && let Some(r) = self.row.as_mut()
                    {
                        r.cert_subject = Some(cert.subject);
                        r.cert_issuer = Some(cert.issuer);
                        r.cert_serial = Some(cert.serial);
                        r.cert_self_signed = Some(cert.self_signed);
                        r.cert_not_before = cert.not_before;
                        r.cert_not_after = cert.not_after;
                    }
                    self.dir_done(d, out);
                    return;
                }
                (1, 14) => {
                    self.dir_done(d, out);
                    return;
                }
                _ => {}
            }
        }
    }

    fn dir_done(&mut self, d: usize, out: &mut Out) {
        let td = &mut self.dirs[d];
        td.done = true;
        td.rec = Vec::new();
        td.hs = Vec::new();
        if d == 1
            && let Some(r) = self.row.take()
        {
            out.tls.push(r);
        }
    }

    pub fn finish(&mut self, out: &mut Out) {
        if let Some(r) = self.row.take() {
            out.tls.push(r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FoxIO JA4 README example: the raw lists and the hashed fingerprint.
    #[test]
    fn ja4_spec_vector() {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let exts = [
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033,
            0x002d, 0x002b, 0x001b, 0x0015, 0x4469,
        ];
        let sigs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut ch = ClientHello {
            legacy_version: 0x0303,
            ciphers: std::iter::once(0x7a7a).chain(ciphers).collect(),
            extensions: std::iter::once(0x2a2a)
                .chain(exts)
                .chain(std::iter::once(0xbaba))
                .collect(),
            sni: Some("example.com".into()),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            supported_versions: vec![0x5a5a, 0x0304, 0x0303],
            sig_algs: sigs.to_vec(),
            session_id_len: 32,
        };
        assert_eq!(
            ja4_raw(&ch, 't'),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
        assert_eq!(ja4(&ch, 't'), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        // No SNI, no ALPN, no signature algorithms.
        ch.extensions
            .retain(|e| *e != EXT_SNI && *e != EXT_ALPN && *e != EXT_SIG_ALGS);
        ch.alpn.clear();
        ch.sig_algs.clear();
        let raw = ja4_raw(&ch, 't');
        assert!(raw.starts_with("t13i151300_"), "{raw}");
        assert!(!raw.ends_with('_'));
        assert_eq!(raw.matches('_').count(), 2);
    }

    #[test]
    fn ja4_edge_cases() {
        let empty = ClientHello::default();
        assert_eq!(ja4(&empty, 't'), "t00i000000_000000000000_000000000000");
        assert_eq!(ja4_alpn(Some(&[0x20, 0x61])), "21"); // spec example
        assert_eq!(ja4_alpn(Some(b"h")), "hh");
        assert_eq!(ja4_alpn(Some(b"")), "00");
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && !is_grease(0x0a1a));
    }

    /// FoxIO JA4S README example: `t130200_1301_a56c5b993250` (raw `..._002b,0033`).
    #[test]
    fn ja4s_spec_vector() {
        let sh = ServerHello {
            legacy_version: 0x0303,
            cipher: 0x1301,
            extensions: vec![0x002b, 0x0033],
            supported_version: Some(0x0304),
            alpn: None,
        };
        assert_eq!(ja4s_raw(&sh, 't'), "t130200_1301_002b,0033");
        assert_eq!(ja4s(&sh, 't'), "t130200_1301_a56c5b993250");
    }
}
