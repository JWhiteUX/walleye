//! TLS record and handshake builders: ClientHello profiles that mimic real
//! clients (so JA4 values look like the real thing), ServerHello for 1.2
//! and 1.3, Certificate, ServerKeyExchange and the encrypted remainder.

use crate::rng::Rng;

pub const CT_CCS: u8 = 20;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPDATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_SERVER_HELLO_DONE: u8 = 14;
const HS_CLIENT_KEY_EXCHANGE: u8 = 16;

/// Which client stack a ClientHello imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Chromium (Chrome, Edge): GREASE, shuffled extensions, h2.
    Chrome,
    Firefox,
    /// Windows SChannel (OS services: update, telemetry).
    Schannel,
    /// Apple system services (CFNetwork).
    Apple,
    /// Commodity implant: TLS 1.2 only, no ALPN, no GREASE.
    Implant,
}

const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn u16be(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn u24be(v: &mut Vec<u8>, x: usize) {
    v.extend_from_slice(&[(x >> 16) as u8, (x >> 8) as u8, x as u8]);
}

fn ext(id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    u16be(&mut v, id);
    u16be(&mut v, body.len() as u16);
    v.extend_from_slice(body);
    v
}

fn list16(items: &[u16]) -> Vec<u8> {
    let mut v = Vec::new();
    u16be(&mut v, (items.len() * 2) as u16);
    for &i in items {
        u16be(&mut v, i);
    }
    v
}

fn sni_ext(host: &str) -> Vec<u8> {
    let mut b = Vec::new();
    u16be(&mut b, (host.len() + 3) as u16);
    b.push(0);
    u16be(&mut b, host.len() as u16);
    b.extend_from_slice(host.as_bytes());
    ext(0, &b)
}

fn alpn_ext(protos: &[&str]) -> Vec<u8> {
    let mut l = Vec::new();
    for p in protos {
        l.push(p.len() as u8);
        l.extend_from_slice(p.as_bytes());
    }
    let mut b = Vec::new();
    u16be(&mut b, l.len() as u16);
    b.extend_from_slice(&l);
    ext(16, &b)
}

fn key_share_ext(shares: &[(u16, usize)], rng: &mut Rng) -> Vec<u8> {
    let mut l = Vec::new();
    for &(group, len) in shares {
        u16be(&mut l, group);
        u16be(&mut l, len as u16);
        l.extend_from_slice(&rng.vec(len));
    }
    let mut b = Vec::new();
    u16be(&mut b, l.len() as u16);
    b.extend_from_slice(&l);
    ext(51, &b)
}

fn versions_ext(versions: &[u16]) -> Vec<u8> {
    let mut b = vec![(versions.len() * 2) as u8];
    for &v in versions {
        u16be(&mut b, v);
    }
    ext(43, &b)
}

fn u8list_ext(id: u16, items: &[u8]) -> Vec<u8> {
    let mut b = vec![items.len() as u8];
    b.extend_from_slice(items);
    ext(id, &b)
}

fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.push(msg_type);
    u24be(&mut v, body.len());
    v.extend_from_slice(body);
    v
}

/// Wrap `body` in one or more TLS records of `content_type` (≤ 16 KiB each).
pub fn records(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5 * (body.len() / 16384 + 1));
    for chunk in body.chunks(16384) {
        out.push(content_type);
        u16be(&mut out, version);
        u16be(&mut out, chunk.len() as u16);
        out.extend_from_slice(chunk);
    }
    out
}

const SIG_CHROME: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const SIG_FIREFOX: [u16; 11] = [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const SIG_SCHANNEL: [u16; 11] = [
    0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601,
];

/// A ClientHello record for `sni` (None = no SNI extension).
pub fn client_hello(profile: Profile, sni: Option<&str>, rng: &mut Rng) -> Vec<u8> {
    let random = rng.vec(32);
    let mut ciphers: Vec<u16>;
    let mut exts: Vec<Vec<u8>> = Vec::new();
    let session_id: Vec<u8>;
    let record_version: u16;
    match profile {
        Profile::Chrome => {
            let g = GREASE[rng.below(16) as usize];
            let g2 = GREASE[rng.below(16) as usize];
            let g3 = GREASE[rng.below(16) as usize];
            ciphers = vec![
                g, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ];
            session_id = rng.vec(32);
            record_version = 0x0301;
            let mut middle = Vec::new();
            if let Some(h) = sni {
                middle.push(sni_ext(h));
            }
            middle.push(ext(23, &[]));
            middle.push(ext(65281, &[0]));
            middle.push(ext(10, &list16(&[g2, 0x11ec, 0x001d, 0x0017, 0x0018])));
            middle.push(u8list_ext(11, &[0]));
            middle.push(ext(35, &[]));
            middle.push(alpn_ext(&["h2", "http/1.1"]));
            middle.push(ext(5, &[1, 0, 0, 0, 0]));
            middle.push(ext(13, &list16(&SIG_CHROME)));
            middle.push(ext(18, &[]));
            middle.push(key_share_ext(&[(g2, 1), (0x11ec, 1216), (0x001d, 32)], rng));
            middle.push(u8list_ext(45, &[1]));
            middle.push(versions_ext(&[g3, 0x0304, 0x0303]));
            middle.push(ext(27, &[2, 0, 2]));
            middle.push(ext(17513, &[0, 3, 2, b'h', b'2']));
            rng.shuffle(&mut middle);
            let ix = rng.below(16) as usize;
            exts.push(ext(GREASE[ix], &[]));
            exts.extend(middle);
            let iy = (ix + 1 + rng.below(15) as usize) % 16;
            exts.push(ext(GREASE[iy], &[0]));
        }
        Profile::Firefox => {
            ciphers = vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ];
            session_id = rng.vec(32);
            record_version = 0x0301;
            if let Some(h) = sni {
                exts.push(sni_ext(h));
            }
            exts.push(ext(23, &[]));
            exts.push(ext(65281, &[0]));
            exts.push(ext(
                10,
                &list16(&[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
            ));
            exts.push(u8list_ext(11, &[0]));
            exts.push(ext(35, &[]));
            exts.push(alpn_ext(&["h2", "http/1.1"]));
            exts.push(ext(5, &[1, 0, 0, 0, 0]));
            exts.push(ext(34, &list16(&[0x0403, 0x0503, 0x0603, 0x0203])));
            exts.push(key_share_ext(
                &[(0x11ec, 1216), (0x001d, 32), (0x0017, 65)],
                rng,
            ));
            exts.push(versions_ext(&[0x0304, 0x0303]));
            exts.push(ext(13, &list16(&SIG_FIREFOX)));
            exts.push(u8list_ext(45, &[1]));
            exts.push(ext(28, &[0x40, 0x01]));
            exts.push(ext(27, &[6, 0, 1, 0, 2, 0, 3]));
        }
        Profile::Schannel | Profile::Apple => {
            ciphers = if profile == Profile::Schannel {
                vec![
                    0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027,
                    0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
                ]
            } else {
                vec![
                    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
                    0xc009, 0xc014, 0xc013,
                ]
            };
            session_id = rng.vec(32);
            record_version = 0x0303;
            if let Some(h) = sni {
                exts.push(sni_ext(h));
            }
            exts.push(ext(5, &[1, 0, 0, 0, 0]));
            exts.push(ext(10, &list16(&[0x001d, 0x0017, 0x0018])));
            exts.push(u8list_ext(11, &[0]));
            exts.push(ext(13, &list16(&SIG_SCHANNEL)));
            exts.push(ext(35, &[]));
            exts.push(alpn_ext(&["h2", "http/1.1"]));
            exts.push(ext(23, &[]));
            exts.push(ext(65281, &[0]));
            exts.push(versions_ext(&[0x0304, 0x0303]));
            exts.push(u8list_ext(45, &[1]));
            exts.push(key_share_ext(&[(0x001d, 32)], rng));
        }
        Profile::Implant => {
            ciphers = vec![
                0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0x009e, 0xc024, 0xc023, 0xc028, 0xc027,
                0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
                0x000a,
            ];
            session_id = Vec::new();
            record_version = 0x0303;
            if let Some(h) = sni {
                exts.push(sni_ext(h));
            }
            exts.push(ext(10, &list16(&[0x001d, 0x0017, 0x0018])));
            exts.push(u8list_ext(11, &[0]));
            exts.push(ext(13, &list16(&SIG_SCHANNEL)));
            exts.push(ext(23, &[]));
            exts.push(ext(65281, &[0]));
        }
    }

    let mut body = Vec::with_capacity(512);
    u16be(&mut body, 0x0303);
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);
    u16be(&mut body, (ciphers.len() * 2) as u16);
    for c in ciphers.drain(..) {
        u16be(&mut body, c);
    }
    body.extend_from_slice(&[1, 0]); // compression: null
    let ext_bytes = exts.concat();
    u16be(&mut body, ext_bytes.len() as u16);
    body.extend_from_slice(&ext_bytes);
    records(
        CT_HANDSHAKE,
        record_version,
        &handshake(HS_CLIENT_HELLO, &body),
    )
}

/// Server flight for TLS 1.3: ServerHello, CCS, then the encrypted
/// EncryptedExtensions/Certificate/Verify/Finished as one appdata blob.
pub fn server_flight_13(cipher: u16, session_id_len: usize, rng: &mut Rng) -> Vec<u8> {
    let mut body = Vec::new();
    u16be(&mut body, 0x0303);
    body.extend_from_slice(&rng.vec(32));
    body.push(session_id_len as u8);
    body.extend_from_slice(&rng.vec(session_id_len));
    u16be(&mut body, cipher);
    body.push(0);
    let mut exts = Vec::new();
    exts.extend(ext(43, &[0x03, 0x04]));
    let mut ks = Vec::new();
    u16be(&mut ks, 0x001d);
    u16be(&mut ks, 32);
    ks.extend_from_slice(&rng.vec(32));
    exts.extend(ext(51, &ks));
    u16be(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);
    let mut out = records(CT_HANDSHAKE, 0x0303, &handshake(HS_SERVER_HELLO, &body));
    out.extend(records(CT_CCS, 0x0303, &[1]));
    let enc_len = rng.range(2600, 5200) as usize;
    out.extend(records(CT_APPDATA, 0x0303, &rng.vec(enc_len)));
    out
}

/// Client finish for TLS 1.3: CCS + encrypted Finished.
pub fn client_finish_13(rng: &mut Rng) -> Vec<u8> {
    let mut out = records(CT_CCS, 0x0303, &[1]);
    out.extend(records(CT_APPDATA, 0x0303, &rng.vec(53)));
    out
}

/// Server flight for TLS 1.2 (ECDHE_RSA): ServerHello, Certificate chain,
/// ServerKeyExchange, ServerHelloDone.
pub fn server_flight_12(cipher: u16, chain: &[Vec<u8>], rng: &mut Rng) -> Vec<u8> {
    let mut sh = Vec::new();
    u16be(&mut sh, 0x0303);
    sh.extend_from_slice(&rng.vec(32));
    sh.push(32);
    sh.extend_from_slice(&rng.vec(32));
    u16be(&mut sh, cipher);
    sh.push(0);
    let mut exts = Vec::new();
    exts.extend(ext(65281, &[0]));
    exts.extend(u8list_ext(11, &[0]));
    exts.extend(ext(23, &[]));
    u16be(&mut sh, exts.len() as u16);
    sh.extend_from_slice(&exts);

    let mut certs = Vec::new();
    for c in chain {
        u24be(&mut certs, c.len());
        certs.extend_from_slice(c);
    }
    let mut cert_body = Vec::new();
    u24be(&mut cert_body, certs.len());
    cert_body.extend_from_slice(&certs);

    let mut ske = vec![3]; // named_curve
    u16be(&mut ske, 0x001d);
    ske.push(32);
    ske.extend_from_slice(&rng.vec(32));
    u16be(&mut ske, 0x0401);
    u16be(&mut ske, 256);
    ske.extend_from_slice(&rng.vec(256));

    let mut hs = handshake(HS_SERVER_HELLO, &sh);
    hs.extend(handshake(HS_CERTIFICATE, &cert_body));
    hs.extend(handshake(HS_SERVER_KEY_EXCHANGE, &ske));
    hs.extend(handshake(HS_SERVER_HELLO_DONE, &[]));
    records(CT_HANDSHAKE, 0x0303, &hs)
}

/// Client flight for TLS 1.2: ClientKeyExchange, CCS, encrypted Finished.
pub fn client_finish_12(rng: &mut Rng) -> Vec<u8> {
    let mut cke = vec![32];
    cke.extend_from_slice(&rng.vec(32));
    let mut out = records(
        CT_HANDSHAKE,
        0x0303,
        &handshake(HS_CLIENT_KEY_EXCHANGE, &cke),
    );
    out.extend(records(CT_CCS, 0x0303, &[1]));
    out.extend(records(CT_HANDSHAKE, 0x0303, &rng.vec(40)));
    out
}

/// Server finish for TLS 1.2: (NewSessionTicket omitted) CCS + Finished.
pub fn server_finish_12(rng: &mut Rng) -> Vec<u8> {
    let mut out = records(CT_CCS, 0x0303, &[1]);
    out.extend(records(CT_HANDSHAKE, 0x0303, &rng.vec(40)));
    out
}

/// Session id length the client used (TLS 1.3 servers echo it).
pub fn session_id_len(profile: Profile) -> usize {
    if profile == Profile::Implant { 0 } else { 32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ch(rec: &[u8]) -> (Vec<u16>, Vec<u16>) {
        assert_eq!(rec[0], CT_HANDSHAKE);
        let rlen = usize::from(u16::from_be_bytes([rec[3], rec[4]]));
        assert_eq!(rlen + 5, rec.len());
        let hs = &rec[5..];
        assert_eq!(hs[0], 1);
        let hlen = (usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]);
        assert_eq!(hlen + 4, hs.len());
        let b = &hs[4..];
        let mut p = 2 + 32;
        p += 1 + usize::from(b[p]);
        let cl = usize::from(u16::from_be_bytes([b[p], b[p + 1]]));
        let ciphers = b[p + 2..p + 2 + cl]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        p += 2 + cl;
        p += 1 + usize::from(b[p]);
        let el = usize::from(u16::from_be_bytes([b[p], b[p + 1]]));
        p += 2;
        assert_eq!(p + el, b.len());
        let mut exts = Vec::new();
        let mut q = p;
        while q < b.len() {
            exts.push(u16::from_be_bytes([b[q], b[q + 1]]));
            let l = usize::from(u16::from_be_bytes([b[q + 2], b[q + 3]]));
            q += 4 + l;
        }
        assert_eq!(q, b.len());
        (ciphers, exts)
    }

    #[test]
    fn client_hellos_are_well_formed() {
        let mut rng = Rng::new(3);
        for p in [
            Profile::Chrome,
            Profile::Firefox,
            Profile::Schannel,
            Profile::Apple,
            Profile::Implant,
        ] {
            let rec = client_hello(p, Some("www.example.com"), &mut rng);
            let (ciphers, exts) = parse_ch(&rec);
            assert!(!ciphers.is_empty());
            assert!(exts.contains(&0), "{p:?} lacks SNI");
            assert_eq!(exts.contains(&16), p != Profile::Implant);
        }
    }
}
