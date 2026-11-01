//! Minimal DER encoder for X.509 v3 certificates.
//!
//! The certificates are structurally valid (any X.509 parser reads subject,
//! issuer, serial, validity, SAN, key and signature) but the RSA key and
//! signature are random bytes: nothing in Walleye verifies signatures, and
//! this keeps the generator free of crypto dependencies.

use crate::rng::Rng;

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n <= 0xFFFF {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

/// Unsigned big-endian integer (leading zero added when the top bit is set).
fn uint(bytes: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = bytes.iter().copied().skip_while(|&x| x == 0).collect();
    if b.is_empty() {
        b.push(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut tmp = vec![(a & 0x7F) as u8];
        let mut v = a >> 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7F) as u8);
            v >>= 7;
        }
        tmp.reverse();
        body.extend_from_slice(&tmp);
    }
    tlv(0x06, &body)
}

const NULL: [u8; 2] = [0x05, 0x00];
const OID_CN: [u64; 4] = [2, 5, 4, 3];
const OID_C: [u64; 4] = [2, 5, 4, 6];
const OID_ST: [u64; 4] = [2, 5, 4, 8];
const OID_O: [u64; 4] = [2, 5, 4, 10];
const OID_SHA256_RSA: [u64; 7] = [1, 2, 840, 113_549, 1, 1, 11];
const OID_RSA: [u64; 7] = [1, 2, 840, 113_549, 1, 1, 1];
const OID_SAN: [u64; 4] = [2, 5, 29, 17];
const OID_BASIC: [u64; 4] = [2, 5, 29, 19];

/// Distinguished name as (attribute, value) pairs, e.g. `[("C","US"),("CN","x")]`.
pub type Dn<'a> = &'a [(&'a str, &'a str)];

fn name(dn: Dn<'_>) -> Vec<u8> {
    let rdns: Vec<Vec<u8>> = dn
        .iter()
        .map(|(k, v)| {
            let (o, tag): (&[u64], u8) = match *k {
                "C" => (&OID_C, 0x13),
                "ST" => (&OID_ST, 0x0C),
                "O" => (&OID_O, 0x0C),
                _ => (&OID_CN, 0x0C),
            };
            set(&[seq(&[oid(o), tlv(tag, v.as_bytes())])])
        })
        .collect();
    seq(&rdns)
}

fn alg(o: &[u64]) -> Vec<u8> {
    seq(&[oid(o), NULL.to_vec()])
}

pub struct CertSpec<'a> {
    pub subject: Dn<'a>,
    pub issuer: Dn<'a>,
    /// UTCTime strings, `YYMMDDHHMMSSZ`.
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub dns_names: &'a [&'a str],
    pub is_ca: bool,
}

/// DER-encoded certificate. Serial, key and signature come from `rng`.
pub fn certificate(spec: &CertSpec<'_>, rng: &mut Rng) -> Vec<u8> {
    let mut serial = rng.bytes::<16>();
    serial[0] &= 0x7F;
    serial[0] |= 0x01;
    let mut modulus = rng.vec(256);
    modulus[0] |= 0x80;
    modulus[255] |= 0x01;
    let rsa_pub = seq(&[uint(&modulus), uint(&[0x01, 0x00, 0x01])]);
    let mut bitstr = vec![0u8];
    bitstr.extend_from_slice(&rsa_pub);
    let spki = seq(&[alg(&OID_RSA), tlv(0x03, &bitstr)]);

    let mut exts = Vec::new();
    if !spec.dns_names.is_empty() {
        let names: Vec<Vec<u8>> = spec
            .dns_names
            .iter()
            .map(|n| tlv(0x82, n.as_bytes()))
            .collect();
        exts.push(seq(&[oid(&OID_SAN), tlv(0x04, &seq(&names))]));
    }
    if spec.is_ca {
        let bc = seq(&[tlv(0x01, &[0xFF])]);
        exts.push(seq(&[oid(&OID_BASIC), tlv(0x01, &[0xFF]), tlv(0x04, &bc)]));
    }

    let mut tbs_parts = vec![
        tlv(0xA0, &uint(&[2])),
        uint(&serial),
        alg(&OID_SHA256_RSA),
        name(spec.issuer),
        seq(&[
            tlv(0x17, spec.not_before.as_bytes()),
            tlv(0x17, spec.not_after.as_bytes()),
        ]),
        name(spec.subject),
        spki,
    ];
    if !exts.is_empty() {
        tbs_parts.push(tlv(0xA3, &seq(&exts)));
    }
    let tbs = seq(&tbs_parts);
    let mut sig = vec![0u8];
    sig.extend_from_slice(&rng.vec(256));
    seq(&[tbs, alg(&OID_SHA256_RSA), tlv(0x03, &sig)])
}

const OID_SHA1: [u64; 6] = [1, 3, 14, 3, 2, 26];
const OID_OCSP_BASIC: [u64; 10] = [1, 3, 6, 1, 5, 5, 7, 48, 1, 1];

fn cert_id(rng: &mut Rng) -> Vec<u8> {
    let mut serial = rng.bytes::<16>();
    serial[0] &= 0x7F;
    serial[0] |= 0x01;
    seq(&[
        alg(&OID_SHA1),
        tlv(0x04, &rng.vec(20)),
        tlv(0x04, &rng.vec(20)),
        uint(&serial),
    ])
}

/// DER OCSPRequest (RFC 6960) for one random certificate.
pub fn ocsp_request(rng: &mut Rng) -> Vec<u8> {
    let req = seq(&[cert_id(rng)]);
    seq(&[seq(&[seq(&[req])])])
}

/// DER OCSPResponse: successful, BasicOCSPResponse with one "good" status.
/// `when` is a GeneralizedTime string, `YYYYMMDDHHMMSSZ`.
pub fn ocsp_response(when: &str, rng: &mut Rng) -> Vec<u8> {
    let gt = |s: &str| tlv(0x18, s.as_bytes());
    let single = seq(&[
        cert_id(rng),
        vec![0x80, 0x00], // certStatus good: [0] IMPLICIT NULL
        gt(when),
        tlv(0xA0, &gt(when)),
    ]);
    let tbs = seq(&[
        tlv(0xA2, &tlv(0x04, &rng.vec(20))), // responderID byKey
        gt(when),
        seq(&[single]),
    ]);
    let mut sig = vec![0u8];
    sig.extend_from_slice(&rng.vec(256));
    let basic = seq(&[tbs, alg(&OID_SHA256_RSA), tlv(0x03, &sig)]);
    let bytes = seq(&[oid(&OID_OCSP_BASIC), tlv(0x04, &basic)]);
    seq(&[tlv(0x0A, &[0]), tlv(0xA0, &bytes)])
}

/// DER v2 CRL from `issuer` with `revoked` random entries.
pub fn crl(issuer: Dn<'_>, revoked: usize, rng: &mut Rng) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = (0..revoked)
        .map(|_| {
            let mut s = rng.bytes::<16>();
            s[0] = (s[0] & 0x7F) | 0x01;
            seq(&[uint(&s), tlv(0x17, b"260215120000Z")])
        })
        .collect();
    let mut tbs = vec![
        uint(&[1]),
        alg(&OID_SHA256_RSA),
        name(issuer),
        tlv(0x17, b"260309000000Z"),
        tlv(0x17, b"260316000000Z"),
    ];
    if !entries.is_empty() {
        tbs.push(seq(&entries));
    }
    let mut sig = vec![0u8];
    sig.extend_from_slice(&rng.vec(256));
    seq(&[seq(&tbs), alg(&OID_SHA256_RSA), tlv(0x03, &sig)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_form_lengths() {
        assert_eq!(tlv(0x04, &[0; 5])[..2], [0x04, 5]);
        assert_eq!(tlv(0x04, &[0; 200])[..3], [0x04, 0x81, 200]);
        assert_eq!(tlv(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2C]);
    }

    #[test]
    fn oid_encoding_matches_known_value() {
        // 1.2.840.113549.1.1.11 = 06 09 2A 86 48 86 F7 0D 01 01 0B
        assert_eq!(
            oid(&OID_SHA256_RSA),
            vec![
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
            ]
        );
    }

    #[test]
    fn certificate_is_one_der_sequence() {
        let mut rng = Rng::new(1);
        let dn: Dn<'_> = &[("CN", "example.test")];
        let c = certificate(
            &CertSpec {
                subject: dn,
                issuer: dn,
                not_before: "260101000000Z",
                not_after: "270101000000Z",
                dns_names: &["example.test"],
                is_ca: false,
            },
            &mut rng,
        );
        assert_eq!(c[0], 0x30);
        assert_eq!(c[1], 0x82);
        let len = usize::from(u16::from_be_bytes([c[2], c[3]]));
        assert_eq!(len + 4, c.len());
    }
}
