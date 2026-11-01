//! Radiotap + IEEE 802.11 parsing for monitor-mode captures (link types 105
//! and 127, CONTRACTS §11.1).
//!
//! The ingest path calls [`parse_frame`] once per frame and gets back either
//! nothing (control frames, frames too short for their header, not 802.11)
//! or a [`WifiFrame`]: the header fields, the management-body summary (SSID,
//! security, channel, reason/status code) and, for unprotected LLC/SNAP data,
//! the ethertype and the offset of the network-layer payload so the existing
//! IP/flow pipeline can take over. The decode tree (`decode_wifi.rs`) reuses
//! the same primitives with byte ranges.
//!
//! All reads are bounds-checked; no function here panics on any input and no
//! per-capture state is kept (so ingest checkpoints need nothing extra).

use walleye_core::WifiKind;

/// 802.11 frame types (frame control bits 2–3).
pub const TYPE_MGMT: u8 = 0;
pub const TYPE_CTRL: u8 = 1;
pub const TYPE_DATA: u8 = 2;

/// Frame control flag bits (second byte).
pub const FL_TO_DS: u8 = 0x01;
pub const FL_FROM_DS: u8 = 0x02;
pub const FL_MORE_FRAG: u8 = 0x04;
pub const FL_RETRY: u8 = 0x08;
pub const FL_PWR_MGMT: u8 = 0x10;
pub const FL_MORE_DATA: u8 = 0x20;
pub const FL_PROTECTED: u8 = 0x40;
pub const FL_ORDER: u8 = 0x80;

/// Radiotap Flags field bits.
pub const RT_FLAG_FCS: u8 = 0x10;
pub const RT_FLAG_DATA_PAD: u8 = 0x20;
pub const RT_FLAG_BAD_FCS: u8 = 0x40;

/// Capability information: Privacy bit.
pub const CAP_PRIVACY: u16 = 0x0010;

pub const ETHERTYPE_EAPOL: u16 = 0x888e;

/// Longest SSID kept (802.11 allows 32 octets).
pub const MAX_SSID: usize = 32;

// ---------------------------------------------------------------------------
// Little helpers

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o.checked_add(1)?)?]))
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn addr(b: &[u8], o: usize) -> Option<[u8; 6]> {
    let s = b.get(o..o.checked_add(6)?)?;
    let mut a = [0u8; 6];
    a.copy_from_slice(s);
    Some(a)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Canonical lowercase `aa:bb:cc:dd:ee:ff` (same output as
/// `walleye_core::mac::mac_text`, without `format!` on the hot path).
pub fn mac_string(a: &[u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, &x) in a.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push(char::from(HEX[usize::from(x >> 4)]));
        s.push(char::from(HEX[usize::from(x & 0x0f)]));
    }
    s
}

// ---------------------------------------------------------------------------
// Radiotap

/// The radiotap fields Walleye reads, with their offsets (from the start of
/// the radiotap header) for the decode tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Radiotap {
    /// `it_len`: header length; the 802.11 frame starts here.
    pub len: usize,
    /// Number of `it_present` words (≥ 1).
    pub present_words: usize,
    /// First `it_present` word.
    pub present: u32,
    pub flags: Option<(u8, usize)>,
    /// (frequency MHz, channel flags, offset).
    pub channel: Option<(u16, u16, usize)>,
    /// (dBm antenna signal, offset).
    pub signal: Option<(i8, usize)>,
}

impl Radiotap {
    fn flag(&self, bit: u8) -> bool {
        self.flags.is_some_and(|(f, _)| f & bit != 0)
    }
    /// The 802.11 frame ends with a 4-byte FCS.
    pub fn has_fcs(&self) -> bool {
        self.flag(RT_FLAG_FCS)
    }
    /// The FCS failed the capturing radio's check.
    pub fn bad_fcs(&self) -> bool {
        self.flag(RT_FLAG_BAD_FCS)
    }
    /// Padding between the 802.11 header and the payload (32-bit alignment).
    pub fn data_pad(&self) -> bool {
        self.flag(RT_FLAG_DATA_PAD)
    }
    pub fn freq(&self) -> Option<u16> {
        self.channel.map(|c| c.0).filter(|&f| f != 0)
    }
}

/// (alignment, size) of radiotap fields 0..=5 of the default namespace:
/// TSFT, Flags, Rate, Channel, FHSS, dBm Antenna Signal.
const RT_FIELDS: [(usize, usize); 6] = [(8, 8), (1, 1), (1, 1), (2, 4), (1, 2), (1, 1)];

/// Most `it_present` words accepted (the chain is bounded by `it_len`
/// anyway; this keeps a hostile header from walking 16 K words).
const MAX_PRESENT_WORDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadiotapError {
    /// Shorter than its fixed 8-byte header or than `it_len`.
    Truncated,
    /// `it_version` is not 0, or `it_len` < 8, or the present chain does not
    /// fit inside `it_len`.
    Malformed,
}

/// Parse the radiotap header at the start of `b`.
///
/// Walks the `it_present` chain (bit 31 = another word follows); fields of
/// the first word are laid out after the last present word, each at its
/// natural alignment from the start of the header. We read Flags, Channel
/// and dBm Antenna Signal; every field before them has a known size, so the
/// walk never has to skip a field it cannot size. A field that would run past
/// `it_len` is left unset.
pub fn parse_radiotap(b: &[u8]) -> Result<Radiotap, RadiotapError> {
    if b.len() < 8 {
        return Err(RadiotapError::Truncated);
    }
    if b[0] != 0 {
        return Err(RadiotapError::Malformed);
    }
    let len = usize::from(u16::from_le_bytes([b[2], b[3]]));
    if len < 8 {
        return Err(RadiotapError::Malformed);
    }
    if len > b.len() {
        return Err(RadiotapError::Truncated);
    }
    let hdr = &b[..len];
    let present = le32(hdr, 4).ok_or(RadiotapError::Malformed)?;
    let mut words = 1usize;
    let mut w = present;
    while w & 0x8000_0000 != 0 {
        if words >= MAX_PRESENT_WORDS {
            return Err(RadiotapError::Malformed);
        }
        w = le32(hdr, 4 + 4 * words).ok_or(RadiotapError::Malformed)?;
        words += 1;
    }
    let mut rt = Radiotap {
        len,
        present_words: words,
        present,
        ..Radiotap::default()
    };
    let mut off = 4 + 4 * words;
    for (bit, &(align, size)) in RT_FIELDS.iter().enumerate() {
        if present & (1 << bit) == 0 {
            continue;
        }
        off = off.div_ceil(align) * align;
        if off + size > len {
            break;
        }
        match bit {
            1 => rt.flags = Some((hdr[off], off)),
            3 => {
                let freq = le16(hdr, off).unwrap_or(0);
                let fl = le16(hdr, off + 2).unwrap_or(0);
                rt.channel = Some((freq, fl, off));
            }
            5 => rt.signal = Some((i8::from_le_bytes([hdr[off]]), off)),
            _ => {}
        }
        off += size;
    }
    Ok(rt)
}

/// IEEE channel number for a centre frequency (2.4, 4.9, 5 and 6 GHz bands).
pub fn freq_to_channel(freq: u16) -> Option<u16> {
    match freq {
        2484 => Some(14),
        2412..=2472 => Some((freq - 2407) / 5),
        4910..=4980 => Some((freq - 4000) / 5),
        5000..=5895 => Some((freq - 5000) / 5),
        5955..=7115 => Some((freq - 5950) / 5),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 802.11 MAC header

/// A parsed management or data frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub ftype: u8,
    pub subtype: u8,
    /// Second frame-control byte (ToDS, FromDS, retry, protected, ...).
    pub flags: u8,
    pub duration: u16,
    pub a1: [u8; 6],
    pub a2: [u8; 6],
    pub a3: [u8; 6],
    pub a4: Option<[u8; 6]>,
    /// Sequence control (fragment number in the low 4 bits).
    pub seq_ctrl: u16,
    pub qos: Option<u16>,
    /// HT Control field present (+HTC).
    pub htc: bool,
    /// Header length in bytes, including QoS/HT control.
    pub len: usize,
}

impl Header {
    pub fn to_ds(&self) -> bool {
        self.flags & FL_TO_DS != 0
    }
    pub fn from_ds(&self) -> bool {
        self.flags & FL_FROM_DS != 0
    }
    pub fn retry(&self) -> bool {
        self.flags & FL_RETRY != 0
    }
    pub fn protected(&self) -> bool {
        self.flags & FL_PROTECTED != 0
    }
    pub fn seq(&self) -> u16 {
        self.seq_ctrl >> 4
    }
    /// QoS data subtypes (bit 3 of the subtype).
    pub fn is_qos_data(&self) -> bool {
        self.ftype == TYPE_DATA && self.subtype & 0x08 != 0
    }
    /// Data subtypes without a frame body (Null, QoS Null, CF-only).
    pub fn is_null_data(&self) -> bool {
        self.ftype == TYPE_DATA && self.subtype & 0x04 != 0
    }

    /// `(src, dst, tx, bssid)` per IEEE 802.11-2020 Table 9-30 for data
    /// frames; management frames always carry DA, SA, BSSID.
    pub fn roles(&self) -> Roles {
        if self.ftype == TYPE_MGMT {
            return Roles {
                src: Some(self.a2),
                dst: Some(self.a1),
                tx: Some(self.a2),
                bssid: Some(self.a3),
            };
        }
        match (self.to_ds(), self.from_ds()) {
            (false, false) => Roles {
                src: Some(self.a2),
                dst: Some(self.a1),
                tx: Some(self.a2),
                bssid: Some(self.a3),
            },
            (false, true) => Roles {
                src: Some(self.a3),
                dst: Some(self.a1),
                tx: Some(self.a2),
                bssid: Some(self.a2),
            },
            (true, false) => Roles {
                src: Some(self.a2),
                dst: Some(self.a3),
                tx: Some(self.a2),
                bssid: Some(self.a1),
            },
            (true, true) => Roles {
                src: self.a4,
                dst: Some(self.a3),
                tx: Some(self.a2),
                bssid: None,
            },
        }
    }
}

/// Address roles resolved from ToDS/FromDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roles {
    pub src: Option<[u8; 6]>,
    pub dst: Option<[u8; 6]>,
    pub tx: Option<[u8; 6]>,
    pub bssid: Option<[u8; 6]>,
}

/// Frame control: (protocol version, type, subtype, flags).
pub fn frame_control(f: &[u8]) -> Option<(u8, u8, u8, u8)> {
    let b0 = *f.first()?;
    let b1 = *f.get(1)?;
    Some((b0 & 0x03, (b0 >> 2) & 0x03, b0 >> 4, b1))
}

/// Parse a management or data header. `None` for control/extension frames,
/// protocol versions other than 0, and frames too short for their header.
pub fn parse_header(f: &[u8]) -> Option<Header> {
    let (ver, ftype, subtype, flags) = frame_control(f)?;
    if ver != 0 || !(ftype == TYPE_MGMT || ftype == TYPE_DATA) {
        return None;
    }
    let duration = le16(f, 2)?;
    let a1 = addr(f, 4)?;
    let a2 = addr(f, 10)?;
    let a3 = addr(f, 16)?;
    let seq_ctrl = le16(f, 22)?;
    let mut len = 24usize;
    let mut a4 = None;
    let mut qos = None;
    let mut htc = false;
    if ftype == TYPE_DATA {
        if flags & FL_TO_DS != 0 && flags & FL_FROM_DS != 0 {
            a4 = Some(addr(f, len)?);
            len += 6;
        }
        if subtype & 0x08 != 0 {
            qos = Some(le16(f, len)?);
            len += 2;
            if flags & FL_ORDER != 0 {
                htc = true;
                len += 4;
            }
        }
    } else if flags & FL_ORDER != 0 {
        // +HTC management frame.
        htc = true;
        len += 4;
    }
    if len > f.len() {
        return None;
    }
    Some(Header {
        ftype,
        subtype,
        flags,
        duration,
        a1,
        a2,
        a3,
        a4,
        seq_ctrl,
        qos,
        htc,
        len,
    })
}

/// Row kind for a management/data header (before EAPOL detection).
pub fn kind_of(h: &Header) -> WifiKind {
    if h.ftype == TYPE_DATA {
        return if h.is_null_data() {
            WifiKind::Null
        } else {
            WifiKind::Data
        };
    }
    match h.subtype {
        0 => WifiKind::AssocReq,
        1 => WifiKind::AssocResp,
        2 => WifiKind::ReassocReq,
        3 => WifiKind::ReassocResp,
        4 => WifiKind::ProbeReq,
        5 => WifiKind::ProbeResp,
        8 => WifiKind::Beacon,
        10 => WifiKind::Disassoc,
        11 => WifiKind::Auth,
        12 => WifiKind::Deauth,
        13 | 14 => WifiKind::Action,
        _ => WifiKind::MgmtOther,
    }
}

/// Human name of a management/data/control subtype for the decode tree.
pub fn subtype_name(ftype: u8, subtype: u8) -> &'static str {
    match (ftype, subtype) {
        (TYPE_MGMT, 0) => "Association Request",
        (TYPE_MGMT, 1) => "Association Response",
        (TYPE_MGMT, 2) => "Reassociation Request",
        (TYPE_MGMT, 3) => "Reassociation Response",
        (TYPE_MGMT, 4) => "Probe Request",
        (TYPE_MGMT, 5) => "Probe Response",
        (TYPE_MGMT, 6) => "Timing Advertisement",
        (TYPE_MGMT, 8) => "Beacon frame",
        (TYPE_MGMT, 9) => "ATIM",
        (TYPE_MGMT, 10) => "Disassociate",
        (TYPE_MGMT, 11) => "Authentication",
        (TYPE_MGMT, 12) => "Deauthentication",
        (TYPE_MGMT, 13) => "Action",
        (TYPE_MGMT, 14) => "Action No Ack",
        (TYPE_MGMT, _) => "Management (reserved)",
        (TYPE_CTRL, 2) => "Trigger",
        (TYPE_CTRL, 4) => "Beamforming Report Poll",
        (TYPE_CTRL, 5) => "VHT/HE NDP Announcement",
        (TYPE_CTRL, 7) => "Control Wrapper",
        (TYPE_CTRL, 8) => "Block Ack Request",
        (TYPE_CTRL, 9) => "Block Ack",
        (TYPE_CTRL, 10) => "PS-Poll",
        (TYPE_CTRL, 11) => "Request-to-send",
        (TYPE_CTRL, 12) => "Clear-to-send",
        (TYPE_CTRL, 13) => "Acknowledgement",
        (TYPE_CTRL, 14) => "CF-End",
        (TYPE_CTRL, 15) => "CF-End + CF-Ack",
        (TYPE_CTRL, _) => "Control (reserved)",
        (TYPE_DATA, 0) => "Data",
        (TYPE_DATA, 4) => "Null function (No data)",
        (TYPE_DATA, 8) => "QoS Data",
        (TYPE_DATA, 12) => "QoS Null function (No data)",
        (TYPE_DATA, s) if s & 0x04 != 0 => "Data (no payload)",
        (TYPE_DATA, _) => "Data (CF)",
        _ => "Extension",
    }
}

// ---------------------------------------------------------------------------
// Management body

/// Offset of the first tagged element in a management body, and the length
/// of the fixed fields before it. `None` = no tagged elements for this
/// subtype (deauth, disassoc, action, ...).
pub fn fixed_len(subtype: u8) -> Option<usize> {
    match subtype {
        0 => Some(4),      // capability, listen interval
        1 | 3 => Some(6),  // capability, status, AID
        2 => Some(10),     // capability, listen interval, current AP
        4 => Some(0),      // probe request: elements only
        5 | 8 => Some(12), // timestamp, beacon interval, capability
        // Authentication (11): algorithm, transaction seq, status, then
        // algorithm-specific fields (SAE scalar/element are not elements).
        _ => None,
    }
}

/// Iterator over tagged elements: `(id, offset of the tag byte, data)`.
/// Stops at the first element that does not fit.
pub struct Elements<'a> {
    b: &'a [u8],
    pos: usize,
    /// Set when iteration stopped on a truncated element.
    pub truncated_at: Option<usize>,
}

impl<'a> Elements<'a> {
    pub fn new(b: &'a [u8], start: usize) -> Self {
        Self {
            b,
            pos: start,
            truncated_at: None,
        }
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = (u8, usize, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.b.len() {
            return None;
        }
        let at = self.pos;
        let (Some(&id), Some(&len)) = (self.b.get(at), self.b.get(at + 1)) else {
            self.truncated_at = Some(at);
            self.pos = self.b.len();
            return None;
        };
        let start = at + 2;
        let Some(data) = self.b.get(start..start + usize::from(len)) else {
            self.truncated_at = Some(at);
            self.pos = self.b.len();
            return None;
        };
        self.pos = start + usize::from(len);
        Some((id, at, data))
    }
}

/// AKM suite flags found in an RSN element.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Akms {
    pub psk: bool,
    pub sae: bool,
    pub owe: bool,
    pub other: bool,
}

/// Read the AKM suite list of an RSN element body (after id/len). A body
/// that ends early yields whatever was read (no AKMs = "other RSN").
pub fn rsn_akms(rsn: &[u8]) -> Akms {
    let mut a = Akms::default();
    // version (2), group cipher (4), pairwise count (2) + 4n.
    let Some(pc) = le16(rsn, 6) else {
        return a;
    };
    let akm_at = 8 + 4 * usize::from(pc);
    let Some(ac) = le16(rsn, akm_at) else {
        return a;
    };
    for i in 0..usize::from(ac) {
        let o = akm_at + 2 + 4 * i;
        let Some(s) = rsn.get(o..o + 4) else {
            break;
        };
        if s[..3] != [0x00, 0x0f, 0xac] {
            a.other = true;
            continue;
        }
        match s[3] {
            2 | 6 => a.psk = true,
            8 | 24 => a.sae = true,
            18 => a.owe = true,
            _ => a.other = true,
        }
    }
    a
}

/// `security` string for a beacon / probe response (CONTRACTS §11.1).
pub fn classify_security(capability: u16, rsn: Option<&[u8]>, wpa: bool) -> &'static str {
    if let Some(r) = rsn {
        let a = rsn_akms(r);
        return if a.owe {
            "owe"
        } else if a.sae && a.psk {
            "wpa2/wpa3"
        } else if a.sae {
            "wpa3"
        } else {
            "wpa2"
        };
    }
    if wpa {
        "wpa"
    } else if capability & CAP_PRIVACY != 0 {
        "wep"
    } else {
        "open"
    }
}

/// Vendor element 221 with OUI 00:50:f2 type 1 (WPA1).
pub fn is_wpa_vendor(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0x00, 0x50, 0xf2, 0x01]
}

/// Characters that render as nothing (or reorder/alter neighbouring text) and
/// so could make two different SSIDs look identical: every Unicode Cf
/// (format), Zl/Zp (line/paragraph separators), Hangul fillers, the
/// combining grapheme joiner, variation selectors, Mongolian free variation
/// selectors, the Braille blank and the whole tag block. Cc is checked
/// separately (`char::is_control`). Table from Unicode 15.1, no dependency.
fn is_invisible(c: char) -> bool {
    walleye_core::text::is_invisible(c)
}

/// Combining marks (Mn) of the common combining blocks. Escaped only as the
/// first character of an SSID, where there is no base for them to attach to.
fn is_leading_combining(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036f}' | '\u{0483}'..='\u{0489}' | '\u{0591}'..='\u{05c7}' |
        '\u{0610}'..='\u{061a}' | '\u{064b}'..='\u{065f}' | '\u{0670}' |
        '\u{06d6}'..='\u{06ed}' | '\u{0e31}' | '\u{0e34}'..='\u{0e3a}' |
        '\u{0e47}'..='\u{0e4e}' | '\u{1ab0}'..='\u{1aff}' | '\u{1dc0}'..='\u{1dff}' |
        '\u{20d0}'..='\u{20ff}' | '\u{302a}'..='\u{302f}' | '\u{3099}'..='\u{309a}' |
        '\u{fe20}'..='\u{fe2f}' | '\u{1d165}'..='\u{1d169}' | '\u{1d16d}'..='\u{1d172}' |
        '\u{1d17b}'..='\u{1d182}')
}

/// Length of the UTF-8 sequence a lead byte starts (0 = not a lead byte).
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

/// SSID as printable text (CONTRACTS §11.1).
///
/// - Clipped to 32 bytes. Only when that clip cut a valid multi-byte
///   character in half are its leading bytes dropped; stray or incomplete
///   bytes in an SSID of ≤ 32 bytes are kept as `\xHH`, so "CorpNet" +
///   `e2 80` never equals "CorpNet".
/// - An all-NUL SSID (hidden network placeholder) is "".
/// - Valid UTF-8 is kept, except: `\` → `\\`; ASCII controls and invalid
///   bytes → `\xHH`; other controls, invisible characters (`is_invisible`)
///   and a combining mark in first position → `\u{…}`.
/// - `"` is kept as is; quote with [`quote_ssid`] when splicing into text.
pub fn sanitize_ssid(full: &[u8]) -> String {
    let mut raw = full.get(..full.len().min(MAX_SSID)).unwrap_or(full);
    if raw.iter().all(|&b| b == 0) {
        return String::new();
    }
    if full.len() > MAX_SSID {
        // Did the clip cut a character that was complete in the original?
        for back in 1..=3usize {
            let Some(s) = MAX_SSID.checked_sub(back) else {
                break;
            };
            let n = full.get(s).map_or(0, |&b| utf8_len(b));
            if n > back {
                if full
                    .get(s..s + n)
                    .is_some_and(|ch| std::str::from_utf8(ch).is_ok())
                {
                    raw = raw.get(..s).unwrap_or(raw);
                }
                break;
            }
            if n != 0 {
                break; // a complete character ends at the clip
            }
        }
    }
    let mut out = String::with_capacity(raw.len() + 8);
    let mut first = true;
    for chunk in raw.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '\\' {
                out.push_str("\\\\");
            } else if c.is_ascii_control() {
                out.push_str(&format!("\\x{:02x}", c as u32));
            } else if c.is_control() || is_invisible(c) || (first && is_leading_combining(c)) {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            } else {
                out.push(c);
            }
            first = false;
        }
        for &b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
            first = false;
        }
    }
    out
}

/// `s` in double quotes with `"` escaped as `\"`, for splicing a sanitized
/// SSID into a label or summary. `\` is already escaped by `sanitize_ssid`,
/// so the result is unambiguous.
pub fn quote_ssid(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        if c == '"' {
            q.push_str("\\\"");
        } else {
            q.push(c);
        }
    }
    q.push('"');
    q
}

/// IEEE 802.3 CRC-32 (the 802.11 FCS), bitwise: used once per decoded frame.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// What a management body says, for the `wifi` row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MgmtInfo {
    pub ssid: Option<String>,
    pub security: Option<&'static str>,
    /// DS Parameter Set channel.
    pub channel: Option<u16>,
    pub reason: Option<u16>,
}

/// Summarise a management body (`body` = bytes after the MAC header,
/// without FCS). Protected bodies are not parsed.
pub fn parse_mgmt_body(subtype: u8, body: &[u8]) -> MgmtInfo {
    let mut m = MgmtInfo::default();
    match subtype {
        10 | 12 => m.reason = le16(body, 0),
        11 => m.reason = le16(body, 4),
        1 | 3 => m.reason = le16(body, 2),
        _ => {}
    }
    // Elements are read only where the row uses them: SSID (probe/assoc
    // requests, beacons, probe responses) and security (the latter two).
    if !matches!(subtype, 0 | 2 | 4 | 5 | 8) {
        return m;
    }
    let Some(fixed) = fixed_len(subtype) else {
        return m;
    };
    let is_bss = subtype == 5 || subtype == 8;
    let cap = if is_bss { le16(body, 10) } else { None };
    if is_bss && cap.is_none() {
        // Fixed fields cut short: nothing reliable to report.
        return m;
    }
    let mut rsn: Option<&[u8]> = None;
    let mut wpa = false;
    for (id, _, data) in Elements::new(body, fixed) {
        match id {
            0 if m.ssid.is_none() => m.ssid = Some(sanitize_ssid(data)),
            3 if m.channel.is_none() => m.channel = data.first().map(|&c| u16::from(c)),
            48 if rsn.is_none() => rsn = Some(data),
            221 if is_wpa_vendor(data) => wpa = true,
            _ => {}
        }
    }
    if let Some(c) = cap {
        m.security = Some(classify_security(c, rsn, wpa));
    }
    m
}

// ---------------------------------------------------------------------------
// Whole frame

/// The 802.11 frame inside a capture record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Located {
    /// Offset of the 802.11 frame in the record (radiotap length or 0).
    pub start: usize,
    /// End of the 802.11 frame (before the FCS when one is present).
    pub end: usize,
    pub fcs: bool,
}

/// A parsed management or data frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiFrame {
    pub radiotap: Option<Radiotap>,
    pub at: Located,
    pub header: Header,
    pub kind: WifiKind,
    pub mgmt: MgmtInfo,
    /// Unprotected LLC/SNAP data: (ethertype, offset of the payload in the
    /// record).
    pub snap: Option<(u16, usize)>,
}

impl WifiFrame {
    /// DS Parameter Set channel, else the radiotap frequency's channel.
    pub fn channel(&self) -> Option<u16> {
        self.mgmt
            .channel
            .or_else(|| self.radiotap.as_ref()?.freq().and_then(freq_to_channel))
    }
}

/// Where the 802.11 frame sits in a record. `record_truncated` (caplen <
/// wirelen) means the trailing FCS was not captured, so nothing is dropped.
pub fn locate(
    link_type: u32,
    data: &[u8],
    record_truncated: bool,
) -> Option<(Option<Radiotap>, Located)> {
    let rt = if link_type == walleye_core::LINKTYPE_IEEE802_11_RADIOTAP {
        Some(parse_radiotap(data).ok()?)
    } else {
        None
    };
    let start = rt.as_ref().map_or(0, |r| r.len);
    let fcs =
        rt.as_ref().is_some_and(Radiotap::has_fcs) && !record_truncated && data.len() >= start + 4;
    let end = if fcs { data.len() - 4 } else { data.len() };
    Some((rt, Located { start, end, fcs }))
}

/// LLC/SNAP encapsulations of an 802.11 data payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Snap {
    /// `aa aa 03` + OUI 00:00:00 (RFC 1042) or 00:00:f8 (bridge tunnel) +
    /// ethertype: payload at +8.
    Ether(u16),
    /// Apple Wireless Direct Link data: OUI 00:17:f2, PID 0x0800, then an
    /// 8-byte AWDL header (`03 04`, sequence, reserved, ethertype): payload
    /// at +16. AirDrop/AirPlay peers send mDNS and IPv6 this way unencrypted.
    Awdl(u16),
}

impl Snap {
    pub fn ethertype(self) -> u16 {
        match self {
            Snap::Ether(t) | Snap::Awdl(t) => t,
        }
    }
    /// Bytes from the start of the LLC header to the network payload.
    pub fn header_len(self) -> usize {
        match self {
            Snap::Ether(_) => 8,
            Snap::Awdl(_) => 16,
        }
    }
}

/// Recognise the LLC/SNAP header at the start of an unprotected data body.
pub fn snap(body: &[u8]) -> Option<Snap> {
    let h = body.get(..8)?;
    if h[..3] != [0xaa, 0xaa, 0x03] {
        return None;
    }
    let pid = u16::from_be_bytes([h[6], h[7]]);
    if h[3..6] == [0, 0, 0] || h[3..6] == [0, 0, 0xf8] {
        return Some(Snap::Ether(pid));
    }
    if h[3..6] == [0x00, 0x17, 0xf2] && pid == 0x0800 {
        let a = body.get(8..16)?;
        if a[..2] == [0x03, 0x04] {
            return Some(Snap::Awdl(u16::from_be_bytes([a[6], a[7]])));
        }
    }
    None
}

/// Ethertype of a plain (RFC 1042 / bridge-tunnel) LLC/SNAP header.
pub fn snap_ethertype(body: &[u8]) -> Option<u16> {
    match snap(body)? {
        Snap::Ether(t) => Some(t),
        Snap::Awdl(_) => None,
    }
}

/// Parse one record of link type 105/127 into a `wifi` row's worth of data.
/// `None` for control and extension frames, unknown protocol versions, a
/// bad radiotap header, and frames too short for their MAC header.
pub fn parse_frame(link_type: u32, data: &[u8], record_truncated: bool) -> Option<WifiFrame> {
    let (radiotap, at) = locate(link_type, data, record_truncated)?;
    let f = data.get(at.start..at.end)?;
    let header = parse_header(f)?;
    let mut body_off = header.len;
    if radiotap.as_ref().is_some_and(Radiotap::data_pad) {
        body_off = body_off.div_ceil(4) * 4;
    }
    let body = f.get(body_off..).unwrap_or(&[]);
    let mut kind = kind_of(&header);
    let mut mgmt = MgmtInfo::default();
    let mut snap = None;
    if header.ftype == TYPE_MGMT {
        if !header.protected() {
            mgmt = parse_mgmt_body(header.subtype, body);
        }
    } else if kind == WifiKind::Data && !header.protected() {
        // A-MSDU (QoS control bit 7) carries subframes, not one LLC header.
        let amsdu = header.qos.is_some_and(|q| q & 0x0080 != 0);
        if !amsdu {
            match self::snap(body) {
                Some(Snap::Ether(ETHERTYPE_EAPOL)) => kind = WifiKind::Eapol,
                Some(s) => snap = Some((s.ethertype(), at.start + body_off + s.header_len())),
                None => {}
            }
        }
    }
    Some(WifiFrame {
        radiotap,
        at,
        header,
        kind,
        mgmt,
        snap,
    })
}

/// Build the `wifi` table row.
pub fn row(
    w: &WifiFrame,
    ts: walleye_core::Ts,
    frame_no: u64,
    wirelen: u32,
) -> walleye_core::WifiRow {
    let r = w.header.roles();
    let rt_len = w.at.start;
    let fcs = if w.radiotap.as_ref().is_some_and(Radiotap::has_fcs) {
        4
    } else {
        0
    };
    let len = (wirelen as usize)
        .saturating_sub(rt_len)
        .saturating_sub(fcs);
    walleye_core::WifiRow {
        ts,
        frame_no,
        kind: w.kind,
        protected: w.header.protected(),
        retry: w.header.retry(),
        src: r.src.as_ref().map(mac_string),
        dst: r.dst.as_ref().map(mac_string),
        tx: r.tx.as_ref().map(mac_string),
        bssid: r.bssid.as_ref().map(mac_string),
        channel: w.channel(),
        freq_mhz: w.radiotap.as_ref().and_then(Radiotap::freq),
        signal_dbm: w
            .radiotap
            .as_ref()
            .and_then(|r| r.signal)
            .map(|(s, _)| i16::from(s)),
        ssid: w.mgmt.ssid.clone(),
        security: w.mgmt.security.map(str::to_string),
        reason: w.mgmt.reason,
        seq: Some(w.header.seq()),
        len: u32::try_from(len).unwrap_or(u32::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const STA: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    const DST: [u8; 6] = [0x00, 0x0c, 0x29, 0x01, 0x02, 0x03];
    const BC: [u8; 6] = [0xff; 6];

    fn hdr(fc0: u8, fc1: u8, a1: [u8; 6], a2: [u8; 6], a3: [u8; 6]) -> Vec<u8> {
        let mut v = vec![fc0, fc1, 0, 0];
        v.extend_from_slice(&a1);
        v.extend_from_slice(&a2);
        v.extend_from_slice(&a3);
        v.extend_from_slice(&(0x0123u16 << 4).to_le_bytes());
        v
    }

    /// Radiotap with Flags, Channel and dBm signal (present 0x2a).
    fn rt(flags: u8, freq: u16, signal: i8) -> Vec<u8> {
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(&0x0000_002au32.to_le_bytes());
        v.push(flags); // 8
        v.push(0); // pad to 10 for Channel
        v.extend_from_slice(&freq.to_le_bytes());
        v.extend_from_slice(&0x00a0u16.to_le_bytes());
        v.push(signal as u8); // 14
        let len = v.len() as u16;
        v[2..4].copy_from_slice(&len.to_le_bytes());
        v
    }

    fn beacon_body(cap: u16, ssid: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&100u16.to_le_bytes());
        b.extend_from_slice(&cap.to_le_bytes());
        b.push(0);
        b.push(ssid.len() as u8);
        b.extend_from_slice(ssid);
        b.extend_from_slice(&[3, 1, 6]);
        b.extend_from_slice(extra);
        b
    }

    fn rsn(akms: &[u8]) -> Vec<u8> {
        let mut r = vec![1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4];
        r.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for &a in akms {
            r.extend_from_slice(&[0x00, 0x0f, 0xac, a]);
        }
        r.extend_from_slice(&[0, 0]);
        let mut e = vec![48, r.len() as u8];
        e.extend_from_slice(&r);
        e
    }

    #[test]
    fn radiotap_alignment_after_channel_with_padding() {
        // TSFT(0) + Flags(1) + Rate(2) + Channel(3) + Signal(5): TSFT is
        // 8-aligned at 8, flags 16, rate 17, channel 18 (2-aligned), signal 22.
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(&0x0000_002fu32.to_le_bytes());
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v.push(RT_FLAG_FCS);
        v.push(0x0c);
        v.extend_from_slice(&5180u16.to_le_bytes());
        v.extend_from_slice(&0x0140u16.to_le_bytes());
        v.push((-61i8) as u8);
        v.push(0); // trailing pad
        let n = v.len() as u16;
        v[2..4].copy_from_slice(&n.to_le_bytes());
        let r = parse_radiotap(&v).expect("test input");
        assert_eq!(r.len, 24);
        assert_eq!(r.flags, Some((RT_FLAG_FCS, 16)));
        assert_eq!(r.channel, Some((5180, 0x0140, 18)));
        assert_eq!(r.signal, Some((-61, 22)));
        assert!(r.has_fcs() && !r.bad_fcs());
        assert_eq!(freq_to_channel(5180), Some(36));

        // Flags + Channel without Rate: channel must be padded from 9 to 10.
        let r = parse_radiotap(&rt(0, 2437, -40)).expect("test input");
        assert_eq!(r.channel, Some((2437, 0x00a0, 10)));
        assert_eq!(r.signal, Some((-40, 14)));
        assert_eq!(freq_to_channel(2437), Some(6));
    }

    #[test]
    fn radiotap_extended_present_bitmaps() {
        // Three present words (bit 31 chains); fields start at 16, and TSFT
        // aligns to 16; then Flags at 24, Channel at 26, signal at 30.
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(&(0x8000_002bu32 | 0x2000_0000).to_le_bytes());
        v.extend_from_slice(&0x8000_0020u32.to_le_bytes());
        v.extend_from_slice(&0x0000_0020u32.to_le_bytes());
        v.extend_from_slice(&[0u8; 8]); // TSFT at 16
        v.push(RT_FLAG_FCS | RT_FLAG_BAD_FCS); // 24
        v.push(0); // 25 pad
        v.extend_from_slice(&2412u16.to_le_bytes()); // 26
        v.extend_from_slice(&0u16.to_le_bytes());
        v.push((-70i8) as u8); // 30
        v.extend_from_slice(&[(-71i8) as u8, (-72i8) as u8]); // later antennas
        let n = v.len() as u16;
        v[2..4].copy_from_slice(&n.to_le_bytes());
        let r = parse_radiotap(&v).expect("test input");
        assert_eq!(r.present_words, 3);
        assert_eq!(r.flags.map(|f| f.1), Some(24));
        assert_eq!(r.channel.map(|c| (c.0, c.2)), Some((2412, 26)));
        assert_eq!(r.signal, Some((-70, 30)));
        assert!(r.bad_fcs());

        // A chain that runs past it_len is malformed, not a panic.
        let mut bad = vec![0, 0, 8, 0];
        bad.extend_from_slice(&0x8000_0000u32.to_le_bytes());
        assert_eq!(parse_radiotap(&bad), Err(RadiotapError::Malformed));
        // An endless chain inside a large it_len is cut off.
        let mut endless = vec![0, 0, 0, 0];
        for _ in 0..200 {
            endless.extend_from_slice(&0x8000_0000u32.to_le_bytes());
        }
        let n = endless.len() as u16;
        endless[2..4].copy_from_slice(&n.to_le_bytes());
        assert_eq!(parse_radiotap(&endless), Err(RadiotapError::Malformed));
    }

    #[test]
    fn radiotap_rejects_bad_headers_and_short_fields() {
        assert_eq!(parse_radiotap(&[0, 0, 8]), Err(RadiotapError::Truncated));
        assert_eq!(
            parse_radiotap(&[1, 0, 8, 0, 0, 0, 0, 0]),
            Err(RadiotapError::Malformed)
        );
        assert_eq!(
            parse_radiotap(&[0, 0, 4, 0, 0, 0, 0, 0]),
            Err(RadiotapError::Malformed)
        );
        assert_eq!(
            parse_radiotap(&[0, 0, 200, 0, 0, 0, 0, 0]),
            Err(RadiotapError::Truncated)
        );
        // Channel claimed but it_len ends after Flags: fields left unset.
        let v = [0, 0, 9, 0, 0x0a, 0, 0, 0, RT_FLAG_FCS];
        let r = parse_radiotap(&v).expect("test input");
        assert_eq!(r.flags, Some((RT_FLAG_FCS, 8)));
        assert_eq!(r.channel, None);
    }

    #[test]
    fn fcs_flag_drops_trailing_four_bytes() {
        let mut rec = rt(RT_FLAG_FCS, 2437, -50);
        let rtlen = rec.len();
        rec.extend_from_slice(&hdr(0xc0, 0, STA, AP, AP));
        rec.extend_from_slice(&7u16.to_le_bytes());
        rec.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let w = parse_frame(127, &rec, false).expect("test input");
        assert!(w.at.fcs);
        assert_eq!(w.at.end, rec.len() - 4);
        assert_eq!(w.kind, WifiKind::Deauth);
        assert_eq!(w.mgmt.reason, Some(7));
        let row = row(&w, 1, 1, rec.len() as u32);
        assert_eq!(row.len as usize, rec.len() - rtlen - 4);
        assert_eq!(row.channel, Some(6));
        assert_eq!(row.signal_dbm, Some(-50));
        // Snapped record: the FCS was not captured, nothing is dropped.
        let w = parse_frame(127, &rec, true).expect("test input");
        assert!(!w.at.fcs);
    }

    #[test]
    fn address_roles_for_all_ds_combinations() {
        let m = |a: [u8; 6]| Some(a);
        // ToDS=0 FromDS=0 (IBSS / direct): A1=DA, A2=SA, A3=BSSID.
        let h = parse_header(&hdr(0x08, 0x00, DST, STA, AP)).expect("test input");
        assert_eq!(
            h.roles(),
            Roles {
                src: m(STA),
                dst: m(DST),
                tx: m(STA),
                bssid: m(AP)
            }
        );
        // FromDS: A1=DA, A2=BSSID (TA), A3=SA.
        let h = parse_header(&hdr(0x08, FL_FROM_DS, STA, AP, DST)).expect("test input");
        assert_eq!(
            h.roles(),
            Roles {
                src: m(DST),
                dst: m(STA),
                tx: m(AP),
                bssid: m(AP)
            }
        );
        // ToDS: A1=BSSID (RA), A2=SA, A3=DA.
        let h = parse_header(&hdr(0x08, FL_TO_DS, AP, STA, DST)).expect("test input");
        assert_eq!(
            h.roles(),
            Roles {
                src: m(STA),
                dst: m(DST),
                tx: m(STA),
                bssid: m(AP)
            }
        );
        // ToDS+FromDS (WDS/mesh): A1=RA, A2=TA, A3=DA, A4=SA, no BSSID.
        let mut f = hdr(0x08, FL_TO_DS | FL_FROM_DS, AP, BC, DST);
        f[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x66]);
        f.extend_from_slice(&STA);
        let h = parse_header(&f).expect("test input");
        assert_eq!(h.len, 30);
        assert_eq!(
            h.roles(),
            Roles {
                src: m(STA),
                dst: m(DST),
                tx: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]),
                bssid: None
            }
        );
        // Four-address header cut before A4: no header.
        assert!(parse_header(&f[..28]).is_none());
        // Management frames always DA/SA/BSSID.
        let h = parse_header(&hdr(0x80, 0, BC, AP, AP)).expect("test input");
        assert_eq!(h.roles().dst, m(BC));
        assert_eq!(h.roles().bssid, m(AP));
    }

    #[test]
    fn qos_and_htc_header_lengths() {
        let mut f = hdr(0x88, FL_TO_DS | FL_ORDER, AP, STA, DST);
        f.extend_from_slice(&[0, 0, 1, 2, 3, 4]);
        let h = parse_header(&f).expect("test input");
        assert_eq!(h.qos, Some(0));
        assert!(h.htc);
        assert_eq!(h.len, 30);
        assert!(parse_header(&f[..29]).is_none());
        // Non-QoS data with Order set has no HT Control.
        let h = parse_header(&hdr(0x08, FL_ORDER, AP, STA, DST)).expect("test input");
        assert_eq!(h.len, 24);
        // Control frames and version 1 produce no header.
        assert!(parse_header(&[0xd4, 0, 0, 0, 1, 2, 3, 4, 5, 6]).is_none());
        let mut v1 = hdr(0x80, 0, BC, AP, AP);
        v1[0] |= 1;
        assert!(parse_header(&v1).is_none());
    }

    fn sec(body: &[u8]) -> Option<&'static str> {
        parse_mgmt_body(8, body).security
    }

    #[test]
    fn security_classification() {
        assert_eq!(sec(&beacon_body(0x0001, b"a", &[])), Some("open"));
        assert_eq!(sec(&beacon_body(0x0011, b"a", &[])), Some("wep"));
        let wpa = [221, 6, 0x00, 0x50, 0xf2, 0x01, 1, 0];
        assert_eq!(sec(&beacon_body(0x0011, b"a", &wpa)), Some("wpa"));
        assert_eq!(sec(&beacon_body(0x0011, b"a", &rsn(&[2]))), Some("wpa2"));
        assert_eq!(sec(&beacon_body(0x0011, b"a", &rsn(&[1]))), Some("wpa2"));
        assert_eq!(sec(&beacon_body(0x0011, b"a", &rsn(&[8]))), Some("wpa3"));
        assert_eq!(
            sec(&beacon_body(0x0011, b"a", &rsn(&[2, 8]))),
            Some("wpa2/wpa3")
        );
        assert_eq!(sec(&beacon_body(0x0011, b"a", &rsn(&[18]))), Some("owe"));
        // RSN wins over the WPA vendor element (mixed WPA/WPA2).
        let mut both = rsn(&[2]);
        both.extend_from_slice(&wpa);
        assert_eq!(sec(&beacon_body(0x0011, b"a", &both)), Some("wpa2"));
        // RSN cut short before the AKM list: still RSN → wpa2.
        assert_eq!(
            sec(&beacon_body(0x0011, b"a", &[48, 2, 1, 0])),
            Some("wpa2")
        );
        // Probe response uses the same rules; probe request has none.
        assert_eq!(
            parse_mgmt_body(5, &beacon_body(0x0011, b"a", &rsn(&[8]))).security,
            Some("wpa3")
        );
        let mut pr = vec![0, 3];
        pr.extend_from_slice(b"Net");
        let m = parse_mgmt_body(4, &pr);
        assert_eq!(m.ssid.as_deref(), Some("Net"));
        assert_eq!(m.security, None);
    }

    #[test]
    fn ssid_sanitizing() {
        assert_eq!(sanitize_ssid(b"HomeNet"), "HomeNet");
        assert_eq!(sanitize_ssid(b"a\x00b\x1b[31m\n"), "a\\x00b\\x1b[31m\\x0a");
        assert_eq!(sanitize_ssid(b"back\\slash"), "back\\\\slash");
        assert_eq!(sanitize_ssid(&[0, 0, 0, 0]), "");
        assert_eq!(sanitize_ssid(b""), "");
        let long = [b'x'; 40];
        assert_eq!(sanitize_ssid(&long), "x".repeat(32));
        assert_eq!(sanitize_ssid("Café ☕".as_bytes()), "Café ☕");
        // Bidi override is escaped, not rendered.
        assert_eq!(sanitize_ssid("ab\u{202e}cd".as_bytes()), "ab\\u{202e}cd");
        // Invalid UTF-8 falls back to byte escapes.
        assert_eq!(sanitize_ssid(&[b'a', 0xff, b'b']), "a\\xffb");
        // A multi-byte char cut at 32 bytes keeps the valid prefix.
        let mut cut = vec![b'y'; 31];
        cut.extend_from_slice("é".as_bytes());
        assert_eq!(sanitize_ssid(&cut), "y".repeat(31));
        // Through a beacon body.
        let m = parse_mgmt_body(8, &beacon_body(1, b"evil\x07\x7f", &[]));
        assert_eq!(m.ssid.as_deref(), Some("evil\\x07\\x7f"));
        assert_eq!(m.channel, Some(6));
    }

    /// Security review M2: stray trailing bytes are not silently dropped.
    #[test]
    fn ssid_stray_trailing_bytes_are_escaped_not_dropped() {
        let spoof = [b'C', b'o', b'r', b'p', b'N', b'e', b't', 0xe2, 0x80];
        assert_eq!(sanitize_ssid(&spoof), "CorpNet\\xe2\\x80");
        assert_ne!(sanitize_ssid(&spoof), sanitize_ssid(b"CorpNet"));
        assert_eq!(sanitize_ssid(&[b'N', b'e', b't', 0xf0]), "Net\\xf0");
        assert_eq!(sanitize_ssid(&[0xe2, 0x80]), "\\xe2\\x80");
        // Exactly 32 bytes ending in an incomplete char: nothing was clipped.
        let mut x = vec![b'z'; 30];
        x.extend_from_slice(&[0xe2, 0x82]);
        assert_eq!(sanitize_ssid(&x), format!("{}\\xe2\\x82", "z".repeat(30)));
        // 34 bytes whose 32nd byte starts a char the clip cut: dropped.
        let mut y = vec![b'z'; 31];
        y.extend_from_slice("€".as_bytes());
        assert_eq!(sanitize_ssid(&y), "z".repeat(31));
        // Clip cutting an already-invalid sequence keeps it escaped.
        let mut z = vec![b'z'; 31];
        z.extend_from_slice(&[0xe2, 0x41, 0x41]);
        assert_eq!(sanitize_ssid(&z), format!("{}\\xe2", "z".repeat(31)));
        // A char ending exactly at 32 bytes is kept.
        let mut w = vec![b'z'; 29];
        w.extend_from_slice("€".as_bytes());
        w.push(b'!');
        assert_eq!(sanitize_ssid(&w), format!("{}€", "z".repeat(29)));
        // Valid text around invalid bytes stays readable.
        assert_eq!(sanitize_ssid(&[0xff, b'C', 0xc3, 0xa9]), "\\xffCé");
    }

    /// Security review M3: invisible characters cannot make look-alikes.
    #[test]
    fn ssid_invisible_characters_are_escaped() {
        let cases = [
            ("CorpNet\u{e0041}", "CorpNet\\u{e0041}"),
            ("Corp\u{e0001}Net", "Corp\\u{e0001}Net"),
            ("Corp\u{115f}Net", "Corp\\u{115f}Net"),
            ("Corp\u{1160}Net", "Corp\\u{1160}Net"),
            ("Corp\u{3164}Net", "Corp\\u{3164}Net"),
            ("Corp\u{ffa0}Net", "Corp\\u{ffa0}Net"),
            ("Corp\u{034f}Net", "Corp\\u{34f}Net"),
            ("CorpNet\u{fe0f}", "CorpNet\\u{fe0f}"),
            ("CorpNet\u{e0100}", "CorpNet\\u{e0100}"),
            ("Corp\u{180b}Net", "Corp\\u{180b}Net"),
            ("Corp\u{2028}Net\u{2029}", "Corp\\u{2028}Net\\u{2029}"),
            ("Corp\u{200b}Net", "Corp\\u{200b}Net"),
            ("\u{0600}Net", "\\u{600}Net"),
            ("Corp\u{2800}Net", "Corp\\u{2800}Net"),
            ("Corp\u{85}Net", "Corp\\u{85}Net"),
            // A combining mark with no base; with a base it is kept.
            ("\u{0301}CorpNet", "\\u{301}CorpNet"),
            ("Cafe\u{0301}", "Cafe\u{0301}"),
        ];
        for (input, want) in cases {
            assert_eq!(sanitize_ssid(input.as_bytes()), want, "{input:?}");
        }
        // Visible non-ASCII stays as is.
        for ok in ["Café", "Пример", "東京-WiFi", "☕ Bar", "ﾛﾋﾞｰ"] {
            assert_eq!(sanitize_ssid(ok.as_bytes()), ok);
        }
    }

    /// Security review M4: `"` stays raw in the column, escaped when quoted.
    #[test]
    fn ssid_quotes_are_escaped_when_spliced() {
        let s = sanitize_ssid(br#"Free" ch 6 wpa3"#);
        assert_eq!(s, r#"Free" ch 6 wpa3"#);
        assert_eq!(quote_ssid(&s), r#""Free\" ch 6 wpa3""#);
        // Backslash before a quote cannot un-escape it.
        let t = sanitize_ssid(br#"a\"b"#);
        assert_eq!(t, r#"a\\"b"#);
        assert_eq!(quote_ssid(&t), r#""a\\\"b""#);
        assert_eq!(quote_ssid(""), r#""""#);
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn reason_and_status_codes() {
        assert_eq!(parse_mgmt_body(12, &[7, 0]).reason, Some(7));
        assert_eq!(parse_mgmt_body(10, &[8, 0]).reason, Some(8));
        assert_eq!(parse_mgmt_body(11, &[0, 0, 2, 0, 17, 0]).reason, Some(17));
        assert_eq!(parse_mgmt_body(1, &[1, 0, 0, 0, 1, 0xc0]).reason, Some(0));
        assert_eq!(parse_mgmt_body(12, &[7]).reason, None);
    }

    #[test]
    fn data_frames_snap_eapol_protected() {
        let llc = |et: u16| {
            let mut v = vec![0xaa, 0xaa, 0x03, 0, 0, 0];
            v.extend_from_slice(&et.to_be_bytes());
            v
        };
        let mut f = hdr(0x88, FL_TO_DS, AP, STA, DST);
        f.extend_from_slice(&[0, 0]);
        let base = f.clone();
        f.extend_from_slice(&llc(0x0800));
        f.extend_from_slice(&[0x45; 20]);
        let w = parse_frame(105, &f, false).expect("test input");
        assert_eq!(w.kind, WifiKind::Data);
        assert_eq!(w.snap, Some((0x0800, 34)));

        let mut e = base.clone();
        e.extend_from_slice(&llc(ETHERTYPE_EAPOL));
        e.extend_from_slice(&[2, 3, 0, 0]);
        let w = parse_frame(105, &e, false).expect("test input");
        assert_eq!(w.kind, WifiKind::Eapol);
        assert_eq!(w.snap, None);

        let mut p = hdr(0x88, FL_TO_DS | FL_PROTECTED, AP, STA, DST);
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&llc(0x0800)); // looks like SNAP but is ciphertext
        let w = parse_frame(105, &p, false).expect("test input");
        assert_eq!(w.kind, WifiKind::Data);
        assert!(w.header.protected());
        assert_eq!(w.snap, None);

        // Apple AWDL data: SNAP OUI 00:17:f2 + 8-byte AWDL header.
        let mut a = hdr(0x08, 0, BC, STA, AP);
        a.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00]);
        a.extend_from_slice(&[0x03, 0x04, 5, 0, 0, 0, 0x86, 0xdd]);
        a.extend_from_slice(&[0x60; 40]);
        let w = parse_frame(105, &a, false).expect("test input");
        assert_eq!(w.snap, Some((0x86dd, 40)));
        assert_eq!(snap(&a[24..30]), None);

        let n = hdr(0x48, FL_TO_DS | FL_PWR_MGMT, AP, STA, AP);
        assert_eq!(
            parse_frame(105, &n, false).expect("test input").kind,
            WifiKind::Null
        );
    }

    #[test]
    fn truncated_frames_produce_no_frame() {
        let mut rec = rt(0, 2412, -30);
        let full = {
            let mut f = hdr(0x80, 0, BC, AP, AP);
            f.extend_from_slice(&beacon_body(0x0011, b"Net", &rsn(&[2])));
            f
        };
        rec.extend_from_slice(&full);
        let rtlen = rec.len() - full.len();
        for cut in 0..rtlen + 24 {
            assert!(parse_frame(127, &rec[..cut], true).is_none(), "cut {cut}");
        }
        // Header complete but body cut anywhere: a row, never a panic.
        for cut in rtlen + 24..=rec.len() {
            let w = parse_frame(127, &rec[..cut], true).expect("test input");
            assert_eq!(w.kind, WifiKind::Beacon);
        }
        // Every prefix of every kind of record never panics.
        let mut d = rt(RT_FLAG_FCS | RT_FLAG_DATA_PAD, 5180, -80);
        d.extend_from_slice(&hdr(0x88, FL_TO_DS | FL_FROM_DS | FL_ORDER, AP, STA, DST));
        d.extend_from_slice(&[
            1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 3, 0, 0, 0, 8, 0,
        ]);
        for cut in 0..=d.len() {
            let _ = parse_frame(127, &d[..cut], false);
            let _ = parse_frame(105, &d[..cut], false);
        }
    }

    #[test]
    fn mac_string_matches_core() {
        let a = [0x42, 0x75, 0xc3, 0xd8, 0xbb, 0x9c];
        assert_eq!(mac_string(&a), walleye_core::mac::mac_text(&a));
    }
}
