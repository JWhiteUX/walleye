//! Decode tree for 802.11 frames (link types 105 and 127, CONTRACTS §11.1):
//! "Radiotap header", "IEEE 802.11 <subtype>", then "Management body",
//! LLC/SNAP + the existing IP decode, "802.1X Authentication", or
//! "Encrypted data (N bytes)", and the FCS. Every range is clamped to the
//! frame (fuzzed by `ingest_decode_frame`).

use walleye_core::ipc::DecodeNode;

use crate::decode::{ethertype, leaf, tree, warn};
use crate::util::hex;
use crate::wifi::{
    self, ETHERTYPE_EAPOL, Elements, FL_FROM_DS, FL_MORE_DATA, FL_MORE_FRAG, FL_ORDER,
    FL_PROTECTED, FL_PWR_MGMT, FL_RETRY, FL_TO_DS, Header, Radiotap, RadiotapError, TYPE_CTRL,
    TYPE_DATA, TYPE_MGMT, frame_control, mac_string, parse_radiotap, subtype_name,
};

pub const F_WIFI_SRC: &str = "wifi.src";
pub const F_WIFI_DST: &str = "wifi.dst";
pub const F_WIFI_TX: &str = "wifi.tx";
pub const F_WIFI_BSSID: &str = "wifi.bssid";
pub const F_WIFI_SSID: &str = "wifi.ssid";
pub const F_WIFI_SECURITY: &str = "wifi.security";
pub const F_WIFI_CHANNEL: &str = "wifi.channel";
pub const F_WIFI_FREQ: &str = "wifi.freq";
pub const F_WIFI_SIGNAL: &str = "wifi.signal";
pub const F_WIFI_REASON: &str = "wifi.reason";
pub const F_WIFI_PROTECTED: &str = "wifi.protected";
pub const F_WIFI_RETRY: &str = "wifi.retry";

/// Most tagged elements listed per frame (the rest get one summary node).
const MAX_TAGS: usize = 255;

/// Clamp `(start, len)` to a buffer of `blen` bytes.
fn fit(blen: usize, start: usize, len: usize) -> (usize, usize) {
    let s = start.min(blen);
    (s, len.min(blen - s))
}

fn node(label: impl Into<String>, start: usize, len: usize, blen: usize) -> DecodeNode {
    let (s, l) = fit(blen, start, len);
    tree(label, s, l)
}

/// Leaf whose label shows `shown` but whose `value` is the bare filter value.
fn valued(
    name: &str,
    field: Option<&str>,
    value: String,
    shown: String,
    start: usize,
    len: usize,
    blen: usize,
) -> DecodeNode {
    let (s, l) = fit(blen, start, len);
    let mut n = leaf(name, field, value, s, l);
    n.label = format!("{name}: {shown}");
    n
}

fn plain(
    name: &str,
    field: Option<&str>,
    value: String,
    start: usize,
    len: usize,
    blen: usize,
) -> DecodeNode {
    let (s, l) = fit(blen, start, len);
    leaf(name, field, value, s, l)
}

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o.checked_add(1)?)?]))
}

/// Entry point from `decode_frame`.
pub fn decode(link_type: u32, b: &[u8], nodes: &mut Vec<DecodeNode>) {
    let blen = b.len();
    let mut start = 0usize;
    let mut rt: Option<Radiotap> = None;
    if link_type == walleye_core::LINKTYPE_IEEE802_11_RADIOTAP {
        match parse_radiotap(b) {
            Ok(r) => {
                nodes.push(radiotap_node(&r, blen));
                start = r.len;
                rt = Some(r);
            }
            Err(e) => {
                let w = match e {
                    RadiotapError::Truncated => "truncated",
                    RadiotapError::Malformed => "malformed radiotap header",
                };
                nodes.push(warn(node("Radiotap header", 0, blen, blen), w));
                return;
            }
        }
    }
    // Same rule as ingest (`wifi::fcs_present`): the trailing 4 bytes are the
    // FCS only if the CRC matches or the radio flagged a bad FCS. We get the
    // captured bytes only, so a record is treated as complete here; ingest,
    // which knows caplen < wirelen, additionally never strips snapped
    // records, and their trailers fail the CRC, so both agree.
    let fcs_flag = rt.as_ref().is_some_and(Radiotap::has_fcs) && blen >= start + 4;
    let bad_fcs = rt.as_ref().is_some_and(Radiotap::bad_fcs);
    let fcs = wifi::fcs_present(rt.as_ref(), b, false);
    let end = if fcs { blen - 4 } else { blen };
    let frame = b.get(..end).unwrap_or(b);
    dot11(link_type, b, frame, start, rt.as_ref(), nodes);
    if fcs_flag && !fcs {
        nodes.push(warn(
            plain(
                "Trailing 4 bytes",
                None,
                format!("0x{}", hex(b.get(blen - 4..).unwrap_or(&[]))),
                blen - 4,
                4,
                blen,
            ),
            "FCS flag set but the checksum does not match (corrupted FCS or snapped frame): decoded as frame bytes",
        ));
    }
    if fcs {
        let mut n = plain(
            "Frame check sequence",
            None,
            format!("0x{}", hex(b.get(end..).unwrap_or(&[]))),
            end,
            4,
            blen,
        );
        if bad_fcs {
            n.warning = Some("bad FCS (the radio reported a checksum error)".into());
        }
        nodes.push(n);
    }
}

fn radiotap_node(r: &Radiotap, blen: usize) -> DecodeNode {
    let mut n = node("Radiotap header", 0, r.len, blen);
    let c = &mut n.children;
    c.push(plain("Header length", None, r.len.to_string(), 2, 2, blen));
    c.push(plain(
        "Present flags",
        None,
        format!(
            "0x{:08x}{}",
            r.present,
            if r.present_words > 1 {
                format!(" (+{} more words)", r.present_words - 1)
            } else {
                String::new()
            }
        ),
        4,
        4 * r.present_words,
        blen,
    ));
    if let Some((f, off)) = r.flags {
        let mut parts = Vec::new();
        if f & wifi::RT_FLAG_FCS != 0 {
            parts.push("FCS at end");
        }
        if f & wifi::RT_FLAG_DATA_PAD != 0 {
            parts.push("data pad");
        }
        if f & wifi::RT_FLAG_BAD_FCS != 0 {
            parts.push("bad FCS");
        }
        let shown = if parts.is_empty() {
            format!("0x{f:02x}")
        } else {
            format!("0x{f:02x} ({})", parts.join(", "))
        };
        let mut l = plain("Flags", None, shown, off, 1, blen);
        if f & wifi::RT_FLAG_BAD_FCS != 0 {
            l.warning = Some("bad FCS".into());
        }
        c.push(l);
    }
    if let Some((freq, _, off)) = r.channel {
        c.push(valued(
            "Channel frequency",
            Some(F_WIFI_FREQ),
            freq.to_string(),
            format!("{freq} MHz"),
            off,
            2,
            blen,
        ));
        if let Some(ch) = wifi::freq_to_channel(freq) {
            c.push(plain(
                "Channel",
                Some(F_WIFI_CHANNEL),
                ch.to_string(),
                off,
                2,
                blen,
            ));
        }
    }
    if let Some((s, off)) = r.signal {
        c.push(valued(
            "Antenna signal",
            Some(F_WIFI_SIGNAL),
            s.to_string(),
            format!("{s} dBm"),
            off,
            1,
            blen,
        ));
    }
    if r.bad_fcs() {
        n.warning = Some("bad FCS".into());
    }
    n
}

fn flag_text(flags: u8) -> String {
    let names = [
        (FL_TO_DS, "ToDS"),
        (FL_FROM_DS, "FromDS"),
        (FL_MORE_FRAG, "More fragments"),
        (FL_RETRY, "Retry"),
        (FL_PWR_MGMT, "Power management"),
        (FL_MORE_DATA, "More data"),
        (FL_PROTECTED, "Protected"),
        (FL_ORDER, "+HTC/Order"),
    ];
    let set: Vec<&str> = names
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() {
        format!("0x{flags:02x}")
    } else {
        format!("0x{flags:02x} ({})", set.join(", "))
    }
}

/// (offset in the header, label, filter field) for each address.
fn address_slots(h: &Header) -> Vec<(usize, &'static str, Option<&'static str>)> {
    if h.ftype == TYPE_MGMT {
        return vec![
            (4, "Destination address", Some(F_WIFI_DST)),
            (10, "Source address", Some(F_WIFI_SRC)),
            (16, "BSSID", Some(F_WIFI_BSSID)),
        ];
    }
    match (h.to_ds(), h.from_ds()) {
        (false, false) => vec![
            (4, "Destination address", Some(F_WIFI_DST)),
            (10, "Source address", Some(F_WIFI_SRC)),
            (16, "BSSID", Some(F_WIFI_BSSID)),
        ],
        (false, true) => vec![
            (4, "Destination address", Some(F_WIFI_DST)),
            (10, "BSSID (transmitter)", Some(F_WIFI_BSSID)),
            (16, "Source address", Some(F_WIFI_SRC)),
        ],
        (true, false) => vec![
            (4, "BSSID (receiver)", Some(F_WIFI_BSSID)),
            (10, "Source address", Some(F_WIFI_SRC)),
            (16, "Destination address", Some(F_WIFI_DST)),
        ],
        (true, true) => vec![
            (4, "Receiver address", None),
            (10, "Transmitter address", Some(F_WIFI_TX)),
            (16, "Destination address", Some(F_WIFI_DST)),
            (24, "Source address", Some(F_WIFI_SRC)),
        ],
    }
}

fn mac_at(f: &[u8], o: usize) -> Option<String> {
    let s = f.get(o..o.checked_add(6)?)?;
    let mut a = [0u8; 6];
    a.copy_from_slice(s);
    Some(mac_string(&a))
}

fn dot11(
    link_type: u32,
    whole: &[u8],
    b: &[u8],
    start: usize,
    rt: Option<&Radiotap>,
    nodes: &mut Vec<DecodeNode>,
) {
    let blen = b.len();
    let f = b.get(start..).unwrap_or(&[]);
    let Some((ver, ftype, subtype, flags)) = frame_control(f) else {
        nodes.push(warn(node("IEEE 802.11", start, f.len(), blen), "truncated"));
        return;
    };
    if ver != 0 {
        nodes.push(warn(
            node(
                format!("IEEE 802.11 (protocol version {ver})"),
                start,
                f.len(),
                blen,
            ),
            "unsupported protocol version",
        ));
        return;
    }
    if ftype == TYPE_CTRL {
        control(f, start, subtype, flags, blen, nodes);
        return;
    }
    if ftype != TYPE_MGMT && ftype != TYPE_DATA {
        nodes.push(warn(
            node("IEEE 802.11 Extension frame", start, f.len(), blen),
            "not decoded",
        ));
        return;
    }
    let name = subtype_name(ftype, subtype);
    let Some(w) = wifi::parse_frame(link_type, whole, false) else {
        let mut n = node(format!("IEEE 802.11 {name}"), start, f.len(), blen);
        n.children.push(fc_leaf(start, ftype, subtype, blen));
        n.children
            .push(plain("Flags", None, flag_text(flags), start + 1, 1, blen));
        nodes.push(warn(n, "truncated header"));
        return;
    };
    let h = &w.header;
    let mut n = node(format!("IEEE 802.11 {name}"), start, h.len, blen);
    let c = &mut n.children;
    c.push(fc_leaf(start, ftype, subtype, blen));
    let mut fl = plain("Flags", None, flag_text(flags), start + 1, 1, blen);
    if h.protected() {
        fl.children.push(plain(
            "Protected",
            Some(F_WIFI_PROTECTED),
            "true".into(),
            start + 1,
            1,
            blen,
        ));
    }
    if h.retry() {
        fl.children.push(plain(
            "Retry",
            Some(F_WIFI_RETRY),
            "true".into(),
            start + 1,
            1,
            blen,
        ));
    }
    c.push(fl);
    c.push(valued(
        "Duration",
        None,
        h.duration.to_string(),
        format!("{} µs", h.duration),
        start + 2,
        2,
        blen,
    ));
    for (off, label, field) in address_slots(h) {
        if let Some(m) = mac_at(f, off) {
            c.push(plain(label, field, m, start + off, 6, blen));
        }
    }
    let mut seq = plain(
        "Sequence number",
        None,
        h.seq().to_string(),
        start + 22,
        2,
        blen,
    );
    if h.seq_ctrl & 0x0f != 0 {
        seq.label = format!("{} (fragment {})", seq.label, h.seq_ctrl & 0x0f);
    }
    c.push(seq);
    let mut o = if h.a4.is_some() { 30 } else { 24 };
    if let Some(q) = h.qos {
        let amsdu = if q & 0x0080 != 0 { ", A-MSDU" } else { "" };
        c.push(plain(
            "QoS Control",
            None,
            format!("0x{q:04x} (TID {}{amsdu})", q & 0x0f),
            start + o,
            2,
            blen,
        ));
        o += 2;
    }
    if h.htc {
        c.push(plain(
            "HT Control",
            None,
            format!("0x{}", hex(f.get(o..o + 4).unwrap_or(&[]))),
            start + o,
            4,
            blen,
        ));
    }
    nodes.push(n);

    let mut body_off = h.len;
    if rt.is_some_and(Radiotap::data_pad) {
        body_off = body_off.div_ceil(4) * 4;
    }
    let abs = start + body_off;
    let body = b.get(abs..).unwrap_or(&[]);
    if body.is_empty() {
        return;
    }
    if h.protected() {
        nodes.push(node(
            format!("Encrypted data ({} bytes)", body.len()),
            abs,
            body.len(),
            blen,
        ));
        return;
    }
    if ftype == TYPE_MGMT {
        nodes.push(mgmt_body(h.subtype, body, abs, blen, &w.mgmt));
        return;
    }
    if h.is_null_data() {
        nodes.push(node(
            format!("Data ({} bytes)", body.len()),
            abs,
            body.len(),
            blen,
        ));
        return;
    }
    let amsdu = h.qos.is_some_and(|q| q & 0x0080 != 0);
    match wifi::snap(body).filter(|_| !amsdu) {
        Some(s) => {
            let et = s.ethertype();
            let pid = u16::from_be_bytes([
                body.get(6).copied().unwrap_or(0),
                body.get(7).copied().unwrap_or(0),
            ]);
            let mut l = node("Logical-Link Control", abs, 8, blen);
            l.children.push(plain(
                "DSAP/SSAP/Control",
                None,
                "0xaa 0xaa 0x03 (SNAP)".into(),
                abs,
                3,
                blen,
            ));
            l.children.push(plain(
                "Organization code",
                None,
                format!("0x{}", hex(body.get(3..6).unwrap_or(&[]))),
                abs + 3,
                3,
                blen,
            ));
            l.children.push(plain(
                "Type",
                None,
                format!("0x{pid:04x}"),
                abs + 6,
                2,
                blen,
            ));
            nodes.push(l);
            if let wifi::Snap::Awdl(_) = s {
                let mut a = node("Apple Wireless Direct Link data", abs + 8, 8, blen);
                a.children.push(plain(
                    "Sequence number",
                    None,
                    le16(body, 10).unwrap_or(0).to_string(),
                    abs + 10,
                    2,
                    blen,
                ));
                a.children.push(plain(
                    "EtherType",
                    None,
                    format!("0x{et:04x}"),
                    abs + 14,
                    2,
                    blen,
                ));
                nodes.push(a);
            }
            let payload = abs + s.header_len();
            if et == ETHERTYPE_EAPOL {
                nodes.push(eapol(b.get(payload..).unwrap_or(&[]), payload, blen));
            } else {
                ethertype(et, b, payload, nodes);
            }
        }
        None => nodes.push(node(
            format!(
                "{} ({} bytes)",
                if amsdu { "A-MSDU" } else { "Data" },
                body.len()
            ),
            abs,
            body.len(),
            blen,
        )),
    }
}

fn fc_leaf(start: usize, ftype: u8, subtype: u8, blen: usize) -> DecodeNode {
    let code = (u16::from(ftype) << 4) | u16::from(subtype);
    valued(
        "Type/Subtype",
        None,
        format!("0x{code:04x}"),
        format!("{} (0x{code:04x})", subtype_name(ftype, subtype)),
        start,
        1,
        blen,
    )
}

fn control(
    f: &[u8],
    start: usize,
    subtype: u8,
    flags: u8,
    blen: usize,
    nodes: &mut Vec<DecodeNode>,
) {
    // Control frames with a transmitter address are 16 bytes before their
    // body; ACK/CTS carry only the receiver.
    let has_ta = matches!(subtype, 2 | 4 | 5 | 8 | 9 | 10 | 11 | 14 | 15);
    let hl = if has_ta { 16 } else { 10 };
    let name = subtype_name(TYPE_CTRL, subtype);
    let mut n = node(format!("IEEE 802.11 {name}"), start, hl, blen);
    n.children.push(fc_leaf(start, TYPE_CTRL, subtype, blen));
    n.children
        .push(plain("Flags", None, flag_text(flags), start + 1, 1, blen));
    if let Some(d) = le16(f, 2) {
        n.children.push(valued(
            "Duration",
            None,
            d.to_string(),
            format!("{d} µs"),
            start + 2,
            2,
            blen,
        ));
    }
    if let Some(m) = mac_at(f, 4) {
        n.children
            .push(plain("Receiver address", None, m, start + 4, 6, blen));
    }
    if has_ta {
        if let Some(m) = mac_at(f, 10) {
            n.children
                .push(plain("Transmitter address", None, m, start + 10, 6, blen));
        }
    }
    if f.len() < hl {
        n.warning = Some("truncated".into());
    }
    nodes.push(n);
    if f.len() > hl {
        nodes.push(node(
            format!("Control body ({} bytes)", f.len() - hl),
            start + hl,
            f.len() - hl,
            blen,
        ));
    }
}

fn eapol(p: &[u8], abs: usize, blen: usize) -> DecodeNode {
    let mut n = node("802.1X Authentication", abs, p.len(), blen);
    let (Some(&ver), Some(&ty), Some(len)) = (
        p.first(),
        p.get(1),
        p.get(2..4).map(|s| u16::from_be_bytes([s[0], s[1]])),
    ) else {
        return warn(n, "truncated");
    };
    let ty_name = match ty {
        0 => "EAP Packet",
        1 => "Start",
        2 => "Logoff",
        3 => "Key",
        4 => "Encapsulated ASF Alert",
        _ => "unknown",
    };
    n.children
        .push(plain("Version", None, ver.to_string(), abs, 1, blen));
    n.children.push(plain(
        "Type",
        None,
        format!("{ty_name} ({ty})"),
        abs + 1,
        1,
        blen,
    ));
    n.children
        .push(plain("Length", None, len.to_string(), abs + 2, 2, blen));
    if ty == 3 {
        if let Some(ki) = p.get(5..7).map(|s| u16::from_be_bytes([s[0], s[1]])) {
            // Message number from Key Information (ACK, MIC, Install, Secure).
            let ack = ki & 0x0080 != 0;
            let mic = ki & 0x0100 != 0;
            let install = ki & 0x0040 != 0;
            let secure = ki & 0x0200 != 0;
            let msg = match (ack, mic, install, secure) {
                (true, false, _, _) => "Message 1 of 4",
                (false, true, _, false) => "Message 2 of 4",
                (true, true, true, _) => "Message 3 of 4",
                (false, true, _, true) => "Message 4 of 4",
                _ => "group key / other",
            };
            n.children.push(plain(
                "Key Information",
                None,
                format!("0x{ki:04x} ({msg})"),
                abs + 5,
                2,
                blen,
            ));
        }
    }
    if usize::from(len) + 4 > p.len() {
        n.warning = Some("truncated".into());
    }
    n
}

fn tag_name(id: u8) -> &'static str {
    match id {
        0 => "SSID parameter set",
        1 => "Supported Rates",
        3 => "DS Parameter set",
        5 => "Traffic Indication Map (TIM)",
        7 => "Country Information",
        11 => "QBSS Load Element",
        42 => "ERP Information",
        45 => "HT Capabilities",
        48 => "RSN Information",
        50 => "Extended Supported Rates",
        54 => "Mobility Domain",
        59 => "Supported Operating Classes",
        61 => "HT Information",
        70 => "RM Enabled Capabilities",
        127 => "Extended Capabilities",
        191 => "VHT Capabilities",
        192 => "VHT Operation",
        221 => "Vendor Specific",
        255 => "Element ID Extension",
        _ => "Tag",
    }
}

fn mgmt_body(subtype: u8, body: &[u8], abs: usize, blen: usize, m: &wifi::MgmtInfo) -> DecodeNode {
    let mut n = node("Management body", abs, body.len(), blen);
    let mut short = false;
    {
        let c = &mut n.children;
        let mut fixed =
            |name: &str, field: Option<&str>, off: usize, len: usize, text: Option<String>| {
                match body.get(off..off + len) {
                    Some(s) => {
                        let v = text.unwrap_or_else(|| match len {
                            2 => u16::from_le_bytes([s[0], s[1]]).to_string(),
                            1 => s[0].to_string(),
                            _ => format!("0x{}", hex(s)),
                        });
                        c.push(plain(name, field, v, abs + off, len, blen));
                    }
                    None => short = true,
                }
            };
        let cap_text = |off: usize| {
            le16(body, off).map(|cap| {
                format!(
                    "0x{cap:04x}{}",
                    if cap & wifi::CAP_PRIVACY != 0 {
                        " (Privacy)"
                    } else {
                        ""
                    }
                )
            })
        };
        match subtype {
            5 | 8 => {
                let ts = body
                    .get(..8)
                    .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]));
                fixed("Timestamp", None, 0, 8, ts.map(|t| format!("{t} µs")));
                fixed(
                    "Beacon interval",
                    None,
                    8,
                    2,
                    le16(body, 8).map(|v| format!("{v} TU")),
                );
                fixed("Capabilities", None, 10, 2, cap_text(10));
            }
            0 => {
                fixed("Capabilities", None, 0, 2, cap_text(0));
                fixed("Listen interval", None, 2, 2, None);
            }
            2 => {
                fixed("Capabilities", None, 0, 2, cap_text(0));
                fixed("Listen interval", None, 2, 2, None);
                let ap = body.get(4..10).map(|s| {
                    let mut a = [0u8; 6];
                    a.copy_from_slice(s);
                    mac_string(&a)
                });
                fixed("Current AP", None, 4, 6, ap);
            }
            1 | 3 => {
                fixed("Capabilities", None, 0, 2, cap_text(0));
                fixed("Status code", Some(F_WIFI_REASON), 2, 2, None);
                fixed(
                    "Association ID",
                    None,
                    4,
                    2,
                    le16(body, 4).map(|v| (v & 0x3fff).to_string()),
                );
            }
            11 => {
                fixed("Authentication algorithm", None, 0, 2, None);
                fixed("Transaction sequence", None, 2, 2, None);
                fixed("Status code", Some(F_WIFI_REASON), 4, 2, None);
            }
            10 | 12 => fixed("Reason code", Some(F_WIFI_REASON), 0, 2, None),
            13 | 14 => {
                fixed("Category code", None, 0, 1, None);
                fixed("Action code", None, 1, 1, None);
            }
            _ => {}
        }
    }
    if let Some(sec) = m.security {
        let (s, l) = if body.len() >= 12 { (10, 2) } else { (0, 0) };
        n.children.push(plain(
            "Security",
            Some(F_WIFI_SECURITY),
            sec.to_string(),
            abs + s,
            l,
            blen,
        ));
    }
    if short {
        n.warning = Some("fixed fields truncated".into());
        return n;
    }
    let Some(first) = wifi::fixed_len(subtype) else {
        let (what, fixed) = match subtype {
            13 | 14 => ("Action body", 2),
            11 => ("Authentication data", 6),
            _ => ("Body", 2),
        };
        if body.len() > fixed {
            n.children.push(node(
                format!("{what} ({} bytes)", body.len() - fixed),
                abs + fixed,
                body.len() - fixed,
                blen,
            ));
        }
        return n;
    };
    let mut it = Elements::new(body, first);
    let mut shown = 0usize;
    let mut hidden = 0usize;
    for (id, at, data) in it.by_ref() {
        if shown >= MAX_TAGS {
            hidden += 1;
            continue;
        }
        shown += 1;
        n.children.push(tag_node(id, at, data, abs, blen));
    }
    if hidden > 0 {
        n.children
            .push(tree(format!("{hidden} more tags not shown"), abs, 0));
    }
    if let Some(at) = it.truncated_at {
        n.children.push(warn(
            node("Tag", abs + at, body.len() - at, blen),
            "truncated tag",
        ));
    }
    n
}

fn tag_node(id: u8, at: usize, data: &[u8], abs: usize, blen: usize) -> DecodeNode {
    let start = abs + at;
    let len = 2 + data.len();
    let name = tag_name(id);
    match id {
        0 => {
            let ssid = wifi::sanitize_ssid(data);
            let shown = if ssid.is_empty() {
                "(hidden)".to_string()
            } else {
                wifi::quote_ssid(&ssid)
            };
            let mut n = valued(
                "Tag: SSID parameter set",
                Some(F_WIFI_SSID),
                ssid,
                shown,
                start,
                len,
                blen,
            );
            if data.len() > wifi::MAX_SSID {
                n.warning = Some("SSID longer than 32 bytes (clipped)".into());
            }
            n
        }
        3 => match data.first() {
            Some(&ch) => valued(
                "Tag: DS Parameter set",
                Some(F_WIFI_CHANNEL),
                ch.to_string(),
                format!("channel {ch}"),
                start,
                len,
                blen,
            ),
            None => warn(node("Tag: DS Parameter set", start, len, blen), "empty"),
        },
        48 => {
            let a = wifi::rsn_akms(data);
            let mut akms = Vec::new();
            if a.psk {
                akms.push("PSK");
            }
            if a.sae {
                akms.push("SAE");
            }
            if a.owe {
                akms.push("OWE");
            }
            if a.other {
                akms.push("other");
            }
            let mut n = node(format!("Tag: {name}"), start, len, blen);
            n.children.push(plain(
                "AKM suites",
                None,
                if akms.is_empty() {
                    "(none listed)".into()
                } else {
                    akms.join(", ")
                },
                start + 2,
                data.len(),
                blen,
            ));
            n
        }
        221 => {
            let oui = data.get(..3).map(hex).unwrap_or_default();
            let what = if wifi::is_wpa_vendor(data) {
                " (WPA Information Element)"
            } else {
                ""
            };
            node(
                format!("Tag: Vendor Specific: OUI {oui}{what}"),
                start,
                len,
                blen,
            )
        }
        _ => {
            let label = if name == "Tag" {
                format!("Tag: {id} ({} bytes)", data.len())
            } else {
                format!("Tag: {name}")
            };
            node(label, start, len, blen)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode_frame;

    fn walk(nodes: &[DecodeNode], len: usize, out: &mut Vec<(String, Option<String>)>) {
        for n in nodes {
            if let Some(r) = n.range {
                assert!(
                    r.start as usize + r.len as usize <= len,
                    "{} {r:?} > {len}",
                    n.label
                );
            }
            out.push((n.label.clone(), n.field.clone()));
            walk(&n.children, len, out);
        }
    }

    fn beacon() -> Vec<u8> {
        let mut v = vec![0, 0, 15, 0, 0x2a, 0, 0, 0, wifi::RT_FLAG_FCS, 0];
        v.extend_from_slice(&2437u16.to_le_bytes());
        v.extend_from_slice(&0x00a0u16.to_le_bytes());
        v.push((-42i8) as u8);
        v.extend_from_slice(&[0x80, 0, 0, 0]);
        v.extend_from_slice(&[0xff; 6]);
        v.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0x10, 0]);
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[0x64, 0, 0x11, 0]);
        v.extend_from_slice(&[0, 4, b'H', b'o', b'm', b'e', 3, 1, 6]);
        v.extend_from_slice(&[48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0]);
        v.extend_from_slice(&[0, 0x0f, 0xac, 2, 0, 0]);
        let fcs = wifi::crc32(&v[15..]);
        v.extend_from_slice(&fcs.to_le_bytes());
        v
    }

    #[test]
    fn beacon_tree_has_fields_and_ranges() {
        let b = beacon();
        let tree = decode_frame(127, &b);
        let mut all = Vec::new();
        walk(&tree, b.len(), &mut all);
        let labels: Vec<&str> = all.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels.contains(&"Radiotap header"), "{labels:?}");
        assert!(labels.contains(&"IEEE 802.11 Beacon frame"));
        assert!(labels.contains(&"Management body"));
        assert!(labels.contains(&"Tag: SSID parameter set: \"Home\""));
        assert!(labels.contains(&"Antenna signal: -42 dBm"));
        assert!(labels.iter().any(|l| l.starts_with("Frame check sequence")));
        let fields: Vec<&str> = all.iter().filter_map(|(_, f)| f.as_deref()).collect();
        for f in [
            F_WIFI_DST,
            F_WIFI_SRC,
            F_WIFI_BSSID,
            F_WIFI_SSID,
            F_WIFI_SECURITY,
            F_WIFI_SIGNAL,
            F_WIFI_FREQ,
        ] {
            assert!(fields.contains(&f), "{f} missing: {fields:?}");
        }
        // Every prefix and both link types stay in range.
        for cut in 0..=b.len() {
            let mut v = Vec::new();
            walk(&decode_frame(127, &b[..cut]), cut, &mut v);
            walk(
                &decode_frame(105, &b[15..cut.max(15)]),
                cut.max(15) - 15,
                &mut v,
            );
        }
    }

    #[test]
    fn open_data_reaches_ip_decoder_and_wds_has_tx() {
        let mut f = vec![0x08, FL_TO_DS | FL_FROM_DS, 0, 0];
        for a in [[2u8; 6], [4; 6], [6; 6]] {
            f.extend_from_slice(&a);
        }
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[8u8; 6]);
        f.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]);
        let mut ip = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        ip.extend_from_slice(&[0x30, 0x39, 0, 53, 0, 8, 0, 0]);
        f.extend_from_slice(&ip);
        let tree = decode_frame(105, &f);
        let mut all = Vec::new();
        walk(&tree, f.len(), &mut all);
        assert!(all.iter().any(|(l, _)| l == "Logical-Link Control"));
        assert!(
            all.iter()
                .any(|(l, _)| l.starts_with("Internet Protocol Version 4"))
        );
        assert!(all.iter().any(|(_, f)| f.as_deref() == Some(F_WIFI_TX)));
        assert!(!all.iter().any(|(_, f)| f.as_deref() == Some(F_WIFI_BSSID)));
    }

    #[test]
    fn control_and_encrypted_and_bad_fcs() {
        let ack = [0xd4, 0, 0, 0, 1, 2, 3, 4, 5, 6];
        let t = decode_frame(105, &ack);
        assert_eq!(t[1].label, "IEEE 802.11 Acknowledgement");
        assert!(t[1].warning.is_none());
        let t = decode_frame(105, &ack[..7]);
        assert!(t[1].warning.is_some());

        let mut p = vec![0x88, FL_TO_DS | FL_PROTECTED, 0, 0];
        p.extend_from_slice(&[0u8; 20]);
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&[9u8; 30]);
        let t = decode_frame(105, &p);
        assert!(t.iter().any(|n| n.label == "Encrypted data (30 bytes)"));

        let mut b = beacon();
        b[8] |= wifi::RT_FLAG_BAD_FCS;
        let t = decode_frame(127, &b);
        assert!(t[1].warning.as_deref().unwrap_or("").contains("bad FCS"));
        assert!(t.last().expect("test input").warning.is_some());
    }

    fn labels(t: &[DecodeNode], out: &mut Vec<String>) {
        for n in t {
            out.push(n.label.clone());
            labels(&n.children, out);
        }
    }

    /// Security review M4: a `"` in an SSID cannot end the quoted label.
    #[test]
    fn ssid_quote_is_escaped_in_label() {
        let evil = br#"Free" ch 6 wpa3"#;
        let mut v = beacon();
        let at = v.iter().position(|&x| x == b'H').expect("test input") - 2;
        v.truncate(v.len() - 4);
        let mut b = v[..at].to_vec();
        b.push(0);
        b.push(evil.len() as u8);
        b.extend_from_slice(evil);
        b.extend_from_slice(&v[at + 2 + 4..]);
        let fcs = wifi::crc32(&b[15..]);
        b.extend_from_slice(&fcs.to_le_bytes());
        let t = decode_frame(127, &b);
        let mut all = Vec::new();
        labels(&t, &mut all);
        assert!(
            all.contains(&r#"Tag: SSID parameter set: "Free\" ch 6 wpa3""#.to_string()),
            "{all:?}"
        );
        let mut vals = Vec::new();
        fn values(t: &[DecodeNode], out: &mut Vec<(Option<String>, Option<String>)>) {
            for n in t {
                out.push((n.field.clone(), n.value.clone()));
                values(&n.children, out);
            }
        }
        values(&t, &mut vals);
        assert!(vals.contains(&(
            Some(F_WIFI_SSID.to_string()),
            Some(r#"Free" ch 6 wpa3"#.to_string())
        )));
    }

    /// Security review L3: a snapped record's last 4 bytes are not taken as
    /// the FCS, so the tree parses the frame the way ingest does.
    #[test]
    fn snapped_frame_trailing_bytes_are_not_fcs() {
        let b = beacon();
        // Complete: FCS verifies and is shown as such, no warning.
        let t = decode_frame(127, &b);
        let last = t.last().expect("test input");
        assert!(last.label.starts_with("Frame check sequence"));
        assert!(last.warning.is_none());
        // Snapped by 3 bytes: the trailing 4 bytes are payload.
        let cut = &b[..b.len() - 3];
        let t = decode_frame(127, cut);
        let last = t.last().expect("test input");
        assert!(last.label.starts_with("Trailing 4 bytes"), "{}", last.label);
        assert!(last.warning.is_some());
        let mut all = Vec::new();
        labels(&t, &mut all);
        assert!(!all.iter().any(|l| l.starts_with("Frame check sequence")));
        // The RSN element (whose tail the bogus FCS would have eaten) is
        // still decoded up to where the bytes end.
        let w = wifi::parse_frame(127, cut, true).expect("test input");
        assert_eq!(w.at.end, cut.len());
    }
}
