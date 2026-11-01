//! 802.11 / Ethernet MAC address helpers shared by ingest, index, detect and
//! the mock backend (contract v2).

/// Parses `aa:bb:cc:dd:ee:ff` (also `-` separators, any case) and returns the
/// canonical lowercase colon form, or None.
pub fn parse_mac(s: &str) -> Option<String> {
    let s = s.trim();
    let sep = if s.contains('-') { '-' } else { ':' };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if i > 0 {
            out.push(':');
        }
        out.push_str(&p.to_ascii_lowercase());
    }
    Some(out)
}

/// Canonical text for six address bytes.
pub fn mac_text(b: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

/// Group (multicast/broadcast) bit of the first octet.
pub fn is_group(b: &[u8; 6]) -> bool {
    b[0] & 0x01 != 0
}

/// Locally administered bit of the first octet: randomized (privacy) client
/// addresses, virtual APs, or spoofed addresses.
pub fn is_locally_administered(b: &[u8; 6]) -> bool {
    b[0] & 0x02 != 0
}

/// Same as `is_locally_administered` on canonical text; false if unparsable.
pub fn text_is_locally_administered(s: &str) -> bool {
    u8::from_str_radix(s.get(0..2).unwrap_or(""), 16).is_ok_and(|b| b & 0x02 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_bits() {
        assert_eq!(
            parse_mac("42:00:5e:00:53:9C").as_deref(),
            Some("42:00:5e:00:53:9c")
        );
        assert_eq!(
            parse_mac("42-00-5e-00-53-9c").as_deref(),
            Some("42:00:5e:00:53:9c")
        );
        for bad in [
            "",
            "42:00:5e:00:53",
            "42:00:5e:00:53:9g",
            "4275c3d8bb9c",
            "1.2.3.4",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
        assert!(text_is_locally_administered("42:00:5e:00:53:9c"));
        assert!(!text_is_locally_administered("e8:00:5e:00:53:88"));
        assert!(is_group(&[0xff; 6]));
        assert_eq!(mac_text(&[0xff; 6]), "ff:ff:ff:ff:ff:ff");
    }
}
