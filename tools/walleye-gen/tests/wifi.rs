//! `wifi` / `wifi_benign` scenarios: deterministic radiotap pcap (link type
//! 127) with a valid FCS on every frame and honest labels. Semantic checks
//! of the 802.11 content live in walleye-ingest's tests/wifi.rs.

use std::collections::BTreeMap;

use walleye_gen::{Options, Scenario, Summary, generate};

fn gen_wifi(scenario: Scenario, seed: u64, minutes: u64) -> (Vec<u8>, Summary) {
    let mut opts = Options::new(scenario, seed);
    opts.duration_min = minutes;
    let mut buf = Vec::new();
    let s = generate(&opts, &mut buf).expect("generate");
    (buf, s)
}

fn crc32(data: &[u8]) -> u32 {
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

struct Rec<'a> {
    ts: i64,
    data: &'a [u8],
}

fn records(b: &[u8]) -> Vec<Rec<'_>> {
    assert_eq!(&b[0..4], &0xa1b2_c3d4u32.to_le_bytes());
    assert_eq!(
        u32::from_le_bytes(b[20..24].try_into().expect("test input")),
        127
    );
    let mut out = Vec::new();
    let mut p = 24;
    while p < b.len() {
        let sec = u32::from_le_bytes(b[p..p + 4].try_into().expect("test input"));
        let usec = u32::from_le_bytes(b[p + 4..p + 8].try_into().expect("test input"));
        let incl = u32::from_le_bytes(b[p + 8..p + 12].try_into().expect("test input")) as usize;
        let orig = u32::from_le_bytes(b[p + 12..p + 16].try_into().expect("test input")) as usize;
        assert_eq!(incl, orig);
        out.push(Rec {
            ts: i64::from(sec) * 1_000_000 + i64::from(usec),
            data: &b[p + 16..p + 16 + incl],
        });
        p += 16 + incl;
    }
    assert_eq!(p, b.len());
    out
}

#[test]
fn wifi_is_byte_identical_per_seed() {
    let (a, sa) = gen_wifi(Scenario::Wifi, 9, 4);
    let (b, sb) = gen_wifi(Scenario::Wifi, 9, 4);
    assert_eq!(a, b);
    assert_eq!(sa.sha256, sb.sha256);
    assert_eq!(sa.labels, sb.labels);
    let (c, _) = gen_wifi(Scenario::Wifi, 10, 4);
    assert_ne!(a, c);
    let (d, _) = gen_wifi(Scenario::WifiBenign, 9, 4);
    assert_ne!(a, d);
}

#[test]
fn radiotap_and_fcs_are_valid_and_time_ordered() {
    let (b, s) = gen_wifi(Scenario::Wifi, 1, 5);
    let recs = records(&b);
    assert_eq!(recs.len() as u64, s.packets);
    let mut kinds: BTreeMap<u8, usize> = BTreeMap::new();
    let mut seqs: BTreeMap<[u8; 6], Vec<u16>> = BTreeMap::new();
    for w in recs.windows(2) {
        assert!(w[0].ts <= w[1].ts);
    }
    for r in &recs {
        let d = r.data;
        // version 0, it_len 23, present = TSFT|Flags|Rate|Channel|Signal.
        assert_eq!(d[0], 0);
        assert_eq!(u16::from_le_bytes([d[2], d[3]]), 23);
        assert_eq!(
            u32::from_le_bytes(d[4..8].try_into().expect("test input")),
            0x2f
        );
        assert_eq!(d[16], 0x10, "FCS flag");
        let f = u16::from_le_bytes([d[18], d[19]]);
        assert!([2412, 2437, 2462].contains(&f), "{f}");
        let sig = d[22] as i8;
        assert!((-95..=-20).contains(&sig));
        let frame = &d[23..d.len() - 4];
        let fcs = u32::from_le_bytes(d[d.len() - 4..].try_into().expect("test input"));
        assert_eq!(crc32(frame), fcs);
        *kinds.entry(frame[0]).or_default() += 1;
        let ftype = (frame[0] >> 2) & 3;
        if ftype != 1 {
            let tx: [u8; 6] = frame[10..16].try_into().expect("test input");
            seqs.entry(tx)
                .or_default()
                .push(u16::from_le_bytes([frame[22], frame[23]]) >> 4);
        }
    }
    // Per-transmitter sequence numbers count up by one (mod 4096).
    for v in seqs.values() {
        assert!(v.windows(2).all(|w| w[1] == (w[0] + 1) & 0x0fff));
    }
    // Beacons, probes, auth, assoc, deauth, action, QoS data, null, ACK.
    for fc0 in [
        0x80u8, 0x40, 0x50, 0xb0, 0x00, 0x10, 0xc0, 0xd0, 0x88, 0x48, 0xd4,
    ] {
        assert!(
            kinds.contains_key(&fc0),
            "fc 0x{fc0:02x} missing: {kinds:x?}"
        );
    }
}

#[test]
fn labels_are_honest() {
    let (_, s) = gen_wifi(Scenario::Wifi, 2, 10);
    let l = &s.labels;
    assert_eq!(l.scenario, "wifi");
    assert!(!l.benign);
    assert_eq!(l.c2_hosts.len(), 3, "{}", l.notes);
    for m in &l.c2_hosts {
        let first = u8::from_str_radix(&m[..2], 16).expect("test input");
        assert_eq!(first & 0x03, 0x02, "{m} locally administered unicast");
    }
    assert!(l.bad_destinations.contains(&"Lighthouse".to_string()));
    assert!(l.bad_destinations.len() >= 10);
    assert!(l.notes.contains("Emitted: deauth flood"));

    let (_, b) = gen_wifi(Scenario::WifiBenign, 2, 10);
    assert!(b.labels.benign);
    assert!(b.labels.c2_hosts.is_empty() && b.labels.bad_destinations.is_empty());

    // Too short for the flood to finish: nothing claimed without evidence.
    let (_, t) = gen_wifi(Scenario::Wifi, 2, 1);
    assert!(
        t.labels.notes.contains("deauth flood NOT labelled"),
        "{}",
        t.labels.notes
    );
    assert!(t.labels.c2_hosts.len() < 3, "{}", t.labels.notes);
}

#[test]
fn duration_is_capped() {
    let mut opts = Options::new(Scenario::WifiBenign, 1);
    opts.duration_min = 600;
    let mut buf = Vec::new();
    generate(&opts, &mut buf).expect("generate");
    let recs = records(&buf);
    let span = recs.last().expect("test input").ts - recs[0].ts;
    assert!(span <= walleye_gen::wifi::MAX_MINUTES as i64 * 60 * 1_000_000);
    assert!(span > 29 * 60 * 1_000_000);
}
