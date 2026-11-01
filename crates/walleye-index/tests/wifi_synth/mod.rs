//! Deterministic synthetic 802.11 rows for paging and scale tests. Built
//! directly as `WifiRow`s (no ingest), written through `IndexWriter`.

#![allow(dead_code)]

use walleye_core::{
    CaptureFormat, CaptureRow, FrameRow, WifiKind, WifiRow,
    error::ApiResult,
    sink::{Checkpoint, IndexSink, RecordBatch},
};

pub struct Lcg(u64);
impl Lcg {
    pub fn new(seed: u64) -> Self {
        Lcg(seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1))
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

pub fn mac(prefix: u8, n: u64) -> String {
    let b = n.to_be_bytes();
    format!(
        "{prefix:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[3], b[4], b[5], b[6], b[7]
    )
}

pub const BROADCAST: &str = "ff:ff:ff:ff:ff:ff";
const SECURITY: [&str; 4] = ["wpa2", "wpa2", "wpa3", "open"];

pub struct Scale {
    pub rows: u64,
    pub aps: u64,
    pub clients: u64,
    pub seed: u64,
    /// Checkpoint every this many rows (0 = never).
    pub checkpoint_rows: u64,
}

pub const T0: i64 = 1_700_000_000_000_000;

fn ap_mac(i: u64) -> String {
    // Every 7th AP has a locally administered BSSID.
    mac(if i % 7 == 0 { 0x42 } else { 0xe8 }, i)
}

fn sta_mac(i: u64) -> String {
    // Half the clients are randomized.
    mac(if i % 2 == 0 { 0xda } else { 0xa4 }, 1_000_000 + i)
}

/// One synthetic row.
pub fn row(r: &mut Lcg, s: &Scale, frame_no: u64) -> WifiRow {
    let ts = T0 + (frame_no as i64) * 1_000;
    let ap = r.below(s.aps);
    let sta = r.below(s.clients);
    let bssid = ap_mac(ap);
    let st = sta_mac(sta);
    let roll = r.below(100);
    let kind = match roll {
        0..=29 => WifiKind::Beacon,
        30..=39 => WifiKind::ProbeReq,
        40..=44 => WifiKind::ProbeResp,
        45..=79 => WifiKind::Data,
        80..=84 => WifiKind::Null,
        85 => WifiKind::Eapol,
        86..=88 => WifiKind::Deauth,
        89 => WifiKind::Disassoc,
        90..=91 => WifiKind::Auth,
        92 => WifiKind::AssocReq,
        93 => WifiKind::AssocResp,
        94 => WifiKind::ReassocReq,
        95..=97 => WifiKind::Action,
        _ => WifiKind::MgmtOther,
    };
    let channel = Some([1u16, 6, 11][(ap % 3) as usize]);
    let ssid_of_ap = format!("net-{}", ap % (s.aps / 2).max(1));
    let to_ap = r.below(2) == 0;
    let (src, dst, tx, ssid, security, reason) = match kind {
        WifiKind::Beacon => (
            bssid.clone(),
            BROADCAST.to_string(),
            bssid.clone(),
            Some(if r.below(50) == 0 {
                String::new()
            } else {
                ssid_of_ap
            }),
            Some(SECURITY[(ap % 4) as usize].to_string()),
            None,
        ),
        WifiKind::ProbeResp => (
            bssid.clone(),
            st.clone(),
            bssid.clone(),
            Some(ssid_of_ap),
            Some(SECURITY[(ap % 4) as usize].to_string()),
            None,
        ),
        WifiKind::ProbeReq => (
            st.clone(),
            BROADCAST.to_string(),
            st.clone(),
            Some(if r.below(3) == 0 {
                String::new()
            } else {
                format!("net-{}", r.below(s.aps))
            }),
            None,
            None,
        ),
        WifiKind::Deauth | WifiKind::Disassoc => (
            bssid.clone(),
            if r.below(2) == 0 {
                BROADCAST.to_string()
            } else {
                st.clone()
            },
            bssid.clone(),
            None,
            None,
            Some(7),
        ),
        _ if to_ap => (st.clone(), bssid.clone(), st.clone(), None, None, None),
        _ => (bssid.clone(), st.clone(), bssid.clone(), None, None, None),
    };
    WifiRow {
        ts,
        frame_no,
        kind,
        protected: kind == WifiKind::Data,
        retry: r.below(20) == 0,
        src: Some(src),
        dst: Some(dst),
        tx: Some(tx),
        bssid: Some(bssid),
        channel,
        freq_mhz: channel.map(|c| 2407 + 5 * c),
        signal_dbm: Some(-30 - r.below(60) as i16),
        ssid,
        security,
        reason,
        seq: Some((frame_no % 4096) as u16),
        len: 60 + r.below(1400) as u32,
    }
}

pub fn capture(rows: u64) -> CaptureRow {
    CaptureRow {
        capture_id: "abcdefabcdefabcd".into(),
        path: "/wifi.pcap".into(),
        sha256: "abcdef".repeat(10) + "abcd",
        size_bytes: rows * 200,
        format: CaptureFormat::Pcap,
        first_ts: T0,
        last_ts: T0 + rows as i64 * 1_000,
        link_type: 127,
        frame_count: rows,
    }
}

/// Writes `s.rows` wifi rows (and their frames) through `sink`.
pub fn generate(sink: &mut dyn IndexSink, s: &Scale) -> ApiResult<CaptureRow> {
    let cap = capture(s.rows);
    sink.begin(&cap)?;
    let mut r = Lcg::new(s.seed);
    let batch = 65_536u64;
    let mut n = 1u64;
    let mut since_cp = 0u64;
    while n <= s.rows {
        let end = (n + batch - 1).min(s.rows);
        let rows: Vec<WifiRow> = (n..=end).map(|i| row(&mut r, s, i)).collect();
        let frames: Vec<FrameRow> = rows
            .iter()
            .map(|w| FrameRow {
                frame_no: w.frame_no,
                ts: w.ts,
                file_offset: 24 + w.frame_no * 200,
                caplen: w.len + 36,
                wirelen: w.len + 36,
                flow_id: None,
                direction: None,
                tcp_flags: None,
                payload_len: 0,
                link_type: Some(127),
            })
            .collect();
        sink.write(RecordBatch::Frames(frames))?;
        sink.write(RecordBatch::Wifi(rows))?;
        since_cp += end - n + 1;
        n = end + 1;
        if s.checkpoint_rows > 0 && since_cp >= s.checkpoint_rows && n <= s.rows {
            sink.checkpoint(Checkpoint {
                file_offset: n * 200,
                frames_emitted: n - 1,
                next_flow_id: 1,
                state: Vec::new(),
            })?;
            since_cp = 0;
        }
    }
    sink.finish(&cap)?;
    Ok(cap)
}
