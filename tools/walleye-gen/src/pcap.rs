//! Classic libpcap writer (little-endian, microsecond timestamps, Ethernet).
//! Hashes the output while writing so labels can carry the file's SHA-256
//! without a second pass over a 10 GB file.

use std::io::{self, Write};

use sha2::{Digest, Sha256};

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const SNAPLEN: u32 = 262_144;

pub struct PcapWriter<W: Write> {
    out: W,
    hasher: Sha256,
    bytes: u64,
    packets: u64,
    last_ts: i64,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(out: W) -> io::Result<Self> {
        Self::with_link_type(out, LINKTYPE_ETHERNET)
    }

    /// A writer for another link type (127 = 802.11 + radiotap).
    pub fn with_link_type(out: W, link_type: u32) -> io::Result<Self> {
        let mut w = PcapWriter {
            out,
            hasher: Sha256::new(),
            bytes: 0,
            packets: 0,
            last_ts: i64::MIN,
        };
        let mut hdr = Vec::with_capacity(24);
        hdr.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        hdr.extend_from_slice(&2u16.to_le_bytes());
        hdr.extend_from_slice(&4u16.to_le_bytes());
        hdr.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        hdr.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        hdr.extend_from_slice(&SNAPLEN.to_le_bytes());
        hdr.extend_from_slice(&link_type.to_le_bytes());
        w.put(&hdr)?;
        Ok(w)
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.hasher.update(b);
        self.bytes += b.len() as u64;
        self.out.write_all(b)
    }

    /// Write one packet. `ts_us` must be non-decreasing (capture order).
    pub fn write_packet(&mut self, ts_us: i64, data: &[u8]) -> io::Result<()> {
        debug_assert!(ts_us >= self.last_ts, "packets out of time order");
        self.last_ts = ts_us;
        let secs = ts_us.div_euclid(1_000_000) as u32;
        let usecs = ts_us.rem_euclid(1_000_000) as u32;
        let len = data.len() as u32;
        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&secs.to_le_bytes());
        rec[4..8].copy_from_slice(&usecs.to_le_bytes());
        rec[8..12].copy_from_slice(&len.to_le_bytes());
        rec[12..16].copy_from_slice(&len.to_le_bytes());
        self.put(&rec)?;
        self.put(data)?;
        self.packets += 1;
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }

    pub fn packets_written(&self) -> u64 {
        self.packets
    }

    /// Flush and return (bytes, packets, lowercase hex SHA-256).
    pub fn finish(mut self) -> io::Result<(u64, u64, String)> {
        self.out.flush()?;
        let digest = self.hasher.finalize();
        Ok((self.bytes, self.packets, hex(&digest)))
    }
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
