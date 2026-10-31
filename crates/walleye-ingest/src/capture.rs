//! Streaming pcap / pcapng record reader.
//!
//! The file is read through a bounded, reusable buffer (`ChunkReader`) rather
//! than memory-mapped: a mapped capture that shrinks or changes while mapped
//! (tcpdump still writing, a network share) raises SIGBUS and kills the app,
//! and mapping needs `unsafe`, which the workspace denies. Memory use is one
//! buffer of `CHUNK` bytes (grown only for a single oversized record, capped at
//! `MAX_RECORD`). Record framing is checked here; record contents are decoded
//! with `pcap-parser`.

use std::io::{self, Read};

use pcap_parser::pcapng::Block;
use serde::{Deserialize, Serialize};
use walleye_core::{CaptureFormat, Ts};

const CHUNK: usize = 4 * 1024 * 1024;
/// Largest record (pcap record or pcapng block) accepted. Real snaplens are
/// ≤ 256 KiB; anything far larger is corruption.
pub const MAX_RECORD: usize = 64 * 1024 * 1024;
/// Link type recorded for packets whose pcapng interface id is undefined.
pub const LINKTYPE_UNKNOWN: u32 = u32::MAX;

const PCAP_MAGICS: [[u8; 4]; 4] = [
    [0xd4, 0xc3, 0xb2, 0xa1], // LE µs
    [0xa1, 0xb2, 0xc3, 0xd4], // BE µs
    [0x4d, 0x3c, 0xb2, 0xa1], // LE ns
    [0xa1, 0xb2, 0x3c, 0x4d], // BE ns
];
const PCAPNG_SHB: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// Buffered reader that keeps track of file offsets.
pub struct ChunkReader<R: Read> {
    r: R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// File offset of `buf[0]`.
    base: u64,
    eof: bool,
}

impl<R: Read> ChunkReader<R> {
    /// `size_hint` (bytes left to read) caps the initial buffer for small inputs.
    pub fn new(r: R, offset: u64, size_hint: u64) -> Self {
        let cap = usize::try_from(size_hint).unwrap_or(CHUNK).clamp(64, CHUNK);
        Self {
            r,
            buf: vec![0; cap],
            start: 0,
            end: 0,
            base: offset,
            eof: false,
        }
    }
    /// File offset of the next unread byte.
    pub fn offset(&self) -> u64 {
        self.base + self.start as u64
    }
    pub fn avail(&self) -> &[u8] {
        self.buf.get(self.start..self.end).unwrap_or(&[])
    }
    pub fn consume(&mut self, n: usize) {
        self.start = (self.start + n).min(self.end);
    }
    /// Ensure at least `need` bytes are buffered. `Ok(false)` at end of file.
    pub fn fill(&mut self, need: usize) -> io::Result<bool> {
        while self.end - self.start < need {
            if self.eof {
                return Ok(false);
            }
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.base += self.start as u64;
                self.end -= self.start;
                self.start = 0;
            }
            if need > self.buf.len() {
                self.buf.resize(need, 0);
            }
            let Some(spare) = self.buf.get_mut(self.end..) else {
                return Ok(false);
            };
            match self.r.read(spare) {
                Ok(0) => self.eof = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub link_type: u32,
    /// Timestamp units per second (10^6 by default).
    pub units_per_sec: u64,
    /// `if_tsoffset`, seconds.
    pub offset_s: i64,
}

/// Everything needed to continue reading from the middle of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderState {
    pub format: Format,
    pub big_endian: bool,
    /// Legacy pcap: nanosecond timestamps.
    pub nanos: bool,
    /// Legacy pcap: the single link type. pcapng: unused.
    pub link_type: u32,
    /// pcapng: interfaces of the current section.
    pub interfaces: Vec<Interface>,
    /// pcapng: last timestamp seen (Simple Packet Blocks carry none).
    pub last_ts: Ts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Format {
    Pcap,
    Pcapng,
}

impl From<Format> for CaptureFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Pcap => CaptureFormat::Pcap,
            Format::Pcapng => CaptureFormat::Pcapng,
        }
    }
}

/// One packet record.
#[derive(Debug, Clone, Copy)]
pub struct RawFrame<'a> {
    pub ts: Ts,
    /// Offset of the packet data in the file.
    pub file_offset: u64,
    pub wirelen: u32,
    pub link_type: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub enum Next<'a> {
    Frame(RawFrame<'a>),
    /// Clean end of file.
    Eof,
    /// The file ends in the middle of a record (capture cut short).
    Truncated,
    /// Framing is broken; reading stops here.
    Corrupt(&'static str),
}

/// Header facts read before indexing starts.
#[derive(Debug, Clone)]
pub struct Opened {
    pub state: ReaderState,
    /// Link type of the first interface (pcap: the file's link type).
    pub first_link_type: u32,
    /// Offset of the first record after the file header (pcap) or 0 (pcapng).
    pub data_offset: u64,
}

/// Detect the format from the first bytes and parse the file header.
pub fn open_header(head: &[u8]) -> Result<Opened, &'static str> {
    let magic: [u8; 4] = head
        .get(..4)
        .and_then(|m| m.try_into().ok())
        .ok_or("file too short")?;
    if magic == PCAPNG_SHB {
        // The first interface's link type is learned from the first IDB; the
        // caller scans for it (see `first_pcapng_link_type`).
        return Ok(Opened {
            state: ReaderState {
                format: Format::Pcapng,
                big_endian: false,
                nanos: false,
                link_type: 0,
                interfaces: Vec::new(),
                last_ts: 0,
            },
            first_link_type: 0,
            data_offset: 0,
        });
    }
    if !PCAP_MAGICS.contains(&magic) {
        return Err("not a pcap or pcapng file");
    }
    let (_, hdr) = pcap_parser::parse_pcap_header(head).map_err(|_| "bad pcap header")?;
    if hdr.is_modified_format() {
        return Err("modified pcap format is not supported");
    }
    let link_type = u32::try_from(hdr.network.0).map_err(|_| "bad link type")?;
    Ok(Opened {
        state: ReaderState {
            format: Format::Pcap,
            big_endian: hdr.is_bigendian(),
            nanos: hdr.is_nanosecond_precision(),
            link_type,
            interfaces: Vec::new(),
            last_ts: 0,
        },
        first_link_type: link_type,
        data_offset: 24,
    })
}

/// Record reader over a `ChunkReader`.
pub struct Records<R: Read> {
    pub src: ChunkReader<R>,
    pub state: ReaderState,
    pending: usize,
}

fn u32_at(b: &[u8], off: usize, be: bool) -> Option<u32> {
    let s: [u8; 4] = b.get(off..off + 4)?.try_into().ok()?;
    Some(if be {
        u32::from_be_bytes(s)
    } else {
        u32::from_le_bytes(s)
    })
}

fn clamp_ts(us: i128) -> Ts {
    us.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as Ts
}

impl<R: Read> Records<R> {
    pub fn new(src: ChunkReader<R>, state: ReaderState) -> Self {
        Self {
            src,
            state,
            pending: 0,
        }
    }

    /// Offset of the next unread record.
    pub fn offset(&self) -> u64 {
        self.src.offset() + self.pending as u64
    }

    pub fn next_record(&mut self) -> io::Result<Next<'_>> {
        let n = std::mem::take(&mut self.pending);
        self.src.consume(n);
        loop {
            match self.state.format {
                Format::Pcap => return self.next_pcap(),
                Format::Pcapng => {
                    // Non-packet blocks are handled inline and loop.
                    match self.next_pcapng_block()? {
                        Some(Step::Skip(len)) => self.src.consume(len),
                        Some(Step::Frame) => break,
                        Some(Step::Stop(s)) => return Ok(s),
                        None => return Ok(Next::Eof),
                    }
                }
            }
        }
        self.pcapng_frame()
    }

    fn next_pcap(&mut self) -> io::Result<Next<'_>> {
        if !self.src.fill(16)? {
            return Ok(if self.src.avail().is_empty() {
                Next::Eof
            } else {
                Next::Truncated
            });
        }
        let be = self.state.big_endian;
        let Some(caplen) = u32_at(self.src.avail(), 8, be) else {
            return Ok(Next::Truncated);
        };
        let caplen = caplen as usize;
        if caplen > MAX_RECORD {
            return Ok(Next::Corrupt("record length too large"));
        }
        if !self.src.fill(16 + caplen)? {
            return Ok(Next::Truncated);
        }
        let offset = self.src.offset();
        let nanos = self.state.nanos;
        let link_type = self.state.link_type;
        let rec = self.src.avail();
        let parsed = if be {
            pcap_parser::parse_pcap_frame_be(rec)
        } else {
            pcap_parser::parse_pcap_frame(rec)
        };
        let Ok((_, blk)) = parsed else {
            return Ok(Next::Corrupt("bad pcap record"));
        };
        let frac = if nanos {
            i128::from(blk.ts_usec) / 1000
        } else {
            i128::from(blk.ts_usec)
        };
        let ts = clamp_ts(i128::from(blk.ts_sec) * 1_000_000 + frac);
        self.pending = 16 + caplen;
        Ok(Next::Frame(RawFrame {
            ts,
            file_offset: offset + 16,
            wirelen: blk.origlen,
            link_type,
            data: blk.data,
        }))
    }

    fn next_pcapng_block(&mut self) -> io::Result<Option<Step>> {
        if !self.src.fill(12)? {
            return Ok(if self.src.avail().is_empty() {
                None
            } else {
                Some(Step::Stop(Next::Truncated))
            });
        }
        let head = self.src.avail();
        let is_shb = head.get(..4) == Some(&PCAPNG_SHB[..]);
        if is_shb {
            // Byte-order magic decides the section's endianness.
            match head.get(8..12) {
                Some([0x1a, 0x2b, 0x3c, 0x4d]) => self.state.big_endian = true,
                Some([0x4d, 0x3c, 0x2b, 0x1a]) => self.state.big_endian = false,
                _ => return Ok(Some(Step::Stop(Next::Corrupt("bad byte-order magic")))),
            }
        }
        let be = self.state.big_endian;
        let Some(len) = u32_at(head, 4, be) else {
            return Ok(Some(Step::Stop(Next::Truncated)));
        };
        let len = len as usize;
        if len < 12 || len % 4 != 0 || len > MAX_RECORD {
            return Ok(Some(Step::Stop(Next::Corrupt("bad block length"))));
        }
        if !self.src.fill(len)? {
            return Ok(Some(Step::Stop(Next::Truncated)));
        }
        let Some(block) = self.src.avail().get(..len) else {
            return Ok(Some(Step::Stop(Next::Truncated)));
        };
        let parsed = if be {
            pcap_parser::pcapng::parse_block_be(block)
        } else {
            pcap_parser::pcapng::parse_block_le(block)
        };
        let Ok((_, blk)) = parsed else {
            return Ok(Some(Step::Stop(Next::Corrupt("bad pcapng block"))));
        };
        match blk {
            Block::SectionHeader(_) => {
                self.state.interfaces.clear();
                Ok(Some(Step::Skip(len)))
            }
            Block::InterfaceDescription(idb) => {
                self.state.interfaces.push(Interface {
                    link_type: u32::try_from(idb.linktype.0).unwrap_or(LINKTYPE_UNKNOWN),
                    units_per_sec: idb.ts_resolution().filter(|&u| u > 0).unwrap_or(1_000_000),
                    offset_s: idb.ts_offset(),
                });
                Ok(Some(Step::Skip(len)))
            }
            Block::EnhancedPacket(_) | Block::SimplePacket(_) => Ok(Some(Step::Frame)),
            _ => Ok(Some(Step::Skip(len))),
        }
    }

    /// Decode the packet block at the front of the buffer (already validated).
    fn pcapng_frame(&mut self) -> io::Result<Next<'_>> {
        let be = self.state.big_endian;
        let offset = self.src.offset();
        let len = u32_at(self.src.avail(), 4, be).unwrap_or(0) as usize;
        self.pending = len;
        let block = self.src.avail().get(..len).unwrap_or(&[]);
        let parsed = if be {
            pcap_parser::pcapng::parse_block_be(block)
        } else {
            pcap_parser::pcapng::parse_block_le(block)
        };
        match parsed {
            Ok((_, Block::EnhancedPacket(epb))) => {
                let iface = self.state.interfaces.get(epb.if_id as usize).copied();
                let (link_type, units, off_s) = match iface {
                    Some(i) => (i.link_type, i.units_per_sec, i.offset_s),
                    None => (LINKTYPE_UNKNOWN, 1_000_000, 0),
                };
                let raw = (u128::from(epb.ts_high) << 32) | u128::from(epb.ts_low);
                let us = raw.saturating_mul(1_000_000) / u128::from(units.max(1));
                let us = i128::try_from(us).unwrap_or(i128::MAX);
                let ts = clamp_ts(us.saturating_add(i128::from(off_s) * 1_000_000));
                self.state.last_ts = ts;
                Ok(Next::Frame(RawFrame {
                    ts,
                    file_offset: offset + 28,
                    wirelen: epb.origlen,
                    link_type,
                    data: epb.data.get(..epb.caplen as usize).unwrap_or(epb.data),
                }))
            }
            Ok((_, Block::SimplePacket(spb))) => {
                let link_type = self
                    .state
                    .interfaces
                    .first()
                    .map_or(LINKTYPE_UNKNOWN, |i| i.link_type);
                Ok(Next::Frame(RawFrame {
                    ts: self.state.last_ts,
                    file_offset: offset + 12,
                    wirelen: spb.origlen,
                    link_type,
                    data: spb.data.get(..spb.origlen as usize).unwrap_or(spb.data),
                }))
            }
            _ => Ok(Next::Corrupt("bad pcapng packet block")),
        }
    }
}

enum Step {
    Skip(usize),
    Frame,
    Stop(Next<'static>),
}

/// Scan the start of a pcapng file for the first interface's link type.
pub fn first_pcapng_link_type(head: &[u8]) -> u32 {
    let mut pos = 0usize;
    let mut be = false;
    for _ in 0..64 {
        let Some(h) = head.get(pos..pos + 12) else {
            break;
        };
        if h.get(..4) == Some(&PCAPNG_SHB[..]) {
            be = h.get(8..12) == Some(&[0x1a, 0x2b, 0x3c, 0x4d][..]);
        }
        let (Some(ty), Some(len)) = (u32_at(h, 0, be), u32_at(h, 4, be)) else {
            break;
        };
        if ty == 1 {
            let lt = head.get(pos + 8..pos + 10).map(|b| {
                if be {
                    u16::from_be_bytes([b[0], b[1]])
                } else {
                    u16::from_le_bytes([b[0], b[1]])
                }
            });
            return lt.map_or(LINKTYPE_UNKNOWN, u32::from);
        }
        if len < 12 {
            break;
        }
        pos = pos.saturating_add(len as usize);
    }
    LINKTYPE_UNKNOWN
}
