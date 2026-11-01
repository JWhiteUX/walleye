//! Time-ordered packet scheduler: a min-heap of active flows keyed by the
//! time of each flow's next packet. Memory is bounded by the number of
//! concurrently active flows, not by capture size.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{self, Write};

use crate::flow::Flow;
use crate::pcap::PcapWriter;

pub struct Sim<W: Write> {
    slots: Vec<Option<Flow>>,
    free: Vec<usize>,
    heap: BinaryHeap<Reverse<(i64, u64, usize)>>,
    seq: u64,
    pub writer: PcapWriter<W>,
    buf: Vec<u8>,
    last_ts: i64,
}

impl<W: Write> Sim<W> {
    pub fn new(writer: PcapWriter<W>) -> Self {
        Sim {
            slots: Vec::new(),
            free: Vec::new(),
            heap: BinaryHeap::new(),
            seq: 0,
            writer,
            buf: Vec::with_capacity(2048),
            last_ts: i64::MIN,
        }
    }

    fn push(&mut self, t: i64, slot: usize) {
        self.seq += 1;
        self.heap.push(Reverse((t, self.seq, slot)));
    }

    pub fn add(&mut self, flow: Flow) {
        let Some(t) = flow.peek() else {
            return;
        };
        let slot = match self.free.pop() {
            Some(s) => {
                self.slots[s] = Some(flow);
                s
            }
            None => {
                self.slots.push(Some(flow));
                self.slots.len() - 1
            }
        };
        self.push(t, slot);
    }

    /// Timestamp of the last packet written (`i64::MIN` before any).
    pub fn last_ts(&self) -> i64 {
        self.last_ts
    }

    pub fn active_flows(&self) -> usize {
        self.heap.len()
    }

    /// Emit every packet with timestamp `< until`. Returns `false` when the
    /// byte limit was reached (the caller should stop).
    pub fn run_until(&mut self, until: i64, limit: Option<u64>) -> io::Result<bool> {
        while let Some(&Reverse((t, _, slot))) = self.heap.peek() {
            if t >= until {
                break;
            }
            if let Some(l) = limit {
                if self.writer.bytes_written() >= l {
                    return Ok(false);
                }
            }
            self.heap.pop();
            let Some(flow) = self.slots[slot].as_mut() else {
                continue;
            };
            let emitted = flow.emit(&mut self.buf);
            debug_assert_eq!(
                emitted, t,
                "flow emitted at a time other than it advertised"
            );
            let ts = emitted.max(self.last_ts);
            let next = flow.peek();
            self.last_ts = ts;
            self.writer.write_packet(ts, &self.buf)?;
            match next {
                Some(n) => self.push(n, slot),
                None => {
                    self.slots[slot] = None;
                    self.free.push(slot);
                }
            }
        }
        Ok(limit.is_none_or(|l| self.writer.bytes_written() < l))
    }
}
