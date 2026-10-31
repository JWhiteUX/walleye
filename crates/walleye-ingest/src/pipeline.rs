//! The ingest loop: records → frames/flows/app rows → batches over a bounded
//! channel to a writer thread that owns the `IndexSink`.

use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};

use serde::{Deserialize, Serialize};
use walleye_core::error::ApiResult;
use walleye_core::sink::{Checkpoint, IndexSink, RecordBatch};
use walleye_core::{ApiError, CaptureRow, ErrorCode, FrameRow, Ts};

use crate::capture::{
    ChunkReader, Next, ReaderState, Records, first_pcapng_link_type, open_header,
};
use crate::flow::{FlowTable, FlowTableState};
use crate::out::Out;
use crate::packet::parse_packet;
use crate::{IngestOptions, Progress};

/// Bump when `SavedState` changes shape; older checkpoints are rejected.
const STATE_VERSION: u32 = 1;
const CHANNEL_DEPTH: usize = 8;
const PROGRESS_EVERY: u64 = 8 * 1024 * 1024;
const CANCEL_EVERY: u64 = 1024;

#[derive(Debug, Serialize, Deserialize)]
struct SavedState {
    version: u32,
    reader: ReaderState,
    flows: FlowTableState,
    first_ts: Option<Ts>,
    last_ts: Option<Ts>,
}

enum Msg {
    Batch(RecordBatch),
    Checkpoint(Checkpoint),
}

struct Engine {
    table: FlowTable,
    out: Out,
    frames: u64,
    first_ts: Option<Ts>,
    last_ts: Option<Ts>,
}

impl Engine {
    fn on_frame(&mut self, ts: Ts, file_offset: u64, wirelen: u32, link_type: u32, data: &[u8]) {
        self.frames += 1;
        let frame_no = self.frames;
        self.first_ts = Some(self.first_ts.map_or(ts, |t| t.min(ts)));
        self.last_ts = Some(self.last_ts.map_or(ts, |t| t.max(ts)));
        let (flow_id, direction, tcp_flags, payload_len) = match parse_packet(link_type, data) {
            Some(p) => {
                let (id, dir) = self.table.packet(frame_no, ts, &p, &mut self.out);
                (Some(id), Some(dir), p.tcp.map(|t| t.flags), p.payload_len)
            }
            None => (None, None, None, 0),
        };
        self.out.frames.push(FrameRow {
            frame_no,
            ts,
            file_offset,
            caplen: u32::try_from(data.len()).unwrap_or(u32::MAX),
            wirelen,
            flow_id,
            direction,
            tcp_flags,
            payload_len,
            link_type: Some(link_type),
        });
        self.table.maybe_sweep(ts, &mut self.out);
    }
}

/// Sentinel: the writer thread hung up (its own error is reported instead).
fn writer_gone() -> ApiError {
    ApiError::internal("index writer stopped")
}

fn send(tx: &SyncSender<Msg>, m: Msg) -> ApiResult<()> {
    tx.send(m).map_err(|_| writer_gone())
}

fn flush(out: &mut Out, tx: &SyncSender<Msg>, force: bool, batch_rows: usize) -> ApiResult<()> {
    let n = batch_rows.max(1);
    macro_rules! table {
        ($field:ident, $variant:ident) => {
            if (force && !out.$field.is_empty()) || out.$field.len() >= n {
                let rows = std::mem::replace(&mut out.$field, Vec::with_capacity(n.min(65_536)));
                send(tx, Msg::Batch(RecordBatch::$variant(rows)))?;
            }
        };
    }
    table!(frames, Frames);
    table!(flows, Flows);
    table!(dns, Dns);
    table!(http, Http);
    table!(tls, Tls);
    table!(files, Files);
    Ok(())
}

/// Ingest any seekable byte source. `ingest()` calls this with the file.
#[allow(clippy::too_many_arguments)]
pub fn run<R: Read + Seek>(
    mut src: R,
    size: u64,
    path: &str,
    sha256: &str,
    sink: &mut dyn IndexSink,
    opts: &IngestOptions,
    progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> ApiResult<CaptureRow> {
    let sha = sha256.to_ascii_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::new(
            ErrorCode::InvalidArgument,
            "sha256 must be 64 hex characters",
        ));
    }
    let mut head = vec![0u8; 64 * 1024];
    let mut got = 0usize;
    while got < head.len() {
        let n = src.read(head.get_mut(got..).unwrap_or(&mut []))?;
        if n == 0 {
            break;
        }
        got += n;
    }
    head.truncate(got);
    let opened =
        open_header(&head).map_err(|e| ApiError::new(ErrorCode::BadCapture, e.to_string()))?;
    let first_link_type = match opened.state.format {
        crate::capture::Format::Pcap => opened.first_link_type,
        crate::capture::Format::Pcapng => first_pcapng_link_type(&head),
    };
    let mut row = CaptureRow {
        capture_id: sha.get(..16).unwrap_or_default().to_string(),
        path: path.to_string(),
        sha256: sha.clone(),
        size_bytes: size,
        format: opened.state.format.into(),
        first_ts: 0,
        last_ts: 0,
        link_type: first_link_type,
        frame_count: 0,
    };

    let mut engine = Engine {
        table: FlowTable::new(opts.tcp_idle_timeout_s, opts.udp_idle_timeout_s),
        out: Out::default(),
        frames: 0,
        first_ts: None,
        last_ts: None,
    };
    let (start, reader_state) = match sink.begin(&row)? {
        Some(cp) => {
            let saved: SavedState = serde_json::from_slice(&cp.state)
                .map_err(|e| ApiError::internal(format!("checkpoint state unreadable: {e}")))?;
            if saved.version != STATE_VERSION
                || cp.file_offset > size
                || saved.reader.format != opened.state.format
            {
                return Err(ApiError::internal(
                    "checkpoint does not match this capture or ingest version",
                ));
            }
            engine.table.restore(saved.flows);
            engine.table.next_id = cp.next_flow_id.max(engine.table.next_id);
            engine.frames = cp.frames_emitted;
            engine.first_ts = saved.first_ts;
            engine.last_ts = saved.last_ts;
            (cp.file_offset, saved.reader)
        }
        None => (opened.data_offset, opened.state),
    };
    src.seek(SeekFrom::Start(start))?;
    let mut records = Records::new(
        ChunkReader::new(src, start, size.saturating_sub(start)),
        reader_state,
    );

    let result = std::thread::scope(|s| {
        let (tx, rx) = sync_channel::<Msg>(CHANNEL_DEPTH);
        let sink_ref: &mut dyn IndexSink = &mut *sink;
        let writer = s.spawn(move || -> ApiResult<()> {
            for m in rx {
                match m {
                    Msg::Batch(b) => sink_ref.write(b)?,
                    Msg::Checkpoint(c) => sink_ref.checkpoint(c)?,
                }
            }
            Ok(())
        });
        let parsed = parse_loop(&mut records, &mut engine, &tx, opts, size, progress, cancel);
        drop(tx);
        let written = writer
            .join()
            .unwrap_or_else(|_| Err(ApiError::internal("index writer panicked")));
        match (parsed, written) {
            (_, Err(e)) => Err(e),
            (Err(e), Ok(())) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        }
    });
    result?;

    row.first_ts = engine.first_ts.unwrap_or(0);
    row.last_ts = engine.last_ts.unwrap_or(0);
    row.frame_count = engine.frames;
    sink.finish(&row)?;
    Ok(row)
}

fn parse_loop<R: Read>(
    records: &mut Records<R>,
    engine: &mut Engine,
    tx: &SyncSender<Msg>,
    opts: &IngestOptions,
    size: u64,
    progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> ApiResult<()> {
    let mut last_cp = records.offset();
    let mut last_progress = records.offset();
    let mut since_cancel_check = 0u64;
    loop {
        let next = records.next_record()?;
        match next {
            Next::Frame(f) => {
                let (ts, off, wl, lt) = (f.ts, f.file_offset, f.wirelen, f.link_type);
                engine.on_frame(ts, off, wl, lt, f.data);
            }
            Next::Eof | Next::Truncated | Next::Corrupt(_) => break,
        }
        flush(&mut engine.out, tx, false, opts.batch_rows)?;
        since_cancel_check += 1;
        if since_cancel_check >= CANCEL_EVERY {
            since_cancel_check = 0;
            if cancel.load(Ordering::Relaxed) {
                return Err(ApiError::new(ErrorCode::Cancelled, "ingest cancelled"));
            }
        }
        let off = records.offset();
        if off.saturating_sub(last_progress) >= PROGRESS_EVERY {
            last_progress = off;
            progress(Progress {
                bytes_done: off,
                bytes_total: size,
                frames: engine.frames,
            });
        }
        if opts.checkpoint_bytes > 0 && off.saturating_sub(last_cp) >= opts.checkpoint_bytes {
            last_cp = off;
            flush(&mut engine.out, tx, true, opts.batch_rows)?;
            let saved = SavedState {
                version: STATE_VERSION,
                reader: records.state.clone(),
                flows: engine.table.save(),
                first_ts: engine.first_ts,
                last_ts: engine.last_ts,
            };
            let state = serde_json::to_vec(&saved)
                .map_err(|e| ApiError::internal(format!("checkpoint encode: {e}")))?;
            send(
                tx,
                Msg::Checkpoint(Checkpoint {
                    file_offset: off,
                    frames_emitted: engine.frames,
                    next_flow_id: engine.table.next_id,
                    state,
                }),
            )?;
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(ApiError::new(ErrorCode::Cancelled, "ingest cancelled"));
    }
    engine.table.finish_all(&mut engine.out);
    flush(&mut engine.out, tx, true, opts.batch_rows)?;
    progress(Progress {
        bytes_done: size,
        bytes_total: size,
        frames: engine.frames,
    });
    Ok(())
}
