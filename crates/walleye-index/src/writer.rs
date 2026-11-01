//! `IndexWriter`: the ingest-side `IndexSink`.
//!
//! Rows are appended to in-memory DuckDB staging tables. At each accepted
//! checkpoint every staging table is written as one Parquet *segment*
//! (`<table>/seg-NNNNNN.parquet`), fsynced, renamed into place, and only then
//! is `checkpoint.json` replaced (write tmp + fsync + rename). Segment numbers
//! below `checkpoint.segments` are therefore durable; anything else found on
//! resume was written after the last accepted checkpoint and is deleted.
//! That is the invariant in `walleye_core::sink`.
//!
//! `finish` compacts each table's segments into one file sorted by time
//! (zstd, 122 880-row groups), writes `manifest.json` (the "index complete"
//! marker `Index::open` requires), then removes the segments.

use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::Engine as _;
use duckdb::{Connection, appender_params_from_iter};
use serde::{Deserialize, Serialize};
use walleye_core::{
    ApiError, CaptureRow,
    error::ApiResult,
    sink::{Checkpoint, IndexSink, RecordBatch},
};

use crate::schema::{self, ALL_TABLES, DATA_TABLES, Tab};

/// 3: the `wifi` table (contract v2, 802.11 captures).
pub(crate) const FORMAT_VERSION: u32 = 3;
pub(crate) const MANIFEST: &str = "manifest.json";
const CHECKPOINT: &str = "checkpoint.json";
/// Parquet options for every file we write.
pub(crate) const PARQUET_OPTS: &str = "FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880";

/// `checkpoint.json` (CONTRACTS §8): last accepted checkpoint, state base64.
#[derive(Debug, Serialize, Deserialize)]
struct CheckpointFile {
    version: u32,
    sha256: String,
    /// Segments `0..segments` are committed.
    segments: u32,
    file_offset: u64,
    frames_emitted: u64,
    next_flow_id: u64,
    state_b64: String,
}

/// `manifest.json`: written last by `finish`; its presence means complete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub version: u32,
    pub capture: CaptureRow,
    /// Table name → Parquet files relative to the index dir.
    pub files: std::collections::BTreeMap<String, Vec<String>>,
}

pub(crate) fn db(e: duckdb::Error) -> ApiError {
    ApiError::internal(format!("index: {e}"))
}

pub(crate) fn io_ctx(what: &str, e: std::io::Error) -> ApiError {
    ApiError::new(walleye_core::ErrorCode::Io, format!("{what}: {e}"))
}

/// SQL string literal for a path we created (never user filter text).
pub(crate) fn sql_path(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}

pub(crate) fn fsync_file(p: &Path) -> ApiResult<()> {
    fs::File::open(p)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_ctx("fsync", e))
}

pub(crate) fn fsync_dir(p: &Path) -> ApiResult<()> {
    // Directory fsync makes renames durable on Linux/macOS.
    match fs::File::open(p) {
        Ok(f) => {
            let _ = f.sync_all();
            Ok(())
        }
        Err(e) => Err(io_ctx("fsync dir", e)),
    }
}

/// Write `bytes` to `path` atomically (tmp + fsync + rename + dir fsync).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> ApiResult<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes).map_err(|e| io_ctx("write", e))?;
    fsync_file(&tmp)?;
    fs::rename(&tmp, path).map_err(|e| io_ctx("rename", e))?;
    if let Some(d) = path.parent() {
        fsync_dir(d)?;
    }
    Ok(())
}

/// Hardening applied to every DuckDB connection we open: never fetch or load
/// extensions at runtime (no network), no community extensions.
pub(crate) fn harden(conn: &Connection) -> ApiResult<()> {
    conn.execute_batch(
        "SET autoinstall_known_extensions = false;
         SET autoload_known_extensions = false;
         SET allow_community_extensions = false;",
    )
    .map_err(db)
}

pub struct IndexWriter {
    dir: PathBuf,
    conn: Connection,
    sha256: Option<String>,
    /// Next segment number.
    seg: u32,
    staged: [u64; DATA_TABLES.len()],
}

fn stage(t: Tab) -> String {
    format!("stage_{}", t.name())
}

fn data_idx(t: Tab) -> usize {
    DATA_TABLES.iter().position(|x| *x == t).unwrap_or(0)
}

impl IndexWriter {
    /// Prepares a writer for `index_dir` (created if missing). Nothing is
    /// deleted until `begin` knows which capture is being indexed.
    pub fn create(index_dir: &Path) -> ApiResult<Self> {
        fs::create_dir_all(index_dir).map_err(|e| io_ctx("create index dir", e))?;
        let conn = Connection::open_in_memory().map_err(db)?;
        harden(&conn)?;
        let spill = index_dir.join(".spill");
        conn.execute_batch(&format!(
            "SET memory_limit = '2GB'; SET temp_directory = {}; SET preserve_insertion_order = false;",
            sql_path(&spill)
        ))
        .map_err(db)?;
        for t in DATA_TABLES {
            conn.execute_batch(&t.ddl(&stage(t))).map_err(db)?;
        }
        Ok(Self {
            dir: index_dir.to_path_buf(),
            conn,
            sha256: None,
            seg: 0,
            staged: [0; DATA_TABLES.len()],
        })
    }

    fn table_dir(&self, t: Tab) -> PathBuf {
        self.dir.join(t.name())
    }

    fn seg_path(&self, t: Tab, n: u32) -> PathBuf {
        self.table_dir(t).join(format!("seg-{n:06}.parquet"))
    }

    /// Removes everything in the table dirs except committed segments `< keep`.
    fn prune(&self, keep: u32) -> ApiResult<()> {
        for t in ALL_TABLES {
            let d = self.table_dir(t);
            fs::create_dir_all(&d).map_err(|e| io_ctx("create table dir", e))?;
            let entries = fs::read_dir(&d).map_err(|e| io_ctx("read table dir", e))?;
            for ent in entries.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                let committed = name
                    .strip_prefix("seg-")
                    .and_then(|s| s.strip_suffix(".parquet"))
                    .and_then(|n| n.parse::<u32>().ok())
                    .is_some_and(|n| n < keep);
                if !committed {
                    let p = ent.path();
                    if p.is_dir() {
                        fs::remove_dir_all(&p).map_err(|e| io_ctx("remove", e))?;
                    } else {
                        fs::remove_file(&p).map_err(|e| io_ctx("remove", e))?;
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(self.dir.join(".spill"));
        Ok(())
    }

    fn append(
        &mut self,
        t: Tab,
        rows: impl Iterator<Item = ApiResult<Vec<duckdb::types::Value>>>,
    ) -> ApiResult<()> {
        let name = stage(t);
        let mut app = self.conn.appender(&name).map_err(db)?;
        let mut n = 0u64;
        for r in rows {
            app.append_row(appender_params_from_iter(r?)).map_err(db)?;
            n += 1;
        }
        app.flush().map_err(db)?;
        self.staged[data_idx(t)] += n;
        Ok(())
    }

    /// Writes all non-empty staging tables as segment `seg` and clears them.
    fn flush_segment(&mut self) -> ApiResult<()> {
        for t in DATA_TABLES {
            if self.staged[data_idx(t)] == 0 {
                continue;
            }
            let path = self.seg_path(t, self.seg);
            let tmp = path.with_extension("parquet.tmp");
            self.conn
                .execute_batch(&format!(
                    "COPY (SELECT * FROM {} ORDER BY {}) TO {} ({PARQUET_OPTS}); DELETE FROM {};",
                    stage(t),
                    t.order_by(),
                    sql_path(&tmp),
                    stage(t)
                ))
                .map_err(db)?;
            fsync_file(&tmp)?;
            fs::rename(&tmp, &path).map_err(|e| io_ctx("rename segment", e))?;
            fsync_dir(&self.table_dir(t))?;
            self.staged[data_idx(t)] = 0;
        }
        Ok(())
    }

    fn segments(&self, t: Tab) -> ApiResult<Vec<PathBuf>> {
        let mut v: Vec<PathBuf> = fs::read_dir(self.table_dir(t))
            .map_err(|e| io_ctx("read table dir", e))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".parquet"))
            })
            .collect();
        v.sort();
        Ok(v)
    }

    /// Writes `t`'s single compacted file from its segments (or an empty one).
    fn compact(&self, t: Tab) -> ApiResult<String> {
        let segs = self.segments(t)?;
        let rel = format!("{}/data-0.parquet", t.name());
        let out = self.dir.join(&rel);
        let tmp = out.with_extension("parquet.tmp");
        let src = if segs.is_empty() {
            stage(t)
        } else {
            let list: Vec<String> = segs.iter().map(|p| sql_path(p)).collect();
            format!("read_parquet([{}])", list.join(", "))
        };
        self.conn
            .execute_batch(&format!(
                "COPY (SELECT {} FROM {src} ORDER BY {}) TO {} ({PARQUET_OPTS});",
                t.column_list(),
                t.order_by(),
                sql_path(&tmp)
            ))
            .map_err(db)?;
        fsync_file(&tmp)?;
        fs::rename(&tmp, &out).map_err(|e| io_ctx("rename", e))?;
        fsync_dir(&self.table_dir(t))?;
        Ok(rel)
    }
}

/// Writes one table from in-memory rows to `<dir>/<rel>` via a temp table.
pub(crate) fn write_table(
    conn: &Connection,
    dir: &Path,
    t: Tab,
    rel: &str,
    rows: Vec<Vec<duckdb::types::Value>>,
) -> ApiResult<()> {
    let tmp_table = format!("tmp_{}", t.name());
    conn.execute_batch(&t.ddl(&tmp_table)).map_err(db)?;
    {
        let mut app = conn.appender(&tmp_table).map_err(db)?;
        for r in rows {
            app.append_row(appender_params_from_iter(r)).map_err(db)?;
        }
        app.flush().map_err(db)?;
    }
    let out = dir.join(rel);
    if let Some(p) = out.parent() {
        fs::create_dir_all(p).map_err(|e| io_ctx("create dir", e))?;
    }
    let tmp = out.with_extension("parquet.tmp");
    conn.execute_batch(&format!(
        "COPY (SELECT * FROM {tmp_table} ORDER BY {}) TO {} ({PARQUET_OPTS}); DROP TABLE {tmp_table};",
        t.order_by(),
        sql_path(&tmp)
    ))
    .map_err(db)?;
    fsync_file(&tmp)?;
    fs::rename(&tmp, &out).map_err(|e| io_ctx("rename", e))?;
    if let Some(p) = out.parent() {
        fsync_dir(p)?;
    }
    Ok(())
}

impl IndexSink for IndexWriter {
    fn begin(&mut self, capture: &CaptureRow) -> ApiResult<Option<Checkpoint>> {
        let cp_path = self.dir.join(CHECKPOINT);
        let prior: Option<CheckpointFile> = fs::read(&cp_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .filter(|c: &CheckpointFile| c.version == FORMAT_VERSION && c.sha256 == capture.sha256);
        for t in DATA_TABLES {
            self.conn
                .execute_batch(&format!("DELETE FROM {}", stage(t)))
                .map_err(db)?;
        }
        self.staged = [0; DATA_TABLES.len()];
        self.sha256 = Some(capture.sha256.clone());
        // An index being (re)written is not complete.
        let _ = fs::remove_file(self.dir.join(MANIFEST));
        match prior {
            Some(c) => {
                let state = base64::engine::general_purpose::STANDARD
                    .decode(c.state_b64.as_bytes())
                    .map_err(|_| ApiError::internal("checkpoint state is not base64"))?;
                self.prune(c.segments)?;
                self.seg = c.segments;
                Ok(Some(Checkpoint {
                    file_offset: c.file_offset,
                    frames_emitted: c.frames_emitted,
                    next_flow_id: c.next_flow_id,
                    state,
                }))
            }
            None => {
                let _ = fs::remove_file(&cp_path);
                self.prune(0)?;
                self.seg = 0;
                Ok(None)
            }
        }
    }

    fn write(&mut self, batch: RecordBatch) -> ApiResult<()> {
        if self.sha256.is_none() {
            return Err(ApiError::internal("IndexWriter::write before begin"));
        }
        match batch {
            RecordBatch::Frames(v) => {
                self.append(Tab::Frames, v.iter().map(|r| Ok(schema::frame_values(r))))
            }
            RecordBatch::Flows(v) => {
                self.append(Tab::Flows, v.iter().map(|r| Ok(schema::flow_values(r))))
            }
            RecordBatch::Dns(v) => {
                self.append(Tab::Dns, v.iter().map(|r| Ok(schema::dns_values(r))))
            }
            RecordBatch::Http(v) => {
                self.append(Tab::Http, v.iter().map(|r| Ok(schema::http_values(r))))
            }
            RecordBatch::Tls(v) => {
                self.append(Tab::Tls, v.iter().map(|r| Ok(schema::tls_values(r))))
            }
            RecordBatch::Files(v) => {
                self.append(Tab::Files, v.iter().map(|r| Ok(schema::file_values(r))))
            }
            RecordBatch::Wifi(v) => {
                self.append(Tab::Wifi, v.iter().map(|r| Ok(schema::wifi_values(r))))
            }
        }
    }

    fn checkpoint(&mut self, cp: Checkpoint) -> ApiResult<()> {
        let Some(sha) = self.sha256.clone() else {
            return Err(ApiError::internal("checkpoint before begin"));
        };
        self.flush_segment()?;
        let file = CheckpointFile {
            version: FORMAT_VERSION,
            sha256: sha,
            segments: self.seg + 1,
            file_offset: cp.file_offset,
            frames_emitted: cp.frames_emitted,
            next_flow_id: cp.next_flow_id,
            state_b64: base64::engine::general_purpose::STANDARD.encode(&cp.state),
        };
        let bytes = serde_json::to_vec(&file).map_err(|e| ApiError::internal(e.to_string()))?;
        write_atomic(&self.dir.join(CHECKPOINT), &bytes)?;
        self.seg += 1;
        Ok(())
    }

    fn finish(&mut self, capture: &CaptureRow) -> ApiResult<()> {
        if self.sha256.as_deref() != Some(capture.sha256.as_str()) {
            return Err(ApiError::internal(
                "finish for a different capture than begin",
            ));
        }
        self.flush_segment()?;
        let mut files = std::collections::BTreeMap::new();
        for t in DATA_TABLES {
            files.insert(t.name().to_string(), vec![self.compact(t)?]);
        }
        for (t, rel) in [
            (Tab::Findings, "findings/data-0.parquet"),
            (Tab::Iocs, "iocs/data-0.parquet"),
        ] {
            write_table(&self.conn, &self.dir, t, rel, Vec::new())?;
            files.insert(t.name().to_string(), vec![rel.to_string()]);
        }
        let rel = "captures/data-0.parquet";
        write_table(
            &self.conn,
            &self.dir,
            Tab::Captures,
            rel,
            vec![schema::capture_values(capture)],
        )?;
        files.insert("captures".to_string(), vec![rel.to_string()]);
        let manifest = Manifest {
            version: FORMAT_VERSION,
            capture: capture.clone(),
            files,
        };
        let bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|e| ApiError::internal(e.to_string()))?;
        write_atomic(&self.dir.join(MANIFEST), &bytes)?;
        // Complete: segments and the resume point are no longer needed.
        for t in DATA_TABLES {
            for s in self.segments(t)? {
                let _ = fs::remove_file(s);
            }
        }
        let _ = fs::remove_file(self.dir.join(CHECKPOINT));
        let _ = fs::remove_dir_all(self.dir.join(".spill"));
        Ok(())
    }
}
