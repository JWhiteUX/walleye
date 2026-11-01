//! Case store: SQLite at `<case_dir>/case.sqlite`.
//!
//! Holds pins (with the evidence resolved at pin time), analyst notes (pins
//! of kind `note`), verdicts and the query log. Every statement uses bound
//! parameters; no value is ever formatted into SQL text. The schema is
//! versioned with `PRAGMA user_version` and migrated forward on open.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use walleye_core::{
    ApiError, CaptureRow, ErrorCode, Evidence, Verdict,
    error::ApiResult,
    ipc::{Case, EvidenceRef, Pin, QueryLogEntry, TimeRange, VerdictEntry, View},
};

use crate::timefmt::now_us;

/// Longest note or verdict note accepted, in bytes.
pub const MAX_NOTE_BYTES: usize = 16 * 1024;
/// Query log entries kept (oldest are dropped first).
pub const MAX_QUERY_LOG: i64 = 10_000;

/// Forward-only migrations; index + 1 is the schema version it produces.
const MIGRATIONS: &[&str] = &[
    // v1
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
     CREATE TABLE pins (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        pin_id TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        note TEXT NOT NULL,
        resolved_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
     );
     CREATE TABLE verdicts (
        finding_id TEXT PRIMARY KEY,
        verdict TEXT NOT NULL,
        note TEXT NOT NULL,
        at INTEGER NOT NULL
     );
     CREATE TABLE verdict_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT NOT NULL,
        verdict TEXT NOT NULL,
        note TEXT NOT NULL,
        at INTEGER NOT NULL
     );
     CREATE TABLE queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filter TEXT NOT NULL,
        view TEXT NOT NULL,
        time_start INTEGER,
        time_end INTEGER,
        sql TEXT,
        rows INTEGER NOT NULL,
        at INTEGER NOT NULL
     );",
];

/// Current schema version.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

fn db_err(e: rusqlite::Error) -> ApiError {
    ApiError::new(ErrorCode::Io, format!("case store: {e}"))
}

fn json_err(e: serde_json::Error) -> ApiError {
    ApiError::internal(format!("case store json: {e}"))
}

fn enum_text<T: serde::Serialize>(v: &T) -> ApiResult<String> {
    match serde_json::to_value(v).map_err(json_err)? {
        serde_json::Value::String(s) => Ok(s),
        other => Err(ApiError::internal(format!(
            "unexpected enum encoding {other}"
        ))),
    }
}

fn enum_parse<T: serde::de::DeserializeOwned>(s: &str) -> ApiResult<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(json_err)
}

fn check_note(note: &str) -> ApiResult<()> {
    if note.len() > MAX_NOTE_BYTES {
        return Err(ApiError::new(
            ErrorCode::InvalidArgument,
            format!("note is longer than {MAX_NOTE_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn kind_of(e: &EvidenceRef) -> &'static str {
    match e {
        EvidenceRef::Frame { .. } => "frame",
        EvidenceRef::Flow { .. } => "flow",
        EvidenceRef::Finding { .. } => "finding",
        EvidenceRef::Ioc { .. } => "ioc",
        EvidenceRef::Query { .. } => "query",
        EvidenceRef::Note => "note",
    }
}

pub struct CaseStore {
    conn: Connection,
    capture: CaptureRow,
}

impl CaseStore {
    /// Open (creating if needed) the case at `case_dir`. Fails with
    /// `invalid_argument` if the store belongs to a different capture.
    pub fn open(case_dir: &Path, capture: &CaptureRow) -> ApiResult<Self> {
        std::fs::create_dir_all(case_dir)?;
        let conn = Connection::open(case_dir.join("case.sqlite")).map_err(db_err)?;
        Self::init(conn, capture)
    }

    /// In-memory store, for tests and previews.
    pub fn open_in_memory(capture: &CaptureRow) -> ApiResult<Self> {
        Self::init(Connection::open_in_memory().map_err(db_err)?, capture)
    }

    fn init(mut conn: Connection, capture: &CaptureRow) -> ApiResult<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(db_err)?;
        migrate(&mut conn)?;
        let stored: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'capture_sha256'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        match stored {
            Some(sha) if sha != capture.sha256 => {
                return Err(ApiError::new(
                    ErrorCode::InvalidArgument,
                    "case store belongs to a different capture",
                ));
            }
            _ => {}
        }
        let cap_json = serde_json::to_string(capture).map_err(json_err)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('capture_sha256', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![capture.sha256],
        )
        .map_err(db_err)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('capture', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![cap_json],
        )
        .map_err(db_err)?;
        Ok(Self {
            conn,
            capture: capture.clone(),
        })
    }

    pub fn schema_version(&self) -> ApiResult<u32> {
        self.conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db_err)
    }

    pub fn get_case(&self) -> ApiResult<Case> {
        Ok(Case {
            case_id: self.capture.capture_id.clone(),
            capture: self.capture.clone(),
            pins: self.pins()?,
            verdicts: self.verdicts()?,
            queries: self.queries()?,
        })
    }

    pub fn pins(&self) -> ApiResult<Vec<Pin>> {
        let mut st = self
            .conn
            .prepare(
                "SELECT pin_id, evidence_json, note, resolved_json, created_at
                 FROM pins ORDER BY seq",
            )
            .map_err(db_err)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (pin_id, ev, note, res, created_at) = row.map_err(db_err)?;
            out.push(Pin {
                pin_id,
                evidence: serde_json::from_str(&ev).map_err(json_err)?,
                note,
                resolved: serde_json::from_str(&res).map_err(json_err)?,
                created_at,
            });
        }
        Ok(out)
    }

    /// Pin evidence with a note. `resolved` must reach at least one frame or
    /// flow, except for `EvidenceRef::Note`, which has none.
    pub fn pin(&self, evidence: &EvidenceRef, note: &str, resolved: &Evidence) -> ApiResult<Pin> {
        check_note(note)?;
        let is_note = matches!(evidence, EvidenceRef::Note);
        if is_note && note.trim().is_empty() {
            return Err(ApiError::new(ErrorCode::InvalidArgument, "note is empty"));
        }
        if !is_note && resolved.is_empty() {
            return Err(ApiError::new(
                ErrorCode::InvalidArgument,
                "evidence resolved to no frames or flows",
            ));
        }
        let resolved = if is_note {
            Evidence::default()
        } else {
            resolved.clone()
        };
        let created_at = now_us();
        let ev_json = serde_json::to_string(evidence).map_err(json_err)?;
        let res_json = serde_json::to_string(&resolved).map_err(json_err)?;
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        // Reserve the next sequence number, then name the pin after it.
        tx.execute(
            "INSERT INTO pins (pin_id, kind, evidence_json, note, resolved_json, created_at)
             VALUES ('', ?1, ?2, ?3, ?4, ?5)",
            params![kind_of(evidence), ev_json, note, res_json, created_at],
        )
        .map_err(db_err)?;
        let seq = tx.last_insert_rowid();
        let pin_id = format!("pin-{seq}");
        tx.execute(
            "UPDATE pins SET pin_id = ?1 WHERE seq = ?2",
            params![pin_id, seq],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(Pin {
            pin_id,
            evidence: evidence.clone(),
            note: note.to_string(),
            resolved,
            created_at,
        })
    }

    pub fn unpin(&self, pin_id: &str) -> ApiResult<()> {
        let n = self
            .conn
            .execute("DELETE FROM pins WHERE pin_id = ?1", params![pin_id])
            .map_err(db_err)?;
        if n == 0 {
            return Err(ApiError::not_found(format!("pin {pin_id}")));
        }
        Ok(())
    }

    /// Replace a pin's note in place (keeps its id, order and evidence).
    /// Not yet exposed over IPC; see the contract request in the report.
    pub fn update_note(&self, pin_id: &str, note: &str) -> ApiResult<Pin> {
        check_note(note)?;
        let kind: Option<String> = self
            .conn
            .query_row(
                "SELECT kind FROM pins WHERE pin_id = ?1",
                params![pin_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        match kind.as_deref() {
            None => return Err(ApiError::not_found(format!("pin {pin_id}"))),
            Some("note") if note.trim().is_empty() => {
                return Err(ApiError::new(ErrorCode::InvalidArgument, "note is empty"));
            }
            Some(_) => {}
        }
        self.conn
            .execute(
                "UPDATE pins SET note = ?1 WHERE pin_id = ?2",
                params![note, pin_id],
            )
            .map_err(db_err)?;
        self.pins()?
            .into_iter()
            .find(|p| p.pin_id == pin_id)
            .ok_or_else(|| ApiError::not_found(format!("pin {pin_id}")))
    }

    pub fn set_verdict(&self, finding_id: &str, verdict: Verdict, note: &str) -> ApiResult<()> {
        check_note(note)?;
        if finding_id.is_empty() || finding_id.len() > 64 {
            return Err(ApiError::new(ErrorCode::InvalidArgument, "bad finding_id"));
        }
        let v = enum_text(&verdict)?;
        let at = now_us();
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO verdicts (finding_id, verdict, note, at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(finding_id) DO UPDATE SET
               verdict = excluded.verdict, note = excluded.note, at = excluded.at",
            params![finding_id, v, note, at],
        )
        .map_err(db_err)?;
        tx.execute(
            "INSERT INTO verdict_log (finding_id, verdict, note, at) VALUES (?1, ?2, ?3, ?4)",
            params![finding_id, v, note, at],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Latest verdict per finding, oldest first.
    pub fn verdicts(&self) -> ApiResult<Vec<VerdictEntry>> {
        let mut st = self
            .conn
            .prepare("SELECT finding_id, verdict, note, at FROM verdicts ORDER BY at, finding_id")
            .map_err(db_err)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (finding_id, v, note, at) = row.map_err(db_err)?;
            out.push(VerdictEntry {
                finding_id,
                verdict: enum_parse(&v)?,
                note,
                at,
            });
        }
        Ok(out)
    }

    pub fn log_query(&self, e: &QueryLogEntry) -> ApiResult<()> {
        let view = enum_text(&e.view)?;
        let (ts, te) = match e.time_range {
            Some(r) => (Some(r.start), Some(r.end)),
            None => (None, None),
        };
        let rows = i64::try_from(e.rows).unwrap_or(i64::MAX);
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO queries (filter, view, time_start, time_end, sql, rows, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![e.filter, view, ts, te, e.sql, rows, e.at],
        )
        .map_err(db_err)?;
        tx.execute(
            "DELETE FROM queries WHERE id <= (SELECT MAX(id) FROM queries) - ?1",
            params![MAX_QUERY_LOG],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    pub fn queries(&self) -> ApiResult<Vec<QueryLogEntry>> {
        let mut st = self
            .conn
            .prepare(
                "SELECT filter, view, time_start, time_end, sql, rows, at FROM queries ORDER BY id",
            )
            .map_err(db_err)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (filter, view, ts, te, sql, rows, at) = row.map_err(db_err)?;
            out.push(QueryLogEntry {
                filter,
                view: enum_parse::<View>(&view)?,
                time_range: match (ts, te) {
                    (Some(start), Some(end)) => Some(TimeRange { start, end }),
                    _ => None,
                },
                sql,
                rows: u64::try_from(rows).unwrap_or(0),
                at,
            });
        }
        Ok(out)
    }
}

fn migrate(conn: &mut Connection) -> ApiResult<()> {
    let current: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(db_err)?;
    if current > SCHEMA_VERSION {
        return Err(ApiError::new(
            ErrorCode::InvalidArgument,
            format!("case store schema v{current} is newer than this build (v{SCHEMA_VERSION})"),
        ));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute_batch(sql).map_err(db_err)?;
        // PRAGMA cannot take a bound parameter; the value is a trusted integer.
        tx.pragma_update(None, "user_version", (i + 1) as u32)
            .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
    }
    Ok(())
}
