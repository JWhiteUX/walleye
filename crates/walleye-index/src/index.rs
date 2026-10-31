//! `Index`: read side over the Parquet files, via DuckDB views.
//!
//! One in-memory DuckDB database per open index; queries run on cloned
//! connections from a small pool, so `Index` is `Send + Sync` and concurrent
//! reads do not serialize on one connection.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};

use base64::Engine as _;
use duckdb::{Connection, params_from_iter};
use serde::{Deserialize, Serialize};
use walleye_core::{
    ApiError, CaptureRow, DnsRow, ErrorCode, Finding, FlowRow, FrameRow, HttpRow, Ioc, TlsRow,
    error::ApiResult,
    fields::{FieldDef, FieldType},
    ipc::{
        Bucket, FindingsFilter, FrameRef, Lane, Lanes, Page, QueryRequest, RowSet, Suggestion,
        SuggestionKind, TimeRange, TimelineRequest, View,
    },
    sink::{DetectSource, ResultSink},
};

use crate::{
    filter::{self, CompletionKind, Param},
    schema::{self, ALL_TABLES, Tab},
    writer::{MANIFEST, Manifest, db, harden, io_ctx, sql_path, write_atomic, write_table},
};

/// Max rows per page (CONTRACTS §3).
pub const MAX_LIMIT: u32 = 10_000;
const MAX_HOSTS: usize = 1_000;
const MAX_FLOW_IDS: usize = 10_000;
const MAX_CURSOR_LEN: usize = 16 * 1024;
/// IPv6 networks resolving to more addresses than this are rejected.
const MAX_V6_SET: usize = 10_000;
const MAX_BUCKETS: u64 = 2_000;
const BULK_BYTES: i64 = 1 << 20;

pub struct Index {
    dir: PathBuf,
    capture: CaptureRow,
    manifest: Mutex<Manifest>,
    base: Mutex<Connection>,
    pool: Mutex<Vec<Connection>>,
    top_values: Mutex<HashMap<String, Vec<(String, u64)>>>,
}

struct Lease<'a> {
    idx: &'a Index,
    conn: Option<Connection>,
}

impl std::ops::Deref for Lease<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        // Always Some until drop.
        self.conn.as_ref().unwrap_or_else(|| unreachable!())
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take()
            && let Ok(mut p) = self.idx.pool.lock()
            && p.len() < 16
        {
            p.push(c);
        }
    }
}

fn view_tab(v: View) -> Tab {
    match v {
        View::Flows => Tab::Flows,
        View::Dns => Tab::Dns,
        View::Http => Tab::Http,
        View::Tls => Tab::Tls,
        View::Files => Tab::Files,
        View::Frames => Tab::Frames,
    }
}

fn keys(v: View) -> &'static [&'static str] {
    match v {
        View::Flows => &["flow_id"],
        View::Frames => &["frame_no"],
        _ => &["flow_id", "frame_no"],
    }
}

fn default_sort(v: View) -> &'static str {
    match v {
        View::Flows => "ts_start",
        View::Frames => "frame_no",
        _ => "ts",
    }
}

fn invalid(msg: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::InvalidArgument, msg)
}

/// Opaque pagination cursor (base64url JSON). Keyset on
/// `(sort value, key columns)` plus a count of already-returned rows that tie
/// on that tuple; `q` binds it to the query it came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Cursor {
    v: u32,
    q: String,
    keyset: bool,
    s: serde_json::Value,
    k: Vec<i64>,
    skip: u64,
    total: Option<u64>,
}

fn fnv(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn query_hash(req: &QueryRequest) -> String {
    let key = serde_json::json!([
        req.filter,
        req.view,
        req.time_range,
        req.hosts,
        req.flow_ids,
        req.sort
    ]);
    fnv(&key.to_string())
}

fn decode_cursor(s: &str, q: &str) -> ApiResult<Cursor> {
    if s.len() > MAX_CURSOR_LEN {
        return Err(invalid("bad cursor"));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| invalid("bad cursor"))?;
    let c: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid("bad cursor"))?;
    if c.v != 1 || c.q != q {
        return Err(invalid("cursor does not belong to this query"));
    }
    let scalar = matches!(
        c.s,
        serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_)
    );
    if !scalar || (c.keyset && c.k.is_empty()) || c.k.len() > 2 {
        return Err(invalid("bad cursor"));
    }
    Ok(c)
}

fn encode_cursor(c: &Cursor) -> String {
    let json = serde_json::to_vec(c).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

fn json_param(v: &serde_json::Value) -> ApiResult<Param> {
    match v {
        serde_json::Value::Bool(b) => Ok(Param::Bool(*b)),
        serde_json::Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))
            .map(Param::Int)
            .ok_or_else(|| invalid("bad cursor")),
        serde_json::Value::String(s) => Ok(Param::Str(s.clone())),
        _ => Err(invalid("bad cursor")),
    }
}

fn canon_ip(s: &str) -> ApiResult<String> {
    s.parse::<IpAddr>()
        .map(|a| a.to_string())
        .map_err(|_| invalid("hosts must be IP addresses"))
}

fn placeholders(n: usize) -> String {
    vec!["?"; n].join(", ")
}

fn tcp_flag_names(fl: u8) -> String {
    [
        (0x02, "SYN"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
    ]
    .iter()
    .filter(|(b, _)| fl & b != 0)
    .map(|(_, n)| *n)
    .collect::<Vec<_>>()
    .join(", ")
}

/// One-line frame summary, e.g. "TCP 51234 → 443 [SYN] len=0" (same format
/// as the mock backend).
pub fn frame_summary(fr: &FrameRow, flow: Option<&FlowRow>) -> String {
    let Some(f) = flow else {
        return format!("Frame {} len={}", fr.frame_no, fr.caplen);
    };
    let (sp, dp) = match fr.direction {
        Some(walleye_core::Direction::Down) => (f.dst_port, f.src_port),
        _ => (f.src_port, f.dst_port),
    };
    match f.proto {
        6 => format!(
            "TCP {sp} → {dp} [{}] len={}",
            tcp_flag_names(fr.tcp_flags.unwrap_or(0)),
            fr.payload_len
        ),
        17 => format!(
            "UDP {sp} → {dp} {}len={}",
            f.app_proto
                .as_deref()
                .map(|a| format!("{} ", a.to_uppercase()))
                .unwrap_or_default(),
            fr.payload_len
        ),
        p => format!("IP proto {p} len={}", fr.payload_len),
    }
}

/// Built query: SQL with `?` placeholders and its params.
struct Built {
    sql: String,
    params: Vec<Param>,
}

impl Index {
    /// Opens a complete index (one whose writer called `finish`).
    pub fn open(index_dir: &Path) -> ApiResult<Self> {
        let bytes = fs::read(index_dir.join(MANIFEST)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ApiError::not_found("index is missing or incomplete")
            } else {
                io_ctx("read manifest", e)
            }
        })?;
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::internal(format!("manifest: {e}")))?;
        if manifest.version != crate::writer::FORMAT_VERSION {
            return Err(ApiError::internal(
                "index format version mismatch; re-index the capture",
            ));
        }
        let dir = fs::canonicalize(index_dir).map_err(|e| io_ctx("index dir", e))?;
        let conn = Connection::open_in_memory().map_err(db)?;
        harden(&conn)?;
        conn.execute_batch(filter::IP_NUM_MACRO).map_err(db)?;
        // Parquet footers are cached across queries.
        let _ = conn.execute_batch("SET enable_object_cache = true;");
        let idx = Index {
            dir: dir.clone(),
            capture: manifest.capture.clone(),
            manifest: Mutex::new(manifest),
            base: Mutex::new(conn),
            pool: Mutex::new(Vec::new()),
            top_values: Mutex::new(HashMap::new()),
        };
        idx.create_views()?;
        // Sandbox: only the index directory is readable/writable, and the
        // configuration cannot be changed afterwards.
        {
            let c = idx
                .base
                .lock()
                .map_err(|_| ApiError::internal("index lock"))?;
            let mut d = dir.to_string_lossy().to_string();
            if !d.ends_with('/') {
                d.push('/');
            }
            c.execute_batch(&format!(
                "SET allowed_directories = [{}]; SET enable_external_access = false; SET lock_configuration = true;",
                sql_path(Path::new(&d))
            ))
            .map_err(db)?;
        }
        Ok(idx)
    }

    fn create_views(&self) -> ApiResult<()> {
        let m = self
            .manifest
            .lock()
            .map_err(|_| ApiError::internal("index lock"))?
            .clone();
        let c = self
            .base
            .lock()
            .map_err(|_| ApiError::internal("index lock"))?;
        for t in ALL_TABLES {
            let files = m.files.get(t.name()).cloned().unwrap_or_default();
            let sql = if files.is_empty() {
                format!("DROP VIEW IF EXISTS {0}; {1};", t.name(), t.ddl(t.name()))
            } else {
                let list: Vec<String> = files.iter().map(|f| sql_path(&self.dir.join(f))).collect();
                format!(
                    "CREATE OR REPLACE VIEW {} AS SELECT {} FROM read_parquet([{}]);",
                    t.name(),
                    t.column_list(),
                    list.join(", ")
                )
            };
            c.execute_batch(&sql).map_err(db)?;
        }
        Ok(())
    }

    fn conn(&self) -> ApiResult<Lease<'_>> {
        let pooled = self
            .pool
            .lock()
            .map_err(|_| ApiError::internal("index lock"))?
            .pop();
        let conn = match pooled {
            Some(c) => c,
            None => self
                .base
                .lock()
                .map_err(|_| ApiError::internal("index lock"))?
                .try_clone()
                .map_err(db)?,
        };
        Ok(Lease {
            idx: self,
            conn: Some(conn),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn capture(&self) -> ApiResult<CaptureRow> {
        Ok(self.capture.clone())
    }

    /// Parses, resolves and compiles `filter` for `view`.
    pub fn compile_filter(&self, text: &str, view: View) -> ApiResult<filter::Compiled> {
        let mut expr = filter::parse(text)?;
        filter::resolve_ipv6_nets(&mut expr, &mut |f, net, prefix| {
            self.resolve_v6(f, net, prefix)
        })?;
        filter::compile(&expr, view)
    }

    fn resolve_v6(
        &self,
        f: &FieldDef,
        net: std::net::Ipv6Addr,
        prefix: u8,
    ) -> ApiResult<Vec<String>> {
        let table = filter::table_name(f.table);
        let sql = format!(
            "SELECT DISTINCT {0} FROM {table} WHERE contains({0}, ':')",
            f.sql
        );
        let c = self.conn()?;
        let mut st = c.prepare(&sql).map_err(db)?;
        let mut rows = st.query([]).map_err(db)?;
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(prefix))
        };
        let want = u128::from(net) & mask;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db)? {
            let s: String = r.get(0).map_err(db)?;
            if let Ok(a) = s.parse::<std::net::Ipv6Addr>()
                && u128::from(a) & mask == want
            {
                out.push(s);
                if out.len() > MAX_V6_SET {
                    return Err(invalid(
                        "IPv6 network matches too many addresses; narrow the prefix",
                    ));
                }
            }
        }
        Ok(out)
    }

    /// The scope predicate (filter + time range + hosts + flow ids).
    fn scope(&self, req: &QueryRequest) -> ApiResult<Built> {
        let c = self.compile_filter(&req.filter, req.view)?;
        let mut sql = c.sql;
        let mut params = c.params;
        if let Some(tr) = &req.time_range {
            if tr.end < tr.start {
                return Err(invalid("time_range end is before start"));
            }
            if req.view == View::Flows {
                sql.push_str(" AND (ts_start < ? AND ts_end >= ?)");
                params.extend([Param::Int(tr.end), Param::Int(tr.start)]);
            } else {
                sql.push_str(" AND (ts >= ? AND ts < ?)");
                params.extend([Param::Int(tr.start), Param::Int(tr.end)]);
            }
        }
        if !req.hosts.is_empty() {
            if req.hosts.len() > MAX_HOSTS {
                return Err(invalid(format!("at most {MAX_HOSTS} hosts")));
            }
            let hs: Vec<String> = req
                .hosts
                .iter()
                .map(|h| canon_ip(h))
                .collect::<ApiResult<_>>()?;
            let ph = placeholders(hs.len());
            let inner = format!("(src_ip IN ({ph}) OR dst_ip IN ({ph}))");
            if req.view == View::Flows {
                sql.push_str(&format!(" AND {inner}"));
            } else {
                sql.push_str(&format!(
                    " AND flow_id IN (SELECT flow_id FROM flows WHERE {inner})"
                ));
            }
            for _ in 0..2 {
                params.extend(hs.iter().cloned().map(Param::Str));
            }
        }
        if !req.flow_ids.is_empty() {
            if req.flow_ids.len() > MAX_FLOW_IDS {
                return Err(invalid(format!("at most {MAX_FLOW_IDS} flow_ids")));
            }
            sql.push_str(&format!(
                " AND flow_id IN ({})",
                placeholders(req.flow_ids.len())
            ));
            for id in &req.flow_ids {
                params.push(Param::Int(
                    i64::try_from(*id).map_err(|_| invalid("flow_id out of range"))?,
                ));
            }
        }
        Ok(Built { sql, params })
    }

    pub fn query(&self, req: &QueryRequest) -> ApiResult<Page> {
        let t0 = Instant::now();
        if req.limit == 0 || req.limit > MAX_LIMIT {
            return Err(invalid(format!("limit must be 1..={MAX_LIMIT}")));
        }
        let tab = view_tab(req.view);
        let cols = tab.columns();
        let (sort_col, desc) = match &req.sort {
            Some(s) => {
                // Allowlist: only the view's own column names, never interpolated
                // from the request (the matched static name is used).
                let c = cols
                    .iter()
                    .find(|(c, _)| *c == s.column)
                    .map(|(c, _)| *c)
                    .ok_or_else(|| {
                        invalid(format!("unknown sort column for {:?} view", req.view))
                    })?;
                (c, s.desc)
            }
            None => (default_sort(req.view), false),
        };
        let is_list = cols
            .iter()
            .any(|(c, t)| *c == sort_col && t.ends_with("[]"));
        let qh = query_hash(req);
        let cursor = req
            .cursor
            .as_deref()
            .map(|s| decode_cursor(s, &qh))
            .transpose()?;
        if let Some(c) = &cursor
            && c.keyset == is_list
        {
            return Err(invalid("bad cursor"));
        }
        let scope = self.scope(req)?;
        let ks = keys(req.view);

        // ORDER BY sort column, then keys, then every other scalar column so
        // the order is total (rows equal on all of them are interchangeable).
        let dir = if desc { "DESC" } else { "ASC" };
        let mut order = vec![format!("\"{sort_col}\" {dir} NULLS LAST")];
        order.extend(
            ks.iter()
                .filter(|k| **k != sort_col)
                .map(|k| format!("\"{k}\" ASC")),
        );
        if ks.len() > 1 {
            order.extend(
                cols.iter()
                    .filter(|(c, t)| *c != sort_col && !ks.contains(c) && !t.ends_with("[]"))
                    .map(|(c, _)| format!("\"{c}\" ASC NULLS LAST")),
            );
        }

        let mut sql = format!(
            "SELECT {} FROM {} WHERE {}",
            tab.column_list(),
            tab.name(),
            scope.sql
        );
        let mut params = scope.params.clone();
        let mut offset = 0u64;
        if let Some(c) = &cursor {
            offset = c.skip;
            if c.keyset {
                // Keys at or after the cursor's key tuple (ties are skipped by OFFSET).
                let (kp, key_params) = match (ks, c.k.as_slice()) {
                    ([k1], [a]) => (format!("(\"{k1}\" >= ?)"), vec![Param::Int(*a)]),
                    ([k1, k2], [a, b]) => (
                        format!("(\"{k1}\" > ? OR (\"{k1}\" = ? AND \"{k2}\" >= ?))"),
                        vec![Param::Int(*a), Param::Int(*a), Param::Int(*b)],
                    ),
                    _ => return Err(invalid("bad cursor")),
                };
                if c.s.is_null() {
                    sql.push_str(&format!(" AND (\"{sort_col}\" IS NULL AND {kp})"));
                    params.extend(key_params);
                } else {
                    let cmp = if desc { "<" } else { ">" };
                    sql.push_str(&format!(
                        " AND (\"{sort_col}\" {cmp} ? OR \"{sort_col}\" IS NULL OR (\"{sort_col}\" = ? AND {kp}))"
                    ));
                    let sv = json_param(&c.s)?;
                    params.push(sv.clone());
                    params.push(sv);
                    params.extend(key_params);
                }
            }
        }
        sql.push_str(&format!(" ORDER BY {} LIMIT ? OFFSET ?", order.join(", ")));
        params.push(Param::Int(i64::from(req.limit) + 1));
        params.push(Param::Int(
            i64::try_from(offset).map_err(|_| invalid("bad cursor"))?,
        ));

        let conn = self.conn()?;
        let mut st = conn.prepare(&sql).map_err(|e| map_query_err(&e))?;
        let mut rows = st
            .query(params_from_iter(params.iter()))
            .map_err(|e| map_query_err(&e))?;
        let mut data = match req.view {
            View::Flows => RowSet::Flows(Vec::new()),
            View::Dns => RowSet::Dns(Vec::new()),
            View::Http => RowSet::Http(Vec::new()),
            View::Tls => RowSet::Tls(Vec::new()),
            View::Files => RowSet::Files(Vec::new()),
            View::Frames => RowSet::Frames(Vec::new()),
        };
        while let Some(r) = rows.next().map_err(db)? {
            match &mut data {
                RowSet::Flows(v) => v.push(schema::flow_from(r)?),
                RowSet::Dns(v) => v.push(schema::dns_from(r)?),
                RowSet::Http(v) => v.push(schema::http_from(r)?),
                RowSet::Tls(v) => v.push(schema::tls_from(r)?),
                RowSet::Files(v) => v.push(schema::file_from(r)?),
                RowSet::Frames(v) => v.push(schema::frame_from(r)?),
            }
        }
        drop(rows);
        let more = data.len() > req.limit as usize;
        truncate(&mut data, req.limit as usize);

        let total = match &cursor {
            Some(c) => c.total,
            None => {
                let csql = format!("SELECT count(*) FROM {} WHERE {}", tab.name(), scope.sql);
                let mut cs = conn.prepare(&csql).map_err(db)?;
                let n: i64 = cs
                    .query_row(params_from_iter(scope.params.iter()), |r| r.get(0))
                    .map_err(db)?;
                Some(u64::try_from(n).unwrap_or(0))
            }
        };

        let next_cursor = if more {
            let jrows = rows_json(&data)?;
            let last = jrows
                .last()
                .ok_or_else(|| ApiError::internal("empty page"))?;
            let next = if is_list {
                Cursor {
                    v: 1,
                    q: qh.clone(),
                    keyset: false,
                    s: serde_json::Value::Null,
                    k: Vec::new(),
                    skip: offset + jrows.len() as u64,
                    total,
                }
            } else {
                let tuple = |r: &serde_json::Value| -> ApiResult<(serde_json::Value, Vec<i64>)> {
                    let s = r.get(sort_col).cloned().unwrap_or(serde_json::Value::Null);
                    let k = ks
                        .iter()
                        .map(|k| {
                            r.get(*k)
                                .and_then(serde_json::Value::as_i64)
                                .ok_or_else(|| ApiError::internal("key"))
                        })
                        .collect::<ApiResult<Vec<_>>>()?;
                    Ok((s, k))
                };
                let (ls, lk) = tuple(last)?;
                let mut ties = 0u64;
                for r in jrows.iter().rev() {
                    if tuple(r)? == (ls.clone(), lk.clone()) {
                        ties += 1;
                    } else {
                        break;
                    }
                }
                if let Some(c) = &cursor
                    && c.keyset
                    && c.s == ls
                    && c.k == lk
                    && ties == jrows.len() as u64
                {
                    ties += c.skip;
                }
                Cursor {
                    v: 1,
                    q: qh.clone(),
                    keyset: true,
                    s: ls,
                    k: lk,
                    skip: ties,
                    total,
                }
            };
            Some(encode_cursor(&next))
        } else {
            None
        };
        Ok(Page {
            data,
            next_cursor,
            total,
            sql: Some(sql),
            elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
        })
    }

    pub fn timeline(&self, req: &TimelineRequest, findings: &[Finding]) -> ApiResult<Lanes> {
        let c = self.compile_filter(&req.filter, View::Flows)?;
        let cap = &self.capture;
        let range = req.time_range.unwrap_or(TimeRange {
            start: cap.first_ts,
            end: cap.last_ts.saturating_add(1),
        });
        if range.end < range.start {
            return Err(invalid("time_range end is before start"));
        }
        let span_us = u64::try_from(range.end.saturating_sub(range.start))
            .unwrap_or(0)
            .max(1);
        let span_ms = span_us.div_ceil(1000);
        let bucket_ms = req.bucket_ms.max(1).max(span_ms.div_ceil(MAX_BUCKETS));
        let bucket_us = i64::try_from(bucket_ms.saturating_mul(1000))
            .map_err(|_| invalid("bucket_ms too large"))?;
        let max_lanes = i64::from(req.max_lanes.clamp(1, 1000));
        let sql = format!(
            "WITH f AS (SELECT src_ip, ts_start, CASE WHEN bytes_up + bytes_down >= ? THEN 3 \
               WHEN app_proto = 'dns' THEN 0 WHEN app_proto = 'tls' THEN 1 WHEN app_proto = 'http' THEN 2 ELSE 4 END AS k \
               FROM flows WHERE {} AND ts_start >= ? AND ts_start < ?), \
             top AS (SELECT src_ip FROM f GROUP BY src_ip ORDER BY count(*) DESC, src_ip LIMIT ?) \
             SELECT top.src_ip AS lane, (f.ts_start - ?) // ? AS bi, f.k, count(*) AS n \
             FROM f LEFT JOIN top ON f.src_ip = top.src_ip GROUP BY ALL",
            c.sql
        );
        let mut params = vec![Param::Int(BULK_BYTES)];
        params.extend(c.params);
        params.extend([
            Param::Int(range.start),
            Param::Int(range.end),
            Param::Int(max_lanes),
            Param::Int(range.start),
            Param::Int(bucket_us),
        ]);
        let conn = self.conn()?;
        let mut st = conn.prepare(&sql).map_err(|e| map_query_err(&e))?;
        let mut rows = st
            .query(params_from_iter(params.iter()))
            .map_err(|e| map_query_err(&e))?;
        let mut lanes: HashMap<Option<String>, (u64, BTreeMap<i64, Bucket>)> = HashMap::new();
        while let Some(r) = rows.next().map_err(db)? {
            let lane: Option<String> = r.get(0).map_err(db)?;
            let bi: i64 = r.get(1).map_err(db)?;
            let k: i32 = r.get(2).map_err(db)?;
            let n: i64 = r.get(3).map_err(db)?;
            let n32 = u32::try_from(n).unwrap_or(u32::MAX);
            let e = lanes.entry(lane).or_default();
            e.0 += u64::try_from(n).unwrap_or(0);
            let t = range.start + bi * bucket_us;
            let b = e.1.entry(t).or_insert_with(|| Bucket {
                t,
                ..Default::default()
            });
            match k {
                0 => b.dns += n32,
                1 => b.tls += n32,
                2 => b.http += n32,
                3 => b.bulk += n32,
                _ => b.other += n32,
            }
        }
        let mut max_score: HashMap<&str, f64> = HashMap::new();
        for f in findings {
            let e = max_score.entry(f.entity.as_str()).or_insert(f.score);
            *e = e.max(f.score);
        }
        let other = lanes.remove(&None);
        let mut out: Vec<Lane> = lanes
            .into_iter()
            .filter_map(|(h, (total, b))| {
                h.map(|host| Lane {
                    max_score: max_score.get(host.as_str()).copied(),
                    host,
                    is_other: false,
                    total,
                    buckets: b.into_values().collect(),
                })
            })
            .collect();
        out.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.host.cmp(&b.host)));
        if let Some((total, b)) = other {
            out.push(Lane {
                host: "other".into(),
                is_other: true,
                total,
                max_score: None,
                buckets: b.into_values().collect(),
            });
        }
        Ok(Lanes {
            bucket_ms,
            range,
            lanes: out,
        })
    }

    pub fn flow(&self, flow_id: u64) -> ApiResult<FlowRow> {
        let id =
            i64::try_from(flow_id).map_err(|_| ApiError::not_found(format!("flow {flow_id}")))?;
        let conn = self.conn()?;
        let mut st = conn
            .prepare(&format!(
                "SELECT {} FROM flows WHERE flow_id = ?",
                Tab::Flows.column_list()
            ))
            .map_err(db)?;
        let mut rows = st.query([id]).map_err(db)?;
        match rows.next().map_err(db)? {
            Some(r) => schema::flow_from(r),
            None => Err(ApiError::not_found(format!("flow {flow_id}"))),
        }
    }

    pub fn frame(&self, frame_no: u64) -> ApiResult<FrameRow> {
        let n = i64::try_from(frame_no)
            .map_err(|_| ApiError::not_found(format!("frame {frame_no}")))?;
        let conn = self.conn()?;
        let mut st = conn
            .prepare(&format!(
                "SELECT {} FROM frames WHERE frame_no = ?",
                Tab::Frames.column_list()
            ))
            .map_err(db)?;
        let mut rows = st.query([n]).map_err(db)?;
        match rows.next().map_err(db)? {
            Some(r) => schema::frame_from(r),
            None => Err(ApiError::not_found(format!("frame {frame_no}"))),
        }
    }

    pub fn flow_frames(&self, flow_id: u64) -> ApiResult<Vec<FrameRef>> {
        let flow = self.flow(flow_id)?;
        let conn = self.conn()?;
        let mut st = conn
            .prepare(&format!(
                "SELECT {} FROM frames WHERE frame_no BETWEEN ? AND ? AND flow_id = ? ORDER BY frame_no",
                Tab::Frames.column_list()
            ))
            .map_err(db)?;
        let p = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        let mut rows = st
            .query([p(flow.first_frame), p(flow.last_frame), p(flow_id)])
            .map_err(db)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db)? {
            let fr = schema::frame_from(r)?;
            out.push(FrameRef {
                summary: frame_summary(&fr, Some(&flow)),
                frame_no: fr.frame_no,
                ts: fr.ts,
                caplen: fr.caplen,
                wirelen: fr.wirelen,
                direction: fr.direction,
                tcp_flags: fr.tcp_flags,
                payload_len: fr.payload_len,
            });
        }
        Ok(out)
    }

    /// Top values of a field (or of the flow endpoints for `host`), most
    /// frequent first, optionally by case-insensitive prefix.
    fn values(&self, key: &str, source_sql: &str, prefix: &str) -> ApiResult<Vec<(String, u64)>> {
        if prefix.is_empty()
            && let Some(v) = self
                .top_values
                .lock()
                .map_err(|_| ApiError::internal("lock"))?
                .get(key)
        {
            return Ok(v.clone());
        }
        let sql = format!(
            "SELECT v, count(*) AS n FROM ({source_sql}) WHERE v IS NOT NULL AND starts_with(lower(v), lower(?)) \
             GROUP BY v ORDER BY n DESC, v LIMIT 20"
        );
        let conn = self.conn()?;
        let mut st = conn.prepare(&sql).map_err(db)?;
        let mut rows = st.query([prefix]).map_err(db)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db)? {
            let v: String = r.get(0).map_err(db)?;
            let n: i64 = r.get(1).map_err(db)?;
            out.push((v, u64::try_from(n).unwrap_or(0)));
        }
        if prefix.is_empty() {
            self.top_values
                .lock()
                .map_err(|_| ApiError::internal("lock"))?
                .insert(key.to_string(), out.clone());
        }
        Ok(out)
    }

    pub fn autocomplete(&self, partial: &str, cursor_pos: u32) -> ApiResult<Vec<Suggestion>> {
        let ctx = filter::completion_context(partial, cursor_pos);
        let mut out = filter::static_suggestions(&ctx);
        let source: Option<(String, String, &str)> = match &ctx.kind {
            CompletionKind::Host => Some((
                "host".into(),
                "SELECT src_ip AS v FROM flows UNION ALL SELECT dst_ip AS v FROM flows".into(),
                "host",
            )),
            CompletionKind::Port => Some((
                "port".into(),
                "SELECT CAST(dst_port AS VARCHAR) AS v FROM flows".into(),
                "port",
            )),
            CompletionKind::Value(f) => value_source(f).map(|s| (f.name.to_string(), s, f.name)),
            _ => None,
        };
        if let Some((key, src, detail)) = source {
            let quoted_field = matches!(&ctx.kind, CompletionKind::Value(f) if matches!(f.ty, FieldType::Str | FieldType::StrList));
            for (v, n) in self.values(&key, &src, &ctx.word)? {
                let insert = if quoted_field || ctx.quoted {
                    filter::render_value(&v, ctx.quoted)
                } else {
                    v.clone()
                };
                out.push(Suggestion {
                    label: v,
                    insert_text: insert,
                    kind: SuggestionKind::Value,
                    detail: Some(format!("{detail} · {n}")),
                    replace_start: if ctx.quoted {
                        ctx.start as u32 - 1
                    } else {
                        ctx.start as u32
                    },
                    replace_end: ctx.end as u32,
                });
            }
        }
        out.truncate(50);
        Ok(out)
    }

    pub fn findings(&self, filter: Option<&FindingsFilter>) -> ApiResult<Vec<Finding>> {
        let mut sql = format!(
            "SELECT {} FROM findings WHERE TRUE",
            Tab::Findings.column_list()
        );
        let mut params: Vec<Param> = Vec::new();
        let mut min_score = None;
        if let Some(f) = filter {
            if let Some(d) = &f.detector {
                sql.push_str(" AND detector = ?");
                params.push(Param::Str(d.clone()));
            }
            if let Some(e) = &f.entity {
                sql.push_str(" AND entity = ?");
                params.push(Param::Str(e.clone()));
            }
            if let Some(tr) = &f.time_range {
                sql.push_str(" AND ts_first < ? AND ts_last >= ?");
                params.extend([Param::Int(tr.end), Param::Int(tr.start)]);
            }
            min_score = f.min_score.filter(|s| s.is_finite());
        }
        sql.push_str(" ORDER BY score DESC, finding_id");
        let conn = self.conn()?;
        let mut st = conn.prepare(&sql).map_err(db)?;
        let mut rows = st.query(params_from_iter(params.iter())).map_err(db)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db)? {
            let f = schema::finding_from(r)?;
            if min_score.is_none_or(|m| f.score >= m) {
                out.push(f);
            }
        }
        Ok(out)
    }

    pub fn iocs(&self) -> ApiResult<Vec<Ioc>> {
        let conn = self.conn()?;
        let mut st = conn
            .prepare(&format!(
                "SELECT {} FROM iocs ORDER BY first_seen, ioc_id",
                Tab::Iocs.column_list()
            ))
            .map_err(db)?;
        let mut rows = st.query([]).map_err(db)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db)? {
            out.push(schema::ioc_from(r)?);
        }
        Ok(out)
    }

    /// Replaces a result table (findings/iocs) with a new file generation.
    fn put_table(&self, t: Tab, rows: Vec<Vec<duckdb::types::Value>>) -> ApiResult<()> {
        let mut m = self
            .manifest
            .lock()
            .map_err(|_| ApiError::internal("index lock"))?
            .clone();
        let old = m.files.get(t.name()).cloned().unwrap_or_default();
        let generation = old
            .iter()
            .filter_map(|f| {
                f.rsplit_once("data-")
                    .and_then(|(_, s)| s.strip_suffix(".parquet"))
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .max()
            .map_or(0, |g| g + 1);
        let rel = format!("{}/data-{generation}.parquet", t.name());
        {
            let c = self
                .base
                .lock()
                .map_err(|_| ApiError::internal("index lock"))?;
            write_table(&c, &self.dir, t, &rel, rows)?;
        }
        m.files.insert(t.name().to_string(), vec![rel]);
        let bytes = serde_json::to_vec_pretty(&m).map_err(|e| ApiError::internal(e.to_string()))?;
        write_atomic(&self.dir.join(MANIFEST), &bytes)?;
        *self
            .manifest
            .lock()
            .map_err(|_| ApiError::internal("index lock"))? = m;
        self.create_views()?;
        for f in old {
            let _ = fs::remove_file(self.dir.join(f));
        }
        Ok(())
    }

    fn stream<T>(
        &self,
        t: Tab,
        order: &str,
        conv: fn(&duckdb::Row<'_>) -> ApiResult<T>,
        f: &mut dyn FnMut(&T),
    ) -> ApiResult<()> {
        let conn = self.conn()?;
        let mut st = conn
            .prepare(&format!(
                "SELECT {} FROM {} ORDER BY {order}",
                t.column_list(),
                t.name()
            ))
            .map_err(db)?;
        let mut rows = st.query([]).map_err(db)?;
        while let Some(r) = rows.next().map_err(db)? {
            f(&conv(r)?);
        }
        Ok(())
    }
}

fn value_source(f: &FieldDef) -> Option<String> {
    let table = filter::table_name(f.table);
    match f.ty {
        FieldType::Str | FieldType::Ip => Some(format!("SELECT {} AS v FROM {table}", f.sql)),
        FieldType::StrList => Some(format!("SELECT unnest({}) AS v FROM {table}", f.sql)),
        _ => None,
    }
}

fn map_query_err(e: &duckdb::Error) -> ApiError {
    ApiError::internal(format!("query failed: {e}"))
}

fn truncate(d: &mut RowSet, n: usize) {
    match d {
        RowSet::Flows(v) => v.truncate(n),
        RowSet::Dns(v) => v.truncate(n),
        RowSet::Http(v) => v.truncate(n),
        RowSet::Tls(v) => v.truncate(n),
        RowSet::Files(v) => v.truncate(n),
        RowSet::Frames(v) => v.truncate(n),
    }
}

fn rows_json(d: &RowSet) -> ApiResult<Vec<serde_json::Value>> {
    let v = match d {
        RowSet::Flows(v) => serde_json::to_value(v),
        RowSet::Dns(v) => serde_json::to_value(v),
        RowSet::Http(v) => serde_json::to_value(v),
        RowSet::Tls(v) => serde_json::to_value(v),
        RowSet::Files(v) => serde_json::to_value(v),
        RowSet::Frames(v) => serde_json::to_value(v),
    }
    .map_err(|e| ApiError::internal(e.to_string()))?;
    match v {
        serde_json::Value::Array(a) => Ok(a),
        _ => Err(ApiError::internal("rows")),
    }
}

impl DetectSource for Index {
    fn capture(&self) -> ApiResult<CaptureRow> {
        Ok(self.capture.clone())
    }
    fn for_each_flow(&self, f: &mut dyn FnMut(&FlowRow)) -> ApiResult<()> {
        self.stream(Tab::Flows, "ts_start, flow_id", schema::flow_from, f)
    }
    fn for_each_dns(&self, f: &mut dyn FnMut(&DnsRow)) -> ApiResult<()> {
        self.stream(Tab::Dns, "ts, flow_id, frame_no", schema::dns_from, f)
    }
    fn for_each_http(&self, f: &mut dyn FnMut(&HttpRow)) -> ApiResult<()> {
        self.stream(Tab::Http, "ts, flow_id, frame_no", schema::http_from, f)
    }
    fn for_each_tls(&self, f: &mut dyn FnMut(&TlsRow)) -> ApiResult<()> {
        self.stream(Tab::Tls, "ts, flow_id, frame_no", schema::tls_from, f)
    }
}

impl ResultSink for Index {
    fn put_findings(&mut self, findings: &[Finding]) -> ApiResult<()> {
        let rows = findings
            .iter()
            .map(schema::finding_values)
            .collect::<ApiResult<Vec<_>>>()?;
        self.put_table(Tab::Findings, rows)
    }
    fn put_iocs(&mut self, iocs: &[Ioc]) -> ApiResult<()> {
        let rows = iocs
            .iter()
            .map(schema::ioc_values)
            .collect::<ApiResult<Vec<_>>>()?;
        self.put_table(Tab::Iocs, rows)
    }
}

/// `ResultSink` through a shared reference, for callers holding `Arc<Index>`.
impl Index {
    pub fn replace_findings(&self, findings: &[Finding]) -> ApiResult<()> {
        let rows = findings
            .iter()
            .map(schema::finding_values)
            .collect::<ApiResult<Vec<_>>>()?;
        self.put_table(Tab::Findings, rows)
    }
    pub fn replace_iocs(&self, iocs: &[Ioc]) -> ApiResult<()> {
        let rows = iocs
            .iter()
            .map(schema::ioc_values)
            .collect::<ApiResult<Vec<_>>>()?;
        self.put_table(Tab::Iocs, rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walleye_core::{CaptureFormat, sink::IndexSink};

    fn tmp(tag: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("walleye-index-unit-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn open_tiny(dir: &Path) -> Index {
        let cap = CaptureRow {
            capture_id: "0123456789abcdef".into(),
            path: "/x.pcap".into(),
            sha256: "0123456789abcdef".repeat(4),
            size_bytes: 1,
            format: CaptureFormat::Pcap,
            first_ts: 0,
            last_ts: 0,
            link_type: 1,
            frame_count: 0,
        };
        let mut w = crate::IndexWriter::create(dir).expect("create");
        w.begin(&cap).expect("begin");
        w.finish(&cap).expect("finish");
        Index::open(dir).expect("open")
    }

    #[test]
    fn sandbox_blocks_files_outside_index_and_locks_config() {
        let d = tmp("sandbox");
        let idx = open_tiny(&d);
        let c = idx.conn().expect("conn");
        let e = c
            .execute_batch("SELECT * FROM read_csv('/etc/passwd')")
            .expect_err("outside dir");
        let m = e.to_string();
        assert!(
            m.contains("disabled") || m.contains("Permission") || m.contains("not allowed"),
            "{m}"
        );
        let e = c
            .execute_batch("SET enable_external_access = true")
            .expect_err("locked");
        assert!(e.to_string().to_lowercase().contains("lock"), "{e}");
        let e = c
            .execute_batch("SET autoload_known_extensions = true")
            .expect_err("locked");
        assert!(e.to_string().to_lowercase().contains("lock"), "{e}");
        assert!(c.execute_batch("INSTALL httpfs").is_err());
        c.execute_batch("SELECT count(*) FROM flows")
            .expect("own files readable");
        drop(c);
        let _ = fs::remove_dir_all(&d);
    }
}
