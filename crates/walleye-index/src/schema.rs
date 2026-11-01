//! Parquet/DuckDB schemas for the index tables and row conversion.
//! Column names and order match the `walleye_core` structs exactly.

use duckdb::types::Value;
use walleye_core::{
    ApiError, CaptureFormat, CaptureRow, Direction, DnsRow, FileRow, Finding, FlowRow, FrameRow,
    HttpRow, Ioc, IocType, TlsRow, error::ApiResult,
};

/// One index table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Frames,
    Flows,
    Dns,
    Http,
    Tls,
    Files,
    Findings,
    Iocs,
    Captures,
}

pub const DATA_TABLES: [Tab; 6] = [
    Tab::Frames,
    Tab::Flows,
    Tab::Dns,
    Tab::Http,
    Tab::Tls,
    Tab::Files,
];
pub const ALL_TABLES: [Tab; 9] = [
    Tab::Frames,
    Tab::Flows,
    Tab::Dns,
    Tab::Http,
    Tab::Tls,
    Tab::Files,
    Tab::Findings,
    Tab::Iocs,
    Tab::Captures,
];

impl Tab {
    pub fn name(self) -> &'static str {
        match self {
            Tab::Frames => "frames",
            Tab::Flows => "flows",
            Tab::Dns => "dns",
            Tab::Http => "http",
            Tab::Tls => "tls",
            Tab::Files => "files",
            Tab::Findings => "findings",
            Tab::Iocs => "iocs",
            Tab::Captures => "captures",
        }
    }

    /// `(column, SQL type)` in struct order.
    pub fn columns(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Tab::Frames => &[
                ("frame_no", "UBIGINT"),
                ("ts", "BIGINT"),
                ("file_offset", "UBIGINT"),
                ("caplen", "UINTEGER"),
                ("wirelen", "UINTEGER"),
                ("flow_id", "UBIGINT"),
                ("direction", "VARCHAR"),
                ("tcp_flags", "UTINYINT"),
                ("payload_len", "UINTEGER"),
                ("link_type", "UINTEGER"),
            ],
            Tab::Flows => &[
                ("flow_id", "UBIGINT"),
                ("ts_start", "BIGINT"),
                ("ts_end", "BIGINT"),
                ("src_ip", "VARCHAR"),
                ("src_port", "USMALLINT"),
                ("dst_ip", "VARCHAR"),
                ("dst_port", "USMALLINT"),
                ("proto", "UTINYINT"),
                ("app_proto", "VARCHAR"),
                ("bytes_up", "UBIGINT"),
                ("bytes_down", "UBIGINT"),
                ("pkts_up", "UBIGINT"),
                ("pkts_down", "UBIGINT"),
                ("first_frame", "UBIGINT"),
                ("last_frame", "UBIGINT"),
            ],
            Tab::Dns => &[
                ("ts", "BIGINT"),
                ("flow_id", "UBIGINT"),
                ("frame_no", "UBIGINT"),
                ("trans_id", "USMALLINT"),
                ("is_response", "BOOLEAN"),
                ("query", "VARCHAR"),
                ("qtype", "VARCHAR"),
                ("rcode", "VARCHAR"),
                ("answers", "VARCHAR[]"),
                ("ttl", "UINTEGER"),
            ],
            Tab::Http => &[
                ("ts", "BIGINT"),
                ("flow_id", "UBIGINT"),
                ("frame_no", "UBIGINT"),
                ("method", "VARCHAR"),
                ("host", "VARCHAR"),
                ("uri", "VARCHAR"),
                ("user_agent", "VARCHAR"),
                ("status", "USMALLINT"),
                ("resp_frame_no", "UBIGINT"),
                ("req_bytes", "UBIGINT"),
                ("resp_bytes", "UBIGINT"),
            ],
            Tab::Tls => &[
                ("ts", "BIGINT"),
                ("flow_id", "UBIGINT"),
                ("frame_no", "UBIGINT"),
                ("sni", "VARCHAR"),
                ("version", "VARCHAR"),
                ("ja4", "VARCHAR"),
                ("ja4s", "VARCHAR"),
                ("cert_subject", "VARCHAR"),
                ("cert_issuer", "VARCHAR"),
                ("cert_serial", "VARCHAR"),
                ("cert_self_signed", "BOOLEAN"),
                ("cert_not_before", "BIGINT"),
                ("cert_not_after", "BIGINT"),
            ],
            Tab::Files => &[
                ("ts", "BIGINT"),
                ("flow_id", "UBIGINT"),
                ("frame_no", "UBIGINT"),
                ("source", "VARCHAR"),
                ("direction", "VARCHAR"),
                ("filename", "VARCHAR"),
                ("mime_type", "VARCHAR"),
                ("size_bytes", "UBIGINT"),
            ],
            Tab::Findings => &[
                ("finding_id", "VARCHAR"),
                ("title", "VARCHAR"),
                ("detector", "VARCHAR"),
                ("entity_type", "VARCHAR"),
                ("entity", "VARCHAR"),
                ("score", "DOUBLE"),
                ("attack_technique", "VARCHAR"),
                ("ts_first", "BIGINT"),
                ("ts_last", "BIGINT"),
                ("reasons", "VARCHAR"),
            ],
            Tab::Iocs => &[
                ("ioc_id", "VARCHAR"),
                ("type", "VARCHAR"),
                ("value", "VARCHAR"),
                ("defanged", "VARCHAR"),
                ("source_finding_id", "VARCHAR"),
                ("first_seen", "BIGINT"),
                ("evidence", "VARCHAR"),
                ("allowlisted", "BOOLEAN"),
                ("allowlist_reason", "VARCHAR"),
            ],
            Tab::Captures => &[
                ("capture_id", "VARCHAR"),
                ("path", "VARCHAR"),
                ("sha256", "VARCHAR"),
                ("size_bytes", "UBIGINT"),
                ("format", "VARCHAR"),
                ("first_ts", "BIGINT"),
                ("last_ts", "BIGINT"),
                ("link_type", "UINTEGER"),
                ("frame_count", "UBIGINT"),
            ],
        }
    }

    /// Row-group sort order ("sorted by time", then the key).
    pub fn order_by(self) -> &'static str {
        match self {
            Tab::Frames => "ts, frame_no",
            Tab::Flows => "ts_start, flow_id",
            Tab::Dns | Tab::Http | Tab::Tls | Tab::Files => "ts, flow_id, frame_no",
            Tab::Findings => "score DESC, finding_id",
            Tab::Iocs => "first_seen, ioc_id",
            Tab::Captures => "capture_id",
        }
    }

    pub fn column_list(self) -> String {
        self.columns()
            .iter()
            .map(|(c, _)| *c)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `CREATE TABLE <name> (...)` with the given name.
    pub fn ddl(self, name: &str) -> String {
        let cols: Vec<String> = self
            .columns()
            .iter()
            .map(|(c, t)| format!("\"{c}\" {t}"))
            .collect();
        format!("CREATE OR REPLACE TABLE {name} ({})", cols.join(", "))
    }
}

fn dir_str(d: Direction) -> &'static str {
    match d {
        Direction::Up => "up",
        Direction::Down => "down",
    }
}

fn opt<T>(v: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    v.map(f).unwrap_or(Value::Null)
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn opt_text(s: &Option<String>) -> Value {
    s.as_deref().map(text).unwrap_or(Value::Null)
}

pub fn frame_values(r: &FrameRow) -> Vec<Value> {
    vec![
        Value::UBigInt(r.frame_no),
        Value::BigInt(r.ts),
        Value::UBigInt(r.file_offset),
        Value::UInt(r.caplen),
        Value::UInt(r.wirelen),
        opt(r.flow_id, Value::UBigInt),
        opt(r.direction, |d| text(dir_str(d))),
        opt(r.tcp_flags, Value::UTinyInt),
        Value::UInt(r.payload_len),
        opt(r.link_type, Value::UInt),
    ]
}

pub fn flow_values(r: &FlowRow) -> Vec<Value> {
    vec![
        Value::UBigInt(r.flow_id),
        Value::BigInt(r.ts_start),
        Value::BigInt(r.ts_end),
        text(&r.src_ip),
        Value::USmallInt(r.src_port),
        text(&r.dst_ip),
        Value::USmallInt(r.dst_port),
        Value::UTinyInt(r.proto),
        opt_text(&r.app_proto),
        Value::UBigInt(r.bytes_up),
        Value::UBigInt(r.bytes_down),
        Value::UBigInt(r.pkts_up),
        Value::UBigInt(r.pkts_down),
        Value::UBigInt(r.first_frame),
        Value::UBigInt(r.last_frame),
    ]
}

pub fn dns_values(r: &DnsRow) -> Vec<Value> {
    vec![
        Value::BigInt(r.ts),
        Value::UBigInt(r.flow_id),
        Value::UBigInt(r.frame_no),
        Value::USmallInt(r.trans_id),
        Value::Boolean(r.is_response),
        text(&r.query),
        text(&r.qtype),
        opt_text(&r.rcode),
        Value::List(r.answers.iter().map(|a| text(a)).collect()),
        opt(r.ttl, Value::UInt),
    ]
}

pub fn http_values(r: &HttpRow) -> Vec<Value> {
    vec![
        Value::BigInt(r.ts),
        Value::UBigInt(r.flow_id),
        Value::UBigInt(r.frame_no),
        opt_text(&r.method),
        opt_text(&r.host),
        opt_text(&r.uri),
        opt_text(&r.user_agent),
        opt(r.status, Value::USmallInt),
        opt(r.resp_frame_no, Value::UBigInt),
        Value::UBigInt(r.req_bytes),
        Value::UBigInt(r.resp_bytes),
    ]
}

pub fn tls_values(r: &TlsRow) -> Vec<Value> {
    vec![
        Value::BigInt(r.ts),
        Value::UBigInt(r.flow_id),
        Value::UBigInt(r.frame_no),
        opt_text(&r.sni),
        opt_text(&r.version),
        opt_text(&r.ja4),
        opt_text(&r.ja4s),
        opt_text(&r.cert_subject),
        opt_text(&r.cert_issuer),
        opt_text(&r.cert_serial),
        opt(r.cert_self_signed, Value::Boolean),
        opt(r.cert_not_before, Value::BigInt),
        opt(r.cert_not_after, Value::BigInt),
    ]
}

pub fn file_values(r: &FileRow) -> Vec<Value> {
    vec![
        Value::BigInt(r.ts),
        Value::UBigInt(r.flow_id),
        Value::UBigInt(r.frame_no),
        text(&r.source),
        text(dir_str(r.direction)),
        opt_text(&r.filename),
        opt_text(&r.mime_type),
        opt(r.size_bytes, Value::UBigInt),
    ]
}

pub fn finding_values(f: &Finding) -> ApiResult<Vec<Value>> {
    let reasons =
        serde_json::to_string(&f.reasons).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(vec![
        text(&f.finding_id),
        text(&f.title),
        text(&f.detector),
        text(&f.entity_type),
        text(&f.entity),
        Value::Double(f.score),
        opt_text(&f.attack_technique),
        Value::BigInt(f.ts_first),
        Value::BigInt(f.ts_last),
        Value::Text(reasons),
    ])
}

pub fn ioc_type_str(t: IocType) -> ApiResult<String> {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(ApiError::internal("ioc type")),
    }
}

pub fn ioc_values(i: &Ioc) -> ApiResult<Vec<Value>> {
    let ev = serde_json::to_string(&i.evidence).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(vec![
        text(&i.ioc_id),
        Value::Text(ioc_type_str(i.ioc_type)?),
        text(&i.value),
        text(&i.defanged),
        opt_text(&i.source_finding_id),
        Value::BigInt(i.first_seen),
        Value::Text(ev),
        Value::Boolean(i.allowlisted),
        opt_text(&i.allowlist_reason),
    ])
}

pub fn capture_values(c: &CaptureRow) -> Vec<Value> {
    vec![
        text(&c.capture_id),
        text(&c.path),
        text(&c.sha256),
        Value::UBigInt(c.size_bytes),
        text(match c.format {
            CaptureFormat::Pcap => "pcap",
            CaptureFormat::Pcapng => "pcapng",
        }),
        Value::BigInt(c.first_ts),
        Value::BigInt(c.last_ts),
        Value::UInt(c.link_type),
        Value::UBigInt(c.frame_count),
    ]
}

// ------------------------------------------------------------ decoding

fn db(e: duckdb::Error) -> ApiError {
    ApiError::internal(format!("index read: {e}"))
}

fn dir_of(s: Option<String>) -> Option<Direction> {
    match s.as_deref() {
        Some("up") => Some(Direction::Up),
        Some("down") => Some(Direction::Down),
        _ => None,
    }
}

fn str_list(v: Value) -> Vec<String> {
    match v {
        Value::List(items) | Value::Array(items) => items
            .into_iter()
            .filter_map(|x| match x {
                Value::Text(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub fn frame_from(r: &duckdb::Row<'_>) -> ApiResult<FrameRow> {
    Ok(FrameRow {
        frame_no: r.get(0).map_err(db)?,
        ts: r.get(1).map_err(db)?,
        file_offset: r.get(2).map_err(db)?,
        caplen: r.get(3).map_err(db)?,
        wirelen: r.get(4).map_err(db)?,
        flow_id: r.get(5).map_err(db)?,
        direction: dir_of(r.get(6).map_err(db)?),
        tcp_flags: r.get(7).map_err(db)?,
        payload_len: r.get(8).map_err(db)?,
        link_type: r.get(9).map_err(db)?,
    })
}

pub fn flow_from(r: &duckdb::Row<'_>) -> ApiResult<FlowRow> {
    Ok(FlowRow {
        flow_id: r.get(0).map_err(db)?,
        ts_start: r.get(1).map_err(db)?,
        ts_end: r.get(2).map_err(db)?,
        src_ip: r.get(3).map_err(db)?,
        src_port: r.get(4).map_err(db)?,
        dst_ip: r.get(5).map_err(db)?,
        dst_port: r.get(6).map_err(db)?,
        proto: r.get(7).map_err(db)?,
        app_proto: r.get(8).map_err(db)?,
        bytes_up: r.get(9).map_err(db)?,
        bytes_down: r.get(10).map_err(db)?,
        pkts_up: r.get(11).map_err(db)?,
        pkts_down: r.get(12).map_err(db)?,
        first_frame: r.get(13).map_err(db)?,
        last_frame: r.get(14).map_err(db)?,
    })
}

pub fn dns_from(r: &duckdb::Row<'_>) -> ApiResult<DnsRow> {
    Ok(DnsRow {
        ts: r.get(0).map_err(db)?,
        flow_id: r.get(1).map_err(db)?,
        frame_no: r.get(2).map_err(db)?,
        trans_id: r.get(3).map_err(db)?,
        is_response: r.get(4).map_err(db)?,
        query: r.get(5).map_err(db)?,
        qtype: r.get(6).map_err(db)?,
        rcode: r.get(7).map_err(db)?,
        answers: str_list(r.get(8).map_err(db)?),
        ttl: r.get(9).map_err(db)?,
    })
}

pub fn http_from(r: &duckdb::Row<'_>) -> ApiResult<HttpRow> {
    Ok(HttpRow {
        ts: r.get(0).map_err(db)?,
        flow_id: r.get(1).map_err(db)?,
        frame_no: r.get(2).map_err(db)?,
        method: r.get(3).map_err(db)?,
        host: r.get(4).map_err(db)?,
        uri: r.get(5).map_err(db)?,
        user_agent: r.get(6).map_err(db)?,
        status: r.get(7).map_err(db)?,
        resp_frame_no: r.get(8).map_err(db)?,
        req_bytes: r.get(9).map_err(db)?,
        resp_bytes: r.get(10).map_err(db)?,
    })
}

pub fn tls_from(r: &duckdb::Row<'_>) -> ApiResult<TlsRow> {
    Ok(TlsRow {
        ts: r.get(0).map_err(db)?,
        flow_id: r.get(1).map_err(db)?,
        frame_no: r.get(2).map_err(db)?,
        sni: r.get(3).map_err(db)?,
        version: r.get(4).map_err(db)?,
        ja4: r.get(5).map_err(db)?,
        ja4s: r.get(6).map_err(db)?,
        cert_subject: r.get(7).map_err(db)?,
        cert_issuer: r.get(8).map_err(db)?,
        cert_serial: r.get(9).map_err(db)?,
        cert_self_signed: r.get(10).map_err(db)?,
        cert_not_before: r.get(11).map_err(db)?,
        cert_not_after: r.get(12).map_err(db)?,
    })
}

pub fn file_from(r: &duckdb::Row<'_>) -> ApiResult<FileRow> {
    Ok(FileRow {
        ts: r.get(0).map_err(db)?,
        flow_id: r.get(1).map_err(db)?,
        frame_no: r.get(2).map_err(db)?,
        source: r.get(3).map_err(db)?,
        direction: dir_of(r.get(4).map_err(db)?).unwrap_or(Direction::Down),
        filename: r.get(5).map_err(db)?,
        mime_type: r.get(6).map_err(db)?,
        size_bytes: r.get(7).map_err(db)?,
    })
}

pub fn finding_from(r: &duckdb::Row<'_>) -> ApiResult<Finding> {
    let reasons: String = r.get(9).map_err(db)?;
    Ok(Finding {
        finding_id: r.get(0).map_err(db)?,
        title: r.get(1).map_err(db)?,
        detector: r.get(2).map_err(db)?,
        entity_type: r.get(3).map_err(db)?,
        entity: r.get(4).map_err(db)?,
        score: r.get(5).map_err(db)?,
        attack_technique: r.get(6).map_err(db)?,
        ts_first: r.get(7).map_err(db)?,
        ts_last: r.get(8).map_err(db)?,
        reasons: serde_json::from_str(&reasons)
            .map_err(|e| ApiError::internal(format!("reasons: {e}")))?,
        verdict: None,
    })
}

pub fn ioc_from(r: &duckdb::Row<'_>) -> ApiResult<Ioc> {
    let ty: String = r.get(1).map_err(db)?;
    let ev: String = r.get(6).map_err(db)?;
    Ok(Ioc {
        ioc_id: r.get(0).map_err(db)?,
        ioc_type: serde_json::from_value(serde_json::Value::String(ty))
            .map_err(|e| ApiError::internal(format!("ioc type: {e}")))?,
        value: r.get(2).map_err(db)?,
        defanged: r.get(3).map_err(db)?,
        source_finding_id: r.get(4).map_err(db)?,
        first_seen: r.get(5).map_err(db)?,
        evidence: serde_json::from_str(&ev)
            .map_err(|e| ApiError::internal(format!("evidence: {e}")))?,
        allowlisted: r.get(7).map_err(db)?,
        allowlist_reason: r.get(8).map_err(db)?,
    })
}
