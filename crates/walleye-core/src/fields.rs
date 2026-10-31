//! Filter-language field registry. The filter compiler (walleye-index), the
//! autocomplete, the packet decode tree (`DecodeNode.field`) and the docs all
//! use this list. Only names in this list may appear in a filter; `sql` is a
//! trusted column expression written here, never derived from user input.

use serde::Serialize;

/// Table a field lives in. Fields of other tables are reached from the queried
/// view through `flow_id` (e.g. `dns.query` on the flows view compiles to
/// `flow_id IN (SELECT flow_id FROM dns WHERE ...)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    Flows,
    Dns,
    Http,
    Tls,
    Files,
    Frames,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// IP literal or CIDR. `==` on a CIDR means "in network".
    Ip,
    Int,
    /// Integer accepting size suffixes B, KB, MB, GB (powers of 1024).
    Bytes,
    /// Microsecond timestamp; accepts RFC 3339 strings.
    Time,
    /// Microsecond duration; accepts suffixes us, ms, s, m, h.
    Duration,
    Str,
    Bool,
    /// List of strings; `==`/`~` match if any element matches.
    StrList,
    /// Protocol: accepts tcp, udp, icmp, icmp6 or a number.
    Proto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FieldDef {
    /// Name as typed in a filter.
    pub name: &'static str,
    pub table: Table,
    /// Trusted SQL expression over that table's columns.
    pub sql: &'static str,
    pub ty: FieldType,
    pub doc: &'static str,
}

const fn f(
    name: &'static str,
    table: Table,
    sql: &'static str,
    ty: FieldType,
    doc: &'static str,
) -> FieldDef {
    FieldDef {
        name,
        table,
        sql,
        ty,
        doc,
    }
}

use FieldType as T;
use Table::*;

pub const FIELDS: &[FieldDef] = &[
    // flows (unprefixed)
    f("flow_id", Flows, "flow_id", T::Int, "Flow id"),
    f("ts", Flows, "ts_start", T::Time, "Flow start time"),
    f("ts_end", Flows, "ts_end", T::Time, "Flow end time"),
    f(
        "duration",
        Flows,
        "(ts_end - ts_start)",
        T::Duration,
        "Flow duration",
    ),
    f("src_ip", Flows, "src_ip", T::Ip, "Initiator address"),
    f("dst_ip", Flows, "dst_ip", T::Ip, "Responder address"),
    f("src_port", Flows, "src_port", T::Int, "Initiator port"),
    f("dst_port", Flows, "dst_port", T::Int, "Responder port"),
    f("proto", Flows, "proto", T::Proto, "Transport protocol"),
    f(
        "app_proto",
        Flows,
        "app_proto",
        T::Str,
        "Application protocol: dns, http, tls",
    ),
    f(
        "bytes_up",
        Flows,
        "bytes_up",
        T::Bytes,
        "Bytes initiator → responder",
    ),
    f(
        "bytes_down",
        Flows,
        "bytes_down",
        T::Bytes,
        "Bytes responder → initiator",
    ),
    f(
        "bytes",
        Flows,
        "(bytes_up + bytes_down)",
        T::Bytes,
        "Total bytes",
    ),
    f(
        "pkts_up",
        Flows,
        "pkts_up",
        T::Int,
        "Packets initiator → responder",
    ),
    f(
        "pkts_down",
        Flows,
        "pkts_down",
        T::Int,
        "Packets responder → initiator",
    ),
    f(
        "pkts",
        Flows,
        "(pkts_up + pkts_down)",
        T::Int,
        "Total packets",
    ),
    // dns
    f("dns.query", Dns, "query", T::Str, "Query name, lowercase"),
    f(
        "dns.qtype",
        Dns,
        "qtype",
        T::Str,
        "Query type mnemonic (A, TXT, ...)",
    ),
    f(
        "dns.rcode",
        Dns,
        "rcode",
        T::Str,
        "Response code mnemonic (NXDOMAIN, ...)",
    ),
    f("dns.answer", Dns, "answers", T::StrList, "Any answer RDATA"),
    f("dns.ttl", Dns, "ttl", T::Int, "Minimum answer TTL"),
    f(
        "dns.is_response",
        Dns,
        "is_response",
        T::Bool,
        "Message is a response",
    ),
    // http
    f("http.method", Http, "method", T::Str, "Request method"),
    f("http.host", Http, "host", T::Str, "Host header"),
    f("http.uri", Http, "uri", T::Str, "Request URI"),
    f(
        "http.user_agent",
        Http,
        "user_agent",
        T::Str,
        "User-Agent header",
    ),
    f(
        "http.status",
        Http,
        "status",
        T::Int,
        "Response status code",
    ),
    f(
        "http.req_bytes",
        Http,
        "req_bytes",
        T::Bytes,
        "Request body bytes",
    ),
    f(
        "http.resp_bytes",
        Http,
        "resp_bytes",
        T::Bytes,
        "Response body bytes",
    ),
    // tls
    f("tls.sni", Tls, "sni", T::Str, "Server Name Indication"),
    f("tls.version", Tls, "version", T::Str, "TLS version"),
    f("tls.ja4", Tls, "ja4", T::Str, "JA4 client fingerprint"),
    f("tls.ja4s", Tls, "ja4s", T::Str, "JA4S server fingerprint"),
    f(
        "tls.cert_subject",
        Tls,
        "cert_subject",
        T::Str,
        "Leaf certificate subject",
    ),
    f(
        "tls.cert_issuer",
        Tls,
        "cert_issuer",
        T::Str,
        "Leaf certificate issuer",
    ),
    f(
        "tls.cert_serial",
        Tls,
        "cert_serial",
        T::Str,
        "Leaf certificate serial (hex)",
    ),
    f(
        "tls.cert_self_signed",
        Tls,
        "cert_self_signed",
        T::Bool,
        "Leaf certificate is self-signed",
    ),
    // files
    f(
        "file.name",
        Files,
        "filename",
        T::Str,
        "Transferred file name",
    ),
    f(
        "file.mime_type",
        Files,
        "mime_type",
        T::Str,
        "Declared Content-Type",
    ),
    f(
        "file.size",
        Files,
        "size_bytes",
        T::Bytes,
        "Declared or observed size",
    ),
    // frames
    f("frame.no", Frames, "frame_no", T::Int, "Frame number"),
    f(
        "frame.len",
        Frames,
        "wirelen",
        T::Bytes,
        "Frame length on the wire",
    ),
    f(
        "frame.tcp_flags",
        Frames,
        "tcp_flags",
        T::Int,
        "TCP flags byte",
    ),
];

/// Shorthand terms that are not `field op value` comparisons.
/// `host X` ≡ `(src_ip == X or dst_ip == X)`, `src X` ≡ `src_ip == X`,
/// `dst X` ≡ `dst_ip == X`, `port N` ≡ `(src_port == N or dst_port == N)`,
/// and a bare protocol name (`dns`, `http`, `tls`, `tcp`, `udp`, `icmp`)
/// ≡ `app_proto == name` / `proto == name`.
pub const SHORTHANDS: &[&str] = &["host", "src", "dst", "port"];
pub const KEYWORDS: &[&str] = &["and", "or", "not", "in"];
pub const OPERATORS: &[&str] = &["==", "!=", ">", ">=", "<", "<=", "~", "in"];
pub const BARE_PROTOCOLS: &[&str] = &["dns", "http", "tls", "tcp", "udp", "icmp"];

pub fn field(name: &str) -> Option<&'static FieldDef> {
    FIELDS.iter().find(|f| f.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_unique() {
        let mut names: Vec<_> = FIELDS.iter().map(|f| f.name).collect();
        names.sort_unstable();
        let n = names.len();
        names.dedup();
        assert_eq!(n, names.len());
    }

    /// Writes the registry for the UI (autocomplete, docs) next to the ts-rs
    /// bindings, like ts-rs does for types.
    #[test]
    fn export_filter_fields_json() {
        let Ok(dir) = std::env::var("TS_RS_EXPORT_DIR") else {
            return;
        };
        let json = serde_json::json!({
            "fields": FIELDS,
            "shorthands": SHORTHANDS,
            "keywords": KEYWORDS,
            "operators": OPERATORS,
            "bare_protocols": BARE_PROTOCOLS,
        });
        let text = serde_json::to_string_pretty(&json).expect("serialize") + "\n";
        let path = std::path::Path::new(&dir).join("filter_fields.json");
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            std::fs::write(&path, text).expect("write filter_fields.json");
        }
    }

    #[test]
    fn sql_is_identifier_safe() {
        // Registry SQL must contain only identifier chars, spaces, + - ( ).
        for f in FIELDS {
            assert!(
                f.sql
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || " _+-()".contains(c)),
                "{}",
                f.name
            );
        }
    }
}
