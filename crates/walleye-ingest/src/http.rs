//! HTTP/1.x request/response heads and a per-connection state machine that
//! pairs requests with responses and counts body bytes (bodies are counted,
//! never stored).

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use walleye_core::{Direction, FileRow, HttpRow};

use crate::out::{Ctx, Out};
use crate::util::{ParseError, ParseResult, escape_bytes, starts_with_ci};

/// Largest request/response head buffered (bytes).
pub const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_VALUE: usize = 4096;
const MAX_PENDING: usize = 64;
const MAX_CHUNK_LINE: usize = 1024;

const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"PROPFIND ",
    b"PROPPATCH ",
    b"MKCOL ",
    b"COPY ",
    b"MOVE ",
    b"LOCK ",
    b"UNLOCK ",
    b"SEARCH ",
    b"REPORT ",
];

/// True if the bytes start like an HTTP/1.x request line.
pub fn looks_like_request(b: &[u8]) -> bool {
    METHODS.iter().any(|m| b.starts_with(m))
}

/// True if the bytes start like an HTTP/1.x status line.
pub fn looks_like_response(b: &[u8]) -> bool {
    b.starts_with(b"HTTP/1.")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartLine {
    Request {
        method: String,
        uri: String,
        version: String,
    },
    Response {
        version: String,
        status: u16,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHead {
    pub start: StartLine,
    /// `(name, value)`; name as sent, value escaped and trimmed.
    pub headers: Vec<(String, String)>,
    /// Byte spans `(start, len)` of the start line and each header line.
    pub line_spans: Vec<(usize, usize)>,
    /// Bytes up to and including the blank line ending the head.
    pub head_len: usize,
}

impl HttpHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")?.trim().parse().ok()
    }
    pub fn is_chunked(&self) -> bool {
        self.header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }
}

/// End of the head: offset just past the blank line (`\r\n\r\n` or `\n\n`).
///
/// One pass, stopping at the first terminator: the cost is the head's length,
/// not the buffer's, so a segment of many tiny pipelined messages stays linear.
pub fn head_end(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(off) = b.get(i..)?.iter().position(|&c| c == b'\n') {
        let nl = i + off;
        match (b.get(nl + 1), b.get(nl + 2)) {
            (Some(b'\n'), _) => return Some(nl + 2),
            (Some(b'\r'), Some(b'\n')) => return Some(nl + 3),
            _ => i = nl + 1,
        }
    }
    None
}

/// Parse an HTTP/1.x request or response head. `Truncated` if the blank line
/// ending the head is not in `b`.
pub fn parse_http(b: &[u8]) -> ParseResult<HttpHead> {
    let end = head_end(b).ok_or(ParseError::Truncated)?;
    let head = b.get(..end).ok_or(ParseError::Truncated)?;
    let mut lines = Vec::new();
    let mut pos = 0usize;
    while pos < head.len() {
        let rest = head.get(pos..).unwrap_or(&[]);
        let nl = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
        let mut line = rest.get(..nl).unwrap_or(&[]);
        if let Some(l) = line.strip_suffix(b"\r") {
            line = l;
        }
        if line.is_empty() {
            break;
        }
        lines.push((pos, line));
        pos += nl + 1;
    }
    let (&(first_pos, first), rest) = lines
        .split_first()
        .ok_or(ParseError::Malformed("empty http head"))?;
    let start = parse_start_line(first)?;
    let mut headers = Vec::new();
    let mut line_spans = vec![(first_pos, first.len())];
    for &(p, line) in rest.iter().take(MAX_HEADERS) {
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue; // obs-fold or junk: skip
        };
        let name = line.get(..colon).unwrap_or(&[]);
        if name.is_empty() || name.len() > 256 || !name.iter().all(|c| is_token(*c)) {
            continue;
        }
        let value = line.get(colon + 1..).unwrap_or(&[]).trim_ascii();
        headers.push((
            String::from_utf8_lossy(name).into_owned(),
            escape_bytes(value, MAX_VALUE),
        ));
        line_spans.push((p, line.len()));
    }
    Ok(HttpHead {
        start,
        headers,
        line_spans,
        head_len: end,
    })
}

fn is_token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn parse_start_line(line: &[u8]) -> ParseResult<StartLine> {
    let mut parts = line.splitn(3, |&c| c == b' ');
    let a = parts.next().unwrap_or(&[]);
    let b = parts
        .next()
        .ok_or(ParseError::Malformed("http start line"))?;
    let c = parts.next().unwrap_or(&[]);
    if a.starts_with(b"HTTP/1.") {
        let status: u16 = std::str::from_utf8(b)
            .ok()
            .filter(|s| s.len() == 3)
            .and_then(|s| s.parse().ok())
            .ok_or(ParseError::Malformed("http status code"))?;
        return Ok(StartLine::Response {
            version: escape_bytes(a, 16),
            status,
            reason: escape_bytes(c, 256),
        });
    }
    if a.is_empty() || a.len() > 20 || !a.iter().all(|x| x.is_ascii_uppercase() || *x == b'-') {
        return Err(ParseError::Malformed("http method"));
    }
    if !starts_with_ci(c, b"HTTP/1.") || c.len() > 16 {
        return Err(ParseError::Malformed("http version"));
    }
    Ok(StartLine::Request {
        method: escape_bytes(a, 20),
        uri: escape_bytes(b, MAX_VALUE),
        version: escape_bytes(c, 16),
    })
}

/// `filename` from a Content-Disposition value.
pub fn disposition_filename(v: &str) -> Option<String> {
    let lower = v.to_ascii_lowercase();
    let (idx, ext) = match lower.find("filename*=") {
        Some(i) => (i + "filename*=".len(), true),
        None => (lower.find("filename=")? + "filename=".len(), false),
    };
    let mut val = v.get(idx..)?.trim_start();
    if ext {
        // RFC 5987: charset'lang'value
        if let Some(p) = val.rfind('\'') {
            val = val.get(p + 1..)?;
        }
    }
    let val = if let Some(q) = val.strip_prefix('"') {
        q.split('"').next()?
    } else {
        val.split(';').next()?.trim()
    };
    (!val.is_empty()).then(|| val.to_string())
}

/// Last path segment of a request URI, without query or fragment.
pub fn uri_filename(uri: &str) -> Option<String> {
    let path = uri.split(['?', '#']).next()?;
    let seg = path.rsplit('/').next()?;
    (!seg.is_empty() && seg != "*").then(|| seg.to_string())
}

fn mime(v: Option<&str>) -> Option<String> {
    let m = v?.split(';').next()?.trim().to_ascii_lowercase();
    (!m.is_empty()).then_some(m)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Body {
    Head,
    Fixed(u64),
    Chunked(Chunk),
    UntilClose,
    /// Protocol switched (101, CONNECT): stop parsing this connection.
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Chunk {
    Size,
    Data(u64),
    DataEnd(u8),
    Trailer,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HDir {
    body: Option<Body>,
    buf: Vec<u8>,
    buf_frame: u64,
    buf_ts: i64,
    desync: bool,
    /// Observed body bytes of the message in progress.
    observed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    row: HttpRow,
    is_head: bool,
    req_done: bool,
    resp_started: bool,
    resp_done: bool,
    req_file: Option<FileRow>,
    resp_file: Option<FileRow>,
}

/// HTTP state for one TCP connection. Direction 0 = up (client), 1 = down.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpConn {
    dirs: [HDir; 2],
    pending: VecDeque<Pending>,
}

impl HttpConn {
    /// Feed in-order stream bytes. `gap` is the number of bytes missing
    /// before `data` (lost segments).
    pub fn feed(&mut self, dir: Direction, data: &[u8], gap: u64, ctx: Ctx, out: &mut Out) {
        let d = usize::from(dir == Direction::Down);
        if gap > 0 {
            self.on_gap(d, gap, out);
        }
        let mut input: &[u8] = data;
        while !input.is_empty() {
            let body = self.dirs[d].body.clone().unwrap_or(Body::Head);
            match body {
                Body::Opaque => return,
                Body::Head => {
                    let dd = &mut self.dirs[d];
                    if dd.buf.is_empty() {
                        let ok = if d == 0 {
                            looks_like_request(input)
                        } else {
                            looks_like_response(input)
                        };
                        if !ok {
                            // Not at a message start: wait for one.
                            dd.desync = true;
                            return;
                        }
                        dd.desync = false;
                        dd.buf_frame = ctx.frame_no;
                        dd.buf_ts = ctx.ts;
                    }
                    // Fast path: a whole head at the start of `input` is
                    // parsed in place, without copying the rest of the
                    // segment (pipelined messages would otherwise be
                    // quadratic: security review).
                    if dd.buf.is_empty() {
                        let window = input.get(..input.len().min(MAX_HEAD)).unwrap_or(input);
                        if let Some(end) = head_end(window) {
                            let (frame, ts) = (dd.buf_frame, dd.buf_ts);
                            let head = input.get(..end).unwrap_or(&[]);
                            match parse_http(head) {
                                Ok(h) => self.on_head(d, &h, frame, ts, ctx, out),
                                Err(_) => {
                                    self.dirs[d].desync = true;
                                    return;
                                }
                            }
                            input = input.get(end..).unwrap_or(&[]);
                            continue;
                        }
                    }
                    let old_len = dd.buf.len();
                    let room = MAX_HEAD.saturating_sub(old_len);
                    let take = input.len().min(room);
                    // Search only where a terminator can newly appear.
                    let search_from = dd.buf.len().saturating_sub(3);
                    dd.buf.extend_from_slice(input.get(..take).unwrap_or(&[]));
                    let found =
                        head_end(dd.buf.get(search_from..).unwrap_or(&[])).map(|e| e + search_from);
                    let Some(end) = found else {
                        if dd.buf.len() >= MAX_HEAD {
                            dd.buf.clear();
                            dd.desync = true;
                        }
                        return;
                    };
                    // A new terminator includes at least one new byte, so the
                    // head ends inside this `input`: continue right after it.
                    let consumed = end.saturating_sub(old_len).min(take);
                    dd.buf.truncate(end);
                    let head_bytes = std::mem::take(&mut dd.buf);
                    let (frame, ts) = (dd.buf_frame, dd.buf_ts);
                    match parse_http(&head_bytes) {
                        Ok(h) => self.on_head(d, &h, frame, ts, ctx, out),
                        Err(_) => {
                            self.dirs[d].desync = true;
                            return;
                        }
                    }
                    input = input.get(consumed..).unwrap_or(&[]);
                }
                Body::Fixed(n) => {
                    let k = n.min(input.len() as u64);
                    self.count(d, k);
                    input = input.get(k as usize..).unwrap_or(&[]);
                    if n == k {
                        self.end_message(d, out);
                    } else {
                        self.dirs[d].body = Some(Body::Fixed(n - k));
                    }
                }
                Body::UntilClose => {
                    self.count(d, input.len() as u64);
                    return;
                }
                Body::Chunked(st) => {
                    input = self.chunked(d, st, input, out);
                }
            }
        }
    }

    fn chunked<'a>(&mut self, d: usize, st: Chunk, input: &'a [u8], out: &mut Out) -> &'a [u8] {
        match st {
            Chunk::Size | Chunk::Trailer => {
                let Some(nl) = input.iter().position(|&c| c == b'\n') else {
                    let dd = &mut self.dirs[d];
                    dd.buf.extend_from_slice(input);
                    if dd.buf.len() > MAX_CHUNK_LINE {
                        self.desync(d);
                    }
                    return &[];
                };
                let dd = &mut self.dirs[d];
                dd.buf.extend_from_slice(input.get(..nl).unwrap_or(&[]));
                let line = std::mem::take(&mut dd.buf);
                let line = line.strip_suffix(b"\r").unwrap_or(&line);
                let rest = input.get(nl + 1..).unwrap_or(&[]);
                if st == Chunk::Trailer {
                    if line.is_empty() {
                        self.end_message(d, out);
                    }
                    return rest;
                }
                let hexpart = line
                    .split(|&c| c == b';')
                    .next()
                    .unwrap_or(&[])
                    .trim_ascii();
                let size = std::str::from_utf8(hexpart)
                    .ok()
                    .filter(|s| !s.is_empty() && s.len() <= 16)
                    .and_then(|s| u64::from_str_radix(s, 16).ok());
                match size {
                    Some(0) => self.dirs[d].body = Some(Body::Chunked(Chunk::Trailer)),
                    Some(n) => self.dirs[d].body = Some(Body::Chunked(Chunk::Data(n))),
                    None => {
                        self.desync(d);
                        return &[];
                    }
                }
                rest
            }
            Chunk::Data(n) => {
                let k = n.min(input.len() as u64);
                self.count(d, k);
                self.dirs[d].body = Some(Body::Chunked(if n == k {
                    Chunk::DataEnd(2)
                } else {
                    Chunk::Data(n - k)
                }));
                input.get(k as usize..).unwrap_or(&[])
            }
            Chunk::DataEnd(left) => {
                // Skip the CRLF after chunk data (tolerate a bare LF).
                let mut i = 0usize;
                let mut left = left;
                while left > 0 && i < input.len() {
                    let c = input.get(i).copied().unwrap_or(0);
                    if c == b'\n' {
                        left = 0;
                    } else {
                        left -= 1;
                    }
                    i += 1;
                }
                self.dirs[d].body = Some(Body::Chunked(if left == 0 {
                    Chunk::Size
                } else {
                    Chunk::DataEnd(left)
                }));
                input.get(i..).unwrap_or(&[])
            }
        }
    }

    fn desync(&mut self, d: usize) {
        let dd = &mut self.dirs[d];
        dd.buf.clear();
        dd.body = None;
        dd.desync = true;
    }

    fn on_gap(&mut self, d: usize, gap: u64, out: &mut Out) {
        match self.dirs[d].body.clone() {
            Some(Body::Fixed(n)) => {
                let k = n.min(gap);
                self.count(d, k);
                if k == n {
                    self.end_message(d, out);
                } else {
                    self.dirs[d].body = Some(Body::Fixed(n - k));
                }
            }
            Some(Body::UntilClose) => self.count(d, gap),
            Some(Body::Opaque) => {}
            _ => self.desync(d),
        }
    }

    fn count(&mut self, d: usize, n: u64) {
        self.dirs[d].observed = self.dirs[d].observed.saturating_add(n);
        if let Some(p) = self.current(d) {
            if d == 0 {
                p.row.req_bytes = p.row.req_bytes.saturating_add(n);
            } else {
                p.row.resp_bytes = p.row.resp_bytes.saturating_add(n);
            }
        }
    }

    fn current(&mut self, d: usize) -> Option<&mut Pending> {
        if d == 0 {
            self.pending.back_mut().filter(|p| !p.req_done)
        } else {
            self.pending
                .iter_mut()
                .find(|p| p.resp_started && !p.resp_done)
        }
    }

    fn on_head(&mut self, d: usize, h: &HttpHead, frame: u64, ts: i64, ctx: Ctx, out: &mut Out) {
        let declared = h.content_length();
        let body_len_known = |chunked: bool| {
            if chunked {
                Some(Body::Chunked(Chunk::Size))
            } else {
                declared.map(Body::Fixed)
            }
        };
        let file = |direction: Direction, filename: Option<String>| FileRow {
            ts,
            flow_id: ctx.flow_id,
            frame_no: frame,
            source: "http".to_string(),
            direction,
            filename,
            mime_type: mime(h.header("content-type")),
            size_bytes: declared,
        };
        self.dirs[d].observed = 0;
        match &h.start {
            StartLine::Request { method, uri, .. } => {
                if self.pending.len() >= MAX_PENDING
                    && let Some(p) = self.pending.pop_front()
                {
                    emit(p, out);
                }
                let body = body_len_known(h.is_chunked()).unwrap_or(Body::Fixed(0));
                let has_body = !matches!(body, Body::Fixed(0));
                let cd = h
                    .header("content-disposition")
                    .and_then(disposition_filename);
                let req_file = has_body.then(|| {
                    let name =
                        cd.or_else(|| (method == "PUT").then(|| uri_filename(uri)).flatten());
                    file(Direction::Up, name)
                });
                self.pending.push_back(Pending {
                    row: HttpRow {
                        ts,
                        flow_id: ctx.flow_id,
                        frame_no: frame,
                        method: Some(method.clone()),
                        host: h.header("host").map(str::to_string),
                        uri: Some(uri.clone()),
                        user_agent: h.header("user-agent").map(str::to_string),
                        status: None,
                        resp_frame_no: None,
                        req_bytes: 0,
                        resp_bytes: 0,
                    },
                    is_head: method == "HEAD",
                    req_done: false,
                    resp_started: false,
                    resp_done: false,
                    req_file,
                    resp_file: None,
                });
                if method == "CONNECT" {
                    self.dirs[0].body = Some(Body::Opaque);
                    self.dirs[1].body = Some(Body::Opaque);
                    if let Some(p) = self.pending.back_mut() {
                        p.req_done = true;
                    }
                    return;
                }
                self.dirs[0].body = Some(body);
                if !has_body {
                    self.end_message(0, out);
                }
            }
            StartLine::Response { status, .. } => {
                let status = *status;
                if (100..200).contains(&status) && status != 101 {
                    self.dirs[1].body = Some(Body::Head); // interim response
                    return;
                }
                let idx = self.pending.iter().position(|p| !p.resp_started);
                let (is_head, uri) = match idx.and_then(|i| self.pending.get_mut(i)) {
                    Some(p) => {
                        p.resp_started = true;
                        p.row.status = Some(status);
                        p.row.resp_frame_no = Some(frame);
                        (p.is_head, p.row.uri.clone())
                    }
                    None => (false, None),
                };
                if status == 101 {
                    self.dirs[0].body = Some(Body::Opaque);
                    self.dirs[1].body = Some(Body::Opaque);
                    if let Some(p) = self.current(1) {
                        p.resp_done = true;
                    }
                    self.flush_done(out);
                    return;
                }
                let body = if is_head || status == 204 || status == 304 {
                    Body::Fixed(0)
                } else {
                    body_len_known(h.is_chunked()).unwrap_or(Body::UntilClose)
                };
                let has_body = !matches!(body, Body::Fixed(0));
                if has_body && let Some(p) = self.current(1) {
                    let name = h
                        .header("content-disposition")
                        .and_then(disposition_filename)
                        .or_else(|| uri.as_deref().and_then(uri_filename));
                    p.resp_file = Some(file(Direction::Down, name));
                }
                self.dirs[1].body = Some(body);
                if !has_body {
                    self.end_message(1, out);
                }
            }
        }
    }

    fn end_message(&mut self, d: usize, out: &mut Out) {
        let observed = self.dirs[d].observed;
        self.dirs[d].body = Some(Body::Head);
        self.dirs[d].observed = 0;
        if let Some(p) = self.current(d) {
            let f = if d == 0 {
                p.req_done = true;
                p.req_file.take()
            } else {
                p.resp_done = true;
                p.resp_file.take()
            };
            if let Some(mut f) = f {
                f.size_bytes = Some(f.size_bytes.unwrap_or(observed));
                out.files.push(f);
            }
        }
        self.flush_done(out);
    }

    fn flush_done(&mut self, out: &mut Out) {
        while self.pending.front().is_some_and(|p| p.resp_done) {
            if let Some(p) = self.pending.pop_front() {
                emit(p, out);
            }
        }
    }

    /// Connection closed or capture ended: emit everything still pending.
    pub fn finish(&mut self, out: &mut Out) {
        for d in 0..2 {
            let observed = self.dirs[d].observed;
            if let Some(p) = self.current(d) {
                let f = if d == 0 {
                    p.req_file.take()
                } else {
                    p.resp_file.take()
                };
                if let Some(mut f) = f {
                    f.size_bytes = Some(f.size_bytes.unwrap_or(observed));
                    out.files.push(f);
                }
            }
        }
        while let Some(p) = self.pending.pop_front() {
            emit(p, out);
        }
    }
}

fn emit(mut p: Pending, out: &mut Out) {
    for f in [p.req_file.take(), p.resp_file.take()]
        .into_iter()
        .flatten()
    {
        out.files.push(f);
    }
    out.http.push(p.row);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_head() {
        let h = parse_http(
            b"GET /a/b.exe?x=1 HTTP/1.1\r\nHost: Example.com\r\nUser-Agent: curl/8\r\n\r\nBODY",
        )
        .expect("parse");
        assert_eq!(
            h.start,
            StartLine::Request {
                method: "GET".into(),
                uri: "/a/b.exe?x=1".into(),
                version: "HTTP/1.1".into()
            }
        );
        assert_eq!(h.header("host"), Some("Example.com"));
        assert_eq!(h.head_len, 68);
        assert_eq!(uri_filename("/a/b.exe?x=1").as_deref(), Some("b.exe"));
    }

    #[test]
    fn response_head_and_errors() {
        let h = parse_http(b"HTTP/1.0 404 Not Found\nContent-Length: 5\n\n").expect("parse");
        assert!(matches!(h.start, StartLine::Response { status: 404, .. }));
        assert_eq!(h.content_length(), Some(5));
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\n"),
            Err(ParseError::Truncated)
        );
        assert!(parse_http(b"get / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_http(b"HTTP/1.1 2000 OK\r\n\r\n").is_err());
    }

    #[test]
    fn disposition() {
        assert_eq!(
            disposition_filename("attachment; filename=\"inv oice.pdf\"").as_deref(),
            Some("inv oice.pdf")
        );
        assert_eq!(
            disposition_filename("attachment; filename*=UTF-8''r%C3%A9.zip").as_deref(),
            Some("r%C3%A9.zip")
        );
        assert_eq!(disposition_filename("inline"), None);
    }
}
