//! HTTP/1.1 message builders and the date helpers they need.

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month, day) for days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC 7231 IMF-fixdate, e.g. `Tue, 10 Mar 2026 09:00:00 GMT`.
pub fn http_date(ts_us: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = ts_us.div_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

pub struct Request<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub host: &'a str,
    pub user_agent: &'a str,
    pub extra: &'a [(&'a str, String)],
    pub body_len: u64,
}

/// Request line + headers (+ terminating CRLF). The body, if any, follows
/// separately so large uploads can be streamed.
pub fn request_head(r: &Request<'_>) -> Vec<u8> {
    let mut s = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\n",
        r.method, r.uri, r.host, r.user_agent
    );
    for (k, v) in r.extra {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    if r.body_len > 0 || r.method == "POST" {
        s.push_str(&format!("Content-Length: {}\r\n", r.body_len));
    }
    s.push_str("Connection: keep-alive\r\n\r\n");
    s.into_bytes()
}

pub struct Response<'a> {
    pub status: u16,
    pub server: &'a str,
    pub content_type: &'a str,
    pub body_len: u64,
    pub date_us: i64,
    pub extra: &'a [(&'a str, String)],
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

pub fn response_head(r: &Response<'_>) -> Vec<u8> {
    let mut s = format!(
        "HTTP/1.1 {} {}\r\nDate: {}\r\nServer: {}\r\n",
        r.status,
        reason(r.status),
        http_date(r.date_us),
        r.server
    );
    if r.status != 204 && r.status != 304 {
        s.push_str(&format!(
            "Content-Type: {}\r\nContent-Length: {}\r\n",
            r.content_type, r.body_len
        ));
    }
    for (k, v) in r.extra {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    s.push_str("Connection: keep-alive\r\n\r\n");
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_roundtrip_and_format() {
        let d = days_from_civil(2026, 3, 10);
        assert_eq!(civil_from_days(d), (2026, 3, 10));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        let ts = (d * 86_400 + 9 * 3600) * 1_000_000;
        assert_eq!(http_date(ts), "Tue, 10 Mar 2026 09:00:00 GMT");
    }

    #[test]
    fn heads_end_with_blank_line() {
        let h = request_head(&Request {
            method: "GET",
            uri: "/",
            host: "example.test",
            user_agent: "x",
            extra: &[],
            body_len: 0,
        });
        assert!(h.ends_with(b"\r\n\r\n"));
        assert!(h.starts_with(b"GET / HTTP/1.1\r\nHost: example.test\r\n"));
    }
}
