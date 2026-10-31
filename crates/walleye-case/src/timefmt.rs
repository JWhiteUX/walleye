//! UTC timestamp formatting without a date-time dependency.

use walleye_core::Ts;

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `2026-03-12T09:04:05.123456Z` (RFC 3339, microseconds, UTC).
pub fn iso(us: Ts) -> String {
    let secs = us.div_euclid(1_000_000);
    let frac = us.rem_euclid(1_000_000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:06}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

/// `2026-03-12 09:04:05.123456Z`, the form the UI shows.
pub fn display(us: Ts) -> String {
    iso(us).replacen('T', " ", 1)
}

/// `1h 2m 3s`-style duration for report headers.
pub fn duration(us: i64) -> String {
    let us = us.max(0);
    if us < 1_000_000 {
        return format!("{:.3} s", us as f64 / 1e6);
    }
    let s = us / 1_000_000;
    let (h, m, s) = (s / 3600, (s / 60) % 60, s % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m {s}s"),
        _ => format!("{h}h {m}m {s}s"),
    }
}

/// Current time in microseconds since the epoch.
pub fn now_us() -> Ts {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as Ts)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(iso(1_773_306_026_906_498), "2026-03-12T09:00:26.906498Z");
        assert_eq!(iso(951_782_400_000_000), "2000-02-29T00:00:00.000000Z");
        assert_eq!(iso(-1), "1969-12-31T23:59:59.999999Z");
        assert_eq!(display(0), "1970-01-01 00:00:00.000000Z");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(3_500_070_084), "58m 20s");
        assert_eq!(duration(3_723_000_000), "1h 2m 3s");
        assert_eq!(duration(5_000_000), "5s");
        assert_eq!(duration(250_000), "0.250 s");
    }
}
