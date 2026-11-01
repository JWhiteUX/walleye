//! 802.11 read side (CONTRACTS §11.2): the derived `wifi_aps` and
//! `wifi_clients` relations, and one-line frame summaries.
//!
//! The SQL here is fixed text: no user input is ever interpolated. Column
//! order of each SELECT matches `WifiApRow` / `WifiClientRow` exactly.

use walleye_core::{WifiKind, WifiRow};

/// Max values kept in `wifi_clients.probed_ssids` and `.bssids` (security
/// review L1).
pub const CLIENT_LIST_CAP: usize = 64;

/// Kinds whose `src`/`dst` mark a station that is associated with (or
/// joining) the BSS.
const STATION_KINDS: &str = "('data', 'null', 'eapol', 'auth', 'assoc_req', 'reassoc_req')";
/// Kinds whose `src`/`dst` count as clients of an access point.
const DATA_KINDS: &str = "('data', 'null', 'eapol')";
/// Kinds that advertise a BSS.
const ADV_KINDS: &str = "('beacon', 'probe_resp')";

/// Unicast test on canonical lowercase MAC text: the group bit is the low bit
/// of the first octet, i.e. of its second hex digit.
fn unicast(col: &str) -> String {
    format!("(substr({col}, 2, 1) IN ('0', '2', '4', '6', '8', 'a', 'c', 'e'))")
}

/// Locally administered bit (`0x02` of the first octet) on canonical text.
fn randomized(col: &str) -> String {
    format!("(substr({col}, 2, 1) IN ('2', '3', '6', '7', 'a', 'b', 'e', 'f'))")
}

/// `wifi_aps`: one row per BSSID that sent a beacon or probe response.
///
/// - `ssid`, `channel`, `security`: most frequent value over that BSSID's
///   beacons, or over its probe responses only when it never beacons (a
///   karma AP answers probes for many SSIDs; what it beacons is what it
///   advertises). Non-empty SSIDs only; ties go to the smallest value, so the
///   result is deterministic.
/// - `first_ts`, `last_ts`, `frames`, `first_frame`: over every `wifi` row
///   whose `bssid` is this BSSID; `beacons` counts its beacon rows.
/// - `clients`: distinct unicast `src`/`dst` other than the BSSID in its
///   data/null/eapol rows.
/// - `signal_max`: over the AP's own transmissions (`tx = bssid`).
pub(crate) fn aps_select() -> String {
    format!(
        "WITH all_adv AS (SELECT bssid, kind, ssid, channel, security FROM wifi \
            WHERE kind IN {ADV_KINDS} AND bssid IS NOT NULL), \
         bcn AS (SELECT DISTINCT bssid FROM all_adv WHERE kind = 'beacon'), \
         adv AS (SELECT bssid, ssid, channel, security FROM all_adv \
            WHERE kind = 'beacon' OR bssid NOT IN (SELECT bssid FROM bcn)), \
         ssid_n AS (SELECT bssid, ssid, count(*) AS n FROM adv WHERE ssid <> '' GROUP BY bssid, ssid), \
         chan_n AS (SELECT bssid, channel, count(*) AS n FROM adv WHERE channel IS NOT NULL GROUP BY bssid, channel), \
         sec_n AS (SELECT bssid, security, count(*) AS n FROM adv WHERE security IS NOT NULL GROUP BY bssid, security), \
         b_ssid AS (SELECT bssid, first(ssid ORDER BY n DESC, ssid) AS ssid FROM ssid_n GROUP BY bssid), \
         b_chan AS (SELECT bssid, first(channel ORDER BY n DESC, channel) AS channel FROM chan_n GROUP BY bssid), \
         b_sec AS (SELECT bssid, first(security ORDER BY n DESC, security) AS security FROM sec_n GROUP BY bssid), \
         tot AS (SELECT bssid, min(ts) AS first_ts, max(ts) AS last_ts, \
            count(*) FILTER (WHERE kind = 'beacon') AS beacons, count(*) AS frames, \
            max(signal_dbm) FILTER (WHERE tx = bssid) AS signal_max, min(frame_no) AS first_frame \
            FROM wifi WHERE bssid IN (SELECT bssid FROM adv) GROUP BY bssid), \
         sta AS (SELECT bssid, src AS m FROM wifi WHERE kind IN {DATA_KINDS} AND bssid IS NOT NULL \
            UNION ALL SELECT bssid, dst AS m FROM wifi WHERE kind IN {DATA_KINDS} AND bssid IS NOT NULL), \
         cl AS (SELECT bssid, count(DISTINCT m) AS clients FROM sta \
            WHERE m IS NOT NULL AND m <> bssid AND {uni} GROUP BY bssid) \
         SELECT t.bssid AS bssid, s.ssid AS ssid, CAST(c.channel AS USMALLINT) AS channel, \
            x.security AS security, t.first_ts AS first_ts, t.last_ts AS last_ts, \
            CAST(t.beacons AS UBIGINT) AS beacons, CAST(t.frames AS UBIGINT) AS frames, \
            CAST(coalesce(cl.clients, 0) AS UBIGINT) AS clients, \
            CAST(t.signal_max AS SMALLINT) AS signal_max, {rnd} AS randomized, \
            CAST(t.first_frame AS UBIGINT) AS first_frame \
         FROM tot t LEFT JOIN b_ssid s ON s.bssid = t.bssid LEFT JOIN b_chan c ON c.bssid = t.bssid \
            LEFT JOIN b_sec x ON x.bssid = t.bssid LEFT JOIN cl ON cl.bssid = t.bssid",
        uni = unicast("m"),
        rnd = randomized("t.bssid"),
    )
}

/// `wifi_clients`: one row per station.
///
/// Stations are unicast addresses that transmitted a probe request, or that
/// appear as `src`/`dst` (other than the frame's BSSID) in
/// data/null/eapol/auth/(re)assoc-request rows, minus every BSSID that
/// advertised itself (beacon or probe response).
///
/// - `first_ts`, `last_ts`, `first_frame`: over every row where the station
///   is `src`, `dst` or `tx`.
/// - `frames`, `signal_max`: over the rows it transmitted (`tx = mac`).
/// - `probed_ssids`: sorted distinct non-empty SSIDs of its probe requests.
/// - `bssids`: sorted distinct BSSIDs (other than itself) of its
///   data/null/eapol/auth/(re)assoc-request rows.
///
/// Both lists keep only their first `CLIENT_LIST_CAP` values in sort order:
/// one hostile station probing for 500k SSIDs must not make a multi-MB row.
/// Filters on `client.probed`/`client.bssid` see the capped list; the full
/// set stays queryable on the `wifi` view (`mac X and wifi.kind == probe_req`).
pub(crate) fn clients_select() -> String {
    format!(
        "WITH ap AS (SELECT DISTINCT bssid FROM wifi WHERE kind IN {ADV_KINDS} AND bssid IS NOT NULL), \
         cand AS (SELECT tx AS mac FROM wifi WHERE kind = 'probe_req' AND tx IS NOT NULL \
            UNION SELECT src AS mac FROM wifi WHERE kind IN {STATION_KINDS} AND src IS NOT NULL AND src IS DISTINCT FROM bssid \
            UNION SELECT dst AS mac FROM wifi WHERE kind IN {STATION_KINDS} AND dst IS NOT NULL AND dst IS DISTINCT FROM bssid), \
         sta AS (SELECT mac FROM cand WHERE {uni} AND mac NOT IN (SELECT bssid FROM ap)), \
         app AS (SELECT tx AS mac, kind, ts, frame_no, signal_dbm, ssid, bssid, TRUE AS is_tx FROM wifi WHERE tx IS NOT NULL \
            UNION ALL SELECT src, kind, ts, frame_no, NULL, NULL, bssid, FALSE FROM wifi \
               WHERE src IS NOT NULL AND src IS DISTINCT FROM tx \
            UNION ALL SELECT dst, kind, ts, frame_no, NULL, NULL, bssid, FALSE FROM wifi \
               WHERE dst IS NOT NULL AND dst IS DISTINCT FROM tx AND dst IS DISTINCT FROM src) \
         SELECT a.mac AS mac, {rnd} AS randomized, min(a.ts) AS first_ts, max(a.ts) AS last_ts, \
            CAST(count(*) FILTER (WHERE a.is_tx) AS UBIGINT) AS frames, \
            coalesce(list_slice(list(DISTINCT a.ssid ORDER BY a.ssid) FILTER (WHERE a.is_tx AND a.kind = 'probe_req' AND a.ssid <> ''), \
               1, {cap}), CAST([] AS VARCHAR[])) AS probed_ssids, \
            coalesce(list_slice(list(DISTINCT a.bssid ORDER BY a.bssid) FILTER (WHERE a.kind IN {STATION_KINDS} \
               AND a.bssid IS NOT NULL AND a.bssid <> a.mac), 1, {cap}), CAST([] AS VARCHAR[])) AS bssids, \
            CAST(max(a.signal_dbm) FILTER (WHERE a.is_tx) AS SMALLINT) AS signal_max, \
            CAST(min(a.frame_no) AS UBIGINT) AS first_frame \
         FROM app a WHERE a.mac IN (SELECT mac FROM sta) GROUP BY a.mac",
        uni = unicast("mac"),
        rnd = randomized("a.mac"),
        cap = CLIENT_LIST_CAP,
    )
}

/// Timeline kind index for a `wifi` row: 0 mgmt, 1 probe, 2 data, 3 deauth.
pub(crate) const DEVICE_KIND_CASE: &str = "CASE WHEN kind IN ('deauth', 'disassoc') THEN 3 \
    WHEN kind IN ('probe_req', 'probe_resp') THEN 1 \
    WHEN kind IN ('data', 'null', 'eapol') THEN 2 ELSE 0 END";

fn addr(a: &Option<String>) -> &str {
    a.as_deref().unwrap_or("?")
}

/// SSIDs are attacker-chosen text that ingest keeps with `"` raw; quote them
/// with the shared helper so a summary's quoted SSID cannot be closed early
/// and spoof the fields after it.
fn ssid_text(s: &Option<String>, empty: &str) -> String {
    match s.as_deref() {
        Some(s) if !s.is_empty() => walleye_core::text::quote_ssid(s),
        _ => empty.to_string(),
    }
}

fn chan_sec(r: &WifiRow) -> String {
    let mut out = String::new();
    if let Some(c) = r.channel {
        out.push_str(&format!(" ch {c}"));
    }
    if let Some(s) = &r.security {
        out.push(' ');
        out.push_str(s);
    }
    out
}

/// One-line summary of an 802.11 frame for the packet list, e.g.
/// `Deauth 42:00:5e:00:53:9c → ff:ff:ff:ff:ff:ff reason 7` or
/// `Beacon "HomeNet" ch 6 wpa2`.
pub fn wifi_summary(r: &WifiRow) -> String {
    // The transmitter is who actually sent it; SA when TA is unknown.
    let from = r.tx.as_ref().or(r.src.as_ref()).map_or("?", String::as_str);
    let to = addr(&r.dst);
    let code = |label: &str| {
        r.reason
            .map(|c| format!(" {label} {c}"))
            .unwrap_or_default()
    };
    match r.kind {
        WifiKind::Beacon => format!("Beacon {}{}", ssid_text(&r.ssid, "(hidden)"), chan_sec(r)),
        WifiKind::ProbeReq => format!("Probe request {} from {from}", ssid_text(&r.ssid, "(any)")),
        WifiKind::ProbeResp => format!(
            "Probe response {} → {to}{}",
            ssid_text(&r.ssid, "(hidden)"),
            chan_sec(r)
        ),
        WifiKind::Deauth => format!("Deauth {from} → {to}{}", code("reason")),
        WifiKind::Disassoc => format!("Disassoc {from} → {to}{}", code("reason")),
        WifiKind::Auth => format!("Auth {from} → {to}{}", code("status")),
        WifiKind::AssocReq => format!(
            "Assoc request {from} → {to} {}",
            ssid_text(&r.ssid, "(hidden)")
        ),
        WifiKind::ReassocReq => format!(
            "Reassoc request {from} → {to} {}",
            ssid_text(&r.ssid, "(hidden)")
        ),
        WifiKind::AssocResp => format!("Assoc response {from} → {to}{}", code("status")),
        WifiKind::ReassocResp => format!("Reassoc response {from} → {to}{}", code("status")),
        WifiKind::Action => format!("Action {from} → {to}"),
        WifiKind::MgmtOther => format!("Management {from} → {to}"),
        WifiKind::Data => format!(
            "Data {from} → {to}{} len={}",
            if r.protected { " [protected]" } else { "" },
            r.len
        ),
        WifiKind::Null => format!("Null {from} → {to}"),
        WifiKind::Eapol => format!("EAPOL {from} → {to} len={}", r.len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: WifiKind) -> WifiRow {
        WifiRow {
            ts: 0,
            frame_no: 1,
            kind,
            protected: false,
            retry: false,
            src: Some("42:00:5e:00:53:9c".into()),
            dst: Some("ff:ff:ff:ff:ff:ff".into()),
            tx: Some("42:00:5e:00:53:9c".into()),
            bssid: Some("42:00:5e:00:53:9c".into()),
            channel: Some(6),
            freq_mhz: Some(2437),
            signal_dbm: Some(-40),
            ssid: Some("HomeNet".into()),
            security: Some("wpa2".into()),
            reason: Some(7),
            seq: Some(1),
            len: 100,
        }
    }

    #[test]
    fn summaries_match_the_contract_examples() {
        assert_eq!(
            wifi_summary(&row(WifiKind::Deauth)),
            "Deauth 42:00:5e:00:53:9c → ff:ff:ff:ff:ff:ff reason 7"
        );
        assert_eq!(
            wifi_summary(&row(WifiKind::Beacon)),
            "Beacon \"HomeNet\" ch 6 wpa2"
        );
        let mut p = row(WifiKind::ProbeReq);
        p.ssid = Some(String::new());
        assert_eq!(
            wifi_summary(&p),
            "Probe request (any) from 42:00:5e:00:53:9c"
        );
        // Hostile SSIDs cannot close the quote and spoof later fields (M4).
        let mut b = row(WifiKind::Beacon);
        b.ssid = Some("Free\" ch 6 wpa3".into());
        b.security = Some("open".into());
        assert_eq!(wifi_summary(&b), "Beacon \"Free\\\" ch 6 wpa3\" ch 6 open");
        // Stored form of the SSID `a\"`: ingest writes the backslash as `\\`.
        b.ssid = Some("a\\\\\"".into());
        assert_eq!(wifi_summary(&b), "Beacon \"a\\\\\\\"\" ch 6 open");
        let mut p = row(WifiKind::ProbeResp);
        p.ssid = Some("x\"y".into());
        assert!(wifi_summary(&p).starts_with("Probe response \"x\\\"y\" → "));
        for k in WifiKind::ALL {
            let mut r = row(k);
            r.src = None;
            r.dst = None;
            r.tx = None;
            r.ssid = None;
            r.reason = None;
            assert!(!wifi_summary(&r).is_empty());
        }
    }
}
