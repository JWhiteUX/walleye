//! 802.11 (Wi-Fi monitor-mode) detectors, fed only by the `wifi` table
//! (CONTRACTS §11.3). Findings are about devices: `entity_type = "device"`,
//! `entity` = the attacker's MAC, evidence = frame numbers (no flows).
//!
//! | detector         | per                    | fires on |
//! |------------------|------------------------|----------|
//! | `wifi_deauth`    | transmitter            | ≥ `min_count` deauth/disassoc frames inside a `window_s` sliding window; scored on peak rate, broadcast share, distinct targets, a spoofed/unbeaconed or randomized BSSID, and EAPOL handshakes right after the burst |
//! | `wifi_evil_twin` | SSID × weaker BSSID    | one SSID advertised as open/OWE/WEP by one BSSID and WPA/WPA2/WPA3 by another; scored up when the weaker one is randomized, on another channel, appeared later, or has another vendor prefix |
//! | `wifi_karma`     | BSSID                  | probe responses for ≥ `min_ssids` distinct SSIDs the BSSID (and its sequential siblings) never beacons, or beacons for that many SSIDs from one BSSID; scored up when the answers echo what a client just asked for, are open, or come from a randomized BSSID |
//!
//! Benign shapes that must stay quiet, and why they do:
//! - Normal deauths (AP housekeeping with reason 6/7, a few kicks per client
//!   per hour) never reach `min_count` inside one window: the window gate is
//!   what separates a flood from volume spread over a capture.
//! - Reason 3/8 sent by a station to its own AP ("I'm leaving") is not
//!   counted at all (`self_leave_reasons`).
//! - Mesh and multi-band networks advertise one SSID with the *same*
//!   security everywhere; only a security split fires the twin rule. Hidden
//!   (empty) SSIDs and factory-default SSIDs are skipped.
//! - Multi-SSID enterprise APs beacon each SSID from its own sequential
//!   BSSID and only answer probes for those; karma counts only SSIDs that
//!   no BSSID in the same sibling group beacons.
//!
//! Memory is bounded for 50 M-row captures: every per-device / per-SSID map
//! and every per-entry list has a hard cap (constants below); entries past a
//! cap are counted and skipped, never stored.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use walleye_core::findings::EVIDENCE_CAP;
use walleye_core::mac::{parse_mac, text_is_locally_administered};
use walleye_core::rules::render_template;
use walleye_core::{Evidence, FrameNo, Reason, Ts, WifiKind, WifiRow};

use crate::combine::{Entity, Hit};
use crate::rules::{Rule, RuleSet};
use crate::util::{clip, display, fmt_num, hash64, ramp, round1};

/// Distinct deauth transmitters tracked per rule.
const MAX_DEAUTH_TX: usize = 20_000;
/// Distinct unicast targets remembered per deauth transmitter.
const MAX_TARGETS: usize = 256;
/// Claimed BSSIDs / reason codes remembered per deauth transmitter.
const MAX_SMALL: usize = 16;
/// Addresses mapped to an active deauth burst (for the handshake signal).
const MAX_BURST_KEYS: usize = 10_000;
/// EAPOL frames kept as evidence per deauth transmitter.
const MAX_EAPOL_EV: usize = 20;
/// BSSIDs whose advertised SSID we remember.
const MAX_APS: usize = 50_000;
/// SSIDs tracked by the evil-twin collector, and BSSIDs per SSID.
const MAX_TWIN_SSIDS: usize = 20_000;
const MAX_BSS_PER_SSID: usize = 32;
/// Channels remembered per (SSID, BSSID).
const MAX_CHANNELS: usize = 8;
/// Frames of the original network shown next to a twin's frames.
const ORIGINAL_EV: usize = 10;
/// BSSIDs tracked by the karma collector, SSIDs answered and beaconed each.
const MAX_KARMA_BSS: usize = 20_000;
const MAX_RESP_SSIDS: usize = 256;
const MAX_BEACON_SSIDS: usize = 64;
/// Recent (client, SSID) probe requests remembered for the echo signal.
const MAX_PROBES: usize = 100_000;
/// Longest wait between futile deauth-map sweeps, in windows.
const MAX_SWEEP_BACKOFF: i64 = 64;
/// SSIDs are at most 32 bytes on the air.
const MAX_SSID: usize = 32;
/// Sub-buckets of the deauth sliding window (the window is approximated to
/// within one sub-bucket, `window_s / SUB`).
const SUB: usize = 6;

const SECURITIES: [&str; 7] = ["open", "owe", "wep", "wpa", "wpa2", "wpa2/wpa3", "wpa3"];

/// Open, OWE (unauthenticated) and WEP: anyone can stand one up.
fn sec_is_weak(i: usize) -> bool {
    i <= 2
}

pub(crate) fn wanted(rules: &RuleSet) -> bool {
    rules
        .rules()
        .iter()
        .any(|r| r.def.enabled && r.def.detector.starts_with("wifi_"))
}

fn is_canonical(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17
        && b.iter().enumerate().all(|(i, &c)| {
            if i % 3 == 2 {
                c == b':'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

/// Canonical lowercase MAC, borrowing when ingest already canonicalised it.
fn canon(s: Option<&str>) -> Option<Cow<'_, str>> {
    let s = s?;
    if is_canonical(s) {
        Some(Cow::Borrowed(s))
    } else {
        parse_mac(s).map(Cow::Owned)
    }
}

fn first_octet(m: &str) -> u8 {
    u8::from_str_radix(m.get(0..2).unwrap_or("00"), 16).unwrap_or(0)
}

fn is_group(m: &str) -> bool {
    first_octet(m) & 0x01 != 0
}

fn randomized(m: &str) -> bool {
    text_is_locally_administered(m)
}

/// Vendor prefix (first three octets) of a canonical MAC.
fn oui(m: &str) -> &str {
    m.get(0..8).unwrap_or(m)
}

/// Sequential BSSIDs of one AP differ in the first octet (locally
/// administered variants) and/or the last octet; octets 2–5 identify the
/// radio.
fn sibling_group(m: &str) -> &str {
    m.get(3..14).unwrap_or(m)
}

/// A non-hidden SSID, clipped to 32 bytes. Empty, whitespace-only and
/// NUL-filled (sanitized to `?`) SSIDs are hidden networks.
fn visible_ssid(s: Option<&str>) -> Option<&str> {
    let s = clip(s?, MAX_SSID);
    if s.chars()
        .all(|c| c == '\0' || c == '?' || c.is_whitespace())
    {
        None
    } else {
        Some(s)
    }
}

fn transmitter(row: &WifiRow) -> Option<Cow<'_, str>> {
    canon(row.tx.as_deref().or(row.src.as_deref())).filter(|m| !is_group(m))
}

fn push_cap(v: &mut Vec<FrameNo>, f: FrameNo, cap: usize) {
    if v.len() < cap {
        v.push(f);
    }
}

/// Sorted, de-duplicated, capped evidence; `total` is the real count.
fn evidence(mut frames: Vec<FrameNo>, total: u64) -> Evidence {
    frames.sort_unstable();
    frames.dedup();
    let total = total.max(frames.len() as u64);
    frames.truncate(EVIDENCE_CAP);
    Evidence {
        flow_ids: Vec::new(),
        truncated: total > frames.len() as u64,
        total,
        frame_nos: frames,
    }
}

fn breakdown(points: &[(&str, f64)]) -> String {
    points
        .iter()
        .filter(|(_, p)| *p >= 0.05)
        .map(|(s, p)| format!("{s} {}", fmt_num(*p, 1)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn push_notes(explanation: &mut String, notes: &[String]) {
    if !notes.is_empty() {
        explanation.push_str(&format!(" ({})", notes.join("; ")));
    }
}

/// An SSID for splicing inside `"…"` in a title or explanation: printable
/// text (`display`) with `\` and `"` escaped, so a crafted SSID cannot close
/// the quote and forge the text that follows.
fn ssid_text(s: &str) -> String {
    display(s).replace('\\', "\\\\").replace('"', "\\\"")
}

fn examples<'a>(it: impl Iterator<Item = &'a str>, n: usize, quote: bool) -> String {
    let v: Vec<String> = it
        .take(n)
        .map(|s| {
            if quote {
                format!("\"{}\"", ssid_text(s))
            } else {
                display(s)
            }
        })
        .collect();
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

// ---------------------------------------------------------------- deauth --

/// Beacon signals remembered per AP (the reference is their median).
const SIG_RING: usize = 16;
/// Signal deltas (deauth − reference beacons) histogram: −60..=60 dB.
const DELTA_SPAN: i16 = 60;
const DELTA_BINS: usize = (2 * DELTA_SPAN + 1) as usize;

/// What one BSSID advertised, and its own recent beacon signal.
#[derive(Debug)]
pub(crate) struct ApInfo {
    /// First SSID it advertised ("" = hidden).
    ssid: String,
    ring: [i16; SIG_RING],
    /// Beacons with a signal reading.
    sig_n: u64,
    last_beacon: Ts,
}

impl ApInfo {
    fn new(ssid: &str) -> Self {
        Self {
            ssid: ssid.to_string(),
            ring: [0; SIG_RING],
            sig_n: 0,
            last_beacon: Ts::MIN,
        }
    }

    fn record(&mut self, ts: Ts, sig: i16) {
        self.ring[(self.sig_n % SIG_RING as u64) as usize] = sig;
        self.sig_n += 1;
        self.last_beacon = ts;
    }

    /// Median signal of the AP's last beacons, if it beaconed enough and
    /// recently enough to compare against a frame at `ts`.
    fn reference(&self, ts: Ts, min_beacons: u64, max_age_us: i64) -> Option<i16> {
        if self.sig_n < min_beacons.max(1) || ts.saturating_sub(self.last_beacon) > max_age_us {
            return None;
        }
        let n = (self.sig_n as usize).min(SIG_RING);
        let mut v = self.ring;
        v[..n].sort_unstable();
        Some(v[n / 2])
    }
}

#[derive(Debug)]
struct DeauthTx {
    count: u64,
    /// Frames sent while the window count was at or over `min_count`.
    burst_frames: u64,
    /// Burst frames to a group address.
    broadcast: u64,
    /// Frames sent as the AP (tx == bssid).
    as_ap: u64,
    /// Frames from a non-AP address to someone other than its AP.
    third_party: u64,
    targets: BTreeSet<String>,
    targets_over: bool,
    bssids: BTreeSet<String>,
    reasons: BTreeMap<u16, u64>,
    ring: [u32; SUB],
    ring_idx: i64,
    peak: u32,
    first_ts: Ts,
    last_ts: Ts,
    frames: Vec<FrameNo>,
    eapol: u64,
    eapol_frames: Vec<FrameNo>,
    burst_until: Ts,
    /// Unicast frames with a rejection reason (6/7) sent as the AP.
    rejections: u64,
    /// Histogram of (deauth signal - reference beacon median), allocated on
    /// the first frame that has a reference.
    deltas: Option<Box<[u32; DELTA_BINS]>>,
    /// Frames compared against beacons, and how many of those against the
    /// transmitter's *own* beacons.
    ref_frames: u64,
    ref_self: u64,
}

impl DeauthTx {
    fn record_delta(&mut self, d: i16, own: bool) {
        let h = self.deltas.get_or_insert_with(|| Box::new([0; DELTA_BINS]));
        let i = (d.clamp(-DELTA_SPAN, DELTA_SPAN) + DELTA_SPAN) as usize;
        h[i] = h[i].saturating_add(1);
        self.ref_frames += 1;
        if own {
            self.ref_self += 1;
        }
    }

    /// Median signal delta in dB over the compared frames.
    fn median_delta(&self) -> Option<i16> {
        let h = self.deltas.as_ref()?;
        let total: u64 = h.iter().map(|&c| u64::from(c)).sum();
        let mut acc = 0u64;
        for (i, &c) in h.iter().enumerate() {
            acc += u64::from(c);
            if acc * 2 >= total && total > 0 {
                return Some(i as i16 - DELTA_SPAN);
            }
        }
        None
    }

    /// Share of compared frames at least `db` away from the reference, and
    /// the median |delta| of those frames.
    fn far(&self, db: f64) -> (f64, f64) {
        let Some(h) = self.deltas.as_ref() else {
            return (0.0, 0.0);
        };
        let far: Vec<(f64, u64)> = h
            .iter()
            .enumerate()
            .map(|(i, &c)| (f64::from((i as i16 - DELTA_SPAN).abs()), u64::from(c)))
            .filter(|(a, c)| *a >= db && *c > 0)
            .collect();
        let n: u64 = far.iter().map(|(_, c)| c).sum();
        if n == 0 || self.ref_frames == 0 {
            return (0.0, 0.0);
        }
        let mut sorted = far;
        sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut acc = 0;
        let mut med = 0.0;
        for (a, c) in sorted {
            acc += c;
            if acc * 2 >= n {
                med = a;
                break;
            }
        }
        (n as f64 / self.ref_frames as f64, med)
    }

    fn new(ts: Ts, sub_us: i64) -> Self {
        Self {
            count: 0,
            burst_frames: 0,
            broadcast: 0,
            as_ap: 0,
            third_party: 0,
            targets: BTreeSet::new(),
            targets_over: false,
            bssids: BTreeSet::new(),
            reasons: BTreeMap::new(),
            ring: [0; SUB],
            ring_idx: ts.div_euclid(sub_us),
            peak: 0,
            first_ts: ts,
            last_ts: ts,
            frames: Vec::new(),
            eapol: 0,
            eapol_frames: Vec::new(),
            burst_until: Ts::MIN,
            rejections: 0,
            deltas: None,
            ref_frames: 0,
            ref_self: 0,
        }
    }

    /// Count one frame at `ts` and return the frames inside the window.
    fn bump(&mut self, ts: Ts, sub_us: i64) -> u32 {
        let idx = ts.div_euclid(sub_us);
        if idx > self.ring_idx {
            let steps = (idx - self.ring_idx).min(SUB as i64);
            for k in 1..=steps {
                self.ring[(self.ring_idx + k).rem_euclid(SUB as i64) as usize] = 0;
            }
            self.ring_idx = idx;
        }
        let slot = self.ring_idx.rem_euclid(SUB as i64) as usize;
        self.ring[slot] = self.ring[slot].saturating_add(1);
        self.ring.iter().fold(0u32, |a, &b| a.saturating_add(b))
    }
}

#[derive(Debug)]
struct DeauthState {
    rule_idx: usize,
    sub_us: i64,
    min_count: u32,
    handshake_us: i64,
    self_reasons: Vec<u16>,
    rejection_reasons: Vec<u16>,
    min_ref_beacons: u64,
    ref_age_us: i64,
    txs: HashMap<String, DeauthTx>,
    /// Address (BSSID or target) → transmitter whose burst touched it.
    burst_keys: HashMap<String, String>,
    suppressed: u64,
    dropped: u64,
    prune_after: Ts,
    /// Current wait between transmitter-map sweeps (µs).
    sweep_backoff: i64,
}

impl DeauthState {
    fn new(rule: &Rule, rule_idx: usize) -> Self {
        let window_us = (rule.num("window_s") * 1e6) as i64;
        Self {
            rule_idx,
            sub_us: (window_us / SUB as i64).max(1),
            min_count: rule.num("min_count").ceil() as u32,
            handshake_us: (rule.num("handshake_window_s") * 1e6) as i64,
            self_reasons: codes(rule.nums("self_leave_reasons")),
            rejection_reasons: codes(rule.nums("rejection_reasons")),
            min_ref_beacons: rule.num("min_ref_beacons") as u64,
            ref_age_us: (rule.num("ref_max_age_s") * 1e6) as i64,
            txs: HashMap::new(),
            burst_keys: HashMap::new(),
            suppressed: 0,
            dropped: 0,
            prune_after: Ts::MIN,
            sweep_backoff: 0,
        }
    }

    fn observe_deauth(
        &mut self,
        row: &WifiRow,
        tx: &str,
        dst: Option<&str>,
        bssid: Option<&str>,
        aps: &HashMap<String, ApInfo>,
    ) {
        let station_to_own_ap = bssid.is_some_and(|b| b != tx) && dst.is_some() && dst == bssid;
        if station_to_own_ap && row.reason.is_some_and(|r| self.self_reasons.contains(&r)) {
            self.suppressed += 1;
            return;
        }
        if !self.txs.contains_key(tx) && self.txs.len() >= MAX_DEAUTH_TX {
            // Evict transmitters that never reached the gate and have been
            // silent for a whole window: they cannot fire on what we've seen
            // (the gate is per window), so forgetting them loses nothing. A
            // random-source flood therefore cannot lock a later attacker out.
            // At most one sweep per sub-bucket keeps this O(1) amortised.
            // Transmitters past the gate are never evicted, so when the map
            // is full of them sweeps free nothing: back off exponentially
            // (up to MAX_SWEEP_BACKOFF windows) until one frees space again.
            if row.ts >= self.prune_after {
                let horizon = row.ts.saturating_sub(self.sub_us * SUB as i64);
                let min = self.min_count;
                let before = self.txs.len();
                self.txs
                    .retain(|_, t| t.peak >= min || t.last_ts >= horizon);
                let freed = before - self.txs.len();
                self.sweep_backoff = if freed * 16 < MAX_DEAUTH_TX {
                    (self.sweep_backoff.max(self.sub_us) * 2)
                        .min(self.sub_us * SUB as i64 * MAX_SWEEP_BACKOFF)
                } else {
                    self.sub_us
                };
                self.prune_after = row.ts.saturating_add(self.sweep_backoff);
            }
            if self.txs.len() >= MAX_DEAUTH_TX {
                self.dropped += 1;
                return;
            }
        }
        let sub_us = self.sub_us;
        let t = self
            .txs
            .entry(tx.to_string())
            .or_insert_with(|| DeauthTx::new(row.ts, sub_us));
        t.count += 1;
        t.last_ts = row.ts;
        push_cap(&mut t.frames, row.frame_no, EVIDENCE_CAP);
        if bssid == Some(tx) {
            t.as_ap += 1;
        } else if bssid.is_some() && dst != bssid {
            t.third_party += 1;
        }
        if let Some(b) = bssid {
            if t.bssids.len() < MAX_SMALL && !t.bssids.contains(b) {
                t.bssids.insert(b.to_string());
            }
        }
        if let Some(r) = row.reason {
            if t.reasons.len() < MAX_SMALL || t.reasons.contains_key(&r) {
                *t.reasons.entry(r).or_default() += 1;
            }
            if self.rejection_reasons.contains(&r)
                && bssid == Some(tx)
                && dst.is_some_and(|d| !is_group(d))
            {
                t.rejections += 1;
            }
        }
        // Signal consistency: compare with the transmitter's own beacons, or
        // (for a third-party sender) with the beacons of the BSSID it claims.
        let delta = row.signal_dbm.and_then(|sig| {
            let (min_b, age) = (self.min_ref_beacons, self.ref_age_us);
            if let Some(r) = aps.get(tx).and_then(|a| a.reference(row.ts, min_b, age)) {
                return Some((sig.saturating_sub(r), true));
            }
            bssid
                .filter(|b| *b != tx)
                .and_then(|b| aps.get(b))
                .and_then(|a| a.reference(row.ts, min_b, age))
                .map(|r| (sig.saturating_sub(r), false))
        });
        let n = t.bump(row.ts, sub_us);
        t.peak = t.peak.max(n);
        if n >= self.min_count {
            // Broadcast share and targets describe the flood itself, so they
            // only count frames sent while the window is over the gate (an
            // AP's housekeeping kicks spread over an hour reach many clients
            // too, and must not add up).
            t.burst_frames += 1;
            // Only burst frames: a spoofer hiding a flood among the real
            // AP's housekeeping must not be averaged away.
            if let Some((d, own)) = delta {
                t.record_delta(d, own);
            }
            match dst {
                Some(d) if is_group(d) => t.broadcast += 1,
                Some(d) if !t.targets.contains(d) => {
                    if t.targets.len() < MAX_TARGETS {
                        t.targets.insert(d.to_string());
                    } else {
                        t.targets_over = true;
                    }
                }
                _ => {}
            }
            t.burst_until = row.ts.saturating_add(self.handshake_us);
            for k in [bssid, dst.filter(|d| !is_group(d))].into_iter().flatten() {
                if self.burst_keys.get(k).map(String::as_str) != Some(tx)
                    && (self.burst_keys.len() < MAX_BURST_KEYS || self.burst_keys.contains_key(k))
                {
                    self.burst_keys.insert(k.to_string(), tx.to_string());
                }
            }
        }
    }

    /// EAPOL right after a burst that touched the same BSSID or client: the
    /// "kick them off, capture the reconnect handshake" pattern.
    fn observe_eapol(&mut self, row: &WifiRow, addrs: &[Option<Cow<'_, str>>]) {
        let Self {
            txs, burst_keys, ..
        } = self;
        for a in addrs.iter().flatten() {
            let Some(txm) = burst_keys.get(a.as_ref()) else {
                continue;
            };
            let Some(t) = txs.get_mut(txm) else {
                continue;
            };
            if row.ts <= t.burst_until && row.ts >= t.first_ts {
                t.eapol += 1;
                push_cap(&mut t.eapol_frames, row.frame_no, MAX_EAPOL_EV);
                return;
            }
        }
    }
}

fn codes(v: &[f64]) -> Vec<u16> {
    v.iter()
        .filter(|r| (0.0..=65535.0).contains(*r))
        .map(|r| *r as u16)
        .collect()
}

fn analyze_deauth(
    st: &DeauthState,
    rule: &Rule,
    aps: &HashMap<String, ApInfo>,
    out: &mut Vec<Hit>,
) {
    for (tx, t) in &st.txs {
        if t.peak < st.min_count || t.count == 0 {
            continue;
        }
        let n_targets = t.targets.len();
        // "Beacons" = the address advertises a network (beacon or probe
        // response) somewhere in the capture.
        let beacons = aps.contains_key(tx.as_str());
        let s_rate = ramp(f64::from(t.peak), 0.0, rule.num("rate_full"));
        // Supporting signals count only as much as the flood is strong.
        let bcast_share = t.broadcast as f64 / t.burst_frames.max(1) as f64;
        let s_bcast = bcast_share * s_rate;
        let s_targets = ramp(n_targets as f64, 1.0, rule.num("targets_full")) * s_rate;
        let mut notes = Vec::new();
        let mut factors: Vec<f64> = Vec::new();
        let mut s_spoof: f64 = 0.0;
        if t.as_ap > 0 && !beacons {
            s_spoof = 1.0;
            notes.push(format!(
                "{} sends as an access point but never beacons",
                display(tx)
            ));
        } else if t.third_party * 2 > t.count {
            s_spoof = 1.0;
            notes.push(format!(
                "{} deauthenticates clients of a network it is not the access point of",
                display(tx)
            ));
        }
        if !beacons && randomized(tx) {
            // Only a note: many consumer APs use locally administered BSSIDs
            // for extra or hidden SSIDs, so the bit scores nothing by itself.
            notes.push(format!("{} is locally administered", display(tx)));
        }
        // Signal consistency (the standard WIDS check): deauths from the
        // real AP arrive as loud as its own beacons; a spoofer is elsewhere.
        let mut s_mismatch = 0.0;
        let delta = t.median_delta();
        let referenced = t.ref_frames * 2 >= t.burst_frames;
        let mut matched = false;
        if let (Some(d), true) = (delta, referenced) {
            let mut ad = f64::from(d.abs());
            let own = t.ref_self * 2 >= t.ref_frames;
            // A spoofer mixed into a genuine AP's own burst: the median may
            // match while a large minority of frames is far off.
            let (far_share, far_med) = t.far(rule.num("signal_mismatch_db"));
            let mixed = far_share >= rule.num("mixed_share") && ad < rule.num("signal_mismatch_db");
            if mixed {
                ad = far_med;
                notes.push(format!(
                    "{}% of the burst frames are heard {} dB or more away from the beacons, the rest like the AP",
                    fmt_num((far_share * 100.0).round(), 0),
                    fmt_num(rule.num("signal_mismatch_db"), 0)
                ));
            }
            if own && !mixed && ad <= rule.num("signal_match_db") {
                matched = true;
                let f = rule.num("genuine_factor");
                factors.push(f);
                notes.push(format!(
                    "deauth signal is within {} dB of {}'s own beacons (median of {} frames), so the real AP likely sent these; score ×{}",
                    d.abs(),
                    display(tx),
                    t.ref_frames,
                    fmt_num(f, 2)
                ));
            } else if ad >= rule.num("signal_mismatch_db") {
                s_mismatch = 0.5
                    + 0.5
                        * ramp(
                            ad,
                            rule.num("signal_mismatch_db"),
                            rule.num("signal_mismatch_full_db"),
                        );
                let whom = if own {
                    "AP it claims to be"
                } else {
                    "network it claims"
                };
                notes.push(if mixed {
                    format!(
                        "those far-off frames are a median {} dB from the beacons of the {whom}: someone else is sending as it",
                        fmt_num(ad, 0)
                    )
                } else {
                    format!(
                        "deauth signal is {} dB {} than the beacons of the {whom} (median of {} frames): sent from somewhere else",
                        d.abs(),
                        if d > 0 { "stronger" } else { "weaker" },
                        t.ref_frames
                    )
                });
            }
        }
        if matched && t.rejections * 5 >= t.count * 4 {
            let f = rule.num("rejection_factor");
            factors.push(f);
            notes.push(format!(
                "{} of {} are reason {} rejections unicast to stations of its own network; score ×{}",
                t.rejections,
                t.count,
                rule.nums("rejection_reasons")
                    .iter()
                    .map(|r| fmt_num(*r, 0))
                    .collect::<Vec<_>>()
                    .join("/"),
                fmt_num(f, 2)
            ));
        }
        let span_s = t.last_ts.saturating_sub(t.first_ts) as f64 / 1e6;
        if n_targets <= 1 && t.broadcast == 0 && span_s >= rule.num("long_single_s") {
            let f = rule.num("single_target_factor");
            factors.push(f);
            notes.push(format!(
                "every burst frame went to one station over {} min, which is how an AP repeatedly rejecting a stuck client looks; score ×{}",
                fmt_num(span_s / 60.0, 1),
                fmt_num(f, 2)
            ));
        }
        let s_hs = ramp(t.eapol as f64, 0.0, rule.num("handshake_full")) * s_rate;
        let factor: f64 = factors.iter().product();
        let pts = [
            ("rate", rule.weight("rate") * s_rate * factor),
            ("broadcast", rule.weight("broadcast") * s_bcast * factor),
            ("targets", rule.weight("targets") * s_targets * factor),
            (
                "spoofed_bssid",
                rule.weight("spoofed_bssid") * s_spoof * factor,
            ),
            ("handshake", rule.weight("handshake") * s_hs * factor),
            (
                "signal_mismatch",
                rule.weight("signal_mismatch") * s_mismatch * factor,
            ),
        ];
        let points: f64 = pts.iter().map(|(_, p)| p).sum();
        if points < rule.def.min_score || points <= 0.0 {
            continue;
        }
        let bssid = t.bssids.iter().next().map(String::as_str);
        let ssid = match bssid.and_then(|b| aps.get(b)).map(|a| a.ssid.as_str()) {
            Some(s) if !s.is_empty() => format!("\"{}\"", ssid_text(s)),
            Some(_) => "a hidden network".into(),
            None => "an unknown network".into(),
        };
        let mut v = BTreeMap::new();
        v.insert("tx".into(), display(tx));
        v.insert("count".into(), t.count.to_string());
        v.insert("peak".into(), t.peak.to_string());
        v.insert("window_s".into(), fmt_num(rule.num("window_s"), 0));
        v.insert(
            "targets".into(),
            if t.targets_over {
                format!("{MAX_TARGETS}+")
            } else {
                n_targets.to_string()
            },
        );
        v.insert(
            "target_examples".into(),
            examples(t.targets.iter().map(String::as_str), 3, false),
        );
        v.insert(
            "broadcast_pct".into(),
            fmt_num((bcast_share * 100.0).round(), 0),
        );
        v.insert("burst_frames".into(), t.burst_frames.to_string());
        v.insert("broadcast".into(), t.broadcast.to_string());
        v.insert("bssid".into(), bssid.map_or_else(|| "none".into(), display));
        v.insert("ssid".into(), ssid);
        v.insert(
            "reasons".into(),
            t.reasons
                .iter()
                .map(|(r, n)| format!("{r} ×{n}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        v.insert("eapol".into(), t.eapol.to_string());
        v.insert(
            "span_min".into(),
            fmt_num(t.last_ts.saturating_sub(t.first_ts) as f64 / 60e6, 1),
        );
        v.insert("points".into(), fmt_num(points, 1));
        v.insert("breakdown".into(), breakdown(&pts));
        let mut explanation = render_template(&rule.def.explanation, &v);
        push_notes(&mut explanation, &notes);
        let mut frames = t.frames.clone();
        let eapol_room = t.eapol_frames.len().min(EVIDENCE_CAP / 10);
        if frames.len() + eapol_room > EVIDENCE_CAP {
            frames.truncate(EVIDENCE_CAP - eapol_room);
        }
        frames.extend_from_slice(&t.eapol_frames[..eapol_room]);
        out.push(Hit {
            entity: Entity::Device(tx.clone()),
            rule_idx: st.rule_idx,
            detector_family: "wifi",
            title: render_template(&rule.def.title, &v),
            tiebreak: tx.clone(),
            ts_first: t.first_ts,
            ts_last: t.last_ts,
            reason: Reason {
                rule_id: rule.def.id.clone(),
                signal: "deauth_rate".into(),
                value: f64::from(t.peak),
                unit: Some("count".into()),
                weight: round1(points),
                explanation,
                attack_technique: rule.def.attack_technique.clone(),
                evidence: evidence(frames, t.count + t.eapol),
            },
        });
    }
}

// ------------------------------------------------------------ evil twin --

#[derive(Debug)]
struct TwinBss {
    bssid: String,
    sec: [u64; SECURITIES.len()],
    channels: Vec<u16>,
    first_ts: Ts,
    last_ts: Ts,
    frames: Vec<FrameNo>,
    total: u64,
}

impl TwinBss {
    fn dominant(&self) -> Option<usize> {
        let (i, n) = self
            .sec
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(&a.0)))?;
        (*n > 0).then_some(i)
    }
}

#[derive(Debug, Default)]
struct TwinCol {
    ssids: HashMap<String, Vec<TwinBss>>,
    dropped: u64,
}

impl TwinCol {
    fn observe(&mut self, row: &WifiRow, bssid: &str, ssid: &str, sec: usize) {
        if !self.ssids.contains_key(ssid) {
            if self.ssids.len() >= MAX_TWIN_SSIDS {
                self.dropped += 1;
                return;
            }
            self.ssids.insert(ssid.to_string(), Vec::new());
        }
        let Some(list) = self.ssids.get_mut(ssid) else {
            return;
        };
        let idx = match list.iter().position(|b| b.bssid == bssid) {
            Some(i) => i,
            None if list.len() < MAX_BSS_PER_SSID => {
                list.push(TwinBss {
                    bssid: bssid.to_string(),
                    sec: [0; SECURITIES.len()],
                    channels: Vec::new(),
                    first_ts: row.ts,
                    last_ts: row.ts,
                    frames: Vec::new(),
                    total: 0,
                });
                list.len() - 1
            }
            None => {
                self.dropped += 1;
                return;
            }
        };
        let b = &mut list[idx];
        b.sec[sec] += 1;
        b.total += 1;
        b.last_ts = row.ts;
        push_cap(&mut b.frames, row.frame_no, EVIDENCE_CAP);
        if let Some(c) = row.channel {
            if !b.channels.contains(&c) && b.channels.len() < MAX_CHANNELS {
                b.channels.push(c);
            }
        }
    }
}

fn channels_text(c: &[u16]) -> String {
    if c.is_empty() {
        return "an unknown channel".into();
    }
    let mut c = c.to_vec();
    c.sort_unstable();
    let v: Vec<String> = c.iter().map(u16::to_string).collect();
    format!("channel {}", v.join("/"))
}

fn analyze_twin(col: &TwinCol, rule: &Rule, rule_idx: usize, out: &mut Vec<Hit>) {
    let min_frames = rule.num("min_frames");
    let later_us = rule.num("later_min_s") * 1e6;
    let ignore: Vec<String> = rule
        .strs("ignore_ssids")
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    for (ssid, list) in &col.ssids {
        if ignore.contains(&ssid.to_ascii_lowercase()) {
            continue;
        }
        let mut weak = Vec::new();
        let mut strong = Vec::new();
        for b in list {
            if (b.total as f64) < min_frames {
                continue;
            }
            match b.dominant() {
                Some(i) if sec_is_weak(i) => weak.push((b, i)),
                Some(i) => strong.push((b, i)),
                None => {}
            }
        }
        if weak.is_empty() || strong.is_empty() {
            continue;
        }
        strong.sort_by(|a, b| {
            a.0.first_ts
                .cmp(&b.0.first_ts)
                .then(a.0.bssid.cmp(&b.0.bssid))
        });
        let (orig, orig_sec) = strong[0];
        let strong_first = orig.first_ts;
        let strong_rand = strong.iter().any(|(b, _)| randomized(&b.bssid));
        let strong_channels: Vec<u16> = strong
            .iter()
            .flat_map(|(b, _)| b.channels.iter().copied())
            .collect();
        for (w, w_sec) in weak {
            let w_rand = randomized(&w.bssid);
            let mut notes = Vec::new();
            let s_rand = match (w_rand, strong_rand) {
                (true, false) => 1.0,
                (true, true) => 0.5,
                _ => 0.0,
            };
            if w_rand {
                notes.push(format!("{} is locally administered", display(&w.bssid)));
            }
            let s_chan = if !w.channels.is_empty()
                && !strong_channels.is_empty()
                && !w.channels.iter().any(|c| strong_channels.contains(c))
            {
                1.0
            } else {
                0.0
            };
            let delay_us = w.first_ts.saturating_sub(strong_first);
            let s_later = if delay_us as f64 >= later_us && delay_us > 0 {
                1.0
            } else {
                0.0
            };
            let s_oui = if !w_rand && strong.iter().all(|(b, _)| oui(&b.bssid) != oui(&w.bssid)) {
                1.0
            } else {
                0.0
            };
            let pts = [
                ("security_mismatch", rule.weight("security_mismatch")),
                ("randomized", rule.weight("randomized") * s_rand),
                ("other_channel", rule.weight("other_channel") * s_chan),
                ("appeared_later", rule.weight("appeared_later") * s_later),
                ("oui_mismatch", rule.weight("oui_mismatch") * s_oui),
            ];
            let points: f64 = pts.iter().map(|(_, p)| p).sum();
            if points < rule.def.min_score || points <= 0.0 {
                continue;
            }
            let mut v = BTreeMap::new();
            v.insert("ssid".into(), ssid_text(ssid));
            v.insert("bssid".into(), display(&w.bssid));
            v.insert("security".into(), SECURITIES[w_sec].to_string());
            v.insert("channel".into(), channels_text(&w.channels));
            v.insert("frames".into(), w.total.to_string());
            v.insert("original_bssid".into(), display(&orig.bssid));
            v.insert("original_security".into(), SECURITIES[orig_sec].to_string());
            v.insert("original_channel".into(), channels_text(&orig.channels));
            v.insert("originals".into(), strong.len().to_string());
            v.insert(
                "delay_s".into(),
                fmt_num((delay_us.max(0) as f64 / 1e6).round(), 0),
            );
            v.insert("points".into(), fmt_num(points, 1));
            v.insert("breakdown".into(), breakdown(&pts));
            let mut explanation = render_template(&rule.def.explanation, &v);
            push_notes(&mut explanation, &notes);
            let orig_n = orig.frames.len().min(ORIGINAL_EV);
            let mut frames: Vec<FrameNo> =
                w.frames[..w.frames.len().min(EVIDENCE_CAP - orig_n)].to_vec();
            frames.extend_from_slice(&orig.frames[..orig_n]);
            out.push(Hit {
                entity: Entity::Device(w.bssid.clone()),
                rule_idx,
                detector_family: "wifi",
                title: render_template(&rule.def.title, &v),
                tiebreak: ssid.clone(),
                ts_first: w.first_ts,
                ts_last: w.last_ts,
                reason: Reason {
                    rule_id: rule.def.id.clone(),
                    signal: "security_mismatch".into(),
                    value: w.total as f64,
                    unit: Some("count".into()),
                    weight: round1(points),
                    explanation,
                    attack_technique: rule.def.attack_technique.clone(),
                    evidence: evidence(frames, w.total + orig_n as u64),
                },
            });
        }
    }
}

// ----------------------------------------------------------------- karma --

#[derive(Debug)]
struct KResp {
    frame_no: FrameNo,
    /// (µs since the client's probe for this SSID, that probe's frame).
    echo: Option<(i64, FrameNo)>,
}

#[derive(Debug, Default)]
struct KBss {
    resp: BTreeMap<String, KResp>,
    resp_over: bool,
    resp_frames: u64,
    open_resp: u64,
    beacons: BTreeMap<String, FrameNo>,
    first_ts: Option<Ts>,
    last_ts: Ts,
}

#[derive(Debug, Default)]
struct KarmaCol {
    bss: HashMap<String, KBss>,
    /// hash(client, SSID) → (ts, frame) of the client's last probe for it.
    probes: HashMap<u64, (Ts, FrameNo)>,
    max_echo_us: i64,
    dropped: u64,
    /// Earliest ts of the next probe-map sweep.
    prune_after: Ts,
}

impl KarmaCol {
    fn entry(&mut self, bssid: &str) -> Option<&mut KBss> {
        if !self.bss.contains_key(bssid) {
            if self.bss.len() >= MAX_KARMA_BSS {
                self.dropped += 1;
                return None;
            }
            self.bss.insert(bssid.to_string(), KBss::default());
        }
        self.bss.get_mut(bssid)
    }

    fn observe_probe(&mut self, row: &WifiRow, client: &str, ssid: &str) {
        let key = hash64(&(client, ssid));
        if self.probes.len() >= MAX_PROBES && !self.probes.contains_key(&key) {
            // At most one sweep per echo window: when every entry is still
            // fresh a sweep frees nothing, and repeating it per probe would
            // be O(MAX_PROBES) per row (CPU DoS). Until the next sweep is
            // due, new probes are dropped and counted.
            if row.ts >= self.prune_after {
                let horizon = row.ts.saturating_sub(self.max_echo_us);
                self.probes.retain(|_, (ts, _)| *ts >= horizon);
                self.prune_after = row.ts.saturating_add(self.max_echo_us.max(1_000_000));
            }
            if self.probes.len() >= MAX_PROBES {
                self.dropped += 1;
                return;
            }
        }
        self.probes.insert(key, (row.ts, row.frame_no));
    }

    fn observe_resp(&mut self, row: &WifiRow, bssid: &str, client: Option<&str>, ssid: &str) {
        let echo = client
            .and_then(|c| self.probes.get(&hash64(&(c, ssid))))
            .map(|(pts, f)| (row.ts.saturating_sub(*pts), *f))
            .filter(|(d, _)| *d >= 0);
        let Some(b) = self.entry(bssid) else {
            return;
        };
        b.resp_frames += 1;
        if matches!(row.security.as_deref(), Some("open" | "owe")) {
            b.open_resp += 1;
        }
        if b.first_ts.is_none() {
            b.first_ts = Some(row.ts);
        }
        b.last_ts = row.ts;
        if !b.resp.contains_key(ssid) {
            if b.resp.len() < MAX_RESP_SSIDS {
                b.resp.insert(
                    ssid.to_string(),
                    KResp {
                        frame_no: row.frame_no,
                        echo,
                    },
                );
            } else {
                b.resp_over = true;
            }
        }
    }

    fn observe_beacon(&mut self, row: &WifiRow, bssid: &str, ssid: &str) {
        let Some(b) = self.entry(bssid) else {
            return;
        };
        if !b.beacons.contains_key(ssid) && b.beacons.len() < MAX_BEACON_SSIDS {
            b.beacons.insert(ssid.to_string(), row.frame_no);
        }
    }
}

fn analyze_karma(col: &KarmaCol, rule: &Rule, rule_idx: usize, out: &mut Vec<Hit>) {
    let min_ssids = rule.num("min_ssids");
    let echo_us = (rule.num("echo_window_s") * 1e6) as i64;
    let mut group_beacons: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for (bssid, b) in &col.bss {
        let g = group_beacons.entry(sibling_group(bssid)).or_default();
        g.extend(b.beacons.keys().map(String::as_str));
    }
    for (bssid, b) in &col.bss {
        let beaconed = group_beacons.get(sibling_group(bssid));
        let counted: Vec<(&str, &KResp)> = b
            .resp
            .iter()
            .filter(|(s, _)| !beaconed.is_some_and(|g| g.contains(s.as_str())))
            .map(|(s, r)| (s.as_str(), r))
            .collect();
        // Loud mode: one BSSID beaconing many SSIDs (legitimate multi-SSID
        // APs use one BSSID per SSID).
        // Own beacons are group-beaconed, so they never overlap `counted`.
        let loud: Vec<(&str, FrameNo)> = if b.beacons.len() as f64 >= min_ssids {
            b.beacons.iter().map(|(s, f)| (s.as_str(), *f)).collect()
        } else {
            Vec::new()
        };
        let n = counted.len() + loud.len();
        if (n as f64) < min_ssids || n == 0 {
            continue;
        }
        let echoed: Vec<&(&str, &KResp)> = counted
            .iter()
            .filter(|(_, r)| r.echo.is_some_and(|(d, _)| d <= echo_us))
            .collect();
        let s_ssids = 0.5 + 0.5 * ramp(n as f64, min_ssids, rule.num("ssids_full"));
        let s_echo = echoed.len() as f64 / n as f64;
        let s_open = if b.resp_frames > 0 {
            b.open_resp as f64 / b.resp_frames as f64
        } else {
            0.0
        };
        let s_rand = if randomized(bssid) { 1.0 } else { 0.0 };
        let pts = [
            ("ssids", rule.weight("ssids") * s_ssids),
            ("echo", rule.weight("echo") * s_echo),
            ("open", rule.weight("open") * s_open),
            ("randomized", rule.weight("randomized") * s_rand),
        ];
        let points: f64 = pts.iter().map(|(_, p)| p).sum();
        if points < rule.def.min_score || points <= 0.0 {
            continue;
        }
        let mut notes = Vec::new();
        if s_rand > 0.0 {
            notes.push(format!("{} is locally administered", display(bssid)));
        }
        if !loud.is_empty() {
            notes.push(format!(
                "it also beacons {} different SSIDs from this one BSSID",
                b.beacons.len()
            ));
        }
        let mut v = BTreeMap::new();
        v.insert("bssid".into(), display(bssid));
        v.insert(
            "ssids".into(),
            if b.resp_over {
                format!("{n}+")
            } else {
                n.to_string()
            },
        );
        v.insert("answered".into(), counted.len().to_string());
        v.insert("echoed".into(), echoed.len().to_string());
        v.insert(
            "echo_window_s".into(),
            fmt_num(rule.num("echo_window_s"), 1),
        );
        v.insert(
            "examples".into(),
            examples(
                counted
                    .iter()
                    .map(|(s, _)| *s)
                    .chain(loud.iter().map(|(s, _)| *s)),
                4,
                true,
            ),
        );
        v.insert("open_pct".into(), fmt_num((s_open * 100.0).round(), 0));
        v.insert("responses".into(), b.resp_frames.to_string());
        v.insert("points".into(), fmt_num(points, 1));
        v.insert("breakdown".into(), breakdown(&pts));
        let mut explanation = render_template(&rule.def.explanation, &v);
        push_notes(&mut explanation, &notes);
        let mut frames = Vec::new();
        for (_, r) in &counted {
            frames.push(r.frame_no);
            if let Some((d, pf)) = r.echo {
                if d <= echo_us {
                    frames.push(pf);
                }
            }
        }
        frames.extend(loud.iter().map(|(_, f)| *f));
        let total = frames.len() as u64;
        let first = b.first_ts.unwrap_or(b.last_ts);
        out.push(Hit {
            entity: Entity::Device(bssid.clone()),
            rule_idx,
            detector_family: "wifi",
            title: render_template(&rule.def.title, &v),
            tiebreak: bssid.clone(),
            ts_first: first,
            ts_last: b.last_ts.max(first),
            reason: Reason {
                rule_id: rule.def.id.clone(),
                signal: "probe_ssids".into(),
                value: n as f64,
                unit: Some("count".into()),
                weight: round1(points),
                explanation,
                attack_technique: rule.def.attack_technique.clone(),
                evidence: evidence(frames, total),
            },
        });
    }
}

/// Keep one hit per device (its strongest) and at most `max_findings` per
/// rule, strongest first. A capture crafted with thousands of attacking MACs
/// must not flood the queue; the top survivor says how many were dropped.
fn cap_hits(mut hits: Vec<Hit>, rule: &Rule, out: &mut Vec<Hit>) {
    hits.sort_by(|a, b| {
        b.reason
            .weight
            .total_cmp(&a.reason.weight)
            .then_with(|| a.entity.cmp(&b.entity))
            .then_with(|| a.tiebreak.cmp(&b.tiebreak))
    });
    let mut seen = BTreeSet::new();
    hits.retain(|h| seen.insert(h.entity.clone()));
    let max = rule.num("max_findings") as usize;
    if hits.len() > max {
        let dropped = hits.len() - max;
        hits.truncate(max);
        if let Some(top) = hits.first_mut() {
            top.reason.explanation.push_str(&format!(
                " ({dropped} weaker {} device(s) not reported: max_findings = {max})",
                rule.def.id
            ));
        }
    }
    out.extend(hits);
}

// ------------------------------------------------------------- collector --

/// Streaming state for the single `for_each_wifi` pass.
#[derive(Debug)]
pub(crate) struct WifiCollector {
    deauth: Vec<DeauthState>,
    want_twin: bool,
    want_karma: bool,
    twin: TwinCol,
    karma: KarmaCol,
    /// BSSID → what it advertised and how loud its own beacons are.
    aps: HashMap<String, ApInfo>,
}

impl WifiCollector {
    pub(crate) fn new(rules: &RuleSet) -> Self {
        let deauth = rules
            .enabled("wifi_deauth")
            .map(|(i, r)| DeauthState::new(r, i))
            .collect();
        let max_echo = rules
            .enabled("wifi_karma")
            .map(|(_, r)| (r.num("echo_window_s") * 1e6) as i64)
            .max()
            .unwrap_or(0);
        Self {
            deauth,
            want_twin: rules.enabled("wifi_evil_twin").next().is_some(),
            want_karma: rules.enabled("wifi_karma").next().is_some(),
            twin: TwinCol::default(),
            karma: KarmaCol {
                max_echo_us: max_echo,
                ..KarmaCol::default()
            },
            aps: HashMap::new(),
        }
    }

    pub(crate) fn observe(&mut self, row: &WifiRow) {
        match row.kind {
            WifiKind::Beacon | WifiKind::ProbeResp => {
                let Some(bssid) = canon(row.bssid.as_deref().or(row.tx.as_deref())) else {
                    return;
                };
                if is_group(&bssid) {
                    return;
                }
                let ssid = visible_ssid(row.ssid.as_deref());
                if !self.aps.contains_key(bssid.as_ref()) && self.aps.len() < MAX_APS {
                    self.aps
                        .insert(bssid.to_string(), ApInfo::new(ssid.unwrap_or("")));
                }
                // The AP's own beacon signal is the reference that tells a
                // genuine AP's deauths from a spoofer somewhere else.
                let own = canon(row.tx.as_deref()).is_none_or(|t| t == bssid);
                if row.kind == WifiKind::Beacon && own {
                    if let (Some(a), Some(sig)) = (self.aps.get_mut(bssid.as_ref()), row.signal_dbm)
                    {
                        a.record(row.ts, sig);
                    }
                }
                let Some(ssid) = ssid else {
                    return;
                };
                if self.want_twin {
                    if let Some(sec) = row
                        .security
                        .as_deref()
                        .and_then(|s| SECURITIES.iter().position(|x| *x == s))
                    {
                        self.twin.observe(row, &bssid, ssid, sec);
                    }
                }
                if self.want_karma {
                    if row.kind == WifiKind::Beacon {
                        self.karma.observe_beacon(row, &bssid, ssid);
                    } else {
                        let client = canon(row.dst.as_deref()).filter(|d| !is_group(d));
                        self.karma
                            .observe_resp(row, &bssid, client.as_deref(), ssid);
                    }
                }
            }
            WifiKind::ProbeReq => {
                if !self.want_karma {
                    return;
                }
                if let (Some(client), Some(ssid)) =
                    (transmitter(row), visible_ssid(row.ssid.as_deref()))
                {
                    self.karma.observe_probe(row, &client, ssid);
                }
            }
            WifiKind::Deauth | WifiKind::Disassoc => {
                if self.deauth.is_empty() {
                    return;
                }
                let Some(tx) = transmitter(row) else {
                    return;
                };
                let dst = canon(row.dst.as_deref());
                let bssid = canon(row.bssid.as_deref()).filter(|b| !is_group(b));
                for st in &mut self.deauth {
                    st.observe_deauth(row, &tx, dst.as_deref(), bssid.as_deref(), &self.aps);
                }
            }
            WifiKind::Eapol => {
                if self.deauth.iter().all(|s| s.burst_keys.is_empty()) {
                    return;
                }
                let addrs = [
                    canon(row.bssid.as_deref()),
                    canon(row.src.as_deref()),
                    canon(row.dst.as_deref()),
                ];
                for st in &mut self.deauth {
                    st.observe_eapol(row, &addrs);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn analyze(&self, rules: &RuleSet, out: &mut Vec<Hit>) {
        for st in &self.deauth {
            if let Some(rule) = rules.rules().get(st.rule_idx) {
                let mut hits = Vec::new();
                analyze_deauth(st, rule, &self.aps, &mut hits);
                cap_hits(hits, rule, out);
            }
        }
        for (idx, rule) in rules.enabled("wifi_evil_twin") {
            let mut hits = Vec::new();
            analyze_twin(&self.twin, rule, idx, &mut hits);
            cap_hits(hits, rule, out);
        }
        for (idx, rule) in rules.enabled("wifi_karma") {
            let mut hits = Vec::new();
            analyze_karma(&self.karma, rule, idx, &mut hits);
            cap_hits(hits, rule, out);
        }
        // Cap counters are kept for debugging; they never change a score.
        let _ = (self.twin.dropped, self.karma.dropped);
        for s in &self.deauth {
            let _ = (s.suppressed, s.dropped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_helpers() {
        assert!(is_canonical("42:00:5e:00:53:9c"));
        assert!(!is_canonical("42:00:5e:00:53:9C"));
        assert_eq!(
            canon(Some("42:00:5e:00:53:9C")).as_deref(),
            Some("42:00:5e:00:53:9c")
        );
        assert_eq!(canon(Some("junk")), None);
        assert!(is_group("ff:ff:ff:ff:ff:ff"));
        assert!(is_group("01:00:5e:00:00:01"));
        assert!(!is_group("42:00:5e:00:53:9c"));
        assert_eq!(oui("e8:00:5e:00:53:88"), "e8:00:5e");
        assert_eq!(
            sibling_group("e8:00:5e:00:53:88"),
            sibling_group("ea:00:5e:00:53:8c")
        );
        assert_ne!(
            sibling_group("e8:00:5e:00:53:88"),
            sibling_group("e8:00:5f:00:53:88")
        );
    }

    #[test]
    fn ssid_quotes_are_escaped() {
        assert_eq!(ssid_text(r#"Free" ch 6 wpa3"#), r#"Free\" ch 6 wpa3"#);
        assert_eq!(ssid_text(r#"a\"#), r#"a\\"#);
        assert_eq!(examples(["x\"y"].into_iter(), 1, true), r#""x\"y""#);
    }

    #[test]
    fn hidden_ssids() {
        assert_eq!(visible_ssid(Some("")), None);
        assert_eq!(visible_ssid(Some("   ")), None);
        assert_eq!(visible_ssid(Some("????????")), None);
        assert_eq!(visible_ssid(Some("\0\0\0")), None);
        assert_eq!(visible_ssid(None), None);
        assert_eq!(visible_ssid(Some("HomeNet")), Some("HomeNet"));
        assert_eq!(visible_ssid(Some(&"x".repeat(100))).map(str::len), Some(32));
    }

    #[test]
    fn sliding_window_ring() {
        let sub = 10_000_000; // 60 s window / 6
        let mut t = DeauthTx::new(0, sub);
        for i in 0..50 {
            assert_eq!(t.bump(i * 1_000_000, sub), (i + 1) as u32);
        }
        // 70 s later the first sub-buckets have aged out.
        let n = t.bump(110_000_000, sub);
        assert!(n < 50, "{n}");
        // Far in the future: only the new frame.
        assert_eq!(t.bump(10_000_000_000, sub), 1);
    }

    #[test]
    fn evidence_sorted_capped() {
        let e = evidence((0..500u64).rev().collect(), 500);
        assert_eq!(e.frame_nos.len(), EVIDENCE_CAP);
        assert_eq!(e.frame_nos[0], 0);
        assert!(e.truncated);
        assert_eq!(e.total, 500);
        assert!(e.flow_ids.is_empty());
        let e = evidence(vec![3, 1, 3], 2);
        assert_eq!(e.frame_nos, vec![1, 3]);
        assert!(!e.truncated);
    }
}
