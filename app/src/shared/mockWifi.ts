// Deterministic 802.11 (monitor-mode, radiotap) sample capture for the
// browser mock (`?mock=wifi`, or opening a path containing "wifi"). Mirrors
// the scenario in CONTRACTS §11.1 (`walleye-gen wifi`), scaled down:
//
//   - 8 access points: a 3-AP mesh sharing "Lakeside-Office" (wpa2), a cafe
//     AP (wpa2), a hidden-SSID AP (wpa3), and three attackers:
//   - deauth flood: d6:5e:00:53:de:ad (randomized) beacons "Lakeside-Office"
//     and sends ~380 deauths (reason 7) in 90 s to broadcast and mesh clients;
//   - evil twin: 02:5e:00:53:e7:01 (randomized) advertises "Corner-Cafe" as an
//     open network on another channel, four minutes in;
//   - karma: 9e:5e:00:53:ca:fe (randomized) answers directed probe requests
//     for every SSID clients ask for.
//   - 30 clients, half randomized: probes, auth/assoc, EAPOL 4-way
//     handshakes, protected data, null frames and a few normal deauths.
//
// All addresses are invented: universally administered ones use the IANA
// documentation block 00:00:5e:00:53:xx (RFC 7042); randomized ones are
// locally administered values, which belong to no vendor.
//
// The AP and client rows are derived from the frame rows with the same rules
// as the index's `wifi_aps` / `wifi_clients` views (CONTRACTS §11.2), so the
// tabs, timeline and device frame lists always agree.
import type { CaptureRow } from "./bindings/CaptureRow";
import type { DecodeNode } from "./bindings/DecodeNode";
import type { Evidence } from "./bindings/Evidence";
import type { Finding } from "./bindings/Finding";
import type { FrameRef } from "./bindings/FrameRef";
import type { FrameRow } from "./bindings/FrameRow";
import type { PacketView } from "./bindings/PacketView";
import type { WifiApRow } from "./bindings/WifiApRow";
import type { WifiClientRow } from "./bindings/WifiClientRow";
import type { WifiKind } from "./bindings/WifiKind";
import type { WifiRow } from "./bindings/WifiRow";
import { isRandomizedMac, quoteSsid } from "./wifi";

export const BROADCAST = "ff:ff:ff:ff:ff:ff";
const EVIDENCE_CAP = 200;
const RADIOTAP_LEN = 15;
const HDR_LEN = 24;

/** Capture start: 2026-03-12 09:00:00 UTC, in µs. */
export const WIFI_T0 = Date.UTC(2026, 2, 12, 9, 0, 0) * 1000;
const SPAN_S = 600;
const S = 1_000_000;

export const ATTACKERS = {
  deauth: "d6:5e:00:53:de:ad",
  twin: "02:5e:00:53:e7:01",
  karma: "9e:5e:00:53:ca:fe",
} as const;


// ---------------------------------------------------------------- generator

/** mulberry32: small, fast, deterministic. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface ApDef {
  bssid: string;
  ssid: string;
  channel: number;
  security: string;
  signal: number;
  start: number;
  end: number;
  every: number;
}

const APS: ApDef[] = [
  { bssid: "00:00:5e:00:53:01", ssid: "Lakeside-Office", channel: 1, security: "wpa2", signal: -48, start: 0, end: SPAN_S, every: 1 },
  { bssid: "00:00:5e:00:53:02", ssid: "Lakeside-Office", channel: 6, security: "wpa2", signal: -55, start: 0, end: SPAN_S, every: 1 },
  { bssid: "00:00:5e:00:53:03", ssid: "Lakeside-Office", channel: 11, security: "wpa2", signal: -61, start: 0, end: SPAN_S, every: 1 },
  { bssid: "00:00:5e:00:53:10", ssid: "Corner-Cafe", channel: 6, security: "wpa2", signal: -58, start: 0, end: SPAN_S, every: 1 },
  { bssid: "00:00:5e:00:53:11", ssid: "", channel: 11, security: "wpa3", signal: -66, start: 0, end: SPAN_S, every: 1 },
  { bssid: ATTACKERS.twin, ssid: "Corner-Cafe", channel: 11, security: "open", signal: -44, start: 240, end: SPAN_S, every: 1 },
  { bssid: ATTACKERS.karma, ssid: "FreeWiFi", channel: 6, security: "open", signal: -50, start: 120, end: SPAN_S, every: 5 },
  { bssid: ATTACKERS.deauth, ssid: "Lakeside-Office", channel: 6, security: "wpa2", signal: -40, start: 340, end: 480, every: 2 },
];

const PROBE_SSIDS = [
  "HomeNet-5G",
  "Airport_Free",
  "Hotel-Lobby",
  "Library-Public",
  "Conference-2026",
  "Gym-Members",
  "Train-WiFi",
  "Apartment-4B",
  "Studio-Guest",
  "Harbor-View",
  "Lakeside-Office",
  "Corner-Cafe",
];

const RAND_PREFIX = ["02", "4a", "9e", "d6", "1e", "6a"];
const hex2 = (n: number) => (n & 0xff).toString(16).padStart(2, "0");

/** Internal frame: the row plus what the byte builder needs. */
export interface WFrame extends WifiRow {
  /** Data frames: ToDS (station → AP) or FromDS (AP → station). */
  dir: "to" | "from" | null;
  bodyLen: number;
  /** EAPOL message number (1..4). */
  eapolMsg: number | null;
}

type Draft = Omit<WFrame, "frame_no" | "seq" | "len" | "freq_mhz"> & { ts: number };

export interface WifiDataset {
  capture: CaptureRow;
  frames: FrameRow[];
  wifi: WifiRow[];
  wifi_aps: WifiApRow[];
  wifi_clients: WifiClientRow[];
  findings: Finding[];
  /** Full frames (row + build info), index = frame_no - 1. */
  wframes: WFrame[];
}

function bodyLength(d: Draft): number {
  switch (d.kind) {
    case "beacon":
    case "probe_resp":
      return 12 + 2 + utf8Len(d.ssid ?? "") + 6 + 3 + (d.security === "wpa2" || d.security === "wpa3" ? 22 : 0);
    case "probe_req":
      return 2 + utf8Len(d.ssid ?? "") + 6;
    case "auth":
      return 6;
    case "assoc_req":
    case "reassoc_req":
      return 4 + 2 + utf8Len(d.ssid ?? "") + 6;
    case "assoc_resp":
    case "reassoc_resp":
      return 6 + 6;
    case "deauth":
    case "disassoc":
      return 2;
    case "eapol":
      return 8 + 99;
    case "null":
      return 0;
    case "data":
      return d.bodyLen;
    default:
      return d.bodyLen;
  }
}

const utf8Len = (s: string) => new TextEncoder().encode(s).length;

function generate(): WifiDataset {
  const r = rng(0x802_11);
  const drafts: Draft[] = [];
  const at = (s: number) => WIFI_T0 + Math.round(s * S);
  const jitter = (spread: number) => (r() - 0.5) * spread;
  const signalOf = new Map<string, number>();
  const chOf = new Map<string, number>(APS.map((a) => [a.bssid, a.channel]));
  const sig = (mac: string) => Math.round((signalOf.get(mac) ?? -70) + jitter(6));
  const base = (
    kind: WifiKind,
    ts: number,
    o: Partial<Draft> & { src: string | null; dst: string | null; tx: string | null; bssid: string | null },
  ): Draft => ({
    ts,
    kind,
    protected: false,
    retry: false,
    channel: null,
    signal_dbm: o.tx ? sig(o.tx) : null,
    ssid: null,
    security: null,
    reason: null,
    dir: null,
    bodyLen: 0,
    eapolMsg: null,
    ...o,
  });
  for (const a of APS) signalOf.set(a.bssid, a.signal);

  // Beacons.
  for (const a of APS) {
    for (let s = a.start + r() * a.every; s < a.end; s += a.every * (1 + jitter(0.004))) {
      drafts.push(
        base("beacon", at(s), {
          src: a.bssid,
          dst: BROADCAST,
          tx: a.bssid,
          bssid: a.bssid,
          channel: a.channel,
          ssid: a.ssid,
          security: a.security,
        }),
      );
    }
  }

  // Clients.
  interface Client {
    mac: string;
    home: ApDef | null;
    probes: string[];
    join: number;
  }
  const clients: Client[] = [];
  for (let i = 0; i < 30; i++) {
    const randomized = i % 2 === 1;
    const mac = randomized
      ? `${RAND_PREFIX[i % RAND_PREFIX.length]}:5e:00:53:${hex2(0x20 + i)}:${hex2(Math.floor(r() * 256))}`
      : `00:00:5e:00:53:${hex2(0x40 + i)}`;
    const home = i < 16 ? APS[i % 3]! : i < 24 ? APS[3]! : i < 28 ? APS[4]! : i === 28 ? APS[5]! : null;
    const n = 1 + Math.floor(r() * 3);
    const probes = [PROBE_SSIDS[i % PROBE_SSIDS.length]!, PROBE_SSIDS[(i * 5 + 3) % PROBE_SSIDS.length]!].slice(0, n);
    if (home?.ssid && !probes.includes(home.ssid)) probes.push(home.ssid);
    signalOf.set(mac, -52 - Math.floor(r() * 28));
    clients.push({ mac, home, probes, join: i === 28 ? 300 : 5 + r() * 100 });
  }

  const associate = (c: Client, s: number, reassoc = false) => {
    const a = c.home!;
    const ch = a.channel;
    const sta = { channel: ch };
    drafts.push(base("auth", at(s), { src: c.mac, dst: a.bssid, tx: c.mac, bssid: a.bssid, ...sta }));
    drafts.push(base("auth", at(s + 0.002), { src: a.bssid, dst: c.mac, tx: a.bssid, bssid: a.bssid, reason: 0, ...sta }));
    drafts.push(
      base(reassoc ? "reassoc_req" : "assoc_req", at(s + 0.004), {
        src: c.mac,
        dst: a.bssid,
        tx: c.mac,
        bssid: a.bssid,
        ssid: a.ssid,
        ...sta,
      }),
    );
    drafts.push(
      base(reassoc ? "reassoc_resp" : "assoc_resp", at(s + 0.006), {
        src: a.bssid,
        dst: c.mac,
        tx: a.bssid,
        bssid: a.bssid,
        reason: 0,
        ...sta,
      }),
    );
    if (a.security !== "open") {
      for (let m = 1; m <= 4; m++) {
        const fromAp = m % 2 === 1;
        drafts.push(
          base("eapol", at(s + 0.01 + m * 0.004), {
            src: fromAp ? a.bssid : c.mac,
            dst: fromAp ? c.mac : a.bssid,
            tx: fromAp ? a.bssid : c.mac,
            bssid: a.bssid,
            dir: fromAp ? "from" : "to",
            eapolMsg: m,
            ...sta,
          }),
        );
      }
    }
  };

  const victims: Client[] = [];
  for (const [i, c] of clients.entries()) {
    // Probe bursts every ~70 s; randomized clients mostly send wildcard probes.
    const ch = c.home?.channel ?? 1;
    for (let s = 1 + r() * 30; s < SPAN_S; s += 50 + r() * 40) {
      const list = i % 2 === 1 && r() < 0.5 ? [""] : c.probes;
      for (const [k, ssid] of list.entries()) {
        const t = s + k * 0.03;
        drafts.push(base("probe_req", at(t), { src: c.mac, dst: BROADCAST, tx: c.mac, bssid: BROADCAST, ssid, channel: ch }));
        // Legitimate APs answer for their own SSID (or a wildcard from their own clients).
        for (const a of APS.slice(0, 5)) {
          if (!a.ssid || (ssid !== a.ssid && !(ssid === "" && c.home === a))) continue;
          drafts.push(
            base("probe_resp", at(t + 0.003), {
              src: a.bssid,
              dst: c.mac,
              tx: a.bssid,
              bssid: a.bssid,
              ssid: a.ssid,
              security: a.security,
              channel: a.channel,
            }),
          );
        }
        // Karma: answers every directed probe with the SSID that was asked for.
        if (ssid && t >= 120) {
          drafts.push(
            base("probe_resp", at(t + 0.002), {
              src: ATTACKERS.karma,
              dst: c.mac,
              tx: ATTACKERS.karma,
              bssid: ATTACKERS.karma,
              ssid,
              security: "open",
              channel: 6,
            }),
          );
        }
      }
    }
    if (!c.home) continue;
    associate(c, c.join);
    if (i < 16) victims.push(c);
    const a = c.home;
    const protectedData = a.security !== "open";
    // Data both ways and power-save null frames.
    for (let s = c.join + 1 + r() * 3; s < SPAN_S; s += 3 + r() * 6) {
      if (i < 16 && s > 350 && s < 445) continue; // knocked off by the flood
      const up = r() < 0.45;
      if (protectedData) {
        drafts.push(
          base("data", at(s), {
            src: up ? c.mac : a.bssid,
            dst: up ? a.bssid : c.mac,
            tx: up ? c.mac : a.bssid,
            bssid: a.bssid,
            protected: true,
            retry: r() < 0.04,
            dir: up ? "to" : "from",
            bodyLen: 16 + 60 + Math.floor(r() * 1300),
            channel: a.channel,
          }),
        );
      }
      if (r() < 0.25 || !protectedData)
        drafts.push(base("null", at(s + 0.5), { src: c.mac, dst: a.bssid, tx: c.mac, bssid: a.bssid, dir: "to", channel: a.channel }));
    }
    // A few ordinary goodbyes (reason 3 = leaving), sent by the station about itself.
    if (i % 7 === 3) {
      const s = 520 + r() * 60;
      drafts.push(base("deauth", at(s), { src: c.mac, dst: a.bssid, tx: c.mac, bssid: a.bssid, reason: 3, channel: a.channel }));
    }
  }

  // Deauth flood: 90 s, ~4 frames/s, alternating broadcast and mesh clients.
  const D = ATTACKERS.deauth;
  for (let k = 0, s = 350; s < 440; k++, s += 0.237 + jitter(0.04)) {
    const victim = k % 2 === 0 ? null : victims[(k >> 1) % victims.length]!;
    drafts.push(
      base("deauth", at(s), {
        src: D,
        dst: victim ? victim.mac : BROADCAST,
        tx: D,
        bssid: D,
        reason: 7,
        channel: 6,
      }),
    );
  }
  // Victims re-associate (and re-handshake) right after the flood.
  for (const [k, v] of victims.entries()) associate(v, 445 + k * 1.3, true);

  // Order, number, sequence.
  drafts.sort((a, b) => a.ts - b.ts);
  const seqOf = new Map<string, number>();
  const wframes: WFrame[] = drafts.map((d, i) => {
    const tx = d.tx ?? "";
    const seq = ((seqOf.get(tx) ?? Math.floor(r() * 4096)) + 1) & 0xfff;
    seqOf.set(tx, seq);
    const len = HDR_LEN + bodyLength(d);
    const channel = d.channel ?? (d.bssid ? (chOf.get(d.bssid) ?? null) : null);
    return { ...d, frame_no: i + 1, seq, len, channel, freq_mhz: channel ? 2407 + 5 * channel : null };
  });

  const wifi: WifiRow[] = wframes.map((f) => ({
    ts: f.ts,
    frame_no: f.frame_no,
    kind: f.kind,
    protected: f.protected,
    retry: f.retry,
    src: f.src,
    dst: f.dst,
    tx: f.tx,
    bssid: f.bssid,
    channel: f.channel,
    freq_mhz: f.freq_mhz,
    signal_dbm: f.signal_dbm,
    ssid: f.ssid,
    security: f.security,
    reason: f.reason,
    seq: f.seq,
    len: f.len,
  }));

  let offset = 24;
  const frames: FrameRow[] = wframes.map((f) => {
    const caplen = RADIOTAP_LEN + f.len;
    const row: FrameRow = {
      frame_no: f.frame_no,
      ts: f.ts,
      file_offset: offset,
      caplen,
      wirelen: caplen,
      flow_id: null,
      direction: null,
      tcp_flags: null,
      payload_len: f.len - HDR_LEN,
      link_type: 127,
    };
    offset += 16 + caplen;
    return row;
  });

  const wifi_aps = deriveAps(wifi);
  const wifi_clients = deriveClients(wifi, new Set(wifi_aps.map((a) => a.bssid)));
  const last = wifi[wifi.length - 1]!.ts;
  const capture: CaptureRow = {
    capture_id: "c0ffee80211a0b1c",
    path: "/mock/lakeside-wifi.pcap",
    sha256: "c0ffee80211a0b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c",
    size_bytes: offset,
    format: "pcap",
    first_ts: wifi[0]!.ts,
    last_ts: last,
    link_type: 127,
    frame_count: wifi.length,
  };
  return { capture, frames, wifi, wifi_aps, wifi_clients, findings: findingsFor(wifi), wframes };
}

// ------------------------------------------------- views (CONTRACTS §11.2)

function mostFrequent<T>(xs: T[]): T | null {
  const m = new Map<T, number>();
  let best: T | null = null;
  let bn = 0;
  for (const x of xs) {
    const n = (m.get(x) ?? 0) + 1;
    m.set(x, n);
    if (n > bn) {
      bn = n;
      best = x;
    }
  }
  return best;
}

const isUnicast = (mac: string | null): mac is string => !!mac && (parseInt(mac.slice(0, 2), 16) & 1) === 0;

export function deriveAps(rows: WifiRow[]): WifiApRow[] {
  const adv = new Map<string, WifiRow[]>();
  for (const w of rows) {
    if ((w.kind === "beacon" || w.kind === "probe_resp") && w.bssid) {
      let l = adv.get(w.bssid);
      if (!l) adv.set(w.bssid, (l = []));
      l.push(w);
    }
  }
  const out: WifiApRow[] = [];
  for (const [bssid, own] of adv) {
    const all = rows.filter((w) => w.bssid === bssid);
    const clients = new Set<string>();
    for (const w of all) {
      if (w.kind !== "data" && w.kind !== "null" && w.kind !== "eapol") continue;
      for (const m of [w.src, w.dst]) if (isUnicast(m) && m !== bssid) clients.add(m);
    }
    const sigs = all.filter((w) => w.tx === bssid && w.signal_dbm !== null).map((w) => w.signal_dbm!);
    out.push({
      bssid,
      ssid: mostFrequent(own.map((w) => w.ssid).filter((s): s is string => !!s)),
      channel: mostFrequent(own.map((w) => w.channel)),
      security: mostFrequent(own.map((w) => w.security)),
      first_ts: all[0]!.ts,
      last_ts: all[all.length - 1]!.ts,
      beacons: own.filter((w) => w.kind === "beacon").length,
      frames: all.length,
      clients: clients.size,
      signal_max: sigs.length ? Math.max(...sigs) : null,
      randomized: isRandomizedMac(bssid),
      first_frame: all[0]!.frame_no,
    });
  }
  return out.sort((a, b) => b.beacons - a.beacons || (a.bssid < b.bssid ? -1 : 1));
}

const STA_KINDS: ReadonlySet<WifiKind> = new Set(["data", "null", "eapol", "auth", "assoc_req", "reassoc_req"]);

export function deriveClients(rows: WifiRow[], apSet: ReadonlySet<string>): WifiClientRow[] {
  interface Acc {
    probed: Set<string>;
    bssids: Set<string>;
  }
  const acc = new Map<string, Acc>();
  const touch = (mac: string) => {
    let a = acc.get(mac);
    if (!a) acc.set(mac, (a = { probed: new Set(), bssids: new Set() }));
    return a;
  };
  for (const w of rows) {
    if (w.kind === "probe_req" && isUnicast(w.src) && !apSet.has(w.src)) {
      const a = touch(w.src);
      if (w.ssid) a.probed.add(w.ssid);
    } else if (STA_KINDS.has(w.kind)) {
      for (const m of [w.src, w.dst]) {
        if (!isUnicast(m) || m === w.bssid || apSet.has(m)) continue;
        const a = touch(m);
        if (w.bssid && isUnicast(w.bssid)) a.bssids.add(w.bssid);
      }
    }
  }
  const out: WifiClientRow[] = [];
  for (const [mac, a] of acc) {
    const own = rows.filter((w) => w.tx === mac);
    const seen = rows.filter((w) => w.src === mac || w.dst === mac || w.tx === mac);
    const sigs = own.filter((w) => w.signal_dbm !== null).map((w) => w.signal_dbm!);
    out.push({
      mac,
      randomized: isRandomizedMac(mac),
      first_ts: seen[0]!.ts,
      last_ts: seen[seen.length - 1]!.ts,
      frames: own.length,
      probed_ssids: [...a.probed].sort(),
      bssids: [...a.bssids].sort(),
      signal_max: sigs.length ? Math.max(...sigs) : null,
      first_frame: seen[0]!.frame_no,
    });
  }
  return out.sort((a, b) => b.frames - a.frames || (a.mac < b.mac ? -1 : 1));
}

// ------------------------------------------------------------- findings

function ev(frames: number[]): Evidence {
  return { flow_ids: [], frame_nos: frames.slice(0, EVIDENCE_CAP), truncated: frames.length > EVIDENCE_CAP, total: frames.length };
}

function findingsFor(rows: WifiRow[]): Finding[] {
  const D = ATTACKERS.deauth;
  const deauths = rows.filter((w) => w.tx === D && (w.kind === "deauth" || w.kind === "disassoc"));
  const bcast = deauths.filter((w) => w.dst === BROADCAST).length;
  const targets = new Set(deauths.filter((w) => w.dst !== BROADCAST).map((w) => w.dst));
  const lastDeauth = deauths[deauths.length - 1]!;
  const handshakes = rows.filter((w) => w.kind === "eapol" && w.ts > lastDeauth.ts && w.ts < lastDeauth.ts + 60 * S);
  const durS = (lastDeauth.ts - deauths[0]!.ts) / S;

  const twinBeacons = rows.filter((w) => w.tx === ATTACKERS.twin && w.kind === "beacon");
  const origBeacons = rows.filter((w) => w.bssid === "00:00:5e:00:53:10" && w.kind === "beacon");
  const karmaResp = rows.filter((w) => w.tx === ATTACKERS.karma && w.kind === "probe_resp");
  const karmaSsids = new Set(karmaResp.map((w) => w.ssid));

  const id = (s: string) => {
    let h = 0x811c9dc5;
    for (const c of s) h = Math.imul(h ^ c.charCodeAt(0), 0x01000193) >>> 0;
    return h.toString(16).padStart(8, "0") + "0000wifi";
  };
  return [
    {
      finding_id: id(`wifi_deauth|device|${D}`),
      title: "Deauthentication flood",
      detector: "wifi_deauth",
      entity_type: "device",
      entity: D,
      score: 95,
      attack_technique: "T1498",
      ts_first: deauths[0]!.ts,
      ts_last: lastDeauth.ts,
      verdict: null,
      reasons: [
        {
          rule_id: "wifi.deauth_flood",
          signal: "deauth_rate",
          value: deauths.length,
          unit: "count",
          weight: 48,
          explanation: `${D} sent ${deauths.length} deauthentication frames in ${durS.toFixed(0)} s (reason 7)`,
          attack_technique: "T1498",
          evidence: ev(deauths.map((w) => w.frame_no)),
        },
        {
          rule_id: "wifi.deauth_flood",
          signal: "broadcast_share",
          value: Math.round((bcast / deauths.length) * 1000) / 10,
          unit: "pct",
          weight: 14,
          explanation: `${bcast} of them were sent to the broadcast address, ${targets.size} clients were targeted directly`,
          attack_technique: "T1498",
          evidence: ev(deauths.filter((w) => w.dst === BROADCAST).map((w) => w.frame_no)),
        },
        {
          rule_id: "wifi.deauth_flood",
          signal: "randomized_bssid",
          value: 1,
          unit: "bool",
          weight: 18,
          explanation: `The transmitter claims BSSID ${D}, a locally administered (randomized) address, while advertising "Lakeside-Office"`,
          attack_technique: "T1498",
          evidence: ev(rows.filter((w) => w.tx === D && w.kind === "beacon").map((w) => w.frame_no)),
        },
        {
          rule_id: "wifi.deauth_flood",
          signal: "handshakes_after",
          value: handshakes.length / 4,
          unit: "count",
          weight: 15,
          explanation: `${handshakes.length / 4} EAPOL handshakes followed within 60 s (capture-the-handshake pattern)`,
          attack_technique: "T1498",
          evidence: ev(handshakes.map((w) => w.frame_no)),
        },
      ],
    },
    {
      finding_id: id(`wifi_evil_twin|device|${ATTACKERS.twin}`),
      title: 'Evil twin of "Corner-Cafe"',
      detector: "wifi_evil_twin",
      entity_type: "device",
      entity: ATTACKERS.twin,
      score: 84,
      attack_technique: "T1557",
      ts_first: twinBeacons[0]!.ts,
      ts_last: twinBeacons[twinBeacons.length - 1]!.ts,
      verdict: null,
      reasons: [
        {
          rule_id: "wifi.evil_twin",
          signal: "security_downgrade",
          value: 1,
          unit: "bool",
          weight: 52,
          explanation: `SSID "Corner-Cafe" is advertised as wpa2 by 00:00:5e:00:53:10 (ch 6) and as open by ${ATTACKERS.twin} (ch 11)`,
          attack_technique: "T1557",
          evidence: ev([...twinBeacons.slice(0, 100), ...origBeacons.slice(0, 100)].map((w) => w.frame_no).sort((a, b) => a - b)),
        },
        {
          rule_id: "wifi.evil_twin",
          signal: "randomized_bssid",
          value: 1,
          unit: "bool",
          weight: 20,
          explanation: `The open copy uses a locally administered (randomized) BSSID and appeared ${Math.round((twinBeacons[0]!.ts - origBeacons[0]!.ts) / S)} s after the original`,
          attack_technique: "T1557",
          evidence: ev(twinBeacons.map((w) => w.frame_no)),
        },
      ],
    },
    {
      finding_id: id(`wifi_karma|device|${ATTACKERS.karma}`),
      title: "Karma access point",
      detector: "wifi_karma",
      entity_type: "device",
      entity: ATTACKERS.karma,
      score: 77,
      attack_technique: "T1557",
      ts_first: karmaResp[0]!.ts,
      ts_last: karmaResp[karmaResp.length - 1]!.ts,
      verdict: null,
      reasons: [
        {
          rule_id: "wifi.karma",
          signal: "distinct_ssids",
          value: karmaSsids.size,
          unit: "count",
          weight: 50,
          explanation: `${ATTACKERS.karma} answered probe requests for ${karmaSsids.size} different SSIDs, including ${[...karmaSsids].slice(0, 3).map((x) => qs(x ?? "")).join(", ")}`,
          attack_technique: "T1557",
          evidence: ev(karmaResp.map((w) => w.frame_no)),
        },
      ],
    },
  ];
}

// ------------------------------------------------------- frame summaries

/** Quote an SSID for a summary, escaping `\` and `"` so it cannot close the quotes early. */
const qs = quoteSsid;
const q = (s: string | null) => (s ? qs(s) : "(hidden)");

export function wifiSummary(f: WifiRow): string {
  const a = `${f.src ?? "?"} → ${f.dst ?? "?"}`;
  switch (f.kind) {
    case "beacon":
      return `Beacon ${q(f.ssid)} ch ${f.channel ?? "?"} ${f.security ?? ""}`.trim();
    case "probe_req":
      return `Probe request ${f.ssid ? qs(f.ssid) : "(wildcard)"} from ${f.src ?? "?"}`;
    case "probe_resp":
      return `Probe response ${q(f.ssid)} ${a}`;
    case "auth":
      return `Auth ${a}${f.reason !== null ? ` status ${f.reason}` : ""}`;
    case "deauth":
      return `Deauth ${a} reason ${f.reason ?? "?"}`;
    case "disassoc":
      return `Disassoc ${a} reason ${f.reason ?? "?"}`;
    case "assoc_req":
    case "reassoc_req":
      return `${f.kind === "assoc_req" ? "Assoc" : "Reassoc"} request ${a} ${q(f.ssid)}`;
    case "assoc_resp":
    case "reassoc_resp":
      return `${f.kind === "assoc_resp" ? "Assoc" : "Reassoc"} response ${a} status ${f.reason ?? "?"}`;
    case "eapol":
      return `EAPOL key ${a}`;
    case "null":
      return `Null data ${a}`;
    case "data":
      return `Data ${a}${f.protected ? " (protected)" : ""} len=${f.len}`;
    default:
      return `${f.kind} ${a}`;
  }
}

export function toFrameRef(f: WifiRow): FrameRef {
  const caplen = RADIOTAP_LEN + f.len;
  return {
    frame_no: f.frame_no,
    ts: f.ts,
    caplen,
    wirelen: caplen,
    direction: null,
    tcp_flags: null,
    payload_len: f.len - HDR_LEN,
    summary: wifiSummary(f),
  };
}

// --------------------------------------------------- bytes + decode tree

const KIND_TS: Record<WifiKind, [number, number, string]> = {
  assoc_req: [0, 0, "Association Request"],
  assoc_resp: [0, 1, "Association Response"],
  reassoc_req: [0, 2, "Reassociation Request"],
  reassoc_resp: [0, 3, "Reassociation Response"],
  probe_req: [0, 4, "Probe Request"],
  probe_resp: [0, 5, "Probe Response"],
  beacon: [0, 8, "Beacon frame"],
  disassoc: [0, 10, "Disassociation"],
  auth: [0, 11, "Authentication"],
  deauth: [0, 12, "Deauthentication"],
  action: [0, 13, "Action"],
  mgmt_other: [0, 15, "Management"],
  data: [2, 0, "Data"],
  null: [2, 4, "Null function (No data)"],
  eapol: [2, 0, "Data"],
};

const REASONS: Record<number, string> = {
  1: "Unspecified reason",
  3: "Deauthenticated because sending station is leaving",
  7: "Class 3 frame received from nonassociated station",
  8: "Disassociated because sending station is leaving BSS",
};

class Bytes {
  b: number[] = [];
  get off() {
    return this.b.length;
  }
  u8(...v: number[]) {
    this.b.push(...v.map((x) => x & 0xff));
  }
  u16le(v: number) {
    this.u8(v, v >> 8);
  }
  u16be(v: number) {
    this.u8(v >> 8, v);
  }
  mac(m: string | null) {
    this.u8(...(m ?? "00:00:00:00:00:00").split(":").map((h) => parseInt(h, 16)));
  }
  str(s: string) {
    this.u8(...new TextEncoder().encode(s));
  }
}

const leaf = (label: string, value: string | null, start: number, len: number, field: string | null = null): DecodeNode => ({
  label: value === null ? label : `${label}: ${value}`,
  field,
  value,
  range: { start, len },
  warning: null,
  children: [],
});
const group = (label: string, start: number, len: number, children: DecodeNode[], field: string | null = null): DecodeNode => ({
  label,
  field,
  value: null,
  range: { start, len },
  warning: null,
  children,
});

/** Addresses in header order for a frame's ToDS/FromDS (802.11-2020 Table 9-30). */
function headerAddrs(f: WFrame): { a: [string | null, string | null, string | null]; labels: [string, string, string]; fields: [string, string, string]; flags: number } {
  if (f.dir === "to")
    return { a: [f.bssid, f.src, f.dst], labels: ["Receiver address (BSSID)", "Transmitter address (SA)", "Destination address"], fields: ["wifi.bssid", "wifi.src", "wifi.dst"], flags: 0x01 };
  if (f.dir === "from")
    return { a: [f.dst, f.bssid, f.src], labels: ["Destination address", "Transmitter address (BSSID)", "Source address"], fields: ["wifi.dst", "wifi.bssid", "wifi.src"], flags: 0x02 };
  return { a: [f.dst, f.src, f.bssid], labels: ["Destination address", "Source address", "BSSID"], fields: ["wifi.dst", "wifi.src", "wifi.bssid"], flags: 0 };
}

export function buildPacket(f: WFrame): PacketView {
  const r = rng(f.frame_no * 2654435761);
  const w = new Bytes();
  const tree: DecodeNode[] = [];

  // Radiotap: version, pad, length, present (Flags | Channel | Antenna signal).
  w.u8(0, 0);
  w.u16le(RADIOTAP_LEN);
  w.u8(0x2a, 0, 0, 0);
  w.u8(0); // flags
  w.u8(0); // alignment pad for Channel
  const freq = f.freq_mhz ?? 2412;
  w.u16le(freq);
  w.u16le(0x00a0); // 2 GHz, CCK
  w.u8(f.signal_dbm ?? -90);
  tree.push(
    group("Radiotap header", 0, RADIOTAP_LEN, [
      leaf("Header revision", "0", 0, 1),
      leaf("Header length", String(RADIOTAP_LEN), 2, 2),
      leaf("Present flags", "0x0000002a (Flags, Channel, Antenna signal)", 4, 4),
      leaf("Flags", "0x00", 8, 1),
      leaf("Channel frequency", `${freq} MHz${f.channel ? ` [channel ${f.channel}]` : ""}`, 10, 2, "wifi.freq"),
      leaf("Channel flags", "0x00a0, 2 GHz, CCK", 12, 2),
      leaf("Antenna signal", `${f.signal_dbm ?? "?"} dBm`, 14, 1, "wifi.signal"),
    ]),
  );

  // 802.11 header.
  const h0 = w.off;
  const [type, subtype, name] = KIND_TS[f.kind];
  const ad = headerAddrs(f);
  const flags = ad.flags | (f.retry ? 0x08 : 0) | (f.protected ? 0x40 : 0);
  w.u8((subtype << 4) | (type << 2), flags);
  w.u16le(f.kind === "beacon" || f.dst === BROADCAST ? 0 : 314);
  w.mac(ad.a[0]);
  w.mac(ad.a[1]);
  w.mac(ad.a[2]);
  w.u16le((f.seq ?? 0) << 4);
  const flagNames = [
    flags & 0x01 && "To DS",
    flags & 0x02 && "From DS",
    flags & 0x08 && "Retry",
    flags & 0x40 && "Protected",
  ].filter(Boolean);
  const hdr = group(`IEEE 802.11 ${name}`, h0, HDR_LEN, [
    group("Frame Control", h0, 2, [
      leaf("Type/Subtype", `${name} (0x${((type << 4) | subtype).toString(16).padStart(4, "0")})`, h0, 1, "wifi.kind"),
      leaf("Flags", `0x${flags.toString(16).padStart(2, "0")}${flagNames.length ? ` (${flagNames.join(", ")})` : ""}`, h0 + 1, 1),
    ]),
    leaf("Duration", `${f.kind === "beacon" || f.dst === BROADCAST ? 0 : 314} µs`, h0 + 2, 2),
    leaf(ad.labels[0], ad.a[0] ?? "?", h0 + 4, 6, ad.fields[0]),
    leaf(ad.labels[1], ad.a[1] ?? "?", h0 + 10, 6, ad.fields[1]),
    leaf(ad.labels[2], ad.a[2] ?? "?", h0 + 16, 6, ad.fields[2]),
    leaf("Sequence number", String(f.seq ?? 0), h0 + 22, 2),
  ]);
  if (f.tx) hdr.children.splice(5, 0, { ...leaf("Transmitter (TA)", f.tx, h0 + 10, 6, "wifi.tx") });
  tree.push(hdr);

  // Body.
  const b0 = w.off;
  const tags: DecodeNode[] = [];
  const tag = (id: number, label: string, value: string, write: () => void) => {
    const s = w.off;
    w.u8(id, 0);
    write();
    w.b[s + 1] = w.off - s - 2;
    tags.push(leaf(`Tag: ${label}`, value, s, w.off - s, id === 0 ? "wifi.ssid" : id === 3 ? "wifi.channel" : null));
  };
  const ssidTag = () => tag(0, "SSID parameter set", f.ssid ? f.ssid : "(wildcard or hidden)", () => w.str(f.ssid ?? ""));
  const ratesTag = () => tag(1, "Supported Rates", "1, 2, 5.5, 11 Mbit/s", () => w.u8(0x82, 0x84, 0x8b, 0x96));
  switch (f.kind) {
    case "beacon":
    case "probe_resp": {
      const fixed0 = w.off;
      for (let i = 0; i < 8; i++) w.u8(Math.floor(r() * 256));
      w.u16le(100);
      const cap = 0x0401 | (f.security && f.security !== "open" ? 0x0010 : 0);
      w.u16le(cap);
      ssidTag();
      ratesTag();
      tag(3, "DS Parameter set", `Current Channel: ${f.channel ?? "?"}`, () => w.u8(f.channel ?? 0));
      if (f.security === "wpa2" || f.security === "wpa3") {
        const akm = f.security === "wpa3" ? 8 : 2;
        tag(48, "RSN Information", `CCMP, AKM ${akm === 8 ? "SAE" : "PSK"}`, () => {
          w.u16le(1);
          w.u8(0x00, 0x0f, 0xac, 4);
          w.u16le(1);
          w.u8(0x00, 0x0f, 0xac, 4);
          w.u16le(1);
          w.u8(0x00, 0x0f, 0xac, akm);
          w.u16le(f.security === "wpa3" ? 0x00c0 : 0x0000);
        });
      }
      tree.push(
        group("IEEE 802.11 Wireless Management", b0, w.off - b0, [
          group("Fixed parameters (12 bytes)", fixed0, 12, [
            leaf("Timestamp", "(TSF)", fixed0, 8),
            leaf("Beacon Interval", "0.102400 s", fixed0 + 8, 2),
            leaf("Capabilities Information", `0x${cap.toString(16).padStart(4, "0")}${cap & 0x10 ? " (Privacy)" : ""}`, fixed0 + 10, 2),
          ]),
          group(`Tagged parameters (${w.off - b0 - 12} bytes)`, b0 + 12, w.off - b0 - 12, tags),
          { ...leaf("Security (derived)", f.security ?? "?", b0, 0, "wifi.security"), range: null },
        ]),
      );
      break;
    }
    case "probe_req":
    case "assoc_req":
    case "reassoc_req": {
      const fixed: DecodeNode[] = [];
      if (f.kind !== "probe_req") {
        w.u16le(0x0411);
        w.u16le(10);
        fixed.push(group("Fixed parameters (4 bytes)", b0, 4, [leaf("Capabilities Information", "0x0411", b0, 2), leaf("Listen Interval", "10", b0 + 2, 2)]));
      }
      const t0 = w.off;
      ssidTag();
      ratesTag();
      tree.push(group("IEEE 802.11 Wireless Management", b0, w.off - b0, [...fixed, group(`Tagged parameters (${w.off - t0} bytes)`, t0, w.off - t0, tags)]));
      break;
    }
    case "auth":
      w.u16le(0);
      w.u16le(f.src === f.bssid ? 2 : 1);
      w.u16le(f.reason ?? 0);
      tree.push(
        group("IEEE 802.11 Wireless Management", b0, 6, [
          group("Fixed parameters (6 bytes)", b0, 6, [
            leaf("Authentication Algorithm", "Open System (0)", b0, 2),
            leaf("Authentication SEQ", String(f.src === f.bssid ? 2 : 1), b0 + 2, 2),
            leaf("Status code", `${f.reason ?? 0} (Successful)`, b0 + 4, 2, "wifi.reason"),
          ]),
        ]),
      );
      break;
    case "assoc_resp":
    case "reassoc_resp": {
      w.u16le(0x0411);
      w.u16le(f.reason ?? 0);
      w.u16le(0xc000 | (1 + (f.frame_no % 200)));
      const t0 = w.off;
      ratesTag();
      tree.push(
        group("IEEE 802.11 Wireless Management", b0, w.off - b0, [
          group("Fixed parameters (6 bytes)", b0, 6, [
            leaf("Capabilities Information", "0x0411", b0, 2),
            leaf("Status code", `${f.reason ?? 0} (Successful)`, b0 + 2, 2, "wifi.reason"),
            leaf("Association ID", String(1 + (f.frame_no % 200)), b0 + 4, 2),
          ]),
          group(`Tagged parameters (${w.off - t0} bytes)`, t0, w.off - t0, tags),
        ]),
      );
      break;
    }
    case "deauth":
    case "disassoc":
      w.u16le(f.reason ?? 1);
      tree.push(
        group("IEEE 802.11 Wireless Management", b0, 2, [
          group("Fixed parameters (2 bytes)", b0, 2, [
            leaf("Reason code", `${REASONS[f.reason ?? 1] ?? "Reserved"} (0x${(f.reason ?? 1).toString(16).padStart(4, "0")})`, b0, 2, "wifi.reason"),
          ]),
        ]),
      );
      break;
    case "eapol": {
      w.u8(0xaa, 0xaa, 0x03, 0, 0, 0);
      w.u16be(0x888e);
      tree.push(
        group("Logical-Link Control", b0, 8, [
          leaf("DSAP", "SNAP (0xaa)", b0, 1),
          leaf("SSAP", "SNAP (0xaa)", b0 + 1, 1),
          leaf("Control field", "U, func=UI (0x03)", b0 + 2, 1),
          leaf("Organization Code", "00:00:00 (Officially Xerox, but 00:00:00 is encapsulated Ethernet)", b0 + 3, 3),
          leaf("Type", "802.1X Authentication (0x888e)", b0 + 6, 2),
        ]),
      );
      const e0 = w.off;
      const m = f.eapolMsg ?? 1;
      const info = [0x008a, 0x010a, 0x13ca, 0x030a][m - 1]!;
      w.u8(2, 3);
      w.u16be(95);
      w.u8(2);
      w.u16be(info);
      w.u16be(16);
      for (let i = 0; i < 8; i++) w.u8(i === 7 ? 1 + (m > 2 ? 1 : 0) : 0);
      const nonce0 = w.off;
      for (let i = 0; i < 32; i++) w.u8(m === 4 ? 0 : Math.floor(r() * 256));
      for (let i = 0; i < 16 + 8 + 8; i++) w.u8(0);
      const mic0 = w.off;
      for (let i = 0; i < 16; i++) w.u8(m === 1 ? 0 : Math.floor(r() * 256));
      w.u16be(0);
      tree.push(
        group("802.1X Authentication", e0, w.off - e0, [
          leaf("Version", "802.1X-2004 (2)", e0, 1),
          leaf("Type", "Key (3)", e0 + 1, 1),
          leaf("Length", "95", e0 + 2, 2),
          leaf("Key Descriptor Type", "EAPOL RSN Key (2)", e0 + 4, 1),
          leaf("Key Information", `0x${info.toString(16).padStart(4, "0")} (message ${m} of 4)`, e0 + 5, 2),
          leaf("Key Length", "16", e0 + 7, 2),
          leaf("Replay Counter", String(1 + (m > 2 ? 1 : 0)), e0 + 9, 8),
          leaf("WPA Key Nonce", m === 4 ? "(zero)" : "(32 bytes)", nonce0, 32),
          leaf("WPA Key MIC", m === 1 ? "(zero)" : "(16 bytes)", mic0, 16),
          leaf("WPA Key Data Length", "0", mic0 + 16, 2),
        ]),
      );
      break;
    }
    case "data": {
      const n = f.len - HDR_LEN;
      for (let i = 0; i < n; i++) w.u8(Math.floor(r() * 256));
      tree.push(
        group(`Encrypted data (${n} bytes)`, b0, n, [
          leaf("CCMP parameters", "PN, key ID 0", b0, 8),
          leaf("Data", `${Math.max(0, n - 16)} bytes, not decrypted`, b0 + 8, Math.max(0, n - 16)),
          leaf("MIC", "(8 bytes)", b0 + n - 8, 8),
        ]),
      );
      break;
    }
    default:
      break;
  }
  if (w.off !== RADIOTAP_LEN + f.len) {
    // Keep the declared length honest even if a body builder drifted.
    while (w.off < RADIOTAP_LEN + f.len) w.u8(0);
    w.b.length = RADIOTAP_LEN + f.len;
  }
  const bytes_hex = w.b.map((x) => x.toString(16).padStart(2, "0")).join("");
  return {
    frame_no: f.frame_no,
    ts: f.ts,
    caplen: w.b.length,
    wirelen: w.b.length,
    link_type: 127,
    flow_id: null,
    decode_tree: tree,
    bytes_hex,
  };
}

let cached: WifiDataset | null = null;
/** The sample, generated once on first use (~11k frames, a few ms). */
export function wifiDataset(): WifiDataset {
  return (cached ??= generate());
}
