// Deterministic generator for the mock backend dataset.
//
//   node crates/walleye-core/mock/generate.mjs
//
// Writes dataset.json (capture, tables, findings, IOCs) and packets.json
// (frame_no -> PacketView) next to this file. Both the Rust MockBackend and
// the browser mock (app/src/shared/mock.ts) read these files, so the UI sees
// the same data in `pnpm tauri dev` and in Playwright.
//
// Scenario (one hour, 2026-03-12 09:00Z):
//   10.0.0.23  TLS beacon to 185.199.110.77 (cdn-update.top) every 60 s ±3 %
//   10.0.0.17  DNS tunnel: long TXT queries under t.exfil-dns.xyz
//   10.0.0.12  DGA: bursts of NXDOMAIN for random .top/.xyz names
//   10.0.0.15  periodic Windows Update checks (allowlisted, false positive)
//   others     office browsing over TLS/HTTP with DNS lookups

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// ---- seeded PRNG (mulberry32) -------------------------------------------
let seed = 0x5eed1234;
function rnd() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const pick = (xs) => xs[Math.floor(rnd() * xs.length)];

const T0 = Date.UTC(2026, 2, 12, 9, 0, 0) * 1000; // micros
const HOUR = 3600 * 1e6;
const DNS_SERVER = "10.0.0.2";

const flows = [];
const frames = [];
const dns = [];
const http = [];
const tls = [];
const files = [];
const packets = {};
let nextFlow = 1;
let fileOffset = 24; // pcap global header

// ---- byte builders --------------------------------------------------------
const hex = (n, w) => n.toString(16).padStart(w * 2, "0");
const ipBytes = (ip) => ip.split(".").map((x) => hex(+x, 1)).join("");
const macFor = (ip) => "02" + ipBytes(ip) + "00";
const ascii = (s) => [...s].map((c) => hex(c.charCodeAt(0) & 0xff, 1)).join("");

function node(label, field, value, start, len, children = []) {
  return {
    label,
    field: field ?? null,
    value: value ?? null,
    range: start === null ? null : { start, len },
    warning: null,
    children,
  };
}

// Build one frame: Ethernet + IPv4 + TCP/UDP + payload (ascii or hex).
function buildPacket({ src, dst, sport, dport, proto, flags, payloadHex, appTree, ts, frameNo, flowId }) {
  const l4len = proto === 6 ? 20 : 8;
  const plen = payloadHex.length / 2;
  const iplen = 20 + l4len + plen;
  const eth = macFor(dst) + macFor(src) + "0800";
  const ip =
    "4500" + hex(iplen, 2) + hex(frameNo & 0xffff, 2) + "4000" + "40" + hex(proto, 1) + "0000" + ipBytes(src) + ipBytes(dst);
  let l4;
  if (proto === 6) {
    l4 = hex(sport, 2) + hex(dport, 2) + hex(frameNo * 1000, 4) + hex(frameNo * 7, 4) + "50" + hex(flags, 1) + "faf0" + "0000" + "0000";
  } else {
    l4 = hex(sport, 2) + hex(dport, 2) + hex(8 + plen, 2) + "0000";
  }
  const bytes = eth + ip + l4 + payloadHex;
  const caplen = bytes.length / 2;
  const flagNames = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"].filter((_, i) => flags & (1 << i));
  const tree = [
    node(`Frame ${frameNo}: ${caplen} bytes`, null, null, 0, caplen, [
      node(`Frame number: ${frameNo}`, "frame.no", String(frameNo), null, null),
      node(`Captured length: ${caplen}`, "frame.len", String(caplen), null, null),
    ]),
    node("Ethernet II", null, null, 0, 14, [
      node(`Destination: ${fmtMac(macFor(dst))}`, null, fmtMac(macFor(dst)), 0, 6),
      node(`Source: ${fmtMac(macFor(src))}`, null, fmtMac(macFor(src)), 6, 6),
      node("Type: IPv4 (0x0800)", null, "0x0800", 12, 2),
    ]),
    node(`Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, null, null, 14, 20, [
      node("Version: 4", null, "4", 14, 1),
      node(`Total length: ${iplen}`, null, String(iplen), 16, 2),
      node("Time to live: 64", null, "64", 22, 1),
      node(`Protocol: ${proto === 6 ? "TCP (6)" : "UDP (17)"}`, "proto", String(proto), 23, 1),
      node(`Source address: ${src}`, "src_ip", src, 26, 4),
      node(`Destination address: ${dst}`, "dst_ip", dst, 30, 4),
    ]),
    proto === 6
      ? node(`Transmission Control Protocol, Src Port: ${sport}, Dst Port: ${dport}, Len: ${plen}`, null, null, 34, 20, [
          node(`Source port: ${sport}`, "src_port", String(sport), 34, 2),
          node(`Destination port: ${dport}`, "dst_port", String(dport), 36, 2),
          node(`Flags: 0x${hex(flags, 1)} (${flagNames.join(", ")})`, "frame.tcp_flags", String(flags), 47, 1),
          node("Window: 64240", null, "64240", 48, 2),
        ])
      : node(`User Datagram Protocol, Src Port: ${sport}, Dst Port: ${dport}`, null, null, 34, 8, [
          node(`Source port: ${sport}`, "src_port", String(sport), 34, 2),
          node(`Destination port: ${dport}`, "dst_port", String(dport), 36, 2),
          node(`Length: ${8 + plen}`, null, String(8 + plen), 38, 2),
        ]),
  ];
  if (appTree && plen > 0) tree.push(appTree(14 + 20 + l4len, plen));
  else if (plen > 0) tree.push(node(`Data (${plen} bytes)`, null, null, 14 + 20 + l4len, plen));
  packets[frameNo] = {
    frame_no: frameNo,
    ts,
    caplen,
    wirelen: caplen,
    link_type: 1,
    flow_id: flowId,
    decode_tree: tree,
    bytes_hex: bytes,
  };
  return { caplen, plen };
}
const fmtMac = (h) => h.match(/../g).join(":");

// ---- flow builder ---------------------------------------------------------
// steps: [{dir:'up'|'down', flags, payloadHex, appTree, dt}] ; returns flow row
function addFlow({ src, dst, sport, dport, proto, app, t, steps }) {
  const flowId = nextFlow++;
  const f = {
    flow_id: flowId,
    ts_start: t,
    ts_end: t,
    src_ip: src,
    src_port: sport,
    dst_ip: dst,
    dst_port: dport,
    proto,
    app_proto: app,
    bytes_up: 0,
    bytes_down: 0,
    pkts_up: 0,
    pkts_down: 0,
    first_frame: 0,
    last_frame: 0,
  };
  let ts = t;
  const nos = [];
  for (const s of steps) {
    ts += s.dt ?? ri(200, 30000);
    const frameNo = frames.length + 1;
    const up = s.dir === "up";
    const { caplen, plen } = buildPacket({
      src: up ? src : dst,
      dst: up ? dst : src,
      sport: up ? sport : dport,
      dport: up ? dport : sport,
      proto,
      flags: s.flags ?? 0,
      payloadHex: s.payloadHex ?? "",
      appTree: s.appTree,
      ts,
      frameNo,
      flowId,
    });
    fileOffset += 16;
    frames.push({
      frame_no: frameNo,
      ts,
      file_offset: fileOffset,
      caplen,
      wirelen: caplen,
      flow_id: flowId,
      direction: s.dir,
      tcp_flags: proto === 6 ? s.flags ?? 0 : null,
      payload_len: plen,
    });
    fileOffset += caplen;
    if (up) {
      f.bytes_up += s.bytes ?? plen;
      f.pkts_up++;
    } else {
      f.bytes_down += s.bytes ?? plen;
      f.pkts_down++;
    }
    nos.push(frameNo);
    if (s.onFrame) s.onFrame(frameNo, ts);
  }
  f.ts_end = ts;
  f.first_frame = nos[0];
  f.last_frame = nos[nos.length - 1];
  flows.push(f);
  return { flow: f, frameNos: nos };
}

const SYN = 0x02, ACK = 0x10, PSH = 0x08, FIN = 0x01;
const tcpOpen = () => [
  { dir: "up", flags: SYN, dt: 0 },
  { dir: "down", flags: SYN | ACK, dt: ri(800, 40000) },
  { dir: "up", flags: ACK, dt: ri(50, 400) },
];
const tcpClose = () => [
  { dir: "up", flags: FIN | ACK },
  { dir: "down", flags: FIN | ACK },
];

// ---- protocol helpers -----------------------------------------------------
function dnsLookup(client, t, name, { qtype = "A", answers = null, rcode = "NOERROR" } = {}) {
  const sport = ri(49152, 65535);
  const txid = ri(1, 65535);
  const ans = answers ?? (rcode === "NOERROR" ? [`${ri(20, 220)}.${ri(0, 255)}.${ri(0, 255)}.${ri(1, 254)}`] : []);
  const qHex = ascii(name);
  const qTree = (start, len) =>
    node(`Domain Name System (query) ${qtype} ${name}`, null, null, start, len, [
      node(`Transaction ID: 0x${hex(txid, 2)}`, null, `0x${hex(txid, 2)}`, start, 2),
      node(`Name: ${name}`, "dns.query", name, start + 12, Math.max(1, len - 16)),
      node(`Type: ${qtype}`, "dns.qtype", qtype, start + len - 4, 2),
    ]);
  const rTree = (start, len) =>
    node(`Domain Name System (response) ${rcode} ${name}`, null, null, start, len, [
      node(`Transaction ID: 0x${hex(txid, 2)}`, null, `0x${hex(txid, 2)}`, start, 2),
      node(`Reply code: ${rcode}`, "dns.rcode", rcode, start + 3, 1),
      node(`Name: ${name}`, "dns.query", name, start + 12, Math.max(1, Math.min(len - 12, name.length + 2))),
      ...ans.map((a) => node(`Answer: ${a}`, "dns.answer", a, null, null)),
    ]);
  const header = hex(txid, 2) + "0100000100000000000";
  return addFlow({
    src: client,
    dst: DNS_SERVER,
    sport,
    dport: 53,
    proto: 17,
    app: "dns",
    t,
    steps: [
      {
        dir: "up",
        dt: 0,
        payloadHex: header + "0" + qHex + "0000010001",
        appTree: qTree,
        onFrame: (frameNo, ts) =>
          dns.push({ ts, flow_id: nextFlow - 1, frame_no: frameNo, trans_id: txid, is_response: false, query: name, qtype, rcode: null, answers: [], ttl: null }),
      },
      {
        dir: "down",
        dt: ri(900, 25000),
        payloadHex: header + "0" + qHex + "0000010001" + ans.map((a) => ipBytes(a.includes(".") ? a : "0.0.0.0")).join(""),
        appTree: rTree,
        onFrame: (frameNo, ts) =>
          dns.push({ ts, flow_id: nextFlow - 1, frame_no: frameNo, trans_id: txid, is_response: true, query: name, qtype, rcode, answers: ans, ttl: ans.length ? ri(30, 3600) : null }),
      },
    ],
  });
}

const JA4_CHROME = "t13d1516h2_8daaf6152771_02713d6af862";
const JA4_FIREFOX = "t13d1715h2_5b57614c22b0_3d5424432f57";
const JA4_BEACON = "t12d190800_d83cc789557e_7af1ed941c26";

function tlsSession(client, server, t, sni, { ja4 = JA4_CHROME, ja4s = "t130200_1301_234ea6891581", issuer = "CN=R11,O=Let's Encrypt,C=US", selfSigned = false, serial = null, appBytes = [ri(400, 2000), ri(2000, 90000)], version = "TLS 1.3" } = {}) {
  const sport = ri(49152, 65535);
  const certSerial = serial ?? hex(ri(1, 2 ** 31), 4) + hex(ri(1, 2 ** 31), 4);
  const chTree = (start, len) =>
    node(`Transport Layer Security: Client Hello (SNI ${sni})`, null, null, start, len, [
      node("Handshake type: Client Hello (1)", null, "1", start + 5, 1),
      node(`Server Name: ${sni}`, "tls.sni", sni, start + len - sni.length, sni.length),
      node(`JA4: ${ja4}`, "tls.ja4", ja4, null, null),
    ]);
  const shTree = (start, len) =>
    node("Transport Layer Security: Server Hello, Certificate", null, null, start, len, [
      node(`Version: ${version}`, "tls.version", version, start + 9, 2),
      node(`JA4S: ${ja4s}`, "tls.ja4s", ja4s, null, null),
      node(`Certificate subject: CN=${sni}`, "tls.cert_subject", `CN=${sni}`, null, null),
      node(`Certificate issuer: ${issuer}`, "tls.cert_issuer", issuer, null, null),
    ]);
  let chFrame = 0;
  const res = addFlow({
    src: client,
    dst: server,
    sport,
    dport: 443,
    proto: 6,
    app: "tls",
    t,
    steps: [
      ...tcpOpen(),
      { dir: "up", flags: PSH | ACK, payloadHex: "16030100" + hex(64 + sni.length, 1) + "01" + "00".repeat(54) + ascii(sni), appTree: chTree, onFrame: (n) => (chFrame = n) },
      { dir: "down", flags: PSH | ACK, payloadHex: "1603030060" + "02" + "00".repeat(60), appTree: shTree },
      { dir: "up", flags: PSH | ACK, payloadHex: "17030300" + "aa".repeat(28), bytes: appBytes[0] },
      { dir: "down", flags: PSH | ACK, payloadHex: "17030300" + "bb".repeat(44), bytes: appBytes[1] },
      ...tcpClose(),
    ],
  });
  tls.push({
    ts: res.flow.ts_start,
    flow_id: res.flow.flow_id,
    frame_no: chFrame,
    sni,
    version,
    ja4,
    ja4s,
    cert_subject: `CN=${sni}`,
    cert_issuer: selfSigned ? `CN=${sni}` : issuer,
    cert_serial: certSerial,
    cert_self_signed: selfSigned,
    cert_not_before: T0 - 30 * 24 * HOUR,
    cert_not_after: T0 + 60 * 24 * HOUR,
  });
  return res;
}

function httpGet(client, server, t, host, uri, { ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", status = 200, mime = "text/html", size = ri(800, 40000), filename = null } = {}) {
  const sport = ri(49152, 65535);
  const req = `GET ${uri} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${ua}\r\n\r\n`;
  const resp = `HTTP/1.1 ${status} OK\r\nContent-Type: ${mime}\r\nContent-Length: ${size}\r\n\r\n`;
  let reqFrame = 0;
  let respFrame = 0;
  const reqTree = (start, len) =>
    node(`Hypertext Transfer Protocol: GET ${uri}`, null, null, start, len, [
      node("Method: GET", "http.method", "GET", start, 3),
      node(`URI: ${uri}`, "http.uri", uri, start + 4, uri.length),
      node(`Host: ${host}`, "http.host", host, start + req.indexOf("Host: ") + 6, host.length),
      node(`User-Agent: ${ua}`, "http.user_agent", ua, start + req.indexOf("User-Agent: ") + 12, ua.length),
    ]);
  const respTree = (start, len) =>
    node(`Hypertext Transfer Protocol: ${status} OK`, null, null, start, len, [
      node(`Status: ${status}`, "http.status", String(status), start + 9, 3),
      node(`Content-Type: ${mime}`, "file.mime_type", mime, start + resp.indexOf("Content-Type: ") + 14, mime.length),
    ]);
  const res = addFlow({
    src: client,
    dst: server,
    sport,
    dport: 80,
    proto: 6,
    app: "http",
    t,
    steps: [
      ...tcpOpen(),
      { dir: "up", flags: PSH | ACK, payloadHex: ascii(req), appTree: reqTree, onFrame: (n) => (reqFrame = n) },
      { dir: "down", flags: PSH | ACK, payloadHex: ascii(resp), appTree: respTree, bytes: size, onFrame: (n) => (respFrame = n) },
      ...tcpClose(),
    ],
  });
  http.push({
    ts: res.flow.ts_start,
    flow_id: res.flow.flow_id,
    frame_no: reqFrame,
    method: "GET",
    host,
    uri,
    user_agent: ua,
    status,
    resp_frame_no: respFrame,
    req_bytes: 0,
    resp_bytes: size,
  });
  if (filename || mime !== "text/html") {
    files.push({ ts: res.flow.ts_end, flow_id: res.flow.flow_id, frame_no: respFrame, source: "http", direction: "down", filename: filename ?? (uri.split("/").pop() || null), mime_type: mime, size_bytes: size });
  }
  return res;
}

// ---- scenario ---------------------------------------------------------------
const office = Array.from({ length: 14 }, (_, i) => `10.0.0.${10 + i}`).filter((h) => !["10.0.0.12", "10.0.0.17", "10.0.0.23"].includes(h));
const sites = [
  ["www.google.com", "142.250.64.100"],
  ["mail.google.com", "142.250.64.101"],
  ["outlook.office365.com", "52.96.88.14"],
  ["teams.microsoft.com", "52.113.194.132"],
  ["github.com", "140.82.112.4"],
  ["slack.com", "34.226.36.50"],
  ["cdn.jsdelivr.net", "151.101.1.229"],
  ["www.wikipedia.org", "208.80.154.224"],
  ["news.ycombinator.com", "209.216.230.207"],
  ["fonts.gstatic.com", "142.250.64.67"],
];

const events = [];
// Office browsing: ~ 140 sessions spread across the hour.
for (let i = 0; i < 140; i++) events.push({ t: T0 + Math.floor(rnd() * HOUR * 0.98), kind: "browse" });
// Plain HTTP downloads.
for (let i = 0; i < 8; i++) events.push({ t: T0 + Math.floor(rnd() * HOUR * 0.95), kind: "download" });
// Beacon: 10.0.0.23, every 60 s ±3 %, starting at +4 min.
let bt = T0 + 4 * 60e6;
events.push({ t: bt - 5e6, kind: "stage" });
while (bt < T0 + HOUR - 30e6) {
  events.push({ t: bt, kind: "beacon" });
  bt += Math.round(60e6 * (1 + (rnd() * 2 - 1) * 0.03));
}
// DNS tunnel: 10.0.0.17, bursts of long TXT queries.
for (let b = 0; b < 6; b++) {
  const start = T0 + (8 + b * 8) * 60e6;
  for (let i = 0; i < 10; i++) events.push({ t: start + i * ri(300e3, 1500e3), kind: "tunnel" });
}
// DGA: 10.0.0.12, three NXDOMAIN bursts.
for (let b = 0; b < 3; b++) {
  const start = T0 + (15 + b * 17) * 60e6;
  for (let i = 0; i < 12; i++) events.push({ t: start + i * ri(80e3, 400e3), kind: "dga" });
}
// Windows Update checks: 10.0.0.15 every 5 min (allowlisted FP).
for (let t = T0 + 2 * 60e6; t < T0 + HOUR - 60e6; t += 300e6 + ri(-2e6, 2e6)) events.push({ t, kind: "wu" });

events.sort((a, b) => a.t - b.t);

const beaconFlows = [];
const tunnelDns = [];
const dgaDns = [];
const wuFlows = [];
let stageFlow = null;
const b32 = "abcdefghijklmnopqrstuvwxyz234567";
const rstr = (n, alpha = b32) => Array.from({ length: n }, () => pick(alpha)).join("");

for (const ev of events) {
  switch (ev.kind) {
    case "browse": {
      const h = pick(office);
      const [name, ip] = pick(sites);
      dnsLookup(h, ev.t, name, { answers: [ip] });
      tlsSession(h, ip, ev.t + ri(5e3, 40e3), name, { ja4: rnd() < 0.7 ? JA4_CHROME : JA4_FIREFOX });
      break;
    }
    case "download": {
      const h = pick(office);
      dnsLookup(h, ev.t, "downloads.vendor-portal.com", { answers: ["93.184.215.14"] });
      httpGet(h, "93.184.215.14", ev.t + 20e3, "downloads.vendor-portal.com", `/files/report-${ri(100, 999)}.pdf`, { mime: "application/pdf", size: ri(200e3, 3e6) });
      break;
    }
    case "stage": {
      dnsLookup("10.0.0.23", ev.t, "cdn-update.top", { answers: ["185.199.110.77"] });
      stageFlow = httpGet("10.0.0.23", "185.199.110.77", ev.t + 30e3, "cdn-update.top", "/gate.php?id=7f3a", { ua: "Mozilla/4.0 (compatible; MSIE 8.0)", mime: "application/octet-stream", size: 48213, filename: "upd.bin" });
      break;
    }
    case "beacon": {
      beaconFlows.push(
        tlsSession("10.0.0.23", "185.199.110.77", ev.t, "cdn-update.top", {
          ja4: JA4_BEACON,
          ja4s: "t120300_c030_9a0d1ae0b2e4",
          selfSigned: true,
          serial: "00d1e2f3a4b5c6d7",
          version: "TLS 1.2",
          appBytes: [ri(180, 240), ri(90, 160)],
        }),
      );
      break;
    }
    case "tunnel": {
      const name = `${rstr(48)}.${rstr(12)}.t.exfil-dns.xyz`;
      const r = dnsLookup("10.0.0.17", ev.t, name, { qtype: "TXT", answers: [rstr(60)] });
      tunnelDns.push(r);
      break;
    }
    case "dga": {
      const name = `${rstr(ri(12, 18), "abcdefghijklmnopqrstuvwxyz")}.${pick(["top", "xyz", "info"])}`;
      dgaDns.push(dnsLookup("10.0.0.12", ev.t, name, { rcode: "NXDOMAIN" }));
      break;
    }
    case "wu": {
      dnsLookup("10.0.0.15", ev.t, "fe2.update.microsoft.com", { answers: ["13.107.4.50"] });
      wuFlows.push(tlsSession("10.0.0.15", "13.107.4.50", ev.t + 15e3, "fe2.update.microsoft.com", { issuer: "CN=Microsoft Azure RSA TLS Issuing CA 03" }));
      break;
    }
  }
}

// ---- findings ---------------------------------------------------------------
const ev = (rs, cap = 200) => {
  const flow_ids = rs.map((r) => r.flow.flow_id);
  const frame_nos = rs.map((r) => r.frameNos[0]);
  return { flow_ids: flow_ids.slice(0, cap), frame_nos: frame_nos.slice(0, cap), truncated: rs.length > cap, total: rs.length };
};
const span = (rs) => [Math.min(...rs.map((r) => r.flow.ts_start)), Math.max(...rs.map((r) => r.flow.ts_end))];
const reason = (rule_id, signal, value, unit, weight, explanation, attack_technique, evidence) => ({ rule_id, signal, value, unit, weight, explanation, attack_technique, evidence });

const intervals = beaconFlows.slice(1).map((r, i) => (r.flow.ts_start - beaconFlows[i].flow.ts_start) / 1e6);
const sorted = [...intervals].sort((a, b) => a - b);
const median = sorted[Math.floor(sorted.length / 2)];
const mad = [...intervals.map((x) => Math.abs(x - median))].sort((a, b) => a - b)[Math.floor(intervals.length / 2)];
const [bFirst, bLast] = span(beaconFlows);

const findings = [
  {
    finding_id: "f1b2c3d4e5f60001",
    title: "Beaconing to 185.199.110.77 (cdn-update.top)",
    detector: "beaconing",
    entity_type: "host",
    entity: "10.0.0.23",
    score: 92,
    attack_technique: "T1071",
    ts_first: bFirst,
    ts_last: bLast,
    reasons: [
      reason("beacon.periodic", "interval_regularity", +(mad / median).toFixed(4), "ratio", 46, `10.0.0.23 contacted 185.199.110.77 ${beaconFlows.length} times, every ${median.toFixed(1)}s ±${((mad / median) * 100).toFixed(1)}%`, "T1071", ev(beaconFlows)),
      reason("beacon.periodic", "duration", +((bLast - bFirst) / 60e6).toFixed(1), "min", 18, `Periodic contact sustained for ${((bLast - bFirst) / 60e6).toFixed(0)} minutes`, "T1071", ev(beaconFlows.slice(0, 1).concat(beaconFlows.slice(-1)))),
      reason("tls.self_signed", "self_signed_cert", 1, "bool", 14, "Server certificate for cdn-update.top is self-signed", "T1071.001", ev(beaconFlows.slice(0, 3))),
      reason("beacon.periodic", "small_payload", 210, "bytes", 9, "Requests are small and uniform (median 210 B up)", "T1071", ev(beaconFlows.slice(0, 10))),
      reason("http.suspicious_ua", "legacy_user_agent", 1, "bool", 5, "Staging download used a legacy MSIE 8.0 User-Agent", "T1071.001", { flow_ids: [stageFlow.flow.flow_id], frame_nos: [stageFlow.frameNos[3]], truncated: false, total: 1 }),
    ],
    verdict: null,
  },
  {
    finding_id: "f1b2c3d4e5f60002",
    title: "DNS tunneling via t.exfil-dns.xyz",
    detector: "dns",
    entity_type: "host",
    entity: "10.0.0.17",
    score: 81,
    attack_technique: "T1071.004",
    ts_first: span(tunnelDns)[0],
    ts_last: span(tunnelDns)[1],
    reasons: [
      reason("dns.entropy", "subdomain_entropy", 4.81, "bits", 30, "Leftmost labels under exfil-dns.xyz average 4.81 bits/char entropy", "T1071.004", ev(tunnelDns)),
      reason("dns.length", "query_length", 83, "chars", 22, "Query names average 83 characters", "T1048", ev(tunnelDns)),
      reason("dns.tunnel", "txt_volume", tunnelDns.length, "count", 18, `${tunnelDns.length} TXT queries to one parent domain`, "T1071.004", ev(tunnelDns)),
      reason("dns.subdomain_rate", "unique_subdomains", tunnelDns.length, "count", 11, `${tunnelDns.length} unique subdomains of exfil-dns.xyz, none repeated`, "T1071.004", ev(tunnelDns)),
    ],
    verdict: null,
  },
  {
    finding_id: "f1b2c3d4e5f60003",
    title: "NXDOMAIN bursts consistent with DGA",
    detector: "dns",
    entity_type: "host",
    entity: "10.0.0.12",
    score: 64,
    attack_technique: "T1568.002",
    ts_first: span(dgaDns)[0],
    ts_last: span(dgaDns)[1],
    reasons: [
      reason("dns.nxdomain_burst", "nxdomain_burst", 12, "per min", 34, "3 bursts of 12 NXDOMAIN responses within 60 s", "T1568.002", ev(dgaDns)),
      reason("dns.entropy", "subdomain_entropy", 3.9, "bits", 20, "Queried names have high character entropy (3.9 bits/char)", "T1568.002", ev(dgaDns.slice(0, 12))),
      reason("dns.tld", "rare_tld", 0.67, "ratio", 10, "67% of failed names use .top/.xyz/.info", "T1568.002", ev(dgaDns.slice(0, 12))),
    ],
    verdict: null,
  },
  {
    finding_id: "f1b2c3d4e5f60004",
    title: "Periodic connections to fe2.update.microsoft.com",
    detector: "beaconing",
    entity_type: "host",
    entity: "10.0.0.15",
    score: 22,
    attack_technique: "T1071",
    ts_first: span(wuFlows)[0],
    ts_last: span(wuFlows)[1],
    reasons: [
      reason("beacon.periodic", "interval_regularity", 0.006, "ratio", 22, `10.0.0.15 contacted 13.107.4.50 ${wuFlows.length} times, every 300.0s ±0.6% (destination allowlisted: Microsoft Update; score reduced)`, "T1071", ev(wuFlows)),
    ],
    verdict: null,
  },
];

// ---- IOCs -------------------------------------------------------------------
const defang = (v, type) =>
  type === "url" ? v.replace(/^http/, "hxxp").replace(/\./g, "[.]") : type === "ip" || type === "domain" ? v.replace(/\./g, "[.]") : v;
let iocN = 1;
const ioc = (type, value, src, first_seen, evidence, allow = null) => ({
  ioc_id: `i0c${String(iocN++).padStart(13, "0")}`,
  type,
  value,
  defanged: defang(value, type),
  source_finding_id: src,
  first_seen,
  evidence,
  allowlisted: !!allow,
  allowlist_reason: allow,
});
const iocs = [
  ioc("ip", "185.199.110.77", "f1b2c3d4e5f60001", stageFlow.flow.ts_start, ev([stageFlow, ...beaconFlows])),
  ioc("domain", "cdn-update.top", "f1b2c3d4e5f60001", stageFlow.flow.ts_start, ev([stageFlow, ...beaconFlows])),
  ioc("url", "http://cdn-update.top/gate.php?id=7f3a", "f1b2c3d4e5f60001", stageFlow.flow.ts_start, { flow_ids: [stageFlow.flow.flow_id], frame_nos: [stageFlow.frameNos[3]], truncated: false, total: 1 }),
  ioc("ja4", JA4_BEACON, "f1b2c3d4e5f60001", bFirst, ev(beaconFlows)),
  ioc("cert_serial", "00d1e2f3a4b5c6d7", "f1b2c3d4e5f60001", bFirst, ev(beaconFlows)),
  ioc("domain", "exfil-dns.xyz", "f1b2c3d4e5f60002", span(tunnelDns)[0], ev(tunnelDns)),
  ...dgaDns.slice(0, 4).map((r) => ioc("domain", dns.find((d) => d.flow_id === r.flow.flow_id).query, "f1b2c3d4e5f60003", r.flow.ts_start, ev([r]))),
  ioc("domain", "fe2.update.microsoft.com", "f1b2c3d4e5f60004", span(wuFlows)[0], ev(wuFlows), "Microsoft Update"),
  ioc("ip", "13.107.4.50", "f1b2c3d4e5f60004", span(wuFlows)[0], ev(wuFlows), "Microsoft"),
];

// ---- capture + write -------------------------------------------------------------
const lastTs = Math.max(...frames.map((f) => f.ts));
const capture = {
  capture_id: "a3f1c9e07b5d2e64",
  path: "/mock/office-beacon.pcap",
  sha256: "a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0",
  size_bytes: fileOffset,
  format: "pcap",
  first_ts: frames[0].ts,
  last_ts: lastTs,
  link_type: 1,
  frame_count: frames.length,
};

const byTs = (k) => (a, b) => a[k] - b[k];
flows.sort(byTs("ts_start"));
dns.sort(byTs("ts"));
http.sort(byTs("ts"));
tls.sort(byTs("ts"));
files.sort(byTs("ts"));

const dataset = { capture, flows, frames, dns, http, tls, files, findings, iocs };
writeFileSync(join(here, "dataset.json"), JSON.stringify(dataset));
// Keep packet bytes for the first 120 flows plus every evidence flow, so the
// file stays small. Other frames return NotFound from packet(), which also
// exercises the packet pane's error state.
const keepFlows = new Set(flows.filter((f) => f.flow_id <= 120).map((f) => f.flow_id));
for (const f of findings) for (const r of f.reasons) r.evidence.flow_ids.forEach((id) => keepFlows.add(id));
for (const i of iocs) i.evidence.flow_ids.forEach((id) => keepFlows.add(id));
const keptPackets = {};
for (const [no, p] of Object.entries(packets)) if (keepFlows.has(p.flow_id)) keptPackets[no] = p;
writeFileSync(join(here, "packets.json"), JSON.stringify(keptPackets));
console.log(
  `flows=${flows.length} frames=${frames.length} dns=${dns.length} http=${http.length} tls=${tls.length} files=${files.length} findings=${findings.length} iocs=${iocs.length} packets=${Object.keys(keptPackets).length}`,
);
