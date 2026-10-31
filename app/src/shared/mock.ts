// Browser-side mock backend. Mirrors crates/walleye-core/src/mock.rs and reads
// the same JSON (crates/walleye-core/mock/*.json, from generate.mjs).
// Used automatically when the UI runs outside Tauri (Vite dev, Playwright,
// Vitest). Not bundled into the Tauri build's hot path: ipc.ts imports it
// lazily only when no Tauri runtime is present.
//
// Filter text: only `host <ip>` terms are honoured (AND-ed); unbalanced
// quotes/parentheses return `invalid_filter` with a span; the rest is ignored.

import datasetJson from "../../../crates/walleye-core/mock/dataset.json";
import type { ApiError } from "./bindings/ApiError";
import type { Bucket } from "./bindings/Bucket";
import type { Case } from "./bindings/Case";
import type { CaptureRow } from "./bindings/CaptureRow";
import type { DnsRow } from "./bindings/DnsRow";
import type { EvidenceRef } from "./bindings/EvidenceRef";
import type { Evidence } from "./bindings/Evidence";
import type { FileRow } from "./bindings/FileRow";
import type { Finding } from "./bindings/Finding";
import type { FindingsFilter } from "./bindings/FindingsFilter";
import type { FlowRow } from "./bindings/FlowRow";
import type { FrameRef } from "./bindings/FrameRef";
import type { FrameRow } from "./bindings/FrameRow";
import type { HttpRow } from "./bindings/HttpRow";
import type { IngestStatus } from "./bindings/IngestStatus";
import type { Ioc } from "./bindings/Ioc";
import type { Lane } from "./bindings/Lane";
import type { Lanes } from "./bindings/Lanes";
import type { PacketView } from "./bindings/PacketView";
import type { Page } from "./bindings/Page";
import type { Pin } from "./bindings/Pin";
import type { QueryLogEntry } from "./bindings/QueryLogEntry";
import type { QueryRequest } from "./bindings/QueryRequest";
import type { RowSet } from "./bindings/RowSet";
import type { SavedQuery } from "./bindings/SavedQuery";
import type { Suggestion } from "./bindings/Suggestion";
import type { TimelineRequest } from "./bindings/TimelineRequest";
import type { TlsRow } from "./bindings/TlsRow";
import type { VerdictEntry } from "./bindings/VerdictEntry";
import type { View } from "./bindings/View";
import { FILTER_FIELDS, FILTER_KEYWORDS, FILTER_OPERATORS } from "./filterFields";

interface Dataset {
  capture: CaptureRow;
  flows: FlowRow[];
  frames: FrameRow[];
  dns: DnsRow[];
  http: HttpRow[];
  tls: TlsRow[];
  files: FileRow[];
  findings: Finding[];
  iocs: Ioc[];
}

const data = datasetJson as unknown as Dataset;
const flowById = new Map(data.flows.map((f) => [f.flow_id, f]));
let packets: Record<string, PacketView> | null = null;
const INGEST_MS = 1500;

const state = {
  jobs: new Map<string, { start: number; cancelled: boolean }>(),
  open: false,
  verdicts: new Map<string, VerdictEntry>(),
  pins: [] as Pin[],
  queries: [] as QueryLogEntry[],
  saved: [
    { name: "Long DNS names", filter: 'dns.query ~ "*.*.*.*" and app_proto == dns', view: "dns" },
    { name: "Large uploads", filter: "bytes_up > 1MB", view: "flows" },
  ] as SavedQuery[],
  nextId: 0,
};

/** Test hook: reset all mock state; `open` starts with the capture loaded. */
export function resetMock(opts: { open?: boolean } = {}): void {
  state.jobs.clear();
  state.open = !!opts.open;
  state.verdicts.clear();
  state.pins = [];
  state.queries = [];
  state.nextId = 0;
}

// `?mock=open` in the URL starts with the capture already indexed.
if (typeof window !== "undefined" && new URLSearchParams(window.location.search).get("mock") === "open") {
  state.open = true;
}

const err = (code: ApiError["code"], message: string, span: ApiError["span"] = null): ApiError => ({ code, message, span });
const nowUs = () => Date.now() * 1000;
const session = () => ({ capture: data.capture, case_id: data.capture.capture_id });

function requireOpen() {
  if (state.open) return;
  for (const j of state.jobs.values()) {
    if (!j.cancelled && Date.now() - j.start >= INGEST_MS) {
      state.open = true;
      return;
    }
  }
  throw err("no_capture", "no capture is open");
}

function checkCase(caseId: string) {
  if (caseId !== data.capture.capture_id) throw err("not_found", `case ${caseId}`);
}

export function mockParseFilter(filter: string): string[] {
  let depth = 0;
  let openAt = 0;
  let inStr = false;
  let strAt = 0;
  for (let i = 0; i < filter.length; i++) {
    const c = filter[i];
    if (c === '"') {
      inStr = !inStr;
      strAt = i;
    } else if (!inStr && c === "(") {
      if (depth === 0) openAt = i;
      depth++;
    } else if (!inStr && c === ")") {
      depth--;
      if (depth < 0) throw err("invalid_filter", "unexpected ')'", { start: i, end: i + 1 });
    }
  }
  if (inStr) throw err("invalid_filter", "unterminated string", { start: strAt, end: filter.length });
  if (depth > 0) throw err("invalid_filter", "unclosed '('", { start: openAt, end: openAt + 1 });
  const toks = filter.split(/[\s()]+/).filter(Boolean);
  const hosts: string[] = [];
  for (let i = 0; i + 1 < toks.length; i++) if (toks[i] === "host") hosts.push(toks[i + 1]!);
  return hosts;
}

type AnyRow = Record<string, unknown>;
const viewRows = (v: View): AnyRow[] =>
  ({ flows: data.flows, dns: data.dns, http: data.http, tls: data.tls, files: data.files, frames: data.frames })[v] as unknown as AnyRow[];

function cmp(a: unknown, b: unknown): number {
  if (a === b) return 0;
  if (a === null || a === undefined) return -1;
  if (b === null || b === undefined) return 1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a) < String(b) ? -1 : 1;
}

function hostsOf(r: AnyRow): [string, string] | null {
  if (typeof r.src_ip === "string" && typeof r.dst_ip === "string") return [r.src_ip, r.dst_ip];
  const f = typeof r.flow_id === "number" ? flowById.get(r.flow_id) : undefined;
  return f ? [f.src_ip, f.dst_ip] : null;
}

function query(req: QueryRequest): Page {
  requireOpen();
  const t0 = performance.now();
  if (req.limit < 1 || req.limit > 10_000) throw err("invalid_argument", "limit must be 1..=10000");
  const filterHosts = mockParseFilter(req.filter);
  const hosts = new Set(req.hosts ?? []);
  const flowIds = new Set(req.flow_ids ?? []);
  const tr = req.time_range ?? null;
  let rows = viewRows(req.view).filter((r) => {
    if (tr) {
      const ok =
        req.view === "flows"
          ? (r.ts_start as number) < tr.end && (r.ts_end as number) >= tr.start
          : (r.ts as number) >= tr.start && (r.ts as number) < tr.end;
      if (!ok) return false;
    }
    if (flowIds.size && !flowIds.has(r.flow_id as number)) return false;
    if (hosts.size || filterHosts.length) {
      const h = hostsOf(r);
      if (!h) return false;
      if (hosts.size && !hosts.has(h[0]) && !hosts.has(h[1])) return false;
      if (!filterHosts.every((x) => x === h[0] || x === h[1])) return false;
    }
    return true;
  });
  if (req.sort) {
    const { column, desc } = req.sort;
    rows = [...rows].sort((a, b) => (desc ? -1 : 1) * cmp(a[column], b[column]));
  }
  const total = rows.length;
  const offset = req.cursor ? Number(req.cursor) : 0;
  if (!Number.isInteger(offset) || offset < 0) throw err("invalid_argument", "bad cursor");
  const end = Math.min(offset + req.limit, total);
  const page = rows.slice(offset, end);
  const sql = `-- mock backend: ${req.view} view, no SQL`;
  state.queries.push({ filter: req.filter, view: req.view, time_range: tr, sql, rows: page.length, at: nowUs() });
  return {
    data: { view: req.view, rows: page } as unknown as RowSet,
    next_cursor: end < total ? String(end) : null,
    total,
    sql,
    elapsed_ms: performance.now() - t0,
  };
}

function timeline(req: TimelineRequest): Lanes {
  requireOpen();
  const filterHosts = mockParseFilter(req.filter);
  const cap = data.capture;
  const range = req.time_range ?? { start: cap.first_ts, end: cap.last_ts + 1 };
  const spanMs = Math.ceil(Math.max(1, range.end - range.start) / 1000);
  const bucketMs = Math.max(1, req.bucket_ms, Math.ceil(spanMs / 2000));
  const bucketUs = bucketMs * 1000;
  const perHost = new Map<string, Map<number, Bucket>>();
  const totals = new Map<string, number>();
  for (const f of data.flows) {
    if (f.ts_start < range.start || f.ts_start >= range.end) continue;
    if (!filterHosts.every((h) => h === f.src_ip || h === f.dst_ip)) continue;
    const t = range.start + Math.floor((f.ts_start - range.start) / bucketUs) * bucketUs;
    let m = perHost.get(f.src_ip);
    if (!m) perHost.set(f.src_ip, (m = new Map()));
    let b = m.get(t);
    if (!b) m.set(t, (b = { t, dns: 0, tls: 0, http: 0, bulk: 0, other: 0 }));
    if (f.bytes_up + f.bytes_down >= 1 << 20) b.bulk++;
    else if (f.app_proto === "dns") b.dns++;
    else if (f.app_proto === "tls") b.tls++;
    else if (f.app_proto === "http") b.http++;
    else b.other++;
    totals.set(f.src_ip, (totals.get(f.src_ip) ?? 0) + 1);
  }
  const order = [...totals.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  const maxLanes = Math.max(1, req.max_lanes);
  const lanes: Lane[] = [];
  const other = new Map<number, Bucket>();
  let otherTotal = 0;
  const sorted = (m: Map<number, Bucket>) => [...m.values()].sort((a, b) => a.t - b.t);
  order.forEach(([h, total], i) => {
    const buckets = perHost.get(h) ?? new Map<number, Bucket>();
    if (i < maxLanes) {
      const scores = data.findings.filter((f) => f.entity === h).map((f) => f.score);
      lanes.push({ host: h, is_other: false, total, max_score: scores.length ? Math.max(...scores) : null, buckets: sorted(buckets) });
    } else {
      otherTotal += total;
      for (const [t, b] of buckets) {
        const o = other.get(t) ?? { t, dns: 0, tls: 0, http: 0, bulk: 0, other: 0 };
        o.dns += b.dns;
        o.tls += b.tls;
        o.http += b.http;
        o.bulk += b.bulk;
        o.other += b.other;
        other.set(t, o);
      }
    }
  });
  if (otherTotal > 0) lanes.push({ host: "other", is_other: true, total: otherTotal, max_score: null, buckets: sorted(other) });
  return { bucket_ms: bucketMs, range, lanes };
}

function frameSummary(fr: FrameRow, f: FlowRow): string {
  const [sp, dp] = fr.direction === "down" ? [f.dst_port, f.src_port] : [f.src_port, f.dst_port];
  if (f.proto === 6) {
    const fl = fr.tcp_flags ?? 0;
    const names = (
      [
        [0x02, "SYN"],
        [0x01, "FIN"],
        [0x04, "RST"],
        [0x08, "PSH"],
        [0x10, "ACK"],
        [0x20, "URG"],
      ] as const
    )
      .filter(([b]) => fl & b)
      .map(([, n]) => n);
    return `TCP ${sp} → ${dp} [${names.join(", ")}] len=${fr.payload_len}`;
  }
  if (f.proto === 17) return `UDP ${sp} → ${dp} ${f.app_proto ? f.app_proto.toUpperCase() + " " : ""}len=${fr.payload_len}`;
  return `IP proto ${f.proto} len=${fr.payload_len}`;
}

function flowFrames(flowId: number): FrameRef[] {
  requireOpen();
  const f = flowById.get(flowId);
  if (!f) throw err("not_found", `flow ${flowId}`);
  return data.frames
    .slice(f.first_frame - 1, f.last_frame)
    .filter((fr) => fr.flow_id === flowId)
    .map((fr) => ({
      frame_no: fr.frame_no,
      ts: fr.ts,
      caplen: fr.caplen,
      wirelen: fr.wirelen,
      direction: fr.direction,
      tcp_flags: fr.tcp_flags,
      payload_len: fr.payload_len,
      summary: frameSummary(fr, f),
    }));
}

async function packet(frameNo: number): Promise<PacketView> {
  requireOpen();
  if (!packets) packets = (await import("../../../crates/walleye-core/mock/packets.json")).default as unknown as Record<string, PacketView>;
  const p = packets[String(frameNo)];
  if (!p) throw err("not_found", `mock dataset has no bytes for frame ${frameNo}`);
  return p;
}

function autocomplete(partial: string, cursorPos: number): Suggestion[] {
  const cur = Math.min(Math.max(0, cursorPos), partial.length);
  const before = partial.slice(0, cur);
  const m = /[\s(]([^\s(]*)$/.exec(" " + before);
  const word = m ? m[1]! : "";
  const start = cur - word.length;
  const prev = before.slice(0, start).trim().split(/\s+/).pop() ?? "";
  const mk = (label: string, kind: Suggestion["kind"], detail: string | null = null): Suggestion => ({
    label,
    insert_text: label,
    kind,
    detail,
    replace_start: start,
    replace_end: cur,
  });
  const out: Suggestion[] = [];
  if (FILTER_FIELDS.some((f) => f.name === prev)) {
    out.push(...FILTER_OPERATORS.filter((o) => o.startsWith(word)).map((o) => mk(o, "operator")));
  } else if (prev === "host" || prev === "src" || prev === "dst") {
    const hosts = [...new Set(data.flows.map((f) => f.src_ip))].sort();
    out.push(...hosts.filter((h) => h.startsWith(word)).slice(0, 20).map((h) => mk(h, "value", "host")));
  } else {
    out.push(...FILTER_FIELDS.filter((f) => f.name.startsWith(word)).map((f) => mk(f.name, "field", f.doc)));
    if (word) out.push(...FILTER_KEYWORDS.filter((k) => k.startsWith(word)).map((k) => mk(k, "keyword")));
    if (start === 0)
      out.push(
        ...state.saved
          .filter((s) => s.name.toLowerCase().startsWith(word.toLowerCase()))
          .map((s) => ({ label: s.name, insert_text: s.filter, kind: "saved" as const, detail: s.filter, replace_start: 0, replace_end: partial.length })),
      );
  }
  return out.slice(0, 50);
}

function mergeEvidence(evs: Evidence[]): Evidence {
  const flows = new Set<number>();
  const frames = new Set<number>();
  let total = 0;
  let truncated = false;
  for (const e of evs) {
    e.flow_ids.forEach((x) => flows.add(x));
    e.frame_nos.forEach((x) => frames.add(x));
    total += e.total;
    truncated ||= e.truncated;
  }
  return { flow_ids: [...flows], frame_nos: [...frames], truncated, total };
}

function resolve(ev: EvidenceRef): Evidence {
  switch (ev.kind) {
    case "frame": {
      const fr = data.frames[ev.frame_no - 1];
      if (!fr) throw err("not_found", `frame ${ev.frame_no}`);
      return { flow_ids: fr.flow_id === null ? [] : [fr.flow_id], frame_nos: [ev.frame_no], truncated: false, total: 1 };
    }
    case "flow": {
      const f = flowById.get(ev.flow_id);
      if (!f) throw err("not_found", `flow ${ev.flow_id}`);
      return { flow_ids: [ev.flow_id], frame_nos: [f.first_frame], truncated: false, total: 1 };
    }
    case "finding": {
      const f = data.findings.find((x) => x.finding_id === ev.finding_id);
      if (!f) throw err("not_found", `finding ${ev.finding_id}`);
      return mergeEvidence(f.reasons.map((r) => r.evidence));
    }
    case "ioc": {
      const i = data.iocs.find((x) => x.ioc_id === ev.ioc_id);
      if (!i) throw err("not_found", `ioc ${ev.ioc_id}`);
      return i.evidence;
    }
    default:
      return { flow_ids: [], frame_nos: [], truncated: false, total: 0 };
  }
}

function findings(filter: FindingsFilter | null): Finding[] {
  requireOpen();
  return data.findings
    .filter(
      (f) =>
        !filter ||
        ((filter.min_score == null || f.score >= filter.min_score) &&
          (filter.detector == null || f.detector === filter.detector) &&
          (filter.entity == null || f.entity === filter.entity) &&
          (filter.time_range == null || (f.ts_first < filter.time_range.end && f.ts_last >= filter.time_range.start))),
    )
    .map((f) => ({ ...f, verdict: state.verdicts.get(f.finding_id)?.verdict ?? null }))
    .sort((a, b) => b.score - a.score);
}

function getCase(caseId: string): Case {
  requireOpen();
  checkCase(caseId);
  return { case_id: caseId, capture: data.capture, pins: [...state.pins], verdicts: [...state.verdicts.values()], queries: [...state.queries] };
}

type Handler = (a: Record<string, unknown>) => unknown;
const s = (a: Record<string, unknown>, k: string) => a[k] as string;

const handlers: Record<string, Handler> = {
  open_capture: (a) => {
    if (!s(a, "path")?.trim()) throw err("invalid_argument", "empty path");
    const id = `job-${++state.nextId}`;
    state.jobs.set(id, { start: Date.now(), cancelled: false });
    return id;
  },
  ingest_status: (a): IngestStatus => {
    const id = s(a, "job_id");
    const j = state.jobs.get(id);
    if (!j) throw err("not_found", `job ${id}`);
    const ms = Date.now() - j.start;
    const frac = Math.min(1, ms / INGEST_MS);
    const total = data.capture.size_bytes;
    const phase = j.cancelled ? "cancelled" : frac >= 1 ? "done" : frac < 0.1 ? "hashing" : frac < 0.85 ? "indexing" : "detecting";
    if (phase === "done") state.open = true;
    return {
      job_id: id,
      phase,
      pct: Math.round(frac * 100),
      bytes_done: Math.floor(total * frac),
      bytes_total: total,
      eta_s: phase === "done" ? null : Math.max(0, INGEST_MS - ms) / 1000,
      error: null,
      resumed: false,
      session: phase === "done" ? session() : null,
    };
  },
  cancel_ingest: (a) => {
    const j = state.jobs.get(s(a, "job_id"));
    if (!j) throw err("not_found", `job ${s(a, "job_id")}`);
    j.cancelled = true;
    return null;
  },
  current_capture: () => {
    try {
      requireOpen();
      return session();
    } catch {
      return null;
    }
  },
  query: (a) => query(a.req as QueryRequest),
  timeline: (a) => timeline(a.req as TimelineRequest),
  flow_frames: (a) => flowFrames(a.flow_id as number),
  packet: (a) => packet(a.frame_no as number),
  autocomplete: (a) => autocomplete(s(a, "partial_filter"), a.cursor_pos as number),
  list_saved_queries: () => [...state.saved],
  save_query: (a) => {
    const q = a.query as SavedQuery;
    if (!q.name.trim()) throw err("invalid_argument", "name is empty");
    mockParseFilter(q.filter);
    state.saved = [...state.saved.filter((x) => x.name !== q.name), q];
    return null;
  },
  delete_saved_query: (a) => {
    state.saved = state.saved.filter((x) => x.name !== s(a, "name"));
    return null;
  },
  findings: (a) => findings((a.filter as FindingsFilter | null) ?? null),
  set_verdict: (a) => {
    requireOpen();
    const id = s(a, "finding_id");
    if (!data.findings.some((f) => f.finding_id === id)) throw err("not_found", `finding ${id}`);
    state.verdicts.set(id, { finding_id: id, verdict: a.verdict as VerdictEntry["verdict"], note: s(a, "note") ?? "", at: nowUs() });
    return null;
  },
  iocs: (a) => {
    requireOpen();
    checkCase(s(a, "case_id"));
    return data.iocs;
  },
  export_iocs: (a) => {
    requireOpen();
    checkCase(s(a, "case_id"));
    return `/tmp/walleye-mock/${data.capture.capture_id}/exports/iocs.${a.format === "csv" ? "csv" : "json"}`;
  },
  get_case: (a) => getCase(s(a, "case_id")),
  case_pin: (a) => {
    requireOpen();
    checkCase(s(a, "case_id"));
    const evidence = a.evidence as EvidenceRef;
    const pin: Pin = { pin_id: `pin-${++state.nextId}`, evidence, note: s(a, "note") ?? "", resolved: resolve(evidence), created_at: nowUs() };
    state.pins.push(pin);
    return pin;
  },
  case_unpin: (a) => {
    checkCase(s(a, "case_id"));
    const n = state.pins.length;
    state.pins = state.pins.filter((p) => p.pin_id !== s(a, "pin_id"));
    if (state.pins.length === n) throw err("not_found", `pin ${s(a, "pin_id")}`);
    return null;
  },
  export_report: (a) => {
    requireOpen();
    checkCase(s(a, "case_id"));
    if (a.format === "pdf") throw err("invalid_argument", "mock backend exports Markdown only");
    return `/tmp/walleye-mock/${data.capture.capture_id}/exports/report.md`;
  },
};

/** Simulated latency so loading states are visible; 0 under Vitest. */
const LATENCY_MS = import.meta.env?.MODE === "test" ? 0 : 30;

export async function mockInvoke(cmd: string, args: Record<string, unknown>): Promise<unknown> {
  const h = handlers[cmd];
  if (!h) throw err("internal", `unknown command ${cmd}`);
  if (LATENCY_MS) await new Promise((r) => setTimeout(r, LATENCY_MS));
  return await h(args);
}
