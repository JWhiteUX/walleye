// Typed IPC client. The ONLY place the UI talks to the backend.
//
// Inside Tauri, calls go through `invoke()` to the `#[tauri::command]`s in
// app/src-tauri/src/commands.rs. In a plain browser (Vite dev server,
// Playwright, Vitest) there is no Tauri runtime, so calls go to the in-browser
// mock (./mock.ts), which serves the same dataset as the Rust MockBackend.
//
// Argument names are snake_case on both sides (commands use
// `rename_all = "snake_case"`). Keep this file in sync with
// crates/walleye-core/src/backend.rs and docs/CONTRACTS.md §3.

import type { ApiError } from "./bindings/ApiError";
import type { Case } from "./bindings/Case";
import type { CaptureSession } from "./bindings/CaptureSession";
import type { EvidenceRef } from "./bindings/EvidenceRef";
import type { Finding } from "./bindings/Finding";
import type { FindingsFilter } from "./bindings/FindingsFilter";
import type { FrameRef } from "./bindings/FrameRef";
import type { TimeRange } from "./bindings/TimeRange";
import type { IngestStatus } from "./bindings/IngestStatus";
import type { Ioc } from "./bindings/Ioc";
import type { IocFormat } from "./bindings/IocFormat";
import type { Lanes } from "./bindings/Lanes";
import type { PacketView } from "./bindings/PacketView";
import type { Page } from "./bindings/Page";
import type { Pin } from "./bindings/Pin";
import type { QueryRequest } from "./bindings/QueryRequest";
import type { ReportFormat } from "./bindings/ReportFormat";
import type { SavedQuery } from "./bindings/SavedQuery";
import type { Suggestion } from "./bindings/Suggestion";
import type { TimelineRequest } from "./bindings/TimelineRequest";
import type { Verdict } from "./bindings/Verdict";

/** Error thrown by every api call. `code`/`span` come from the backend. */
export class WalleyeError extends Error {
  readonly code: ApiError["code"];
  readonly span: ApiError["span"];
  constructor(e: ApiError) {
    super(e.message);
    this.name = "WalleyeError";
    this.code = e.code;
    this.span = e.span ?? null;
  }
}

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function asApiError(e: unknown): ApiError {
  if (e && typeof e === "object" && "code" in e && "message" in e) return e as ApiError;
  return { code: "internal", message: String(e), span: null };
}

type Args = Record<string, unknown>;

/**
 * DEV/TEST ONLY: `?bridge=http://127.0.0.1:<port>&token=<t>` routes calls to
 * tools/walleye-devbridge (the real engine over loopback) instead of the
 * browser mock, so Playwright can exercise the real backend. Ignored inside
 * Tauri and in production builds.
 */
function devBridge(): { url: string; token: string } | null {
  if (!import.meta.env.DEV || typeof window === "undefined") return null;
  const q = new URLSearchParams(window.location.search);
  const url = q.get("bridge");
  const token = q.get("token");
  if (!url || !token || !/^http:\/\/127\.0\.0\.1:\d+$/.test(url)) return null;
  return { url, token };
}

async function call<T>(cmd: string, args: Args = {}): Promise<T> {
  try {
    if (isTauri()) {
      const { invoke } = await import("@tauri-apps/api/core");
      return await invoke<T>(cmd, args);
    }
    const bridge = devBridge();
    if (bridge) {
      const r = await fetch(`${bridge.url}/invoke/${cmd}`, {
        method: "POST",
        headers: { authorization: `Bearer ${bridge.token}`, "content-type": "application/json" },
        body: JSON.stringify(args),
      });
      const body: unknown = await r.json();
      if (!r.ok) throw body;
      return body as T;
    }
    // The browser mock is for development and tests only. A production build
    // outside Tauri fails closed instead of showing invented findings.
    if (!import.meta.env.DEV && import.meta.env.MODE !== "test") {
      throw { code: "internal", message: "Walleye must run inside the desktop app.", span: null };
    }
    const { mockInvoke } = await import("./mock");
    return (await mockInvoke(cmd, args)) as T;
  } catch (e) {
    throw new WalleyeError(asApiError(e));
  }
}

export const api = {
  // capture lifecycle
  openCapture: (path: string) => call<string>("open_capture", { path }),
  ingestStatus: (job_id: string) => call<IngestStatus>("ingest_status", { job_id }),
  cancelIngest: (job_id: string) => call<null>("cancel_ingest", { job_id }),
  currentCapture: () => call<CaptureSession | null>("current_capture"),

  // query
  query: (req: QueryRequest) => call<Page>("query", { req }),
  timeline: (req: TimelineRequest) => call<Lanes>("timeline", { req }),
  flowFrames: (flow_id: number) => call<FrameRef[]>("flow_frames", { flow_id }),
  /** 802.11 frames to/from/through a MAC (contract v2), ≤ 10 000, frame order. */
  deviceFrames: (mac: string, time_range: TimeRange | null = null) =>
    call<FrameRef[]>("device_frames", { mac, time_range }),
  packet: (frame_no: number) => call<PacketView>("packet", { frame_no }),
  autocomplete: (partial_filter: string, cursor_pos: number) =>
    call<Suggestion[]>("autocomplete", { partial_filter, cursor_pos }),
  listSavedQueries: () => call<SavedQuery[]>("list_saved_queries"),
  saveQuery: (query: SavedQuery) => call<null>("save_query", { query }),
  deleteSavedQuery: (name: string) => call<null>("delete_saved_query", { name }),

  // detections
  findings: (filter?: FindingsFilter) => call<Finding[]>("findings", { filter: filter ?? null }),
  setVerdict: (finding_id: string, verdict: Verdict, note = "") =>
    call<null>("set_verdict", { finding_id, verdict, note }),

  // IOCs and case
  iocs: (case_id: string) => call<Ioc[]>("iocs", { case_id }),
  exportIocs: (case_id: string, format: IocFormat) => call<string>("export_iocs", { case_id, format }),
  getCase: (case_id: string) => call<Case>("get_case", { case_id }),
  casePin: (case_id: string, evidence: EvidenceRef, note = "") =>
    call<Pin>("case_pin", { case_id, evidence, note }),
  caseUnpin: (case_id: string, pin_id: string) => call<null>("case_unpin", { case_id, pin_id }),
  caseUpdateNote: (case_id: string, pin_id: string, note: string) =>
    call<Pin>("case_update_note", { case_id, pin_id, note }),
  exportReport: (case_id: string, format: ReportFormat, timeline_png_base64?: string) =>
    call<string>("export_report", { case_id, format, timeline_png_base64: timeline_png_base64 ?? null }),
} as const;

/** Native file picker in Tauri; in the browser mock, a fixed fake path. */
export async function pickCaptureFile(): Promise<string | null> {
  if (!isTauri()) {
    // Dev bridge: the capture to open comes from `?capture=<absolute path>`.
    if (devBridge()) return new URLSearchParams(window.location.search).get("capture");
    // `?mock=wifi` picks the 802.11 sample, so re-opening keeps the same capture.
    return new URLSearchParams(window.location.search).get("mock") === "wifi" ? "/mock/lakeside-wifi.pcap" : "/mock/office-beacon.pcap";
  }
  const { open } = await import("@tauri-apps/plugin-dialog");
  const picked = await open({
    multiple: false,
    directory: false,
    filters: [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] }],
  });
  return typeof picked === "string" ? picked : null;
}

export type Api = typeof api;
