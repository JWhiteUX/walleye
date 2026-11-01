// Lane layout, hit-testing and bucket -> column aggregation. Pure; see
// layout.test.ts. All coordinates are CSS px relative to the canvas.
//
// Lanes are keyed by host (IP captures: marks are flow starts per EventKind)
// or by device (802.11 captures, `Lanes.lane_kind = "device"`: marks are
// frames per Wi-Fi class, from the `wifi_*` bucket counts).
import type { Bucket } from "../shared/bindings/Bucket";
import type { EventKind } from "../shared/bindings/EventKind";
import type { Lane } from "../shared/bindings/Lane";
import type { LaneKind } from "../shared/bindings/LaneKind";
import type { TimeRange } from "../shared/bindings/TimeRange";
import { MARK_ENCODING, scoreBand, type MarkKind, type WifiMarkKind } from "../shared/encoding";
import { macSpoken } from "../shared/wifi";
import { xToTime } from "./scale";

/** Fixed draw order; also the row order of marks inside a lane. */
export const KINDS: EventKind[] = ["dns", "tls", "http", "bulk", "other"];
/** Mark rows of a device lane (802.11). */
export const DEVICE_KINDS: WifiMarkKind[] = ["wifi_mgmt", "wifi_probe", "wifi_data", "wifi_deauth"];

export const kindsFor = (k: LaneKind): readonly MarkKind[] => (k === "device" ? DEVICE_KINDS : KINDS);

export const LAYOUT = {
  axisH: 24,
  laneH: 36,
  labelW: 184,
  /** Device lanes: a 17-character MAC, the randomized chip and a score badge. */
  deviceLabelW: 248,
  padR: 10,
  /** Vertical padding inside a lane, above the first and below the last mark row. */
  lanePad: 3,
} as const;

export const labelWidth = (k: LaneKind): number => (k === "device" ? LAYOUT.deviceLabelW : LAYOUT.labelW);

/** Per-kind counts; only the kinds of the lane's kind set are present. */
export type Counts = Partial<Record<MarkKind, number>>;
export const zeroCounts = (kinds: readonly MarkKind[] = KINDS): Counts => {
  const c: Counts = {};
  for (const k of kinds) c[k] = 0;
  return c;
};

export interface Column {
  /** Column start (µs). */
  t: number;
  counts: Counts;
  total: number;
}

export interface LaneModel {
  host: string;
  isOther: boolean;
  total: number;
  maxScore: number | null;
  /** Per-kind totals over all buckets (for the accessible table). */
  kindTotals: Counts;
  columns: Column[];
}

export const plotX = (labelW: number = LAYOUT.labelW): number => labelW;
export const plotWidth = (width: number, labelW: number = LAYOUT.labelW): number => Math.max(1, width - labelW - LAYOUT.padR);
export const contentHeight = (laneCount: number): number => LAYOUT.axisH + laneCount * LAYOUT.laneH;

/** Top of lane `i` on the canvas, given the scroll offset of the lane area. */
export const laneTop = (i: number, scrollY: number): number => LAYOUT.axisH + i * LAYOUT.laneH - scrollY;

/** Centre y of the mark row for `kind` in a lane whose top is `top`. */
export function rowY(top: number, kind: MarkKind, kinds: readonly MarkKind[] = KINDS): number {
  const rowH = (LAYOUT.laneH - 2 * LAYOUT.lanePad) / kinds.length;
  return top + LAYOUT.lanePad + rowH * (kinds.indexOf(kind) + 0.5);
}

/** Lanes with any part inside the viewport: [first, last) indices. */
export function visibleLanes(count: number, scrollY: number, viewportH: number): [number, number] {
  const first = Math.max(0, Math.floor(scrollY / LAYOUT.laneH));
  const last = Math.min(count, Math.ceil((scrollY + viewportH - LAYOUT.axisH) / LAYOUT.laneH));
  return [first, Math.max(first, last)];
}

export type Hit =
  | { region: "axis"; t: number }
  | { region: "label"; lane: number }
  | { region: "plot"; lane: number | null; t: number }
  | { region: "none" };

export function hitTest(
  x: number,
  y: number,
  opts: { width: number; height: number; scrollY: number; laneCount: number; view: TimeRange; labelW?: number },
): Hit {
  const { width, height, scrollY, laneCount, view } = opts;
  if (x < 0 || y < 0 || x > width || y > height) return { region: "none" };
  const px = plotX(opts.labelW);
  const pw = plotWidth(width, opts.labelW);
  const t = xToTime(Math.min(Math.max(x, px), px + pw), view, px, pw);
  if (y < LAYOUT.axisH) return x >= px ? { region: "axis", t } : { region: "none" };
  const idx = Math.floor((y - LAYOUT.axisH + scrollY) / LAYOUT.laneH);
  const lane = idx >= 0 && idx < laneCount ? idx : null;
  if (x < px) return lane === null ? { region: "none" } : { region: "label", lane };
  if (x > px + pw) return { region: "none" };
  return { region: "plot", lane, t };
}

/** Start of the column containing `t` (columns are aligned to `origin`). */
export const columnStart = (t: number, origin: number, colUs: number): number =>
  origin + Math.floor((t - origin) / colUs) * colUs;

const bucketCount = (b: Bucket, k: MarkKind): number => b[k] ?? 0;

/** Merge sparse buckets into fixed-width columns aligned to `origin`. */
export function aggregateColumns(buckets: Bucket[], origin: number, colUs: number, kinds: readonly MarkKind[] = KINDS): Column[] {
  if (kinds !== KINDS) return aggregateGeneric(buckets, origin, colUs, kinds);
  // Host lanes (the hot path, 50 lanes x 2000 buckets): buckets arrive sorted
  // by t (one pass, appends only). If one is out of order, fall back to a map
  // so the result stays correct.
  const out: Column[] = [];
  let last: Column | null = null;
  let c: Record<EventKind, number> | null = null;
  for (let i = 0; i < buckets.length; i++) {
    const b = buckets[i]!;
    const t = origin + Math.floor((b.t - origin) / colUs) * colUs;
    if (last === null || t > last.t) {
      c = { dns: 0, tls: 0, http: 0, bulk: 0, other: 0 };
      last = { t, counts: c, total: 0 };
      out.push(last);
    } else if (t < last.t) return aggregateGeneric(buckets, origin, colUs, kinds);
    c!.dns += b.dns;
    c!.tls += b.tls;
    c!.http += b.http;
    c!.bulk += b.bulk;
    c!.other += b.other;
    last.total += b.dns + b.tls + b.http + b.bulk + b.other;
  }
  return out;
}

function aggregateGeneric(buckets: Bucket[], origin: number, colUs: number, kinds: readonly MarkKind[]): Column[] {
  const byT = new Map<number, Column>();
  for (const b of buckets) {
    const t = columnStart(b.t, origin, colUs);
    let cur = byT.get(t);
    if (!cur) byT.set(t, (cur = { t, counts: zeroCounts(kinds), total: 0 }));
    for (const k of kinds) {
      const n = bucketCount(b, k);
      cur.counts[k] = (cur.counts[k] ?? 0) + n;
      cur.total += n;
    }
  }
  return [...byT.values()].sort((a, b) => a.t - b.t);
}

export function buildLaneModels(lanes: Lane[], origin: number, colUs: number, kinds: readonly MarkKind[] = KINDS): LaneModel[] {
  return lanes.map((l) => {
    const columns = aggregateColumns(l.buckets, origin, colUs, kinds);
    // Sum the (few) columns rather than the (many) buckets.
    const kindTotals = zeroCounts(kinds);
    for (const c of columns) for (const k of kinds) kindTotals[k] = (kindTotals[k] ?? 0) + (c.counts[k] ?? 0);
    return { host: l.host, isOther: l.is_other, total: l.total, maxScore: l.max_score, kindTotals, columns };
  });
}

/** Find the column of a lane that contains `t` (binary search). */
export function columnAt(lane: LaneModel, t: number, colUs: number): Column | null {
  const cols = lane.columns;
  let lo = 0;
  let hi = cols.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const c = cols[mid]!;
    if (t < c.t) hi = mid - 1;
    else if (t >= c.t + colUs) lo = mid + 1;
    else return c;
  }
  return null;
}

/** Badge text for a lane's highest score: number + band word, never colour alone. */
export function scoreBadge(score: number | null): { text: string; band: ReturnType<typeof scoreBand> } | null {
  if (score === null || score === undefined) return null;
  const band = scoreBand(score);
  return { text: `${Math.round(score)} ${band.label}`, band };
}

/**
 * Text name of a lane (tooltip, accessible table, announcements). Device
 * lanes say "randomized" in words; the canvas draws an "R" chip instead.
 */
export function laneLabel(l: Pick<LaneModel, "host" | "isOther">, kind: LaneKind = "host"): string {
  if (kind === "device") return l.isOther ? "Other devices" : macSpoken(l.host);
  return l.isOther ? "Other hosts" : l.host;
}

/** "DNS 2 · TLS 1" for the kinds with a non-zero count. */
export function describeCounts(c: Counts, kinds: readonly MarkKind[] = KINDS): string {
  const parts = kinds.filter((k) => (c[k] ?? 0) > 0).map((k) => `${MARK_ENCODING[k].label} ${c[k]}`);
  return parts.length ? parts.join(" · ") : kinds === KINDS ? "no flows" : "no frames";
}
