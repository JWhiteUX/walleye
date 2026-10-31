// Pure time-scale math for the timeline: µs <-> px, zoom, pan, ticks and
// bucket sizing. No DOM, no React; covered by scale.test.ts.
import type { TimeRange } from "../shared/bindings/TimeRange";

/** Smallest visible span: 10 ms. Below this buckets stop being meaningful. */
export const MIN_SPAN_US = 10_000;
/** The backend keeps at most this many buckets (CONTRACTS §3). */
export const MAX_BUCKETS = 2000;

export const span = (r: TimeRange): number => r.end - r.start;

export function timeToX(t: number, view: TimeRange, x0: number, width: number): number {
  return x0 + ((t - view.start) / span(view)) * width;
}

export function xToTime(x: number, view: TimeRange, x0: number, width: number): number {
  return view.start + ((x - x0) / width) * span(view);
}

/** Keep `v` inside `extent` with a span in [MIN_SPAN_US, extent span]. */
export function clampView(v: TimeRange, extent: TimeRange): TimeRange {
  const ext = span(extent);
  const s = Math.min(Math.max(span(v), Math.min(MIN_SPAN_US, ext)), ext);
  const start = Math.min(Math.max(v.start, extent.start), extent.end - s);
  return { start, end: start + s };
}

/** Zoom by `factor` (< 1 zooms in) keeping `anchor` at the same screen position. */
export function zoomAt(view: TimeRange, extent: TimeRange, factor: number, anchor: number): TimeRange {
  const s = span(view);
  const frac = s > 0 ? (anchor - view.start) / s : 0.5;
  // Clamp the span first so the anchor stays put when zoom hits a limit.
  const next = Math.min(Math.max(s * factor, Math.min(MIN_SPAN_US, span(extent))), span(extent));
  const start = anchor - frac * next;
  return clampView({ start, end: start + next }, extent);
}

export function pan(view: TimeRange, extent: TimeRange, deltaUs: number): TimeRange {
  return clampView({ start: view.start + deltaUs, end: view.end + deltaUs }, extent);
}

/** Integer µs range suitable for IPC (half-open, so round outwards). */
export function toIpcRange(r: TimeRange): TimeRange {
  return { start: Math.floor(r.start), end: Math.ceil(r.end) };
}

const MS = 1000;
const S = 1_000_000;
const MIN = 60 * S;
const H = 60 * MIN;
/** Candidate tick steps, µs. Aligned to UTC multiples. */
export const TICK_STEPS = [
  1 * MS, 2 * MS, 5 * MS, 10 * MS, 20 * MS, 50 * MS, 100 * MS, 200 * MS, 500 * MS,
  1 * S, 2 * S, 5 * S, 10 * S, 15 * S, 30 * S,
  1 * MIN, 2 * MIN, 5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN,
  1 * H, 2 * H, 3 * H, 6 * H, 12 * H, 24 * H,
];

/** Smallest step whose ticks are at least `minPx` apart. */
export function tickStep(view: TimeRange, width: number, minPx = 90): number {
  const pxPerUs = width / Math.max(1, span(view));
  for (const s of TICK_STEPS) if (s * pxPerUs >= minPx) return s;
  return TICK_STEPS[TICK_STEPS.length - 1]!;
}

export function ticks(view: TimeRange, width: number, minPx = 90): { step: number; values: number[] } {
  const step = tickStep(view, width, minPx);
  const values: number[] = [];
  for (let t = Math.ceil(view.start / step) * step; t < view.end && values.length < 500; t += step) values.push(t);
  return { step, values };
}

/** Axis label for a tick, precision chosen from the step. UTC. */
export function tickLabel(t: number, step: number): string {
  const iso = new Date(Math.floor(t / 1000)).toISOString(); // 2026-03-12T09:04:05.123Z
  if (step >= 24 * H) return iso.slice(0, 10);
  if (step >= MIN) return iso.slice(11, 16);
  if (step >= S) return iso.slice(11, 19);
  return iso.slice(11, 23);
}

const NICE = [1, 2, 5];
/** Round up to 1-2-5 × 10^k. */
export function niceCeil(x: number): number {
  if (x <= 1) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(x)));
  for (const n of NICE) if (n * p >= x) return n * p;
  return 10 * p;
}

/**
 * Bucket width (ms) to request for a view: about one bucket per `pxPerBucket`
 * px, never more than MAX_BUCKETS, rounded to a 1-2-5 value so small pans
 * reuse the same grid.
 */
export function chooseBucketMs(view: TimeRange, plotWidth: number, pxPerBucket = 2): number {
  const target = Math.max(1, Math.min(MAX_BUCKETS, Math.floor(plotWidth / pxPerBucket)));
  const spanMs = Math.max(1, span(view) / 1000);
  return niceCeil(spanMs / target);
}

/**
 * Width in µs of one drawn column: a whole number of buckets, at least
 * `minPx` wide, so marks never overlap horizontally.
 */
export function columnUs(bucketUs: number, view: TimeRange, plotWidth: number, minPx = 7): number {
  const bucketPx = (bucketUs / Math.max(1, span(view))) * plotWidth;
  const k = Math.max(1, Math.ceil(minPx / Math.max(bucketPx, 1e-9)));
  return k * bucketUs;
}
