// Brush math (pointer drags and keyboard brushing). Pure; see brush.test.ts.
import type { TimeRange } from "../shared/bindings/TimeRange";

/** Drags shorter than this are clicks, not brushes. */
export const MIN_BRUSH_PX = 3;

/**
 * Turn two brush endpoints into a half-open integer µs range clamped to the
 * extent, or null when the result is empty.
 */
export function normalizeBrush(a: number, b: number, extent: TimeRange): TimeRange | null {
  const lo = Math.max(extent.start, Math.min(a, b));
  const hi = Math.min(extent.end, Math.max(a, b));
  const start = Math.floor(lo);
  const end = Math.ceil(hi);
  return end > start ? { start, end } : null;
}

export function inRange(t: number, r: TimeRange | null): boolean {
  return !!r && t >= r.start && t < r.end;
}

/** Keyboard cursor step: one drawn column, but at least 1/200 of the view. */
export function cursorStep(colUs: number, view: TimeRange): number {
  return Math.max(colUs, (view.end - view.start) / 200);
}

export interface KeyBrushState {
  /** Keyboard cursor time (µs), or null before the first arrow press. */
  cursor: number | null;
  /** Where a shift-extend started; null when not extending. */
  anchor: number | null;
}

export interface KeyBrushResult extends KeyBrushState {
  /** New brush to commit; undefined = leave the brush alone. */
  brush?: TimeRange | null;
}

/**
 * One arrow-key press. Plain arrows move the cursor (and end an extension);
 * shift+arrows extend a brush from the anchor to the cursor.
 */
export function keyBrush(
  st: KeyBrushState,
  dir: -1 | 1,
  extend: boolean,
  step: number,
  view: TimeRange,
  extent: TimeRange,
): KeyBrushResult {
  const from = st.cursor ?? (view.start + view.end) / 2;
  const moved = st.cursor === null && !extend ? from : from + dir * step;
  const cursor = Math.min(extent.end, Math.max(extent.start, moved));
  if (!extend) return { cursor, anchor: null };
  const anchor = st.anchor ?? from;
  return { cursor, anchor, brush: normalizeBrush(anchor, cursor, extent) };
}
