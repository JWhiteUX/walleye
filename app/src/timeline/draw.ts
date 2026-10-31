// Canvas 2D renderer for the timeline. One call draws a whole frame from a
// plain `Scene`; marks are batched into one path per kind, so cost grows with
// visible columns, not with buckets. Captured strings are drawn with
// fillText (never parsed as markup).
import type { TimeRange } from "../shared/bindings/TimeRange";
import type { Shape } from "../shared/encoding";
import { EVENT_ENCODING } from "../shared/encoding";
import {
  columnStart,
  KINDS,
  LAYOUT,
  type LaneModel,
  laneLabel,
  laneTop,
  plotWidth,
  plotX,
  rowY,
  scoreBadge,
  visibleLanes,
} from "./layout";
import { ticks, tickLabel, timeToX } from "./scale";

export interface Theme {
  bg: string;
  surface: string;
  surface2: string;
  border: string;
  text: string;
  muted: string;
  accent: string;
  focus: string;
  selection: string;
  kinds: Record<(typeof KINDS)[number], string>;
  score: { High: string; Medium: string; Low: string };
  fontUi: string;
  fontMono: string;
}

export interface Scene {
  width: number;
  height: number;
  dpr: number;
  scrollY: number;
  view: TimeRange;
  lanes: LaneModel[];
  colUs: number;
  /** Columns are aligned to this time (the data's range start). */
  colOrigin: number;
  selectedHosts: ReadonlySet<string>;
  brush: TimeRange | null;
  /** Brush being dragged, not yet committed. */
  draft: TimeRange | null;
  cursor: number | null;
  focusedLane: number | null;
  /** Whether the canvas has keyboard focus (draw the focus ring). */
  focused: boolean;
  hover: { lane: number; t: number } | null;
  message?: string | null;
}

/** The subset of the 2D context the shape builder uses (testable with a fake). */
export interface PathSink {
  moveTo(x: number, y: number): void;
  lineTo(x: number, y: number): void;
  arc(x: number, y: number, r: number, a0: number, a1: number): void;
  rect(x: number, y: number, w: number, h: number): void;
  closePath(): void;
}

/** Append one mark of `shape` centred at (cx, cy) with radius r to the path. */
export function shapePath(p: PathSink, shape: Shape, cx: number, cy: number, r: number): void {
  switch (shape) {
    case "circle":
      p.moveTo(cx + r, cy);
      p.arc(cx, cy, r, 0, Math.PI * 2);
      return;
    case "square": {
      const s = r * 0.85;
      p.rect(cx - s, cy - s, 2 * s, 2 * s);
      return;
    }
    case "triangle":
      p.moveTo(cx, cy - r);
      p.lineTo(cx + r, cy + r * 0.85);
      p.lineTo(cx - r, cy + r * 0.85);
      p.closePath();
      return;
    case "diamond":
      p.moveTo(cx, cy - r);
      p.lineTo(cx + r, cy);
      p.lineTo(cx, cy + r);
      p.lineTo(cx - r, cy);
      p.closePath();
      return;
    case "cross": // stroked, not filled
      p.moveTo(cx - r, cy - r);
      p.lineTo(cx + r, cy + r);
      p.moveTo(cx + r, cy - r);
      p.lineTo(cx - r, cy + r);
      return;
  }
}

/** Shapes drawn as outlines rather than fills. */
export const STROKED: ReadonlySet<Shape> = new Set(["cross"]);

const MARK_R = 2.6;
const MARK_R_BIG = 3.2;
/** Sprite box in CSS px (fits the big mark plus its stroke). */
const SPRITE_CSS = 10;
const SPRITE_HALF = SPRITE_CSS / 2;
const sprites = new Map<string, HTMLCanvasElement>();

function sprite(shape: Shape, colour: string, big: boolean, dpr: number): HTMLCanvasElement {
  const key = `${shape}|${colour}|${big ? 1 : 0}|${dpr}`;
  let c = sprites.get(key);
  if (c) return c;
  c = document.createElement("canvas");
  c.width = c.height = Math.ceil(SPRITE_CSS * dpr);
  const g = c.getContext("2d");
  if (g) {
    g.setTransform(c.width / SPRITE_CSS, 0, 0, c.height / SPRITE_CSS, 0, 0);
    g.beginPath();
    shapePath(g, shape, SPRITE_HALF, SPRITE_HALF, big ? MARK_R_BIG : MARK_R);
    if (STROKED.has(shape)) {
      g.strokeStyle = colour;
      g.lineWidth = big ? 1.9 : 1.4;
      g.stroke();
    } else {
      g.fillStyle = colour;
      g.fill();
    }
  }
  if (sprites.size > 256) sprites.clear();
  sprites.set(key, c);
  return c;
}

/** Index of the first column starting at or after `t` (binary search). */
function firstColumn(cols: { t: number }[], t: number): number {
  let lo = 0;
  let hi = cols.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (cols[mid]!.t < t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function clipText(ctx: CanvasRenderingContext2D, s: string, maxW: number): string {
  if (ctx.measureText(s).width <= maxW) return s;
  let lo = 0;
  let hi = s.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ctx.measureText(s.slice(0, mid) + "…").width <= maxW) lo = mid;
    else hi = mid - 1;
  }
  return s.slice(0, lo) + "…";
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

export function drawTimeline(ctx: CanvasRenderingContext2D, s: Scene, th: Theme): void {
  const { width: W, height: H, dpr, view } = s;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.globalAlpha = 1;
  ctx.fillStyle = th.surface;
  ctx.fillRect(0, 0, W, H);

  const px = plotX();
  const pw = plotWidth(W);
  const X = (t: number) => timeToX(t, view, px, pw);
  const [first, last] = visibleLanes(s.lanes.length, s.scrollY, H);
  const tk = ticks(view, pw);

  // --- lane area (clipped below the axis) ---
  ctx.save();
  ctx.beginPath();
  ctx.rect(0, LAYOUT.axisH, W, H - LAYOUT.axisH);
  ctx.clip();

  for (let i = first; i < last; i++) {
    const l = s.lanes[i]!;
    const top = laneTop(i, s.scrollY);
    const selected = !l.isOther && s.selectedHosts.has(l.host);
    ctx.fillStyle = selected ? th.selection : i % 2 ? th.surface2 : th.surface;
    ctx.fillRect(0, top, W, LAYOUT.laneH);
  }

  // Grid lines.
  ctx.strokeStyle = th.border;
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (const t of tk.values) {
    const x = Math.round(X(t)) + 0.5;
    ctx.moveTo(x, LAYOUT.axisH);
    ctx.lineTo(x, H);
  }
  ctx.moveTo(px - 0.5, LAYOUT.axisH);
  ctx.lineTo(px - 0.5, H);
  ctx.stroke();

  // Hover column.
  if (s.hover && s.hover.lane >= first && s.hover.lane < last) {
    const c0 = columnStart(s.hover.t, s.colOrigin, s.colUs);
    const top = laneTop(s.hover.lane, s.scrollY);
    ctx.globalAlpha = 0.35;
    ctx.fillStyle = th.accent;
    ctx.fillRect(X(c0), top, Math.max(1, X(c0 + s.colUs) - X(c0)), LAYOUT.laneH);
    ctx.globalAlpha = 1;
  }

  // Marks: one batched path per kind (and size).
  ctx.save();
  ctx.beginPath();
  ctx.rect(px, LAYOUT.axisH, pw, H - LAYOUT.axisH);
  ctx.clip();
  const half = s.colUs / 2;
  // Each mark is a pre-rendered sprite (per kind, size, colour and dpr):
  // drawImage is far cheaper than tessellating thousands of path shapes.
  const snap = (v: number) => Math.round(v * dpr) / dpr;
  for (const kind of KINDS) {
    const colour = th.kinds[kind];
    const small = sprite(EVENT_ENCODING[kind].shape, colour, false, dpr);
    const big = sprite(EVENT_ENCODING[kind].shape, colour, true, dpr);
    for (let i = first; i < last; i++) {
      const lane = s.lanes[i]!;
      const y = snap(rowY(laneTop(i, s.scrollY), kind)) - SPRITE_HALF;
      const cols = lane.columns;
      // Columns are sorted: skip straight to the first one in view.
      for (let j = firstColumn(cols, view.start - s.colUs); j < cols.length; j++) {
        const c = cols[j]!;
        if (c.t > view.end) break;
        const n = c.counts[kind];
        if (n === 0) continue;
        ctx.drawImage(n > 2 ? big : small, snap(X(c.t + half)) - SPRITE_HALF, y, SPRITE_CSS, SPRITE_CSS);
      }
    }
  }
  ctx.restore();

  // Brush (committed) and draft.
  const drawBrush = (r: TimeRange, dashed: boolean) => {
    const x0 = Math.max(px, X(r.start));
    const x1 = Math.min(px + pw, X(r.end));
    if (x1 < px || x0 > px + pw) return;
    ctx.globalAlpha = 0.16;
    ctx.fillStyle = th.accent;
    ctx.fillRect(x0, LAYOUT.axisH, Math.max(1, x1 - x0), H - LAYOUT.axisH);
    ctx.globalAlpha = 1;
    ctx.strokeStyle = th.accent;
    ctx.lineWidth = 1.5;
    ctx.setLineDash(dashed ? [4, 3] : []);
    ctx.beginPath();
    ctx.moveTo(x0, LAYOUT.axisH);
    ctx.lineTo(x0, H);
    ctx.moveTo(x1, LAYOUT.axisH);
    ctx.lineTo(x1, H);
    ctx.stroke();
    ctx.setLineDash([]);
  };
  if (s.brush) drawBrush(s.brush, false);
  if (s.draft) drawBrush(s.draft, true);

  // Keyboard cursor.
  if (s.cursor !== null && s.cursor >= view.start && s.cursor <= view.end) {
    const x = Math.round(X(s.cursor)) + 0.5;
    ctx.strokeStyle = th.focus;
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 2]);
    ctx.beginPath();
    ctx.moveTo(x, LAYOUT.axisH);
    ctx.lineTo(x, H);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Lane labels (drawn over the marks' left edge).
  ctx.textBaseline = "middle";
  for (let i = first; i < last; i++) {
    const l = s.lanes[i]!;
    const top = laneTop(i, s.scrollY);
    const mid = top + LAYOUT.laneH / 2;
    const selected = !l.isOther && s.selectedHosts.has(l.host);
    ctx.fillStyle = selected ? th.selection : i % 2 ? th.surface2 : th.surface;
    ctx.fillRect(0, top, px - 1, LAYOUT.laneH);
    let x = 8;
    if (selected) {
      // Check mark: selection is shown by a glyph, not colour alone.
      ctx.strokeStyle = th.text;
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.moveTo(x, mid);
      ctx.lineTo(x + 3, mid + 3);
      ctx.lineTo(x + 8, mid - 4);
      ctx.stroke();
    }
    x += 12;
    const badge = scoreBadge(l.maxScore);
    const badgeW = badge ? 58 : 0;
    ctx.font = `${l.isOther ? "italic " : ""}${selected ? "600 " : ""}12px ${l.isOther ? th.fontUi : th.fontMono}`;
    ctx.fillStyle = l.isOther ? th.muted : th.text;
    ctx.fillText(clipText(ctx, laneLabel(l), px - x - badgeW - 10), x, mid);
    if (badge) {
      const bx = px - badgeW - 6;
      const by = mid - 8;
      const colour = th.score[badge.band.label];
      roundRect(ctx, bx, by, badgeW, 16, 3);
      // Band also shown by badge style: High = filled, Medium = outlined, Low = dashed outline.
      if (badge.band.label === "High") {
        ctx.fillStyle = colour;
        ctx.fill();
        ctx.fillStyle = th.bg;
      } else {
        ctx.strokeStyle = colour;
        ctx.lineWidth = 1.2;
        ctx.setLineDash(badge.band.label === "Low" ? [2, 2] : []);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = th.text;
      }
      ctx.font = `600 10px ${th.fontUi}`;
      ctx.textAlign = "center";
      ctx.fillText(badge.text, bx + badgeW / 2, mid + 0.5);
      ctx.textAlign = "left";
    }
    if (s.focused && s.focusedLane === i) {
      ctx.strokeStyle = th.focus;
      ctx.lineWidth = 2;
      ctx.strokeRect(1, top + 1, W - 2, LAYOUT.laneH - 2);
    }
  }
  ctx.restore();

  // --- axis ---
  ctx.fillStyle = th.surface;
  ctx.fillRect(0, 0, W, LAYOUT.axisH);
  ctx.strokeStyle = th.border;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, LAYOUT.axisH - 0.5);
  ctx.lineTo(W, LAYOUT.axisH - 0.5);
  ctx.stroke();
  ctx.font = `11px ${th.fontMono}`;
  ctx.fillStyle = th.muted;
  ctx.textBaseline = "middle";
  ctx.fillText("UTC", 8, LAYOUT.axisH / 2);
  for (const t of tk.values) {
    const x = X(t);
    ctx.beginPath();
    ctx.moveTo(Math.round(x) + 0.5, LAYOUT.axisH - 5);
    ctx.lineTo(Math.round(x) + 0.5, LAYOUT.axisH);
    ctx.stroke();
    ctx.fillText(tickLabel(t, tk.step), x + 3, LAYOUT.axisH / 2);
  }
  if (s.brush) {
    const x0 = Math.max(px, X(s.brush.start));
    const x1 = Math.min(px + pw, X(s.brush.end));
    if (x1 > x0) {
      ctx.fillStyle = th.accent;
      ctx.fillRect(x0, LAYOUT.axisH - 3, x1 - x0, 3);
    }
  }

  if (s.message) {
    ctx.font = `12px ${th.fontUi}`;
    ctx.fillStyle = th.muted;
    ctx.textAlign = "center";
    ctx.fillText(s.message, px + pw / 2, LAYOUT.axisH + 40);
    ctx.textAlign = "left";
  }
  if (s.focused && s.focusedLane === null) {
    ctx.strokeStyle = th.focus;
    ctx.lineWidth = 2;
    ctx.strokeRect(1, 1, W - 2, H - 2);
  }
}

/** Resolve theme tokens from CSS custom properties (theme.css). */
export function readTheme(el: Element): Theme {
  const cs = getComputedStyle(el);
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback;
  return {
    bg: v("--wl-bg", "#0f1216"),
    surface: v("--wl-surface", "#171b21"),
    surface2: v("--wl-surface-2", "#1f252d"),
    border: v("--wl-border", "#313945"),
    text: v("--wl-text", "#e6e9ee"),
    muted: v("--wl-text-muted", "#a3acb9"),
    accent: v("--wl-accent", "#6cb6ff"),
    focus: v("--wl-focus", "#ffd166"),
    selection: v("--wl-selection", "#23415f"),
    kinds: {
      dns: v(EVENT_ENCODING.dns.cssVar, "#79c0ff"),
      tls: v(EVENT_ENCODING.tls.cssVar, "#7ee787"),
      http: v(EVENT_ENCODING.http.cssVar, "#d2a8ff"),
      bulk: v(EVENT_ENCODING.bulk.cssVar, "#ffa657"),
      other: v(EVENT_ENCODING.other.cssVar, "#a3acb9"),
    },
    score: {
      High: v("--wl-score-high", "#ff7b72"),
      Medium: v("--wl-score-medium", "#e3b341"),
      Low: v("--wl-score-low", "#8b949e"),
    },
    fontUi: v("--wl-font-ui", "system-ui, sans-serif"),
    fontMono: v("--wl-font-mono", "ui-monospace, monospace"),
  };
}
