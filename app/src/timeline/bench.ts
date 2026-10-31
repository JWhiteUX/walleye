// Dev/test-only redraw benchmark (e2e/timeline-perf.spec.ts). Runs the real
// pipeline on synthetic lanes: buckets -> columns (only on data/zoom change in
// the app) and the canvas draw (every hover/brush/scroll frame). Each timing
// ends with a 1-pixel readback so GPU rasterisation is included.
import type { Lane } from "../shared/bindings/Lane";
import { drawTimeline, readTheme, type Scene } from "./draw";
import { buildLaneModels, contentHeight, plotWidth } from "./layout";
import { columnUs, span } from "./scale";

export interface BenchOptions {
  lanes?: number;
  buckets?: number;
  runs?: number;
  width?: number;
  height?: number;
  dpr?: number;
}

const stats = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const r = (x: number | undefined) => Math.round((x ?? 0) * 100) / 100;
  return { median: r(s[Math.floor(s.length / 2)]), p95: r(s[Math.min(s.length - 1, Math.floor(s.length * 0.95))]), max: r(s[s.length - 1]) };
};

export function syntheticLanes(laneCount: number, bucketCount: number, spanUs: number): Lane[] {
  const bucketUs = spanUs / bucketCount;
  return Array.from({ length: laneCount }, (_, i) => ({
    host: `10.0.${i >> 8}.${i & 255}`,
    is_other: i === laneCount - 1,
    total: bucketCount,
    max_score: i % 3 === 0 ? (i * 7) % 100 : null,
    buckets: Array.from({ length: bucketCount }, (_, j) => ({
      t: j * bucketUs,
      dns: (i + j) % 3,
      tls: (i * j) % 2,
      http: j % 5 === 0 ? 1 : 0,
      bulk: j % 97 === 0 ? 1 : 0,
      other: (i + 2 * j) % 7 === 0 ? 2 : 0,
    })),
  }));
}

export function runTimelineBench(themeSource: Element, o: BenchOptions = {}) {
  const { lanes: laneCount = 50, buckets: bucketCount = 2000, runs = 30 } = o;
  const width = o.width ?? 1200;
  const height = o.height ?? 600;
  const dpr = o.dpr ?? 1;
  const view = { start: 0, end: 3600e6 };
  const lanesIn = syntheticLanes(laneCount, bucketCount, span(view));
  const bucketUs = span(view) / bucketCount;
  const th = readTheme(themeSource);
  const pw = plotWidth(width);
  const colUs = columnUs(bucketUs, view, pw);

  const canvas = document.createElement("canvas");
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const ctx = canvas.getContext("2d", { alpha: false })!;
  const scene = (models: Scene["lanes"], r: number, h = height): Scene => ({
    width,
    height: h,
    dpr,
    scrollY: (r * 37) % Math.max(1, contentHeight(laneCount) - h),
    view,
    lanes: models,
    colUs,
    colOrigin: 0,
    selectedHosts: new Set(["10.0.0.3"]),
    brush: { start: 600e6, end: 1200e6 },
    draft: null,
    cursor: 900e6,
    focusedLane: 2,
    focused: true,
    hover: { lane: 1, t: 1000e6 },
  });

  const agg: number[] = [];
  const draw: number[] = [];
  const full: number[] = [];
  let models = buildLaneModels(lanesIn, 0, colUs);
  for (let r = 0; r < runs; r++) {
    const t0 = performance.now();
    models = buildLaneModels(lanesIn, 0, colUs);
    const t1 = performance.now();
    drawTimeline(ctx, scene(models, r), th);
    ctx.getImageData(0, 0, 1, 1);
    const t2 = performance.now();
    agg.push(t1 - t0);
    draw.push(t2 - t1);
    full.push(t2 - t0);
  }
  // Report export: all 50 lanes in one tall canvas.
  const tallH = contentHeight(laneCount);
  const tall = document.createElement("canvas");
  tall.width = Math.round(width * dpr);
  tall.height = Math.round(tallH * dpr);
  const tctx = tall.getContext("2d", { alpha: false })!;
  const ts = performance.now();
  drawTimeline(tctx, { ...scene(models, 0, tallH), scrollY: 0 }, th);
  tctx.getImageData(0, 0, 1, 1);
  const allLanesMs = Math.round((performance.now() - ts) * 100) / 100;

  return {
    lanes: laneCount,
    buckets: bucketCount,
    width,
    height,
    dpr,
    runs,
    columns_per_lane: models[0]?.columns.length ?? 0,
    /** data/zoom change: buckets -> columns + draw */
    rebuild_and_draw_ms: stats(full),
    /** hover/brush/scroll frame: draw only */
    draw_only_ms: stats(draw),
    aggregate_ms: stats(agg),
    all_lanes_snapshot_ms: allLanesMs,
  };
}
