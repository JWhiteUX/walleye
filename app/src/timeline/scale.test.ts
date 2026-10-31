import { describe, expect, it } from "vitest";
import {
  chooseBucketMs,
  clampView,
  columnUs,
  MAX_BUCKETS,
  MIN_SPAN_US,
  niceCeil,
  pan,
  span,
  tickLabel,
  ticks,
  timeToX,
  toIpcRange,
  xToTime,
  zoomAt,
} from "./scale";

const EXT = { start: 1_000_000_000, end: 1_000_000_000 + 3600e6 }; // one hour

describe("time <-> px", () => {
  it("maps view edges to plot edges and round-trips", () => {
    const view = { start: 100, end: 1100 };
    expect(timeToX(100, view, 50, 500)).toBe(50);
    expect(timeToX(1100, view, 50, 500)).toBe(550);
    for (const x of [50, 123.4, 300, 550]) expect(timeToX(xToTime(x, view, 50, 500), view, 50, 500)).toBeCloseTo(x, 9);
  });
});

describe("clampView", () => {
  it("keeps the view inside the extent without changing its span", () => {
    const v = clampView({ start: EXT.start - 10e6, end: EXT.start + 50e6 }, EXT);
    expect(v.start).toBe(EXT.start);
    expect(span(v)).toBe(60e6);
    const w = clampView({ start: EXT.end - 10e6, end: EXT.end + 50e6 }, EXT);
    expect(w.end).toBe(EXT.end);
    expect(span(w)).toBe(60e6);
  });
  it("enforces the minimum and maximum span", () => {
    expect(span(clampView({ start: EXT.start, end: EXT.start + 5 }, EXT))).toBe(MIN_SPAN_US);
    expect(clampView({ start: EXT.start - 1e9, end: EXT.end + 1e9 }, EXT)).toEqual(EXT);
  });
  it("handles an extent shorter than the minimum span", () => {
    const tiny = { start: 0, end: 500 };
    expect(clampView({ start: 0, end: 10 }, tiny)).toEqual(tiny);
  });
});

describe("zoomAt", () => {
  it("keeps the anchor at the same fraction of the view", () => {
    const view = { start: EXT.start, end: EXT.start + 1000e6 };
    const anchor = EXT.start + 250e6;
    const z = zoomAt(view, EXT, 0.5, anchor);
    expect(span(z)).toBe(500e6);
    expect((anchor - z.start) / span(z)).toBeCloseTo(0.25, 9);
  });
  it("zooming out past the extent returns the extent", () => {
    expect(zoomAt(EXT, EXT, 4, EXT.start + 1e6)).toEqual(EXT);
  });
  it("stops at the minimum span with the anchor still in view", () => {
    let v = EXT;
    const anchor = EXT.start + 1800e6;
    for (let i = 0; i < 60; i++) v = zoomAt(v, EXT, 0.5, anchor);
    expect(span(v)).toBe(MIN_SPAN_US);
    expect(anchor).toBeGreaterThanOrEqual(v.start);
    expect(anchor).toBeLessThanOrEqual(v.end);
  });
});

describe("pan", () => {
  it("shifts and clamps at the extent edges", () => {
    const view = { start: EXT.start + 100e6, end: EXT.start + 200e6 };
    expect(pan(view, EXT, 50e6)).toEqual({ start: EXT.start + 150e6, end: EXT.start + 250e6 });
    expect(pan(view, EXT, -1e12)).toEqual({ start: EXT.start, end: EXT.start + 100e6 });
    expect(pan(view, EXT, 1e12)).toEqual({ start: EXT.end - 100e6, end: EXT.end });
  });
});

describe("ticks", () => {
  it("spaces ticks at least minPx apart and aligns to the step", () => {
    const { step, values } = ticks(EXT, 900, 90);
    expect((step / span(EXT)) * 900).toBeGreaterThanOrEqual(90);
    expect(values.length).toBeGreaterThan(3);
    for (const t of values) {
      expect(t % step).toBe(0);
      expect(t).toBeGreaterThanOrEqual(EXT.start);
      expect(t).toBeLessThan(EXT.end);
    }
  });
  it("labels with precision matching the step (UTC)", () => {
    const t = Date.UTC(2026, 2, 12, 9, 4, 5, 123) * 1000;
    expect(tickLabel(t, 5 * 60e6)).toBe("09:04");
    expect(tickLabel(t, 10e6)).toBe("09:04:05");
    expect(tickLabel(t, 100e3)).toBe("09:04:05.123");
  });
});

describe("bucket sizing", () => {
  it("rounds up to 1-2-5 values", () => {
    expect([0.3, 1, 1.5, 3, 7, 20, 21, 4999].map(niceCeil)).toEqual([1, 1, 2, 5, 10, 20, 50, 5000]);
  });
  it("never asks for more than MAX_BUCKETS buckets", () => {
    for (const w of [100, 1000, 4000, 20000]) {
      const ms = chooseBucketMs(EXT, w);
      expect(span(EXT) / 1000 / ms).toBeLessThanOrEqual(MAX_BUCKETS);
      expect(ms).toBeGreaterThanOrEqual(1);
    }
  });
  it("columns are whole buckets and at least minPx wide", () => {
    const bucketUs = 1e6;
    const c = columnUs(bucketUs, EXT, 1000, 7);
    expect(c % bucketUs).toBe(0);
    expect((c / span(EXT)) * 1000).toBeGreaterThanOrEqual(7);
    expect(columnUs(60e6, { start: 0, end: 120e6 }, 1000, 7)).toBe(60e6);
  });
});

describe("toIpcRange", () => {
  it("rounds outwards to integers", () => {
    expect(toIpcRange({ start: 10.7, end: 20.2 })).toEqual({ start: 10, end: 21 });
  });
});
