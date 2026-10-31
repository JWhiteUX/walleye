import { describe, expect, it } from "vitest";
import type { Bucket } from "../shared/bindings/Bucket";
import { EVENT_ENCODING } from "../shared/encoding";
import {
  aggregateColumns,
  buildLaneModels,
  columnAt,
  contentHeight,
  describeCounts,
  hitTest,
  KINDS,
  laneLabel,
  LAYOUT,
  plotWidth,
  rowY,
  scoreBadge,
  visibleLanes,
} from "./layout";

const b = (t: number, p: Partial<Bucket> = {}): Bucket => ({ t, dns: 0, tls: 0, http: 0, bulk: 0, other: 0, ...p });
const VIEW = { start: 0, end: 1_000_000 };
const OPTS = { width: 1000, height: 300, scrollY: 0, laneCount: 5, view: VIEW };

describe("hitTest", () => {
  it("finds the axis, labels, plot and outside regions", () => {
    expect(hitTest(500, 10, OPTS).region).toBe("axis");
    expect(hitTest(50, 10, OPTS).region).toBe("none");
    expect(hitTest(50, LAYOUT.axisH + 1, OPTS)).toEqual({ region: "label", lane: 0 });
    expect(hitTest(50, LAYOUT.axisH + LAYOUT.laneH * 2 + 5, OPTS)).toEqual({ region: "label", lane: 2 });
    const p = hitTest(LAYOUT.labelW, LAYOUT.axisH + 1, OPTS);
    expect(p).toEqual({ region: "plot", lane: 0, t: 0 });
    expect(hitTest(-1, 50, OPTS).region).toBe("none");
    expect(hitTest(1001, 50, OPTS).region).toBe("none");
  });
  it("maps plot x to time", () => {
    const x = LAYOUT.labelW + plotWidth(1000) / 2;
    const h = hitTest(x, LAYOUT.axisH + 1, OPTS);
    expect(h.region).toBe("plot");
    if (h.region === "plot") expect(h.t).toBeCloseTo(500_000, 6);
  });
  it("accounts for the vertical scroll offset", () => {
    const h = hitTest(50, LAYOUT.axisH + 1, { ...OPTS, scrollY: LAYOUT.laneH * 3 });
    expect(h).toEqual({ region: "label", lane: 3 });
  });
  it("below the last lane: plot without a lane, no label", () => {
    const y = LAYOUT.axisH + LAYOUT.laneH * 5 + 2;
    expect(hitTest(50, y, { ...OPTS, height: 400 }).region).toBe("none");
    const h = hitTest(600, y, { ...OPTS, height: 400 });
    expect(h.region === "plot" && h.lane).toBeNull();
  });
});

describe("visibleLanes", () => {
  it("returns the lanes intersecting the viewport", () => {
    expect(visibleLanes(50, 0, LAYOUT.axisH + LAYOUT.laneH * 3)).toEqual([0, 3]);
    expect(visibleLanes(50, LAYOUT.laneH * 10 + 1, LAYOUT.axisH + LAYOUT.laneH * 3)).toEqual([10, 14]);
    expect(visibleLanes(4, 0, 2000)).toEqual([0, 4]);
    expect(contentHeight(4)).toBe(LAYOUT.axisH + 4 * LAYOUT.laneH);
  });
});

describe("aggregateColumns", () => {
  it("sums buckets into aligned columns per kind", () => {
    const cols = aggregateColumns([b(0, { dns: 1 }), b(10, { tls: 2 }), b(25, { dns: 3, bulk: 1 })], 0, 20);
    expect(cols).toEqual([
      { t: 0, counts: { dns: 1, tls: 2, http: 0, bulk: 0, other: 0 }, total: 3 },
      { t: 20, counts: { dns: 3, tls: 0, http: 0, bulk: 1, other: 0 }, total: 4 },
    ]);
  });
  it("is correct for unsorted input", () => {
    const cols = aggregateColumns([b(25, { http: 1 }), b(0, { dns: 1 }), b(30, { http: 1 })], 0, 20);
    expect(cols.map((c) => [c.t, c.total])).toEqual([
      [0, 1],
      [20, 2],
    ]);
  });
  it("aligns to an origin that is not zero", () => {
    expect(aggregateColumns([b(105), b(95)], 100, 10).map((c) => c.t)).toEqual([90, 100]);
  });
});

describe("lane models", () => {
  const lanes = buildLaneModels(
    [
      { host: "10.0.0.23", is_other: false, total: 3, max_score: 92, buckets: [b(0, { tls: 2 }), b(40, { dns: 1 })] },
      { host: "other", is_other: true, total: 1, max_score: null, buckets: [b(0, { other: 1 })] },
    ],
    0,
    20,
  );
  it("keeps per-kind totals and columns", () => {
    expect(lanes[0]!.kindTotals.tls).toBe(2);
    expect(lanes[0]!.kindTotals.dns).toBe(1);
    expect(columnAt(lanes[0]!, 45, 20)?.counts.dns).toBe(1);
    expect(columnAt(lanes[0]!, 25, 20)).toBeNull();
  });
  it("labels the other lane", () => {
    expect(laneLabel(lanes[1]!)).toBe("Other hosts");
    expect(laneLabel(lanes[0]!)).toBe("10.0.0.23");
  });
});

describe("encoding (shape + label, not colour alone)", () => {
  it("each kind has a distinct shape and a text label", () => {
    const shapes = KINDS.map((k) => EVENT_ENCODING[k].shape);
    expect(new Set(shapes).size).toBe(KINDS.length);
    expect(shapes).toEqual(["circle", "square", "triangle", "diamond", "cross"]);
    for (const k of KINDS) expect(EVENT_ENCODING[k].label).toMatch(/\w/);
  });
  it("each kind gets its own row inside a lane", () => {
    const ys = KINDS.map((k) => rowY(0, k));
    expect(new Set(ys).size).toBe(KINDS.length);
    for (const y of ys) {
      expect(y).toBeGreaterThan(0);
      expect(y).toBeLessThan(LAYOUT.laneH);
    }
  });
  it("score badges carry the number and band word", () => {
    expect(scoreBadge(92)?.text).toBe("92 High");
    expect(scoreBadge(64)?.text).toBe("64 Medium");
    expect(scoreBadge(22)?.text).toBe("22 Low");
    expect(scoreBadge(null)).toBeNull();
  });
  it("describes counts in words", () => {
    expect(describeCounts({ dns: 2, tls: 0, http: 1, bulk: 0, other: 0 })).toBe("DNS 2 · HTTP 1");
    expect(describeCounts({ dns: 0, tls: 0, http: 0, bulk: 0, other: 0 })).toBe("no flows");
  });
});
