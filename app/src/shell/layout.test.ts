import { describe, expect, it } from "vitest";
import {
  DEFAULT_LAYOUT,
  fitLayout,
  PACKETS_MIN,
  SIDE_MAX_SHARE,
  SIDE_MIN,
  SPLITTERS_H,
  TABLE_MIN,
  TIMELINE_MIN,
  type Layout,
} from "./layout";

const layout = (over: Partial<Layout> = {}): Layout => ({ ...DEFAULT_LAYOUT, timelineH: 200, packetsH: 300, sideW: 380, ...over });
const WIDE = 2000;
/** Main-column height at which `l` fits exactly with the table at TABLE_MIN. */
const exactH = (l: Layout) => l.timelineH! + l.packetsH! + TABLE_MIN + SPLITTERS_H;

describe("fitLayout", () => {
  it("leaves the stored sizes alone when they fit", () => {
    const l = layout();
    expect(fitLayout(l, WIDE, exactH(l) + 50)).toEqual({ timelineH: 200, packetsH: 300, sideW: 380 });
    expect(fitLayout(l, WIDE, exactH(l))).toEqual({ timelineH: 200, packetsH: 300, sideW: 380 });
  });

  it("shrinks timeline and packets in proportion to their stored sizes", () => {
    const l = layout({ timelineH: 200, packetsH: 300 });
    const out = fitLayout(l, WIDE, exactH(l) - 100);
    // 100 px cut, split 2:3.
    expect(out.timelineH).toBe(160);
    expect(out.packetsH).toBe(240);
    expect(exactH(l) - 100 - SPLITTERS_H - out.timelineH - out.packetsH).toBe(TABLE_MIN);
  });

  it("never goes below the pane minimums", () => {
    const out = fitLayout(layout(), WIDE, 100);
    expect(out.timelineH).toBe(TIMELINE_MIN);
    expect(out.packetsH).toBe(PACKETS_MIN);
  });

  it("gives the packet pane the rest of the cut once the timeline hits its minimum", () => {
    const l = layout({ timelineH: 100, packetsH: 600 });
    const mainH = TIMELINE_MIN + 200 + TABLE_MIN + SPLITTERS_H;
    const out = fitLayout(l, WIDE, mainH);
    expect(out.timelineH).toBe(TIMELINE_MIN);
    expect(out.packetsH).toBe(200);
  });

  it("keeps the session table at TABLE_MIN whenever the minimums allow it", () => {
    const floor = TIMELINE_MIN + PACKETS_MIN + TABLE_MIN + SPLITTERS_H;
    for (const l of [layout(), layout({ timelineH: 90, packetsH: 700 }), layout({ timelineH: 500, packetsH: 130 }), layout({ timelineH: 333, packetsH: 333 })]) {
      for (let mainH = floor; mainH <= exactH(l) + 40; mainH += 7) {
        const out = fitLayout(l, WIDE, mainH);
        const table = mainH - SPLITTERS_H - out.timelineH - out.packetsH;
        expect(table, `layout ${l.timelineH}/${l.packetsH} at ${mainH}`).toBeGreaterThanOrEqual(TABLE_MIN);
        expect(out.timelineH).toBeGreaterThanOrEqual(TIMELINE_MIN);
        expect(out.packetsH).toBeGreaterThanOrEqual(PACKETS_MIN);
        expect(out.timelineH).toBeLessThanOrEqual(l.timelineH!);
        expect(out.packetsH).toBeLessThanOrEqual(l.packetsH!);
      }
    }
  });

  it("clamps the side column between SIDE_MIN and its share of the window", () => {
    expect(fitLayout(layout({ sideW: 100 }), WIDE, 0).sideW).toBe(SIDE_MIN);
    expect(fitLayout(layout({ sideW: 5000 }), 1000, 0).sideW).toBe(Math.floor(1000 * SIDE_MAX_SHARE));
    expect(fitLayout(layout({ sideW: 380 }), WIDE, 0).sideW).toBe(380);
    // On a window too narrow for the share, SIDE_MIN still wins.
    const narrow = Math.floor((SIDE_MIN - 40) / SIDE_MAX_SHARE);
    expect(fitLayout(layout({ sideW: 5000 }), narrow, 0).sideW).toBe(SIDE_MIN);
    // Unknown width (not measured yet) passes the stored width through.
    expect(fitLayout(layout({ sideW: 5000 }), 0, 0).sideW).toBe(5000);
  });

  it("passes heights through when the main column is not measured yet", () => {
    const out = fitLayout(layout({ timelineH: 900, packetsH: 900 }), WIDE, 0);
    expect(out).toEqual({ timelineH: 900, packetsH: 900, sideW: 380 });
  });

  it("sizes panes by share of the window until the user resizes them", () => {
    const auto = { ...DEFAULT_LAYOUT };
    const small = fitLayout(auto, 1024, 680);
    const big = fitLayout(auto, 1728, 1030);
    expect(big.timelineH).toBeGreaterThan(small.timelineH);
    expect(big.packetsH).toBeGreaterThan(small.packetsH);
    expect(big.sideW).toBeGreaterThan(small.sideW);
    for (const [out, w, h] of [[small, 1024, 680], [big, 1728, 1030]] as const) {
      expect(h - SPLITTERS_H - out.timelineH - out.packetsH).toBeGreaterThanOrEqual(TABLE_MIN);
      expect(out.sideW).toBeLessThanOrEqual(Math.floor(w * SIDE_MAX_SHARE));
    }
  });
});
