import { expect, test } from "@playwright/test";

// Redraw cost for the acceptance target: ~50 lanes × 2000 buckets, through
// the real renderer in Chromium (see app/src/timeline/bench.ts).
type Stats = { median: number; p95: number; max: number };
type Bench = {
  rebuild_and_draw_ms: Stats;
  draw_only_ms: Stats;
  aggregate_ms: Stats;
  all_lanes_snapshot_ms: number;
};

for (const size of [
  { name: "in-app panel size", width: undefined, height: undefined, dpr: undefined },
  { name: "1400x600 @2x", width: 1400, height: 600, dpr: 2 },
]) {
  test(`timeline redraw, 50 lanes x 2000 buckets (${size.name})`, async ({ page }) => {
    await page.goto("/?mock=open");
    await expect(page.getByTestId("timeline-panel")).toHaveAttribute("data-state", "ready");
    const r = (await page.evaluate(
      (o) =>
        (window as unknown as { __walleyeE2E: { timelineBench: (o: object) => Promise<unknown> } }).__walleyeE2E.timelineBench({
          lanes: 50,
          buckets: 2000,
          runs: 40,
          ...o,
        }),
      { width: size.width, height: size.height, dpr: size.dpr },
    )) as Bench;
    console.log(`[perf] ${size.name}: ${JSON.stringify(r)}`);
    // Hover/brush/scroll frames redraw only: must fit a 60 fps frame.
    expect(r.draw_only_ms.median).toBeLessThan(16.7);
    // Data/zoom changes also rebuild columns: well inside the 1 s pivot budget.
    expect(r.rebuild_and_draw_ms.p95).toBeLessThan(50);
  });
}
