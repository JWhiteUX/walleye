import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

// Against the Vite dev server + browser mock. `window.__walleyeE2E` is the
// dev-only hook from app/src/timeline/testHooks.ts.
type Sel = { time_range: { start: number; end: number } | null; hosts: string[]; flow_ids: number[]; frame_no: number | null };
const selection = (page: Page) =>
  page.evaluate(() => (window as unknown as { __walleyeE2E: { selection: () => Sel } }).__walleyeE2E.selection());

const LABEL_W = 184; // LAYOUT.labelW
const AXIS_H = 24; // LAYOUT.axisH
const LANE_H = 36; // LAYOUT.laneH

async function openTimeline(page: Page) {
  await page.goto("/?mock=open");
  const panel = page.getByTestId("timeline-panel");
  await expect(panel).toHaveAttribute("data-state", "ready");
  await expect(panel).toHaveAttribute("data-loading", "false");
  const canvas = page.getByTestId("timeline-canvas");
  await expect.poll(async () => Number(await canvas.getAttribute("data-draws"))).toBeGreaterThan(0);
  const box = (await canvas.boundingBox())!;
  return { panel, canvas, box };
}
const viewSpan = async (page: Page) => {
  const p = page.getByTestId("timeline-panel");
  return Number(await p.getAttribute("data-view-end")) - Number(await p.getAttribute("data-view-start"));
};

test("brushing sets the selection time_range and redraws the timeline", async ({ page }) => {
  const { canvas, box } = await openTimeline(page);
  expect((await selection(page)).time_range).toBeNull();
  const draws0 = Number(await canvas.getAttribute("data-draws"));
  const before = await canvas.screenshot();

  const y = box.y + AXIS_H + LANE_H / 2;
  await page.mouse.move(box.x + LABEL_W + 100, y);
  await page.mouse.down();
  await page.mouse.move(box.x + LABEL_W + 250, y, { steps: 5 });
  await page.mouse.move(box.x + LABEL_W + 400, y, { steps: 5 });
  const t0 = Date.now();
  await page.mouse.up();
  await expect.poll(async () => (await selection(page)).time_range).not.toBeNull();
  const brushMs = Date.now() - t0;
  console.log(`[timeline] brush -> selection.time_range visible to the test after ${brushMs} ms (incl. CDP round-trips)`);

  const r = (await selection(page)).time_range!;
  expect(r.end).toBeGreaterThan(r.start);
  await expect(page.getByTestId("timeline-brush-readout")).toContainText("Time range:");
  expect(Number(await canvas.getAttribute("data-draws"))).toBeGreaterThan(draws0);
  const after = await canvas.screenshot();
  expect(after.equals(before)).toBe(false);

  // Brushing does not re-scope the timeline itself (it stays the context).
  await expect(page.getByTestId("timeline-panel")).toHaveAttribute("data-loading", "false");

  // Clicking outside the brush clears it.
  await page.mouse.click(box.x + box.width - 20, y);
  await expect.poll(async () => (await selection(page)).time_range).toBeNull();
});

test("keyboard: cursor, shift+arrow brushing, Escape, lane focus and host toggle", async ({ page }) => {
  const { canvas } = await openTimeline(page);
  await canvas.focus();
  await page.keyboard.press("ArrowRight");
  for (let i = 0; i < 5; i++) await page.keyboard.press("Shift+ArrowRight");
  const r = (await selection(page)).time_range;
  expect(r).not.toBeNull();
  expect(r!.end).toBeGreaterThan(r!.start);
  await expect(page.getByTestId("timeline-live")).toContainText("Time range");
  await page.keyboard.press("Escape");
  expect((await selection(page)).time_range).toBeNull();

  const firstHost = await page.getByTestId("timeline-summary").locator("tbody tr").first().getAttribute("data-host");
  await page.keyboard.press("ArrowDown");
  await expect(page.getByTestId("timeline-live")).toContainText(`Lane 1 of`);
  await page.keyboard.press("Enter");
  expect((await selection(page)).hosts).toEqual([firstHost]);
});

test("zoom (wheel, keys) and pan change the view window and re-query", async ({ page }) => {
  const { canvas, box } = await openTimeline(page);
  const full = await viewSpan(page);
  await page.mouse.move(box.x + LABEL_W + 200, box.y + AXIS_H + 20);
  await page.mouse.wheel(0, -400);
  await expect.poll(() => viewSpan(page)).toBeLessThan(full);
  await expect(page.getByTestId("timeline-panel")).toHaveAttribute("data-loading", "false");
  const zoomed = await viewSpan(page);
  const start0 = Number(await page.getByTestId("timeline-panel").getAttribute("data-view-start"));
  await canvas.focus();
  await page.keyboard.press("]");
  await expect
    .poll(async () => Number(await page.getByTestId("timeline-panel").getAttribute("data-view-start")))
    .toBeGreaterThan(start0);
  expect(await viewSpan(page)).toBeCloseTo(zoomed, -3);
  await page.keyboard.press("=");
  await expect.poll(() => viewSpan(page)).toBeLessThan(zoomed);
  await page.keyboard.press("0");
  await expect.poll(() => viewSpan(page)).toBe(full);
});

test("lane label click toggles the host; hover shows per-kind counts", async ({ page }) => {
  const { box } = await openTimeline(page);
  const firstHost = await page.getByTestId("timeline-summary").locator("tbody tr").first().getAttribute("data-host");
  await page.mouse.click(box.x + 60, box.y + AXIS_H + LANE_H / 2);
  expect((await selection(page)).hosts).toEqual([firstHost]);
  await page.mouse.click(box.x + 60, box.y + AXIS_H + LANE_H / 2);
  expect((await selection(page)).hosts).toEqual([]);

  await page.mouse.move(box.x + LABEL_W + 300, box.y + AXIS_H + LANE_H / 2);
  const tip = page.locator(".wl-tl-tip");
  await expect(tip).toBeVisible();
  for (const label of ["DNS:", "TLS:", "HTTP:", "Bulk transfer:", "Other:"]) await expect(tip).toContainText(label);
  await expect(tip).toContainText(firstHost!);
});

test.describe("high-DPI", () => {
  test.use({ deviceScaleFactor: 2 });
  test("canvas backing store matches devicePixelRatio", async ({ page }) => {
    const { canvas } = await openTimeline(page);
    const dims = await canvas.evaluate((c: HTMLCanvasElement) => ({ w: c.width, h: c.height, cw: c.clientWidth, ch: c.clientHeight }));
    expect(dims.w).toBe(dims.cw * 2);
    expect(dims.h).toBe(dims.ch * 2);
  });
});

test("report snapshot is a PNG of all lanes", async ({ page }) => {
  await openTimeline(page);
  const b64 = await page.evaluate(() =>
    (window as unknown as { __walleyeE2E: { timelineSnapshot: () => string | null } }).__walleyeE2E.timelineSnapshot(),
  );
  expect(b64).toBeTruthy();
  const buf = Buffer.from(b64!, "base64");
  expect(buf.subarray(1, 4).toString()).toBe("PNG");
  const height = buf.readUInt32BE(20);
  const lanes = await page.getByTestId("timeline-summary").locator("tbody tr").count();
  expect(height).toBe((AXIS_H + lanes * LANE_H) * 2);
});

test("timeline panel has no WCAG 2.1 AA violations (axe)", async ({ page }) => {
  await openTimeline(page);
  const res = await new AxeBuilder({ page })
    .include("[data-testid=timeline-panel]")
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  console.log(`[axe] timeline: ${res.violations.length} violations, ${res.passes.length} passing rules`);
  expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
});

test.describe("dark theme", () => {
  test.use({ colorScheme: "dark" });
  test("timeline panel has no WCAG 2.1 AA violations in the dark theme (axe)", async ({ page }) => {
  await openTimeline(page);
    const res = await new AxeBuilder({ page })
      .include("[data-testid=timeline-panel]")
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    console.log(`[axe] timeline (dark): ${res.violations.length} violations, ${res.passes.length} passing rules`);
    expect(res.violations.map((v) => v.id)).toEqual([]);
  });
});

// Cross-panel: brushing narrows the session table. The table is virtualized,
// so compare its total row count, not the number of rendered rows.
test("brush narrows the session table", async ({ page }) => {
  const { box } = await openTimeline(page);
  const count = page.getByTestId("table-count");
  await expect(count).toContainText(/\d/);
  const total = async () => Number(((await count.textContent()) ?? "").replace(/[^0-9]/g, ""));
  const before = await total();
  expect(before).toBeGreaterThan(1);
  const y = box.y + AXIS_H + LANE_H / 2;
  await page.mouse.move(box.x + LABEL_W + 10, y);
  await page.mouse.down();
  await page.mouse.move(box.x + LABEL_W + 40, y, { steps: 4 });
  await page.mouse.up();
  await expect.poll(total, { timeout: 1000 }).toBeLessThan(before);
});
