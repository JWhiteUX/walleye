import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

type Sel = { time_range: { start: number; end: number } | null; hosts: string[]; flow_ids: number[]; frame_no: number | null };
type Hooks = {
  selection: () => Sel;
  selectionActions: () => { setTimeRange: (r: { start: number; end: number } | null) => void };
  loadSession: () => Promise<unknown>;
};
const hooks = <T,>(page: Page, fn: (h: Hooks) => T | Promise<T>) =>
  page.evaluate(fn as never) as Promise<T>;
const selection = (page: Page) => page.evaluate(() => (window as unknown as { __walleyeE2E: Hooks }).__walleyeE2E.selection());

async function openQueue(page: Page) {
  await page.goto("/?mock=open");
  const panel = page.getByTestId("queue-panel");
  const list = panel.getByRole("list", { name: /findings/i });
  await expect(list).toBeVisible();
  const heads = list.locator("li[data-finding-id] > button[aria-expanded]");
  await expect(heads).toHaveCount(4);
  return { panel, list, heads };
}

test("queue is ranked by score with number + band label", async ({ page }) => {
  const { list } = await openQueue(page);
  const nums = await list.locator(".wl-q-num").allTextContents();
  expect(nums.map(Number)).toEqual([92, 81, 64, 22]);
  const bands = await list.locator(".wl-q-band").allTextContents();
  expect(bands).toEqual(["High", "High", "Medium", "Low"]);
  await expect(list.locator("a")).toHaveCount(0); // indicators are never links
});

test("queue → evidence sets the selection (flows, first frame, host)", async ({ page }) => {
  const { panel, heads } = await openQueue(page);
  await heads.first().click();
  const ev = panel.getByTestId("queue-evidence").first();
  await expect(ev).toContainText("56 flows · 56 frames");
  await ev.click();
  const s = await selection(page);
  expect(s.frame_no).toBe(140);
  expect(s.flow_ids).toHaveLength(56);
  expect(s.flow_ids[0]).toBe(27);
  expect(s.hosts).toEqual(["10.0.0.23"]);
  await expect(panel.getByTestId("queue-status")).toContainText("frame 140");
});

// Cross-panel: needs Agent D's real packet pane (a stub in this worktree).
// Once D's pane lands this should pass unchanged.
test.fixme("queue → evidence → packet pane shows the frame", async ({ page }) => {
  const { panel, heads } = await openQueue(page);
  await heads.first().click();
  await panel.getByTestId("queue-evidence").first().click();
  await expect(page.getByTestId("packets-panel")).toContainText("140", { timeout: 1000 });
});

test("verdicts by button and by keyboard (j/k, Enter, v + s/b/r)", async ({ page }) => {
  const { panel, heads } = await openQueue(page);
  await heads.first().click();
  await panel.getByRole("button", { name: "Suspicious", exact: true }).click();
  await expect(panel.getByRole("button", { name: "✓ Suspicious" })).toHaveAttribute("aria-pressed", "true");
  await expect(panel.getByTestId("queue-verdict").first()).toHaveText("Suspicious");

  await heads.first().focus();
  await page.keyboard.press("j");
  await expect(heads.nth(1)).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(heads.nth(1)).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("v");
  await page.keyboard.press("b");
  await expect(panel.getByTestId("queue-verdict").nth(1)).toHaveText("Benign");
  await page.keyboard.press("k");
  await expect(heads.first()).toBeFocused();
});

test("queue follows the selected time range", async ({ page }) => {
  const { panel } = await openQueue(page);
  await expect(panel.getByTestId("queue-count")).toHaveText("4 findings");
  await hooks(page, async () => {
    const h = (window as unknown as { __walleyeE2E: Hooks }).__walleyeE2E;
    const s = (await h.loadSession()) as { capture: { first_ts: number } };
    h.selectionActions().setTimeRange({ start: s.capture.first_ts, end: s.capture.first_ts + 1 });
  });
  await expect(panel.getByTestId("queue-count")).not.toHaveText("4 findings");
  await expect(panel.getByTestId("queue-count")).toContainText("in time range");
  await panel.getByRole("checkbox", { name: /only in selected time range/i }).uncheck();
  await expect(panel.getByTestId("queue-count")).toHaveText("4 findings");
});

test("pin finding goes to the case", async ({ page }) => {
  const { panel, heads } = await openQueue(page);
  await hooks(page, () => (window as unknown as { __walleyeE2E: Hooks }).__walleyeE2E.loadSession());
  await heads.first().click();
  await panel.getByRole("button", { name: "Pin finding" }).click();
  await expect(panel.getByTestId("queue-status")).toContainText("Pinned");
});

test("queue panel has no WCAG 2.1 AA violations (axe), expanded", async ({ page }) => {
  const { heads } = await openQueue(page);
  await heads.first().click();
  await heads.nth(1).click();
  const res = await new AxeBuilder({ page })
    .include("[data-testid=queue-panel]")
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  console.log(`[axe] queue: ${res.violations.length} violations, ${res.passes.length} passing rules`);
  expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
});

test.describe("dark theme", () => {
  test.use({ colorScheme: "dark" });
  test("queue panel has no WCAG 2.1 AA violations in the dark theme (axe)", async ({ page }) => {
  const { heads } = await openQueue(page);
  await heads.first().click();
  await heads.nth(1).click();
    const res = await new AxeBuilder({ page })
      .include("[data-testid=queue-panel]")
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    console.log(`[axe] queue (dark): ${res.violations.length} violations, ${res.passes.length} passing rules`);
    expect(res.violations.map((v) => v.id)).toEqual([]);
  });
});
