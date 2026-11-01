import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import os from "node:os";
import path from "node:path";

// 802.11 sample (`?mock=wifi`, app/src/shared/mockWifi.ts): Wi-Fi tabs, device
// focus driving the packet list, device findings -> evidence -> decoded frame.
// WALLEYE_SHOTS=1 also saves screenshots to the system temp dir.

const SPOOFED = "d6:5e:00:53:de:ad";
// WCAG 2.1 A + AA rules only, as in shell-a11y.spec.ts.
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

type Sel = { device: string | null; flow_ids: number[]; frame_no: number | null };
const selection = (page: Page) =>
  page.evaluate(() => (window as unknown as { __walleyeE2E: { selection: () => Sel } }).__walleyeE2E.selection());

async function shot(page: Page, name: string) {
  if (!process.env.WALLEYE_SHOTS) return;
  const file = path.join(os.tmpdir(), `walleye-wifi-${name}.png`);
  await page.screenshot({ path: file, fullPage: false });
  console.log(`[shot] ${file}`);
}

async function openWifi(page: Page) {
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.goto("/?mock=wifi");
  const table = page.getByTestId("table-panel");
  await expect(table.getByRole("button", { name: "Access points" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("table-count")).toHaveText("8 of 8 rows");
  return table;
}

test("802.11 capture: Wi-Fi tabs only, IP tabs hidden when there are no flows", async ({ page }) => {
  const table = await openWifi(page);
  const tabs = await table.getByRole("group", { name: "View" }).getByRole("button").allTextContents();
  expect(tabs).toEqual(["Access points", "Clients", "Wi-Fi frames"]);
  // Hidden SSID is a styled placeholder, randomized MACs carry a text marker.
  const grid = page.getByTestId("table-grid");
  await expect(grid.locator(".is-placeholder", { hasText: "(hidden)" })).toHaveCount(1);
  await expect(grid.getByText(`${SPOOFED} (rand)`)).toBeVisible();
  await expect(grid.locator("a")).toHaveCount(0);
  // Keyboard: v c / v w switch tabs.
  await page.locator("body").press("v");
  await page.locator("body").press("c");
  await expect(table.getByRole("button", { name: "Clients" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("table-count")).toHaveText("30 of 30 rows");
  await page.locator("body").press("v");
  await page.locator("body").press("w");
  await expect(table.getByRole("button", { name: "Wi-Fi frames" })).toHaveAttribute("aria-pressed", "true");
  // Timeline shows device lanes with the Wi-Fi legend.
  const legend = page.getByTestId("timeline-panel").getByRole("list", { name: "Legend" });
  await expect(legend).toContainText("Management");
  await expect(legend).toContainText("Deauth");
  await expect(legend).toContainText("Randomized MAC");
  await expect(page.getByTestId("timeline-summary").locator(`tr[data-host="${SPOOFED}"]`)).toContainText("95 High");
});

test("AP → spoofed AP frames → deauth finding → Show evidence → frame decoded", async ({ page }) => {
  await openWifi(page);
  const row = page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]', { hasText: SPOOFED });
  await row.click();
  let s = await selection(page);
  expect(s.device).toBe(SPOOFED);
  expect(s.flow_ids).toEqual([]);
  expect(s.frame_no).not.toBeNull();

  const packets = page.getByTestId("packets-panel");
  await expect(packets.getByTestId("frame-source")).toContainText(`Frames of device ${SPOOFED} (rand)`);
  const list = packets.getByTestId("frame-list");
  await expect(list.getByRole("option").first()).toContainText('Beacon "Lakeside-Office" ch 6 wpa2');
  await expect(packets.getByTestId("decode-tree")).toContainText("IEEE 802.11 Beacon frame");
  await shot(page, "ap-selected");

  // Queue: the deauth flood ranks first; its evidence opens a deauth frame.
  const queue = page.getByTestId("queue-panel");
  const heads = queue.getByRole("list", { name: /findings/i }).locator("li[data-finding-id] > button[aria-expanded]");
  await expect(heads).toHaveCount(3);
  await expect(heads.first()).toContainText("Deauthentication flood");
  await expect(heads.first()).toContainText(`${SPOOFED} (rand)`);
  await expect(heads.first()).toContainText("T1498");
  await heads.first().click();
  const ev = queue.getByTestId("queue-evidence").first();
  await expect(ev).toContainText("frames");
  await ev.click();
  s = await selection(page);
  expect(s.device).toBe(SPOOFED);
  expect(s.frame_no).not.toBeNull();
  await expect(packets.getByTestId("packet-meta")).toContainText(String(s.frame_no));
  const tree = packets.getByTestId("decode-tree");
  await expect(tree).toContainText("IEEE 802.11 Deauthentication");
  await expect(tree).toContainText("Radiotap header");
  await expect(list.getByRole("option", { selected: true })).toContainText(`Deauth ${SPOOFED}`);
  await shot(page, "deauth-evidence");
});

test("timeline device lane click focuses the device (not the host selection)", async ({ page }) => {
  await openWifi(page);
  const tl = page.getByTestId("timeline-panel");
  await expect(tl).toHaveAttribute("data-state", "ready");
  const canvas = page.getByTestId("timeline-canvas");
  await canvas.focus();
  await canvas.press("ArrowDown");
  await canvas.press("Enter");
  const s = await selection(page);
  const first = await page.getByTestId("timeline-summary").locator("tbody tr").first().getAttribute("data-host");
  expect(s.device).toBe(first);
  await expect(page.getByTestId("frame-source")).toContainText(`Frames of device ${first}`);
  const hosts = await page.evaluate(
    () => (window as unknown as { __walleyeE2E: { selection: () => { hosts: string[] } } }).__walleyeE2E.selection().hosts,
  );
  expect(hosts).toEqual([]);
});

test("filter: mac shorthand and wifi.kind narrow the Wi-Fi frames tab", async ({ page }) => {
  const table = await openWifi(page);
  await table.getByRole("button", { name: "Wi-Fi frames" }).click();
  const input = page.getByTestId("filter-input");
  await input.fill("ma");
  await expect(page.getByRole("listbox", { name: "Filter suggestions" })).toContainText("mac");
  await input.fill(`mac ${SPOOFED} and wifi.kind == deauth`);
  await input.press("Enter");
  await expect(page.getByTestId("table-count")).toHaveText(/of 3\d\d rows/);
  // The timeline applies the same filter: only the spoofed transmitter's lane is left.
  const tl = page.getByTestId("timeline-panel");
  await expect(tl).toHaveAttribute("data-loading", "false");
  await expect(page.getByTestId("timeline-summary").locator("tbody tr")).toHaveCount(1);
  await expect(page.getByTestId("timeline-summary").locator("tbody tr")).toHaveAttribute("data-host", SPOOFED);
  await shot(page, "filter-deauth");
});

for (const scheme of ["light", "dark"] as const) {
  test.describe(`${scheme} theme`, () => {
    test.use({ colorScheme: scheme });
    test(`802.11 main screen has no WCAG 2.1 AA violations (${scheme})`, async ({ page }) => {
      await openWifi(page);
      await page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]', { hasText: SPOOFED }).click();
      await expect(page.getByTestId("decode-tree").getByRole("treeitem").first()).toBeVisible();
      const queue = page.getByTestId("queue-panel");
      await queue.locator("li[data-finding-id] > button[aria-expanded]").nth(1).click();
      await shot(page, `main-${scheme}`);
      const r = await new AxeBuilder({ page }).withTags(TAGS).analyze();
      const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
      console.log(`[axe] wifi ${scheme}: ${r.passes.length} rules passed, ${r.violations.length} violated${summary.length ? "\n  " + summary.join("\n  ") : ""}`);
      expect(summary).toEqual([]);
    });
  });
}
