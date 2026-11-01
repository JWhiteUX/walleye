import { expect, test, type Page } from "@playwright/test";

// The analyst triage path against the REAL engine (dev bridge), on the
// generated beacon capture: open -> queue ranks the C2 host -> evidence ->
// packet decoded from capture bytes -> brush filters the table in < 1 s ->
// export IOCs and the report.

const qs = () => process.env.WALLEYE_REAL_QS ?? "";
const bodyRows = (page: Page) => page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]');

async function openReal(page: Page) {
  await page.goto(`/?${qs()}`);
  await page.getByTestId("open-capture").click();
  await expect(page.getByTestId("ingest-dialog")).toBeHidden({ timeout: 120_000 });
  await expect(page.getByTestId("capture-info")).toContainText("beacon");
}

test("real backend: queue -> evidence -> packet, brush < 1 s, exports", async ({ page }) => {
  await openReal(page);

  // Queue: the labelled C2 host (10.0.0.23) ranks first.
  const queue = page.getByTestId("queue-panel");
  const heads = queue.locator("li[data-finding-id] > button[aria-expanded]");
  await expect(heads.first()).toBeVisible({ timeout: 10_000 });
  await expect(heads.first()).toContainText("10.0.0.23");

  // Evidence -> packet pane shows a frame decoded from the capture bytes.
  await heads.first().click();
  await queue.getByTestId("queue-evidence").first().click();
  const packets = page.getByTestId("packets-panel");
  await expect(packets.getByTestId("decode-tree").getByRole("treeitem").first()).toBeVisible({ timeout: 5_000 });
  await expect(packets.getByTestId("decode-tree")).toContainText(/Internet Protocol|IPv4/);
  await expect(packets.getByTestId("hex-view")).toContainText("0000");

  // Brush on the real backend: the table count changes within 1 s.
  await expect(bodyRows(page).first()).toBeVisible();
  const before = await page.getByTestId("table-count").textContent();
  const canvas = page.getByTestId("timeline-canvas");
  const box = await canvas.boundingBox();
  if (!box) throw new Error("timeline canvas not laid out");
  const y = box.y + box.height / 2;
  await page.mouse.move(box.x + box.width * 0.4, y);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.5, y, { steps: 5 });
  const t0 = Date.now();
  await page.mouse.up();
  await expect(page.getByTestId("table-count")).not.toHaveText(before ?? "", { timeout: 1_000 });
  const brushMs = Date.now() - t0;
  console.log(`brush -> table updated in ${brushMs} ms (real backend)`);
  expect(brushMs).toBeLessThan(1_000);

  // Case panel: IOCs extracted, exports return paths in the case dir.
  const toggle = page.getByRole("button", { name: /case/i }).first();
  if (!(await page.getByTestId("case-panel").isVisible())) await toggle.click();
  const casePanel = page.getByTestId("case-panel");
  await expect(casePanel.getByTestId("ioc-row").first()).toBeVisible({ timeout: 5_000 });
  await expect(casePanel.getByTestId("ioc-table")).toContainText("185[.]199[.]110[.]77");
  for (const name of [/csv/i, /json/i, /markdown/i, /pdf/i]) {
    await casePanel.getByRole("button", { name }).first().click();
    await expect(casePanel.getByTestId("case-status")).toContainText(/exports/i, { timeout: 15_000 });
  }
});
