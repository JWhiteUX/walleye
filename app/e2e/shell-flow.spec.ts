import { expect, test, type Page } from "@playwright/test";

// Agent D: open -> filter -> select row -> packet shown, against the browser mock.

const bodyRows = (page: Page) => page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]');

async function openCapture(page: Page) {
  await page.goto("/");
  await expect(page.getByTestId("capture-info")).toHaveCount(0);
  await page.getByTestId("open-capture").click();
  const dialog = page.getByTestId("ingest-dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("progressbar")).toBeVisible();
  await expect(page.getByTestId("ingest-phase")).toHaveText(/Hashing|Indexing|Running detections|Starting/);
  await expect(page.getByTestId("ingest-eta")).toContainText(/left/);
  await expect(dialog).toBeHidden({ timeout: 10_000 });
  await expect(page.getByTestId("capture-info")).toContainText("office-beacon");
}

test("open -> filter -> select row -> packet shown", async ({ page }) => {
  await openCapture(page);
  await expect(bodyRows(page).first()).toBeVisible();
  await expect(page.getByTestId("table-count")).toContainText(/474 rows/);

  const input = page.getByTestId("filter-input");
  await input.fill("host 10.0.0.23");
  await input.press("Enter");
  await expect(page.getByTestId("table-count")).not.toContainText(/474 rows/);
  const n = await bodyRows(page).count();
  expect(n).toBeGreaterThan(0);
  for (let i = 0; i < Math.min(n, 10); i++) {
    await expect(bodyRows(page).nth(i)).toContainText("10.0.0.23");
  }

  const first = bodyRows(page).first();
  await first.click();
  await expect(first).toHaveAttribute("aria-selected", "true");

  const packets = page.getByTestId("packets-panel");
  await expect(packets.getByTestId("frame-list").getByRole("option").first()).toBeVisible();
  await expect(packets.getByTestId("packet-meta")).toContainText("Frame");
  const tree = packets.getByTestId("decode-tree");
  await expect(tree.getByRole("treeitem").first()).toBeVisible();
  await expect(tree).toContainText("Internet Protocol");
  await expect(packets.getByTestId("hex-view")).toContainText("0000");
});

test("Enter on a focused row selects it (keyboard only)", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(bodyRows(page).first()).toBeVisible();
  await page.getByTestId("table-grid").focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(bodyRows(page).nth(1)).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("decode-tree").getByRole("treeitem").first()).toBeVisible();
});

test("cancel ingest shows the resume message", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("open-capture").click();
  const dialog = page.getByTestId("ingest-dialog");
  await expect(dialog.getByRole("button", { name: /Cancel/ })).toBeEnabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toContainText("Indexing cancelled");
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("capture-info")).toHaveCount(0);
});

test("invalid filter shows an inline underline and message", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(bodyRows(page).first()).toBeVisible();
  const input = page.getByTestId("filter-input");
  await input.fill('dns.query ~ "abc');
  await input.press("Enter");
  await expect(page.getByTestId("filter-error")).toContainText("unterminated string");
  await expect(page.getByTestId("filter-error")).toContainText("Column 13");
  await expect(page.getByTestId("filter-error-underline")).toHaveText('"abc');
  await expect(input).toHaveAttribute("aria-invalid", "true");
  await input.fill("host 10.0.0.23");
  await input.press("Enter");
  await expect(page.getByTestId("filter-error")).toHaveCount(0);
});

test("autocomplete is keyboard navigable and applies replace_start/end", async ({ page }) => {
  await page.goto("/?mock=open");
  const input = page.getByTestId("filter-input");
  await input.click();
  await input.pressSequentially("dns.q");
  const list = page.getByRole("listbox", { name: "Filter suggestions" });
  await expect(list.getByRole("option").first()).toContainText("dns.q");
  await input.press("ArrowDown");
  await expect(list.getByRole("option").first()).toHaveAttribute("aria-selected", "true");
  await input.press("Enter");
  await expect(input).toHaveValue(/^dns\.q\S* $/);
  // Next suggestions are operators for that field.
  await expect(list.getByRole("option", { name: /~/ })).toBeVisible();
});

test("column filter composes into the visible filter text", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(bodyRows(page).first()).toBeVisible();
  await page.getByLabel("Column", { exact: true }).selectOption({ label: "Source" });
  await page.getByLabel("Column filter value").fill("10.0.0.23");
  await page.getByRole("button", { name: "Add filter" }).click();
  await expect(page.getByTestId("filter-input")).toHaveValue("src_ip == 10.0.0.23");
  await page.getByLabel("Column filter value").fill("nonsense!");
  await page.getByRole("button", { name: "Add filter" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "IP address" })).toBeVisible();
});

test("sorting is server-side and marked with text, not colour", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(bodyRows(page).first()).toBeVisible();
  const header = page.getByTestId("table-grid").getByRole("columnheader", { name: /Bytes up/ });
  await header.getByRole("button").click();
  await expect(header).toHaveAttribute("aria-sort", "ascending");
  await header.getByRole("button").click();
  await expect(header).toHaveAttribute("aria-sort", "descending");
  await expect(header).toContainText("▼");
});

test("saved queries: apply, save, delete", async ({ page }) => {
  await page.goto("/?mock=open");
  await page.getByRole("button", { name: /Saved/ }).click();
  const pop = page.getByTestId("saved-queries");
  await pop.getByRole("button", { name: /^Large uploads flows/ }).click();
  await expect(page.getByTestId("filter-input")).toHaveValue("bytes_up > 1MB");

  await page.getByRole("button", { name: /Saved/ }).click();
  await pop.getByLabel(/Save applied filter/).fill("My uploads");
  await pop.getByRole("button", { name: "Save", exact: true }).click();
  await expect(pop.getByRole("button", { name: /^My uploads/ })).toBeVisible();
  await pop.getByRole("button", { name: "Delete saved query My uploads" }).click();
  await expect(pop.getByRole("button", { name: /My uploads/ })).toHaveCount(0);
});

test("view switcher changes the table view", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(bodyRows(page).first()).toBeVisible();
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  await expect(page.getByTestId("table-grid").getByRole("columnheader", { name: /Query/ })).toBeVisible();
  await expect(page.getByTestId("table-count")).toContainText(/514 rows/);
});
