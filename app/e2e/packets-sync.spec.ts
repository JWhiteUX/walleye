import { expect, test, type Page } from "@playwright/test";

const bodyRows = (page: Page) => page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]');

async function selectFirstFlow(page: Page) {
  await page.goto("/?mock=open");
  await bodyRows(page).first().click();
  await expect(page.getByTestId("decode-tree").getByRole("treeitem").first()).toBeVisible();
}

test("tree node -> byte range highlight", async ({ page }) => {
  await selectFirstFlow(page);
  const tree = page.getByTestId("decode-tree");
  const eth = tree.getByRole("treeitem", { name: /^▸?\s*Ethernet II/ });
  await eth.click();
  await expect(eth).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("hex-readout")).toContainText("14 bytes at offset 0");
  const hl = page.locator('[data-testid="hex-view"] .wl-hex-bytes .wl-byte.is-hl');
  await expect(hl).toHaveCount(14);
  // Expand with ArrowRight, move to the first child with ArrowDown.
  await page.keyboard.press("ArrowRight");
  await expect(eth).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("ArrowDown");
  await expect(tree.getByRole("treeitem", { name: /Destination/ })).toHaveAttribute("aria-selected", "true");
  await expect(hl).toHaveCount(6);
});

test("byte -> deepest tree node", async ({ page }) => {
  await selectFirstFlow(page);
  // Byte 0x17 (23) is the IPv4 protocol field.
  await page.locator('[data-testid="hex-view"] .wl-hex-bytes [data-off="23"]').click();
  const tree = page.getByTestId("decode-tree");
  await expect(tree.getByRole("treeitem", { selected: true })).toContainText("Protocol");
  await expect(tree.getByRole("treeitem", { name: /Internet Protocol/ })).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByTestId("hex-readout")).toContainText("Byte 0x0017");
  // Arrow keys move the byte cursor and keep the tree in sync.
  await page.getByTestId("hex-view").focus();
  await page.keyboard.press("ArrowLeft");
  await expect(page.getByTestId("hex-readout")).toContainText("Byte 0x0016");
  await expect(tree.getByRole("treeitem", { selected: true })).toContainText("Time to live");
});

test("frame list selection and ] / [ step through frames", async ({ page }) => {
  await selectFirstFlow(page);
  const list = page.getByTestId("frame-list");
  const opts = list.getByRole("option");
  await expect(opts.first()).toHaveAttribute("aria-selected", "true");
  await page.getByRole("heading", { name: "Walleye" }).click();
  await page.keyboard.press("]");
  await expect(opts.nth(1)).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("[");
  await expect(opts.first()).toHaveAttribute("aria-selected", "true");
});

test("frames without bytes show a not_found state", async ({ page }) => {
  await page.goto("/?mock=open");
  // Packet bytes exist only for the first 120 flows (+ evidence flows); sort descending to reach later ones.
  await page.getByTestId("table-grid").getByRole("columnheader", { name: /^Flow/ }).getByRole("button").click();
  await page.getByTestId("table-grid").getByRole("columnheader", { name: /^Flow/ }).getByRole("button").click();
  await expect(page.getByTestId("table-grid").getByRole("columnheader", { name: /^Flow/ })).toHaveAttribute("aria-sort", "descending");
  const rows = bodyRows(page);
  // Find a row whose frame has no bytes.
  for (let i = 0; i < 20; i++) {
    await rows.nth(i).click();
    const err = page.getByTestId("packet-error");
    const tree = page.getByTestId("decode-tree");
    await expect(err.or(tree)).toBeVisible();
    if (await err.isVisible()) {
      await expect(err).toContainText("No bytes available");
      await expect(err).toContainText("not_found");
      return;
    }
  }
  throw new Error("no not_found frame in the last 20 flows");
});

test("pin frame and pin flow report success", async ({ page }) => {
  await selectFirstFlow(page);
  await page.getByRole("button", { name: "Pin frame" }).click();
  await expect(page.getByTestId("packets-panel").getByRole("status")).toContainText(/Pinned frame \d+/);
  await page.getByRole("button", { name: "Pin flow" }).click();
  await expect(page.getByTestId("table-panel").getByRole("status")).toContainText(/Pinned flow \d+/);
});
