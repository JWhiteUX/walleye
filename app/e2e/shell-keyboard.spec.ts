import { expect, test, type Page } from "@playwright/test";

/** The app's "mod" key for the page's platform (the Desktop Chrome device spoofs Windows). */
const modKey = (page: Page) =>
  page.evaluate(() => {
    const ua = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform || navigator.platform;
    return /mac|iphone|ipad/i.test(ua) ? "Meta" : "Control";
  });

test("mod+k opens the palette, filters, runs a command, Escape restores focus", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(page.getByTestId("capture-info")).toBeVisible();
  await page.getByRole("heading", { name: "Walleye" }).click();
  await page.keyboard.press(`${await modKey(page)}+k`);
  const palette = page.getByTestId("command-palette");
  await expect(palette).toBeVisible();
  const search = palette.getByRole("combobox", { name: "Search commands" });
  await expect(search).toBeFocused();
  await expect(palette.getByRole("option").first()).toBeVisible();
  await search.fill("dns view");
  await expect(palette.getByRole("option").first()).toContainText("Show DNS view");
  await search.press("Enter");
  await expect(palette).toBeHidden();
  await expect(page.getByRole("button", { name: "DNS", exact: true })).toHaveAttribute("aria-pressed", "true");

  await page.keyboard.press(`${await modKey(page)}+k`);
  await expect(palette).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(palette).toBeHidden();
});

test("palette lists shortcuts from every registered command", async ({ page }) => {
  await page.goto("/?mock=open");
  await page.getByTestId("open-palette").click();
  const palette = page.getByTestId("command-palette");
  for (const t of ["Open capture", "Focus filter bar", "Focus next pane", "Show TLS view", "Next frame in flow"]) {
    await expect(palette.getByRole("option", { name: new RegExp(t) })).toBeVisible();
  }
  await expect(palette.getByRole("option", { name: /Go to timeline/ })).toContainText("G then T");
});

test("sequence shortcuts and '/' move focus", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]').first()).toBeVisible();
  await page.getByRole("heading", { name: "Walleye" }).click();
  await page.keyboard.press("/");
  await expect(page.getByTestId("filter-input")).toBeFocused();
  await page.keyboard.press("Escape");
  await page.getByTestId("filter-input").blur();
  await page.keyboard.press("g");
  await page.keyboard.press("s");
  await expect(page.getByTestId("table-grid")).toBeFocused();
  // Plain letters typed into the filter bar never trigger shortcuts.
  await page.keyboard.press("/");
  await page.keyboard.type("g s");
  await expect(page.getByTestId("filter-input")).toBeFocused();
  await expect(page.getByTestId("filter-input")).toHaveValue("g s");
});

test("F6 cycles focus between panes, Shift+F6 goes back", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]').first()).toBeVisible();
  await page.getByTestId("filter-input").focus();
  const paneOf = () => page.evaluate(() => document.activeElement?.closest("[data-pane]")?.getAttribute("data-pane"));
  await page.keyboard.press("F6");
  expect(await paneOf()).toBe("timeline");
  await page.keyboard.press("F6");
  expect(await paneOf()).toBe("table");
  await expect(page.getByTestId("table-grid")).toBeFocused();
  await page.keyboard.press("F6");
  expect(await paneOf()).toBe("packets");
  await page.keyboard.press("F6");
  expect(await paneOf()).toBe("queue");
  await page.keyboard.press("F6");
  expect(await paneOf()).toBe("case");
  await page.keyboard.press("F6");
  expect(await paneOf()).toBe("filter");
  await page.keyboard.press("Shift+F6");
  expect(await paneOf()).toBe("case");
});

test("splitters resize with the keyboard", async ({ page }) => {
  await page.goto("/?mock=open");
  const sep = page.getByRole("separator", { name: "Resize timeline" });
  const before = Number(await sep.getAttribute("aria-valuenow"));
  await sep.focus();
  await page.keyboard.press("ArrowDown");
  await expect(sep).toHaveAttribute("aria-valuenow", String(before + 16));
});

test("case panel toggles with mod+\\", async ({ page }) => {
  await page.goto("/?mock=open");
  await expect(page.getByTestId("case-panel")).toBeVisible();
  await page.getByRole("heading", { name: "Walleye" }).click();
  await page.keyboard.press(`${await modKey(page)}+Backslash`);
  await expect(page.getByTestId("case-panel")).toHaveCount(0);
  await page.keyboard.press("g");
  await page.keyboard.press("c");
  await expect(page.getByTestId("case-panel")).toBeVisible();
});
