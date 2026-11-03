import { expect, test } from "@playwright/test";

// Runs against the Vite dev server + browser mock (see playwright.config.ts).
test("shell renders every panel", async ({ page }) => {
  await page.goto("/");
  for (const id of ["timeline", "queue", "table", "packets"]) {
    await expect(page.getByTestId(`${id}-panel`)).toBeVisible();
  }
  // The case shares the side column with Findings as a tab.
  await page.getByTestId("side-tab-case").click();
  await expect(page.getByTestId("case-panel")).toBeVisible();
});
