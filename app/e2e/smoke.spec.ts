import { expect, test } from "@playwright/test";

// Runs against the Vite dev server + browser mock (see playwright.config.ts).
test("shell renders every panel", async ({ page }) => {
  await page.goto("/");
  for (const id of ["timeline", "queue", "table", "packets", "case"]) {
    await expect(page.getByTestId(`${id}-panel`)).toBeVisible();
  }
});
