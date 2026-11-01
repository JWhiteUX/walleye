import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// WCAG 2.1 A + AA rules only.
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

async function axe(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s) — ${v.nodes[0]?.target.join(" ")}`);
  console.log(`axe: ${r.passes.length} rules passed, ${r.violations.length} violated${summary.length ? "\n  " + summary.join("\n  ") : ""}`);
  return r.violations;
}

for (const scheme of ["light", "dark"] as const) {
  test.describe(`${scheme} theme`, () => {
    test.use({ colorScheme: scheme });

    test("main screen has no WCAG 2.1 AA violations", async ({ page }) => {
      await page.goto("/?mock=open");
      const row = page.locator('[data-testid="table-grid"] .wl-grid-body [role="row"]').first();
      await row.click();
      await expect(page.getByTestId("decode-tree").getByRole("treeitem").first()).toBeVisible();
      await page.getByTestId("decode-tree").getByRole("treeitem").nth(1).click();
      expect(await axe(page)).toEqual([]);
    });

    test("command palette has no WCAG 2.1 AA violations", async ({ page }) => {
      await page.goto("/?mock=open");
      await page.getByTestId("open-palette").click();
      await expect(page.getByTestId("command-palette")).toBeVisible();
      expect(await axe(page)).toEqual([]);
    });

    test("filter suggestions and error state have no WCAG 2.1 AA violations", async ({ page }) => {
      await page.goto("/?mock=open");
      const input = page.getByTestId("filter-input");
      await input.fill("(host");
      await input.press("Enter");
      await expect(page.getByTestId("filter-error")).toBeVisible();
      await input.fill("dns");
      await input.press("ArrowDown");
      await expect(page.getByRole("listbox", { name: "Filter suggestions" })).toBeVisible();
      expect(await axe(page)).toEqual([]);
    });

    test("ingest progress dialog has no WCAG 2.1 AA violations", async ({ page }) => {
      await page.goto("/");
      await page.getByTestId("open-capture").click();
      await expect(page.getByTestId("ingest-dialog").getByRole("progressbar")).toBeVisible();
      expect(await axe(page)).toEqual([]);
    });
  });
}
