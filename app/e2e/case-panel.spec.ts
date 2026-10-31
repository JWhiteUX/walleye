import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

type IpcModule = typeof import("../src/shared/ipc");
type CaseEventsModule = typeof import("../src/shared/caseEvents");
// Module URLs on the Vite dev server: importing them in the page yields the
// same module instances the app uses.
const MODULES: [string, string] = ["/src/shared/ipc.ts", "/src/shared/caseEvents.ts"];

// Case panel against the browser mock (?mock=open starts with the capture
// indexed). Pins are made through the shared API seam, as another panel would.
test.describe("case panel", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/?mock=open");
    await expect(page.getByTestId("ioc-table")).toBeVisible();
  });

  test("lists defanged IOCs without links", async ({ page }) => {
    const panel = page.getByTestId("case-panel");
    await expect(panel.getByTestId("ioc-row")).toHaveCount(12);
    await expect(panel.getByText("cdn-update[.]top", { exact: true })).toBeVisible();
    await expect(panel.locator("a")).toHaveCount(0);
    await expect(panel.getByTestId("allowlisted-badge")).toHaveCount(2);
    await panel.getByLabel("Type").selectOption("ip");
    await expect(panel.getByTestId("ioc-row")).toHaveCount(2);
  });

  test("a pin made through the API appears in the panel", async ({ page }) => {
    await page.evaluate(async ([ipcUrl, eventsUrl]) => {
      const { api } = (await import(/* @vite-ignore */ ipcUrl)) as IpcModule;
      const { useCaseEvents } = (await import(/* @vite-ignore */ eventsUrl)) as CaseEventsModule;
      const s = await api.currentCapture();
      await api.casePin(s?.case_id ?? "", { kind: "frame", frame_no: 140 }, "beacon TLS hello");
      useCaseEvents.getState().bump();
    }, MODULES);
    const item = page.getByTestId("pin-item");
    await expect(item).toHaveCount(1);
    await expect(item).toContainText("Frame 140");
    await expect(item).toContainText("beacon TLS hello");
  });

  test("export buttons call the API and report the result", async ({ page }) => {
    const panel = page.getByTestId("case-panel");
    await panel.getByRole("button", { name: "Export IOCs CSV" }).click();
    await expect(panel.getByTestId("case-status")).toContainText("/exports/iocs.csv");
    await panel.getByRole("button", { name: "Export IOCs JSON" }).click();
    await expect(panel.getByTestId("case-status")).toContainText("/exports/iocs.json");
    await panel.getByRole("button", { name: "Export Report Markdown" }).click();
    await expect(panel.getByTestId("case-status")).toContainText("/exports/report.md");
    // the browser mock exports Markdown only; the PDF error is surfaced
    await panel.getByRole("button", { name: "Export Report PDF" }).click();
    await expect(panel.getByRole("alert")).toContainText("PDF export failed");
  });

  test("notes are keyboard operable", async ({ page }) => {
    const panel = page.getByTestId("case-panel");
    await panel.getByLabel("New note").focus();
    await page.keyboard.type("Escalated to IR");
    await page.keyboard.press("ControlOrMeta+Enter");
    await expect(panel.getByTestId("pin-item")).toContainText("Escalated to IR");
    await panel.getByRole("button", { name: /Edit note/ }).focus();
    await page.keyboard.press("Enter");
    const editBox = panel.getByRole("textbox", { name: /Edit note for/ });
    await expect(editBox).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(editBox).toHaveCount(0);
    await expect(panel.getByRole("button", { name: /Edit note/ })).toBeVisible();
  });

  test("is axe-clean", async ({ page }) => {
    await page.evaluate(async ([ipcUrl, eventsUrl]) => {
      const { api } = (await import(/* @vite-ignore */ ipcUrl)) as IpcModule;
      const { useCaseEvents } = (await import(/* @vite-ignore */ eventsUrl)) as CaseEventsModule;
      const s = await api.currentCapture();
      await api.casePin(s?.case_id ?? "", { kind: "note" }, "a note");
      await api.casePin(s?.case_id ?? "", { kind: "flow", flow_id: 27 }, "");
      useCaseEvents.getState().bump();
    }, MODULES);
    await expect(page.getByTestId("pin-item")).toHaveCount(2);
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme });
      const results = await new AxeBuilder({ page }).include('[data-testid="case-panel"]').analyze();
      expect(results.violations.map((v) => `${colorScheme} ${v.id}: ${v.nodes.map((n) => n.target).join(", ")}`)).toEqual([]);
    }
  });
});
