import { expect, test } from "@playwright/test";

// Webview half of the network-deny gate (the backend half is
// scripts/netdeny.sh). On macOS, WKWebView networking runs outside
// sandbox-exec, so this test audits every request the UI makes while an
// analyst walks the triage path against the real engine. Allowed: the page's
// own origin (the Vite dev server, including its HMR socket), the loopback dev
// bridge that stands in for Tauri IPC, data: and blob:. Anything else is
// aborted and fails the test, as does any CSP violation.
// Adapted from Agent H's fuzz/netdeny/no-network.spec.ts.

const qs = () => process.env.WALLEYE_REAL_QS ?? "";

test("UI makes no requests outside the app and its IPC bridge", async ({ page, baseURL }) => {
  const origin = new URL(baseURL ?? "http://localhost:1480").origin;
  const bridge = new URLSearchParams(qs()).get("bridge");
  const allowed = new Set([origin, ...(bridge ? [new URL(bridge).origin] : [])]);
  const external: string[] = [];

  await page.context().route("**/*", (route) => {
    const url = route.request().url();
    if (url.startsWith("data:") || url.startsWith("blob:") || allowed.has(new URL(url).origin)) {
      return route.continue();
    }
    external.push(`${route.request().resourceType()} ${url}`);
    return route.abort("blockedbyclient");
  });
  page.on("websocket", (ws) => {
    if (!allowed.has(new URL(ws.url()).origin.replace(/^ws/, "http"))) external.push(`websocket ${ws.url()}`);
  });
  const cspViolations: string[] = [];
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to (load|connect)/i.test(m.text())) cspViolations.push(m.text());
  });

  await page.goto(`/?${qs()}`);
  await page.getByTestId("open-capture").click();
  await expect(page.getByTestId("ingest-dialog")).toBeHidden({ timeout: 120_000 });

  // Render capture-derived strings in every panel: queue details and
  // evidence, packet pane, table rows, IOC table, exports.
  const queue = page.getByTestId("queue-panel");
  const heads = queue.locator("li[data-finding-id] > button[aria-expanded]");
  await expect(heads.first()).toBeVisible({ timeout: 10_000 });
  await heads.first().click();
  await queue.getByTestId("queue-evidence").first().click();
  await expect(page.getByTestId("decode-tree").getByRole("treeitem").first()).toBeVisible({ timeout: 5_000 });
  for (const view of ["DNS", "HTTP", "TLS"]) {
    const tab = page.getByRole("tab", { name: new RegExp(`^${view}`, "i") });
    if (await tab.count()) await tab.first().click();
  }
  const toggle = page.getByRole("button", { name: /case/i }).first();
  if (!(await page.getByTestId("case-panel").isVisible())) await toggle.click();
  const casePanel = page.getByTestId("case-panel");
  await expect(casePanel.getByTestId("ioc-row").first()).toBeVisible({ timeout: 5_000 });
  for (const name of [/markdown/i, /pdf/i]) {
    await casePanel.getByRole("button", { name }).first().click();
    await expect(casePanel.getByTestId("case-status")).toContainText(/exports/i, { timeout: 15_000 });
  }
  await page.waitForLoadState("networkidle");

  expect(external, "requests outside the app origin and IPC bridge").toEqual([]);
  expect(cspViolations, "CSP violations").toEqual([]);
});

// Negative control: the audit must catch a request when one is made. The
// request is aborted by the route before it leaves the browser, and targets
// TEST-NET-2 (198.51.100.0/24, RFC 5737), which is never routed.
test("audit catches an external request (control)", async ({ page, baseURL }) => {
  const origin = new URL(baseURL ?? "http://localhost:1480").origin;
  const external: string[] = [];
  await page.context().route("**/*", (route) => {
    const url = route.request().url();
    if (new URL(url).origin === origin) return route.continue();
    external.push(url);
    return route.abort("blockedbyclient");
  });
  await page.goto(`/?${qs()}`);
  await page.evaluate(() => fetch("http://198.51.100.7/beacon").catch(() => null));
  // (Bridge calls are recorded too, because this control allows only the page origin.)
  expect(external).toContain("http://198.51.100.7/beacon");
});
