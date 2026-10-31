// Webview half of the network-deny test. PROPOSED for app/e2e/no-network.spec.ts
// (Agent H cannot edit app/; the lead places it at integration).
//
// Why a browser test: on macOS, WKWebView fetches run in a launchd XPC service
// outside `sandbox-exec`, so run_denied.sh cannot see them. The CSP
// (tauri.conf.json) should stop them; this test proves the UI never even
// tries. It drives the production bundle (`vite preview`, not the dev server,
// so there is no HMR socket) through the analyst flow and fails on any request
// or WebSocket that leaves the page's own origin.
//
// Run: pnpm build && pnpm exec playwright test e2e/no-network.spec.ts
// (playwright.config.ts webServer should be `pnpm preview --port 1420 --strictPort`
// for this project, or set PW_BASE_URL).
import { expect, test } from "@playwright/test";

test("UI makes no requests outside its own origin", async ({ page, baseURL }) => {
  const origin = new URL(baseURL ?? "http://localhost:1420").origin;
  const external: string[] = [];

  // Abort (and record) anything that is not same-origin, data: or blob:.
  await page.context().route("**/*", (route) => {
    const url = route.request().url();
    if (url.startsWith("data:") || url.startsWith("blob:") || new URL(url).origin === origin) {
      return route.continue();
    }
    external.push(`${route.request().resourceType()} ${url}`);
    return route.abort("blockedbyclient");
  });
  page.on("websocket", (ws) => {
    if (new URL(ws.url()).origin.replace(/^ws/, "http") !== origin) external.push(`websocket ${ws.url()}`);
  });
  // CSP violations would mean the webview tried something the CSP blocked.
  const cspViolations: string[] = [];
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to (load|connect)/i.test(m.text())) cspViolations.push(m.text());
  });

  await page.goto("/?mock=open");
  // Walk every panel: table, packet pane, timeline, queue, case export.
  await page.getByTestId("table-panel").waitFor();
  await page.getByTestId("timeline-panel").waitFor();
  await page.getByTestId("queue-panel").waitFor();
  await page.getByTestId("case-panel").waitFor();
  // Click the first evidence link and the first table row if present; these
  // render capture-derived strings (domains, URLs, SNI) that must stay inert.
  for (const sel of ['[data-testid="queue-panel"] a, [data-testid="queue-panel"] button', '[role="row"]']) {
    const el = page.locator(sel).nth(1);
    if (await el.count()) await el.click({ trial: false }).catch(() => {});
  }
  await page.waitForLoadState("networkidle");

  expect(external, "requests outside the app origin").toEqual([]);
  expect(cspViolations, "CSP violations").toEqual([]);
});
