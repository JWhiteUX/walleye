import { defineConfig, devices } from "@playwright/test";

// e2e runs the Vite dev server in a plain browser. With no Tauri runtime
// present, app/src/shared/ipc.ts routes every call to the browser mock
// (app/src/shared/mock.ts), which serves crates/walleye-core/mock/*.json.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:1420",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "pnpm dev",
    url: "http://localhost:1420",
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
