import { defineConfig, devices } from "@playwright/test";

// e2e runs the Vite dev server in a plain browser. With no Tauri runtime
// present, app/src/shared/ipc.ts routes every call to the browser mock
// (app/src/shared/mock.ts), which serves crates/walleye-core/mock/*.json.
// Each worktree/run can pick its own port so parallel runs never test each
// other's dev server (WALLEYE_E2E_PORT, default 1420).
const port = Number(process.env.WALLEYE_E2E_PORT ?? 1420);

export default defineConfig({
  testDir: "e2e",
  testIgnore: ["real/**"],
  fullyParallel: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://localhost:${port}`,
    trace: "retain-on-failure",
  },
  webServer: {
    command: `pnpm exec vite --port ${port} --strictPort`,
    url: `http://localhost:${port}`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
