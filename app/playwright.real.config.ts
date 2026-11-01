import { defineConfig, devices } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

// Real-backend e2e: the UI in Chromium talks to the real engine through the
// dev-only loopback bridge (tools/walleye-devbridge). Run with `pnpm e2e:real`.
// Needs `cargo build --release -p walleye-devbridge` and the generated fixtures
// in $WALLEYE_FIXTURES (default ~/.walleye-fixtures).
const vitePort = Number(process.env.WALLEYE_E2E_PORT ?? 1480);
const bridgePort = Number(process.env.WALLEYE_BRIDGE_PORT ?? 7377);
const token = process.env.WALLEYE_BRIDGE_TOKEN ?? randomBytes(24).toString("hex");
const fixtures = process.env.WALLEYE_FIXTURES ?? join(homedir(), ".walleye-fixtures");
const data = process.env.WALLEYE_E2E_DATA ?? mkdtempSync(join(tmpdir(), "walleye-e2e-"));
process.env.WALLEYE_BRIDGE_TOKEN = token;
process.env.WALLEYE_REAL_QS = new URLSearchParams({
  bridge: `http://127.0.0.1:${bridgePort}`,
  token,
  capture: process.env.WALLEYE_E2E_CAPTURE ?? join(fixtures, "generated", "beacon.pcap"),
}).toString();

export default defineConfig({
  testDir: "e2e/real",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  reporter: [["list"]],
  use: { baseURL: `http://localhost:${vitePort}`, trace: "retain-on-failure" },
  webServer: [
    {
      command: `../target/release/walleye-devbridge --data ${data} --port ${bridgePort} --origin http://localhost:${vitePort}`,
      url: `http://127.0.0.1:${bridgePort}/`,
      env: { WALLEYE_BRIDGE_TOKEN: token },
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: `pnpm exec vite --port ${vitePort} --strictPort`,
      url: `http://localhost:${vitePort}`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
