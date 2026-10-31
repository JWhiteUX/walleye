import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import type { BenchResult } from "../src/table/TableBench";

// 1,000,000 synthetic rows in the real VirtualGrid (`?bench=table`), scrolled
// for 5 s at 1200 px/frame with a random jump across the whole range every
// 60 frames, while requestAnimationFrame deltas are recorded.
//
// The fps gate runs against a PRODUCTION build (React prod mode), built here
// with VITE_WALLEYE_BENCH=1 and served by `vite preview`, because the dev
// server's React development build is several times slower and is not what
// ships. The dev-server numbers are logged for reference only.

test.describe.configure({ mode: "serial" });

let outDir = "";
let preview: ChildProcess | null = null;
let prodUrl = "";

test.beforeAll(async () => {
  test.setTimeout(120_000);
  outDir = mkdtempSync(join(tmpdir(), "walleye-table-bench-"));
  execFileSync("pnpm", ["exec", "vite", "build", "--outDir", outDir, "--emptyOutDir", "--logLevel", "error"], {
    env: { ...process.env, VITE_WALLEYE_BENCH: "1" },
    stdio: "inherit",
  });
  preview = spawn("pnpm", ["exec", "vite", "preview", "--outDir", outDir, "--port", "4317"], { stdio: ["ignore", "pipe", "pipe"] });
  prodUrl = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("vite preview did not start")), 30_000);
    preview!.stdout!.on("data", (b: Buffer) => {
      // eslint-disable-next-line no-control-regex
      const m = /Local:\s+(http:\/\/\S+)/.exec(b.toString().replace(/\x1b\[[0-9;]*m/g, ""));
      if (m) {
        clearTimeout(t);
        resolve(m[1]!.endsWith("/") ? m[1]! : `${m[1]}/`);
      }
    });
    preview!.on("exit", (code) => reject(new Error(`vite preview exited ${code}`)));
  });
});

test.afterAll(() => {
  preview?.kill();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

async function runBench(page: Page, base: string): Promise<BenchResult> {
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.goto(`${base}?bench=table&seconds=5&px=1200`);
  await expect(page.getByTestId("bench-rows")).toContainText("1,000,000 rows", { timeout: 30_000 });
  await expect(page.getByTestId("bench-grid")).toHaveAttribute("aria-rowcount", "1000001");
  await page.waitForTimeout(500);
  await page.getByRole("button", { name: "Run scroll benchmark" }).click();
  const handle = await page.waitForFunction(() => window.__tableBench, null, { timeout: 30_000 });
  const r = (await handle.jsonValue())!;
  await expect(page.locator('[data-testid="bench-grid"] .wl-grid-body [role="row"]').first()).toBeVisible();
  return r;
}

test("table scrolls 1M rows at 60 fps (production build)", async ({ page }) => {
  test.setTimeout(90_000);
  const r = await runBench(page, prodUrl);
  console.log(`table bench (production build): ${JSON.stringify(r)}`);
  expect(r.rows).toBe(1_000_000);
  expect(r.fps).toBeGreaterThanOrEqual(58);
  expect(r.p95FrameMs).toBeLessThanOrEqual(17.5);
});

test("table bench on the dev server (reference only)", async ({ page }) => {
  test.setTimeout(90_000);
  const r = await runBench(page, "/");
  console.log(`table bench (dev server, React development build): ${JSON.stringify(r)}`);
  expect(r.rows).toBe(1_000_000);
});
