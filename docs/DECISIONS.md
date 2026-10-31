# Decisions

Why things are the way they are. Newest last. Stack decisions in the first block are confirmed by the product owner and are not reopened; everything else may change with a new entry that says why.

## Confirmed by the product owner

| # | Decision |
|---|----------|
| D1 | Tauri 2 desktop app (macOS + Linux). |
| D2 | Rust workspace with native parsers (`pcap-parser`, `etherparse`, hand-written DNS/HTTP/TLS). No Zeek. |
| D3 | DuckDB (`duckdb` crate) over Parquet, one index directory per capture. |
| D4 | React + TypeScript + Vite; TanStack Table (virtualized); timeline on Canvas 2D (WebGL only if Canvas misses the latency target). |
| D5 | Detection rules are YAML in `rules/`, loaded at runtime. |
| D6 | Tests: cargo test, criterion, Vitest, Playwright. pnpm. |

## Phase 0 (lead)

**D7. Tauri layer is the official `create-tauri-app` React-TS template, trimmed.** We kept its layout (`app/src-tauri` with `build.rs`, `tauri.conf.json`, `capabilities/`, `icons/`) so Tauri docs apply as written. Removed `tauri-plugin-opener` (not needed, and it can open URLs). Added one official plugin, `tauri-plugin-dialog`, because a webview `<input type=file>` cannot give Rust a real filesystem path; the native open dialog can. *Tauri note:* plugins need both the Rust crate (`.plugin(...)` in `lib.rs`) and a permission in `capabilities/default.json` (`dialog:allow-open`); without the permission the JS call is rejected.

**D8. Commands are thin, async and snake_case.** Every `#[tauri::command]` in `commands.rs` forwards to one `Backend` trait method on Tauri's blocking pool. *Tauri notes:* (a) a non-`async` command runs on the main thread and would freeze the window during a slow query; (b) by default Tauri renames Rust `snake_case` arguments to `camelCase` for JS; `rename_all = "snake_case"` keeps one spelling everywhere so the TS types generated from Rust match the call sites.

**D9. One `Backend` trait in `walleye-core`, implemented by `MockBackend` now and by the real wiring in Phase 2.** UI agents build against the mock with no Rust changes, and swapping is a one-line change in `make_backend()`. The browser mock (`app/src/shared/mock.ts`) serves the same JSON so Playwright can run in plain Chromium. *Tauri note:* Tauri's WebDriver (`tauri-driver`) does not support macOS, so e2e tests drive the Vite dev server in a browser, not the packaged app.

**D10. TypeScript types come from Rust via ts-rs**, exported on `cargo test -p walleye-core` to `app/src/shared/bindings/`. `check.sh` fails if the committed bindings differ from the regenerated ones, so the two sides cannot drift. 64-bit integers are annotated as `number` (all our ids and µs timestamps are < 2^53); ts-rs would otherwise emit `bigint`, which `JSON.parse` never produces.

**D11. Structured selection scope in `QueryRequest`.** `hosts[]` and `flow_ids[]` are fields beside `filter`, rather than being spliced into the filter text. Splicing would make the UI build filter strings (fragile, and an injection surface even with parameterized SQL downstream).

**D12. Added a `files` table** for "file-transfer metadata" (P0 item 2). It records declared metadata only (name, Content-Type, size) from HTTP. No bodies are stored, hashed or carved, because carving is out of scope and every carved payload is hostile.

**D13. Findings keep `detector`/`attack_technique` (from the top reason) and add per-reason `rule_id`/`attack_technique`.** A per-host finding combines several detectors, so the single columns in the spec would lose information; the per-reason fields keep it without changing the spec's table shape.

**D14. Strict CSP and no extra capabilities.** `tauri.conf.json` sets `default-src 'self'`, `connect-src ipc: http://ipc.localhost` (Tauri 2's IPC transport), no remote scripts, `object-src`/`frame-src 'none'`, and `freezePrototype`. Capabilities grant `core:default` and `dialog:allow-open` only: no shell, fs, http or opener plugins. Exports are written by Rust into the case directory, so the webview never needs filesystem access.

**D15. Saved queries are app-level** (`<data_dir>/saved_queries.json`), not per case: analysts reuse them across captures.

**D16. YAML via `serde_yaml_ng`.** `serde_yaml` is archived; `serde_yaml_ng` is the maintained fork with the same API.

**D17. Rust found at `~/.cargo/bin` but not on the default shell PATH.** `scripts/check.sh` prepends it when `cargo` is missing. Developers should add `. "$HOME/.cargo/env"` to their shell profile (see DEV_SETUP.md).
