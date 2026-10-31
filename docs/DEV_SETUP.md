# Developer setup

For someone who has never used Tauri.

## What Tauri is

A Tauri app is two programs in one window:

- a **Rust backend** (native code, full OS access), in `app/src-tauri/`, and
- a **web UI** (our React + TypeScript app, in `app/src/`) running in the operating system's own webview (WebKit on macOS, WebKitGTK on Linux). No bundled Chromium, no Node at runtime.

The UI cannot touch the filesystem or network by itself. It asks the Rust side to do things through **commands**.

## How a UI call reaches Rust

```
app/src/table/…            api.query(req)                      (TypeScript)
app/src/shared/ipc.ts      invoke("query", { req })            @tauri-apps/api
        │  Tauri IPC (JSON over the ipc:// scheme)
app/src-tauri/src/commands.rs
                           #[tauri::command] async fn query(state, req) -> Result<Page, ApiError>
                           → state.backend.query(&req)          (Rust)
crates/walleye-*           the real work
```

1. `ipc.ts` calls `invoke(name, args)`. Argument names are snake_case, matching the Rust parameter names (`rename_all = "snake_case"`).
2. Tauri deserializes `args` into the command's parameters with serde, runs it, and serializes the `Ok` value or the `ApiError` back. `invoke` resolves or rejects with that.
3. A command must be listed in `tauri::generate_handler![...]` (`commands.rs` → `handler()`), or the call fails with "command not found".
4. The TS types for requests and responses are generated from the Rust structs (ts-rs) into `app/src/shared/bindings/`, so both sides agree.

Outside Tauri (plain browser, Vitest, Playwright) `ipc.ts` sends calls to an in-browser mock instead.

## Where configuration lives

| File | What it controls |
|---|---|
| `app/src-tauri/tauri.conf.json` | App name, window size, dev server URL (`devUrl`), where the built UI is (`frontendDist`), the Content Security Policy, bundle targets and icons. |
| `app/src-tauri/capabilities/default.json` | **Permissions**: which built-in and plugin APIs the window may call. We grant `core:default` and `dialog:allow-open` only. A plugin API missing here is rejected at runtime even if the plugin is installed. Our own commands are allowed by default. |
| `app/src-tauri/Cargo.toml` | Rust dependencies of the shell (Tauri, plugins, our crates). |
| `app/src-tauri/build.rs` | Runs `tauri_build::build()`; generates permission schemas into `gen/` (git-ignored). |
| `app/vite.config.ts` | Vite dev server on port 1420 (must match `devUrl`), Vitest config. |
| `app/package.json` | UI dependencies and scripts. |

## Toolchain

- Rust stable via rustup. If `cargo` is "command not found", add `. "$HOME/.cargo/env"` to `~/.zshrc`.
- Node 22+, pnpm 11 (`corepack enable` or `npm i -g pnpm`).
- macOS: Xcode command-line tools (`xcode-select --install`). Linux: the WebKitGTK packages listed at <https://tauri.app/start/prerequisites/>.
- First Rust build compiles DuckDB from source: expect several minutes and ~3–5 GB in `target/`.

```sh
pnpm install                      # at the repo root (pnpm workspace with app/)
pnpm --dir app exec playwright install chromium   # once, for e2e
```

## The four commands

| Command | What it does |
|---|---|
| `pnpm tauri dev` | Starts Vite on :1420, builds the Rust shell in debug, opens the app window. UI edits hot-reload; Rust edits rebuild and restart. `WALLEYE_BACKEND=mock-open pnpm tauri dev` starts with the mock capture already loaded. |
| `pnpm tauri build` | Release build of the UI and Rust, then packages (`.app`/`.dmg` on macOS, `.deb`/AppImage on Linux) under `target/release/bundle/`. |
| `cargo test --workspace` | All Rust tests. Also regenerates `app/src/shared/bindings/`. |
| `scripts/check.sh` | The commit gate: fmt, clippy `-D warnings`, cargo test, bindings drift, ESLint + `tsc`, Vitest. Must pass before any commit. |

Also useful: `pnpm dev` (UI only, in a browser, against the mock), `pnpm e2e` (Playwright against the mock), `pnpm test` (Vitest).

## Fixtures and disk

Generated and downloaded captures live in `$WALLEYE_FIXTURES` (default `~/.walleye-fixtures`), never in the repo. The full run needs 35–55 GB free; see `docs/BUILD_PROMPT.md` §5. Treat every capture as hostile input: never open carved content.
