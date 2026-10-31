# Build log

One line per agent dispatch, report and gate result. Numbers come from command output; nothing is marked passed without it.

| When (UTC) | Phase | Who | Event | Result / evidence |
|---|---|---|---|---|
| 2026-10-30 | 0 | Lead | Toolchain check | rustc 1.99.1 + cargo 1.99.1 (stable, rustup; in `~/.cargo/bin`, not on default PATH), Node v22.22.3, pnpm 11.10.0, Xcode at /Applications/Xcode.app. 12 cores, 64 GB RAM. |
| 2026-10-30 | 0 | Lead | Disk check | Finder free (incl. purgeable) 180.08 GB (≥ 60 OK); `df` avail 51 GiB (≥ 40 OK). No warning needed. |
| 2026-10-31 | 0 | Lead | Contracts + skeleton | `walleye-core` (tables, findings, IPC, sink traits, rules, allowlist, field registry, mock backend), Tauri shell with 20 commands on the mock, React shell + shared selection/IPC/mock, docs. |
| 2026-10-31 | 0 | Lead | **Gate 0** `scripts/check.sh` | **PASS** — fmt ok; clippy -D warnings ok; cargo test 65 passed (walleye-core); bindings ok; eslint+tsc ok; Vitest 2 files / 7 tests passed. Also: `pnpm build` ok, `pnpm e2e` 1 passed. |
| 2026-10-31 | 1 | Lead | Dispatch A–H (one message, `isolation: worktree`, base f063c4e) | Rust-heavy agents A, B, C, F, G use their own `target/`; UI agents D, E and reviewer H share the lead's `target/` via `CARGO_TARGET_DIR` to save ~10 GB. df at dispatch: 47 GiB. |
| 2026-10-31 | 1 | Lead | Unblocked cargo | Agent H's nightly `cargo fuzz build` (PID 14460) hung for 13 min on a dead crates.io socket while holding `~/.cargo/.package-cache`; 9 builds were queued behind it. Killed it; builds resumed within seconds. H told to use `--offline` or HTTP timeouts. |
| 2026-10-31 | 1 | E | Report: timeline + queue (`34fcb46`) | check.sh PASS (Vitest 10 files / 75 tests). e2e 18 passed, 2 `fixme` (both need D's panels), run on a private port because port 1420 collided with another worktree. axe 0 violations, both panels, light and dark. Redraw 50 lanes × 2000 buckets: 14.6 ms median / 15.3 ms p95 at 1400×600 @2x, so WebGL not needed. Brush → selection in 20 ms against the mock. |
| 2026-10-31 | 1 | D | Report: shell + table + packets (`b25609e`) | check.sh PASS (Vitest 8 files / 55 tests). e2e on private port 1461: 30/31 in a full run, the 1 ✘ a Playwright trace-file ENOENT in a scratch dir with all assertions passed; perf spec rerun `2 passed`. axe 0 violations (main, palette, filter error, ingest dialog; light and dark). 1M-row scroll: 60.0 fps on the production build, p95 frame 16.7 ms, 0/301 frames over 20 ms; 56.6 fps on the dev server. |
| 2026-10-31 | 1 | Lead | Log collision | The scratchpad is shared by every agent. H's interim "check.sh passes, 55 Vitest" was read from a `check.log` that D's worktree had overwritten; H withdrew it. All agents told to write logs inside their own worktree. Agent-reported numbers count only after the lead's own check.sh run on each merge. |
