# Build log

One line per agent dispatch, report and gate result. Numbers come from command output; nothing is marked passed without it.

| When (UTC) | Phase | Who | Event | Result / evidence |
|---|---|---|---|---|
| 2026-10-30 | 0 | Lead | Toolchain check | rustc 1.99.1 + cargo 1.99.1 (stable, rustup; in `~/.cargo/bin`, not on default PATH), Node v22.22.3, pnpm 11.10.0, Xcode at /Applications/Xcode.app. 12 cores, 64 GB RAM. |
| 2026-10-30 | 0 | Lead | Disk check | Finder free (incl. purgeable) 180.08 GB (≥ 60 OK); `df` avail 51 GiB (≥ 40 OK). No warning needed. |
| 2026-10-31 | 0 | Lead | Contracts + skeleton | `walleye-core` (tables, findings, IPC, sink traits, rules, allowlist, field registry, mock backend), Tauri shell with 20 commands on the mock, React shell + shared selection/IPC/mock, docs. |
| 2026-10-31 | 0 | Lead | **Gate 0** `scripts/check.sh` | **PASS** — fmt ok; clippy -D warnings ok; cargo test 65 passed (walleye-core); bindings ok; eslint+tsc ok; Vitest 2 files / 7 tests passed. Also: `pnpm build` ok, `pnpm e2e` 1 passed. |
