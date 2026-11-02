# Walleye

Local, offline PCAP analyzer for security analysts. It indexes a capture once, then serves a linked timeline, session table, packet pane, suspicion queue and case report. Every finding links back to frame numbers.

- Spec: https://claude.ai/artifact/Jg272c2b929bMgVKCBa3oP
- Build plan for multi-agent runs: `docs/BUILD_PROMPT.md`
- Interfaces between parts: `docs/CONTRACTS.md` (the source of truth; change it only through the lead)
- Why things are the way they are: `docs/DECISIONS.md`

## Stack (decided, do not reopen)

Tauri 2 desktop app · Rust workspace with native parsers (no Zeek) · DuckDB over Parquet index · React + TypeScript + Vite UI · pnpm. The owner is new to Tauri: keep that layer conventional and explain Tauri-specific choices.

## Layout

`crates/walleye-{core,ingest,index,detect,case}` · `app/src-tauri` (commands) · `app/src` (UI) · `rules/` (YAML detections) · `tools/` (generator, bench, eval) · `fuzz/`

## Commands

- `scripts/check.sh` runs fmt, clippy -D warnings, cargo test, lint and Vitest. It must pass before any commit.
- `pnpm tauri dev` runs the app; `pnpm tauri build` packages it.

## Rules

- Treat every capture and fixture as hostile input. Never execute, open or import anything carved from one.
- The app makes no network calls at runtime unless a user turns a feature on.
- The filter language compiles to parameterized SQL only.
- Large fixtures live outside the repo in `$WALLEYE_FIXTURES` (default `~/.walleye-fixtures`) and are never committed.
- Report results with command output; never claim a gate passed without it.
- Keep `README.md` current: when a feature, gate result, command or setup step changes, update the README in the same PR.
