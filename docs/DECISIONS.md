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

## Phase 1

**D18. Ingest reads captures through a reusable buffer, not mmap** (Agent A, reviewed with Agent H). If a mapped file shrinks or changes while it's open, for example tcpdump still writing to it or a file on a network share, the process dies with SIGBUS. mmap also needs `unsafe`, which the workspace denies. The reader streams through a buffer of up to 4 MiB and never loads the whole file. Measured parsing speed is still well above the 150 MB/s target.

**D19. The timeline brush highlights a range; it doesn't zoom** (Agent E). The timeline queries its own zoom window and draws the brushed range on top, so the surrounding context stays visible; "Zoom to range" narrows the view on request. Every other view still filters on `time_range`, so the shared selection model doesn't change.

**D20. Pending contract change: add `link_type` to `FrameRow`** (Agent A). A pcapng file can mix link types across interfaces; without a per-frame link type, `packet()` would decode those frames with the wrong link layer. This goes in at integration, after B's writer merges, together with `case_update_note` (Agent F) and these clarifications: `bytes_*` include retransmissions; a DNS message with no parseable question gets `query = ""` and `qtype = "TYPE0"`; `CaptureRow.path` is canonical and absolute.

## Phase 2 (integration)

**D21. Release builds unwind on panic instead of aborting** (security review, Agent H). Every Tauri command runs its backend call inside `tauri::async_runtime::spawn_blocking`. With `panic = "unwind"`, a panic there (for example a parser bug triggered by a hostile capture) comes back as a `JoinError`, which `commands.rs` turns into an `internal` error; the window stays open and the analyst keeps their case. With `panic = "abort"`, the same bug would kill the whole app. The cost is a slightly larger binary. Panics are still bugs: parsers are fuzzed, and arithmetic on IPC arguments is checked (CONTRACTS §3, "Argument validation").

**D22. The browser mock only runs in development and tests.** `ipc.ts` falls back to the mock backend when it isn't inside Tauri, so the UI can be developed and tested in a plain browser. A production bundle outside Tauri now fails with an error instead, so it can never show invented findings as if they were real.

**D23. Invisible characters are shown, not rendered.** Capture strings (domains, SNI, URIs, user agents, finding titles, decode labels) go through `visible()` in `app/src/shared/format.ts`, which writes control, zero-width and bidi characters as `\u{…}`. A domain with a U+202E right-to-left override can't pose as another name in the table, queue, IOC table or packet tree. The Markdown report does the same (walleye-case).

**D24. Network-deny gate in two halves.** On macOS, `sandbox-exec` with `fuzz/netdeny/netdeny.sb` kills a process on any IP socket or DNS lookup; `scripts/netdeny.sh` runs a headless smoke binary that calls every backend command (open through all four exports) under it, for each fixture, after a self-test proves the profile catches loopback connects, UDP, bind and DNS. WKWebView networking runs in a separate system process that the sandbox can't see, so the UI half is a Playwright request audit (`app/e2e/real/no-network.spec.ts`) over the real engine, with a negative control. The Vite dev server has no CSP (the CSP lives in `tauri.conf.json`), so that audit checks requests, not CSP enforcement.

**D25. The beacon detector's known-good vendor list lives in the rule file.** `known_good_suffixes` (vendor apex domains such as `microsoft.com`) moved from code into `rules/beacon.periodic.yaml`, next to the factor it uses. It is a weaker, beacon-only down-weight (×0.35) than `rules/allowlist.yaml` (specific update hosts, ×0.25, which also flags IOCs); an allowlist match wins. `cloudfront.net` and `fastly.net` left the allowlist: anyone can create a distribution there, and both are documented C2 front ends.

**D26. Capabilities stay at `core:default` + `dialog:allow-open` for the MVP.** The review noted `core:default` grants more than the app uses (window, menu, tray, path, event APIs). None of those let the webview reach the network or the filesystem, and narrowing them can only be checked by running the packaged app, which this build environment can't drive. Narrowing to per-command permissions is a v1 item.

## Wi-Fi (contract v2)

**D27. 802.11 frames get their own table and views instead of being forced into flows.** A monitor-mode capture is mostly management frames and encrypted data: the test capture (WiFi Coconut, 38 min, 1.2 M frames) had 87 unencrypted IP frames. Flows would show almost nothing. The `wifi` table keeps one row per management or data frame with its addresses, SSID, security, channel, signal and reason code; access points and clients are DuckDB views over it, so they need no ingest state and can't drift from the frames. Control frames (ACK/RTS/CTS, about 40 % of the capture) stay only in `frames`: they carry a receiver address and nothing an analyst triages on. Unencrypted 802.11 data still feeds the normal flow pipeline, so open networks get DNS/HTTP/TLS like any other capture.

**D28. Device findings are keyed by MAC, and evidence is frames only.** Wi-Fi attacks have no IP host to blame, so findings use `entity_type = "device"` and the attacker's MAC; their evidence lists frames, with no flows. The UI's selection gains a focused `device` that drives the packet list (`device_frames`) without filtering the table, mirroring how a selected flow drives it today. Filtering by MAC stays in the filter language (`mac X`).

**D29. No vendor (OUI) lookup in this version.** Showing "Apple" or "TP-Link" next to a MAC needs the IEEE OUI registry (about 5 MB, updated monthly). Bundling it is a v1 item; downloading it at runtime would break the no-network rule. The locally administered bit is shown instead, because it's what matters for spoofing and privacy randomization.

**D30. Access-point and client lists are materialized when a capture is large.** Plain DuckDB views over `wifi` kept the lists always in step with the frames, but at 2 M frames the client list took 1.3 s per query (gate: 1 s). Above 50 000 rows the index now builds both as in-memory tables when it opens (about 0.4 s at 2 M rows; queries then take 2–16 ms). They are rebuilt on every open, so they still can't drift.

**D31. SSIDs keep their Unicode.** Network names are often accented or use emoji; escaping every non-ASCII byte would make `wifi.ssid == "Café"` impossible. Valid UTF-8 is kept and only control, bidi/format characters and backslashes are escaped, the same characters `visible()` escapes in the UI (D23).

**D32. Apple AWDL data feeds the flow pipeline.** In the test capture, the only unencrypted IP traffic was AWDL (AirDrop/Continuity) mDNS between nearby Apple devices, which uses its own SNAP OUI and an 8-byte header. Treating it like ordinary LLC/SNAP data gives those frames flows and makes them filterable.
