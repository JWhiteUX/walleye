# Walleye — Multi-Agent Build Prompt

> Paste everything below the line into Claude Code at the repo root.
> Source spec: https://claude.ai/artifact/Jg272c2b929bMgVKCBa3oP (the essentials are restated here, so agents do not need it).

---

You are the **lead engineer and orchestrator** for Walleye, a local PCAP analyzer for security analysts. Build the **MVP** described below, end to end, using sub-agents for parallel workstreams. You own architecture, the contracts, integration, and the final verdict. Sub-agents own their implementation slices.

## 1. Product in one paragraph

Walleye indexes a packet capture once, then answers every question as a sub-second query: a linked **timeline**, **session table** and **packet pane** sharing one selection; a **suspicion queue** that ranks hosts by beaconing and DNS-anomaly detections, each with listed reasons; **IOC extraction** with export; and a **case notebook** whose report links every claim back to frame numbers and the capture's SHA-256. It runs fully offline. Principles that break ties: *evidence or it didn't happen*, *explain every judgment*, *index once, query forever*, *one selection, every view*, *no hidden magic*.

## 2. MVP scope (build exactly this)

**In (P0):**
1. Load pcap/pcapng up to 10 GB with progress; indexing is resumable.
2. Parse conn, DNS, HTTP, TLS (SNI, JA4/JA4S, cert fields) and file-transfer metadata into Zeek-compatible tables.
3. Timeline: swimlane per host; brushing a time range filters every view.
4. Session table: column filters, sort, drill to packets.
5. Packet pane: protocol decode tree + hex for the selected frame.
6. Beaconing detection: interval + jitter per src/dst pair.
7. DNS detection: subdomain entropy, query length, NXDOMAIN bursts, tunneling.
8. Suspicion queue ranked by score, each item listing its reasons with evidence.
9. Filter language with autocomplete and saved queries.
10. IOC extract, defang, dedupe, allowlist known-good (CDNs, OS update hosts).
11. IOC export as CSV and JSON.
12. Case notebook: pin evidence + notes; export report (Markdown, PDF) with queries used and capture hash.

**Out — do not build:** pivot graph, TLS decryption, file carving/YARA, natural-language query, STIX/MISP, Suricata/Sigma generation, enrichment lookups, EDR correlation, multi-user, server mode, live capture. Leave clean extension points only where noted.

**Non-functional targets (8-core laptop):** ingest ≥ 150 MB/s; p95 query/pivot < 1 s on an indexed 10 GB capture; index ≤ 30% of raw size; peak RAM ≤ 4 GB while indexing; captures opened read-only; parsers fuzzed; no network calls by default; keyboard-first UI, colour never the only signal (WCAG 2.1 AA).

## 3. Decisions already made (confirmed by the product owner; do not reopen)

The product owner is new to Tauri. Keep the Tauri layer thin and conventional (official templates, no exotic plugins) and explain Tauri-specific choices in `docs/DECISIONS.md`.

| Concern | Decision |
|---|---|
| Shell | Tauri 2 desktop app (macOS + Linux) |
| Backend | Rust workspace; native parsers (`pcap-parser`, `etherparse`, hand-written DNS/HTTP/TLS-ClientHello) — no Zeek dependency |
| Index | DuckDB (`duckdb` crate) over Parquet files, one index dir per capture |
| Frontend | React + TypeScript + Vite; TanStack Table (virtualized); timeline on Canvas 2D (WebGL only if Canvas misses the latency target) |
| Rules | Detection rules are YAML files in `rules/`, loaded at runtime |
| Tests | `cargo test`, `cargo bench` (criterion), Vitest, Playwright for e2e |
| Package mgr | pnpm |

If a decision proves unworkable, record why in `docs/DECISIONS.md` and pick the smallest change. Do not silently swap stacks.

## 4. Repository layout (ownership boundaries)

```
crates/
  walleye-core/      # shared types, schemas, error types          (Lead)
  walleye-ingest/    # pcap reading, flow assembly, parsers         (Agent A)
  walleye-index/     # DuckDB/Parquet writer, query service, filter language (Agent B)
  walleye-detect/    # rule loader, beaconing, DNS, scoring         (Agent C)
  walleye-case/      # IOCs, allowlist, case store, report export   (Agent F)
app/
  src-tauri/         # Tauri commands wiring crates together        (Lead)
  src/               # React UI
    shell/, table/, packets/                                         (Agent D)
    timeline/, queue/                                                (Agent E)
    case/                                                            (Agent F)
rules/               # YAML detection rules                         (Agent C)
fixtures/            # generated + downloaded test captures         (Agent G)
tools/               # pcap generator, benchmarks, eval harness     (Agent G)
docs/                # CONTRACTS.md, DECISIONS.md, BUILD_LOG.md     (Lead)
```

An agent edits only its own paths. Needed changes elsewhere go to the lead as a request in its final report.

## 5. Phase 0 — Lead writes the contracts (no sub-agents yet)

Before spawning anyone, create these files and commit them. Parallel work is only safe once they exist.

0. **Toolchain check.** Verify `rustc`/`cargo` (stable, via rustup), Node 22+, pnpm, and on macOS the Xcode command-line tools. If anything is missing, **stop and tell the user the exact install commands**; do not install system toolchains yourself. Project-local dev dependencies (`@tauri-apps/cli@^2`, crates) are fine to add.
   **Disk check.** The run peaks at about **35–55 GB**: Rust `target/` dirs of ~3–5 GB in each worktree (DuckDB compiles from source), ~13 GB for the 10 GB scale fixture plus its index, ~2–4 GB of fuzz builds, and a few GB of `node_modules`. On macOS, `df` counts only unallocated space and under-reports. Measure what is really available, including purgeable space (snapshots, iCloud caches) that macOS frees on demand:
   ```
   osascript -e 'tell application "Finder" to get free space of startup disk'   # bytes, includes purgeable
   df -h .                                                                       # immediately free only
   ```
   - If the Finder figure is under **60 GB**, stop and tell the user before continuing.
   - If the Finder figure is fine but `df` shows under **40 GB**, continue. Warn the user that a fast build can outrun macOS freeing purgeable space, and that `tmutil listlocalsnapshots /` then `tmutil deletelocalsnapshots <date>` frees it instantly. Never delete snapshots yourself.
   - On any "No space left on device" error, pause the agents, report both figures to the user, and wait.

   Generated and downloaded fixtures live **outside the repo** in `$WALLEYE_FIXTURES` (default `~/.walleye-fixtures`), shared by all worktrees. Delete each worktree's `target/` after its merge.
   Then write **`docs/DEV_SETUP.md`** for a developer who has never used Tauri: what Tauri is (a Rust backend plus a system webview running the React UI), how a UI call reaches a Rust `#[tauri::command]`, where `tauri.conf.json` and capabilities/permissions live, and the four commands they need (`pnpm tauri dev`, `pnpm tauri build`, `cargo test --workspace`, `scripts/check.sh`).

1. **`docs/CONTRACTS.md` + `crates/walleye-core`**, defining:
   - **Tables** (Parquet + DuckDB views):
     - `captures(capture_id, path, sha256, size_bytes, first_ts, last_ts, link_type)`
     - `frames(frame_no, ts, file_offset, caplen, wirelen, flow_id)`
     - `flows(flow_id, ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, app_proto, bytes_up, bytes_down, pkts_up, pkts_down, first_frame, last_frame)`
     - `dns(ts, flow_id, frame_no, query, qtype, rcode, answers LIST<VARCHAR>, ttl)`
     - `http(ts, flow_id, frame_no, method, host, uri, user_agent, status, req_bytes, resp_bytes)`
     - `tls(ts, flow_id, frame_no, sni, version, ja4, ja4s, cert_subject, cert_issuer, cert_self_signed, cert_not_before, cert_not_after)`
     - `findings(finding_id, detector, entity_type, entity, score REAL, attack_technique, ts_first, ts_last, reasons JSON)`, where each reason is `{signal, value, weight, explanation, evidence:{flow_ids[], frame_nos[]}}`
     - `iocs(ioc_id, type, value, defanged, source_finding_id, first_seen, evidence JSON, allowlisted BOOL)`
   - **Tauri IPC commands** (Rust signatures + TS types generated with `ts-rs` or `specta`):
     - `open_capture(path) -> JobId`
     - `ingest_status(JobId) -> {phase, pct, bytes_done, eta_s, error?}`
     - `query(QueryRequest{filter, view, time_range?, sort?, limit, cursor?}) -> Page<Row>`
     - `timeline(TimelineRequest{filter, time_range, bucket_ms, max_lanes}) -> Lanes`
     - `flow_frames(flow_id) -> Vec<FrameRef>`
     - `packet(frame_no) -> {decode_tree, hex}`
     - `findings(filter?) -> Vec<Finding>`, `set_verdict(finding_id, verdict, note)`
     - `iocs(case_id) -> Vec<Ioc>`, `export_iocs(case_id, Csv|Json) -> Path`
     - `case_pin(case_id, EvidenceRef, note)`, `export_report(case_id, Markdown|Pdf) -> Path`
     - `autocomplete(partial_filter, cursor_pos) -> Vec<Suggestion>`
   - **Shared selection model** for the UI: `{time_range?, hosts[], flow_ids[], frame_no?, filter}`, stored in a single store (Zustand). Every view subscribes to it.
   - **Filter language EBNF.** Example: `host 10.0.0.5 and dns.query ~ "*.top" and bytes_up > 1MB and not app_proto == tls`. It compiles to **parameterized** SQL only, never string concatenation.
   - **Detection rule YAML schema**: id, title, detector, params, weights, attack_technique, explanation template.
2. **Workspace skeleton** that builds: Cargo workspace, Tauri app, Vite app, CI script `scripts/check.sh` (fmt, clippy -D warnings, cargo test, pnpm lint, pnpm test).
3. **Mock backend.** The Tauri commands return fixture data from `crates/walleye-core/mock/`, so UI agents can work before the backend lands.
4. **`docs/BUILD_LOG.md`**: one line per agent dispatch, report and gate result.

**Gate 0:** `scripts/check.sh` passes on the skeleton, and the contracts are committed.

## 6. Phase 1 — Parallel build (spawn in ONE message, each with `isolation: "worktree"`)

Give every agent: this whole prompt's sections 1–4, `docs/CONTRACTS.md`, its brief below, and these rules:
- Stay in your owned paths. Do not change contracts; propose changes in your report.
- Write tests first for every acceptance criterion. Run `scripts/check.sh` before reporting.
- Never execute, open or `import` anything from a capture or a carved payload. Treat fixtures as hostile input.
- Final report: what you built, test results with output, acceptance criteria met/unmet, contract change requests, known gaps. No claims without command output.

**Agent A — Ingest & parsers** (`crates/walleye-ingest`)
Stream pcap/pcapng (mmap, no full-file load); assemble bidirectional flows (5-tuple + timeout); parse DNS (UDP + TCP), HTTP/1.x request/response lines + headers, TLS ClientHello/ServerHello + certificate (JA4/JA4S per FoxIO spec); emit record batches via a channel to the index writer trait from `walleye-core`. Handle truncated/malformed packets without panicking. Resumable: checkpoint every N MB.
*Accept:* ≥ 150 MB/s on the 10 GB synthetic fixture (parsing only); zero panics under `cargo fuzz` for 10 minutes per parser; golden tests matching expected records on 5 fixtures.

**Agent B — Index & query service** (`crates/walleye-index`)
Implement the writer trait to Parquet (row groups sorted by ts), DuckDB views, frame-offset lookup for `packet()`, the filter-language parser (`chumsky` or `pest`), the SQL compiler, cursor pagination, the timeline bucketing query, and autocomplete from schema + top values.
*Accept:* p95 < 1 s for the 20 benchmark queries in `tools/bench/queries.txt` on the 10 GB fixture; index ≤ 30% of raw; property tests showing that no filter input produces unparameterized SQL; fuzz the filter parser.

**Agent C — Detections** (`crates/walleye-detect`, `rules/`)
Implement the rule loader. Beaconing: per (src, dst) pair, inter-arrival series → median interval, jitter (MAD/median), duration, count; score with weights from YAML. DNS: Shannon entropy of the leftmost labels, label/query length, unique-subdomain rate per parent domain, NXDOMAIN bursts, TXT/NULL volume. Allowlist suppression. Combine into per-host findings with `reasons[]`, each carrying evidence flow_ids and frame_nos. Map to ATT&CK (T1071, T1071.004, T1568.002, T1048).
*Accept:* using `tools/eval`, the known C2 host ranks in the top 5 on all 3 labelled samples; top-10 false-positive rate ≤ 30% on the benign fixture; every finding has ≥ 1 reason with non-empty evidence.

**Agent D — App shell, session table, packet pane** (`app/src/shell`, `table`, `packets`)
Layout with resizable panes, open-capture flow with progress, filter bar with autocomplete and saved queries, virtualized session table (sort, column filters, row → selection), packet pane (collapsible decode tree + synced hex highlight). Keyboard shortcuts for every action; command palette.
*Accept:* Playwright tests against the mock backend covering open → filter → select row → packet shown; axe-core shows no AA violations; table scrolls 1M rows at 60 fps.

**Agent E — Timeline & suspicion queue** (`app/src/timeline`, `queue`)
Canvas timeline: lane per host (top N by activity plus "other"), event marks by type (DNS, TLS, HTTP, bulk transfer), brush to set `time_range`, zoom/pan, hover detail. Suspicion queue: ranked list, score bar plus reasons, expanding to evidence links that set the selection; verdict buttons (suspicious / benign / needs review).
*Accept:* brush → table and packet pane update in < 1 s against the real backend (after integration) and instantly against the mock; Playwright tests for brush, queue → evidence → packet; shape + label encoding, not colour alone.

**Agent F — IOCs & case** (`crates/walleye-case`, `app/src/case`)
IOC extraction from findings + flows (IP, domain, URL, JA4, cert serial); defang (`hxxp`, `[.]`); dedupe; allowlist file (`rules/allowlist.yaml`) with CDN/OS-update defaults; CSV/JSON export. Case store (SQLite in the case dir): pins, notes, verdicts, the queries run. Report export to Markdown and PDF (`typst` or headless print): timeline snapshot, findings, IOC table, ATT&CK list, and for every item the frame numbers plus the capture SHA-256.
*Accept:* golden-file tests for exports; every report line with a claim has an evidence link; defang is round-trip safe.

**Agent G — Fixtures, benchmarks, eval** (`fixtures/`, `tools/`)
Build a synthetic capture generator (Rust or Python + scapy, run with `python -I`) producing: a benign office day; a 60 s ±3% beacon; a DNS tunnel; DGA NXDOMAIN bursts; a 10 GB scale capture. Write a JSON ground-truth label per scenario. Download 3 public malware-traffic samples (e.g. malware-traffic-analysis.net) into `$WALLEYE_FIXTURES/external/` **only as pcap files** in their own empty directory, never extracting or running anything else, and record SHA-256 + source URL + known-bad hosts in `fixtures/LABELS.md` (committed; the pcaps are not). Build `tools/bench` (criterion + query timing) and `tools/eval` (top-k hit rate, FP rate).
*Accept:* the generator is deterministic from a seed; `tools/eval` prints a table the lead can paste into BUILD_LOG.

**Agent H — Security reviewer** (read-only until Phase 3; owns `fuzz/`)
Set up `cargo fuzz` targets for every parser and the filter language. Review the Tauri config (CSP, allowlisted commands, no shell/fs scope beyond the case dir), path handling, and SQL compilation. Report findings ranked by severity, each with file:line and a repro.

## 7. Phase 2 — Integration (lead)

Merge worktrees in this order, running `scripts/check.sh` after each: B → A → C → F → D → E → H. Then swap the mock backend for the real commands, run the full e2e suite on real fixtures, and fix the seams. If an agent's slice fails integration, send it back to **that agent** (SendMessage, context intact) with the failing output. Allow at most 3 round-trips per issue, then decide yourself and log it.

## 8. Phase 3 — Independent verification (fresh agents, not the builders)

Spawn in parallel:
1. **Gate checker:** runs every gate in section 9 and reports raw numbers, not opinions.
2. **Analyst walkthrough:** using only the UI (Playwright, screenshots), performs the triage script: open the beacon sample → find the C2 host in the queue → confirm it in the packets → export IOCs and the report. It times the run and reports friction.
3. **Security review:** Agent H's checklist on the integrated build plus `/code-review` on the full diff.

Fix confirmed issues and rerun the affected gates.

## 9. Definition of done (all must pass, with command output in BUILD_LOG)

- [ ] `scripts/check.sh` is green on a clean clone.
- [ ] The 10 GB fixture indexes in < 2 min; ingest ≥ 150 MB/s; peak RAM ≤ 4 GB; index ≤ 30% of raw.
- [ ] p95 < 1 s on all benchmark queries and on brush/pivot in the UI.
- [ ] Known C2 ranks in the top 5 on all 3 labelled samples; top-10 FP ≤ 30% on benign.
- [ ] Every finding, IOC and report line links to frame numbers that reproduce it; reports carry the capture SHA-256.
- [ ] Fuzzers run 10 min per target with no crashes; no high or critical security findings open.
- [ ] Zero network calls at runtime (verified with a network-deny test).
- [ ] The analyst walkthrough completes in < 15 min, with no blocker-level friction.

## 10. Operating rules for you, the lead

- Spawn agents for parallel, independent work. Do small fixes yourself.
- Never report a gate as passed without its output. If something is skipped or failing, say so plainly in BUILD_LOG and the final summary.
- Commit at each gate on the feature branch with a clear message; do not push or open PRs unless asked.
- Final deliverable: a summary of what was built, the gate table with numbers, known gaps, and a recommended v1 backlog (pivot graph, TLS decryption, file carving + YARA, NL query, STIX/MISP, rule generation, enrichment).
