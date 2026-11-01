# Fuzzing and network-deny tests

`cargo fuzz` targets for every parser and the filter language, plus the
network-deny harness. This is a separate cargo workspace: it needs nightly and
sanitizer flags, and the root `Cargo.toml` lists it under `exclude`. Owner: Agent H.

```sh
rustup toolchain install nightly        # once
cargo install cargo-fuzz                # once
fuzz/run_all.sh 60                      # smoke: every target that builds today
fuzz/run_all.sh 600                     # DoD gate: 10 min per target
FEATURES="ingest index" fuzz/run_all.sh 600   # once Agents A and B have landed
rustup run nightly cargo fuzz run core_mock_backend fuzz/artifacts/core_mock_backend/<crash>  # replay
```

`run_all.sh` builds, runs each target with its seeds and dictionary, and prints
a table with target, time, execs, coverage, corpus size and status. It exits
non-zero if any target crashed. Limits: `-rss_limit_mb=2048` and `-timeout=10`
(override them with `RSS_MB` and `TIMEOUT_S`).

## Layout

| Path | What |
|---|---|
| `fuzz_targets/*.rs` | One file per target |
| `seeds/<target>/` | Tiny hand-built seeds (committed). Regenerate with `python3 -I fuzz/tools/make_seeds.py` |
| `repro/<target>/` | Reproducers for crashes found in review (committed; synthetic) |
| `dict/*.dict` | libFuzzer dictionaries (JSON args, filter language, YAML) |
| `corpus/`, `artifacts/`, `logs/`, `target/` | Generated, git-ignored |
| `netdeny/` | Network-deny test (see below) |

The seeds are synthetic, built byte by byte from RFC layouts. None of them is a
real capture or a malware sample. Seed files end in `.bin` because the repo's
`.gitignore` ignores `*.pcap`.

## Targets

| Target | Function under test | Feature | Invariants beyond "no panic" |
|---|---|---|---|
| `core_allowlist_yaml` | `Allowlist::from_yaml` | — | accepted CIDRs parse; each entry matches itself |
| `core_allowlist_match` | `Allowlist::{domain,ip,ja4}`, `parse_cidr`, `cidr_contains` | — | domain matches only on a label boundary; a network contains itself; no v4/v6 cross-match |
| `core_rule_yaml` | `RuleDef::from_yaml` | — | JSON round trip is stable; alias bombs stay under the RSS limit |
| `core_render_template` | `rules::render_template` | — | identity when there is no `{` or no values; output length bounded |
| `core_ipc_json` | serde `Deserialize` of every IPC argument type | — | own output re-parses; exact round trip for float-free types |
| `core_mock_filter` | `mock::mock_parse_filter` | — | error span inside the text, on char boundaries |
| `core_mock_backend` | `MockBackend` via Tauri-shaped args JSON, 18 commands (exports excluded) | — | autocomplete replace range inside the input |
| `ingest_read_capture` | `walleye_ingest::fuzz::read_capture(&[u8])` | `ingest` | no hang (timeout), bounded memory |
| `ingest_decode_frame` | `walleye_ingest::decode_frame(link_type, &[u8])` (CONTRACTS §7) | `ingest` | every `DecodeNode.range` lies inside the frame; tree depth < 256 |
| `ingest_dns` | `walleye_ingest::fuzz::parse_dns(&[u8], is_tcp: bool)` | `ingest` | (compression-pointer loops via seeds) |
| `ingest_http` | `walleye_ingest::fuzz::parse_http(&[u8])` | `ingest` | |
| `ingest_tls_client_hello` | `walleye_ingest::fuzz::parse_tls_client_hello(&[u8])` | `ingest` | |
| `ingest_tls_server_hello` | `walleye_ingest::fuzz::parse_tls_server_hello(&[u8])` | `ingest` | |
| `ingest_certificate` | `walleye_ingest::fuzz::parse_certificate(&[u8])` (DER) | `ingest` | |
| `index_filter` | `walleye_index::filter::{parse, compile}` for all 6 views | `index` | over-4-KiB input rejected; `?` count == `params.len()`; no `;`/`--`/`/*`; after removing the fixed `ESCAPE '\'`, no quotes and no non-ASCII, and every word is a registry identifier, table name or fixed keyword (agreed with Agent B) |

### Pending targets: what each one needs

The `ingest` and `index` targets compile only once these public items exist.
Agent A has confirmed the `walleye_ingest::fuzz` names: they take `&[u8]`,
return `()` and never panic.

- **walleye-ingest** (Agent A): `pub mod fuzz { pub fn read_capture(&[u8]); pub fn parse_dns(&[u8], bool); pub fn parse_http(&[u8]); pub fn parse_tls_client_hello(&[u8]); pub fn parse_tls_server_hello(&[u8]); pub fn parse_certificate(&[u8]); }` plus `pub fn decode_frame(u32, &[u8]) -> Vec<DecodeNode>` at the crate root.
- **walleye-index** (Agent B): `pub mod filter { pub fn parse(&str) -> ApiResult<Expr>; pub fn compile(&Expr, View) -> ApiResult<Compiled>; }`, where `Compiled { pub sql: String, pub params: Vec<Param> }` (CONTRACTS §7).

Check with `rustup run nightly cargo fuzz build --features ingest,index`.

## Network-deny test (`netdeny/`)

The DoD requires zero network calls at runtime. There are two halves, because
on macOS the webview's networking runs outside the app's process tree.

1. **Backend and anything it spawns:** `fuzz/netdeny/run_denied.sh -- <cmd>`.
   - **macOS:** `sandbox-exec -f netdeny.sb`. Any IP socket (loopback
     included), bind or DNS lookup SIGKILLs the process (exit 137), so the
     script returns 2 even when the code swallows the error. DNS needs
     explicit rules: `getaddrinfo` talks to mDNSResponder over a unix socket
     and mach service, so an IP-only profile misses it. Verified on macOS 26.6.2.
   - **Linux:** `unshare -rn` plus `strace -f`. The run fails on any
     `AF_INET`/`AF_INET6` socket and on any connect to systemd-resolved or
     nscd. `strace -f` follows WebKitGTK's network process, so on Linux this
     also covers the full app (`xvfb-run`).
   - `fuzz/netdeny/run_denied.sh --selftest` proves the detector works on the
     host: 4 positive controls must be caught and 2 negative controls must
     pass. The probes only use loopback or `localhost`.
2. **Webview:** `netdeny/no-network.spec.ts`, a Playwright test for the lead to
   place in `app/e2e/`. It runs against `vite preview` (the production
   bundle), routes every request, and fails on any that is not same-origin,
   `data:` or `blob:`. It also fails on any WebSocket to another origin and on
   any CSP violation.

**Proposed gate for the lead (`scripts/netdeny.sh`):**

```sh
fuzz/netdeny/run_denied.sh --selftest
# Backend end to end, real crates, real fixture. A headless smoke binary that
# opens a capture, waits for done, runs query/timeline/findings/packet and
# both exports (e.g. `cargo run -p walleye-app --example smoke -- <pcap>`):
cargo build --release --example smoke -p walleye-app
fuzz/netdeny/run_denied.sh -- target/release/examples/smoke "$WALLEYE_FIXTURES/generated/beacon.pcap"
# Webview:
(cd app && pnpm build && pnpm exec playwright test e2e/no-network.spec.ts)
# Linux only: the whole packaged app under xvfb for 20 s. `timeout` makes the
# command exit non-zero (rc 1 from the script); exit 2 means a network attempt.
# WALLEYE_BACKEND=mock-open xvfb-run fuzz/netdeny/run_denied.sh -- timeout 20 target/release/walleye-app
```
