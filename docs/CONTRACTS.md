# Walleye contracts

The interfaces between parts. **This file and `crates/walleye-core` are the source of truth.** Only the lead changes them; agents propose changes in their final report.

Contract version: **2** (`walleye_core::CONTRACT_VERSION`). Version 2 adds 802.11 (Wi-Fi) captures: §11.

| § | Contract | Code |
|---|----------|------|
| 1 | Units and identifiers | `walleye-core/src/lib.rs` |
| 2 | Index tables | `walleye-core/src/tables.rs`, `findings.rs` |
| 3 | Tauri IPC commands | `walleye-core/src/backend.rs`, `ipc.rs`, `app/src-tauri/src/commands.rs`, `app/src/shared/ipc.ts` |
| 4 | UI shared selection and cross-panel seams | `app/src/shared/*` |
| 5 | Filter language | `walleye-core/src/fields.rs` (+ grammar below) |
| 6 | Detection rule YAML and allowlist | `walleye-core/src/rules.rs`, `allowlist.rs` |
| 7 | Crate APIs (ingest → index → detect → case → app) | `walleye-core/src/sink.rs` + signatures below |
| 8 | On-disk layout | below |
| 9 | Fixtures, labels, bench and eval | below |
| 10 | Mock backend | `walleye-core/src/mock.rs`, `mock/`, `app/src/shared/mock.ts` |
| 11 | 802.11 (Wi-Fi) captures | `walleye-core/src/tables.rs` (`Wifi*`), `mac.rs`, `ipc.rs`, `fields.rs`, `sink.rs` |

---

## 1. Units and identifiers

| Thing | Type | Rule |
|---|---|---|
| Timestamps (`ts`, `ts_*`, `first_seen`, `at`, …) | `i64` | Microseconds since Unix epoch, UTC. A JS number holds it exactly. |
| `frame_no` | `u64` | 1-based, capture order (Wireshark numbering). |
| `flow_id` | `u64` | Assigned sequentially from 1 by ingest when a flow opens. Always < 2^53. |
| `capture_id` | `String` | First 16 lowercase hex chars of the capture's SHA-256. |
| `case_id` | `String` | MVP: one case per capture, `case_id == capture_id`. |
| `finding_id`, `ioc_id` | `String` | 16 lowercase hex chars of a stable hash (see §2). Same input → same id across runs. |
| IP addresses | `String` | Canonical `std::net::IpAddr` text (`10.0.0.5`, `2001:db8::1`). |
| Durations in params | seconds unless the key ends in `_ms`/`_us`. |
| Sizes in the filter language | `B`, `KB`, `MB`, `GB` are powers of 1024. |

## 2. Index tables

One Parquet dataset per table, row groups sorted by time, exposed as a DuckDB view of the same name. Column names, order and nullability match the Rust structs exactly. Over IPC, `None` is `null`.

| Table | Struct | Key columns | Notes |
|---|---|---|---|
| `captures` | `CaptureRow` | `capture_id` | `capture_id, path, sha256, size_bytes, format, first_ts, last_ts, link_type, frame_count` |
| `frames` | `FrameRow` | `frame_no` | `frame_no, ts, file_offset, caplen, wirelen, flow_id?, direction?, tcp_flags?, payload_len, link_type?`. `file_offset` points at the packet **data** (after the record header). `link_type` is per frame (pcapng interfaces can differ); `null` = unknown, use the capture's. |
| `flows` | `FlowRow` | `flow_id` | `flow_id, ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, app_proto?, bytes_up, bytes_down, pkts_up, pkts_down, first_frame, last_frame`. `src` = initiator (SYN sender, else first packet). `bytes_*` count transport payload bytes. |
| `dns` | `DnsRow` | `(flow_id, frame_no)` | `ts, flow_id, frame_no, trans_id, is_response, query, qtype, rcode?, answers LIST<VARCHAR>, ttl?`. One row per DNS message. `query` lowercase, no trailing dot. `qtype`/`rcode` are mnemonics or `TYPE<n>`/`RCODE<n>`. |
| `http` | `HttpRow` | `(flow_id, frame_no)` | `ts, flow_id, frame_no, method?, host?, uri?, user_agent?, status?, resp_frame_no?, req_bytes, resp_bytes`. One row per request, paired with its response in order. |
| `tls` | `TlsRow` | `(flow_id, frame_no)` | `ts, flow_id, frame_no, sni?, version?, ja4?, ja4s?, cert_subject?, cert_issuer?, cert_serial?, cert_self_signed?, cert_not_before?, cert_not_after?`. One row per ClientHello. JA4/JA4S per the FoxIO spec. |
| `files` | `FileRow` | `(flow_id, frame_no)` | Transfer **metadata** only: `ts, flow_id, frame_no, source, direction, filename?, mime_type?, size_bytes?`. No body bytes are stored, hashed or carved. |
| `findings` | `Finding` | `finding_id` | `finding_id, title, detector, entity_type, entity, score REAL, attack_technique?, ts_first, ts_last, reasons JSON`. `verdict` is not stored here (case store). |
| `iocs` | `Ioc` | `ioc_id` | `ioc_id, type, value, defanged, source_finding_id?, first_seen, evidence JSON, allowlisted, allowlist_reason?` |

**Reason** (`reasons[]` element): `{rule_id, signal, value, unit?, weight, explanation, attack_technique?, evidence}`.
**Evidence**: `{flow_ids[], frame_nos[], truncated, total}`. Never empty on a reason or IOC. Lists are capped at `EVIDENCE_CAP` (200): keep the earliest, set `truncated`, report the real `total`.

**Stable ids:** `finding_id = hex16(sha256("finding\0" + entity_type + "\0" + entity))` (no detector: a host's top reason can change between runs, and the id must not, or verdicts are orphaned), `ioc_id = hex16(sha256("ioc\0" + type + "\0" + value))`, where `type` is the snake_case `IocType`.

**Scores:** each reason contributes `weight × strength` (strength 0..1) points. A finding's score is `min(100, Σ points)` over its reasons. Reasons are sorted by `weight` descending; the top one sets `detector` and `attack_technique`. Entity for the MVP is always the internal host (`entity_type = "host"`, `entity = src_ip`).

**Direction:** `up` = initiator → responder, `down` = responder → initiator.

## 3. Tauri IPC commands

All commands are `async`, take snake_case argument names (`#[tauri::command(rename_all = "snake_case")]`) and return `Result<T, ApiError>`. On the TS side, `app/src/shared/ipc.ts` exposes them as `api.*` and throws `WalleyeError {code, message, span}`.

| Command | Args | Returns |
|---|---|---|
| `open_capture` | `path: string` | `JobId` (string). Opens read-only; resumes from checkpoint if the same SHA-256 was partially indexed. |
| `ingest_status` | `job_id` | `IngestStatus {job_id, phase, pct, bytes_done, bytes_total, eta_s?, error?, resumed, session?}`. `phase`: `queued → hashing → indexing → detecting → done` or `failed`/`cancelled`. `pct` spans the whole job. `session` set when `done`. |
| `cancel_ingest` | `job_id` | `null`. Leaves the last checkpoint so a later `open_capture` resumes. |
| `current_capture` | — | `CaptureSession {capture, case_id} \| null` |
| `query` | `req: QueryRequest {filter, view, time_range?, hosts?, flow_ids?, sort?, limit, cursor?}` | `Page {data: RowSet, next_cursor?, total?, sql?, elapsed_ms}`. `RowSet = {view, rows}` tagged by view. `limit` 1..10 000. `sql` has `?` placeholders, never values. `hosts`/`flow_ids` AND with the filter; within each list, OR. |
| `timeline` | `req: TimelineRequest {filter, time_range?, bucket_ms, max_lanes}` | `Lanes {bucket_ms, range, lanes: Lane[]}`. `Lane {host, is_other, total, max_score?, buckets: Bucket[]}`. Lanes are keyed by flow initiator (`src_ip`), top `max_lanes` by flow count, then one `other` lane. `Bucket {t, dns, tls, http, bulk, other}` counts flow **starts** per kind; sparse. Bulk = flow with ≥ 1 MiB total bytes (takes precedence over its app proto). Backend may widen `bucket_ms` to keep ≤ 2000 buckets. |
| `flow_frames` | `flow_id` | `FrameRef[] {frame_no, ts, caplen, wirelen, direction?, tcp_flags?, payload_len, summary}` in frame order. |
| `packet` | `frame_no` | `PacketView {frame_no, ts, caplen, wirelen, link_type, flow_id?, decode_tree: DecodeNode[], bytes_hex}`. `DecodeNode {label, field?, value?, range? {start, len}, warning?, children}`; `range` indexes into the frame bytes; `field` names a filter field when one exists. `bytes_hex` covers at most the first 1 MiB of the frame (`caplen` gives the full size). |
| `autocomplete` | `partial_filter, cursor_pos` (byte offset) | `Suggestion[] {label, insert_text, kind, detail?, replace_start, replace_end}`. `kind`: `field`, `operator`, `keyword`, `value`, `saved`. Values come from the index's top values for the field. |
| `list_saved_queries` | — | `SavedQuery[] {name, filter, view}` |
| `save_query` | `query: SavedQuery` | `null`. Same name replaces. Filter must parse. |
| `delete_saved_query` | `name` | `null` |
| `findings` | `filter?: FindingsFilter {min_score?, detector?, entity?, time_range?}` | `Finding[]` sorted by score desc, with `verdict` joined from the case. |
| `set_verdict` | `finding_id, verdict, note` | `null`. `verdict`: `suspicious`, `benign`, `needs_review`. |
| `iocs` | `case_id` | `Ioc[]` |
| `export_iocs` | `case_id, format: "csv" \| "json"` | absolute path inside `<case>/exports/` |
| `get_case` | `case_id` | `Case {case_id, capture, pins, verdicts, queries}` |
| `case_pin` | `case_id, evidence: EvidenceRef, note` | `Pin {pin_id, evidence, note, resolved: Evidence, created_at}`. `EvidenceRef` is tagged by `kind`: `frame{frame_no}`, `flow{flow_id}`, `finding{finding_id}`, `ioc{ioc_id}`, `query{filter, view, time_range}`, `note`. The backend resolves it to frames at pin time. |
| `case_unpin` | `case_id, pin_id` | `null` |
| `case_update_note` | `case_id, pin_id, note` | `Pin` with the new note (≤ 16 KiB). |
| `export_report` | `case_id, format: "markdown" \| "pdf", timeline_png_base64?` | absolute path inside `<case>/exports/` |

`ApiError {code, message, span?}`. `code`: `invalid_filter` (with `span` into the filter text), `invalid_argument`, `not_found`, `no_capture`, `bad_capture`, `io`, `cancelled`, `internal`. Messages never contain raw capture bytes.

The backend logs every `query` call into the open case (`Case.queries`, newest 10 000 kept), so reports can list the queries used.

**Argument validation (security review, all backends):**
- `case_id` must equal the open session's `case_id`, else `not_found`. File paths are built from the session, never from an argument, and always land under `<data_dir>`.
- `open_capture.path` must canonicalize to a non-empty regular file (no FIFOs, devices or directories), else `bad_capture`.
- `time_range` must have `end > start`; arithmetic on hostile ranges and `bucket_ms` is checked or saturating, never wrapping. Invalid → `invalid_argument`.
- Size caps: `note` 16 KiB, `timeline_png_base64` (decoded PNG cap in walleye-case), saved-query filter 4 KiB and 500 saved queries, `hosts` 1 000, `flow_ids` 10 000, `cursor` 16 KiB.
- A panic inside a command is a bug, but it must not take the app down: release builds use `panic = "unwind"`, so `spawn_blocking` turns it into `internal` (D21).

**Adding a command** touches four places, in this order: `Backend` trait → `MockBackend` → `commands.rs` (+ `handler()`) → `ipc.ts` (+ `mock.ts`). Only the lead does this.

## 4. UI shared state and seams (`app/src/shared`, lead-owned)

**Selection** (`selection.ts`, Zustand): one store, every view subscribes.

```ts
interface Selection {
  time_range: TimeRange | null; // timeline brush; null = whole capture
  hosts: string[];              // lane/host clicks
  flow_ids: number[];           // table row(s), evidence links
  frame_no: number | null;      // packet pane
  filter: string;               // committed filter-bar text
}
```

| Writer | Action |
|---|---|
| Timeline brush | `setTimeRange` |
| Timeline lane label / host cell | `toggleHost` / `setHosts` |
| Session table row | `selectFlows([flow_id])`, then `selectFrame(first_frame)` |
| Packet list row | `selectFrame` |
| Queue evidence link | `applyEvidence(evidence)` (flows + first frame) |
| Filter bar submit | `setFilter` |

Readers build requests with `selectionScope(selection)` → `{filter, time_range, hosts, flow_ids}`. The session table queries with the full scope **except** that selecting a row must not filter the table to that row: the table passes `flow_ids: []` and highlights selected rows instead. The timeline uses `filter` + `time_range` only (it draws hosts as lanes).

**Other seams:**

| File | Purpose |
|---|---|
| `ipc.ts` | `api.*`, `WalleyeError`, `isTauri()`, `pickCaptureFile()`. The only backend access. |
| `session.ts` | `useSession` → `{session: CaptureSession \| null}`. Set by the shell's open flow. |
| `commands.ts` | `useRegisterCommands([...])`: register actions with optional shortcut; the shell renders the palette and owns the global key handler. Ids are `<area>.<verb>` (`timeline.zoom-in`). |
| `caseEvents.ts` | `pinEvidence(ref, note)` from any panel; the case panel re-reads on `useCaseEvents.version` change. |
| `snapshots.ts` | Timeline registers `() => base64Png`; report export calls `getTimelineSnapshot()`. |
| `encoding.ts` | Event kind → label + shape + colour var; score bands. Colour is never the only signal. |
| `format.ts` | `formatTs`, `formatTime`, `formatBytes`, `formatDuration`, `protoName`, `defang`. |
| `theme.css` | CSS custom properties (`--wl-*`). Panels use these, not literal colours. |
| `filterFields.ts` | Field registry for autocomplete/help, generated from Rust. |
| `bindings/` | ts-rs output. Generated by `cargo test -p walleye-core`; never hand-edit. |

**Panel exports** (the shell imports these names; each agent owns its directory):

| Directory | Export | Owner |
|---|---|---|
| `shell/` | `AppShell` | D |
| `table/` | `SessionTable` | D |
| `packets/` | `PacketPane` | D |
| `timeline/` | `TimelinePanel` | E |
| `queue/` | `QueuePanel` | E |
| `case/` | `CasePanel` | F |

Each panel root has `data-testid="<dir>-panel"` and an accessible name. Captured strings are rendered as text only (`dangerouslySetInnerHTML` and `innerHTML` are lint errors). Indicators (domains, URLs) are never rendered as live links.

## 5. Filter language

Compiles to **parameterized SQL only**. Field names resolve through the registry (`walleye_core::fields::FIELDS`), whose `sql` expressions are trusted code; every literal becomes a bound parameter. No user text is ever concatenated into SQL.

```ebnf
filter      = [ or_expr ] ;
or_expr     = and_expr , { "or" , and_expr } ;
and_expr    = unary , { [ "and" ] , unary } ;          (* juxtaposition = and *)
unary       = "not" , unary | "!" , unary | primary ;
primary     = "(" , or_expr , ")"
            | shorthand
            | comparison
            | bare_proto ;
shorthand   = ( "host" | "src" | "dst" ) , ip_value
            | "port" , integer ;
comparison  = field , op , value
            | field , "in" , "[" , value , { "," , value } , "]" ;
bare_proto  = "dns" | "http" | "tls" | "tcp" | "udp" | "icmp" ;
field       = ident , { "." , ident } ;                (* must be in FIELDS *)
op          = "==" | "!=" | ">" | ">=" | "<" | "<=" | "~" ;
value       = string | number | ip_value | ident ;
ip_value    = ipv4 [ "/" , digit+ ] | ipv6 [ "/" , digit+ ] ;
number      = digit+ [ "." digit+ ] [ unit ] ;
unit        = "B" | "KB" | "MB" | "GB" | "us" | "ms" | "s" | "m" | "h" ;
string      = '"' , { char - '"' - "\" | "\" , ( '"' | "\" ) } , '"' ;
ident       = ( letter | "_" ) , { letter | digit | "_" | "-" } ;
```

Semantics:

- Keywords (`and or not in host src dst port`) are case-insensitive; field names are lowercase.
- `host X` ≡ `(src_ip == X or dst_ip == X)`; `src X` ≡ `src_ip == X`; `dst X` ≡ `dst_ip == X`; `port N` ≡ `(src_port == N or dst_port == N)`. A CIDR value means "in network".
- Bare protocol: `dns`/`http`/`tls` ≡ `app_proto == name`; `tcp`/`udp`/`icmp` ≡ `proto == number`.
- `~` is a case-insensitive glob (`*` any run, `?` one char) → `ILIKE ? ESCAPE '\'` with `%`, `_`, `\` in the literal escaped. On `str_list` fields it matches any element.
- A bare `ident` value is a string (`app_proto == tls`).
- Type errors (`bytes_up ~ "x"`, `src_ip > 5`, unknown field) are `invalid_filter` errors with a `span`.
- Fields of another table reach the queried view via `flow_id`: on `flows`, `dns.query ~ "*.top"` → `flow_id IN (SELECT flow_id FROM dns WHERE query ILIKE ?)`; on `dns`, `bytes_up > 1MB` → `flow_id IN (SELECT flow_id FROM flows WHERE (bytes_up) > ?)`. `frames` fields only apply on the `frames` view.
- Limits: 4 KiB of text, nesting depth 64, 256 terms. Over limit → `invalid_filter`.

SQL inputs outside the filter text follow the same rule (agreed with Agent B):
- `sort.column` is matched against the view's static column list and the matched static name is used; unknown → `invalid_argument`. Rows are ordered by the sort column, then the view's key columns, then every other scalar column, so order is total and paging is stable.
- `cursor` is opaque (base64url JSON, ≤ 16 KiB): a keyset on `(sort value, keys)` plus a tie-skip count, bound to the query it came from by a hash of `(filter, view, time_range, hosts, flow_ids, sort)`. A cursor from another query, or a malformed one, is `invalid_argument`. All cursor values are bound parameters.
- `hosts[]` must parse as IP addresses or CIDRs (IPv6 networks larger than 10 000 addresses are rejected); `flow_ids[]` are integers. Both are bound parameters.
- `FindingsFilter` strings are bound parameters.
- DuckDB is hardened on every connection: extension autoinstall/autoload off, community extensions off, `allowed_directories` = the index dir, `enable_external_access = false`, then `lock_configuration = true`.

Example: `host 10.0.0.5 and dns.query ~ "*.top" and bytes_up > 1MB and not app_proto == tls`.

## 6. Detection rules and allowlist

**Rules** live in `rules/*.yaml` (one rule per file; `allowlist.yaml` is not a rule) and load at runtime. Schema (`RuleDef`, unknown keys rejected):

```yaml
id: beacon.periodic            # unique, stable; appears in Reason.rule_id
title: Periodic outbound connections
detector: beaconing            # beaconing | dns_entropy | dns_length | dns_subdomain_rate | dns_nxdomain_burst | dns_tunnel
enabled: true                  # default true
attack_technique: T1071        # T1071, T1071.004, T1568.002, T1048
params:                        # detector-specific; numbers, strings or lists
  min_count: 8
  max_jitter: 0.2
  min_duration_s: 600
weights:                       # signal -> max points; points = weight × strength(0..1)
  regularity: 50
  count: 20
  duration: 20
  small_payload: 10
min_score: 30                  # drop reasons below this many points
explanation: "{src} contacted {dst} {count} times, every {interval_s}s ±{jitter_pct}%"
```

`title` and `explanation` are both templates: `{name}` placeholders are filled by the detector with `render_template`; no logic, no markup. Captured strings are sanitized to printable text and clipped before substitution.

**Allowlist** (`rules/allowlist.yaml`, `Allowlist`):

```yaml
version: 1
domains: [ { suffix: windowsupdate.com, reason: "Microsoft Update" } ]   # label-boundary suffix match
cidrs:   [ { cidr: 13.107.4.50/32, reason: "Microsoft" } ]
ja4:     [ { value: t13d1516h2_8daaf6152771_02713d6af862, reason: "Chrome" } ]
```

Detectors use it to suppress or down-weight reasons (and must say so in the explanation). IOC extraction keeps allowlisted IOCs but sets `allowlisted` and `allowlist_reason`. Matching lives in `walleye_core::allowlist` so both crates agree.

## 7. Crate APIs

The lead wires these in `app/src-tauri` during integration. Agents may add more public items but must provide these signatures (or propose a change).

```rust
// walleye-ingest (Agent A)
pub struct IngestOptions { pub tcp_idle_timeout_s: u32 /*300*/, pub udp_idle_timeout_s: u32 /*60*/,
                           pub checkpoint_bytes: u64 /*CHECKPOINT_BYTES*/, pub batch_rows: usize /*65_536*/ }
impl Default for IngestOptions;
pub struct Progress { pub bytes_done: u64, pub bytes_total: u64, pub frames: u64 }
pub fn hash_file(path: &Path, progress: &mut dyn FnMut(u64)) -> std::io::Result<String>; // lowercase hex sha256
pub fn ingest(path: &Path, sha256: &str, sink: &mut dyn IndexSink, opts: &IngestOptions,
              progress: &mut dyn FnMut(Progress), cancel: &AtomicBool) -> ApiResult<CaptureRow>;
pub fn read_frame(path: &Path, file_offset: u64, caplen: u32) -> std::io::Result<Vec<u8>>;
pub fn decode_frame(link_type: u32, bytes: &[u8]) -> Vec<DecodeNode>; // never panics

// walleye-index (Agent B)
pub struct IndexWriter;  impl IndexSink for IndexWriter;
impl IndexWriter { pub fn create(index_dir: &Path) -> ApiResult<Self>; }
pub struct Index;        // Send + Sync; cheap concurrent reads
impl Index {
    pub fn open(index_dir: &Path) -> ApiResult<Self>;
    pub fn capture(&self) -> ApiResult<CaptureRow>;
    pub fn query(&self, req: &QueryRequest) -> ApiResult<Page>;
    pub fn timeline(&self, req: &TimelineRequest, findings: &[Finding]) -> ApiResult<Lanes>;
    pub fn flow(&self, flow_id: u64) -> ApiResult<FlowRow>;
    pub fn frame(&self, frame_no: u64) -> ApiResult<FrameRow>;
    pub fn flow_frames(&self, flow_id: u64) -> ApiResult<Vec<FrameRef>>;
    pub fn autocomplete(&self, partial: &str, cursor_pos: u32) -> ApiResult<Vec<Suggestion>>;
    pub fn findings(&self, filter: Option<&FindingsFilter>) -> ApiResult<Vec<Finding>>; // verdict = None
    pub fn iocs(&self) -> ApiResult<Vec<Ioc>>;
}
impl DetectSource for Index;  impl ResultSink for Index;
pub mod filter {
    pub fn parse(text: &str) -> ApiResult<Expr>;
    pub fn compile(expr: &Expr, view: View) -> ApiResult<Compiled>; // Compiled { sql: String, params: Vec<Param> }
}

// walleye-detect (Agent C)
pub struct RuleSet;
pub fn load_rules(dir: &Path) -> ApiResult<RuleSet>;   // all *.yaml except allowlist.yaml
pub fn run(src: &dyn DetectSource, rules: &RuleSet, allow: &Allowlist) -> ApiResult<Vec<Finding>>;

// walleye-case (Agent F)
pub fn load_allowlist(path: &Path) -> ApiResult<Allowlist>;
pub fn extract_iocs(findings: &[Finding], src: &dyn DetectSource, allow: &Allowlist) -> ApiResult<Vec<Ioc>>;
pub fn defang(ioc_type: IocType, value: &str) -> String;
pub fn refang(ioc_type: IocType, defanged: &str) -> String;     // refang(defang(x)) == x
pub struct CaseStore;   // SQLite at <case_dir>/case.sqlite; Send
impl CaseStore {
    pub fn open(case_dir: &Path, capture: &CaptureRow) -> ApiResult<Self>;
    pub fn get_case(&self) -> ApiResult<Case>;
    pub fn pin(&self, evidence: &EvidenceRef, note: &str, resolved: &Evidence) -> ApiResult<Pin>;
    pub fn unpin(&self, pin_id: &str) -> ApiResult<()>;
    pub fn set_verdict(&self, finding_id: &str, verdict: Verdict, note: &str) -> ApiResult<()>;
    pub fn verdicts(&self) -> ApiResult<Vec<VerdictEntry>>;
    pub fn log_query(&self, entry: &QueryLogEntry) -> ApiResult<()>;
}
pub fn export_iocs(iocs: &[Ioc], capture: &CaptureRow, format: IocFormat, out_dir: &Path) -> ApiResult<PathBuf>;
pub struct ReportInput<'a> { pub capture: &'a CaptureRow, pub case: &'a Case, pub findings: &'a [Finding],
                             pub iocs: &'a [Ioc], pub timeline_png: Option<&'a [u8]> }
pub fn export_report(input: &ReportInput, format: ReportFormat, out_dir: &Path) -> ApiResult<PathBuf>;
```

Saved queries are app-level (not per case) and stored by `app/src-tauri` in `<data_dir>/saved_queries.json`.

## 8. On-disk layout

`<data_dir>` = Tauri app data dir (`~/Library/Application Support/design.0xfff.walleye` on macOS, `~/.local/share/design.0xfff.walleye` on Linux), overridable with `WALLEYE_DATA`.

```
<data_dir>/
  saved_queries.json
  captures/<capture_id>/
    capture.json                 # CaptureRow
    index/                       # owned by walleye-index
      checkpoint.json            # last accepted Checkpoint (state base64); removed when complete
      manifest.json              # written last: capture row + file list; its presence = index complete
      frames/ flows/ dns/ http/ tls/ files/ findings/ iocs/   # *.parquet
    case/                        # owned by walleye-case
      case.sqlite
      exports/                   # iocs.csv, iocs.json, report.md, report.pdf
```

Captures are never copied, modified or written next to. Open them read-only.

`FORMAT_VERSION` (walleye-index) is 2 (frames gained `link_type`). `Index::open` returns `not_found` for an index with another version or without `manifest.json`, and the engine rebuilds it from the capture.

**Report links.** Markdown reports cite evidence as `[frames 41, 57, 63](walleye://sha256/<capture sha256>/frames/41,57,63)` (and `…/flows/3,4`). The app does not register the `walleye://` scheme in the MVP, so a link is a stable identifier that carries the capture hash, not a live URL. `report-timeline.png` is written next to the report when the UI supplies a snapshot.

## 9. Fixtures, labels, bench, eval (Agent G)

`$WALLEYE_FIXTURES` defaults to `~/.walleye-fixtures`; never inside the repo.

```
$WALLEYE_FIXTURES/
  generated/<scenario>.pcap            # from walleye-gen
  generated/<scenario>.labels.json
  external/<sample-name>/<file>.pcap   # each in its own directory; pcap only
```

Generator: `cargo run -p walleye-gen --release -- --scenario <office|beacon|dns_tunnel|dga|scale> --seed <u64> --out <path.pcap> [--size-gb 10]`. Same seed → byte-identical output. Writes `<path>.labels.json` beside it (same stem, `.labels.json`).

Labels JSON (also the format for external samples, stored in `fixtures/labels/<name>.labels.json`):

```json
{
  "scenario": "beacon",
  "source": "walleye-gen seed=1" ,
  "sha256": "<hex>",
  "c2_hosts": ["10.0.0.23"],
  "bad_destinations": ["185.199.110.77", "cdn-update.top"],
  "benign": false,
  "notes": "60 s ±3% TLS beacon"
}
```

`fixtures/LABELS.md` (committed) lists each external sample: name, source URL, SHA-256, known-bad hosts.

Bench: `tools/bench/queries.txt` has one benchmark per line, `view<TAB>filter` (`#` comments). `cargo run -p walleye-bench --release -- --index <dir> --queries tools/bench/queries.txt` prints p50/p95/max per query and overall.

Eval: `cargo run -p walleye-eval --release -- --findings <findings.json> --labels <labels.json> [--k 5]` prints a Markdown table: sample, C2 rank, hit@k, top-10 false-positive rate. **Top-10 FP rate** = (findings ranked 1–10 whose `entity` is not in `c2_hosts`) / 10, with a fixed denominator and no score floor; on a `benign` sample every finding in the top 10 is a false positive. Gate: ≤ 30 % on the benign sample. **C2 rank** = best rank among findings whose entity is in `c2_hosts`; hit@k when it is ≤ k. Before integration it reads a findings JSON (`Vec<Finding>`); the lead adds an end-to-end mode in Phase 2.

## 10. Mock backend

`crates/walleye-core/mock/generate.mjs` (deterministic) writes `dataset.json` and `packets.json`. `MockBackend` (Rust) and `app/src/shared/mock.ts` (browser) both serve them.

- Starts with no capture open; `open_capture(any path)` finishes in ~1.5 s. `WALLEYE_BACKEND=mock-open` (Tauri) or `?mock=open` (browser) starts open.
- Filter text: only `host <ip>` terms are applied (AND-ed). Unbalanced quotes/parens → `invalid_filter` with span. Everything else is accepted and ignored.
- Packet bytes exist for the first 120 flows and every evidence flow; other frames return `not_found` (useful for error states).
- Scenario: `10.0.0.23` beacons to `185.199.110.77`/`cdn-update.top` every 60 s ±3 %; `10.0.0.17` DNS tunnel via `t.exfil-dns.xyz`; `10.0.0.12` DGA NXDOMAIN bursts; `10.0.0.15` periodic Windows Update (allowlisted false positive).
- Mock export commands write to the system temp dir (Rust) or return a fake path (browser).

## 11. 802.11 (Wi-Fi) captures (contract v2)

Monitor-mode captures (WiFi Coconut, airodump-ng, Kismet) use link type **127** (802.11 + radiotap) or **105** (802.11 without a radio header). Most data frames are encrypted, so the useful evidence is in management frames: who advertises which network, who probes for what, who deauthenticates whom, and who completes a handshake. Walleye indexes those frames in their own table and shows them in three views, a device timeline and three detectors. `walleye_core::is_wifi_link_type(lt)` decides; a pcapng can mix 802.11 and Ethernet interfaces, and each frame follows its own link type.

**MAC addresses** are lowercase `aa:bb:cc:dd:ee:ff` everywhere (`walleye_core::mac`). "Randomized" means the locally administered bit (`0x02` of the first octet) is set: privacy-randomized clients, virtual APs, or spoofed addresses.

### 11.1 Ingest (Agent W-A)

- **Radiotap:** `it_len` at bytes 2–3 (LE) gives the header length; walk the `it_present` bitmap chain (bit 31 = another word follows) with each field's natural alignment from the start of the header, reading at least Flags (1), Channel (3: freq u16 + flags u16) and Antenna Signal (5: i8 dBm). Unknown present bits after the last field we need stop the walk (we never need fields past one we can't size). Flags bit `0x10` = FCS at the end of the 802.11 frame: drop those 4 bytes; flag `0x40` = bad FCS: keep the row and add a `warning` in the decode tree.
- **802.11 header:** frame control (type, subtype, ToDS, FromDS, retry, protected), duration, addr1–addr3, sequence control, addr4 when ToDS && FromDS, QoS control for QoS subtypes (+ HT control when the order bit is set on QoS data). Addresses map to `src/dst/tx/bssid` per 802.11-2020 Table 9-30 (ToDS/FromDS).
- **Rows:** one `WifiRow` per management or data frame, in frame order, via `RecordBatch::Wifi`. Control frames (type 1) produce no row. A frame that is too short for its header still gets a `FrameRow` and no `WifiRow`.
- **Management bodies:** beacon/probe response: fixed fields (timestamp, interval, capabilities), then tagged elements. Read SSID (0), DS Parameter Set (3, channel), RSN (48), vendor WPA (221, OUI 00:50:f2 type 1). `security`: RSN with AKM SAE (8) only → `wpa3`; SAE + PSK → `wpa2/wpa3`; OWE (18) → `owe`; other RSN → `wpa2`; WPA vendor element without RSN → `wpa`; Privacy capability bit without either → `wep`; else `open`. Probe request and (re)assoc request: SSID. Deauth/disassoc: reason code; auth and (re)assoc response: status code → `reason`. SSIDs pass through the same printable-text sanitizer as other capture strings and are clipped to 32 bytes.
- **Data frames:** unprotected data with an LLC/SNAP header (`aa aa 03 00 00 00` + ethertype) is handed to the existing IP/flow pipeline exactly like an Ethernet frame with that ethertype, so flows, DNS, HTTP and TLS work on open networks. Ethertype `0x888e` → kind `eapol` (no flow). Protected data → kind `data`, payload not parsed.
- **Decode tree** (`decode_frame(105|127, bytes)`): "Radiotap header" (length, present flags, channel/frequency, signal), "IEEE 802.11 <kind>" (frame control flags, duration, each address with `field` set to `wifi.src`/`wifi.dst`/`wifi.tx`/`wifi.bssid`, sequence), "Management body" (fixed fields, each tagged element with `range`), or LLC/SNAP followed by the existing IP decode, or "Encrypted data (N bytes)". Every node's `range` stays inside the frame (fuzzed).
- **Generator** (`walleye-gen`): scenarios `wifi` and `wifi_benign` write radiotap pcap (link type 127). `wifi_benign`: 6 APs on channels 1/6/11 including a 3-AP mesh sharing one SSID and security, 25 clients (half randomized) probing, associating, EAPOL 4-way handshakes, protected data, occasional normal deauths (reason 3/8, a few per client). `wifi` adds three labelled attacks: a deauth flood (a spoofed BSSID sends ≥ 300 broadcast and unicast deauths in 2 minutes), an evil twin (an open AP advertising the SSID of a WPA2 AP, from a locally administered BSSID, on another channel) and a karma AP (one BSSID answering probe requests for ≥ 10 different SSIDs). Labels: `c2_hosts` holds the attacker MACs (the entities detectors should rank first); `bad_destinations` holds the targeted SSIDs.

### 11.2 Index (Agent W-B)

- `wifi` Parquet table from `WifiRow` (column order = struct order; `kind` as its snake_case string), sorted by `(ts, frame_no)`.
- `wifi_aps` and `wifi_clients` are DuckDB views over `wifi`, created at `Index::open` with the struct column order:
  - **wifi_aps:** group rows with kind `beacon` or `probe_resp` by `bssid`. `ssid` = most frequent non-empty SSID, `channel`/`security` = most frequent; `beacons` = beacon rows; `frames` = all `wifi` rows with that `bssid`; `clients` = distinct unicast `src`/`dst` ≠ bssid in `data`/`null`/`eapol` rows of that bssid; `signal_max` over that AP's own transmissions (`tx = bssid`); `randomized` from the bssid; `first_frame` = min frame_no.
  - **wifi_clients:** unicast addresses that transmitted a `probe_req`, or that appear as `src` (or `dst`) ≠ `bssid` in `data`/`null`/`eapol`/`auth`/`assoc_req`/`reassoc_req` rows, excluding every BSSID in `wifi_aps`. `frames` = rows with `tx = mac`; `probed_ssids` = sorted distinct non-empty SSIDs of its probe requests; `bssids` = sorted distinct bssids of its data/auth/assoc rows.
- Keys and default sort: `wifi` → key `frame_no`, sort `ts`; `wifi_aps` → key `bssid`, sort `beacons` desc; `wifi_clients` → key `mac`, sort `frames` desc. Paging, sort allowlist and cursors work as on other views.
- **Filter:** `wifi.*`, `ap.*` and `client.*` fields apply only on their own view; flow-family fields and `hosts`/`flow_ids` do not apply on 802.11 views (`invalid_filter` / `invalid_argument`). `time_range` applies to `ts` (wifi) or overlap of `[first_ts, last_ts]` (aps, clients). `Mac` fields accept a quoted or bare MAC (the lexer reads `xx:xx:xx:xx:xx:xx` as one value token), compared lowercase; `~` globs. Shorthand `mac X` ≡ any address column equals X (§5 grammar: `shorthand += "mac", mac_value`). Autocomplete suggests `wifi.kind` values and top SSIDs/MACs.
- **Timeline:** when `capture.link_type` is 105/127 (or the index has `wifi` rows and no flows), `Lanes.lane_kind = device`: lanes keyed by `tx` (top `max_lanes` by frame count, then `other`), buckets count **frames** in `wifi_mgmt` (management except probes and deauth/disassoc), `wifi_probe`, `wifi_data` (data/null/eapol) and `wifi_deauth` (deauth + disassoc); the IP kinds stay 0. The filter applies with `wifi.*` fields. `max_score` comes from `device` findings whose entity is the lane MAC.
- `Index::device_frames(mac, time_range)` → `FrameRef`s of `wifi` rows where `mac` is src, dst, tx or bssid; `summary` like `"Deauth 42:00:5e:00:53:9c → ff:ff:ff:ff:ff:ff reason 7"`, `"Beacon \"HomeNet\" ch 6 wpa2"`.
- `DetectSource::for_each_wifi` streams `wifi` in `(ts, frame_no)` order. `FORMAT_VERSION` becomes 3.

### 11.3 Detection (Agent W-C)

New detectors (`RuleDef.detector`): `wifi_deauth`, `wifi_evil_twin`, `wifi_karma`. Findings use `entity_type = "device"`, `entity` = the attacker MAC; evidence lists `frame_nos` (`flow_ids` empty). ATT&CK: deauth flood **T1498** (Network Denial of Service), evil twin and karma **T1557** (Adversary-in-the-Middle).

| Rule file | Fires on | Down-weights / suppressions |
|---|---|---|
| `wifi.deauth_flood.yaml` | A transmitter sending ≥ `min_count` deauth/disassoc frames inside a `window_s` sliding window; signals: rate, broadcast destination share, number of distinct targets, the transmitter claiming a BSSID it doesn't beacon from (or a randomized BSSID), EAPOL handshakes following within `handshake_window_s` (capture-the-handshake pattern). | Low volume spread over the capture (normal roaming/idle kicks); reason codes 3 (leaving) / 8 (left BSS) sent by a station about itself. |
| `wifi.evil_twin.yaml` | An SSID advertised by BSSIDs with **different security** (open/owe vs wpa2/wpa3), especially when the weaker one is randomized, on another channel, or appears after the original. | Same security on every BSSID (mesh, multi-band); hidden SSIDs. |
| `wifi.karma.yaml` | One BSSID sending probe responses (or beacons) for ≥ `min_ssids` distinct SSIDs, especially SSIDs that clients probed for just before. | Multi-SSID enterprise APs that **beacon** all their SSIDs steadily from sequential BSSIDs; the detector uses probe-response-only SSIDs. |

### 11.4 IPC and UI (Agent W-D)

- New command `device_frames(mac, time_range?)` → `FrameRef[]` (≤ `DEVICE_FRAMES_CAP` = 10 000), §3.
- `QueryRequest.view` accepts `wifi`, `wifi_aps`, `wifi_clients` (`RowSet` variants of the same names).
- Selection gains `device: string | null` and `selectDevice(mac)`; `applyEvidence(e, device?)` focuses the device when the evidence has no flows. The packet list shows `flowFrames(flow_ids[0])` when a flow is selected, else `deviceFrames(device, time_range)`.
- The session table shows **Access points**, **Clients** and **Wi-Fi frames** tabs (and hides Flows/DNS/HTTP/TLS/Files when the capture has no flows) for 802.11 captures. Rows render MACs, SSIDs and security as text via `visible()`; an AP or client row click calls `selectDevice` and selects its `first_frame`.
- Timeline: `lane_kind = "device"` lanes show MACs (with a randomized marker), and the four `wifi_*` kinds get their own legend entries, shapes and colour tokens in `encoding.ts` (colour is never the only signal). A device-lane click calls `selectDevice`, not `toggleHost`.
- Queue: `device` findings show the MAC and their SSID context from the explanation; "Show evidence" calls `applyEvidence(e, finding.entity)`.
