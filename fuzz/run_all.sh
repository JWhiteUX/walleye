#!/usr/bin/env bash
# Run every fuzz target for N seconds each and print a summary table.
#
#   fuzz/run_all.sh 60                              # smoke: buildable targets
#   fuzz/run_all.sh 600                             # the DoD gate: 10 min each
#   FEATURES="ingest index" fuzz/run_all.sh 600     # after Agents A/B land
#   fuzz/run_all.sh 60 core_mock_backend index_filter   # selected targets
#
# Needs nightly + cargo-fuzz (rustup toolchain install nightly; cargo install
# cargo-fuzz). Working corpora grow in fuzz/corpus/<target> (git-ignored),
# seeded from the hand-written fuzz/seeds/<target>. Crashes land in
# fuzz/artifacts/<target>/ and logs in fuzz/logs/<target>.log.
# Exit status: 0 if every target ran its full time without a crash.
#
# cargo runs from the caller's directory (with --fuzz-dir), so a local
# .cargo/config.toml there (a registry mirror, an offline patch) is honoured
# without touching the repo.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

secs="${1:?usage: run_all.sh <seconds-per-target> [target...]}"
shift
[[ "$secs" =~ ^[0-9]+$ ]] || { echo "seconds must be an integer" >&2; exit 2; }

if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
FEATURES="${FEATURES:-}"
RSS_MB="${RSS_MB:-2048}"
TIMEOUT_S="${TIMEOUT_S:-10}"

core=(core_allowlist_yaml core_allowlist_match core_rule_yaml core_render_template
      core_ipc_json core_mock_filter core_mock_backend)
ingest=(ingest_read_capture ingest_decode_frame ingest_dns ingest_http
        ingest_tls_client_hello ingest_tls_server_hello ingest_certificate)
index=(index_filter)

if [ $# -gt 0 ]; then
  targets=("$@")
else
  targets=("${core[@]}")
  [[ " $FEATURES " == *" ingest "* ]] && targets+=("${ingest[@]}")
  [[ " $FEATURES " == *" index "* ]] && targets+=("${index[@]}")
fi

# bash 3.2 (macOS) treats an empty "${a[@]}" as unbound under set -u, hence
# the ${a[@]+"${a[@]}"} form below.
feat_args=()
[ -n "$FEATURES" ] && feat_args=(--features "${FEATURES// /,}")

dict_for() {
  case "$1" in
    core_ipc_json | core_mock_backend) echo "$here/dict/json.dict" ;;
    core_mock_filter | index_filter) echo "$here/dict/filter.dict" ;;
    core_allowlist_yaml | core_rule_yaml) echo "$here/dict/yaml.dict" ;;
    *) echo "" ;;
  esac
}

echo "==> building (${FEATURES:-default features})"
rustup run nightly cargo fuzz build --fuzz-dir "$here" ${feat_args[@]+"${feat_args[@]}"} >/dev/null
# Run the built binaries directly: `cargo fuzz run` would re-enter cargo
# (and its shared package-cache lock) once per target.
triple="$(rustup run nightly rustc -vV | awk '/^host:/ {print $2}')"
bindir="$here/target/$triple/release"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_odr_violation=0}" # as cargo fuzz run sets it

mkdir -p "$here/logs" "$here/corpus"
results=()
failed=0
for t in "${targets[@]}"; do
  log="$here/logs/$t.log"
  mkdir -p "$here/corpus/$t"
  dirs=("$here/corpus/$t")
  [ -d "$here/seeds/$t" ] && dirs+=("$here/seeds/$t")
  extra=()
  d="$(dict_for "$t")"
  [ -n "$d" ] && extra+=("-dict=$d")
  echo "==> $t (${secs}s)"
  rc=0
  [ -x "$bindir/$t" ] || { echo "missing $bindir/$t (feature not enabled?)" >&2; exit 2; }
  mkdir -p "$here/artifacts/$t"
  "$bindir/$t" -artifact_prefix="$here/artifacts/$t/" \
    -max_total_time="$secs" -timeout="$TIMEOUT_S" -rss_limit_mb="$RSS_MB" \
    -print_final_stats=1 ${extra[@]+"${extra[@]}"} "${dirs[@]}" >"$log" 2>&1 || rc=$?
  runs="$(grep -E '^stat::number_of_executed_units' "$log" | awk '{print $2}' | tail -1)"
  cov="$(grep -oE 'cov: [0-9]+' "$log" | tail -1 | awk '{print $2}')"
  corp="$(find "$here/corpus/$t" -type f | wc -l | tr -d ' ')"
  if [ "$rc" -eq 0 ]; then
    status="ok"
  else
    status="CRASH(rc=$rc)"
    failed=1
    art="$(grep -oE 'Test unit written to [^ ]+' "$log" | tail -1 | sed 's/Test unit written to //')"
    [ -n "$art" ] && status="$status $art"
  fi
  results+=("$(printf '%-26s %-6s %12s %8s %8s  %s' "$t" "${secs}s" "${runs:-?}" "${cov:-?}" "$corp" "$status")")
done

echo
printf '%-26s %-6s %12s %8s %8s  %s\n' target time execs cov corpus status
printf '%s\n' "${results[@]}"
exit "$failed"
