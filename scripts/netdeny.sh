#!/usr/bin/env bash
# Network-deny gate (DoD: "zero network calls").
#
#   scripts/netdeny.sh [capture...]
#
# 1. Self-test: proves the sandbox catches loopback connect, UDP send, bind
#    and DNS lookups on this host (fuzz/netdeny/run_denied.sh --selftest).
# 2. Backend: runs the headless smoke binary (every Backend command: open,
#    ingest, index, detect, query on every view, timeline, packet decode,
#    verdicts, pins, IOCs, CSV/JSON/Markdown/PDF exports) under the sandbox
#    for each capture. Any socket or DNS attempt kills the process.
# 3. Webview: the Playwright request audit (app/e2e/real/no-network.spec.ts)
#    is part of `pnpm e2e:real`, because WKWebView networking runs outside
#    sandbox-exec on macOS.
#
# Default captures: the generated beacon fixture plus every external sample
# in $WALLEYE_FIXTURES (default ~/.walleye-fixtures).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
[ -x "$HOME/.cargo/bin/cargo" ] && export PATH="$HOME/.cargo/bin:$PATH"
fixtures="${WALLEYE_FIXTURES:-$HOME/.walleye-fixtures}"

captures=("$@")
if [ ${#captures[@]} -eq 0 ]; then
  captures=("$fixtures/generated/beacon.pcap")
  while IFS= read -r f; do captures+=("$f"); done < <(find "$fixtures/external" -type f \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null | sort)
fi

echo "==> selftest"
"$root/fuzz/netdeny/run_denied.sh" --selftest

echo "==> build smoke binary (outside the sandbox)"
cargo build -q --release --locked -p walleye-engine --example smoke
smoke="$root/target/release/examples/smoke"

data="$(mktemp -d "${TMPDIR:-/tmp}/walleye-netdeny.XXXXXX")"
trap 'rm -rf "$data"' EXIT
fail=0
for c in "${captures[@]}"; do
  echo "==> $c"
  rc=0
  "$root/fuzz/netdeny/run_denied.sh" -- "$smoke" "$c" "$data" || rc=$?
  [ "$rc" -eq 0 ] || fail=1
done
[ "$fail" -eq 0 ] && echo "netdeny: PASS (${#captures[@]} captures, no network attempts)" || { echo "netdeny: FAIL" >&2; exit 1; }
