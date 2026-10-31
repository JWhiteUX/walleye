#!/usr/bin/env bash
# Ingest throughput / peak-RAM harness. Runs a command under /usr/bin/time
# (-l on macOS, -v on Linux) and prints one Markdown row:
#   | label | input | size MiB | wall s | MiB/s | peak RSS MiB | exit |
# Usage:
#   tools/bench/ingest.sh --input <capture> [--label <name>] [--header] -- <command> [args...]
# Example (after integration):
#   tools/bench/ingest.sh --header --input ~/.walleye-fixtures/generated/scale.pcap \
#     -- target/release/walleye-ingest-bench ~/.walleye-fixtures/generated/scale.pcap
# Throughput uses MiB (2^20 bytes), which is stricter than the 150 MB/s gate.
set -euo pipefail

input="" label="" header=0
while [ $# -gt 0 ]; do
  case "$1" in
    --input) input="$2"; shift 2 ;;
    --label) label="$2"; shift 2 ;;
    --header) header=1; shift ;;
    --) shift; break ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ $# -gt 0 ] || { echo "missing command after --" >&2; exit 2; }
[ -n "$input" ] && [ -f "$input" ] || { echo "--input must name an existing file" >&2; exit 2; }
[ -n "$label" ] || label="$(basename "$1")"

size=$(wc -c < "$input" | tr -d ' ')
log=$(mktemp "${TMPDIR:-/tmp}/walleye-ingest-time.XXXXXX")
trap 'rm -f "$log"' EXIT

set +e
case "$(uname -s)" in
  Darwin) /usr/bin/time -l -o "$log" "$@" >/dev/null ;;
  *)      /usr/bin/time -v -o "$log" "$@" >/dev/null ;;
esac
rc=$?
set -e

case "$(uname -s)" in
  Darwin)
    wall=$(awk '/ real /{print $1; exit}' "$log")
    rss_bytes=$(awk '/maximum resident set size/{print $1; exit}' "$log")
    ;;
  *)
    wall=$(awk -F': ' '/Elapsed \(wall clock\)/{print $2; exit}' "$log" \
      | awk -F: '{ if (NF==3) print $1*3600+$2*60+$3; else print $1*60+$2 }')
    rss_kb=$(awk -F': ' '/Maximum resident set size/{print $2; exit}' "$log")
    rss_bytes=$(( ${rss_kb:-0} * 1024 ))
    ;;
esac

awk -v label="$label" -v input="$(basename "$input")" -v size="$size" \
    -v wall="${wall:-0}" -v rss="${rss_bytes:-0}" -v rc="$rc" -v header="$header" 'BEGIN {
  if (header) {
    print "| Label | Input | Size MiB | Wall s | MiB/s | Peak RSS MiB | Exit |"
    print "|---|---|---:|---:|---:|---:|---:|"
  }
  mib = size / 1048576
  rate = (wall > 0) ? mib / wall : 0
  printf "| %s | %s | %.1f | %.2f | %.1f | %.1f | %d |\n", label, input, mib, wall, rate, rss / 1048576, rc
}'
exit "$rc"
