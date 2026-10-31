#!/usr/bin/env bash
# Validate generated captures with an independent parser (tshark), offline
# and read-only: checksum validation on, then count expert-info warnings and
# errors, malformed packets and protocol mix. Usage:
#   tools/walleye-gen/validate.sh <capture.pcap>...
# Only for walleye-gen output; never point it at downloaded captures.
set -euo pipefail
command -v tshark >/dev/null || { echo "tshark not installed" >&2; exit 2; }
CK=(-o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE)
status=0
for f in "$@"; do
  echo "== $f"
  total=$(tshark -n -r "$f" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
  bad_ck=$(tshark -n -r "$f" "${CK[@]}" -Y 'ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0' -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
  malformed=$(tshark -n -r "$f" -Y '_ws.malformed || _ws.expert.severity >= "error"' -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
  warn=$(tshark -n -r "$f" -Y '_ws.expert.severity == "warning"' -T fields -e _ws.expert.message 2>/dev/null | sort | uniq -c | sort -rn | head -5)
  echo "frames=$total bad_checksums=$bad_ck malformed_or_error=$malformed"
  echo "protocols (frames):"
  tshark -n -r "$f" -q -z io,stat,0,"dns","tls.handshake.type == 1","tls.handshake.type == 11","http.request","tcp.flags.syn == 1 && tcp.flags.ack == 0","ntp","ipv6" 2>/dev/null | grep -E '^\|' | tail -2
  tls_ver=$(tshark -n -r "$f" -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -5)
  echo "top SNI:"; echo "$tls_ver"
  echo "top expert warnings:"; echo "${warn:-  (none)}"
  if [ "$bad_ck" != "0" ] || [ "$malformed" != "0" ]; then status=1; fi
done
exit $status
