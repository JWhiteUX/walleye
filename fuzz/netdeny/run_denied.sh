#!/usr/bin/env bash
# Run a command with network access denied and fail if it tries to use it.
#
#   fuzz/netdeny/run_denied.sh --selftest        # prove the detector works here
#   fuzz/netdeny/run_denied.sh -- <cmd> [args]   # run <cmd>; exit 0 only if it
#                                                # succeeded and made no attempt
#
# macOS: sandbox-exec with netdeny.sb. Any IP socket use or DNS lookup kills
#        the process (SIGKILL, exit 137). Covers the Rust backend and anything
#        it spawns. It does not cover WKWebView networking, which runs in a
#        launchd XPC service; use no-network.spec.ts for the webview.
# Linux: `unshare -rn` (new user + network namespace: loopback only, no
#        route) under `strace -f`. Every socket()/connect()/sendto() is logged.
#        The run fails on any AF_INET/AF_INET6 socket, or on any unix-socket
#        connect to a resolver (systemd-resolved, nscd). strace -f follows
#        children, which includes WebKitGTK's network process, so on Linux
#        this also covers the full Tauri app (run it under xvfb-run).
#
# Exit codes: 0 clean; 1 command failed; 2 network attempt; 3 setup problem.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

run_macos() {
  local rc=0
  sandbox-exec -f "$here/netdeny.sb" "$@" || rc=$?
  if [ "$rc" -eq 137 ]; then
    echo "netdeny: NETWORK ATTEMPT (process killed by sandbox): $*" >&2
    return 2
  fi
  [ "$rc" -eq 0 ] || { echo "netdeny: command failed (exit $rc): $*" >&2; return 1; }
  echo "netdeny: clean (no network attempt): $*"
}

run_linux() {
  command -v unshare >/dev/null || { echo "netdeny: unshare not found" >&2; return 3; }
  command -v strace >/dev/null || { echo "netdeny: strace not found (apt install strace)" >&2; return 3; }
  local log
  log="$(mktemp -t walleye-netdeny.XXXXXX)"
  local rc=0
  unshare -rn strace -f -qq -e trace=socket,connect,sendto,sendmsg,bind -o "$log" "$@" || rc=$?
  local hits
  hits="$(grep -E 'socket\(AF_INET6?,|sa_family=AF_INET6?|/run/systemd/resolve|/var/run/nscd|/run/nscd' "$log" || true)"
  if [ -n "$hits" ]; then
    echo "netdeny: NETWORK ATTEMPT(S):" >&2
    echo "$hits" | head -20 >&2
    echo "(full trace: $log)" >&2
    return 2
  fi
  rm -f "$log"
  [ "$rc" -eq 0 ] || { echo "netdeny: command failed (exit $rc): $*" >&2; return 1; }
  echo "netdeny: clean (no network attempt): $*"
}

run() {
  case "$(uname -s)" in
    Darwin) run_macos "$@" ;;
    Linux) run_linux "$@" ;;
    *) echo "netdeny: unsupported OS $(uname -s)" >&2; return 3 ;;
  esac
}

selftest() {
  local py
  py="$(command -v python3)" || { echo "netdeny: python3 needed for --selftest" >&2; return 3; }
  local fail=0
  # Positive controls must be caught. They only touch loopback or resolve
  # "localhost", so nothing leaves the machine even if the detector fails.
  for probe in \
    'import socket; socket.socket().connect(("127.0.0.1", 9))' \
    'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))' \
    'import socket; socket.getaddrinfo("localhost", 80)' \
    'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()'; do
    local rc=0
    run "$py" -I -c "$probe" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then echo "selftest: caught    | $probe"; else echo "selftest: MISSED    | $probe (rc=$rc)"; fail=1; fi
  done
  # Negative controls must pass: file I/O and a unix socketpair are not network.
  for probe in \
    'import os, tempfile; open(os.path.join(tempfile.mkdtemp(), "f"), "w").write("x")' \
    'import socket; a, b = socket.socketpair(); a.send(b"x"); assert b.recv(1) == b"x"'; do
    local rc=0
    run "$py" -I -c "$probe" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then echo "selftest: allowed   | $probe"; else echo "selftest: FALSE HIT | $probe (rc=$rc)"; fail=1; fi
  done
  [ "$fail" -eq 0 ] && echo "selftest: OK" || { echo "selftest: FAILED" >&2; return 3; }
}

case "${1:-}" in
  --selftest) selftest ;;
  --) shift; [ $# -gt 0 ] || { echo "usage: $0 -- <cmd> [args]" >&2; exit 3; }; run "$@" ;;
  *) echo "usage: $0 --selftest | -- <cmd> [args]" >&2; exit 3 ;;
esac
