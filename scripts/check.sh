#!/usr/bin/env bash
# The gate every commit must pass: fmt, clippy -D warnings, cargo test,
# TS bindings drift, UI lint (eslint + tsc) and Vitest. Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# rustup's default install puts cargo in ~/.cargo/bin, which non-login shells
# may not have on PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

step "cargo fmt --check"
cargo fmt --all -- --check

step "cargo clippy (-D warnings)"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "cargo test"
cargo test --workspace --locked

step "TS bindings up to date"
# cargo test (ts-rs) regenerates app/src/shared/bindings; fail if that changed
# committed files, so Rust and TypeScript types cannot drift.
if git rev-parse --git-dir >/dev/null 2>&1 && [ -n "$(git ls-files app/src/shared/bindings)" ]; then
  if ! git diff --quiet -- app/src/shared/bindings; then
    git --no-pager diff --stat -- app/src/shared/bindings
    echo "bindings changed: commit the regenerated files" >&2
    exit 1
  fi
fi

step "pnpm install (frozen lockfile)"
pnpm install --frozen-lockfile --silent

step "pnpm lint (eslint + tsc)"
pnpm lint

step "pnpm test (vitest)"
pnpm test

printf '\n\033[1;32mcheck.sh: all gates passed\033[0m\n'
