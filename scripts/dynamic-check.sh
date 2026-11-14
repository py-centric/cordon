#!/usr/bin/env bash
set -euo pipefail

# Dynamic code analysis: execute all unit + integration tests with strict
# debug assertions and integer overflow checks enabled, plus live CLI smoke checks.
RUSTFLAGS="-C debug-assertions=on -C overflow-checks=on" \
    cargo test --offline --all-targets

cargo run --offline --quiet -- --json doctor >/dev/null
cargo run --offline --quiet -- --json profiles >/dev/null

echo "dynamic-check: OK (debug-assertions + overflow-checks + CLI runtime smoke checks passed)"
