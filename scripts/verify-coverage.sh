#!/usr/bin/env bash
set -euo pipefail

# Verify Rust line, region (LLVM branch-arm), and function coverage via cargo-llvm-cov.
# Note: true MC/DC --branch coverage in rustc requires a nightly toolchain
# (-Z coverage-options=branch); on stable rustc we enforce >= 90% line coverage
# and >= 88% region coverage (every basic block / branch arm in LLVM IR).

if [[ -z "${LLVM_COV:-}" && -x /usr/sbin/llvm-cov ]]; then
    export LLVM_COV=/usr/sbin/llvm-cov
fi
if [[ -z "${LLVM_PROFDATA:-}" && -x /usr/sbin/llvm-profdata ]]; then
    export LLVM_PROFDATA=/usr/sbin/llvm-profdata
fi

cargo llvm-cov --offline --summary-only --fail-under-lines 90 --fail-under-regions 88

if command -v rustup >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    echo "Running nightly branch coverage check..."
    cargo +nightly llvm-cov --offline --branch --summary-only --fail-under-lines 90
else
    echo "verify-coverage: stable toolchain active (lines >= 90%, regions >= 88% verified; --branch skipped without nightly)"
fi
