---
name: cordon-contributor-guardian
description: Enforce PyCentric Cordon constitutional gates before commit and push via prek (cargo fmt, clippy -D warnings, <= 400-line modules, zero-em-dash typography, >= 90% line and >= 88% region coverage, cargo deny, and cargo audit).
---

# Cordon Contributor Guardian

Use this skill before committing or pushing any change to `cordon-public`.

## Core Rules
- **Fail Loudly**: Never bypass git hooks (`--no-verify`) or relax clippy/coverage/typography gates. Fix the underlying violation and re-run the check.
- **Constitutional Invariants** (`agents.md` and `design.md`):
  - `unsafe_code = "forbid"`, `unwrap_used = "deny"`, `expect_used = "deny"` (including `#[cfg(test)]`). Use `Result` + `?` or `.unwrap_or_else(|e| panic!(...))` in tests.
  - Every `.rs` file in `src/` and `tests/` must stay `<= 400` lines (`[GL-01]`).
  - Zero Unicode em-dashes (`\u2014`) or en-dashes (`\u2013`) anywhere (`[INV-TYPOGRAPHY]`).

## 1. Hook Installation
Ensure `prek` hooks are installed for both `pre-commit` and `pre-push`:
```bash
task hooks:install
# or: prek install --install-hooks
```

## 2. Pre-Commit Checks (Fast Static & Unit Gate)
Runs automatically on `git commit`, or manually via `task hooks:pre-commit` (`prek run --all-files`):
1. `cargo fmt -- --check`
2. `cargo clippy --all-targets --offline -- -D warnings`
3. `cargo test --lib --offline`
4. `bash scripts/check-emdash.sh`
5. `bash scripts/bundle-lint.sh`
6. `bash -n deploy/bin/agent-sandbox deploy/bin/agent-shell deploy/net/setup-sandbox-net.sh deploy/tests/verify_sandbox_tv.sh`
7. `bash scripts/check-file-size.sh` (`<= 400` lines per `.rs` file)

## 3. Pre-Push Checks (Full Test, Dynamic, Coverage & Supply-Chain Gate)
Runs automatically on `git push`, or manually via `task hooks:pre-push` (`prek run --hook-stage pre-push --all-files`):
1. `cargo test --offline --all-targets`
2. `bash scripts/dynamic-check.sh` (`RUSTFLAGS="-C debug-assertions=on -C overflow-checks=on"` full test run + CLI smoke checks)
3. `bash scripts/verify-coverage.sh` (`>= 90%` lines and `>= 88%` LLVM regions; also runs `--branch` if a `nightly` toolchain is installed)
4. `cargo deny --offline check`
5. `cargo audit --no-fetch`
