# PyCentric AI Agent Governance (`agents.md`)

**Repository**: `pycentric-cordon` (Cordon Linux Execution Sandbox & L3-L7 Network Telemetry Engine)
**License**: `AGPL-3.0-only` (Open Core) / `LICENSE-PYCENTRIC.md` (Distribution)
**Primary Stack**: Rust (`edition = "2024"`, `rust-version = "1.89"`, `axum`, `tokio`, `clap`, `ratatui`, `crossterm`) + Flutter Companion UI (`flutter_client/`, Dart `^3.7.0`, Material 3)

## 1. Constitutional Invariants

1. **Architecture (Hexagonal / Ports & Adapters)**:
   - Core domain types live in `src/domain/` and traits in `src/ports.rs`.
   - Domain logic must never depend on `axum`, `clap`, `ratatui`, or `flutter_client/`.
   - All production source files must stay `<= 400` lines (`GL-01`).
2. **Safety & Rust Lints**:
   - `#![forbid(unsafe_code)]`, `unwrap_used = "deny"`, `expect_used = "deny"`, `clippy::all = "deny"`, `clippy::pedantic = "warn"` (`-D warnings` in CI).
3. **Typography (`[INV-TYPOGRAPHY]`)**:
   - Unicode em-dashes (`\u2014`) and en-dashes (`\u2013`) are strictly prohibited across all source files, docs, comments, UI strings, and commit messages. Verify with `bash scripts/check-emdash.sh`.
4. **Testing & Coverage (`GL-07`)**:
   - Red-Green-Refactor TDD is mandatory.
   - Minimum `>= 90.0%` line coverage (`cargo llvm-cov --offline --summary-only --fail-under-lines 90`).
   - Integration contracts are verified via `.tea` (`tests/tea/cordon_api.tea`) and load SLOs via `pummel` (`tests/pummel/cordon_load.yaml`).
5. **Security & Supply Chain (`GL-02`)**:
   - `publish = false` in `Cargo.toml` (`[INV-PRIVATE-PUBLISH-GUARD]`).
   - `cargo deny check` and `cargo audit` must pass with zero unapproved advisories or copyleft/banned dependencies (`deny.toml`).
   - `gitleaks` full-history scan must pass (`task release:sanitize`).
6. **Zero-Drift API Contract**:
   - Control-plane routes and schemas are documented in OpenAPI 3.1.0 (`GET /openapi.json` and `docs/api/openapi.json`).
   - Non-idempotent `POST /api/v1/*` routes support `Idempotency-Key` correlation headers.
   - Errors return RFC 7807 `application/problem+json` (`ProblemDetails`) with `trace_id`.

## 2. Standard Verification Commands

```bash
cargo fmt -- --check
cargo clippy --all-targets --offline -- -D warnings
cargo test --offline
LLVM_COV=/usr/sbin/llvm-cov LLVM_PROFDATA=/usr/sbin/llvm-profdata cargo llvm-cov --offline --summary-only --fail-under-lines 90
cargo deny --offline check
bash scripts/check-emdash.sh
bash scripts/bundle-lint.sh
```
