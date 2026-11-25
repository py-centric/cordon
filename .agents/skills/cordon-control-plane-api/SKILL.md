---
name: cordon-control-plane-api
description: Operate, inspect, and contract-test the Cordon axum HTTP Control Plane (:8095), OpenAPI 3.1.0 specification (/openapi.json), Idempotency-Key validation, RFC 7807 errors, Tea E2E suite, and Pummel load tests.
---

# Cordon Control Plane API & Contracts

Use this skill when starting, querying, or contract-testing the Cordon HTTP Control Plane (`axum` on `:8095`).

## Referenced Skills
- **E2E Contract Testing**: Delegate Tea execution and `.tea` authoring to the `tea` skill (`/home/v/.gemini/config/skills/tea/SKILL.md`).
- **Load & SLA Testing**: Delegate Pummel/Goose execution and scenario tuning to the `pycentric-pummel` skill (`/home/v/.gemini/config/skills/pycentric-pummel/SKILL.md`).

## 1. Start the Control Plane
```bash
task serve
# or directly:
cargo run --offline -- serve --host 127.0.0.1 --port 8095
```

## 2. Core Endpoints & Contracts
- **Probes & Metrics**: `GET /health`, `GET /health/liveness`, `GET /health/readiness`, `GET /health/dependencies`, `GET /metrics`.
- **OpenAPI 3.1.0**: `GET /openapi.json` returns the live machine-readable schema for all routes and RFC 7807 `ProblemDetails` responses.
- **Read Endpoints**: `GET /api/v1/meta` (AGPL-3.0-only notices), `GET /api/v1/profiles`, `GET /api/v1/templates`, `GET /api/v1/doctor`, `GET /api/v1/apparmor/{profile}`, `GET /api/v1/network/{profile}`, `GET /api/v1/events`.
- **Mutating Endpoints**: `POST /api/v1/compile`, `POST /api/v1/compile-config`, `POST /api/v1/evaluate-l7`.
  - When supplying `Idempotency-Key`, it must be non-empty, `<= 128` bytes, and printable ASCII only (no control characters); invalid keys fail loudly with RFC 7807 `400 Bad Request`.
  - Host header validation rejects foreign `Host` headers (`421 Misdirected Request`, DNS rebinding defense), and error responses never leak host filesystem paths.

## 3. Contract & Load Verification
- **Rust API Security & Control Plane Tests**:
  ```bash
  task test:contract
  ```
- **Tea E2E Suite** (against a running server on `127.0.0.1:8787` or configured port):
  - SUT: `tests/tea/sut.yaml`
  - Suite: `tests/tea/cordon_api.tea`
- **Pummel Load SLA** (`p95 <= 200ms`, `p99 <= 500ms`, `0%` 5xx):
  - Scenario: `tests/pummel/cordon_load.yaml`
  - If any SLA threshold or assertion fails, fail loudly with the exact status code, latency percentile, and RFC 7807 `detail` payload.
