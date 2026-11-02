# Contributing to Cordon

Thank you for your interest in contributing to Cordon. This repository is an
open-core product of PyCentric (Pty) Ltd.

## Licensing

- The **open core** (engine source, deployment assets, packaging definitions,
  tests, and operator documentation) is licensed under the **GNU Affero
  General Public License v3 only** (`AGPL-3.0-only`). See [`LICENSE`](LICENSE)
  and [`NOTICE.md`](NOTICE.md).
- **Excluded works** (internal governance, commercial, and legal documents) and
  **PyCentric-branded distribution packages** remain proprietary. See
  [`LICENSE-PYCENTRIC.md`](LICENSE-PYCENTRIC.md). Do not copy, redistribute, or
  derive works from the excluded works.
- "PyCentric", "Cordon", `pycentric-cordon`, and `org.pycentric` are trade
  marks of PyCentric (Pty) Ltd. No trade mark rights are granted.

By contributing, you agree that your contribution is licensed under
`AGPL-3.0-only` and, per the PyCentric Contributor License Agreement
([`CLA.md`](CLA.md)), that PyCentric may also license it under other terms
(dual licensing). Every pull request requires a signed CLA; the CLA bot
provides a link and a signing comment on your first PR.

## Contribution workflow

1. Fork and create a feature branch.
2. Keep changes focused; update tests and documentation with behavior changes.
3. Run the local gates before opening a PR:
   - `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
   - `cargo test`
   - `ruff check src tests`, `pytest`
   - `bash scripts/check-emdash.sh` (typography rule: hyphens and colons only,
     no unicode dashes)
4. Open a pull request with a clear description of the problem and the change.
   Disclose material AI-generated content in the PR description (CLA section 4.2).
5. Sign the CLA when prompted.

## Security issues

Do not open public issues for security vulnerabilities. Follow the disclosure
policy in [`SECURITY.md`](SECURITY.md).

## Code of conduct

Be respectful and constructive. Maintainers may close contributions that do not
meet these standards or that violate the licence boundaries in `NOTICE.md`.
