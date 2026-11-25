# Changelog

All notable changes to **PyCentric Cordon** (`pycentric-cordon`) are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/), and versions follow semantic versioning. The open core is licensed under the GNU Affero General Public License v3 only (see [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md)); PyCentric-branded distribution packages and excluded works remain under the PyCentric proprietary license (see [`LICENSE-PYCENTRIC.md`](LICENSE-PYCENTRIC.md)).

## [Unreleased] - Remediation Wave (2026-10-31)

### Added
- Gate 3.5 MicroVM isolation plane, compile-time preview ([`docs/design/microvm-isolation.md`](docs/design/microvm-isolation.md)): `IsolationBackend` (`native-bwrap`, `qemu-microvm`, `firecracker`, `krun` reserved) and `VmDiskMode` with a validated `MicroVmSpec` (backend/disk-mode matrix, resource bounds, allowlisted image roots, no symlinked image paths, engine-aware rate limits with explicit units).
- `[vm]` / `[vm.rate_limits]` TOML tables and `VM_BACKEND`, `VM_RESOURCES`, `VM_KERNEL`, `VM_ROOTFS`, `VM_SNAPSHOT`, `VM_RATE_LIMIT` Cordonfile directives; `--vm-*` flags on `run` and `inspect-cmd`; optional `vm` object on `POST /api/v1/compile`.
- Plan compiler for QEMU `-M microvm` and the Firecracker API sequence; the VMM runs inside the Gate 1-3 Bubblewrap tail, `/dev/kvm` and `/dev/net/tun` are bound only for MicroVM plans, and native plan JSON is unchanged.
- AppArmor `cordon_<slug>_microvm` variant (`render-apparmor --microvm`); native profiles now explicitly deny `/dev/kvm`. Per-netns `tcvm` tap pool on `10.200.255.0/24` (`render-netns --microvm`).
- `cordon doctor` grows from 11 to 15 checks with non-required MicroVM readiness probes.
- New errors `IncompatibleVmDiskMode`, `UnsafeMicroVmImage`, `UnsupportedVmOption` (HTTP 422) and `MicroVmUnavailable` (HTTP 503, CLI exit code 69). Live MicroVM launch is refused until the guest agent ships.
- Python reference parity (`src/cordon/microvm.py`) checked against the shared fixture `tests/golden/microvm_spec_cases.json`.

### Licensing
- Open-core relicensing: the Cordon engine source, deployment assets, packaging definitions, Flutter client, tests, and operator documentation are now licensed under `AGPL-3.0-only` (new [`LICENSE`](LICENSE)).
- Excluded works remain proprietary and confidential under [`LICENSE-PYCENTRIC.md`](LICENSE-PYCENTRIC.md): `AUDIENCE_MANIFEST.md`, `FEASIBILITY_AND_STRATEGY.md`, `docs/legal/`, `docs/adr/`, `docs/governance/`, `docs/newsletter/`, `docs/PRD.md`, `docs/FLUTTER_UI_UX_SIGNOFF.md`, and `pc.toml` (PyCentric `pc` orchestrator integration).
- PyCentric-branded distribution packages (`pycentric-cordon` `.deb`/`.rpm`/tarball/wheel/Flatpak artifacts) are distributed by PyCentric as copyright owner under the proprietary terms and are not covered by the AGPL grant; trade marks ("PyCentric", "Cordon", `pycentric-cordon`, `org.pycentric`) are not licensed. Full scope map in [`NOTICE.md`](NOTICE.md).
- Contributor governance moved to a GitHub Contributor License Agreement: new [`CLA.md`](CLA.md) (individual and corporate, dual-licensing grant, AI-generated contribution disclosure) and the CLA enforcement workflow [`.github/workflows/cla.yml`](.github/workflows/cla.yml), with contribution rules in [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Open-core compliance hardening: [`LICENSE-PYCENTRIC.md`](LICENSE-PYCENTRIC.md) rewritten as Part A (excluded works) / Part B (commercial EULA for the supported enterprise distribution) with a third-party carve-out; [`CLA.md`](CLA.md) v1.1 (AI warranties, minors, version-bound signing, POPIA terms); `packaging/deb/copyright` (DEP-5) and `packaging/SOURCE_OFFER.txt` (AGPL s.6/s.13 source offer); `GET /api/v1/meta` plus dashboard, TUI, and Flutter legal notices carrying `AGPL-3.0-only` and the Corresponding Source URL.

### Changed
- AGPL s.13/s.5(d) compliance across all network UIs (`/api/v1/meta`, dashboard/TUI/Flutter footers); security disclosure policy re-pointed to private reporting (no UAT channel); internal-only document references in public docs now read "internal (not published)" so a public mirror has no dead links; new public [`docs/OPEN_CORE_FAQ.md`](docs/OPEN_CORE_FAQ.md) and README "Open Core, Licensing & Procurement" section.
- Governance material re-based on the open-core model: `AUDIENCE_MANIFEST.md` and the UAT evaluator stress test retired (probes harvested into `docs/governance/PRE_RELEASE_RED_TEAM_CHECKLIST.md`); feasibility, playbook, sign-off, founder brief, operating cadence, roadmap, and feasibility-claims documents carry OPEN-CORE RESTATEMENT banners and sales-use bans where claims are stale; POPIA processing notice drafted (`docs/legal/src/personal-information-processing-notice.md`); human governance actions tracked in `docs/governance/OPEN_CORE_GOVERNANCE_ACTIONS.md`.
- Release engineering: `scripts/export-public.sh` (squashed, sanitized public export with excluded-path and secret gates) plus `task release:sanitize` / `task release:export`; `scripts/bundle-lint.sh` authority re-pointed to [`NOTICE.md`](NOTICE.md) + [`CONTRIBUTING.md`](CONTRIBUTING.md); hardening-test narration neutralized (CH-01..CH-08 IDs preserved); `tea.db` removed and ignored.

### Removed
- UAT confidentiality and evaluation agreement (`docs/legal/src/uat-confidentiality-evaluation-agreement.md`) and its executed-form artifacts (`docs/legal/pdf/PYC-UAT-2026-001*`) are withdrawn; open-core distribution under `AGPL-3.0-only` and the GitHub CLA supersede the pre-release UAT confidentiality model.

### Security
- `MASK_DIR` is implemented as a real enforcement directive: it masks the directory with an empty `tmpfs` overlay inside the sandbox.
- `ALLOW_DOMAIN` / `DENY_DOMAIN` directives are wired to the running L7 enforcement plane (headless `mitmdump`, `cordon-l7.service`).
- Secret scanner covers 6 signature families including fine-grained GitHub token (`github_pat_...`) and AWS temporary key (`ASIA...`) formats, plus URL/query/header scanning and fail-closed enforcement (golden corpus [`tests/golden/l7_corpus.json`](tests/golden/l7_corpus.json)).
- `cordon doctor` reports live AppArmor gate-confinement status (`apparmor_aa_exec`, `apparmor_confinement`) as an 11-point diagnostic.
- Privilege boundary hardening: `agent-sandbox` launches the privileged chain under `sudo /usr/bin/env -i` with absolute binary paths, a validated `cordon.sudoers` policy, and capability-bounded hardened systemd units.
- Control-plane API hardening: optional `CORDON_API_TOKEN` bearer auth, Host-header validation (DNS-rebinding defense), POST rate limits, body-size caps, and security headers (`CSP`, `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`).
- Evidence hygiene: block events record `secret_fingerprint` (SHA-256 prefix) and `rule_id`, never raw payloads; audit-ring eviction raises a WARNING event instead of silently dropping; REPL history is written `0600` with secret values redacted.
- Terminal hardening: ANSI/OSC/DCS sanitization on rendered untrusted text and forced terminal-state reset after child processes.

### Testing
- New regression suites: `tests/cordon_hardening.rs` (sandbox isolation hardening), `tests/api_security.rs` (HTTP control-plane security), and `tests/golden/l7_corpus.json` (golden L7 secret corpus).

### Documentation
- Documentation-drift remediation across [`README.md`](README.md), [`SECURITY.md`](SECURITY.md), `docs/PRD.md`, [`docs/OPERATIONS_AND_WORKLOAD_GUIDE.md`](docs/OPERATIONS_AND_WORKLOAD_GUIDE.md), `docs/adr/ADR-L0-SEC-02.md`, and `FEASIBILITY_AND_STRATEGY.md`: canonical 5-gate ordering, real profile slugs, corrected `MASK_DIR` semantics, doctor check-count claims, 6-family secret DLP claim, repo-relative links only, and one canonical latency metrics table (`M1`..`M4`) in the ADR.
- New `AUDIENCE_MANIFEST.md` UAT bundle confidentiality control and [`docs/QUICKSTART.md`](docs/QUICKSTART.md) onboarding guide.
- `docs/FLUTTER_UI_UX_SIGNOFF.md` refresh tracked separately (Flutter track).

### Build & CI
- New GitHub Actions workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): rustfmt + clippy lint, Rust and Python test suites, `cargo llvm-cov` coverage gate, best-effort `cargo deny` / `cargo audit` (non-blocking until `deny.toml` exists), and `gitleaks detect --full-history` secret scanning.
- Taskfile repairs: `test:fast` now runs the library-only fast lane (`cargo test --lib`), `test:stress` is rewired to the hardening suite (`tests/cordon_hardening.rs`, `--ignored`), and `validate-docs` uses the repo-local [`scripts/check-emdash.sh`](scripts/check-emdash.sh) instead of a machine-absolute validator path.
- `pc.toml` `minimum_rust` aligned with `Cargo.toml` (`1.89`).

## [1.0.0] - 2026-10-21 (hardening sprint merged 2026-10-31)

### Added
- 5-gate sandbox domain engine: `ip netns` + veth (Gate 1), AppArmor 4.0 MAC (Gate 2), Bubblewrap VFS (Gate 3), `iptables` REDIRECT to L7 `mitmproxy` (Gate 4), and bounded `tshark` PCAP ring capture (Gate 5), with hexagonal ports and enforcement compilers.
- Reproducible environment config engine (`Cordonfile`, `Cordonfile.toml`, `cordon.json`) with command groups, directory groups, and starter workload templates.
- CLI control plane with `--json` output, `axum` HTTP API, WCAG 2.1 AA tri-theme web dashboard, `ratatui` TUI, and interactive `crossterm` sandbox REPL with a tmux-style plugin ecosystem.
- Python 3.12 reference control plane, `mitmproxy` policy addon, and host deployment scripts.
- Multi-platform Flutter companion client (Material 3, responsive layouts, ARB localization).
- Multi-distro packaging pipeline (`.tar.gz`, `.deb`, `.rpm`, AppImage, Flatpak) with Bash/Zsh/Fish shell completions.
- Rust integration suites and Python verification tests.
- Governance documentation set (ADR-L0-SEC-02, PRD, security threat model, operations guide) and UAT legal contracts (founder IP assignment deed, confidentiality evaluation agreement).

### Changed
- Relicensed to PyCentric (Pty) Ltd proprietary terms; the proprietary `LICENSE` ships as the Debian copyright file.
- Contact and documentation URLs unified on `pycentric.co.za`.
- Public newsletter article replaces the internal architecture brief.

### Security
- Hardening sprint: Bubblewrap mount guards, terminal session isolation (`--new-session` / `--die-with-parent` TIOCSTI mitigation), fail-closed `ip netns` fallback, IPv6 bypass disable (`net.ipv6` disable + `ip6tables FORWARD -j DROP`), full `mitmproxy` request-body scanning, workspace plugin manifest shadowing fix, and sandbox isolation regression tests.
