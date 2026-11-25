# Security Policy & Threat Model (`SECURITY.md`)

- **Service**: PyCentric Cordon (`pycentric-cordon`)
- **Governing Architecture**: `docs/adr/ADR-L0-SEC-02.md` (internal-only)
- **Security Owner**: PyCentric Chief Information Security Officer (CISO) & Security QA Engineering

> [!IMPORTANT]
> **The Rust engine (`src/*.rs`) is authoritative for all enforcement behavior, Gate 4 L7 inspection (`cordon l7-proxy`), and security guarantees.**

---

## 1. Supported Versions

| Version | Rust Engine (`src/*.rs`) | Host Scripts (`deploy/`) | Security Support Status |
| :--- | :--- | :--- | :--- |
| **`1.0.x`** | Supported (`Edition 2024`) | Supported (`AppArmor 4.0`) | **Active Security Updates** |
| **`< 1.0.0`** | Pre-release | Pre-release | Unsupported |

---

## 2. STRIDE Threat Model & 5-Gate Countermeasures

| STRIDE Category | Threat Scenario | Attack Vector | Cordon Enforcement Gate | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Process impersonates host TLS server or bypasses user-space `HTTPS_PROXY` | Direct socket connection to `1.1.1.1:443` or raw TCP IP | **Gate 1 & Gate 4 (`ip netns` + `iptables`)**: Kernel `PREROUTING REDIRECT` forces all TCP 80/443 to `127.0.0.1:8080`; `FORWARD -j DROP` blocks non-redirected flows. | `test_network_namespace_and_iptables_commands` |
| **Spoofing (IPv6 Enforcement Bypass)** | Workload opens IPv6 TCP/UDP sockets to evade the IPv4 `iptables` REDIRECT into Gate 4 | Direct IPv6 connection (`::1`, `2606:4700::1111`) bypassing IPv4 NAT rules | **Gate 1 (`ip netns`)**: IPv6 is disabled inside the sandbox network namespace (`net.ipv6.conf.*.disable=1`) and `ip6tables -A FORWARD -j DROP` terminates all IPv6 forwarding fail-closed. | `tests/cordon_hardening.rs` (IPv6 bypass regression) |
| **Tampering** | Prompt-injected AI agent modifies `.git/hooks/pre-commit` or `/etc/apparmor.d` | Living-off-the-Land (LotL) write inside RW workspace | **Gate 2 & Gate 3**: `bwrap --ro-bind-try <ws>/.git <ws>/.git` (`EC-01`) + AppArmor `deny /etc/apparmor.d/** rwlkmx,` (`FR-3.5`). | `test_compile_launch_plan_ai_agent_and_untrusted` |
| **Repudiation** | Compromised build script performs unlogged outbound network calls | Ephemeral sub-process spawned during `npm install` | **Gate 4 & Gate 5**: headless `cordon l7-proxy` (`cordon-l7.service`) writes `0640` structured JSONL flow logs to `/var/log/cordon/audit.jsonl` + `tshark` 1 GB rotating PCAPNG ring buffer (`-b filesize:102400 -b files:10`) + `axum` audit ring buffer. | `test_control_plane_and_tui_snapshot` |
| **Information Disclosure** | Exfiltration of `~/.ssh/id_ed25519`, `~/.aws/credentials`, or `OPENAI_API_KEY` | Reading `$HOME` secrets or embedding keys in LLM prompt POST bodies | **Gate 2 & Gate 4**: AppArmor `deny @{HOME}/.ssh/** rwlkmx,` + L7 regex secret scanner (6 signature families: `SECRET_GITHUB_PAT`, `SECRET_OPENAI_KEY`, `SECRET_AWS_ACCESS_KEY`, `SECRET_PRIVATE_KEY_PEM`, `SECRET_JWT_BEARER`, `SECRET_ENV_ASSIGNMENT`, including fine-grained `github_pat_...` and AWS `ASIA...` formats) + `UNAUTHORIZED_MUTATING_METHOD` on package registries. | `test_l7_policy_evaluator_doh_secrets_and_allowlist` |
| **Denial of Service** | Fork bomb, orphan background daemons, or disk exhaustion via PCAP | Process spawns background workers or floods network tap | **Gate 3 & Gate 5**: `bwrap --unshare-pid --die-with-parent` reaps entire process tree on exit; `tshark -b filesize:102400 -b files:10` caps PCAP disk usage. | `test_compile_launch_plan_ai_agent_and_untrusted` |
| **Elevation of Privilege** | Container/namespace escape via `CAP_SYS_ADMIN`, `ptrace`, or `/tmp` BYOB | Executing downloaded exploit in `/tmp` or `ptrace` attaching to host PID | **Gate 2 (AppArmor 4.0)**: `deny capability sys_admin,`, `deny capability sys_ptrace,`, `deny ptrace,`, `deny signal peer=unconfined,`, `deny /tmp/** x,`, `deny /dev/shm/** x,`. | `test_apparmor_4_0_profile_rendering` |
| **Elevation of Privilege (TTY Hijack / TIOCSTI)** | Malicious workload uses the `TIOCSTI` ioctl to inject keystrokes into the host terminal session, or escapes via its controlling TTY | `ioctl(TIOCSTI)` legacy terminal injection from inside the sandbox | **Gate 3 (Bubblewrap VFS)**: `bwrap --new-session` starts the workload in a fresh `setsid()` session with no controlling TTY, and `--die-with-parent` reaps it on exit; `cordon doctor` reports host `legacy_tiocsti` status (`kernel_tiocsti_disabled`). | `tests/cordon_hardening.rs` (terminal session isolation regression) |

---

## 3. Hardening Regression Suite

The remediation wave pins the countermeasures above with dedicated regression coverage:

| Suite | Scope |
| :--- | :--- |
| `tests/cordon_hardening.rs` | Sandbox isolation hardening: Bubblewrap mount guards, fail-closed `ip netns` fallback, IPv6 bypass disable (`net.ipv6` disable + `ip6tables FORWARD -j DROP`), and `--new-session` / `--die-with-parent` TIOCSTI mitigation. |
| `tests/api_security.rs` | HTTP control-plane security: request header handling, RFC 7807 error contracts, and abuse resistance on `POST /api/v1/*` endpoints. |
| `tests/golden/l7_corpus.json` | Golden L7 corpus: known-secret payloads and benign tokens scored against the 6 secret signature families. |

---

## 4. Rust Memory & Type-Safety Guarantees

The Cordon engine (`src/*.rs`) enforces compile-time security invariants in `Cargo.toml`:
1. **`#![forbid(unsafe_code)]`**: Zero `unsafe` blocks are permitted anywhere in the crate.
2. **`unwrap_used = "deny"` & `expect_used = "deny"`**: Every fallible operation returns a typed `Result<T, CordonError>` mapped to RFC 7807 `application/problem+json`.
3. **Typestate Path Verification (`CanonicalPath`)**: All workspace and bind paths are canonicalized before `SandboxLaunchPlan` construction, and mounting `/` or `$HOME` read-write is rejected with `CordonError::UnsafeWorkspaceMount` (`HTTP 422`).
4. **Safe Web Dashboard DOM**: `src/dashboard.rs` uses `replaceChildren()`, `createElement()`, and `textContent` exclusively, eliminating DOM-based Cross-Site Scripting (XSS) when rendering untrusted URLs or audit logs.

---

## 5. Responsible Vulnerability Disclosure

If you discover a security vulnerability or sandbox bypass in Cordon:
1. **Do NOT open a public GitHub issue, publish proof-of-concept code, or discuss the finding in any public channel.** Report it privately to PyCentric only, and do not open a public GitHub security advisory until a fix has been released.
2. Email a detailed reproduction report to `security@pycentric.co.za` with the subject `[CORDON-SEC-ADVISORY]`.
3. Include the output of `cordon --json doctor`, your Linux kernel version (`uname -r`), AppArmor ABI version (`aa-status`), and the exact profile slug tested.
4. PyCentric Security Engineering acknowledges all reports within **24 hours** and provides a status update within **72 hours**. For critical findings (`CVSS >= 7.0`) we target a verified patch within **96 hours** where feasible, and we coordinate disclosure timing with the reporter (coordinated disclosure: public discussion after the fix is released or 90 days after acknowledgement, whichever comes first).
