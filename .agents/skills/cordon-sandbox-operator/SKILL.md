---
name: cordon-sandbox-operator
description: Operate PyCentric Cordon 5-gate Linux sandboxes, choose among the 6 universal workload profiles, author Cordonfile/TOML configs, evaluate L7 egress URLs, and diagnose host confinement via cordon doctor.
---

# Cordon Sandbox Operator

Use this skill when running, configuring, or troubleshooting workloads inside PyCentric Cordon (`cordon` CLI / `Taskfile.yml`).

## Core Invariants
- **Fail-Closed Posture**: Never suggest disabling AppArmor, network namespace isolation, or unsafe-path checks to work around an error. Always surface the exact `cordon doctor` or `CordonError` diagnostic and remediation command.
- **Zero Em-Dashes (`[INV-TYPOGRAPHY]`)**: Never emit Unicode em-dashes or en-dashes in generated `Cordonfile`, TOML, or documentation.

## 1. Pre-Flight Host Diagnostics
Before launching workloads on a new host, inspect the 15-point confinement report:
```bash
cordon --json doctor
```
- If `kernel_apparmor_lsm`, `apparmor_aa_exec`, or `bwrap` fails, stop and print the exact missing package or kernel parameter from `doctor` output.
- If `agent-net` netns is inactive, note that Cordon fails closed to `--unshare-net` loopback airgap unless `sudo deploy/net/setup-sandbox-net.sh` is run.

## 2. Selecting a Built-in Profile
Inspect available profiles with `cordon --json profiles`:
- `ai-agent`: Default for coding agents (`opencode`, `antigravity`); workspace RW, L7 proxy egress.
- `untrusted-code`: Untrusted scripts; strict filesystem/network isolation.
- `package-build`: Cargo/npm/pip builds with build scratch support.
- `network-audit`: Traffic inspection and forensic capture (`mitmproxy` / `tshark`).
- `gui-desktop`: Wayland + `/dev/dri` GPU passthrough (`allow_gpu_dri = true`, `allow_gui_wayland = true`). Note: MicroVM backends reject GUI/GPU passthrough.
- `airgapped`: Zero network (`--unshare-net`), masked `$HOME` and credential directories.

## 3. Reproducible Configs (`Cordonfile` / TOML / JSON)
List starter templates and scaffold a config:
```bash
cordon --json config list-templates
cordon config init --template opencode --format toml --output Cordonfile.toml
```
Dry-run and inspect the compiled 5-gate `SandboxLaunchPlan` before execution:
```bash
cordon --json plan --profile ai-agent -- /bin/true
```

## 4. L7 Egress Policy Evaluation
Test whether a domain, URL, or HTTP method is permitted before running an agent:
```bash
cordon --json evaluate-url --profile ai-agent --url https://api.github.com/repos --method GET
```

## 5. MicroVM Mode
MicroVM backends (`firecracker`, `qemu`, `cloud-hypervisor`, `libkrun`) require `/dev/kvm` (and `/dev/net/tun` for TAP networking) and reject `gui-desktop` / GPU passthrough (`UnsupportedVmOption`). Verify readiness in `cordon --json doctor` before invoking `cordon vm ...`.
