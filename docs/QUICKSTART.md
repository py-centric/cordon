# Cordon Quickstart (Linux)

- **Service**: PyCentric Cordon (`pycentric-cordon` v1.0.0)
- **Audience**: operators and contributors evaluating the open core (the internal audience manifest is not published)
- **Deep-dive guide**: [`docs/OPERATIONS_AND_WORKLOAD_GUIDE.md`](OPERATIONS_AND_WORKLOAD_GUIDE.md)

This guide takes you from prerequisites to your first sandboxed run and back to a clean uninstall. Every command below is verified against the shipped CLI and scripts.

---

## 1. Prerequisites

| Requirement | Minimum | Notes |
| :--- | :--- | :--- |
| Linux kernel | `>= 5.15` (`6.8+` recommended) | Ubuntu 24.04+ provides AppArmor 4.0 `abi <abi/4.0>` support |
| Bubblewrap (`bwrap`) | any | Gate 3 VFS/PID/IPC isolation engine (required) |
| `iproute2` (`ip`) | any | Gate 1 network namespace and veth management (required) |
| `iptables` | any | Gate 4 transparent TCP 80/443 REDIRECT (required) |
| AppArmor 4.0 | `abi <abi/4.0>` | Gate 2 MAC policy (`aa-status` reports host state) |
| `mitmproxy` (`mitmdump`) | any | Gate 4 L7 TLS inspection and policy enforcement |
| `tshark` | any | Gate 5 bounded PCAP ring capture |
| Rust toolchain | `1.89` (Edition 2024) | Matches `rust-version` in [`Cargo.toml`](../Cargo.toml) |
| Python (optional) | `>= 3.12` | Only for the reference control plane and its test suite |

`cordon doctor` verifies all of the above in a **15-point diagnostic report**: the 7 toolchain binaries (`bwrap`, `ip`, `iptables`, `aa-status`, `mitmproxy`, `tshark`, `rustc`) plus `kernel_apparmor_lsm`, the live gate-confinement checks `apparmor_aa_exec` and `apparmor_confinement`, `kernel_tiocsti_disabled`, and four optional MicroVM readiness probes (`kvm_device_accessible`, `tun_device_accessible`, `microvm_vmm_binaries`, `btrfs_reflink_support`) that never affect the overall health flag.

---

## 2. Install

```bash
# 1. Build the release binary (target/release/cordon)
task build            # cargo build --release --offline

# 2. Install user-local: ~/.local/bin/cordon + starter configs + Bash/Zsh/Fish completions
task install:local

# Alternative: system-wide via the pc CLI orchestrator
pc install            # installs to /usr/local/bin/cordon

# Alternative: Debian/Ubuntu package
sudo dpkg -i dist/pycentric-cordon_1.0.0_amd64.deb
```

Verify the installation and your host:

```bash
cordon doctor
```

---

## 3. First Dry-Run (no execution, no privileges)

A dry-run compiles the full 5-gate `SandboxLaunchPlan` and prints it without executing anything. Use it to inspect the Bubblewrap argv, network namespace, AppArmor policy, and L7 proxy wiring:

```bash
# Inspect the compiled plan for an air-gapped Python run
cordon run -f configs/Cordonfile.python -w "$PWD" --dry-run -- python3 -I -V

# Inspect the plan for an AI agent workload
cordon run -f configs/Cordonfile.opencode -w "$PWD" --dry-run -- opencode
```

Check the guardrails while you are here: read-write mounts of `/` or `$HOME` are rejected with `CordonError::UnsafeWorkspaceMount` (exit code `1`):

```bash
cordon run -w / --dry-run -- true    # expected: refused with CordonError::UnsafeWorkspaceMount (exit code 1)
```

---

## 4. First Run

### 4.1 One-time network provisioning (Gate 1)

```bash
# Create the agent-net namespace + veth pair (10.200.1.2/24 <-> 10.200.1.1/24),
# fail-closed iptables rules, and IPv6 bypass disable
sudo deploy/net/setup-sandbox-net.sh up
sudo deploy/net/setup-sandbox-net.sh status
```

DNS inside the sandbox is redirected to the host-local resolver at `10.200.1.1:53` (optional `dnsmasq` query logging on the host).

### 4.2 Run a workload

```bash
# Quick mode: run any command in the current project (network fallback is automatic)
cordon run opencode

# Air-gapped untrusted Python (zero network, masked $HOME, masked credential dirs)
cordon run --offline python3 -I your_script.py

# Interactive sandboxed shell and control REPL
cordon shell
cordon repl
```

### 4.3 L7 enforcement plane (Gate 4)

In production the L7 plane runs headless `mitmdump` under `systemd` as `cordon-l7.service`, loading [`deploy/mitmproxy/agent_policy_addon.py`](../deploy/mitmproxy/agent_policy_addon.py) and writing `0640` JSONL audit events to `/var/log/cordon/audit.jsonl`. `ALLOW_DOMAIN` / `DENY_DOMAIN` in your `Cordonfile` are wired into this running enforcement plane. Forensic L3/L4 capture is bounded at approximately 1 GB (`tshark -b filesize:102400 -b files:10`).

---

## 5. Uninstall

```bash
# 1. User-local binary and configs
task deploy:rollback                       # removes ~/.local/bin/cordon
rm -rf ~/.config/cordon/configs
rm -f ~/.local/share/bash-completion/completions/cordon \
      ~/.local/share/zsh/site-functions/_cordon \
      ~/.zfunc/_cordon \
      ~/.config/fish/completions/cordon.fish

# 2. System-wide (if installed via dpkg)
sudo dpkg -r pycentric-cordon

# 3. Tear down the network namespace and iptables rules
sudo deploy/net/setup-sandbox-net.sh down
```

---

## 6. Where to Go Next

- [`README.md`](../README.md): profiles, `Cordonfile` engine, HTTP control plane API map.
- [`docs/OPERATIONS_AND_WORKLOAD_GUIDE.md`](OPERATIONS_AND_WORKLOAD_GUIDE.md): workload recipes, packaging, shell completions, L7/DNS/audit operations.
- [`SECURITY.md`](../SECURITY.md): STRIDE threat model and responsible disclosure.
