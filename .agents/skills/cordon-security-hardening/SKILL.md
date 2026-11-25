---
name: cordon-security-hardening
description: Verify and preserve Cordon CH-01..CH-08 security hardening invariants, AppArmor 4.0 policy validation, bubblewrap device/socket/env isolation, and MicroVM fail-closed boundaries.
---

# Cordon Security Hardening

Use this skill when modifying sandbox compilation, AppArmor policy rendering, L7 proxy rules, plugin loading, or MicroVM attachment.

## Hardening Invariants (CH-01 to CH-08)
1. **CH-01 Prefix-Based RW Mount Rejection**: Reject unsafe writable roots (`/`, `/home`, `/etc`, `$HOME/.ssh`, etc.) by canonical prefix, not exact string match (`src/sandbox/policy.rs`).
2. **CH-02 `MASK_DIR` Ordering**: Emit `--tmpfs` masks *after* all bind mounts so secret subtrees cannot be re-exposed by later binds; expand `~` safely.
3. **CH-03 Reserved Env & Socket Masks**: Reject `RESERVED_ENV_KEYS` (`LD_PRELOAD`, `SSL_CERT_FILE`, `HTTPS_PROXY`, etc.) unless `--allow-reserved-env` is explicitly passed; mask host XDG/D-Bus/keyring sockets.
4. **CH-04 Gate Attestation**: `gates_applied` must never overclaim AppArmor or netns confinement; `cordon doctor` and live argv must match actual kernel/binary state.
5. **CH-05 Plugin Isolation**: Built-in plugins (`cordon-hud`, `cordon-fish`) must never be shadowed by hostile workspace plugins; workspace plugins are denied unless explicitly opted in.
6. **AppArmor 4.0 Entry Validation**: Reject newlines, quotes, braces, or DSL injection characters in profile paths (`CordonError::InvalidInput`) and fall back to a deny-all `FAIL_CLOSED_PROFILE`.
7. **Device & Accelerator Boundaries**:
   - Native `bwrap` uses `--dev /dev` by default; only `gui-desktop` (`allow_gpu_dri = true`) binds `/dev/dri`.
   - MicroVM backends (`firecracker`, `qemu`, `cloud-hypervisor`, `libkrun`) must fail closed with `UnsupportedVmOption` on GUI/GPU passthrough and only expose `/dev/kvm` (and `/dev/net/tun` for TAP) to the VMM wrapper.
8. **CH-08 Canonical Network Constants**: Preserve canonical `agent-net` subnet, DNS resolver (`10.200.1.1:53`), and DoH/IP-literal blocking rules.

## Verification Commands
Run the dedicated security and hardening suites after any security-sensitive change:
```bash
cargo test --test hardening_paths_and_env --test hardening_isolation_and_plugins --offline
cargo test --test api_security_auth_headers --test api_security_limits --offline
```
If any hardening assertion fails, halt immediately and report the exact failing test and invariant.
