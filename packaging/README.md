# PyCentric Cordon Packaging Notes

Governing Spec: ADR-L0-SEC-02. Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.

## Installed Units (packaging/systemd/)

| Unit | Purpose | Start order |
| --- | --- | --- |
| `cordon-netns.service` | Gate 1: network namespace, veth, iptables, tshark ring buffer | 1 |
| `cordon-l7.service` | Gate 4: headless `mitmdump` L7 policy engine (no web UI) | 2 |
| `cordon-control-plane.service` | HTTP control plane + telemetry dashboard (127.0.0.1:8095) | 3 |

## System User

`cordon-l7.service` runs as the dedicated `cordon` system user (MITM state in
`/var/lib/cordon`, audit log in `/var/log/cordon`). Create it once:

```bash
sudo useradd --system --home-dir /var/lib/cordon --no-create-home \
    --shell /usr/sbin/nologin cordon
```

(The `.deb` postinst and the `.spec` `%pre` scriptlet do this automatically.)

## Sudoers Policy (CWE-426 mitigation)

`deploy/bin/cordon.sudoers` grants the `cordon` group password-less,
absolute-path-only execution of the sandbox launcher. Install:

```bash
sudo visudo -cf deploy/bin/cordon.sudoers
sudo install -o root -g root -m 0440 deploy/bin/cordon.sudoers /etc/sudoers.d/cordon
sudo usermod -aG cordon "$USER"
```

Never grant sudoers entries for `/usr/bin/env`, `/usr/sbin/ip`, or
`/usr/bin/setpriv` directly; the launcher re-execs itself and rebuilds a
minimal environment via `/usr/bin/env -i` internally.

## L7 Policy Provisioning

The mitmproxy addon enforces the policy from `/run/cordon/policy.json`
(root-owned 0644). Provision it from a `Cordonfile` before launching workloads:

```bash
cordon run --config ./Cordonfile --dry-run   # preview the policy file commands
sudo cordon run --config ./Cordonfile -- <command>   # writes policy.json, then execs
```

`ALLOW_DOMAIN`, `DENY_DOMAIN`, and `POST_ALLOWED_HOST` directives in the
`Cordonfile` are merged onto the base profile with `strict_whitelist=true`.
Env overrides (`CORDON_EXTRA_HOSTS`) never widen the running policy without
`CORDON_ALLOW_INSECURE=1`, and every deviation is written to
`/var/log/cordon/audit.jsonl` as a canonical audit event.

## Service Activation

```bash
sudo systemctl enable --now cordon-netns.service
sudo systemctl enable --now cordon-l7.service
sudo systemctl enable --now cordon-control-plane.service
```
