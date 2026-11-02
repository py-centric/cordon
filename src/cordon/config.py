"""Reproducible environment configuration parser for Cordon (`Cordonfile`, TOML, JSON).

Provides Python reference parity with `src/config.rs` so mitmproxy L7 hooks and
Python automation tooling can inspect `Cordonfile`, `Cordonfile.toml`, and `cordon.json`
environment specifications.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from cordon.models import CordonProfile
from cordon.policy_rules import PolicyConfig
from cordon.profiles import get_profile


@dataclass(slots=True)
class CordonEnvironmentConfig:
    """Declarative reproducible sandbox environment specification."""

    name: str = "cordon-env"
    base_profile: str = "ai-agent"
    description: str = "Reproducible Cordon sandbox environment"
    workdir: str | None = None
    readonly_mounts: list[str] = field(default_factory=list)
    writable_mounts: list[str] = field(default_factory=list)
    masked_binaries: list[str] = field(default_factory=list)
    masked_dirs: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    allowed_domains: list[str] = field(default_factory=list)
    denied_domains: list[str] = field(default_factory=list)
    post_allowed_hosts: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> CordonEnvironmentConfig:
        """Load a `Cordonfile`, `Cordonfile.toml`, or `cordon.json` from disk."""
        file_path = Path(path)
        raw = file_path.read_text(encoding="utf-8")
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            return cls.from_json_str(raw)
        if suffix == ".toml":
            return cls.from_toml_str(raw)
        if file_path.name.startswith("Cordonfile"):
            return cls.from_cordonfile_str(raw)
        trimmed = raw.lstrip()
        if trimmed.startswith("{"):
            return cls.from_json_str(raw)
        if trimmed.startswith("[") or "=" in trimmed.splitlines()[0]:
            return cls.from_toml_str(raw)
        return cls.from_cordonfile_str(raw)

    @classmethod
    def from_json_str(cls, raw: str) -> CordonEnvironmentConfig:
        """Parse a JSON environment configuration."""
        data = json.loads(raw)
        return cls(
            name=str(data.get("name", "cordon-env")),
            base_profile=str(data.get("base_profile", "ai-agent")),
            description=str(data.get("description", "Reproducible Cordon sandbox environment")),
            workdir=data.get("workdir"),
            readonly_mounts=list(data.get("readonly_mounts", [])),
            writable_mounts=list(data.get("writable_mounts", [])),
            masked_binaries=list(data.get("masked_binaries", [])),
            masked_dirs=list(data.get("masked_dirs", [])),
            env_vars=dict(data.get("env_vars", {})),
            allowed_domains=list(data.get("allowed_domains", [])),
            denied_domains=list(data.get("denied_domains", [])),
            post_allowed_hosts=list(data.get("post_allowed_hosts", [])),
            cmd=list(data.get("cmd", [])),
        )

    @classmethod
    def from_toml_str(cls, raw: str) -> CordonEnvironmentConfig:
        """Parse a `Cordonfile.toml` environment configuration."""
        data = tomllib.loads(raw)
        env_sec = data.get("environment", {})
        fs_sec = data.get("filesystem", {})
        net_sec = data.get("network", {})
        runtime_sec = data.get("runtime", {})
        raw_env = data.get("env", {})

        return cls(
            name=str(env_sec.get("name", data.get("name", "cordon-env"))),
            base_profile=str(
                env_sec.get("base_profile", data.get("base_profile", "ai-agent"))
            ),
            description=str(
                env_sec.get(
                    "description",
                    data.get("description", "Reproducible Cordon sandbox environment"),
                )
            ),
            workdir=env_sec.get("workdir", data.get("workdir")),
            readonly_mounts=list(
                fs_sec.get("readonly_mounts", data.get("readonly_mounts", []))
            ),
            writable_mounts=list(
                fs_sec.get("writable_mounts", data.get("writable_mounts", []))
            ),
            masked_binaries=list(
                fs_sec.get("masked_binaries", data.get("masked_binaries", []))
            ),
            masked_dirs=list(fs_sec.get("masked_dirs", data.get("masked_dirs", []))),
            env_vars={str(k): str(v) for k, v in raw_env.items()},
            allowed_domains=list(
                net_sec.get("allowed_domains", data.get("allowed_domains", []))
            ),
            denied_domains=list(
                net_sec.get("denied_domains", data.get("denied_domains", []))
            ),
            post_allowed_hosts=list(
                net_sec.get("post_allowed_hosts", data.get("post_allowed_hosts", []))
            ),
            cmd=list(runtime_sec.get("cmd", data.get("cmd", []))),
        )

    @classmethod
    def from_cordonfile_str(cls, raw: str) -> CordonEnvironmentConfig:
        """Parse a Dockerfile/Containerfile-style `Cordonfile`."""
        cfg = cls()
        for line_no, raw_line in enumerate(raw.splitlines(), start=1):
            trimmed = raw_line.strip()
            if not trimmed or trimmed.startswith("#"):
                continue
            parts = trimmed.split(None, 1)
            if len(parts) < 2:
                raise ValueError(f"Line {line_no}: directive '{trimmed}' requires arguments")
            directive, rest = parts[0].upper(), parts[1].strip()
            if directive in ("FROM", "PROFILE"):
                cfg.base_profile = rest.strip("\"'")
            elif directive == "NAME":
                cfg.name = rest.strip("\"'")
            elif directive == "DESCRIPTION":
                cfg.description = rest.strip("\"'")
            elif directive == "WORKDIR":
                cfg.workdir = rest.strip("\"'")
            elif directive == "MOUNT":
                path_val, is_rw = parse_volume_spec(rest)
                target = cfg.writable_mounts if is_rw else cfg.readonly_mounts
                if path_val not in target:
                    target.append(path_val)
            elif directive == "MASK":
                for item in rest.split():
                    cleaned = item.strip("\"'")
                    if cleaned and cleaned not in cfg.masked_binaries:
                        cfg.masked_binaries.append(cleaned)
            elif directive == "MASK_DIR":
                for item in rest.split():
                    cleaned = item.strip("\"'")
                    if cleaned and cleaned not in cfg.masked_dirs:
                        cfg.masked_dirs.append(cleaned)
            elif directive == "ALLOW_DOMAIN":
                for item in rest.split():
                    cleaned = item.strip("\"'")
                    if cleaned and cleaned not in cfg.allowed_domains:
                        cfg.allowed_domains.append(cleaned)
            elif directive == "DENY_DOMAIN":
                for item in rest.split():
                    cleaned = item.strip("\"'")
                    if cleaned and cleaned not in cfg.denied_domains:
                        cfg.denied_domains.append(cleaned)
            elif directive in ("POST_ALLOWED_HOST", "POST_ALLOWED_HOSTS"):
                for item in rest.split():
                    cleaned = item.strip("\"'")
                    if cleaned and cleaned not in cfg.post_allowed_hosts:
                        cfg.post_allowed_hosts.append(cleaned)
            elif directive == "ENV":
                if "=" not in rest:
                    raise ValueError(f"Line {line_no}: ENV requires KEY=VALUE")
                k, v = rest.split("=", 1)
                cfg.env_vars[k.strip()] = v.strip().strip("\"'")
            elif directive == "CMD":
                if rest.startswith("["):
                    cfg.cmd = [str(x) for x in json.loads(rest)]
                else:
                    cfg.cmd = [x.strip("\"'") for x in rest.split()]
            else:
                raise ValueError(f"Line {line_no}: unknown Cordonfile directive '{directive}'")
        return cfg

    def resolve_effective_profile(self) -> CordonProfile:
        """Merge Cordonfile policy overrides onto the base CordonProfile.

        Merges ALLOW_DOMAIN / DENY_DOMAIN / POST_ALLOWED_HOST overrides onto
        the base profile's `allowed_domains` / `denied_domains` /
        `post_allowed_hosts`. The resulting tuples are what
        [`CordonEnvironmentConfig.resolve_effective_policy`] serializes into
        the root-owned L7 policy file (default /run/cordon/policy.json) that
        the running mitmproxy addon enforces.
        """
        base = get_profile(self.base_profile)

        def merge(base_list: tuple[str, ...], extra: list[str]) -> tuple[str, ...]:
            merged: list[str] = [str(item).strip().lower() for item in base_list]
            for item in extra:
                cleaned = str(item).strip().lower()
                if cleaned and cleaned not in merged:
                    merged.append(cleaned)
            return tuple(merged)

        return base.model_copy(
            update={
                "description": self.description or base.description,
                "allowed_domains": merge(base.allowed_domains, self.allowed_domains),
                "denied_domains": merge(base.denied_domains, self.denied_domains),
                "post_allowed_hosts": merge(base.post_allowed_hosts, self.post_allowed_hosts),
            }
        )

    def resolve_effective_policy(self) -> PolicyConfig:
        """Derive the canonical L7 PolicyConfig the launcher serializes for the addon.

        `strict_whitelist` defaults to True (inherited from the base profile);
        env overrides such as CORDON_EXTRA_HOSTS never widen the serialized
        policy without CORDON_ALLOW_INSECURE=1 (enforced at addon startup by
        `cordon.policy_rules.resolve_runtime_policy`, which logs every
        deviation as an audit event).
        """
        profile = self.resolve_effective_profile()
        return PolicyConfig.from_mapping(
            {
                "profile": str(profile.name),
                "network_mode": str(profile.network_mode),
                "strict_whitelist": profile.strict_whitelist,
                "block_doh": True,
                "inspect_body_secrets": True,
                "allow_streamed_bodies": False,
                "allowed_domains": list(profile.allowed_domains),
                "denied_domains": list(profile.denied_domains),
                "post_allowed_hosts": list(profile.post_allowed_hosts),
            }
        )


def parse_volume_spec(spec: str) -> tuple[str, bool]:
    """Parse `-v /host/path[:ro|:rw]` into `(expanded_path, is_rw)`."""
    cleaned = spec.strip().strip("\"'")
    if not cleaned:
        raise ValueError("Empty volume mount specification")
    if cleaned.endswith(":rw"):
        return expand_tilde(cleaned[:-3]), True
    if cleaned.endswith(":ro"):
        return expand_tilde(cleaned[:-3]), False
    return expand_tilde(cleaned), False


def expand_tilde(path_str: str) -> str:
    """Expand leading `~/` to `$HOME/`."""
    trimmed = path_str.strip()
    if trimmed.startswith("~/"):
        home = os.environ.get("HOME", "/root")
        return f"{home.rstrip('/')}/{trimmed[2:]}"
    return trimmed
