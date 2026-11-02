"""Built-In Universal Workload Profiles for Cordon.

Extends ADR-L0-SEC-02 beyond AI CLI coding agents to support running any
untrusted software, script, package build, network audit, GUI app, or airgapped binary.
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

from cordon.models import CordonProfile, FilesystemMode, NetworkMode, WorkloadKind

DEFAULT_LLM_HOSTS: tuple[str, ...] = (
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "api.deepinfra.com",
    "api.fireworks.ai",
    "api.together.xyz",
    "generativelanguage.googleapis.com",
)

DEFAULT_REGISTRY_HOSTS: tuple[str, ...] = (
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "registry.npmjs.org",
    "proxy.golang.org",
    "sum.golang.org",
    "storage.googleapis.com",
    "pub.dev",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "example.com",
)

BUILTIN_PROFILES: dict[WorkloadKind, CordonProfile] = {
    WorkloadKind.AI_AGENT: CordonProfile(
        name=WorkloadKind.AI_AGENT,
        description=(
            "Local AI CLI coding agents (opencode, antigravity, pi, claude) with "
            "read-write $REAL_PWD, read-only .git guard, credential MAC protection, "
            "and full L7 LLM prompt/webhook inspection."
        ),
        filesystem_mode=FilesystemMode.WORKSPACE_RW,
        network_mode=NetworkMode.INSPECTED,
        protect_git_dir=True,
        isolate_home_tmpfs=False,
        enable_build_scratch=False,
        allowed_domains=DEFAULT_LLM_HOSTS + DEFAULT_REGISTRY_HOSTS,
        post_allowed_hosts=DEFAULT_LLM_HOSTS,
        strict_whitelist=True,
    ),
    WorkloadKind.UNTRUSTED_CODE: CordonProfile(
        name=WorkloadKind.UNTRUSTED_CODE,
        description=(
            "General-purpose sandbox for untrusted scripts, third-party binaries, "
            "or downloaded code. Mounts workspace read-only, masks $HOME with tmpfs, "
            "blocks destructive/network binaries, and inspects all egress."
        ),
        filesystem_mode=FilesystemMode.WORKSPACE_RO,
        network_mode=NetworkMode.INSPECTED,
        protect_git_dir=True,
        isolate_home_tmpfs=True,
        enable_build_scratch=False,
        allowed_domains=("example.com",),
        post_allowed_hosts=(),
        strict_whitelist=True,
    ),
    WorkloadKind.PACKAGE_BUILD: CordonProfile(
        name=WorkloadKind.PACKAGE_BUILD,
        description=(
            "Supply-chain safe package installation and compilation (npm install, "
            "pip install, cargo build, go build). Enables project-local TMPDIR scratch "
            "(EC-02) and restricts network strictly to GET/HEAD from package registries."
        ),
        filesystem_mode=FilesystemMode.WORKSPACE_RW,
        network_mode=NetworkMode.INSPECTED,
        protect_git_dir=True,
        isolate_home_tmpfs=False,
        enable_build_scratch=True,
        allowed_domains=DEFAULT_REGISTRY_HOSTS,
        post_allowed_hosts=(),
        strict_whitelist=True,
    ),
    WorkloadKind.NETWORK_AUDIT: CordonProfile(
        name=WorkloadKind.NETWORK_AUDIT,
        description=(
            "Reverse-engineering and network telemetry mode for any binary or CLI. "
            "Allows curl/wget inside the sandbox while logging 100% of L3/L4 packets "
            "in tshark and L7 payloads in mitmproxy (strict_whitelist=False, POST gated)."
        ),
        filesystem_mode=FilesystemMode.WORKSPACE_RO,
        network_mode=NetworkMode.INSPECTED,
        protect_git_dir=True,
        isolate_home_tmpfs=False,
        enable_build_scratch=False,
        blacklisted_binaries=(
            "/usr/bin/rm",
            "/usr/bin/shred",
            "/usr/bin/ssh",
            "/usr/bin/scp",
            "/usr/bin/sftp",
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/pkexec",
        ),
        allowed_domains=DEFAULT_LLM_HOSTS + DEFAULT_REGISTRY_HOSTS,
        post_allowed_hosts=DEFAULT_LLM_HOSTS,
        strict_whitelist=False,
    ),
    WorkloadKind.GUI_DESKTOP: CordonProfile(
        name=WorkloadKind.GUI_DESKTOP,
        description=(
            "Sandboxed execution for desktop GUI, Electron, or Playwright browser "
            "applications with Wayland/X11 display pass-through, credential isolation, "
            "and full L3/L4/L7 traffic inspection."
        ),
        filesystem_mode=FilesystemMode.WORKSPACE_RW,
        network_mode=NetworkMode.INSPECTED,
        protect_git_dir=True,
        isolate_home_tmpfs=False,
        enable_build_scratch=False,
        pass_display_sockets=True,
        allowed_domains=DEFAULT_LLM_HOSTS + DEFAULT_REGISTRY_HOSTS,
        post_allowed_hosts=DEFAULT_LLM_HOSTS,
        strict_whitelist=False,
    ),
    WorkloadKind.AIRGAPPED: CordonProfile(
        name=WorkloadKind.AIRGAPPED,
        description=(
            "Maximum containment mode (--unshare-net loopback-only + ephemeral tmpfs "
            "workspace + masked $HOME) for running high-risk or unknown executables "
            "with zero network egress and zero host disk mutation."
        ),
        filesystem_mode=FilesystemMode.EPHEMERAL_TMPFS,
        network_mode=NetworkMode.AIRGAPPED,
        protect_git_dir=True,
        isolate_home_tmpfs=True,
        enable_build_scratch=False,
        allowed_domains=(),
        post_allowed_hosts=(),
        strict_whitelist=True,
    ),
}


def get_profile(kind: WorkloadKind | str) -> CordonProfile:
    """Returns the canonical CordonProfile for the requested workload kind."""
    resolved = WorkloadKind(kind) if isinstance(kind, str) else kind
    return BUILTIN_PROFILES[resolved]
