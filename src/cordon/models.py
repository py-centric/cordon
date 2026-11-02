"""Pydantic v2 Domain Models & DTOs for Cordon Universal Sandbox Engine.

Governing Spec: ADR-L0-SEC-02
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class WorkloadKind(StrEnum):
    """Supported universal workload isolation profiles."""

    AI_AGENT = "ai-agent"
    UNTRUSTED_CODE = "untrusted-code"
    PACKAGE_BUILD = "package-build"
    NETWORK_AUDIT = "network-audit"
    GUI_DESKTOP = "gui-desktop"
    AIRGAPPED = "airgapped"


class NetworkMode(StrEnum):
    """Network isolation and telemetry enforcement modes."""

    INSPECTED = "inspected"  # ip netns + veth + iptables + mitmproxy L7 + tshark L3/L4
    PASSTHROUGH = "passthrough"  # ip netns + veth + tshark L3/L4 + iptables (no TLS MITM)
    AIRGAPPED = "airgapped"  # --unshare-net loopback-only zero external egress


class FilesystemMode(StrEnum):
    """Workspace VFS bind-mount modes inside Bubblewrap."""

    WORKSPACE_RW = "workspace-rw"  # --ro-bind / / and --bind $REAL_PWD $REAL_PWD
    WORKSPACE_RO = "workspace-ro"  # --ro-bind / / and --ro-bind $REAL_PWD $REAL_PWD
    EPHEMERAL_TMPFS = "ephemeral-tmpfs"  # --ro-bind / / and ephemeral RAM workspace


class CordonProfile(BaseModel):
    """Declarative security & networking policy for a sandboxed workload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: WorkloadKind = Field(..., description="Unique profile identifier.")
    description: str = Field(..., description="Human-readable workload summary.")
    filesystem_mode: FilesystemMode = Field(
        default=FilesystemMode.WORKSPACE_RW,
        description="VFS bind strategy for the active working directory.",
    )
    network_mode: NetworkMode = Field(
        default=NetworkMode.INSPECTED,
        description="Network namespace and L3/L4/L7 inspection topology.",
    )
    protect_git_dir: bool = Field(
        default=True,
        description="Mount $REAL_PWD/.git read-only to prevent LotL repo corruption (EC-01).",
    )
    isolate_home_tmpfs: bool = Field(
        default=False,
        description="Overlay ephemeral tmpfs on $REAL_HOME so general untrusted code sees an empty home.",
    )
    enable_build_scratch: bool = Field(
        default=False,
        description="Redirect TMPDIR into project-local scratch for cargo/pip/node-gyp (EC-02).",
    )
    pass_display_sockets: bool = Field(
        default=False,
        description="Pass Wayland/X11 sockets into sandbox for GUI desktop apps.",
    )
    blacklisted_binaries: tuple[str, ...] = Field(
        default=(
            "/usr/bin/rm",
            "/usr/bin/shred",
            "/usr/bin/curl",
            "/usr/bin/wget",
            "/usr/bin/nc",
            "/usr/bin/netcat",
            "/usr/bin/ncat",
            "/usr/bin/socat",
            "/usr/bin/ssh",
            "/usr/bin/scp",
            "/usr/bin/sftp",
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/pkexec",
        ),
        description="Executables denied via AppArmor kernel MAC and/or /dev/null bind mounts (FR-3.1).",
    )
    protected_credential_paths: tuple[str, ...] = Field(
        default=(
            "~/.ssh",
            "~/.gnupg",
            "~/.aws",
            "~/.config/gcloud",
            "~/.kube",
            "~/.mitmproxy/mitmproxy-ca.pem",
            "~/.netrc",
            "~/.docker/config.json",
            "~/.pypirc",
            "~/.npmrc",
        ),
        description="Host credential directories denied rwlkmx at the kernel LSM layer (FR-3.3).",
    )
    allowed_domains: tuple[str, ...] = Field(
        default=(),
        description="Domains allowed by the mitmproxy L7 policy addon when strict_whitelist=True.",
    )
    denied_domains: tuple[str, ...] = Field(
        default=(),
        description="Domains always blocked by the L7 policy addon, enforced BEFORE the allow-list.",
    )
    post_allowed_hosts: tuple[str, ...] = Field(
        default=(),
        description="Hosts allowed to receive mutating HTTP methods (POST/PUT/PATCH/DELETE).",
    )
    strict_whitelist: bool = Field(
        default=True,
        description="Block any outbound HTTP/HTTPS request to domains not in allowed_domains.",
    )
    pinned_passthrough_hosts: tuple[str, ...] = Field(
        default=(),
        description="Regex patterns passed to mitmproxy --ignore-hosts for pinned binaries (EC-04).",
    )


class SandboxLaunchPlan(BaseModel):
    """Compiled 5-gate execution plan produced by Cordon for a target command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: WorkloadKind
    network_mode: NetworkMode
    filesystem_mode: FilesystemMode
    real_pwd: str
    real_home: str
    netns_name: str
    bwrap_argv: tuple[str, ...]
    full_argv: tuple[str, ...]
    env_exports: dict[str, str]
    gates_applied: tuple[str, ...]


class PolicyDecision(BaseModel):
    """Result of evaluating an outbound HTTP/HTTPS request against a Cordon L7 profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    status_code: int = Field(default=200)
    reason: str
    profile: WorkloadKind
    host: str
    method: str
    url: str
    rule_id: str = Field(default="DEFAULT_ALLOW", description="Canonical rule identifier.")
    rule_version: int = Field(default=2, description="Canonical L7 rule table version.")
    secret_fingerprint: str | None = Field(
        default=None,
        description="sha256 hex[:16] of the matched secret span (NEVER the raw payload).",
    )
    matched_secret_pattern: str | None = Field(
        default=None,
        description="Deprecated alias of rule_id for secret matches; kept for API compat.",
    )


class AuditEvent(BaseModel):
    """Canonical JSONL telemetry event (schema_version 1). NEVER carries raw payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1)
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(tz=UTC).isoformat(),
    )
    plane: str = Field(default="mitmproxy", description="mitmproxy | netns | apparmor | bwrap | tshark")
    gate: int = Field(default=4, description="Canonical gate: 1 netns, 2 AppArmor, 3 bwrap, 4 iptables/mitmproxy, 5 tshark.")
    severity: str = Field(..., description="INFO | WARNING | CRITICAL")
    verdict: str = Field(..., description="ALLOW | BLOCK | AUDIT")
    profile: str
    session_id: str = Field(default="unset")
    host: str = Field(default="")
    method: str = Field(default="")
    url: str = Field(default="")
    rule_id: str = Field(..., description="Canonical rule identifier that produced the verdict.")
    rule_version: int = Field(default=2)
    reason: str
    bytes: int = Field(default=0, description="Request/response body byte count (never raw payloads).")
    secret_fingerprint: str | None = Field(default=None)
    status_code: int | None = Field(default=None)


class DoctorCheck(BaseModel):
    """Single environment readiness check result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    requirement: str
    passed: bool
    detail: str


class DoctorReport(BaseModel):
    """Complete system readiness report for Cordon."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    healthy: bool
    kernel_release: str
    checks: tuple[DoctorCheck, ...]
