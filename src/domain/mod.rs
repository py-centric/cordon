//! Core type-safe domain models, validated newtypes, and enums for Cordon.

mod microvm;
mod microvm_exec;
mod microvm_plan;
mod telemetry;
#[cfg(test)]
mod tests;

pub use self::microvm::{
    IsolationBackend, SnapshotName, VmDiskMode, VmImageKind, VmImagePath, VmRateLimits,
};
pub use self::microvm_exec::{
    FirecrackerApiCall, GuestExecEnvelope, GuestNetConfig, MicroVmCompileContext,
    MicroVmExecutionPlan, TapSlot,
};
pub use self::microvm_plan::{MicroVmSpec, RawMicroVmSpec};
pub use self::telemetry::{
    AUDIT_DETAIL_DASHBOARD_KEYS, AUDIT_EVENT_DASHBOARD_KEYS, AuditEvent, DoctorCheck, DoctorReport,
    PolicyDecision, audit_json,
};

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::error::CordonError;

/// Validated canonical physical filesystem path (FR-1.2 realpath invariant).
///
/// Guarantees at the type level that all symlinks have been resolved where the path
/// exists on disk, preventing symlink-traversal escapes outside the intended mount.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Resolves any filesystem path into its canonical physical path.
    pub fn resolve(raw: impl AsRef<Path>) -> Result<Self, CordonError> {
        let path_ref = raw.as_ref();
        let raw_str = path_ref.to_string_lossy().into_owned();
        if raw_str.trim().is_empty() {
            return Err(CordonError::PathResolutionFailed {
                path: raw_str,
                reason: "Path cannot be empty".to_owned(),
            });
        }

        let resolved: PathBuf = if let Ok(canon) = std::fs::canonicalize(path_ref) {
            canon
        } else if path_ref.is_absolute() {
            Self::normalize_lexical(path_ref)
        } else {
            let cwd = std::env::current_dir().map_err(|err| CordonError::PathResolutionFailed {
                path: raw_str.clone(),
                reason: err.to_string(),
            })?;
            Self::normalize_lexical(&cwd.join(path_ref))
        };

        Ok(Self(resolved.to_string_lossy().into_owned()))
    }

    /// Creates a `CanonicalPath` from an already-verified absolute system path constant.
    pub fn from_trusted_static(path: &'static str) -> Self {
        Self(path.to_owned())
    }

    /// Returns the string slice representation of the canonical path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn normalize_lexical(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    let _ = out.pop();
                }
                std::path::Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        out
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monetary value represented strictly in 64-bit integer ZAR minor units (cents, never float).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ZarCents(pub i64);

/// Supported workload classifications for universal software sandboxing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadKind {
    /// Semi-trusted local AI CLI coding agents (`opencode`, `antigravity`, `claude`).
    AiAgent,
    /// Arbitrary untrusted scripts, CTF binaries, or third-party executables.
    UntrustedCode,
    /// Supply-chain package installation (`npm`, `pip`, `cargo`, `poetry`).
    PackageBuild,
    /// Closed-source binary network telemetry and L7 TLS inspection.
    NetworkAudit,
    /// Desktop GUI / Wayland application with isolated IPC and GPU passthrough.
    GuiDesktop,
    /// Strictly offline airgapped execution with loopback-only networking.
    Airgapped,
}

/// Outbound network isolation and telemetry mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Route traffic through `ip netns`, `tshark` L3/L4 tap, and `mitmproxy` L7 TLS inspection.
    Inspected,
    /// Enforce strict domain allowlist in `mitmproxy` L7 policy engine.
    AllowlistOnly,
    /// Direct host network namespace (no L7 MITM).
    Direct,
    /// Complete network namespace isolation (`--unshare-net`, loopback only).
    None,
}

/// Filesystem mount isolation mode inside Bubblewrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemMode {
    /// Root (`/`) read-only, active workspace (`$PWD`) read-write, ephemeral `/tmp`.
    WorkspaceRw,
    /// Root (`/`) read-only, active workspace (`$PWD`) read-only, ephemeral `/tmp`.
    WorkspaceRo,
    /// Strict read-only root and workspace with minimal ephemeral `/tmp`.
    StrictRo,
}

/// Policy decision outcome across L7 `mitmproxy` or AppArmor MAC gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    /// Request or execution permitted.
    Allow,
    /// Request or execution denied.
    Block,
    /// Request permitted with elevated audit alert.
    Audit,
}

/// Severity classification for telemetry audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Routine operational event.
    Info,
    /// Policy block or suspicious living-off-the-land probe.
    Warning,
    /// High-severity credential exfiltration or sandbox escape attempt.
    Critical,
}

/// Kernel or userspace plane emitting a telemetry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementPlane {
    /// Bubblewrap VFS/PID/IPC namespace plane.
    Bwrap,
    /// AppArmor 4.0 Mandatory Access Control LSM plane.
    Apparmor,
    /// Linux network namespace and iptables NAT/filter plane.
    Netns,
    /// Layer 7 `mitmproxy` TLS inspection and policy engine.
    Mitmproxy,
    /// Layer 3/4 `tshark` packet capture tap.
    Tshark,
}

/// Complete, immutable sandbox and network policy profile for any workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CordonProfile {
    /// Unique profile slug (`^[a-z0-9][a-z0-9_-]{1,62}$`).
    pub name: String,
    /// High-level workload category.
    pub kind: WorkloadKind,
    /// Human-readable summary of the profile's containment posture.
    pub description: String,
    /// Filesystem binding mode inside Bubblewrap.
    pub filesystem_mode: FilesystemMode,
    /// Network routing and L7 inspection mode.
    pub network_mode: NetworkMode,
    /// Linux network namespace identifier.
    pub netns_name: String,
    /// Host-side veth IPv4 address.
    pub host_veth_ip: String,
    /// Sandbox-side veth IPv4 address.
    pub sandbox_veth_ip: String,
    /// Dedicated point-to-point subnet CIDR.
    pub subnet_cidr: String,
    /// Local port where `mitmproxy` listens for transparently redirected TCP 80/443 flows.
    pub mitm_port: u16,
    /// Host binaries denied execution (`deny ... x`) by AppArmor and/or `/dev/null` masking.
    pub denied_binaries: Vec<String>,
    /// Sensitive user credential paths denied `rwlkmx` by AppArmor.
    pub protected_paths: Vec<String>,
    /// Additional host paths mounted read-only inside the sandbox.
    pub extra_ro_binds: Vec<String>,
    /// Additional host paths mounted read-write inside the sandbox.
    pub extra_rw_binds: Vec<String>,
    /// Allowed outbound L7 domains when `network_mode` is `AllowlistOnly` or `Inspected`.
    pub allowed_domains: Vec<String>,
    /// Hosts permitted to receive mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) per FR-5.4.
    pub post_allowed_hosts: Vec<String>,
    /// Explicitly blocked L7 domains.
    pub denied_domains: Vec<String>,
    /// Mount `$REAL_PWD/.git` read-only inside RW workspaces to prevent LotL repo corruption (EC-01).
    pub protect_git_dir: bool,
    /// Overlay ephemeral tmpfs on `$HOME` so untrusted code sees an empty home directory.
    pub isolate_home_tmpfs: bool,
    /// Redirect `TMPDIR` into project-local scratch for `cargo`/`pip`/`npm` builds (EC-02).
    pub enable_build_scratch: bool,
    /// Block outbound DNS-over-HTTPS (DoH) endpoints to prevent DNS tunnel bypass.
    pub block_doh: bool,
    /// Block UDP 443 (QUIC/HTTP3) to force deterministic TCP 443 TLS fallback (RFC 9114).
    pub block_quic_udp_443: bool,
    /// Inspect HTTP/HTTPS request bodies for leaked API keys, tokens, and private keys.
    pub inspect_body_secrets: bool,
    /// Permit Wayland display socket passthrough (`GUI_DESKTOP` profile).
    pub allow_gui_wayland: bool,
    /// Permit X11 socket passthrough (disabled by default to prevent X11 keylogging).
    pub allow_x11: bool,
    /// Permit GPU `/dev/dri` device node passthrough.
    pub allow_gpu_dri: bool,
    /// Ephemeral `/tmp` tmpfs size in megabytes.
    pub tmpfs_size_mb: u32,
    /// Enforce `--unshare-pid` and isolated `/proc` mount.
    pub unshare_pid: bool,
    /// Enforce `--unshare-ipc` namespace isolation.
    pub unshare_ipc: bool,
    /// Enforce `--die-with-parent` lifecycle coupling (`PR_SET_PDEATHSIG`).
    pub die_with_parent: bool,
    /// Combined system + mitmproxy CA bundle path on the host.
    pub ca_bundle_source: String,
}

/// Deterministic, auditable 5-gate execution plan compiled from a [`CordonProfile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxLaunchPlan {
    /// Source profile name.
    pub profile_name: String,
    /// Workload classification.
    pub workload_kind: WorkloadKind,
    /// Verified canonical physical workspace path (`realpath`).
    pub canonical_workspace: CanonicalPath,
    /// Bubblewrap (`bwrap`) argument vector.
    pub bwrap_argv: Vec<String>,
    /// Network namespace wrapper (`ip netns exec`) argument vector, if applicable.
    pub netns_exec_argv: Vec<String>,
    /// Complete 5-gate command vector executed on the host.
    pub full_argv: Vec<String>,
    /// Host binaries masked with `/dev/null` inside the mount namespace.
    pub masked_binaries: Vec<String>,
    /// Environment variables injected into the sandboxed process.
    pub env_overrides: BTreeMap<String, String>,
    /// Ordered list of isolation gates active for this launch plan.
    pub gates_applied: Vec<String>,
    /// Network mode active for this launch plan.
    pub network_mode: NetworkMode,
    /// Filesystem mode active for this launch plan.
    pub filesystem_mode: FilesystemMode,
    /// Gate 3.5 MicroVM plan executed inside Gates 1-3 (`None` for native Bubblewrap launches;
    /// omitted from JSON so native plans serialize unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub microvm: Option<MicroVmExecutionPlan>,
}
