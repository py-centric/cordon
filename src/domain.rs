//! Core type-safe domain models, validated newtypes, and enums for Cordon.

use std::collections::BTreeMap;
use std::fmt;
use std::num::{NonZeroU8, NonZeroU32};
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

    fn normalize_lexical(path: &Path) -> PathBuf {
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

/// Layer 7 HTTP/HTTPS inspection verdict produced by the Cordon policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Final policy verdict (`ALLOW`, `BLOCK`, `AUDIT`).
    pub verdict: Verdict,
    /// HTTP status code returned to the client (`200` on allow, `403` on block).
    pub status_code: u16,
    /// Human-readable explanation of the policy match.
    pub reason: String,
    /// Identifier of the rule that triggered this decision.
    pub matched_rule: String,
    /// Target URL evaluated.
    pub url: String,
    /// HTTP method evaluated.
    pub method: String,
    /// Policy evaluation latency in microseconds.
    pub evaluation_latency_us: u64,
}

/// Structured telemetry event emitted across L3/L4, L7, AppArmor, or Bubblewrap planes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event UUID.
    pub event_id: String,
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// Enforcement plane that generated the event.
    pub plane: EnforcementPlane,
    /// Severity tier (`INFO`, `WARNING`, `CRITICAL`).
    pub severity: Severity,
    /// Policy verdict (`ALLOW`, `BLOCK`, `AUDIT`).
    pub verdict: Verdict,
    /// Active profile name.
    pub profile: String,
    /// Concise summary of the event.
    pub subject: String,
    /// Structured metadata key-value pairs.
    pub details: BTreeMap<String, String>,
}

/// Canonical serialized [`AuditEvent`] JSON field names consumed by the web dashboard.
///
/// This module is the single source of truth shared by `src/dashboard.rs` (which injects
/// these names into the generated `/app.js` telemetry table code) and the serde contract
/// tests in `tests/cordon_api_and_cli.rs`, so the dashboard JavaScript and the wire schema
/// cannot drift apart.
pub mod audit_json {
    /// `AuditEvent` field holding the RFC 3339 UTC timestamp.
    pub const TIMESTAMP: &str = "timestamp";
    /// `AuditEvent` field holding the active profile name.
    pub const PROFILE: &str = "profile";
    /// `AuditEvent` field holding the policy verdict.
    pub const VERDICT: &str = "verdict";
    /// `AuditEvent` field holding the concise event summary.
    pub const SUBJECT: &str = "subject";
    /// `AuditEvent` field holding the structured metadata map.
    pub const DETAILS: &str = "details";
    /// `details` map key holding the evaluated URL (dashboard "Target" column).
    pub const DETAIL_URL: &str = "url";
    /// `details` map key holding the matched rule (dashboard "Rule / Detail" column).
    pub const DETAIL_RULE: &str = "rule";
}

/// Top-level [`AuditEvent`] JSON keys dereferenced by the dashboard telemetry table.
///
/// The rendered dashboard JavaScript must only read these keys (through the injected
/// `EVK` map); the contract test asserts every entry exists in the serialized event.
pub const AUDIT_EVENT_DASHBOARD_KEYS: &[&str] = &[
    audit_json::TIMESTAMP,
    audit_json::PROFILE,
    audit_json::VERDICT,
    audit_json::SUBJECT,
    audit_json::DETAILS,
];

/// `details` map keys the dashboard derives its Target and Rule columns from.
pub const AUDIT_DETAIL_DASHBOARD_KEYS: &[&str] = &[audit_json::DETAIL_URL, audit_json::DETAIL_RULE];

/// Single diagnostic check result from `cordon doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Check identifier.
    pub name: String,
    /// Whether the dependency or kernel feature is available.
    pub passed: bool,
    ///Whether this check is required for full 5-gate enforcement.
    pub required: bool,
    /// Diagnostic detail or binary path.
    pub detail: String,
}

/// Aggregated `cordon doctor` diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Overall readiness flag (true if all required checks pass).
    pub healthy: bool,
    /// Kernel version and OS platform summary.
    pub platform_summary: String,
    /// Individual dependency and kernel checks.
    pub checks: Vec<DoctorCheck>,
}

// ---------------------------------------------------------------------------------------------
// Gate 3.5: optional KVM MicroVM isolation plane (see docs/design/microvm-isolation.md).
// ---------------------------------------------------------------------------------------------

/// Isolation backend executing the workload inside Gates 1-3.
///
/// Wire names are explicit (not derived) so the JSON/TOML/CLI vocabulary is stable and shared
/// with the Python reference stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, ValueEnum)]
pub enum IsolationBackend {
    /// Native Bubblewrap process isolation on the host kernel (no MicroVM).
    #[default]
    #[serde(rename = "native-bwrap")]
    #[value(name = "native-bwrap")]
    NativeBwrap,
    /// QEMU `-M microvm` with a virtiofsd-exported live workspace.
    #[serde(rename = "qemu-microvm")]
    #[value(name = "qemu-microvm")]
    QemuMicrovm,
    /// Firecracker sealed block-device MicroVM with optional snapshot restore.
    #[serde(rename = "firecracker")]
    #[value(name = "firecracker")]
    Firecracker,
    /// libkrun-based MicroVM (reserved: accepted by the schema, rejected by the compiler until a
    /// launcher is selected).
    #[serde(rename = "krun")]
    #[value(name = "krun")]
    Krun,
}

impl IsolationBackend {
    /// Stable wire name (`native-bwrap`, `qemu-microvm`, `firecracker`, `krun`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeBwrap => "native-bwrap",
            Self::QemuMicrovm => "qemu-microvm",
            Self::Firecracker => "firecracker",
            Self::Krun => "krun",
        }
    }

    /// Returns `true` for every backend that boots a guest kernel through `/dev/kvm`.
    pub const fn is_microvm(self) -> bool {
        !matches!(self, Self::NativeBwrap)
    }

    /// Disk modes supported by this backend (VM-INV-1). Empty for `native-bwrap`.
    pub const fn supported_disk_modes(self) -> &'static [VmDiskMode] {
        match self {
            Self::NativeBwrap => &[],
            Self::QemuMicrovm => &[
                VmDiskMode::VirtioFsLive,
                VmDiskMode::EphemeralTmpfs,
                VmDiskMode::BtrfsCowOverlay,
            ],
            Self::Firecracker => &[
                VmDiskMode::EphemeralTmpfs,
                VmDiskMode::BtrfsCowOverlay,
                VmDiskMode::SnapshotRestore,
            ],
            Self::Krun => &[VmDiskMode::VirtioFsLive],
        }
    }

    /// Default disk mode applied when a spec omits `disk_mode`.
    pub const fn default_disk_mode(self) -> Option<VmDiskMode> {
        match self {
            Self::NativeBwrap => None,
            Self::QemuMicrovm | Self::Krun => Some(VmDiskMode::VirtioFsLive),
            Self::Firecracker => Some(VmDiskMode::EphemeralTmpfs),
        }
    }
}

impl fmt::Display for IsolationBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Guest root/workspace storage strategy for a MicroVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum VmDiskMode {
    /// Live host view exported through virtio-fs (QEMU/krun only; Firecracker has no virtio-fs).
    VirtioFsLive,
    /// Read-only base image with a guest RAM (tmpfs) overlay, discarded on exit.
    EphemeralTmpfs,
    /// Instant Btrfs reflink clone of an ext4 base image, attached read-write, deleted on exit.
    BtrfsCowOverlay,
    /// Warm memory + device state restore from a named snapshot (Firecracker only).
    SnapshotRestore,
}

impl VmDiskMode {
    /// Stable wire name (`virtio-fs-live`, `ephemeral-tmpfs`, `btrfs-cow-overlay`, `snapshot-restore`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VirtioFsLive => "virtio-fs-live",
            Self::EphemeralTmpfs => "ephemeral-tmpfs",
            Self::BtrfsCowOverlay => "btrfs-cow-overlay",
            Self::SnapshotRestore => "snapshot-restore",
        }
    }

    /// Returns `true` when the guest root is a block device (every mode except virtio-fs).
    pub const fn is_block(self) -> bool {
        !matches!(self, Self::VirtioFsLive)
    }
}

impl fmt::Display for VmDiskMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deterministic per-VM I/O rate limits. Units are explicit in the field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmRateLimits {
    /// Block device operations per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_iops: Option<NonZeroU32>,
    /// Block device bandwidth in MiB per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_bandwidth_mib_s: Option<NonZeroU32>,
    /// Network bandwidth in Mbit per second (applied to RX and TX independently).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_bandwidth_mbit_s: Option<NonZeroU32>,
}

impl VmRateLimits {
    /// Returns `true` when any disk limit is configured.
    pub const fn has_disk_limits(&self) -> bool {
        self.disk_iops.is_some() || self.disk_bandwidth_mib_s.is_some()
    }
}

/// Kind of MicroVM image, which selects the permitted directory roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmImageKind {
    /// Guest kernel (`vmlinux` / `bzImage`).
    Kernel,
    /// Guest root filesystem image (erofs / ext4).
    Rootfs,
}

impl VmImageKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Kernel => "kernel_image",
            Self::Rootfs => "rootfs_image",
        }
    }

    /// System-wide directory roots MicroVM images of this kind must reside under.
    ///
    /// An allowlist (rather than a denylist) prevents attaching arbitrary user-readable files
    /// (for example private keys) to the guest as raw block devices.
    pub const fn system_roots(self) -> &'static [&'static str] {
        match self {
            Self::Kernel => &[
                "/boot",
                "/var/lib/cordon/kernels",
                "/usr/lib/cordon/kernels",
                "/usr/share/cordon/kernels",
            ],
            Self::Rootfs => &[
                "/var/lib/cordon/images",
                "/usr/lib/cordon/images",
                "/usr/share/cordon/images",
            ],
        }
    }

    /// Per-user directory root (relative to the canonical `$HOME`).
    pub const fn user_root(self) -> &'static str {
        match self {
            Self::Kernel => ".local/share/cordon/kernels",
            Self::Rootfs => ".local/share/cordon/images",
        }
    }
}

/// Validated MicroVM kernel or rootfs image path (VM-INV-2).
///
/// Guarantees: absolute, lexically normalized, free of `..`, located under an allowlisted image
/// root, contains no symlink in any existing component, and is a regular file when it exists.
/// Existence itself is re-verified by the live launcher (images may live on the execution host
/// rather than the compiling host).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VmImagePath(String);

impl VmImagePath {
    /// Validates an image path against the allowlisted roots for `kind`.
    pub fn new(raw: &str, kind: VmImageKind) -> Result<Self, CordonError> {
        let home = std::env::var("HOME").ok();
        Self::new_with_home(raw, kind, home.as_deref())
    }

    /// [`Self::new`] with an explicit `$HOME` (testable seam).
    pub fn new_with_home(
        raw: &str,
        kind: VmImageKind,
        home: Option<&str>,
    ) -> Result<Self, CordonError> {
        let unsafe_image = |reason: &str| CordonError::UnsafeMicroVmImage {
            path: raw.to_owned(),
            reason: format!("{}: {reason}", kind.label()),
        };
        let trimmed = raw.trim();
        let path = Path::new(trimmed);
        if trimmed.is_empty() || !path.is_absolute() {
            return Err(unsafe_image("path must be absolute"));
        }
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(unsafe_image("path must not contain '..'"));
        }
        let lexical = CanonicalPath::normalize_lexical(path);

        let mut roots: Vec<PathBuf> = kind.system_roots().iter().map(PathBuf::from).collect();
        if let Some(home) = home.filter(|h| !h.trim().is_empty()) {
            let home_canon = std::fs::canonicalize(home).unwrap_or_else(|_| PathBuf::from(home));
            roots.push(home_canon.join(kind.user_root()));
        }
        if !roots
            .iter()
            .any(|root| lexical.starts_with(root) && lexical != *root)
        {
            return Err(unsafe_image(
                "path is outside the allowlisted MicroVM image directories",
            ));
        }

        // Symlink check: canonicalizing the longest existing ancestor must not change it.
        let mut existing = lexical.as_path();
        while std::fs::symlink_metadata(existing).is_err() {
            match existing.parent() {
                Some(parent) => existing = parent,
                None => break,
            }
        }
        if let Ok(canon) = std::fs::canonicalize(existing)
            && canon != existing
        {
            return Err(unsafe_image("path traverses a symbolic link"));
        }
        if let Ok(meta) = std::fs::symlink_metadata(&lexical)
            && !meta.file_type().is_file()
        {
            return Err(unsafe_image("path must be a regular file"));
        }

        Ok(Self(lexical.to_string_lossy().into_owned()))
    }

    /// Returns the validated path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VmImagePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated snapshot slug (`^[a-z0-9][a-z0-9_-]{1,62}$`), resolved by the launcher to
/// `/var/lib/cordon/snapshots/<name>/`. Users never supply raw memory-dump paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SnapshotName(String);

impl SnapshotName {
    /// Root directory holding named Firecracker snapshots.
    pub const ROOT: &'static str = "/var/lib/cordon/snapshots";

    /// Validates a snapshot slug.
    pub fn new(raw: &str) -> Result<Self, CordonError> {
        let bytes = raw.as_bytes();
        let valid_len = (2..=63).contains(&bytes.len());
        let valid_first = bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let valid_rest = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_');
        if valid_len && valid_first && valid_rest {
            Ok(Self(raw.to_owned()))
        } else {
            Err(CordonError::InvalidInput(format!(
                "Invalid snapshot name '{raw}': must match ^[a-z0-9][a-z0-9_-]{{1,62}}$"
            )))
        }
    }

    /// Returns the slug.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the snapshot directory (`/var/lib/cordon/snapshots/<name>`).
    pub fn directory(&self) -> String {
        format!("{}/{}", Self::ROOT, self.0)
    }
}

impl TryFrom<String> for SnapshotName {
    type Error = CordonError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<SnapshotName> for String {
    fn from(value: SnapshotName) -> Self {
        value.0
    }
}

/// Unvalidated wire representation of a MicroVM spec (`[vm]` table, API `vm` object).
///
/// Convert with [`MicroVmSpec::try_from`]; the validated type is the only one the compiler accepts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMicroVmSpec {
    /// Isolation backend (`native-bwrap` disables the MicroVM plane).
    #[serde(default)]
    pub backend: IsolationBackend,
    /// Guest vCPU count (1..=32, default 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u8>,
    /// Guest memory in MiB (128..=65536, default 1024).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,
    /// Disk mode (defaults per backend).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mode: Option<VmDiskMode>,
    /// Guest kernel image path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_image: Option<String>,
    /// Guest root filesystem image path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_image: Option<String>,
    /// Named snapshot (required for, and only valid with, `snapshot-restore`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// Optional I/O rate limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<VmRateLimits>,
}

/// Validated MicroVM specification (Gate 3.5).
///
/// Fields are private and the only constructor is [`TryFrom<RawMicroVmSpec>`] (also used by
/// serde), so an invalid backend / disk-mode / image combination cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawMicroVmSpec", into = "RawMicroVmSpec")]
pub struct MicroVmSpec {
    backend: IsolationBackend,
    vcpus: NonZeroU8,
    memory_mib: NonZeroU32,
    disk_mode: VmDiskMode,
    kernel_image: Option<VmImagePath>,
    rootfs_image: Option<VmImagePath>,
    snapshot: Option<SnapshotName>,
    rate_limits: Option<VmRateLimits>,
}

impl MicroVmSpec {
    /// Maximum guest vCPUs (Firecracker limit).
    pub const MAX_VCPUS: u8 = 32;
    /// Minimum guest memory in MiB.
    pub const MIN_MEMORY_MIB: u32 = 128;
    /// Maximum guest memory in MiB.
    pub const MAX_MEMORY_MIB: u32 = 65_536;
    /// Default guest vCPUs.
    pub const DEFAULT_VCPUS: u8 = 2;
    /// Default guest memory in MiB.
    pub const DEFAULT_MEMORY_MIB: u32 = 1024;

    /// Validates a raw spec with an explicit `$HOME` (testable seam for image-root resolution).
    pub fn from_raw_with_home(
        raw: &RawMicroVmSpec,
        home: Option<&str>,
    ) -> Result<Self, CordonError> {
        let backend = raw.backend;
        let Some(default_mode) = backend.default_disk_mode() else {
            return Err(CordonError::InvalidInput(
                "MicroVM spec requires a MicroVM backend (qemu-microvm, firecracker, krun); \
                 native-bwrap means no [vm] section"
                    .to_owned(),
            ));
        };
        let disk_mode = raw.disk_mode.unwrap_or(default_mode);
        if !backend.supported_disk_modes().contains(&disk_mode) {
            return Err(CordonError::IncompatibleVmDiskMode {
                backend: backend.as_str().to_owned(),
                disk_mode: disk_mode.as_str().to_owned(),
            });
        }

        let vcpus_raw = raw.vcpus.unwrap_or(Self::DEFAULT_VCPUS);
        let vcpus = NonZeroU8::new(vcpus_raw)
            .filter(|v| v.get() <= Self::MAX_VCPUS)
            .ok_or_else(|| {
                CordonError::InvalidInput(format!(
                    "vcpus must be between 1 and {}, got {vcpus_raw}",
                    Self::MAX_VCPUS
                ))
            })?;
        let memory_raw = raw.memory_mib.unwrap_or(Self::DEFAULT_MEMORY_MIB);
        let memory_mib = NonZeroU32::new(memory_raw)
            .filter(|m| (Self::MIN_MEMORY_MIB..=Self::MAX_MEMORY_MIB).contains(&m.get()))
            .ok_or_else(|| {
                CordonError::InvalidInput(format!(
                    "memory_mib must be between {} and {}, got {memory_raw}",
                    Self::MIN_MEMORY_MIB,
                    Self::MAX_MEMORY_MIB
                ))
            })?;

        let kernel_image = raw
            .kernel_image
            .as_deref()
            .map(|p| VmImagePath::new_with_home(p, VmImageKind::Kernel, home))
            .transpose()?;
        let rootfs_image = raw
            .rootfs_image
            .as_deref()
            .map(|p| VmImagePath::new_with_home(p, VmImageKind::Rootfs, home))
            .transpose()?;
        let snapshot = raw.snapshot.as_deref().map(SnapshotName::new).transpose()?;

        // VM-INV-3: required / forbidden companions per backend and disk mode.
        match backend {
            IsolationBackend::Krun if kernel_image.is_some() => {
                return Err(CordonError::InvalidInput(
                    "krun uses its bundled kernel; kernel_image is not allowed".to_owned(),
                ));
            }
            IsolationBackend::QemuMicrovm | IsolationBackend::Firecracker
                if kernel_image.is_none() =>
            {
                return Err(CordonError::InvalidInput(format!(
                    "{backend} requires kernel_image"
                )));
            }
            _ => {}
        }
        if disk_mode.is_block()
            && disk_mode != VmDiskMode::SnapshotRestore
            && rootfs_image.is_none()
        {
            return Err(CordonError::InvalidInput(format!(
                "disk_mode '{disk_mode}' requires rootfs_image"
            )));
        }
        if disk_mode == VmDiskMode::VirtioFsLive && rootfs_image.is_some() {
            return Err(CordonError::InvalidInput(
                "disk_mode 'virtio-fs-live' exports the sandbox view as the guest root; \
                 rootfs_image is not allowed"
                    .to_owned(),
            ));
        }
        if disk_mode == VmDiskMode::BtrfsCowOverlay
            && rootfs_image.as_ref().is_some_and(|p| {
                !Path::new(p.as_str())
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("ext4"))
            })
        {
            return Err(CordonError::InvalidInput(
                "disk_mode 'btrfs-cow-overlay' requires a writable ext4 rootfs_image (*.ext4)"
                    .to_owned(),
            ));
        }
        match (disk_mode == VmDiskMode::SnapshotRestore, snapshot.is_some()) {
            (true, false) => {
                return Err(CordonError::InvalidInput(
                    "disk_mode 'snapshot-restore' requires snapshot".to_owned(),
                ));
            }
            (false, true) => {
                return Err(CordonError::InvalidInput(
                    "snapshot is only valid with disk_mode 'snapshot-restore'".to_owned(),
                ));
            }
            _ => {}
        }

        // VM-INV-5: rate limits each engine can actually enforce.
        if let Some(limits) = raw.rate_limits.as_ref() {
            if disk_mode == VmDiskMode::VirtioFsLive && limits.has_disk_limits() {
                return Err(CordonError::UnsupportedVmOption(
                    "disk rate limits apply to block devices; not supported with virtio-fs-live"
                        .to_owned(),
                ));
            }
            if backend == IsolationBackend::QemuMicrovm && limits.net_bandwidth_mbit_s.is_some() {
                return Err(CordonError::UnsupportedVmOption(
                    "net_bandwidth_mbit_s is not supported on qemu-microvm".to_owned(),
                ));
            }
        }
        let rate_limits = raw
            .rate_limits
            .filter(|l| l.has_disk_limits() || l.net_bandwidth_mbit_s.is_some());

        Ok(Self {
            backend,
            vcpus,
            memory_mib,
            disk_mode,
            kernel_image,
            rootfs_image,
            snapshot,
            rate_limits,
        })
    }

    /// Cross-validates this spec against the effective profile (VM-INV-4) and backend
    /// availability. Called by the plan compiler.
    pub fn validate_for_profile(&self, profile: &CordonProfile) -> Result<(), CordonError> {
        if self.backend == IsolationBackend::Krun {
            return Err(CordonError::UnsupportedVmOption(
                "krun launcher not selected; use qemu-microvm or firecracker".to_owned(),
            ));
        }
        if profile.network_mode == NetworkMode::Direct {
            return Err(CordonError::UnsupportedVmOption(
                "MicroVM backends require network_mode inspected, allowlist_only, or none \
                 (direct would bypass Gates 4-5)"
                    .to_owned(),
            ));
        }
        if profile.allow_gui_wayland || profile.allow_x11 || profile.allow_gpu_dri {
            return Err(CordonError::UnsupportedVmOption(
                "MicroVM backends do not support GUI or GPU passthrough".to_owned(),
            ));
        }
        Ok(())
    }

    /// Isolation backend.
    pub const fn backend(&self) -> IsolationBackend {
        self.backend
    }
    /// Guest vCPUs.
    pub const fn vcpus(&self) -> NonZeroU8 {
        self.vcpus
    }
    /// Guest memory in MiB.
    pub const fn memory_mib(&self) -> NonZeroU32 {
        self.memory_mib
    }
    /// Disk mode.
    pub const fn disk_mode(&self) -> VmDiskMode {
        self.disk_mode
    }
    /// Guest kernel image.
    pub const fn kernel_image(&self) -> Option<&VmImagePath> {
        self.kernel_image.as_ref()
    }
    /// Guest rootfs image.
    pub const fn rootfs_image(&self) -> Option<&VmImagePath> {
        self.rootfs_image.as_ref()
    }
    /// Named snapshot.
    pub const fn snapshot(&self) -> Option<&SnapshotName> {
        self.snapshot.as_ref()
    }
    /// I/O rate limits.
    pub const fn rate_limits(&self) -> Option<&VmRateLimits> {
        self.rate_limits.as_ref()
    }
}

impl TryFrom<RawMicroVmSpec> for MicroVmSpec {
    type Error = CordonError;
    fn try_from(raw: RawMicroVmSpec) -> Result<Self, Self::Error> {
        let home = std::env::var("HOME").ok();
        Self::from_raw_with_home(&raw, home.as_deref())
    }
}

impl From<MicroVmSpec> for RawMicroVmSpec {
    fn from(spec: MicroVmSpec) -> Self {
        Self {
            backend: spec.backend,
            vcpus: Some(spec.vcpus.get()),
            memory_mib: Some(spec.memory_mib.get()),
            disk_mode: Some(spec.disk_mode),
            kernel_image: spec.kernel_image.map(|p| p.0),
            rootfs_image: spec.rootfs_image.map(|p| p.0),
            snapshot: spec.snapshot.map(String::from),
            rate_limits: spec.rate_limits,
        }
    }
}

/// One slot of the per-netns MicroVM tap pool (`tcvm<n>`, one `/30` per slot inside
/// `10.200.255.0/24`). The veth pair keeps `10.200.1.0/24`; guest traffic is masqueraded to the
/// sandbox veth address inside the netns so host-side Gate 4/5 rules apply unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TapSlot(u8);

impl TapSlot {
    /// Maximum tap pool size (slots `0..16` fit in `10.200.255.0/26`).
    pub const MAX_POOL: u8 = 16;
    /// Default tap pool size provisioned by the netns setup.
    pub const DEFAULT_POOL: u8 = 4;
    /// Supernet carved into per-slot `/30` links.
    pub const SUPERNET: &'static str = "10.200.255.0/24";

    /// Validates a slot index (`0..MAX_POOL`).
    pub fn new(index: u8) -> Result<Self, CordonError> {
        if index < Self::MAX_POOL {
            Ok(Self(index))
        } else {
            Err(CordonError::InvalidNetworkConfig(format!(
                "tap slot {index} out of range (0..{})",
                Self::MAX_POOL
            )))
        }
    }

    /// Slot index.
    pub const fn index(self) -> u8 {
        self.0
    }

    /// Tap device name (`tcvm<n>`).
    pub fn device(self) -> String {
        format!("tcvm{}", self.0)
    }

    /// Netns-side gateway address (`10.200.255.(4n+1)`).
    pub fn gateway(self) -> String {
        format!("10.200.255.{}", u16::from(self.0) * 4 + 1)
    }

    /// Guest address (`10.200.255.(4n+2)`).
    pub fn guest_addr(self) -> String {
        format!("10.200.255.{}", u16::from(self.0) * 4 + 2)
    }

    /// Guest address in CIDR form (`10.200.255.(4n+2)/30`).
    pub fn guest_cidr(self) -> String {
        format!("{}/30", self.guest_addr())
    }
}

/// Guest NIC configuration delivered in the [`GuestExecEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestNetConfig {
    /// Guest address in CIDR form.
    pub addr: String,
    /// Default gateway (netns side of the tap).
    pub gw: String,
    /// Resolver address (host veth; the host DNS DNAT applies regardless of destination).
    pub dns: String,
}

/// Versioned command envelope sent to `cordon-guest-init` over the control channel.
///
/// Frames on the wire are a big-endian `u32` length followed by UTF-8 JSON (max
/// [`GuestExecEnvelope::MAX_FRAME_BYTES`]). Per-run fields (`uid`, `gid`, `entropy_b64`) are
/// filled by the supervisor at launch and omitted from compiled plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestExecEnvelope {
    /// Protocol version.
    pub v: u8,
    /// Command vector executed in the guest.
    pub argv: Vec<String>,
    /// Working directory in the guest.
    pub cwd: String,
    /// Environment for the guest command (CA overlay keys included under L7 inspection).
    pub env: BTreeMap<String, String>,
    /// Guest NIC configuration (`None` = loopback only, fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<GuestNetConfig>,
    /// Sandbox-side CA bundle path the supervisor reads and forwards for block-device guests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_from: Option<String>,
    /// Run the command on the guest console as a TTY.
    pub tty: bool,
    /// Guest uid (filled at launch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Guest gid (filled at launch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Base64 host entropy for guest RNG reseeding (filled at launch; mandatory on restore).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_b64: Option<String>,
}

impl GuestExecEnvelope {
    /// Current protocol version.
    pub const VERSION: u8 = 1;
    /// Maximum encoded frame size in bytes.
    pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
}

/// One Firecracker API request issued over the VMM's Unix API socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirecrackerApiCall {
    /// HTTP method (`PUT` / `PATCH`).
    pub method: String,
    /// Request path (`/machine-config`, `/drives/rootfs`, ...).
    pub path: String,
    /// JSON request body.
    pub body: serde_json::Value,
}

/// Compiled, deterministic Gate 3.5 execution plan, run *inside* the Gate 1-3 launch plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmExecutionPlan {
    /// Isolation backend.
    pub backend: IsolationBackend,
    /// Disk mode.
    pub disk_mode: VmDiskMode,
    /// Validated spec this plan was compiled from.
    pub spec: MicroVmSpec,
    /// Per-run identifier used for run-scoped host files (overlay clones).
    pub run_id: String,
    /// Tap slot used by the guest NIC (`None` = no NIC, loopback-only guest).
    pub tap_slot: Option<TapSlot>,
    /// virtiofsd argv (virtio-fs-live only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtiofsd_argv: Option<Vec<String>>,
    /// VMM argv (`qemu-system-x86_64 ...` or `firecracker --api-sock ...`).
    pub vmm_argv: Vec<String>,
    /// Ordered Firecracker API calls (empty for QEMU).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub firecracker_api: Vec<FirecrackerApiCall>,
    /// Host device nodes bound into the Gate 3 mount namespace.
    pub device_binds: Vec<String>,
    /// Control channel socket path inside the Gate 3 namespace.
    pub control_socket: String,
    /// Command envelope delivered to `cordon-guest-init`.
    pub envelope: GuestExecEnvelope,
}

/// Inputs for compiling one MicroVM plan (everything except the validated spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmCompileContext {
    /// Canonical workspace (guest working directory).
    pub workspace: CanonicalPath,
    /// Guest command vector.
    pub command: Vec<String>,
    /// Environment from the Gate 3 plan (CA overlay and config env).
    pub env: BTreeMap<String, String>,
    /// Effective network mode.
    pub network_mode: NetworkMode,
    /// Guest resolver (host veth address).
    pub dns: String,
    /// Tap slot for the guest NIC (`None` = loopback-only guest).
    pub tap_slot: Option<TapSlot>,
    /// Run identifier for run-scoped files.
    pub run_id: String,
    /// Attach the guest command to the console as a TTY.
    pub tty: bool,
}

#[cfg(test)]
mod microvm_tests {
    use super::*;

    const KERNEL: &str = "/var/lib/cordon/kernels/vmlinux-microvm";
    const ROOTFS_EROFS: &str = "/var/lib/cordon/images/base.erofs";
    const ROOTFS_EXT4: &str = "/var/lib/cordon/images/base.ext4";

    fn raw(backend: IsolationBackend, disk_mode: VmDiskMode) -> RawMicroVmSpec {
        let rootfs = match disk_mode {
            VmDiskMode::VirtioFsLive | VmDiskMode::SnapshotRestore => None,
            VmDiskMode::BtrfsCowOverlay => Some(ROOTFS_EXT4.to_owned()),
            VmDiskMode::EphemeralTmpfs => Some(ROOTFS_EROFS.to_owned()),
        };
        RawMicroVmSpec {
            backend,
            disk_mode: Some(disk_mode),
            kernel_image: (backend != IsolationBackend::Krun).then(|| KERNEL.to_owned()),
            rootfs_image: rootfs,
            snapshot: (disk_mode == VmDiskMode::SnapshotRestore).then(|| "warm-01".to_owned()),
            ..RawMicroVmSpec::default()
        }
    }

    fn build(raw: &RawMicroVmSpec) -> Result<MicroVmSpec, CordonError> {
        MicroVmSpec::from_raw_with_home(raw, Some("/home/tester"))
    }

    const ALL_MODES: [VmDiskMode; 4] = [
        VmDiskMode::VirtioFsLive,
        VmDiskMode::EphemeralTmpfs,
        VmDiskMode::BtrfsCowOverlay,
        VmDiskMode::SnapshotRestore,
    ];

    #[test]
    fn backend_disk_mode_matrix_is_enforced() {
        for backend in [
            IsolationBackend::QemuMicrovm,
            IsolationBackend::Firecracker,
            IsolationBackend::Krun,
        ] {
            for mode in ALL_MODES {
                let result = build(&raw(backend, mode));
                let supported = backend.supported_disk_modes().contains(&mode);
                match result {
                    Ok(spec) => {
                        assert!(supported, "{backend}+{mode} must be rejected");
                        assert_eq!(spec.disk_mode(), mode);
                    }
                    Err(CordonError::IncompatibleVmDiskMode { .. }) => {
                        assert!(!supported, "{backend}+{mode} must be accepted");
                    }
                    Err(other) => panic!("{backend}+{mode}: unexpected error {other}"),
                }
            }
        }
    }

    #[test]
    fn firecracker_rejects_virtio_fs_live() {
        let err = build(&raw(
            IsolationBackend::Firecracker,
            VmDiskMode::VirtioFsLive,
        ));
        assert!(matches!(
            err,
            Err(CordonError::IncompatibleVmDiskMode { .. })
        ));
    }

    #[test]
    fn native_bwrap_is_not_a_microvm_spec() {
        let spec = RawMicroVmSpec::default();
        assert!(matches!(build(&spec), Err(CordonError::InvalidInput(_))));
    }

    #[test]
    fn wire_names_are_stable() {
        let names: Vec<String> = [
            IsolationBackend::NativeBwrap,
            IsolationBackend::QemuMicrovm,
            IsolationBackend::Firecracker,
            IsolationBackend::Krun,
        ]
        .iter()
        .map(|b| serde_json::to_string(b).unwrap_or_default())
        .collect();
        assert_eq!(
            names,
            [
                "\"native-bwrap\"",
                "\"qemu-microvm\"",
                "\"firecracker\"",
                "\"krun\""
            ]
        );
        let modes: Vec<String> = ALL_MODES
            .iter()
            .map(|m| serde_json::to_string(m).unwrap_or_default())
            .collect();
        assert_eq!(
            modes,
            [
                "\"virtio-fs-live\"",
                "\"ephemeral-tmpfs\"",
                "\"btrfs-cow-overlay\"",
                "\"snapshot-restore\""
            ]
        );
        for b in [IsolationBackend::QemuMicrovm, IsolationBackend::Firecracker] {
            assert_eq!(
                format!("\"{b}\""),
                serde_json::to_string(&b).unwrap_or_default()
            );
        }
    }

    #[test]
    fn defaults_applied_per_backend() {
        let mut fc = raw(IsolationBackend::Firecracker, VmDiskMode::EphemeralTmpfs);
        fc.disk_mode = None;
        let Ok(spec) = build(&fc) else {
            panic!("firecracker default spec must validate");
        };
        assert_eq!(spec.disk_mode(), VmDiskMode::EphemeralTmpfs);
        assert_eq!(spec.vcpus().get(), MicroVmSpec::DEFAULT_VCPUS);
        assert_eq!(spec.memory_mib().get(), MicroVmSpec::DEFAULT_MEMORY_MIB);

        let mut qemu = raw(IsolationBackend::QemuMicrovm, VmDiskMode::VirtioFsLive);
        qemu.disk_mode = None;
        assert!(build(&qemu).is_ok_and(|s| s.disk_mode() == VmDiskMode::VirtioFsLive));
    }

    #[test]
    fn resource_bounds_are_enforced() {
        for (vcpus, mem, ok) in [
            (0_u8, 1024_u32, false),
            (33, 1024, false),
            (32, 1024, true),
            (1, 127, false),
            (1, 128, true),
            (1, 65_537, false),
        ] {
            let mut r = raw(IsolationBackend::QemuMicrovm, VmDiskMode::VirtioFsLive);
            r.vcpus = Some(vcpus);
            r.memory_mib = Some(mem);
            assert_eq!(build(&r).is_ok(), ok, "vcpus={vcpus} mem={mem}");
        }
    }

    #[test]
    fn image_paths_must_be_under_allowlisted_roots() {
        let home = Some("/home/tester");
        for bad in [
            "relative/vmlinux",
            "/etc/shadow",
            "/dev/sda",
            "/",
            "/home/tester/.ssh/id_ed25519",
            "/var/lib/cordon/kernels/../../../etc/passwd",
            "/var/lib/cordon/kernels",
            "/var/lib/cordon/images/base.erofs",
        ] {
            assert!(
                matches!(
                    VmImagePath::new_with_home(bad, VmImageKind::Kernel, home),
                    Err(CordonError::UnsafeMicroVmImage { .. })
                ),
                "{bad} must be rejected as a kernel image"
            );
        }
        for good in [
            "/boot/vmlinuz-linux",
            KERNEL,
            "/home/tester/.local/share/cordon/kernels/vmlinux",
        ] {
            assert!(
                VmImagePath::new_with_home(good, VmImageKind::Kernel, home).is_ok(),
                "{good} must be accepted"
            );
        }
        assert!(VmImagePath::new_with_home(ROOTFS_EROFS, VmImageKind::Rootfs, home).is_ok());
        assert!(VmImagePath::new_with_home("/boot/initrd", VmImageKind::Rootfs, home).is_err());
    }

    #[test]
    fn image_path_rejects_symlinked_component_and_non_files() {
        let base = std::env::temp_dir().join(format!("cordon-vm-{}", uuid::Uuid::new_v4()));
        let home = base.join("home");
        let kernels = home.join(".local/share/cordon/kernels");
        let real = base.join("real");
        assert!(std::fs::create_dir_all(&real).is_ok());
        assert!(std::fs::create_dir_all(home.join(".local/share/cordon")).is_ok());
        assert!(std::os::unix::fs::symlink(&real, &kernels).is_ok());
        assert!(std::fs::write(real.join("vmlinux"), b"k").is_ok());
        let home_str = home.to_string_lossy().into_owned();
        let via_link = kernels.join("vmlinux").to_string_lossy().into_owned();
        assert!(matches!(
            VmImagePath::new_with_home(&via_link, VmImageKind::Kernel, Some(&home_str)),
            Err(CordonError::UnsafeMicroVmImage { .. })
        ));

        assert!(std::fs::remove_file(&kernels).is_ok());
        assert!(std::fs::create_dir_all(kernels.join("subdir")).is_ok());
        let dir_path = kernels.join("subdir").to_string_lossy().into_owned();
        assert!(
            VmImagePath::new_with_home(&dir_path, VmImageKind::Kernel, Some(&home_str)).is_err()
        );
        assert!(std::fs::write(kernels.join("vmlinux"), b"k").is_ok());
        let file_path = kernels.join("vmlinux").to_string_lossy().into_owned();
        assert!(
            VmImagePath::new_with_home(&file_path, VmImageKind::Kernel, Some(&home_str)).is_ok()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn companion_fields_are_validated() {
        let mut no_kernel = raw(IsolationBackend::Firecracker, VmDiskMode::EphemeralTmpfs);
        no_kernel.kernel_image = None;
        assert!(build(&no_kernel).is_err());

        let mut krun_kernel = raw(IsolationBackend::Krun, VmDiskMode::VirtioFsLive);
        krun_kernel.kernel_image = Some(KERNEL.to_owned());
        assert!(build(&krun_kernel).is_err());

        let mut no_rootfs = raw(IsolationBackend::Firecracker, VmDiskMode::EphemeralTmpfs);
        no_rootfs.rootfs_image = None;
        assert!(build(&no_rootfs).is_err());

        let mut live_rootfs = raw(IsolationBackend::QemuMicrovm, VmDiskMode::VirtioFsLive);
        live_rootfs.rootfs_image = Some(ROOTFS_EROFS.to_owned());
        assert!(build(&live_rootfs).is_err());

        let mut cow_erofs = raw(IsolationBackend::Firecracker, VmDiskMode::BtrfsCowOverlay);
        cow_erofs.rootfs_image = Some(ROOTFS_EROFS.to_owned());
        assert!(build(&cow_erofs).is_err());

        let mut no_snap = raw(IsolationBackend::Firecracker, VmDiskMode::SnapshotRestore);
        no_snap.snapshot = None;
        assert!(build(&no_snap).is_err());

        let mut stray_snap = raw(IsolationBackend::Firecracker, VmDiskMode::EphemeralTmpfs);
        stray_snap.snapshot = Some("warm-01".to_owned());
        assert!(build(&stray_snap).is_err());

        let mut bad_snap = raw(IsolationBackend::Firecracker, VmDiskMode::SnapshotRestore);
        bad_snap.snapshot = Some("../etc".to_owned());
        assert!(build(&bad_snap).is_err());
    }

    #[test]
    fn rate_limits_are_engine_aware() {
        let nz = |v: u32| NonZeroU32::new(v);
        let mut live_disk = raw(IsolationBackend::QemuMicrovm, VmDiskMode::VirtioFsLive);
        live_disk.rate_limits = Some(VmRateLimits {
            disk_iops: nz(100),
            ..VmRateLimits::default()
        });
        assert!(matches!(
            build(&live_disk),
            Err(CordonError::UnsupportedVmOption(_))
        ));

        let mut qemu_net = raw(IsolationBackend::QemuMicrovm, VmDiskMode::EphemeralTmpfs);
        qemu_net.rate_limits = Some(VmRateLimits {
            net_bandwidth_mbit_s: nz(100),
            ..VmRateLimits::default()
        });
        assert!(matches!(
            build(&qemu_net),
            Err(CordonError::UnsupportedVmOption(_))
        ));

        let mut fc = raw(IsolationBackend::Firecracker, VmDiskMode::EphemeralTmpfs);
        fc.rate_limits = Some(VmRateLimits {
            disk_iops: nz(5000),
            disk_bandwidth_mib_s: nz(250),
            net_bandwidth_mbit_s: nz(100),
        });
        assert!(build(&fc).is_ok_and(|s| s.rate_limits().is_some()));

        let mut empty = raw(IsolationBackend::Firecracker, VmDiskMode::EphemeralTmpfs);
        empty.rate_limits = Some(VmRateLimits::default());
        assert!(build(&empty).is_ok_and(|s| s.rate_limits().is_none()));
    }

    #[test]
    fn spec_round_trips_through_json_and_rejects_unknown_fields() {
        let Ok(spec) = build(&raw(
            IsolationBackend::Firecracker,
            VmDiskMode::SnapshotRestore,
        )) else {
            panic!("snapshot spec must validate");
        };
        let json = serde_json::to_string(&spec).unwrap_or_default();
        let back: Result<MicroVmSpec, _> = serde_json::from_str(&json);
        assert!(back.is_ok_and(|b| b == spec));

        let bad = r#"{"backend":"firecracker","vsock_cid":3}"#;
        assert!(serde_json::from_str::<RawMicroVmSpec>(bad).is_err());
        let invalid = r#"{"backend":"firecracker","disk_mode":"virtio-fs-live","kernel_image":"/boot/vmlinux"}"#;
        assert!(serde_json::from_str::<MicroVmSpec>(invalid).is_err());
    }

    #[test]
    fn profile_cross_validation() {
        let Ok(spec) = build(&raw(
            IsolationBackend::QemuMicrovm,
            VmDiskMode::VirtioFsLive,
        )) else {
            panic!("qemu spec must validate");
        };
        let Ok(mut profile) = crate::profiles::get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        assert!(spec.validate_for_profile(&profile).is_ok());
        profile.network_mode = NetworkMode::Direct;
        assert!(matches!(
            spec.validate_for_profile(&profile),
            Err(CordonError::UnsupportedVmOption(_))
        ));
        profile.network_mode = NetworkMode::None;
        profile.allow_gpu_dri = true;
        assert!(spec.validate_for_profile(&profile).is_err());

        let Ok(krun) = build(&raw(IsolationBackend::Krun, VmDiskMode::VirtioFsLive)) else {
            panic!("krun spec must parse (reserved)");
        };
        let Ok(plain) = crate::profiles::get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        assert!(matches!(
            krun.validate_for_profile(&plain),
            Err(CordonError::UnsupportedVmOption(_))
        ));
    }
}
