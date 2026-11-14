//! Gate 3.5 MicroVM backend enums, disk modes, rate limits, and validated image/snapshot newtypes.

use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::CanonicalPath;
use crate::error::CordonError;

/// Isolation backend executing the workload inside Gates 1-3.
///
/// Wire names are explicit (not derived) so the JSON/TOML/CLI vocabulary is pinned by the
/// golden conformance fixture (`tests/golden/microvm_spec_cases.json`).
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
pub struct VmImagePath(pub(super) String);

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
