//! Validated [`MicroVmSpec`] and wire [`RawMicroVmSpec`] structures.

use std::num::{NonZeroU8, NonZeroU32};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::microvm::{
    IsolationBackend, SnapshotName, VmDiskMode, VmImageKind, VmImagePath, VmRateLimits,
};
use super::{CordonProfile, NetworkMode};
use crate::error::CordonError;

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

        Self::validate_companions(
            backend,
            disk_mode,
            kernel_image.as_ref(),
            rootfs_image.as_ref(),
            snapshot.as_ref(),
        )?;
        Self::validate_rate_limits(backend, disk_mode, raw.rate_limits.as_ref())?;

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

    fn validate_companions(
        backend: IsolationBackend,
        disk_mode: VmDiskMode,
        kernel_image: Option<&VmImagePath>,
        rootfs_image: Option<&VmImagePath>,
        snapshot: Option<&SnapshotName>,
    ) -> Result<(), CordonError> {
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
            && rootfs_image.is_some_and(|p| {
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
            (true, false) => Err(CordonError::InvalidInput(
                "disk_mode 'snapshot-restore' requires snapshot".to_owned(),
            )),
            (false, true) => Err(CordonError::InvalidInput(
                "snapshot is only valid with disk_mode 'snapshot-restore'".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    fn validate_rate_limits(
        backend: IsolationBackend,
        disk_mode: VmDiskMode,
        limits: Option<&VmRateLimits>,
    ) -> Result<(), CordonError> {
        if let Some(limits) = limits {
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
        Ok(())
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
    #[must_use]
    pub const fn backend(&self) -> IsolationBackend {
        self.backend
    }
    /// Guest vCPUs.
    #[must_use]
    pub const fn vcpus(&self) -> NonZeroU8 {
        self.vcpus
    }
    /// Guest memory in MiB.
    #[must_use]
    pub const fn memory_mib(&self) -> NonZeroU32 {
        self.memory_mib
    }
    /// Disk mode.
    #[must_use]
    pub const fn disk_mode(&self) -> VmDiskMode {
        self.disk_mode
    }
    /// Guest kernel image.
    #[must_use]
    pub const fn kernel_image(&self) -> Option<&VmImagePath> {
        self.kernel_image.as_ref()
    }
    /// Guest rootfs image.
    #[must_use]
    pub const fn rootfs_image(&self) -> Option<&VmImagePath> {
        self.rootfs_image.as_ref()
    }
    /// Named snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> Option<&SnapshotName> {
        self.snapshot.as_ref()
    }
    /// I/O rate limits.
    #[must_use]
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
