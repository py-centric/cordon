"""Gate 3.5 MicroVM spec model: Python reference parity with the Rust engine.

Mirrors ``src/domain.rs`` (``IsolationBackend``, ``VmDiskMode``, ``MicroVmSpec``) and the
token-bucket / tap-slot helpers in ``src/microvm.rs``. Both stacks are checked against the shared
fixture ``tests/golden/microvm_spec_cases.json``. See ``docs/design/microvm-isolation.md``.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict


class IsolationBackend(StrEnum):
    """Isolation backend executing the workload inside Gates 1-3."""

    NATIVE_BWRAP = "native-bwrap"
    QEMU_MICROVM = "qemu-microvm"
    FIRECRACKER = "firecracker"
    KRUN = "krun"  # reserved: parses, rejected by the compiler until a launcher is selected


class VmDiskMode(StrEnum):
    """Guest root/workspace storage strategy."""

    VIRTIO_FS_LIVE = "virtio-fs-live"
    EPHEMERAL_TMPFS = "ephemeral-tmpfs"
    BTRFS_COW_OVERLAY = "btrfs-cow-overlay"
    SNAPSHOT_RESTORE = "snapshot-restore"


SUPPORTED_DISK_MODES: dict[IsolationBackend, tuple[VmDiskMode, ...]] = {
    IsolationBackend.NATIVE_BWRAP: (),
    IsolationBackend.QEMU_MICROVM: (
        VmDiskMode.VIRTIO_FS_LIVE,
        VmDiskMode.EPHEMERAL_TMPFS,
        VmDiskMode.BTRFS_COW_OVERLAY,
    ),
    IsolationBackend.FIRECRACKER: (
        VmDiskMode.EPHEMERAL_TMPFS,
        VmDiskMode.BTRFS_COW_OVERLAY,
        VmDiskMode.SNAPSHOT_RESTORE,
    ),
    IsolationBackend.KRUN: (VmDiskMode.VIRTIO_FS_LIVE,),
}

DEFAULT_DISK_MODE: dict[IsolationBackend, VmDiskMode] = {
    IsolationBackend.QEMU_MICROVM: VmDiskMode.VIRTIO_FS_LIVE,
    IsolationBackend.KRUN: VmDiskMode.VIRTIO_FS_LIVE,
    IsolationBackend.FIRECRACKER: VmDiskMode.EPHEMERAL_TMPFS,
}

KERNEL_ROOTS = ("/boot", "/var/lib/cordon/kernels", "/usr/lib/cordon/kernels", "/usr/share/cordon/kernels")
ROOTFS_ROOTS = ("/var/lib/cordon/images", "/usr/lib/cordon/images", "/usr/share/cordon/images")
USER_KERNEL_ROOT = ".local/share/cordon/kernels"
USER_ROOTFS_ROOT = ".local/share/cordon/images"

MAX_VCPUS = 32
MIN_MEMORY_MIB = 128
MAX_MEMORY_MIB = 65_536
DEFAULT_VCPUS = 2
DEFAULT_MEMORY_MIB = 1024
TAP_MAX_POOL = 16
_SNAPSHOT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")


class MicroVmError(ValueError):
    """Validation failure carrying the Rust ``CordonError`` variant name for parity checks."""

    def __init__(self, variant: str, message: str) -> None:
        super().__init__(message)
        self.variant = variant


class VmRateLimits(BaseModel):
    """Per-VM I/O limits with explicit units."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    disk_iops: int | None = None
    disk_bandwidth_mib_s: int | None = None
    net_bandwidth_mbit_s: int | None = None

    def has_disk_limits(self) -> bool:
        return self.disk_iops is not None or self.disk_bandwidth_mib_s is not None

    def is_empty(self) -> bool:
        return not self.has_disk_limits() and self.net_bandwidth_mbit_s is None


class RawMicroVmSpec(BaseModel):
    """Unvalidated ``[vm]`` table / API ``vm`` object (unknown keys are rejected)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    backend: IsolationBackend = IsolationBackend.NATIVE_BWRAP
    vcpus: int | None = None
    memory_mib: int | None = None
    disk_mode: VmDiskMode | None = None
    kernel_image: str | None = None
    rootfs_image: str | None = None
    snapshot: str | None = None
    rate_limits: VmRateLimits | None = None


def _normalize(path: str) -> PurePosixPath:
    parts: list[str] = []
    for part in PurePosixPath(path).parts[1:]:
        if part == ".":
            continue
        parts.append(part)
    return PurePosixPath("/", *parts)


def validate_image_path(raw: str, kind: str, home: str | None) -> str:
    """Mirrors ``VmImagePath::new_with_home`` (allowlisted roots, no '..', no symlinks)."""
    label = "kernel_image" if kind == "kernel" else "rootfs_image"

    def fail(reason: str) -> MicroVmError:
        return MicroVmError("UnsafeMicroVmImage", f"Refusing MicroVM image '{raw}': {label}: {reason}")

    trimmed = raw.strip()
    if not trimmed or not trimmed.startswith("/"):
        raise fail("path must be absolute")
    if ".." in PurePosixPath(trimmed).parts:
        raise fail("path must not contain '..'")
    lexical = _normalize(trimmed)
    roots = [PurePosixPath(r) for r in (KERNEL_ROOTS if kind == "kernel" else ROOTFS_ROOTS)]
    if home and home.strip():
        home_path = Path(home)
        home_canon = home_path.resolve() if home_path.exists() else home_path
        roots.append(PurePosixPath(home_canon) / (USER_KERNEL_ROOT if kind == "kernel" else USER_ROOTFS_ROOT))
    if not any(lexical != root and lexical.is_relative_to(root) for root in roots):
        raise fail("path is outside the allowlisted MicroVM image directories")
    existing = Path(lexical)
    while not os.path.lexists(existing) and existing != existing.parent:
        existing = existing.parent
    if existing.resolve() != existing:
        raise fail("path traverses a symbolic link")
    if os.path.lexists(lexical) and not Path(lexical).is_file():
        raise fail("path must be a regular file")
    return str(lexical)


def validate_microvm_spec(raw: RawMicroVmSpec, home: str | None = None) -> dict[str, Any]:
    """Validates a raw spec and returns the normalized wire form (same as Rust serialization)."""
    backend = raw.backend
    if backend not in DEFAULT_DISK_MODE:
        raise MicroVmError(
            "InvalidInput",
            "MicroVM spec requires a MicroVM backend (qemu-microvm, firecracker, krun)",
        )
    disk_mode = raw.disk_mode or DEFAULT_DISK_MODE[backend]
    if disk_mode not in SUPPORTED_DISK_MODES[backend]:
        raise MicroVmError(
            "IncompatibleVmDiskMode",
            f"MicroVM backend '{backend}' does not support disk_mode '{disk_mode}'",
        )
    vcpus = DEFAULT_VCPUS if raw.vcpus is None else raw.vcpus
    if not 1 <= vcpus <= MAX_VCPUS:
        raise MicroVmError("InvalidInput", f"vcpus must be between 1 and {MAX_VCPUS}, got {vcpus}")
    memory = DEFAULT_MEMORY_MIB if raw.memory_mib is None else raw.memory_mib
    if not MIN_MEMORY_MIB <= memory <= MAX_MEMORY_MIB:
        raise MicroVmError("InvalidInput", f"memory_mib out of range, got {memory}")

    kernel = validate_image_path(raw.kernel_image, "kernel", home) if raw.kernel_image else None
    rootfs = validate_image_path(raw.rootfs_image, "rootfs", home) if raw.rootfs_image else None
    if raw.snapshot is not None and not _SNAPSHOT_RE.match(raw.snapshot):
        raise MicroVmError("InvalidInput", f"Invalid snapshot name '{raw.snapshot}'")

    if backend is IsolationBackend.KRUN and kernel:
        raise MicroVmError("InvalidInput", "krun uses its bundled kernel; kernel_image is not allowed")
    if backend in (IsolationBackend.QEMU_MICROVM, IsolationBackend.FIRECRACKER) and not kernel:
        raise MicroVmError("InvalidInput", f"{backend} requires kernel_image")
    is_block = disk_mode is not VmDiskMode.VIRTIO_FS_LIVE
    if is_block and disk_mode is not VmDiskMode.SNAPSHOT_RESTORE and not rootfs:
        raise MicroVmError("InvalidInput", f"disk_mode '{disk_mode}' requires rootfs_image")
    if disk_mode is VmDiskMode.VIRTIO_FS_LIVE and rootfs:
        raise MicroVmError("InvalidInput", "rootfs_image is not allowed with virtio-fs-live")
    if disk_mode is VmDiskMode.BTRFS_COW_OVERLAY and rootfs and not rootfs.lower().endswith(".ext4"):
        raise MicroVmError("InvalidInput", "btrfs-cow-overlay requires an ext4 rootfs_image")
    if (disk_mode is VmDiskMode.SNAPSHOT_RESTORE) != (raw.snapshot is not None):
        raise MicroVmError("InvalidInput", "snapshot is required for, and only valid with, snapshot-restore")

    limits = raw.rate_limits
    if limits is not None:
        for value in (limits.disk_iops, limits.disk_bandwidth_mib_s, limits.net_bandwidth_mbit_s):
            if value is not None and value <= 0:
                raise MicroVmError("InvalidInput", "rate limits must be greater than 0")
        if disk_mode is VmDiskMode.VIRTIO_FS_LIVE and limits.has_disk_limits():
            raise MicroVmError("UnsupportedVmOption", "disk rate limits are not supported with virtio-fs-live")
        if backend is IsolationBackend.QEMU_MICROVM and limits.net_bandwidth_mbit_s is not None:
            raise MicroVmError("UnsupportedVmOption", "net_bandwidth_mbit_s is not supported on qemu-microvm")

    normalized: dict[str, Any] = {
        "backend": backend.value,
        "vcpus": vcpus,
        "memory_mib": memory,
        "disk_mode": disk_mode.value,
    }
    if kernel:
        normalized["kernel_image"] = kernel
    if rootfs:
        normalized["rootfs_image"] = rootfs
    if raw.snapshot is not None:
        normalized["snapshot"] = raw.snapshot
    if limits is not None and not limits.is_empty():
        normalized["rate_limits"] = limits.model_dump(exclude_none=True)
    return normalized


def firecracker_disk_rate_limiter(limits: VmRateLimits) -> dict[str, Any] | None:
    """Firecracker block token bucket (MiB/s -> bytes, IOPS -> ops; refill 1000 ms)."""
    if not limits.has_disk_limits():
        return None
    limiter: dict[str, Any] = {}
    if limits.disk_bandwidth_mib_s is not None:
        limiter["bandwidth"] = {"size": limits.disk_bandwidth_mib_s * 1_048_576, "refill_time": 1000}
    if limits.disk_iops is not None:
        limiter["ops"] = {"size": limits.disk_iops, "refill_time": 1000}
    return limiter


def firecracker_net_rate_limiter(limits: VmRateLimits) -> dict[str, Any] | None:
    """Firecracker network token bucket (Mbit/s -> bytes per second)."""
    if limits.net_bandwidth_mbit_s is None:
        return None
    return {"bandwidth": {"size": limits.net_bandwidth_mbit_s * 125_000, "refill_time": 1000}}


def tap_slot(index: int) -> dict[str, str]:
    """Tap pool slot addressing (``tcvm<n>``, one /30 per slot in 10.200.255.0/24)."""
    if not 0 <= index < TAP_MAX_POOL:
        raise MicroVmError("InvalidNetworkConfig", f"tap slot {index} out of range (0..{TAP_MAX_POOL})")
    return {
        "device": f"tcvm{index}",
        "gateway": f"10.200.255.{index * 4 + 1}",
        "guest_cidr": f"10.200.255.{index * 4 + 2}/30",
    }
