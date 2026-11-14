use std::num::NonZeroU32;

use super::*;
use crate::error::CordonError;

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
    assert!(VmImagePath::new_with_home(&dir_path, VmImageKind::Kernel, Some(&home_str)).is_err());
    assert!(std::fs::write(kernels.join("vmlinux"), b"k").is_ok());
    let file_path = kernels.join("vmlinux").to_string_lossy().into_owned();
    assert!(VmImagePath::new_with_home(&file_path, VmImageKind::Kernel, Some(&home_str)).is_ok());
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
    let invalid =
        r#"{"backend":"firecracker","disk_mode":"virtio-fs-live","kernel_image":"/boot/vmlinux"}"#;
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
