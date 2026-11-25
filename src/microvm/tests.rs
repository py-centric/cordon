use std::collections::BTreeMap;
use std::num::NonZeroU32;

use super::*;
use crate::domain::{CanonicalPath, RawMicroVmSpec, VmRateLimits};
use crate::profiles::get_profile;

pub(super) const KERNEL: &str = "/var/lib/cordon/kernels/vmlinux-microvm";

pub(super) fn spec(
    backend: IsolationBackend,
    mode: VmDiskMode,
    limits: Option<VmRateLimits>,
) -> MicroVmSpec {
    let raw = RawMicroVmSpec {
        backend,
        disk_mode: Some(mode),
        kernel_image: Some(KERNEL.to_owned()),
        rootfs_image: match mode {
            VmDiskMode::EphemeralTmpfs => Some("/var/lib/cordon/images/base.erofs".to_owned()),
            VmDiskMode::BtrfsCowOverlay => Some("/var/lib/cordon/images/base.ext4".to_owned()),
            VmDiskMode::VirtioFsLive | VmDiskMode::SnapshotRestore => None,
        },
        snapshot: (mode == VmDiskMode::SnapshotRestore).then(|| "warm-01".to_owned()),
        rate_limits: limits,
        ..RawMicroVmSpec::default()
    };
    match MicroVmSpec::from_raw_with_home(&raw, None) {
        Ok(s) => s,
        Err(e) => panic!("test spec must validate: {e}"),
    }
}

pub(super) fn ctx(network_mode: NetworkMode, slot: Option<u8>) -> MicroVmCompileContext {
    let mut env = BTreeMap::new();
    env.insert(
        "SSL_CERT_FILE".to_owned(),
        "/etc/ssl/certs/ca-certificates.crt".to_owned(),
    );
    MicroVmCompileContext {
        workspace: CanonicalPath::from_trusted_static("/srv/ws"),
        command: vec!["python3".to_owned(), "-I".to_owned(), "a.py".to_owned()],
        env,
        network_mode,
        dns: "10.200.1.1".to_owned(),
        tap_slot: slot.and_then(|s| TapSlot::new(s).ok()),
        run_id: "run-1".to_owned(),
        tty: true,
    }
}

fn compile(s: &MicroVmSpec, c: &MicroVmCompileContext) -> MicroVmExecutionPlan {
    match compile_microvm_plan(s, c) {
        Ok(p) => p,
        Err(e) => panic!("compile failed: {e}"),
    }
}

fn call<'a>(plan: &'a MicroVmExecutionPlan, path: &str) -> Option<&'a FirecrackerApiCall> {
    plan.firecracker_api.iter().find(|c| c.path == path)
}

#[test]
fn tap_slot_addresses_do_not_overlap_the_veth_subnet() {
    let Ok(s0) = TapSlot::new(0) else { panic!() };
    let Ok(s3) = TapSlot::new(3) else { panic!() };
    assert_eq!(
        (s0.device(), s0.gateway(), s0.guest_cidr()),
        (
            "tcvm0".to_owned(),
            "10.200.255.1".to_owned(),
            "10.200.255.2/30".to_owned()
        )
    );
    assert_eq!(
        (s3.gateway(), s3.guest_addr()),
        ("10.200.255.13".to_owned(), "10.200.255.14".to_owned())
    );
    assert!(TapSlot::new(TapSlot::MAX_POOL).is_err());
    let Ok(profile) = get_profile("ai-agent") else {
        panic!()
    };
    assert!(!s0.guest_addr().starts_with("10.200.1."));
    assert_ne!(s0.guest_addr(), profile.sandbox_veth_ip);
}

#[test]
fn firecracker_plan_emits_rate_limiters_with_explicit_units() {
    let limits = VmRateLimits {
        disk_iops: NonZeroU32::new(5000),
        disk_bandwidth_mib_s: NonZeroU32::new(250),
        net_bandwidth_mbit_s: NonZeroU32::new(100),
    };
    let plan = compile(
        &spec(
            IsolationBackend::Firecracker,
            VmDiskMode::EphemeralTmpfs,
            Some(limits),
        ),
        &ctx(NetworkMode::Inspected, Some(0)),
    );
    let Some(rootfs) = call(&plan, "/drives/rootfs") else {
        panic!("rootfs drive missing")
    };
    assert_eq!(
        rootfs.body["rate_limiter"]["bandwidth"]["size"],
        250 * 1_048_576
    );
    assert_eq!(rootfs.body["rate_limiter"]["ops"]["size"], 5000);
    assert_eq!(rootfs.body["is_read_only"], true);
    let Some(eth0) = call(&plan, "/network-interfaces/eth0") else {
        panic!("nic missing")
    };
    assert_eq!(eth0.body["host_dev_name"], "tcvm0");
    assert_eq!(
        eth0.body["rx_rate_limiter"]["bandwidth"]["size"],
        100 * 125_000
    );
    assert_eq!(
        eth0.body["tx_rate_limiter"]["bandwidth"]["size"],
        100 * 125_000
    );
    assert_eq!(
        plan.firecracker_api.last().map(|c| c.path.as_str()),
        Some("/actions")
    );
    assert!(
        !plan.vmm_argv.iter().any(|a| a == "--no-seccomp"),
        "Firecracker seccomp must stay on"
    );
    assert_eq!(plan.control_socket, FC_VSOCK_SOCKET);
}

#[test]
fn firecracker_without_limits_has_no_rate_limiter_keys() {
    let plan = compile(
        &spec(
            IsolationBackend::Firecracker,
            VmDiskMode::EphemeralTmpfs,
            None,
        ),
        &ctx(NetworkMode::Inspected, Some(1)),
    );
    let Some(rootfs) = call(&plan, "/drives/rootfs") else {
        panic!()
    };
    assert!(rootfs.body.get("rate_limiter").is_none());
    let Some(eth0) = call(&plan, "/network-interfaces/eth0") else {
        panic!()
    };
    assert!(eth0.body.get("rx_rate_limiter").is_none());
    assert_eq!(eth0.body["host_dev_name"], "tcvm1");
}

#[test]
fn fail_closed_and_offline_guests_have_no_nic() {
    for (mode, slot) in [(NetworkMode::Inspected, None), (NetworkMode::None, Some(0))] {
        let fc = compile(
            &spec(
                IsolationBackend::Firecracker,
                VmDiskMode::EphemeralTmpfs,
                None,
            ),
            &ctx(mode, slot),
        );
        assert!(call(&fc, "/network-interfaces/eth0").is_none());
        assert!(fc.envelope.net.is_none());
        assert!(!fc.device_binds.contains(&"/dev/net/tun".to_owned()));
        let qemu = compile(
            &spec(
                IsolationBackend::QemuMicrovm,
                VmDiskMode::VirtioFsLive,
                None,
            ),
            &ctx(mode, slot),
        );
        assert!(!qemu.vmm_argv.iter().any(|a| a.contains("virtio-net")));
        assert!(qemu.tap_slot.is_none());
    }
}

#[test]
fn btrfs_overlay_uses_run_scoped_writable_clone() {
    let plan = compile(
        &spec(
            IsolationBackend::Firecracker,
            VmDiskMode::BtrfsCowOverlay,
            None,
        ),
        &ctx(NetworkMode::None, None),
    );
    let Some(rootfs) = call(&plan, "/drives/rootfs") else {
        panic!()
    };
    assert_eq!(
        rootfs.body["path_on_host"],
        "/var/lib/cordon/run/run-1.ext4"
    );
    assert_eq!(rootfs.body["is_read_only"], false);
    let Some(boot) = call(&plan, "/boot-source") else {
        panic!()
    };
    assert!(
        boot.body["boot_args"]
            .as_str()
            .is_some_and(|a| a.contains("root=/dev/vda rw"))
    );
}

#[test]
fn snapshot_restore_loads_named_snapshot_with_nic_override() {
    let plan = compile(
        &spec(
            IsolationBackend::Firecracker,
            VmDiskMode::SnapshotRestore,
            None,
        ),
        &ctx(NetworkMode::Inspected, Some(2)),
    );
    assert_eq!(plan.firecracker_api.len(), 1);
    let Some(load) = call(&plan, "/snapshot/load") else {
        panic!()
    };
    assert_eq!(
        load.body["snapshot_path"],
        "/var/lib/cordon/snapshots/warm-01/vm.snap"
    );
    assert_eq!(
        load.body["mem_backend"]["backend_path"],
        "/var/lib/cordon/snapshots/warm-01/vm.mem"
    );
    assert_eq!(load.body["network_overrides"][0]["host_dev_name"], "tcvm2");
    assert_eq!(load.body["resume_vm"], true);
}

#[test]
fn qemu_virtio_fs_plan_exports_the_sandbox_view_with_shared_memory() {
    let plan = compile(
        &spec(
            IsolationBackend::QemuMicrovm,
            VmDiskMode::VirtioFsLive,
            None,
        ),
        &ctx(NetworkMode::Inspected, Some(0)),
    );
    let joined = plan.vmm_argv.join(" ");
    assert!(joined.contains("-M microvm,"));
    assert!(joined.contains("-enable-kvm"));
    assert!(joined.contains("memory-backend-memfd,id=mem,size=1024M,share=on"));
    assert!(joined.contains("vhost-user-fs-device,chardev=fs0,tag=cordonroot"));
    assert!(joined.contains("rootfstype=virtiofs root=cordonroot rw"));
    assert!(joined.contains("ifname=tcvm0,script=no,downscript=no"));
    assert!(joined.contains("name=org.cordon.ctl"));
    assert!(!joined.contains("vhost-vsock"), "no host-global vsock CIDs");
    let Some(ref vfs) = plan.virtiofsd_argv else {
        panic!("virtiofsd missing")
    };
    assert!(vfs.contains(&"--shared-dir=/".to_owned()));
    assert!(vfs.contains(&"--sandbox=none".to_owned()));
    assert!(
        plan.envelope.ca_bundle_from.is_none(),
        "virtio-fs guest sees the CA overlay directly"
    );
}

#[test]
fn qemu_block_plan_applies_drive_throttling() {
    let limits = VmRateLimits {
        disk_iops: NonZeroU32::new(300),
        ..VmRateLimits::default()
    };
    let plan = compile(
        &spec(
            IsolationBackend::QemuMicrovm,
            VmDiskMode::EphemeralTmpfs,
            Some(limits),
        ),
        &ctx(NetworkMode::None, None),
    );
    let joined = plan.vmm_argv.join(" ");
    assert!(joined.contains("file=/var/lib/cordon/images/base.erofs,format=raw,if=none,readonly=on,throttling.iops-total=300"));
    assert!(joined.contains(&format!("file={WORKSPACE_IMAGE}")));
    assert!(plan.virtiofsd_argv.is_none());
}

#[test]
fn envelope_carries_ca_environment_and_guest_network() {
    let plan = compile(
        &spec(
            IsolationBackend::Firecracker,
            VmDiskMode::EphemeralTmpfs,
            None,
        ),
        &ctx(NetworkMode::Inspected, Some(0)),
    );
    let env = &plan.envelope.env;
    assert_eq!(
        env.get("CARGO_HTTP_CAINFO").map(String::as_str),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        env.get("CORDON_MICROVM").map(String::as_str),
        Some("firecracker")
    );
    assert_eq!(
        plan.envelope.ca_bundle_from.as_deref(),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    let Some(ref net) = plan.envelope.net else {
        panic!("net missing")
    };
    assert_eq!(
        (net.addr.as_str(), net.gw.as_str(), net.dns.as_str()),
        ("10.200.255.2/30", "10.200.255.1", "10.200.1.1")
    );
    assert!(plan.envelope.entropy_b64.is_none() && plan.envelope.uid.is_none());
    assert_eq!(plan.envelope.v, GuestExecEnvelope::VERSION);
    assert_eq!(plan.envelope.cwd, "/srv/ws");
}

#[test]
fn krun_and_empty_commands_are_rejected() {
    let raw = RawMicroVmSpec {
        backend: IsolationBackend::Krun,
        ..RawMicroVmSpec::default()
    };
    let Ok(krun) = MicroVmSpec::from_raw_with_home(&raw, None) else {
        panic!()
    };
    assert!(matches!(
        compile_microvm_plan(&krun, &ctx(NetworkMode::None, None)),
        Err(CordonError::UnsupportedVmOption(_))
    ));
    let mut empty = ctx(NetworkMode::None, None);
    empty.command.clear();
    assert!(matches!(
        compile_microvm_plan(
            &spec(
                IsolationBackend::Firecracker,
                VmDiskMode::EphemeralTmpfs,
                None
            ),
            &empty
        ),
        Err(CordonError::EmptyCommand)
    ));
}
