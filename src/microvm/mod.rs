//! Gate 3.5 MicroVM plan compiler (QEMU `-M microvm` and Firecracker).
//!
//! Pure, deterministic compiler: it never spawns a VMM and links no hypervisor library. It emits
//! the VMM argv / Firecracker API sequence and the guest command envelope, and rewrites a Gate 1-3
//! [`SandboxLaunchPlan`] so the VMM itself runs confined by netns, AppArmor, and Bubblewrap.
//! See `docs/design/microvm-isolation.md`.

mod attach;
#[cfg(test)]
mod attach_tests;
#[cfg(test)]
mod tests;

use std::fmt::Write as _;

use serde_json::json;

pub use attach::{attach_microvm_plan, filesystem_type_of, microvm_doctor_checks};

use crate::domain::{
    FirecrackerApiCall, GuestExecEnvelope, GuestNetConfig, IsolationBackend, MicroVmCompileContext,
    MicroVmExecutionPlan, MicroVmSpec, NetworkMode, TapSlot, VmDiskMode, VmRateLimits,
};
use crate::error::CordonError;
use crate::ports::MicroVmCompilerPort;

/// Per-launch runtime directory inside the Gate 3 mount namespace (on the bwrap `/tmp` tmpfs, so
/// it is private to the sandbox and never touches the host filesystem).
pub const VM_RUNTIME_DIR: &str = "/tmp/cordon-vm";
/// Firecracker API socket.
pub const FC_API_SOCKET: &str = "/tmp/cordon-vm/fc.sock";
/// Firecracker hybrid vsock Unix socket (host side of the guest control channel).
pub const FC_VSOCK_SOCKET: &str = "/tmp/cordon-vm/vsock.sock";
/// QEMU virtio-serial control socket.
pub const QEMU_CONTROL_SOCKET: &str = "/tmp/cordon-vm/ctl.sock";
/// virtiofsd vhost-user socket.
pub const VIRTIOFSD_SOCKET: &str = "/tmp/cordon-vm/fs.sock";
/// Packed read-only workspace image for block-device guests. Always padded to the workspace cap
/// so its virtio-blk capacity is constant (required for snapshot restore).
pub const WORKSPACE_IMAGE: &str = "/tmp/cordon-vm/workspace.img";
/// Host directory holding run-scoped Btrfs reflink overlay clones.
pub const OVERLAY_DIR: &str = "/var/lib/cordon/run";
/// Guest PID 1 (`cordon-guest-init`), present at this path in the host view and in images.
pub const GUEST_INIT_PATH: &str = "/usr/lib/cordon/cordon-guest-init";
/// Guest vsock port `cordon-guest-init` listens on (Firecracker).
pub const GUEST_CONTROL_VSOCK_PORT: u32 = 1024;
/// virtio-serial port name `cordon-guest-init` opens (QEMU).
pub const GUEST_CONTROL_SERIAL_NAME: &str = "org.cordon.ctl";
/// virtio-fs tag of the exported sandbox root.
pub const VIRTIOFS_ROOT_TAG: &str = "cordonroot";
/// Firecracker guest CID (hybrid vsock is per-VMM, so a fixed CID never collides).
pub const FC_GUEST_CID: u32 = 3;

fn firecracker_bucket(size: u64) -> serde_json::Value {
    json!({ "size": size, "refill_time": 1000 })
}

/// Firecracker block-device token bucket (`disk_bandwidth_mib_s` -> bytes, `disk_iops` -> ops).
pub fn firecracker_disk_rate_limiter(limits: &VmRateLimits) -> Option<serde_json::Value> {
    if !limits.has_disk_limits() {
        return None;
    }
    let mut limiter = serde_json::Map::new();
    if let Some(mib) = limits.disk_bandwidth_mib_s {
        limiter.insert(
            "bandwidth".to_owned(),
            firecracker_bucket(u64::from(mib.get()) * 1_048_576),
        );
    }
    if let Some(iops) = limits.disk_iops {
        limiter.insert("ops".to_owned(), firecracker_bucket(u64::from(iops.get())));
    }
    Some(serde_json::Value::Object(limiter))
}

/// Firecracker network token bucket (`net_bandwidth_mbit_s` -> bytes per second).
pub fn firecracker_net_rate_limiter(limits: &VmRateLimits) -> Option<serde_json::Value> {
    limits
        .net_bandwidth_mbit_s
        .map(|mbit| json!({ "bandwidth": firecracker_bucket(u64::from(mbit.get()) * 125_000) }))
}

fn qemu_drive_throttling(limits: Option<&VmRateLimits>) -> String {
    let mut out = String::new();
    if let Some(limits) = limits {
        if let Some(iops) = limits.disk_iops {
            let _ = write!(out, ",throttling.iops-total={}", iops.get());
        }
        if let Some(mib) = limits.disk_bandwidth_mib_s {
            let _ = write!(
                out,
                ",throttling.bps-total={}",
                u64::from(mib.get()) * 1_048_576
            );
        }
    }
    out
}

pub(super) fn guest_has_nic(ctx: &MicroVmCompileContext) -> Option<TapSlot> {
    match ctx.network_mode {
        NetworkMode::Inspected | NetworkMode::AllowlistOnly => ctx.tap_slot,
        NetworkMode::Direct | NetworkMode::None => None,
    }
}

fn rootfs_host_path(spec: &MicroVmSpec, run_id: &str) -> Option<String> {
    match spec.disk_mode() {
        VmDiskMode::BtrfsCowOverlay => Some(format!("{OVERLAY_DIR}/{run_id}.ext4")),
        VmDiskMode::EphemeralTmpfs => spec.rootfs_image().map(|p| p.as_str().to_owned()),
        VmDiskMode::VirtioFsLive | VmDiskMode::SnapshotRestore => None,
    }
}

fn kernel_cmdline(spec: &MicroVmSpec, console: &str, control: &str) -> String {
    let root = match spec.disk_mode() {
        VmDiskMode::VirtioFsLive => format!("rootfstype=virtiofs root={VIRTIOFS_ROOT_TAG} rw"),
        VmDiskMode::BtrfsCowOverlay => "root=/dev/vda rw".to_owned(),
        VmDiskMode::EphemeralTmpfs | VmDiskMode::SnapshotRestore => "root=/dev/vda ro".to_owned(),
    };
    format!(
        "console={console} quiet loglevel=0 reboot=k panic=-1 {root} init={GUEST_INIT_PATH} cordon.disk_mode={} cordon.ctl={control}",
        spec.disk_mode().as_str()
    )
}

fn build_envelope(spec: &MicroVmSpec, ctx: &MicroVmCompileContext) -> GuestExecEnvelope {
    let mut env = ctx.env.clone();
    env.insert(
        "CORDON_MICROVM".to_owned(),
        spec.backend().as_str().to_owned(),
    );
    let ca_path = env.get("SSL_CERT_FILE").cloned();
    if let Some(ref ca) = ca_path {
        env.insert("CARGO_HTTP_CAINFO".to_owned(), ca.clone());
    }
    let net = guest_has_nic(ctx).map(|slot| GuestNetConfig {
        addr: slot.guest_cidr(),
        gw: slot.gateway(),
        dns: ctx.dns.clone(),
    });
    GuestExecEnvelope {
        v: GuestExecEnvelope::VERSION,
        argv: ctx.command.clone(),
        cwd: ctx.workspace.as_str().to_owned(),
        env,
        net,
        ca_bundle_from: ca_path.filter(|_| spec.disk_mode().is_block()),
        tty: ctx.tty,
        uid: None,
        gid: None,
        entropy_b64: None,
    }
}

fn push_words(argv: &mut Vec<String>, words: &str) {
    argv.extend(words.split_whitespace().map(str::to_owned));
}

fn compile_qemu(
    spec: &MicroVmSpec,
    ctx: &MicroVmCompileContext,
) -> (Vec<String>, Option<Vec<String>>) {
    let mem = format!("{}M", spec.memory_mib().get());
    let smp = spec.vcpus().get();
    let kernel = spec
        .kernel_image()
        .map_or_else(String::new, |k| k.as_str().to_owned());
    let mut argv = Vec::new();
    push_words(
        &mut argv,
        &format!(
            "qemu-system-x86_64 -M microvm,x-option-roms=off,pit=off,pic=off,isa-serial=on,rtc=off -enable-kvm -cpu host -smp {smp} -m {mem} -nodefaults -no-user-config -nographic -no-reboot"
        ),
    );
    argv.extend([
        "-kernel".to_owned(),
        kernel,
        "-append".to_owned(),
        kernel_cmdline(spec, "ttyS0", "virtio-serial"),
        "-serial".to_owned(),
        "stdio".to_owned(),
    ]);

    let mut virtiofsd = None;
    if spec.disk_mode() == VmDiskMode::VirtioFsLive {
        push_words(
            &mut argv,
            &format!(
                "-object memory-backend-memfd,id=mem,size={mem},share=on -numa node,memdev=mem -chardev socket,id=fs0,path={VIRTIOFSD_SOCKET} -device vhost-user-fs-device,chardev=fs0,tag={VIRTIOFS_ROOT_TAG}"
            ),
        );
        let mut vfs = Vec::new();
        push_words(
            &mut vfs,
            &format!(
                "virtiofsd --socket-path={VIRTIOFSD_SOCKET} --shared-dir=/ --sandbox=none --cache=auto --announce-submounts"
            ),
        );
        virtiofsd = Some(vfs);
    } else {
        let thr = qemu_drive_throttling(spec.rate_limits());
        let ro = if spec.disk_mode() == VmDiskMode::BtrfsCowOverlay {
            "off"
        } else {
            "on"
        };
        if let Some(rootfs) = rootfs_host_path(spec, &ctx.run_id) {
            push_words(
                &mut argv,
                &format!(
                    "-drive id=rootfs,file={rootfs},format=raw,if=none,readonly={ro}{thr} -device virtio-blk-device,drive=rootfs"
                ),
            );
        }
        push_words(
            &mut argv,
            &format!(
                "-drive id=workspace,file={WORKSPACE_IMAGE},format=raw,if=none,readonly=on{thr} -device virtio-blk-device,drive=workspace"
            ),
        );
    }

    if let Some(slot) = guest_has_nic(ctx) {
        let dev = slot.device();
        push_words(
            &mut argv,
            &format!(
                "-netdev tap,id=net0,ifname={dev},script=no,downscript=no -device virtio-net-device,netdev=net0"
            ),
        );
    }
    push_words(
        &mut argv,
        &format!(
            "-device virtio-serial-device -chardev socket,id=ctl,path={QEMU_CONTROL_SOCKET},server=on,wait=off -device virtserialport,chardev=ctl,name={GUEST_CONTROL_SERIAL_NAME} -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-device,rng=rng0"
        ),
    );
    (argv, virtiofsd)
}

fn put(path: &str, body: serde_json::Value) -> FirecrackerApiCall {
    FirecrackerApiCall {
        method: "PUT".to_owned(),
        path: path.to_owned(),
        body,
    }
}

fn compile_firecracker(
    spec: &MicroVmSpec,
    ctx: &MicroVmCompileContext,
) -> (Vec<String>, Vec<FirecrackerApiCall>) {
    let mut argv = Vec::new();
    push_words(
        &mut argv,
        &format!(
            "firecracker --api-sock {FC_API_SOCKET} --id cordon-{} --level Warning",
            ctx.run_id
        ),
    );
    let nic = guest_has_nic(ctx);

    if let Some(snapshot) = spec.snapshot() {
        let dir = snapshot.directory();
        let mut body = json!({
            "snapshot_path": format!("{dir}/vm.snap"),
            "mem_backend": { "backend_type": "File", "backend_path": format!("{dir}/vm.mem") },
            "resume_vm": true,
        });
        if let Some(slot) = nic {
            body["network_overrides"] =
                json!([{ "iface_id": "eth0", "host_dev_name": slot.device() }]);
        }
        return (argv, vec![put("/snapshot/load", body)]);
    }

    let disk_limiter = spec.rate_limits().and_then(firecracker_disk_rate_limiter);
    let net_limiter = spec.rate_limits().and_then(firecracker_net_rate_limiter);
    let drive = |id: &str, path: &str, root: bool, ro: bool| {
        let mut body = json!({
            "drive_id": id,
            "path_on_host": path,
            "is_root_device": root,
            "is_read_only": ro,
        });
        if let Some(ref limiter) = disk_limiter {
            body["rate_limiter"] = limiter.clone();
        }
        body
    };

    let kernel_path = spec.kernel_image().map(|k| k.as_str().to_owned());
    let boot_args = format!("{} pci=off", kernel_cmdline(spec, "ttyS0", "vsock"));
    let mut calls = vec![
        put(
            "/machine-config",
            json!({ "vcpu_count": spec.vcpus().get(), "mem_size_mib": spec.memory_mib().get(), "smt": false }),
        ),
        put(
            "/boot-source",
            json!({ "kernel_image_path": kernel_path, "boot_args": boot_args }),
        ),
    ];
    if let Some(rootfs) = rootfs_host_path(spec, &ctx.run_id) {
        let ro = spec.disk_mode() != VmDiskMode::BtrfsCowOverlay;
        calls.push(put("/drives/rootfs", drive("rootfs", &rootfs, true, ro)));
    }
    calls.push(put(
        "/drives/workspace",
        drive("workspace", WORKSPACE_IMAGE, false, true),
    ));
    if let Some(slot) = nic {
        let mut body = json!({ "iface_id": "eth0", "host_dev_name": slot.device() });
        if let Some(ref limiter) = net_limiter {
            body["rx_rate_limiter"] = limiter.clone();
            body["tx_rate_limiter"] = limiter.clone();
        }
        calls.push(put("/network-interfaces/eth0", body));
    }
    calls.push(put(
        "/vsock",
        json!({ "guest_cid": FC_GUEST_CID, "uds_path": FC_VSOCK_SOCKET }),
    ));
    calls.push(put("/entropy", json!({})));
    calls.push(put("/actions", json!({ "action_type": "InstanceStart" })));
    (argv, calls)
}

/// Compiles a deterministic [`MicroVmExecutionPlan`] for `spec`.
pub fn compile_microvm_plan(
    spec: &MicroVmSpec,
    ctx: &MicroVmCompileContext,
) -> Result<MicroVmExecutionPlan, CordonError> {
    if ctx.command.is_empty() {
        return Err(CordonError::EmptyCommand);
    }
    let nic = guest_has_nic(ctx);
    let mut device_binds = vec!["/dev/kvm".to_owned()];
    if nic.is_some() {
        device_binds.push("/dev/net/tun".to_owned());
    }
    let (vmm_argv, virtiofsd_argv, firecracker_api, control_socket) = match spec.backend() {
        IsolationBackend::QemuMicrovm => {
            let (argv, vfs) = compile_qemu(spec, ctx);
            (argv, vfs, Vec::new(), QEMU_CONTROL_SOCKET)
        }
        IsolationBackend::Firecracker => {
            let (argv, calls) = compile_firecracker(spec, ctx);
            (argv, None, calls, FC_VSOCK_SOCKET)
        }
        IsolationBackend::Krun => {
            return Err(CordonError::UnsupportedVmOption(
                "krun launcher not selected; use qemu-microvm or firecracker".to_owned(),
            ));
        }
        IsolationBackend::NativeBwrap => {
            return Err(CordonError::InvalidInput(
                "native-bwrap has no MicroVM plan".to_owned(),
            ));
        }
    };
    Ok(MicroVmExecutionPlan {
        backend: spec.backend(),
        disk_mode: spec.disk_mode(),
        spec: spec.clone(),
        run_id: ctx.run_id.clone(),
        tap_slot: nic,
        virtiofsd_argv,
        vmm_argv,
        firecracker_api,
        device_binds,
        control_socket: control_socket.to_owned(),
        envelope: build_envelope(spec, ctx),
    })
}

/// Default stateless implementation of [`MicroVmCompilerPort`].
#[derive(Debug, Default, Clone, Copy)]
pub struct MicroVmCompiler;

impl MicroVmCompilerPort for MicroVmCompiler {
    fn compile_microvm_plan(
        &self,
        spec: &MicroVmSpec,
        ctx: &MicroVmCompileContext,
    ) -> Result<MicroVmExecutionPlan, CordonError> {
        compile_microvm_plan(spec, ctx)
    }
}
