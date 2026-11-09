//! Gate 3.5 MicroVM plan compiler (QEMU `-M microvm` and Firecracker).
//!
//! Pure, deterministic compiler: it never spawns a VMM and links no hypervisor library. It emits
//! the VMM argv / Firecracker API sequence and the guest command envelope, and rewrites a Gate 1-3
//! [`SandboxLaunchPlan`] so the VMM itself runs confined by netns, AppArmor, and Bubblewrap.
//! See `docs/design/microvm-isolation.md`.

use std::fmt::Write as _;

use serde_json::json;

use crate::domain::{
    CordonProfile, DoctorCheck, FirecrackerApiCall, GuestExecEnvelope, GuestNetConfig,
    IsolationBackend, MicroVmCompileContext, MicroVmExecutionPlan, MicroVmSpec, NetworkMode,
    SandboxLaunchPlan, TapSlot, VmDiskMode, VmRateLimits,
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

fn guest_has_nic(ctx: &MicroVmCompileContext) -> Option<TapSlot> {
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
        // virtio-fs guests see the sandbox CA overlay directly; block guests get it forwarded.
        ca_bundle_from: ca_path.filter(|_| spec.disk_mode().is_block()),
        tty: ctx.tty,
        uid: None,
        gid: None,
        entropy_b64: None,
    }
}

fn compile_qemu(
    spec: &MicroVmSpec,
    ctx: &MicroVmCompileContext,
) -> (Vec<String>, Option<Vec<String>>) {
    let s = |v: &str| v.to_owned();
    let mem = spec.memory_mib().get();
    let mut argv = vec![
        s("qemu-system-x86_64"),
        s("-M"),
        s("microvm,x-option-roms=off,pit=off,pic=off,isa-serial=on,rtc=off"),
        s("-enable-kvm"),
        s("-cpu"),
        s("host"),
        s("-smp"),
        spec.vcpus().get().to_string(),
        s("-m"),
        format!("{mem}M"),
        s("-nodefaults"),
        s("-no-user-config"),
        s("-nographic"),
        s("-no-reboot"),
        s("-kernel"),
        spec.kernel_image()
            .map_or_else(String::new, |k| k.as_str().to_owned()),
        s("-append"),
        kernel_cmdline(spec, "ttyS0", "virtio-serial"),
        s("-serial"),
        s("stdio"),
    ];

    let mut virtiofsd = None;
    if spec.disk_mode() == VmDiskMode::VirtioFsLive {
        argv.extend([
            s("-object"),
            format!("memory-backend-memfd,id=mem,size={mem}M,share=on"),
            s("-numa"),
            s("node,memdev=mem"),
            s("-chardev"),
            format!("socket,id=fs0,path={VIRTIOFSD_SOCKET}"),
            s("-device"),
            format!("vhost-user-fs-device,chardev=fs0,tag={VIRTIOFS_ROOT_TAG}"),
        ]);
        // virtiofsd exports "/" as seen inside Bubblewrap, so the guest inherits the exact Gate 3
        // policy (read-only root, EC-01 read-only .git, credential masks, CA overlay).
        virtiofsd = Some(vec![
            s("virtiofsd"),
            format!("--socket-path={VIRTIOFSD_SOCKET}"),
            s("--shared-dir=/"),
            s("--sandbox=none"),
            s("--cache=auto"),
            s("--announce-submounts"),
        ]);
    } else {
        let throttle = qemu_drive_throttling(spec.rate_limits());
        let rootfs_ro = spec.disk_mode() != VmDiskMode::BtrfsCowOverlay;
        if let Some(rootfs) = rootfs_host_path(spec, &ctx.run_id) {
            argv.extend([
                s("-drive"),
                format!(
                    "id=rootfs,file={rootfs},format=raw,if=none,readonly={}{throttle}",
                    if rootfs_ro { "on" } else { "off" }
                ),
                s("-device"),
                s("virtio-blk-device,drive=rootfs"),
            ]);
        }
        argv.extend([
            s("-drive"),
            format!("id=workspace,file={WORKSPACE_IMAGE},format=raw,if=none,readonly=on{throttle}"),
            s("-device"),
            s("virtio-blk-device,drive=workspace"),
        ]);
    }

    if let Some(slot) = guest_has_nic(ctx) {
        argv.extend([
            s("-netdev"),
            format!(
                "tap,id=net0,ifname={},script=no,downscript=no",
                slot.device()
            ),
            s("-device"),
            s("virtio-net-device,netdev=net0"),
        ]);
    }
    argv.extend([
        s("-device"),
        s("virtio-serial-device"),
        s("-chardev"),
        format!("socket,id=ctl,path={QEMU_CONTROL_SOCKET},server=on,wait=off"),
        s("-device"),
        format!("virtserialport,chardev=ctl,name={GUEST_CONTROL_SERIAL_NAME}"),
        s("-object"),
        s("rng-random,id=rng0,filename=/dev/urandom"),
        s("-device"),
        s("virtio-rng-device,rng=rng0"),
    ]);
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
    let argv = vec![
        "firecracker".to_owned(),
        "--api-sock".to_owned(),
        FC_API_SOCKET.to_owned(),
        "--id".to_owned(),
        format!("cordon-{}", ctx.run_id),
        "--level".to_owned(),
        "Warning".to_owned(),
    ];
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
    let with_limiter = |mut body: serde_json::Value| {
        if let Some(ref limiter) = disk_limiter {
            body["rate_limiter"] = limiter.clone();
        }
        body
    };

    let mut calls = vec![
        put(
            "/machine-config",
            json!({
                "vcpu_count": spec.vcpus().get(),
                "mem_size_mib": spec.memory_mib().get(),
                "smt": false,
            }),
        ),
        put(
            "/boot-source",
            json!({
                "kernel_image_path": spec.kernel_image().map(|k| k.as_str().to_owned()),
                "boot_args": format!("{} pci=off", kernel_cmdline(spec, "ttyS0", "vsock")),
            }),
        ),
    ];
    if let Some(rootfs) = rootfs_host_path(spec, &ctx.run_id) {
        calls.push(put(
            "/drives/rootfs",
            with_limiter(json!({
                "drive_id": "rootfs",
                "path_on_host": rootfs,
                "is_root_device": true,
                "is_read_only": spec.disk_mode() != VmDiskMode::BtrfsCowOverlay,
            })),
        ));
    }
    calls.push(put(
        "/drives/workspace",
        with_limiter(json!({
            "drive_id": "workspace",
            "path_on_host": WORKSPACE_IMAGE,
            "is_root_device": false,
            "is_read_only": true,
        })),
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

fn cordon_executable() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .map_or_else(|| "cordon".to_owned(), |p| p.to_string_lossy().into_owned())
}

/// Rewrites a compiled Gate 1-3 [`SandboxLaunchPlan`] so its Bubblewrap tail runs the Gate 3.5
/// supervisor (`cordon vm supervise`) instead of the workload, binds only the device nodes and
/// images the VMM needs, re-attaches the `cordon_<slug>_microvm` AppArmor profile, and records
/// the compiled [`MicroVmExecutionPlan`].
///
/// The display plan is compiled for tap slot 0; the supervisor picks a free slot at launch (or
/// boots the guest without a NIC when the netns/tap pool is unavailable, preserving fail-closed).
pub fn attach_microvm_plan(
    plan: &mut SandboxLaunchPlan,
    profile: &CordonProfile,
    spec: &MicroVmSpec,
    run_id: &str,
) -> Result<(), CordonError> {
    spec.validate_for_profile(profile)?;
    let Some(chdir_idx) = plan.bwrap_argv.iter().position(|a| a == "--chdir") else {
        return Err(CordonError::InvalidInput(
            "launch plan has no --chdir tail".to_owned(),
        ));
    };
    let dash_idx = chdir_idx + 2;
    if plan.bwrap_argv.get(dash_idx).map(String::as_str) != Some("--") {
        return Err(CordonError::InvalidInput(
            "launch plan tail is not '--chdir <ws> -- <cmd>'".to_owned(),
        ));
    }
    let command: Vec<String> = plan.bwrap_argv[dash_idx + 1..].to_vec();
    let networked = matches!(
        profile.network_mode,
        NetworkMode::Inspected | NetworkMode::AllowlistOnly
    );
    let ctx = MicroVmCompileContext {
        workspace: plan.canonical_workspace.clone(),
        command: command.clone(),
        env: plan.env_overrides.clone(),
        network_mode: profile.network_mode,
        dns: profile.host_veth_ip.clone(),
        tap_slot: if networked {
            Some(TapSlot::new(0)?)
        } else {
            None
        },
        run_id: run_id.to_owned(),
        tty: true,
    };
    let vm_plan = compile_microvm_plan(spec, &ctx)?;

    // Gate 3 additions, inserted before the tail so they win over earlier mounts.
    let mut extra: Vec<String> = Vec::new();
    for dev in &vm_plan.device_binds {
        extra.extend(["--dev-bind".to_owned(), dev.clone(), dev.clone()]);
    }
    extra.extend(["--dir".to_owned(), VM_RUNTIME_DIR.to_owned()]);
    if let Some(kernel) = spec.kernel_image() {
        extra.extend([
            "--ro-bind".to_owned(),
            kernel.as_str().to_owned(),
            kernel.as_str().to_owned(),
        ]);
    }
    if let Some(rootfs) = spec.rootfs_image() {
        extra.extend([
            "--ro-bind".to_owned(),
            rootfs.as_str().to_owned(),
            rootfs.as_str().to_owned(),
        ]);
    }
    if spec.disk_mode() == VmDiskMode::BtrfsCowOverlay {
        extra.extend([
            "--bind".to_owned(),
            OVERLAY_DIR.to_owned(),
            OVERLAY_DIR.to_owned(),
        ]);
    }
    if let Some(snapshot) = spec.snapshot() {
        let dir = snapshot.directory();
        extra.extend(["--ro-bind".to_owned(), dir.clone(), dir]);
    }

    let spec_json = serde_json::to_string(spec)?;
    let mut supervisor = vec![
        cordon_executable(),
        "vm".to_owned(),
        "supervise".to_owned(),
        "--spec-json".to_owned(),
        spec_json,
        "--run-id".to_owned(),
        run_id.to_owned(),
        "--tap".to_owned(),
        if networked { "auto" } else { "none" }.to_owned(),
        "--forward-env".to_owned(),
        plan.env_overrides
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(","),
        "--".to_owned(),
    ];
    supervisor.extend(command);

    let mut bwrap = plan.bwrap_argv[..chdir_idx].to_vec();
    bwrap.extend(extra);
    bwrap.extend(plan.bwrap_argv[chdir_idx..=dash_idx].iter().cloned());
    bwrap.extend(supervisor);
    plan.bwrap_argv = bwrap;

    let aa_prefix = crate::sandbox::aa_exec_microvm_confinement_prefix(&plan.profile_name);
    let mut full = plan.netns_exec_argv.clone();
    full.extend(aa_prefix.iter().cloned());
    full.extend(plan.bwrap_argv.iter().cloned());
    plan.full_argv = full;

    let gate2 = if aa_prefix.is_empty() {
        "Gate 2: AppArmor 4.0 Mandatory Access Control LSM (not applied: aa-exec or a loaded cordon_<slug>_microvm profile unavailable)".to_owned()
    } else {
        format!(
            "Gate 2: AppArmor 4.0 Mandatory Access Control LSM (attached via {})",
            aa_prefix.join(" ")
        )
    };
    let mut rewritten_gates = Vec::with_capacity(plan.gates_applied.len() + 1);
    for gate in plan.gates_applied.drain(..) {
        if gate.starts_with("Gate 2:") {
            rewritten_gates.push(gate2.clone());
        } else if gate.starts_with("Gate 4:") {
            rewritten_gates.push(
                "Gate 4: Confined Workload Process (guest kernel, cordon-guest-init)".to_owned(),
            );
        } else {
            let is_gate3 = gate.starts_with("Gate 3:");
            rewritten_gates.push(gate);
            if is_gate3 {
                rewritten_gates.push(format!(
                    "Gate 3.5: KVM MicroVM ({}, {}, {} vCPU, {} MiB, {})",
                    spec.backend(),
                    spec.disk_mode(),
                    spec.vcpus(),
                    spec.memory_mib(),
                    if networked {
                        "tap pool -> netns MASQUERADE"
                    } else {
                        "no NIC"
                    }
                ));
            }
        }
    }
    plan.gates_applied = rewritten_gates;
    plan.microvm = Some(vm_plan);
    Ok(())
}

fn device_rw_accessible(path: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Returns the filesystem type of the mount containing `path` (longest mount-point prefix in
/// `/proc/self/mountinfo`), resolving the nearest existing ancestor first.
pub fn filesystem_type_of(path: &str, mountinfo: &str) -> Option<String> {
    let mut probe = std::path::PathBuf::from(path);
    while !probe.exists() {
        if !probe.pop() {
            break;
        }
    }
    let target = std::fs::canonicalize(&probe).unwrap_or(probe);
    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        let (Some(mount_point), Some(fstype)) = (fields.get(4), fields.get(sep + 1)) else {
            continue;
        };
        let mount_point = mount_point.replace("\\040", " ");
        if target.starts_with(&mount_point)
            && best
                .as_ref()
                .is_none_or(|(len, _)| mount_point.len() >= *len)
        {
            best = Some((mount_point.len(), (*fstype).to_owned()));
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// Non-required `cordon doctor` probes for Gate 3.5 readiness (they never affect `healthy`).
pub fn microvm_doctor_checks(find_binary: impl Fn(&str) -> Option<String>) -> Vec<DoctorCheck> {
    let mut checks = Vec::with_capacity(4);

    let kvm = device_rw_accessible("/dev/kvm");
    checks.push(DoctorCheck {
        name: "kvm_device_accessible".to_owned(),
        passed: kvm.is_ok(),
        required: false,
        detail: match kvm {
            Ok(()) => "/dev/kvm is readable and writable (Gate 3.5 MicroVM available)".to_owned(),
            Err(e) => format!("/dev/kvm not accessible ({e}); MicroVM backends unavailable"),
        },
    });

    let tun = device_rw_accessible("/dev/net/tun");
    checks.push(DoctorCheck {
        name: "tun_device_accessible".to_owned(),
        passed: tun.is_ok(),
        required: false,
        detail: match tun {
            Ok(()) => "/dev/net/tun accessible for the per-netns tcvm tap pool".to_owned(),
            Err(e) => {
                format!("/dev/net/tun not accessible ({e}); MicroVM guests boot without a NIC")
            }
        },
    });

    let found: Vec<(&str, Option<String>)> = ["firecracker", "qemu-system-x86_64", "virtiofsd"]
        .into_iter()
        .map(|b| (b, find_binary(b)))
        .collect();
    let has = |name: &str| found.iter().any(|(b, p)| *b == name && p.is_some());
    let engine_ready = has("firecracker") || (has("qemu-system-x86_64") && has("virtiofsd"));
    let detail = found
        .iter()
        .map(|(b, p)| format!("{b}={}", p.as_deref().unwrap_or("missing")))
        .collect::<Vec<_>>()
        .join(", ");
    checks.push(DoctorCheck {
        name: "microvm_vmm_binaries".to_owned(),
        passed: engine_ready,
        required: false,
        detail,
    });

    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let fstype = filesystem_type_of("/var/lib/cordon", &mountinfo);
    let btrfs = fstype.as_deref() == Some("btrfs");
    checks.push(DoctorCheck {
        name: "btrfs_reflink_support".to_owned(),
        passed: btrfs,
        required: false,
        detail: if btrfs {
            "/var/lib/cordon is on Btrfs (instant reflink overlays for btrfs-cow-overlay)".to_owned()
        } else {
            format!(
                "/var/lib/cordon is on {}; btrfs-cow-overlay unavailable (ephemeral-tmpfs still works)",
                fstype.as_deref().unwrap_or("an unknown filesystem")
            )
        },
    });
    checks
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use std::collections::BTreeMap;

    use super::*;
    use crate::domain::{CanonicalPath, RawMicroVmSpec, VmRateLimits};
    use crate::profiles::get_profile;
    use crate::sandbox::compile_launch_plan;

    const KERNEL: &str = "/var/lib/cordon/kernels/vmlinux-microvm";

    fn spec(
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

    fn ctx(network_mode: NetworkMode, slot: Option<u8>) -> MicroVmCompileContext {
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

    fn workspace_with_git() -> std::path::PathBuf {
        let ws = std::env::temp_dir().join(format!("cordon-vm-ws-{}", uuid::Uuid::new_v4()));
        assert!(std::fs::create_dir_all(ws.join(".git/hooks")).is_ok());
        ws
    }

    fn attached(profile_name: &str, s: &MicroVmSpec) -> (SandboxLaunchPlan, std::path::PathBuf) {
        let ws = workspace_with_git();
        let Ok(profile) = get_profile(profile_name) else {
            panic!()
        };
        let cmd = vec!["opencode".to_owned()];
        let Ok(mut plan) = compile_launch_plan(&profile, &ws, &cmd, &[], &[]) else {
            panic!()
        };
        if let Err(e) = attach_microvm_plan(&mut plan, &profile, s, "run-1") {
            panic!("attach failed: {e}");
        }
        (plan, ws)
    }

    #[test]
    fn attach_keeps_ec01_git_binds_before_the_vmm_supervisor() {
        let s = spec(
            IsolationBackend::QemuMicrovm,
            VmDiskMode::VirtioFsLive,
            None,
        );
        let (plan, ws) = attached("ai-agent", &s);
        let argv = &plan.bwrap_argv;
        let canon = std::fs::canonicalize(&ws)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let git = format!("{canon}/.git");
        let git_bind = argv
            .windows(3)
            .position(|w| w[0] == "--ro-bind-try" && w[1] == git && w[2] == git);
        let supervise = argv
            .windows(2)
            .position(|w| w[0] == "vm" && w[1] == "supervise");
        assert!(
            matches!((git_bind, supervise), (Some(g), Some(v)) if g < v),
            "EC-01 .git RO bind must precede the VMM"
        );
        let chdir = argv.iter().position(|a| a == "--chdir");
        let kvm = argv
            .windows(3)
            .position(|w| w[0] == "--dev-bind" && w[1] == "/dev/kvm");
        assert!(matches!((kvm, chdir), (Some(k), Some(c)) if k < c));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--dir" && w[1] == VM_RUNTIME_DIR)
        );
        assert!(
            argv.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == KERNEL)
        );
        let tail_start = supervise.unwrap_or(0);
        assert_eq!(argv.last().map(String::as_str), Some("opencode"));
        assert!(argv[tail_start..].iter().any(|a| a == "--tap"));
        assert!(plan.microvm.is_some());
        assert!(
            plan.gates_applied
                .iter()
                .any(|g| g.starts_with("Gate 3.5: KVM MicroVM (qemu-microvm, virtio-fs-live"))
        );
        assert!(plan.full_argv.ends_with(&plan.bwrap_argv));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn native_plans_never_receive_kvm_or_tun() {
        let ws = workspace_with_git();
        for profile in crate::profiles::list_profiles() {
            let Ok(plan) = compile_launch_plan(&profile, &ws, &["true".to_owned()], &[], &[])
            else {
                panic!()
            };
            assert!(
                !plan
                    .bwrap_argv
                    .iter()
                    .any(|a| a == "/dev/kvm" || a == "/dev/net/tun")
            );
            assert!(plan.microvm.is_none());
            let json = serde_json::to_value(&plan).unwrap_or_default();
            assert!(
                json.get("microvm").is_none(),
                "native plan JSON must be unchanged"
            );
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn attach_for_offline_profile_requests_no_tap() {
        let s = spec(
            IsolationBackend::Firecracker,
            VmDiskMode::EphemeralTmpfs,
            None,
        );
        let (plan, ws) = attached("airgapped", &s);
        let argv = &plan.bwrap_argv;
        assert!(argv.windows(2).any(|w| w[0] == "--tap" && w[1] == "none"));
        assert!(!argv.iter().any(|a| a == "/dev/net/tun"));
        assert!(
            argv.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == "/var/lib/cordon/images/base.erofs")
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn attach_rejects_gui_profiles() {
        let ws = workspace_with_git();
        let Ok(profile) = get_profile("gui-desktop") else {
            panic!()
        };
        let Ok(mut plan) = compile_launch_plan(&profile, &ws, &["true".to_owned()], &[], &[])
        else {
            panic!()
        };
        let s = spec(
            IsolationBackend::Firecracker,
            VmDiskMode::EphemeralTmpfs,
            None,
        );
        assert!(matches!(
            attach_microvm_plan(&mut plan, &profile, &s, "run-1"),
            Err(CordonError::UnsupportedVmOption(_))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn mountinfo_longest_prefix_selects_the_filesystem() {
        let mountinfo = "22 1 0:21 / / rw,relatime - ext4 /dev/sda1 rw\n\
                         40 22 0:35 / /var rw,relatime - btrfs /dev/sda2 rw\n";
        assert_eq!(
            filesystem_type_of("/var/lib/cordon", mountinfo).as_deref(),
            Some("btrfs")
        );
        assert_eq!(
            filesystem_type_of("/etc", mountinfo).as_deref(),
            Some("ext4")
        );
        assert_eq!(filesystem_type_of("/etc", "garbage line"), None);
    }

    #[test]
    fn microvm_doctor_checks_are_never_required() {
        let checks = microvm_doctor_checks(|b| {
            (b == "firecracker").then(|| "/usr/bin/firecracker".to_owned())
        });
        let names: Vec<&str> = checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "kvm_device_accessible",
                "tun_device_accessible",
                "microvm_vmm_binaries",
                "btrfs_reflink_support"
            ]
        );
        assert!(checks.iter().all(|c| !c.required));
        assert!(
            checks
                .iter()
                .any(|c| c.name == "microvm_vmm_binaries" && c.passed)
        );
        let none = microvm_doctor_checks(|_| None);
        assert!(none.iter().any(|c| c.name == "microvm_vmm_binaries"
            && !c.passed
            && c.detail.contains("virtiofsd=missing")));
        let qemu_only = microvm_doctor_checks(|b| (b == "qemu-system-x86_64").then(String::new));
        assert!(
            qemu_only
                .iter()
                .any(|c| c.name == "microvm_vmm_binaries" && !c.passed),
            "QEMU needs virtiofsd"
        );
    }
}
