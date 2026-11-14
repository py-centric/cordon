//! Gate 1-3 launch plan rewriting and `cordon doctor` readiness probes for Gate 3.5 MicroVMs.

use crate::domain::{
    CordonProfile, DoctorCheck, MicroVmCompileContext, MicroVmSpec, NetworkMode, SandboxLaunchPlan,
    TapSlot, VmDiskMode,
};
use crate::error::CordonError;

use super::{OVERLAY_DIR, VM_RUNTIME_DIR, compile_microvm_plan};

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
    use super::*;
    use crate::domain::RawMicroVmSpec;
    use crate::ports::SandboxCompilerPort;
    use crate::profiles::get_profile;
    use crate::sandbox::BwrapSandboxCompiler;

    #[test]
    fn attach_microvm_plan_rejects_malformed_bwrap_tail() -> anyhow::Result<()> {
        let profile = get_profile("ai-agent")?;
        let spec = MicroVmSpec::try_from(RawMicroVmSpec {
            backend: crate::domain::IsolationBackend::Krun,
            ..RawMicroVmSpec::default()
        })?;
        let mut plan = BwrapSandboxCompiler.compile_launch_plan(
            &profile,
            std::path::Path::new("."),
            &["/bin/true".to_owned()],
            &[],
            &[],
        )?;
        plan.bwrap_argv.retain(|a| a != "--chdir");
        assert!(attach_microvm_plan(&mut plan, &profile, &spec, "run-1").is_err());

        let mut plan2 = BwrapSandboxCompiler.compile_launch_plan(
            &profile,
            std::path::Path::new("."),
            &["/bin/true".to_owned()],
            &[],
            &[],
        )?;
        if let Some(pos) = plan2.bwrap_argv.iter().position(|a| a == "--") {
            plan2.bwrap_argv[pos] = "not-dash".to_owned();
        }
        assert!(attach_microvm_plan(&mut plan2, &profile, &spec, "run-2").is_err());
        Ok(())
    }
}
