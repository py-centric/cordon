use super::tests::{KERNEL, spec};
use super::*;
use crate::domain::SandboxLaunchPlan;
use crate::profiles::get_profile;
use crate::sandbox::compile_launch_plan;

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
        let Ok(plan) = compile_launch_plan(&profile, &ws, &["true".to_owned()], &[], &[]) else {
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
    let Ok(mut plan) = compile_launch_plan(&profile, &ws, &["true".to_owned()], &[], &[]) else {
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
    let checks =
        microvm_doctor_checks(|b| (b == "firecracker").then(|| "/usr/bin/firecracker".to_owned()));
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
