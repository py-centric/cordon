use std::path::Path;

use super::*;
use crate::domain::CanonicalPath;
use crate::error::CordonError;

fn test_home() -> CanonicalPath {
    CanonicalPath::from_trusted_static("/home/tester")
}

#[test]
fn rw_guard_rejects_system_roots_by_prefix() {
    let home = test_home();
    for forbidden in [
        "/etc",
        "/etc/cron.d",
        "/usr/local",
        "/bin",
        "/sbin",
        "/lib",
        "/boot",
        "/root",
        "/root/X",
        "/var",
        "/var/tmp/work",
        "/opt",
        "/opt/builds",
        "/run",
        "/sys",
        "/proc",
        "/dev",
        "/",
        "/home",
    ] {
        assert!(
            is_unsafe_writable_path(forbidden, Some(&home)),
            "expected rejection for '{forbidden}'"
        );
    }
}

#[test]
fn rw_guard_rejects_home_and_secret_subtrees() {
    let home = test_home();
    for forbidden in [
        "/home/tester",
        "/home/tester/",
        "/home/tester/.ssh",
        "/home/tester/.ssh/keys",
        "/home/tester/.aws",
        "/home/tester/.gnupg",
        "/home/tester/.kube",
        "/home/tester/.docker",
        "/home/tester/.netrc",
        "/home/tester/.git-credentials",
        "/home/tester/.config/gh",
        "/home/tester/.config/gcloud/x",
        "/home/tester/.azure",
        "/home/tester/.local/share/cordon",
        "/home/tester/.mozilla",
    ] {
        assert!(
            is_unsafe_writable_path(forbidden, Some(&home)),
            "expected rejection for '{forbidden}'"
        );
    }
}

#[test]
fn rw_guard_allows_workspaces_under_home() {
    let home = test_home();
    for allowed in [
        "/home/tester/Projects/cordon",
        "/home/tester/Projects",
        "/home/tester/.cache",
        "/home/tester/.config/opencode",
        "/home/tester/.local/share/opencode",
        "/home/tester/.sshrc",
        "/mnt/data",
        "/srv/build",
    ] {
        assert!(
            !is_unsafe_writable_path(allowed, Some(&home)),
            "expected allowance for '{allowed}'"
        );
    }
}

#[test]
fn mask_dir_tmpfs_is_emitted_after_all_binds() {
    let Ok(profile) = crate::profiles::get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let masked = vec!["/opt/agent-masked".to_owned()];
    let Ok(plan) = compile_launch_plan_with_masks(
        &profile,
        Path::new("."),
        &["true".to_owned()],
        &[],
        &[],
        &masked,
    ) else {
        panic!("compile_launch_plan_with_masks failed");
    };

    let mut last_bind_idx = 0usize;
    let mut tmpfs_idx = None;
    let mut chdir_idx = None;
    let mut idx = 0usize;
    while idx < plan.bwrap_argv.len() {
        match plan.bwrap_argv[idx].as_str() {
            "--bind" | "--ro-bind" | "--ro-bind-try" | "--dev-bind" => {
                last_bind_idx = idx;
                idx += 3;
            }
            "--tmpfs" => {
                if plan.bwrap_argv[idx + 1] == "/opt/agent-masked" {
                    tmpfs_idx = Some(idx);
                }
                idx += 2;
            }
            "--setenv" => idx += 3,
            "--chdir" => {
                chdir_idx = Some(idx);
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    let (Some(tmpfs_idx), Some(chdir_idx)) = (tmpfs_idx, chdir_idx) else {
        panic!("masked dir tmpfs or --chdir missing from bwrap argv");
    };
    assert!(tmpfs_idx > last_bind_idx, "tmpfs must follow every bind");
    assert!(tmpfs_idx < chdir_idx);
}

#[test]
fn mask_dir_rejects_relative_and_root_entries() {
    let Ok(profile) = crate::profiles::get_profile("untrusted-code") else {
        panic!("untrusted-code profile missing");
    };
    for bad in ["/", "relative/dir", ""] {
        let result = compile_launch_plan_with_masks(
            &profile,
            Path::new("."),
            &["true".to_owned()],
            &[],
            &[],
            &[bad.to_owned()],
        );
        assert!(
            matches!(result, Err(CordonError::InvalidInput(_))),
            "expected InvalidInput for MASK_DIR '{bad}'"
        );
    }
}

#[test]
fn gates_applied_gate2_is_honest() {
    let Ok(profile) = crate::profiles::get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let Ok(plan) = compile_launch_plan(&profile, Path::new("."), &["true".to_owned()], &[], &[])
    else {
        panic!("compile_launch_plan failed");
    };
    let gate2 = plan.gates_applied.iter().find(|g| g.starts_with("Gate 2"));
    let gate2 = gate2.map(String::as_str).unwrap_or_default();
    assert!(!gate2.is_empty(), "Gate 2 entry must always report status");
    let attached = plan.full_argv.iter().any(|a| a == "aa-exec");
    if attached {
        assert!(
            gate2.contains("aa-exec"),
            "applied gate must name the wrapper"
        );
    } else {
        assert!(
            gate2.contains("not applied"),
            "unattached gate must be marked not applied"
        );
    }
}

#[test]
fn socket_mask_candidates_cover_host_service_sockets() {
    let targets = unix_socket_mask_candidates("/run/user/1000");
    let paths: Vec<&str> = targets.iter().map(|t| t.path.as_str()).collect();
    for expected in [
        "/run/user/1000/systemd/private",
        "/run/user/1000/bus",
        "/run/user/1000/keyring",
        "/run/user/1000/gcr",
        "/run/dbus/system_bus_socket",
        "/run/docker.sock",
        "/var/run/docker.sock",
    ] {
        assert!(
            paths.contains(&expected),
            "missing socket mask for {expected}"
        );
    }
}

#[test]
fn doctor_reports_confinement_status() {
    let report = run_doctor_checks();
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "apparmor_confinement" && !c.required)
    );
    assert!(report.checks.iter().any(|c| c.name == "apparmor_aa_exec"));
}
