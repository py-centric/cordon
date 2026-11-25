//! Semantic security regression tests pinning the Cordon hardening mitigations (CH-01..CH-08).
//!
//! Every test asserts on parsed launch-plan structures (argv token groups, typed errors,
//! resolved plugin manifests) rather than opaque string containment.

use std::collections::BTreeMap;
use std::path::Path;

use cordon::config::{CordonEnvironmentConfig, RESERVED_ENV_KEYS, expand_tilde};
use cordon::domain::CanonicalPath;
use cordon::error::CordonError;
use cordon::profiles::get_profile;
use cordon::sandbox::{compile_launch_plan, is_unsafe_writable_path};

mod common;

#[test]
fn ch01_forbidden_roots_rejected_by_prefix_not_exact_match() {
    let home = CanonicalPath::from_trusted_static("/home/tester");
    // Every system root AND a representative subdir must be rejected by prefix match.
    for forbidden in [
        "/etc",
        "/etc/cron.d",
        "/usr",
        "/usr/local",
        "/bin",
        "/sbin",
        "/lib",
        "/boot",
        "/root",
        "/root/X",
        "/var",
        "/run",
        "/opt",
        "/sys",
        "/proc",
        "/dev",
        "/",
        "/home",
    ] {
        assert!(
            is_unsafe_writable_path(forbidden, Some(&home)),
            "CH-01: '{forbidden}' must be rejected read-write"
        );
    }
}

#[test]
fn ch01_home_secret_subtrees_rejected_but_workspaces_allowed() {
    let home = CanonicalPath::from_trusted_static("/home/tester");
    for forbidden in [
        "/home/tester",
        "/home/tester/.ssh",
        "/home/tester/.ssh/keys",
        "/home/tester/.aws/credentials",
        "/home/tester/.gnupg",
        "/home/tester/.kube/config",
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
            "CH-01: '{forbidden}' must be rejected read-write"
        );
    }
    for allowed in [
        "/home/tester/Projects/cordon",
        "/home/tester/Projects",
        "/home/tester/.cache",
        "/home/tester/.config/opencode",
        "/home/tester/.local/share/opencode",
        "/home/tester/.sshrc",
    ] {
        assert!(
            !is_unsafe_writable_path(allowed, Some(&home)),
            "CH-01: '{allowed}' must remain mountable read-write"
        );
    }
}

#[test]
fn ch01_compile_rejects_unsafe_rw_mounts_with_422_error() {
    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let cmd = vec!["true".to_owned()];
    for bad in [
        "/etc/cron.d",
        "/usr/local",
        "/root/X",
        "/var",
        "/run",
        "/opt",
    ] {
        let result = compile_launch_plan(&profile, Path::new("."), &cmd, &[], &[bad.to_owned()]);
        match result {
            Err(err @ CordonError::UnsafeWorkspaceMount { .. }) => {
                assert_eq!(err.to_problem_details("/api/v1/run", "test").status, 422);
            }
            other => panic!(
                "expected UnsafeWorkspaceMount for {bad}, got {:?}",
                other.err()
            ),
        }
    }
}

#[test]
fn ch01_home_projects_workspace_still_compiles_rw() {
    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let ws = format!("{home}/Projects/cordon-hardening-rw-test");
    let result = compile_launch_plan(&profile, Path::new(&ws), &["true".to_owned()], &[], &[]);
    assert!(
        result.is_ok(),
        "CH-01: workspace under $HOME/Projects must compile read-write: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// CH-02: MASK_DIR emits --tmpfs after every bind
// ---------------------------------------------------------------------------

#[test]
fn ch02_mask_dir_emits_tmpfs_after_all_binds() {
    let cf =
        "FROM ai-agent\nNAME mask-test\nWORKDIR .\nMASK_DIR /opt/agent-masked\nCMD [\"true\"]\n";
    let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(cf) else {
        panic!("Cordonfile with MASK_DIR failed to parse");
    };
    assert_eq!(cfg.masked_dirs, vec!["/opt/agent-masked".to_owned()]);
    let Ok((_profile, plan)) = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new()) else {
        panic!("compile with MASK_DIR failed");
    };

    let mut last_bind_idx = 0usize;
    let mut masked_tmpfs_idx = None;
    let mut chdir_idx = None;
    let mut idx = 0;
    while idx < plan.bwrap_argv.len() {
        match plan.bwrap_argv[idx].as_str() {
            "--bind" | "--ro-bind" | "--ro-bind-try" | "--dev-bind" => {
                last_bind_idx = idx;
                idx += 3;
            }
            "--tmpfs" => {
                if plan.bwrap_argv[idx + 1] == "/opt/agent-masked" {
                    masked_tmpfs_idx = Some(idx);
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
    let (Some(mask_idx), Some(chdir)) = (masked_tmpfs_idx, chdir_idx) else {
        panic!("MASK_DIR tmpfs or --chdir missing from bwrap argv");
    };
    assert!(
        mask_idx > last_bind_idx,
        "tmpfs must follow every ro/rw bind"
    );
    assert!(mask_idx < chdir);
}

#[test]
fn ch02_mask_dir_toml_key_also_emits_tmpfs() {
    let toml = "[sandbox]\nname = \"mask-toml\"\nbase_profile = \"untrusted-code\"\n\n[security]\nmasked_dirs = [\"/opt/toml-masked\"]\n";
    let Ok(cfg) = CordonEnvironmentConfig::from_toml_str(toml) else {
        panic!("TOML with masked_dirs failed to parse");
    };
    let Ok((_profile, plan)) =
        cfg.compile_plan(None, &["true".to_owned()], &[], &[], &[], &BTreeMap::new())
    else {
        panic!("compile with TOML masked_dirs failed");
    };
    let has_tmpfs = plan
        .bwrap_argv
        .windows(2)
        .any(|w| w[0] == "--tmpfs" && w[1] == "/opt/toml-masked");
    assert!(has_tmpfs, "TOML masked_dirs must emit --tmpfs");
}

#[test]
fn ch02_home_secret_mask_dir_expands_tilde() {
    let cf = "FROM untrusted-code\nNAME mask-home\nWORKDIR .\nMASK_DIR ~/.ssh\nCMD [\"true\"]\n";
    let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(cf) else {
        panic!("Cordonfile with home MASK_DIR failed to parse");
    };
    let expected = expand_tilde("~/.ssh");
    assert_eq!(cfg.masked_dirs, vec![expected.clone()]);
    let Ok((_profile, plan)) = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new()) else {
        panic!("compile with home MASK_DIR failed");
    };
    let has_tmpfs = plan
        .bwrap_argv
        .windows(2)
        .any(|w| w[0] == "--tmpfs" && w[1] == expected);
    assert!(has_tmpfs);
}

// ---------------------------------------------------------------------------
// CH-03 (env): reserved environment keys cannot override CA/proxy/loader config
// ---------------------------------------------------------------------------

#[test]
fn ch03_reserved_env_table_rejected_from_config_and_cli() {
    for key in RESERVED_ENV_KEYS {
        let cf =
            format!("FROM ai-agent\nNAME env-test\nWORKDIR .\nENV {key}=evil\nCMD [\"true\"]\n");
        let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(&cf) else {
            panic!("Cordonfile with ENV {key} failed to parse");
        };
        let result = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new());
        match result {
            Err(CordonError::InvalidInput(msg)) => {
                assert!(msg.contains(key), "rejection must name key {key}: {msg}");
            }
            other => panic!(
                "expected InvalidInput for config ENV {key}, got {:?}",
                other.err()
            ),
        }

        let mut cli_env = BTreeMap::new();
        cli_env.insert((*key).to_owned(), "evil".to_owned());
        let Ok(benign) = CordonEnvironmentConfig::from_cordonfile_str(
            "FROM ai-agent\nNAME env-cli\nWORKDIR .\nCMD [\"true\"]\n",
        ) else {
            panic!("benign Cordonfile failed to parse");
        };
        let cli_result = benign.compile_plan(None, &[], &[], &[], &[], &cli_env);
        assert!(
            matches!(cli_result, Err(CordonError::InvalidInput(_))),
            "expected rejection for CLI env {key}"
        );
    }
}

#[test]
fn ch03_reserved_env_allowed_with_explicit_override() {
    let cf = "FROM ai-agent\nNAME env-override\nWORKDIR .\nENV HTTPS_PROXY=http://attacker:8080\nCMD [\"true\"]\n";
    let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(cf) else {
        panic!("Cordonfile failed to parse");
    };
    let empty_env = BTreeMap::new();
    let result = cfg.compile_plan_with_policy(&cordon::config::PlanCompileOptions {
        workspace_override: None,
        cli_command_override: &[],
        readonly_mounts: &[],
        writable_mounts: &[],
        extra_masked_bins: &[],
        extra_env: &empty_env,
        allow_reserved_env: true,
    });
    assert!(
        result.is_ok(),
        "--allow-reserved-env must permit the override: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// CH-03: Unix socket mask overlays (bwrap tmpfs)
// ---------------------------------------------------------------------------
