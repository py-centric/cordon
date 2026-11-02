//! Semantic security regression tests pinning the Cordon hardening mitigations (CH-01..CH-08).
//!
//! Every test asserts on parsed launch-plan structures (argv token groups, typed errors,
//! resolved plugin manifests) rather than opaque string containment.

use std::collections::BTreeMap;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use cordon::apparmor::{
    render_apparmor_profile, try_render_apparmor_profile, validate_apparmor_entry,
};
use cordon::config::{CordonEnvironmentConfig, RESERVED_ENV_KEYS, expand_tilde};
use cordon::domain::CanonicalPath;
use cordon::error::CordonError;
use cordon::network::generate_network_setup_commands;
use cordon::plugins::{list_available_plugins_in, resolve_plugin_in};
use cordon::profiles::get_profile;
use cordon::sandbox::{
    SocketMaskKind, compile_launch_plan, is_unsafe_writable_path, prepare_live_execution_argv,
    prepare_live_execution_argv_with_runtime, run_doctor_checks, unix_socket_mask_candidates,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cordon-hardening-{tag}-{}", std::process::id()));
    assert!(
        std::fs::create_dir_all(&dir).is_ok(),
        "failed to create temp dir {}",
        dir.display()
    );
    dir
}

fn argv_triples(argv: &[String]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut idx = 0;
    while idx + 2 < argv.len() {
        out.push((
            argv[idx].clone(),
            argv[idx + 1].clone(),
            argv[idx + 2].clone(),
        ));
        idx += 3;
    }
    out
}

// ---------------------------------------------------------------------------
// CH-01: prefix-based read-write mount rejection
// ---------------------------------------------------------------------------

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
    let result = cfg.compile_plan_with_policy(None, &[], &[], &[], &[], &BTreeMap::new(), true);
    assert!(
        result.is_ok(),
        "--allow-reserved-env must permit the override: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// CH-03: Unix socket mask overlays (bwrap tmpfs)
// ---------------------------------------------------------------------------

#[test]
fn ch03_socket_masks_present_in_live_bwrap_argv() {
    let rt = tmp_dir("xdg-runtime");
    for sub in ["systemd", "keyring", "gcr"] {
        assert!(
            std::fs::create_dir_all(rt.join(sub)).is_ok(),
            "failed to create runtime subdir {sub}"
        );
    }
    let listeners: Vec<UnixListener> = [
        rt.join("systemd/private"),
        rt.join("bus"),
        rt.join("keyring/ssh"),
        rt.join("gcr/socket"),
    ]
    .iter()
    .map(|sock| {
        UnixListener::bind(sock).unwrap_or_else(|e| panic!("failed to bind socket {sock:?}: {e}"))
    })
    .collect();

    let Ok(profile) = get_profile("untrusted-code") else {
        panic!("untrusted-code profile missing");
    };
    let Ok(plan) = compile_launch_plan(&profile, Path::new("."), &["true".to_owned()], &[], &[])
    else {
        panic!("compile_launch_plan failed");
    };
    let runtime_str = rt.to_string_lossy().into_owned();
    let (live_argv, _notice) =
        prepare_live_execution_argv_with_runtime(&plan, true, false, Some(&runtime_str));

    let canon = |p: &Path| {
        std::fs::canonicalize(p)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let triples = argv_triples(&live_argv);
    for socket in [rt.join("systemd/private"), rt.join("bus")] {
        let target = canon(&socket);
        assert!(
            triples
                .iter()
                .any(|(f, s, d)| f == "--ro-bind" && s == "/dev/null" && *d == target),
            "CH-03: socket {socket:?} must be masked with /dev/null"
        );
    }
    // keyring/gcr/gnupg agent sockets are covered by whole-directory tmpfs overlays.
    for masked_dir in [rt.join("keyring"), rt.join("gcr")] {
        let target = canon(&masked_dir);
        assert!(
            live_argv
                .windows(2)
                .any(|w| w[0] == "--tmpfs" && w[1] == target),
            "CH-03: socket dir {masked_dir:?} must be overlaid with tmpfs"
        );
    }
    for agent_socket in [rt.join("keyring/ssh"), rt.join("gcr/socket")] {
        let dir_target = canon(&agent_socket);
        let masked = live_argv
            .windows(2)
            .any(|w| w[0] == "--tmpfs" && dir_target.starts_with(&w[1]));
        assert!(
            masked,
            "CH-03: agent socket {agent_socket:?} must sit under a tmpfs mask"
        );
    }
    // Masks are mount overlays: they must be emitted before --chdir (mounts complete first).
    let mask_pos = live_argv.iter().position(|a| a == "/dev/null").unwrap_or(0);
    let chdir_pos = live_argv
        .iter()
        .position(|a| a == "--chdir")
        .unwrap_or(usize::MAX);
    assert!(mask_pos < chdir_pos);
    drop(listeners);
    let _ = std::fs::remove_dir_all(&rt);
}

#[test]
fn ch03_socket_mask_candidates_cover_fixed_system_sockets() {
    let targets = unix_socket_mask_candidates("/run/user/4242");
    let lookup = |path: &str| targets.iter().find(|t| t.path == path);
    assert_eq!(
        lookup("/run/user/4242/systemd/private").map(|t| t.kind),
        Some(SocketMaskKind::EmptyFile)
    );
    assert_eq!(
        lookup("/run/user/4242/bus").map(|t| t.kind),
        Some(SocketMaskKind::EmptyFile)
    );
    assert_eq!(
        lookup("/run/user/4242/keyring").map(|t| t.kind),
        Some(SocketMaskKind::EmptyDir)
    );
    for fixed in [
        "/run/dbus/system_bus_socket",
        "/run/docker.sock",
        "/var/run/docker.sock",
    ] {
        assert!(
            lookup(fixed).is_some(),
            "CH-03: fixed socket target {fixed} must be masked"
        );
    }
}

// ---------------------------------------------------------------------------
// CH-04: gates_applied attestation honesty
// ---------------------------------------------------------------------------

#[test]
fn ch04_gates_applied_never_overclaims_apparmor() {
    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let Ok(plan) = compile_launch_plan(&profile, Path::new("."), &["true".to_owned()], &[], &[])
    else {
        panic!("compile_launch_plan failed");
    };
    let gate2 = plan
        .gates_applied
        .iter()
        .find(|g| g.starts_with("Gate 2"))
        .map(String::as_str)
        .unwrap_or_default();
    assert!(!gate2.is_empty(), "Gate 2 status must always be reported");
    let attached = plan.full_argv.iter().any(|a| a == "aa-exec");
    if attached {
        assert!(
            gate2.contains("aa-exec -p"),
            "attached Gate 2 must name the confinement profile"
        );
    } else {
        assert!(
            gate2.contains("not applied"),
            "Gate 2 must be marked 'not applied' when no confinement is attached"
        );
    }
}

#[test]
fn ch04_doctor_reports_confinement_status() {
    let report = run_doctor_checks();
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "apparmor_confinement" && !c.required),
        "doctor must include the confinement status check"
    );
    assert!(report.checks.iter().any(|c| c.name == "apparmor_aa_exec"));
}

#[test]
fn ch04_live_argv_matches_gates_attestation() {
    let Ok(profile) = get_profile("untrusted-code") else {
        panic!("untrusted-code profile missing");
    };
    let Ok(plan) = compile_launch_plan(&profile, Path::new("."), &["true".to_owned()], &[], &[])
    else {
        panic!("compile_launch_plan failed");
    };
    let (live_argv, _) = prepare_live_execution_argv(&plan, true, false);
    let live_attached = live_argv.iter().any(|a| a == "aa-exec");
    let plan_attached = plan.full_argv.iter().any(|a| a == "aa-exec");
    // The spawn path and the attestation must agree on confinement (or both report none).
    let gate2 = plan
        .gates_applied
        .iter()
        .find(|g| g.starts_with("Gate 2"))
        .map(String::as_str)
        .unwrap_or_default();
    assert_eq!(
        live_attached,
        gate2.contains("aa-exec -p"),
        "spawn argv and Gate 2 attestation must agree"
    );
    assert_eq!(live_attached, plan_attached);
}

// ---------------------------------------------------------------------------
// CH-05: plugin shadowing regression
// ---------------------------------------------------------------------------

fn write_manifest(dir: &Path, manifest: &str) {
    assert!(
        std::fs::create_dir_all(dir).is_ok(),
        "failed to create {}",
        dir.display()
    );
    assert!(
        std::fs::write(dir.join("plugin.toml"), manifest).is_ok(),
        "failed to write plugin manifest in {}",
        dir.display()
    );
}

#[test]
fn ch05_builtins_never_shadowed_by_hostile_workspace() {
    let ws = tmp_dir("plugin-shadow");
    write_manifest(
        &ws.join("cordon-fish"),
        "name = \"cordon-fish\"\nrepo_id = \"cordon-plugins/cordon-fish\"\nversion = \"9.9.9\"\n\
         [groups]\ndefault_command_groups = [\"net-diag\", \"coreutils\"]\n",
    );
    for allow_workspace in [false, true] {
        let resolved = resolve_plugin_in("cordon-fish", &ws, allow_workspace)
            .unwrap_or_else(|e| panic!("builtin must resolve: {e}"));
        assert_eq!(resolved.version, "0.2.0", "hostile manifest must not load");
        assert_eq!(
            resolved.default_command_groups,
            vec!["coreutils".to_owned(), "shell-builtins".to_owned()],
            "builtin policy must not widen (allow_workspace={allow_workspace})"
        );
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn ch05_workspace_plugins_denied_by_default_allowed_with_opt_in() {
    let ws = tmp_dir("plugin-optin");
    write_manifest(
        &ws.join("plugins").join("custom-thing"),
        "name = \"custom-thing\"\nrepo_id = \"cordon-plugins/custom-thing\"\nversion = \"1.2.3\"\n",
    );
    assert!(
        resolve_plugin_in("custom-thing", &ws, false).is_err(),
        "workspace plugin must be denied by default"
    );
    let resolved = resolve_plugin_in("custom-thing", &ws, true)
        .unwrap_or_else(|e| panic!("opt-in plugin must resolve: {e}"));
    assert_eq!(resolved.name, "custom-thing");

    assert!(
        !list_available_plugins_in(Some(&ws), false)
            .iter()
            .any(|p| p.name == "custom-thing"),
        "default listing must exclude workspace plugins"
    );
    assert!(
        list_available_plugins_in(Some(&ws), true)
            .iter()
            .any(|p| p.name == "custom-thing"),
        "opt-in listing must include workspace plugins"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// AppArmor entry validation (CH-07)
// ---------------------------------------------------------------------------

#[test]
fn apparmor_hostile_entries_rejected_with_invalid_input() {
    for hostile in ["deny } x,", "foo\" bar", "foo\nbar", "foo,bar", "@{EVIL}/x"] {
        assert!(
            matches!(
                validate_apparmor_entry(hostile),
                Err(CordonError::InvalidInput(_))
            ),
            "expected rejection for '{hostile}'"
        );
    }
    assert!(validate_apparmor_entry("@{HOME}/.ssh/**").is_ok());
    assert!(validate_apparmor_entry("/usr/bin/nc*").is_ok());
}

#[test]
fn apparmor_render_rejects_hostile_profile_entries_and_fails_closed() {
    let Ok(mut profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let Ok(clean) = try_render_apparmor_profile(&profile, "/usr/local/bin/agent-shell") else {
        panic!("clean profile must render");
    };
    for denial in [
        "deny /run/user/**/systemd/** rwlkmx,",
        "deny /run/user/**/bus rwlkmx,",
        "deny /run/user/**/keyring/** rwlkmx,",
        "deny /run/dbus/** rwlkmx,",
        "deny /run/docker.sock rwlkmx,",
    ] {
        assert!(clean.contains(denial), "CH-03 denial missing: {denial}");
    }

    let hostile = "evil } x,".to_owned();
    profile.denied_binaries.push(hostile.clone());
    assert!(matches!(
        try_render_apparmor_profile(&profile, "/usr/local/bin/agent-shell"),
        Err(CordonError::InvalidInput(_))
    ));
    let rendered = render_apparmor_profile(&profile, "/usr/local/bin/agent-shell");
    assert!(
        !rendered.contains(&hostile),
        "no DSL injection via infallible path"
    );
    assert!(rendered.contains("deny /** rwlkmx,"));

    let Ok(mut attach_profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    attach_profile.denied_binaries.clear();
    assert!(matches!(
        try_render_apparmor_profile(&attach_profile, "/usr/bin/evil\" wkl,\n  / pwn"),
        Err(CordonError::InvalidInput(_))
    ));
}

// ---------------------------------------------------------------------------
// Canonical network constants (CH-08)
// ---------------------------------------------------------------------------

#[test]
fn ch08_network_constants_stay_canonical() {
    use cordon::network::{build_mitmproxy_command, build_tshark_command};

    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let tshark = build_tshark_command(&profile, "/var/log/cordon");
    let files_idx = tshark
        .iter()
        .position(|a| a == "files:10")
        .unwrap_or(usize::MAX);
    assert!(
        files_idx > 0 && tshark[files_idx - 2] == "filesize:102400",
        "tshark ring buffer must be filesize:102400 / files:10"
    );

    let mitm = build_mitmproxy_command(&profile, "/etc/cordon/addon.py", false);
    let set_idx = mitm.iter().position(|a| a == "--set").unwrap_or(usize::MAX);
    assert_eq!(
        mitm.get(set_idx + 1).map(String::as_str),
        Some("stream_large_bodies=5m")
    );

    let cmds = generate_network_setup_commands(&profile).join("\n");
    let dnat = format!(
        "--dport 53 -j DNAT --to-destination {}:53",
        profile.host_veth_ip
    );
    assert!(
        cmds.contains(&dnat),
        "DNS DNAT must target the host veth resolver"
    );
}
