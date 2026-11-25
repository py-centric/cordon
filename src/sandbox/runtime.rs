//! Live host execution argv adapter for Bubblewrap (`bwrap`) launch plans.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;

use super::SYSTEM_CA_BUNDLE_TARGETS;
use super::policy::{aa_exec_confinement_prefix, current_xdg_runtime_dir, emit_socket_masks};
use crate::domain::{NetworkMode, SandboxLaunchPlan, WorkloadKind};

fn is_netns_usable(netns_name: &str) -> bool {
    let is_root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    if !is_root {
        return false;
    }
    let run_path = format!("/run/netns/{netns_name}");
    let var_run_path = format!("/var/run/netns/{netns_name}");
    std::fs::File::open(run_path).is_ok() || std::fs::File::open(var_run_path).is_ok()
}

/// Adapts a compiled [`SandboxLaunchPlan`] for live host execution (`cordon run`, `cordon shell`, `cordon repl`).
#[must_use]
pub fn prepare_live_execution_argv(
    plan: &SandboxLaunchPlan,
    force_offline: bool,
    force_host_net: bool,
) -> (Vec<String>, Option<String>) {
    let runtime_dir = current_xdg_runtime_dir();
    prepare_live_execution_argv_with_runtime(
        plan,
        force_offline,
        force_host_net,
        runtime_dir.as_deref(),
    )
}

/// [`prepare_live_execution_argv`] with an explicit XDG runtime directory for socket masking.
#[must_use]
pub fn prepare_live_execution_argv_with_runtime(
    plan: &SandboxLaunchPlan,
    force_offline: bool,
    force_host_net: bool,
    xdg_runtime_dir: Option<&str>,
) -> (Vec<String>, Option<String>) {
    let mut fallback_notice = None;
    let use_netns = if force_offline || force_host_net || plan.netns_exec_argv.len() < 4 {
        false
    } else {
        let netns_name = &plan.netns_exec_argv[3];
        if is_netns_usable(netns_name) {
            true
        } else {
            fallback_notice = Some(format!(
                "netns '{netns_name}' not active or running unprivileged; failing closed to --unshare-net loopback airgap (Gates 3-4 active; Gate 2 attachment depends on a loaded AppArmor profile; pass --host-net for direct host networking or run 'sudo deploy/net/setup-sandbox-net.sh' for Gate 1/5 netns)"
            ));
            false
        }
    };

    let ca_env_keys = [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "CURL_CA_BUNDLE",
        "DENO_CERT",
    ];
    let mut ca_bundle_present = use_netns;
    let mut filtered_bwrap: Vec<String> = Vec::with_capacity(plan.bwrap_argv.len() + 32);
    let mut seen_null_masks: BTreeSet<String> = BTreeSet::new();
    let has_home_tmpfs = plan.bwrap_argv.windows(2).any(|w| {
        w[0] == "--tmpfs"
            && std::env::var("HOME")
                .ok()
                .and_then(|h| std::fs::canonicalize(h).ok())
                .is_some_and(|ch| ch.to_string_lossy() == w[1])
    });
    let mut idx = 0;
    let raw = &plan.bwrap_argv;

    while idx < raw.len() {
        let token = &raw[idx];
        if (token == "--ro-bind"
            || token == "--ro-bind-try"
            || token == "--bind"
            || token == "--dev-bind")
            && idx + 2 < raw.len()
        {
            let src = &raw[idx + 1];
            let dst = &raw[idx + 2];
            if token == "--ro-bind" && src == "/dev/null" {
                if let Ok(canon_dst) = std::fs::canonicalize(dst)
                    && canon_dst.is_file()
                {
                    let canon_str = canon_dst.to_string_lossy().into_owned();
                    let file_name = canon_dst
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    let is_shared_multicall = matches!(
                        file_name,
                        "busybox" | "coreutils" | "toybox" | "bash" | "sh" | "zsh" | "fish"
                    );
                    if !is_shared_multicall && seen_null_masks.insert(canon_str.clone()) {
                        filtered_bwrap.extend([token.clone(), src.clone(), canon_str]);
                    }
                }
                idx += 3;
                continue;
            }
            if token == "--ro-bind" && SYSTEM_CA_BUNDLE_TARGETS.contains(&dst.as_str()) {
                if use_netns
                    && let (Ok(canon_src), Ok(canon_dst)) =
                        (std::fs::canonicalize(src), std::fs::canonicalize(dst))
                {
                    filtered_bwrap.extend([
                        token.clone(),
                        canon_src.to_string_lossy().into_owned(),
                        canon_dst.to_string_lossy().into_owned(),
                    ]);
                } else if dst == SYSTEM_CA_BUNDLE_TARGETS[0] {
                    ca_bundle_present = false;
                }
                idx += 3;
                continue;
            }
            if dst == "/" {
                filtered_bwrap.extend([token.clone(), src.clone(), dst.clone()]);
                idx += 3;
                continue;
            }
            if let (Ok(canon_src), Ok(canon_dst)) =
                (std::fs::canonicalize(src), std::fs::canonicalize(dst))
            {
                let bind_flag = if token == "--ro-bind-try" {
                    "--ro-bind".to_owned()
                } else {
                    token.clone()
                };
                filtered_bwrap.extend([
                    bind_flag,
                    canon_src.to_string_lossy().into_owned(),
                    canon_dst.to_string_lossy().into_owned(),
                ]);
            }
            idx += 3;
            continue;
        }

        if token == "--setenv" && idx + 2 < raw.len() {
            let key = &raw[idx + 1];
            let val = &raw[idx + 2];
            if !ca_bundle_present && ca_env_keys.contains(&key.as_str()) {
                idx += 3;
                continue;
            }
            if key == "TMPDIR" {
                let _ = std::fs::create_dir_all(val);
            }
            filtered_bwrap.extend([token.clone(), key.clone(), val.clone()]);
            idx += 3;
            continue;
        }

        if token == "--chdir" {
            let fail_closed_net = force_offline
                || (!use_netns
                    && !force_host_net
                    && matches!(
                        plan.network_mode,
                        NetworkMode::Inspected | NetworkMode::AllowlistOnly
                    ));
            if fail_closed_net && !filtered_bwrap.iter().any(|a| a == "--unshare-net") {
                filtered_bwrap.push("--unshare-net".to_owned());
            }
            emit_socket_masks(&mut filtered_bwrap, &mut seen_null_masks, xdg_runtime_dir);
            emit_home_secret_and_agent_mounts(
                &mut filtered_bwrap,
                &mut seen_null_masks,
                has_home_tmpfs,
                plan.workload_kind,
            );
        }

        filtered_bwrap.push(token.clone());
        idx += 1;
    }

    let mut final_argv: Vec<String> = Vec::with_capacity(plan.full_argv.len());
    if use_netns {
        final_argv.extend(plan.netns_exec_argv.clone());
    }
    final_argv.extend(aa_exec_confinement_prefix(&plan.profile_name));
    final_argv.extend(filtered_bwrap);

    (final_argv, fallback_notice)
}

fn emit_home_secret_and_agent_mounts(
    filtered_bwrap: &mut Vec<String>,
    seen_null_masks: &mut BTreeSet<String>,
    has_home_tmpfs: bool,
    workload_kind: WorkloadKind,
) {
    if has_home_tmpfs {
        return;
    }
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    for secret_rel in [
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        ".config/gcloud",
        ".azure",
    ] {
        let secret_dir = format!("{home}/{secret_rel}");
        if let Ok(canon_dir) = std::fs::canonicalize(&secret_dir)
            && canon_dir.is_dir()
        {
            filtered_bwrap.extend([
                "--tmpfs".to_owned(),
                canon_dir.to_string_lossy().into_owned(),
            ]);
        }
    }
    for secret_file_rel in [
        ".docker/config.json",
        ".npmrc",
        ".pypirc",
        ".cargo/credentials.toml",
        ".netrc",
        ".mitmproxy/mitmproxy-ca.pem",
        ".mitmproxy/mitmproxy-ca.p12",
    ] {
        let secret_file = format!("{home}/{secret_file_rel}");
        if let Ok(canon_file) = std::fs::canonicalize(&secret_file)
            && canon_file.is_file()
        {
            let canon_str = canon_file.to_string_lossy().into_owned();
            if seen_null_masks.insert(canon_str.clone()) {
                filtered_bwrap.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), canon_str]);
            }
        }
    }
    if workload_kind == WorkloadKind::AiAgent {
        for agent_rel in [
            ".config/opencode",
            ".local/share/opencode",
            ".local/state/opencode",
            ".cache/opencode",
        ] {
            let agent_dir = format!("{home}/{agent_rel}");
            let _ = std::fs::create_dir_all(&agent_dir);
            if let Ok(canon_dir) = std::fs::canonicalize(&agent_dir)
                && canon_dir.is_dir()
            {
                let canon_str = canon_dir.to_string_lossy().into_owned();
                filtered_bwrap.extend(["--bind".to_owned(), canon_str.clone(), canon_str]);
            }
        }
    }
}
