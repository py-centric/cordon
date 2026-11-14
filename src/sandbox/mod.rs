//! Bubblewrap (`bwrap`) 5-gate command compiler and host toolchain doctor.

mod doctor;
mod policy;
mod runtime;
#[cfg(test)]
mod tests;

pub use self::doctor::run_doctor_checks;
pub use self::policy::{
    AGENT_SHELL_APPARMOR_PROFILE, FORBIDDEN_RW_EXACT_PATHS, FORBIDDEN_RW_HOME_SECRET_SUBTREES,
    FORBIDDEN_RW_SYSTEM_PATHS, SocketMaskKind, SocketMaskTarget, aa_exec_confinement_prefix,
    aa_exec_microvm_confinement_prefix, apparmor_confinement_target, current_xdg_runtime_dir,
    is_unsafe_writable_path, loaded_apparmor_profile_names, rendered_apparmor_profile_name,
    resolve_canonical_paths, unix_socket_mask_candidates,
};
pub use self::runtime::{prepare_live_execution_argv, prepare_live_execution_argv_with_runtime};

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::domain::{
    CanonicalPath, CordonProfile, DoctorReport, FilesystemMode, NetworkMode, SandboxLaunchPlan,
};
use crate::error::CordonError;
use crate::ports::SandboxCompilerPort;

/// Ubuntu/Debian and RHEL/Arch system CA bundle locations overlaid inside the mount namespace.
pub const SYSTEM_CA_BUNDLE_TARGETS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

fn normalize_mask_dir(raw: &str) -> Result<String, CordonError> {
    let expanded = crate::config::expand_tilde(raw);
    let trimmed = expanded.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" || !trimmed.starts_with('/') {
        return Err(CordonError::InvalidInput(format!(
            "MASK_DIR '{raw}' must expand to an absolute path other than '/'; refusing to overlay tmpfs"
        )));
    }
    Ok(trimmed.to_owned())
}

fn apply_ca_overlay(
    profile: &CordonProfile,
    bwrap_argv: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let mut env_overrides = BTreeMap::new();
    env_overrides.insert("CORDON_SANDBOX".to_owned(), "1".to_owned());
    env_overrides.insert("CORDON_PROFILE".to_owned(), profile.name.clone());

    if matches!(
        profile.network_mode,
        NetworkMode::Inspected | NetworkMode::AllowlistOnly
    ) {
        for ca_target in SYSTEM_CA_BUNDLE_TARGETS {
            bwrap_argv.extend([
                "--ro-bind".to_owned(),
                profile.ca_bundle_source.clone(),
                (*ca_target).to_owned(),
            ]);
        }
        let primary_ca_target = SYSTEM_CA_BUNDLE_TARGETS[0];
        for key in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
            "DENO_CERT",
        ] {
            env_overrides.insert(key.to_owned(), primary_ca_target.to_owned());
        }
        env_overrides.insert("RUSTLS_NATIVE_CERTS".to_owned(), "1".to_owned());
    }
    env_overrides
}

fn apply_binary_masking(
    profile: &CordonProfile,
    extra_masked_binaries: &[String],
    bwrap_argv: &mut Vec<String>,
) -> Vec<String> {
    let mut masked_set = BTreeSet::new();
    for bin in &profile.denied_binaries {
        masked_set.insert(bin.clone());
    }
    for bin in extra_masked_binaries {
        masked_set.insert(bin.clone());
    }
    let masked_binaries: Vec<String> = masked_set.into_iter().collect();
    for bin_path in &masked_binaries {
        bwrap_argv.extend([
            "--ro-bind".to_owned(),
            "/dev/null".to_owned(),
            bin_path.clone(),
        ]);
    }
    masked_binaries
}

/// Compiles a deterministic [`SandboxLaunchPlan`] for the 5-gate isolation pipeline.
pub fn compile_launch_plan(
    profile: &CordonProfile,
    workspace_dir: &Path,
    command: &[String],
    extra_masked_binaries: &[String],
    extra_writable_paths: &[String],
) -> Result<SandboxLaunchPlan, CordonError> {
    compile_launch_plan_with_masks(
        profile,
        workspace_dir,
        command,
        extra_masked_binaries,
        extra_writable_paths,
        &[],
    )
}

/// Compiles a [`SandboxLaunchPlan`] with declarative `MASK_DIR` entries.
pub fn compile_launch_plan_with_masks(
    profile: &CordonProfile,
    workspace_dir: &Path,
    command: &[String],
    extra_masked_binaries: &[String],
    extra_writable_paths: &[String],
    masked_dirs: &[String],
) -> Result<SandboxLaunchPlan, CordonError> {
    if command.is_empty() {
        return Err(CordonError::EmptyCommand);
    }

    let mut combined_writable = profile.extra_rw_binds.clone();
    combined_writable.extend_from_slice(extra_writable_paths);

    let (canonical_ws, readonly_mounts, writable_mounts) =
        resolve_canonical_paths(workspace_dir, &profile.extra_ro_binds, &combined_writable)?;

    let canonical_home = std::env::var("HOME")
        .ok()
        .and_then(|h| CanonicalPath::resolve(Path::new(&h)).ok());

    if profile.filesystem_mode == FilesystemMode::WorkspaceRw {
        let ws_str = canonical_ws.as_str();
        if is_unsafe_writable_path(ws_str, canonical_home.as_ref()) {
            return Err(CordonError::UnsafeWorkspaceMount {
                path: ws_str.to_owned(),
            });
        }
    }

    for rw_mount in &writable_mounts {
        let rw_str = rw_mount.as_str();
        if is_unsafe_writable_path(rw_str, canonical_home.as_ref()) {
            return Err(CordonError::UnsafeWorkspaceMount {
                path: rw_str.to_owned(),
            });
        }
    }

    let mut bwrap_argv: Vec<String> = vec![
        "bwrap".to_owned(),
        "--ro-bind".to_owned(),
        "/".to_owned(),
        "/".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--tmpfs".to_owned(),
        "/var/tmp".to_owned(),
        "--tmpfs".to_owned(),
        "/dev/shm".to_owned(),
    ];

    if profile.unshare_pid {
        bwrap_argv.push("--unshare-pid".to_owned());
    }
    if profile.unshare_ipc {
        bwrap_argv.push("--unshare-ipc".to_owned());
    }
    if profile.die_with_parent {
        bwrap_argv.push("--die-with-parent".to_owned());
        bwrap_argv.push("--new-session".to_owned());
    }
    if profile.network_mode == NetworkMode::None {
        bwrap_argv.push("--unshare-net".to_owned());
    }

    if profile.isolate_home_tmpfs
        && let Some(ref home) = canonical_home
    {
        bwrap_argv.extend(["--tmpfs".to_owned(), home.as_str().to_owned()]);
    }

    let ws_flag = match profile.filesystem_mode {
        FilesystemMode::WorkspaceRw => "--bind",
        FilesystemMode::WorkspaceRo | FilesystemMode::StrictRo => "--ro-bind",
    };
    bwrap_argv.extend([
        ws_flag.to_owned(),
        canonical_ws.as_str().to_owned(),
        canonical_ws.as_str().to_owned(),
    ]);

    if profile.filesystem_mode == FilesystemMode::WorkspaceRw && profile.protect_git_dir {
        for sub in [".git", ".git/hooks", ".husky"] {
            let dir = format!("{}/{sub}", canonical_ws.as_str());
            bwrap_argv.extend(["--ro-bind-try".to_owned(), dir.clone(), dir]);
        }
    }

    for mount_path in &readonly_mounts {
        bwrap_argv.extend([
            "--ro-bind".to_owned(),
            mount_path.as_str().to_owned(),
            mount_path.as_str().to_owned(),
        ]);
    }
    for mount_path in &writable_mounts {
        bwrap_argv.extend([
            "--bind".to_owned(),
            mount_path.as_str().to_owned(),
            mount_path.as_str().to_owned(),
        ]);
    }

    if profile.allow_gui_wayland
        && let (Ok(xdg_runtime), Ok(wayland_display)) = (
            std::env::var("XDG_RUNTIME_DIR"),
            std::env::var("WAYLAND_DISPLAY"),
        )
    {
        let sock = format!("{xdg_runtime}/{wayland_display}");
        bwrap_argv.extend(["--ro-bind".to_owned(), sock.clone(), sock]);
    }
    if profile.allow_gpu_dri {
        bwrap_argv.extend([
            "--dev-bind".to_owned(),
            "/dev/dri".to_owned(),
            "/dev/dri".to_owned(),
        ]);
    }

    let mut env_overrides = apply_ca_overlay(profile, &mut bwrap_argv);
    if profile.enable_build_scratch && profile.filesystem_mode == FilesystemMode::WorkspaceRw {
        env_overrides.insert(
            "TMPDIR".to_owned(),
            format!("{}/.cordon-build-tmp", canonical_ws.as_str()),
        );
    }

    let masked_binaries = apply_binary_masking(profile, extra_masked_binaries, &mut bwrap_argv);

    let mut masked_dir_set: BTreeSet<String> = BTreeSet::new();
    for raw_dir in masked_dirs {
        masked_dir_set.insert(normalize_mask_dir(raw_dir)?);
    }
    for masked_dir in &masked_dir_set {
        bwrap_argv.extend(["--tmpfs".to_owned(), masked_dir.clone()]);
    }

    for (key, val) in &env_overrides {
        bwrap_argv.extend(["--setenv".to_owned(), key.clone(), val.clone()]);
    }

    bwrap_argv.extend([
        "--chdir".to_owned(),
        canonical_ws.as_str().to_owned(),
        "--".to_owned(),
    ]);
    bwrap_argv.extend_from_slice(command);

    let (netns_exec_argv, full_argv, gates_applied) = build_gates_and_argv(profile, &bwrap_argv);

    Ok(SandboxLaunchPlan {
        profile_name: profile.name.clone(),
        workload_kind: profile.kind,
        canonical_workspace: canonical_ws,
        bwrap_argv,
        netns_exec_argv,
        full_argv,
        masked_binaries,
        env_overrides,
        gates_applied,
        network_mode: profile.network_mode,
        filesystem_mode: profile.filesystem_mode,
        microvm: None,
    })
}

fn build_gates_and_argv(
    profile: &CordonProfile,
    bwrap_argv: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut gates_applied = Vec::with_capacity(5);
    let aa_prefix = aa_exec_confinement_prefix(&profile.name);
    let (netns_exec_argv, full_argv) = match profile.network_mode {
        NetworkMode::Inspected | NetworkMode::AllowlistOnly => {
            gates_applied.push(format!(
                "Gate 1: ip netns ({} {})",
                profile.netns_name, profile.sandbox_veth_ip
            ));
            let netns = vec![
                "ip".to_owned(),
                "netns".to_owned(),
                "exec".to_owned(),
                profile.netns_name.clone(),
            ];
            let mut full = netns.clone();
            full.extend(aa_prefix.iter().cloned());
            full.extend_from_slice(bwrap_argv);
            (netns, full)
        }
        NetworkMode::Direct => {
            gates_applied.push("Gate 1: Host Network Namespace (Direct)".to_owned());
            let mut full = aa_prefix.clone();
            full.extend_from_slice(bwrap_argv);
            (Vec::new(), full)
        }
        NetworkMode::None => {
            gates_applied.push("Gate 1: bwrap --unshare-net (Loopback Airgap)".to_owned());
            let mut full = aa_prefix.clone();
            full.extend_from_slice(bwrap_argv);
            (Vec::new(), full)
        }
    };

    if aa_prefix.is_empty() {
        gates_applied.push(
            "Gate 2: AppArmor 4.0 Mandatory Access Control LSM (not applied: aa-exec or a loaded cordon/agent_shell profile unavailable)".to_owned(),
        );
    } else {
        gates_applied.push(format!(
            "Gate 2: AppArmor 4.0 Mandatory Access Control LSM (attached via {})",
            aa_prefix.join(" ")
        ));
    }
    gates_applied.push(format!(
        "Gate 3: Bubblewrap VFS ({:?}) & PID/IPC Isolation",
        profile.filesystem_mode
    ));
    gates_applied.push("Gate 4: Confined Workload Process".to_owned());
    if matches!(
        profile.network_mode,
        NetworkMode::Inspected | NetworkMode::AllowlistOnly
    ) {
        gates_applied.push(format!(
            "Gate 5: veth-host -> tshark Ring Buffer + iptables -> mitmproxy (:{})",
            profile.mitm_port
        ));
    }
    (netns_exec_argv, full_argv, gates_applied)
}

/// Default stateless implementation of [`SandboxCompilerPort`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BwrapSandboxCompiler;

impl SandboxCompilerPort for BwrapSandboxCompiler {
    fn compile_launch_plan(
        &self,
        profile: &CordonProfile,
        workspace_dir: &Path,
        command: &[String],
        extra_masked_binaries: &[String],
        extra_rw_paths: &[String],
    ) -> Result<SandboxLaunchPlan, CordonError> {
        compile_launch_plan(
            profile,
            workspace_dir,
            command,
            extra_masked_binaries,
            extra_rw_paths,
        )
    }

    fn run_doctor_checks(&self) -> DoctorReport {
        run_doctor_checks()
    }
}
