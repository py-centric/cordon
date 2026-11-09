//! Bubblewrap (`bwrap`) 5-gate command compiler and host toolchain doctor.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::domain::{
    CanonicalPath, CordonProfile, DoctorCheck, DoctorReport, FilesystemMode, NetworkMode,
    SandboxLaunchPlan,
};
use crate::error::CordonError;
use crate::ports::SandboxCompilerPort;

/// Ubuntu/Debian and RHEL/Arch system CA bundle locations overlaid inside the mount namespace.
pub const SYSTEM_CA_BUNDLE_TARGETS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// Resolves workspace and supplementary bind paths into verified [`CanonicalPath`] instances.
pub fn resolve_canonical_paths(
    workspace_dir: &Path,
    readonly_binds: &[String],
    writable_binds: &[String],
) -> Result<(CanonicalPath, Vec<CanonicalPath>, Vec<CanonicalPath>), CordonError> {
    let canonical_workspace = CanonicalPath::resolve(workspace_dir)?;
    let mut readonly_resolved = Vec::with_capacity(readonly_binds.len());
    for raw in readonly_binds {
        readonly_resolved.push(CanonicalPath::resolve(Path::new(raw))?);
    }
    let mut writable_resolved = Vec::with_capacity(writable_binds.len());
    for raw in writable_binds {
        writable_resolved.push(CanonicalPath::resolve(Path::new(raw))?);
    }
    Ok((canonical_workspace, readonly_resolved, writable_resolved))
}

/// Critical system directory roots that must never be mounted read-write as a workspace or extra
/// volume. Rejected by **prefix match** (`Path::starts_with`, component-aware) so `/etc/cron.d`,
/// `/usr/local`, `/root/<x>`, `/var`, `/run`, and `/opt` are all refused, not only the roots.
pub const FORBIDDEN_RW_SYSTEM_PATHS: &[&str] = &[
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root", "/var", "/opt", "/run",
    "/sys", "/proc", "/dev",
];

/// Filesystem roots forbidden read-write by **exact match only** (`/` and the aggregate `/home`
/// which contains every user home). Subdirectories of `/home` are governed by the `$HOME` rules
/// below so `/home/<user>/Projects/<repo>` workspaces keep working.
pub const FORBIDDEN_RW_EXACT_PATHS: &[&str] = &["/", "/home"];

/// `$HOME` subtrees holding credentials or secrets that must never be mounted read-write
/// (prefix-matched relative to the canonical home directory).
pub const FORBIDDEN_RW_HOME_SECRET_SUBTREES: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".netrc",
    ".git-credentials",
    ".config/gh",
    ".config/gcloud",
    ".azure",
    ".local/share/cordon",
    ".mozilla",
];

/// Returns `true` when mounting `path_str` read-write must be rejected as an unsafe workspace
/// or extra writable volume (`CordonError::UnsafeWorkspaceMount`, HTTP 422).
///
/// Rejection rules:
/// - `/` and `/home` are forbidden exactly (aggregate roots).
/// - System roots (`/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/boot`, `/root`, `/var`, `/opt`,
///   `/run`, `/sys`, `/proc`, `/dev`) are forbidden by prefix match.
/// - `$HOME` itself is forbidden, plus credential subtrees (`~/.ssh`, `~/.aws`, `~/.gnupg`,
///   `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.config/gh`, `~/.config/gcloud`,
///   `~/.azure`, `~/.local/share/cordon`, `~/.mozilla`) by prefix match.
/// - Workspace binds under `$HOME` outside those subtrees (for example
///   `/home/<user>/Projects/<repo>`) remain permitted.
pub fn is_unsafe_writable_path(path_str: &str, canonical_home: Option<&CanonicalPath>) -> bool {
    let trimmed = if path_str.len() > 1 {
        path_str.trim_end_matches('/')
    } else {
        path_str
    };
    let path = Path::new(trimmed);
    if FORBIDDEN_RW_EXACT_PATHS.contains(&trimmed) {
        return true;
    }
    for root in FORBIDDEN_RW_SYSTEM_PATHS {
        if path.starts_with(root) {
            return true;
        }
    }
    if let Some(home) = canonical_home {
        let home_path = Path::new(home.as_str());
        if path == home_path {
            return true;
        }
        for secret in FORBIDDEN_RW_HOME_SECRET_SUBTREES {
            if path.starts_with(home_path.join(secret)) {
                return true;
            }
        }
    }
    false
}

/// Validates and normalizes a declarative `MASK_DIR` entry into an absolute directory path.
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
        env_overrides.insert("SSL_CERT_FILE".to_owned(), primary_ca_target.to_owned());
        env_overrides.insert(
            "REQUESTS_CA_BUNDLE".to_owned(),
            primary_ca_target.to_owned(),
        );
        env_overrides.insert(
            "NODE_EXTRA_CA_CERTS".to_owned(),
            primary_ca_target.to_owned(),
        );
        env_overrides.insert("CURL_CA_BUNDLE".to_owned(), primary_ca_target.to_owned());
        env_overrides.insert("DENO_CERT".to_owned(), primary_ca_target.to_owned());
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

/// AppArmor profile name of the static `agent-shell` launcher profile shipped under
/// `deploy/apparmor/usr.local.bin.agent-shell`.
pub const AGENT_SHELL_APPARMOR_PROFILE: &str = "agent_shell";

/// Returns the AppArmor profile name rendered for a Cordon profile slug (`ai-agent` -> `cordon_ai_agent`).
pub fn rendered_apparmor_profile_name(profile_name: &str) -> String {
    format!("cordon_{}", profile_name.replace('-', "_"))
}

/// Reads the AppArmor profile names currently loaded in the kernel (securityfs), or an empty
/// list when securityfs is unavailable in the current namespace.
pub fn loaded_apparmor_profile_names() -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles") else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| {
            line.split_once(" (")
                .map(|(name, _)| name.trim().to_owned())
        })
        .collect()
}

/// Resolves the AppArmor profile that can actually confine this launch (CH-04), or `None` when
/// confinement is not attachable: `aa-exec` must exist on `PATH` and either the rendered
/// per-profile name or the static `agent_shell` profile must be loaded in the kernel.
pub fn apparmor_confinement_target(profile_name: &str) -> Option<String> {
    // aa-exec must exist on PATH for the confinement transition to be attachable.
    find_binary_on_path("aa-exec")?;
    let loaded = loaded_apparmor_profile_names();
    let rendered = rendered_apparmor_profile_name(profile_name);
    [rendered, AGENT_SHELL_APPARMOR_PROFILE.to_owned()]
        .into_iter()
        .find(|candidate| loaded.iter().any(|loaded_name| loaded_name == candidate))
}

/// Builds the `aa-exec -p <profile> --` confinement prefix for live launches, or an empty vector
/// when AppArmor confinement is not attachable on this host.
pub fn aa_exec_confinement_prefix(profile_name: &str) -> Vec<String> {
    match apparmor_confinement_target(profile_name) {
        Some(target) => {
            vec![
                "aa-exec".to_owned(),
                "-p".to_owned(),
                target,
                "--".to_owned(),
            ]
        }
        None => Vec::new(),
    }
}

/// Builds the `aa-exec -p cordon_<slug>_microvm --` prefix for Gate 3.5 launches, or an empty
/// vector when that profile is not loaded. The non-VM profiles deliberately deny `/dev/kvm`, so
/// there is no fallback to `cordon_<slug>` or `agent_shell` here.
pub fn aa_exec_microvm_confinement_prefix(profile_name: &str) -> Vec<String> {
    if find_binary_on_path("aa-exec").is_none() {
        return Vec::new();
    }
    let target = format!("{}_microvm", rendered_apparmor_profile_name(profile_name));
    if loaded_apparmor_profile_names().contains(&target) {
        vec![
            "aa-exec".to_owned(),
            "-p".to_owned(),
            target,
            "--".to_owned(),
        ]
    } else {
        Vec::new()
    }
}

/// Mask overlay strategy for a host Unix socket that must be unreachable inside the sandbox (CH-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketMaskKind {
    /// Bind-mount `/dev/null` over the socket file so `connect()` fails with `ENOTSOCK`.
    EmptyFile,
    /// Overlay an empty `tmpfs` covering the socket directory and its sibling sockets.
    EmptyDir,
}

/// A host Unix socket path and the mask overlay applied inside the Bubblewrap mount namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketMaskTarget {
    /// Absolute host path of the socket file or socket directory.
    pub path: String,
    /// Overlay strategy applied when the path exists on the host.
    pub kind: SocketMaskKind,
}

/// Host Unix sockets and socket directories masked during live launches (CH-03): systemd private
/// bus, D-Bus session/system buses, keyring/gcr/gnupg agent sockets, and the Docker daemon socket.
pub fn unix_socket_mask_candidates(runtime_dir: &str) -> Vec<SocketMaskTarget> {
    let runtime = runtime_dir.trim_end_matches('/');
    vec![
        SocketMaskTarget {
            path: format!("{runtime}/systemd/private"),
            kind: SocketMaskKind::EmptyFile,
        },
        SocketMaskTarget {
            path: format!("{runtime}/bus"),
            kind: SocketMaskKind::EmptyFile,
        },
        SocketMaskTarget {
            path: format!("{runtime}/keyring"),
            kind: SocketMaskKind::EmptyDir,
        },
        SocketMaskTarget {
            path: format!("{runtime}/gcr"),
            kind: SocketMaskKind::EmptyDir,
        },
        SocketMaskTarget {
            path: format!("{runtime}/gnupg"),
            kind: SocketMaskKind::EmptyDir,
        },
        SocketMaskTarget {
            path: "/run/dbus/system_bus_socket".to_owned(),
            kind: SocketMaskKind::EmptyFile,
        },
        SocketMaskTarget {
            path: "/run/docker.sock".to_owned(),
            kind: SocketMaskKind::EmptyFile,
        },
        SocketMaskTarget {
            path: "/var/run/docker.sock".to_owned(),
            kind: SocketMaskKind::EmptyFile,
        },
    ]
}

/// Resolves the current user's XDG runtime directory (`$XDG_RUNTIME_DIR`, falling back to
/// `/run/user/<uid>`), when it exists on the host.
pub fn current_xdg_runtime_dir() -> Option<String> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR")
        && !dir.trim().is_empty()
        && Path::new(&dir).is_dir()
    {
        return Some(dir);
    }
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    let fallback = format!("/run/user/{uid}");
    Path::new(&fallback).is_dir().then_some(fallback)
}

/// Emits `--ro-bind /dev/null` / `--tmpfs` mask overlays for every host Unix socket candidate
/// that currently exists (ro-binds alone do not block `connect()` on Unix sockets).
fn emit_socket_masks(
    filtered_bwrap: &mut Vec<String>,
    seen_null_masks: &mut BTreeSet<String>,
    xdg_runtime_dir: Option<&str>,
) {
    let Some(runtime_dir) = xdg_runtime_dir else {
        return;
    };
    for target in unix_socket_mask_candidates(runtime_dir) {
        if std::fs::symlink_metadata(&target.path).is_err() {
            continue;
        }
        let canon = std::fs::canonicalize(&target.path).map_or_else(
            |_| target.path.clone(),
            |c| c.to_string_lossy().into_owned(),
        );
        match target.kind {
            SocketMaskKind::EmptyFile => {
                if seen_null_masks.insert(canon.clone()) {
                    filtered_bwrap.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), canon]);
                }
            }
            SocketMaskKind::EmptyDir => {
                filtered_bwrap.extend(["--tmpfs".to_owned(), canon]);
            }
        }
    }
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

/// Compiles a [`SandboxLaunchPlan`] with declarative `MASK_DIR` entries: each masked directory is
/// overlaid with an empty `--tmpfs` **after** every read-only/read-write bind and binary mask in
/// the `bwrap` argv (bwrap applies mounts in order, later mounts win), so the directory is
/// unconditionally empty inside the sandbox.
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

    // EC-01: Mount $REAL_PWD/.git, .git/hooks, and .husky read-only inside RW workspaces to prevent LotL repo corruption
    if profile.filesystem_mode == FilesystemMode::WorkspaceRw && profile.protect_git_dir {
        let git_dir = format!("{}/.git", canonical_ws.as_str());
        bwrap_argv.extend(["--ro-bind-try".to_owned(), git_dir.clone(), git_dir]);
        let git_hooks_dir = format!("{}/.git/hooks", canonical_ws.as_str());
        bwrap_argv.extend([
            "--ro-bind-try".to_owned(),
            git_hooks_dir.clone(),
            git_hooks_dir,
        ]);
        let husky_dir = format!("{}/.husky", canonical_ws.as_str());
        bwrap_argv.extend(["--ro-bind-try".to_owned(), husky_dir.clone(), husky_dir]);
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

    // MASK_DIR (CH-02): overlay an empty tmpfs on every declared directory. This MUST come after
    // all ro/rw binds, CA bundle overlays, and binary masks above because bwrap applies mounts in
    // argv order and the later mount wins.
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

    let mut gates_applied = Vec::with_capacity(5);
    // CH-04: Gate 2 is only claimed when AppArmor confinement is actually attachable for this
    // launch (aa-exec present AND a matching profile loaded in the kernel).
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
            full.extend(bwrap_argv.clone());
            (netns, full)
        }
        NetworkMode::Direct => {
            gates_applied.push("Gate 1: Host Network Namespace (Direct)".to_owned());
            let mut full = aa_prefix.clone();
            full.extend(bwrap_argv.clone());
            (Vec::new(), full)
        }
        NetworkMode::None => {
            gates_applied.push("Gate 1: bwrap --unshare-net (Loopback Airgap)".to_owned());
            let mut full = aa_prefix.clone();
            full.extend(bwrap_argv.clone());
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
///
/// - Automatically falls back from `ip netns exec <name>` to direct `bwrap` execution when the network namespace
///   has not been provisioned on the host yet or when running as an unprivileged user, returning a diagnostic notice.
/// - Filters `--ro-bind /dev/null <bin>` and custom CA bundle mounts to paths that exist on the current host.
/// - Auto-creates missing writable agent state or scratch directories prior to spawning `bwrap`.
/// - Masks existing `$HOME` credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`)
///   with empty `--tmpfs` mounts inside `bwrap`.
/// - Masks host Unix sockets (systemd private bus, D-Bus, keyring/gcr/gnupg agents, Docker socket, CH-03)
///   with `/dev/null` bind mounts or empty `tmpfs` overlays so the workload cannot `connect()` to host services.
/// - Prepends `aa-exec -p <profile> --` when AppArmor confinement is attachable on the host (CH-04).
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

/// [`prepare_live_execution_argv`] with an explicit XDG runtime directory for socket masking
/// (testable seam; the public entry point resolves `$XDG_RUNTIME_DIR` / `/run/user/<uid>`).
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
            // CH-03: ro-binds do not block connect() on Unix sockets; mask host service sockets.
            emit_socket_masks(&mut filtered_bwrap, &mut seen_null_masks, xdg_runtime_dir);
            if !has_home_tmpfs && let Ok(home) = std::env::var("HOME") {
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
                            filtered_bwrap.extend([
                                "--ro-bind".to_owned(),
                                "/dev/null".to_owned(),
                                canon_str,
                            ]);
                        }
                    }
                }
                if plan.workload_kind == crate::domain::WorkloadKind::AiAgent {
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
                            filtered_bwrap.extend([
                                "--bind".to_owned(),
                                canon_str.clone(),
                                canon_str,
                            ]);
                        }
                    }
                }
            }
        }

        filtered_bwrap.push(token.clone());
        idx += 1;
    }

    let mut final_argv: Vec<String> = Vec::with_capacity(plan.full_argv.len());
    if use_netns {
        final_argv.extend(plan.netns_exec_argv.clone());
    }
    // CH-04: attach AppArmor confinement at spawn time when it is actually available.
    final_argv.extend(aa_exec_confinement_prefix(&plan.profile_name));
    final_argv.extend(filtered_bwrap);

    (final_argv, fallback_notice)
}

fn find_binary_on_path(binary: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Runs non-destructive host environment and kernel capability checks (`cordon doctor`).
pub fn run_doctor_checks() -> DoctorReport {
    let required_binaries: &[(&str, bool, &str)] = &[
        (
            "bwrap",
            true,
            "Bubblewrap unprivileged mount/PID namespace engine",
        ),
        ("ip", true, "iproute2 network namespace and veth management"),
        (
            "iptables",
            true,
            "Netfilter NAT PREROUTING and UDP 443 QUIC rejection",
        ),
        (
            "aa-status",
            false,
            "AppArmor Mandatory Access Control inspection utility",
        ),
        (
            "mitmproxy",
            false,
            "Layer 7 HTTPS TLS interception and policy engine",
        ),
        ("tshark", false, "Layer 3/4 Wireshark CLI PCAP capture tap"),
        ("rustc", true, "Type-safe Rust compiler toolchain"),
    ];

    let mut checks = Vec::with_capacity(required_binaries.len() + 2);
    for (bin_name, required, desc) in required_binaries {
        if let Some(found) = find_binary_on_path(bin_name) {
            checks.push(DoctorCheck {
                name: (*bin_name).to_owned(),
                passed: true,
                required: *required,
                detail: format!("{desc} ({found})"),
            });
        } else {
            checks.push(DoctorCheck {
                name: (*bin_name).to_owned(),
                passed: false,
                required: *required,
                detail: format!("{desc} (missing on PATH)"),
            });
        }
    }

    let apparmor_enabled = Path::new("/sys/module/apparmor/parameters/enabled").exists();
    checks.push(DoctorCheck {
        name: "kernel_apparmor_lsm".to_owned(),
        passed: apparmor_enabled,
        required: false,
        detail: if apparmor_enabled {
            "AppArmor LSM kernel module enabled".to_owned()
        } else {
            "/sys/module/apparmor not mounted or disabled in current namespace".to_owned()
        },
    });

    // CH-04: report whether Gate 2 confinement is actually attachable for live launches.
    let aa_exec_present = find_binary_on_path("aa-exec").is_some();
    checks.push(DoctorCheck {
        name: "apparmor_aa_exec".to_owned(),
        passed: aa_exec_present,
        required: false,
        detail: if aa_exec_present {
            "aa-exec profile transition utility available on PATH".to_owned()
        } else {
            "aa-exec missing on PATH; Gate 2 confinement cannot be attached at spawn".to_owned()
        },
    });

    let loaded_profiles = loaded_apparmor_profile_names();
    let attachable_profile = loaded_profiles
        .iter()
        .find(|name| name.as_str() == AGENT_SHELL_APPARMOR_PROFILE || name.starts_with("cordon_"));
    checks.push(DoctorCheck {
        name: "apparmor_confinement".to_owned(),
        passed: aa_exec_present && attachable_profile.is_some(),
        required: false,
        detail: match attachable_profile {
            Some(profile_name) if aa_exec_present => {
                format!("Gate 2 attachable via aa-exec -p {profile_name}")
            }
            Some(profile_name) => {
                format!("profile '{profile_name}' loaded but aa-exec missing on PATH")
            }
            None => {
                "no cordon/agent_shell AppArmor profile loaded; launches will report Gate 2 as not applied".to_owned()
            }
        },
    });

    let tiocsti_disabled = std::fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti")
        .map_or(true, |v| v.trim() == "0");
    checks.push(DoctorCheck {
        name: "kernel_tiocsti_disabled".to_owned(),
        passed: tiocsti_disabled,
        required: false,
        detail: if tiocsti_disabled {
            "TTY TIOCSTI ioctl disabled in kernel and isolated via bwrap --new-session".to_owned()
        } else {
            "legacy_tiocsti=1 on host; mitigated via bwrap --new-session setsid() isolation"
                .to_owned()
        },
    });

    let healthy = checks.iter().filter(|c| c.required).all(|c| c.passed);
    let platform_summary = format!(
        "{}-{} (rust-cordon v{})",
        std::env::consts::OS,
        std::env::consts::ARCH,
        env!("CARGO_PKG_VERSION")
    );

    DoctorReport {
        healthy,
        platform_summary,
        checks,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let Ok(plan) =
            compile_launch_plan(&profile, Path::new("."), &["true".to_owned()], &[], &[])
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
}
