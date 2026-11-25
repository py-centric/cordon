//! Sandbox path safety policies (`FORBIDDEN_RW_*`), AppArmor `aa-exec` attachment, and Unix socket masking (CH-03 / CH-04).

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::domain::CanonicalPath;
use crate::error::CordonError;

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
/// volume. Rejected by **prefix match** (`Path::starts_with`, component-aware).
pub const FORBIDDEN_RW_SYSTEM_PATHS: &[&str] = &[
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root", "/var", "/opt", "/run",
    "/sys", "/proc", "/dev",
];

/// Filesystem roots forbidden read-write by **exact match only** (`/` and `/home`).
pub const FORBIDDEN_RW_EXACT_PATHS: &[&str] = &["/", "/home"];

/// `$HOME` subtrees holding credentials or secrets that must never be mounted read-write.
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
#[must_use]
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

/// AppArmor profile name of the static `agent-shell` launcher profile shipped under
/// `deploy/apparmor/usr.local.bin.agent-shell`.
pub const AGENT_SHELL_APPARMOR_PROFILE: &str = "agent_shell";

/// Returns the AppArmor profile name rendered for a Cordon profile slug (`ai-agent` -> `cordon_ai_agent`).
#[must_use]
pub fn rendered_apparmor_profile_name(profile_name: &str) -> String {
    format!("cordon_{}", profile_name.replace('-', "_"))
}

/// Reads the AppArmor profile names currently loaded in the kernel (securityfs).
#[must_use]
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
/// confinement is not attachable.
#[must_use]
pub fn apparmor_confinement_target(profile_name: &str) -> Option<String> {
    find_binary_on_path("aa-exec")?;
    let loaded = loaded_apparmor_profile_names();
    let rendered = rendered_apparmor_profile_name(profile_name);
    [rendered, AGENT_SHELL_APPARMOR_PROFILE.to_owned()]
        .into_iter()
        .find(|candidate| loaded.iter().any(|loaded_name| loaded_name == candidate))
}

/// Builds the `aa-exec -p <profile> --` confinement prefix for live launches.
#[must_use]
pub fn aa_exec_confinement_prefix(profile_name: &str) -> Vec<String> {
    match apparmor_confinement_target(profile_name) {
        Some(target) => vec![
            "aa-exec".to_owned(),
            "-p".to_owned(),
            target,
            "--".to_owned(),
        ],
        None => Vec::new(),
    }
}

/// Builds the `aa-exec -p cordon_<slug>_microvm --` prefix for Gate 3.5 launches.
#[must_use]
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

/// Host Unix sockets and socket directories masked during live launches (CH-03).
#[must_use]
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

/// Resolves the current user's XDG runtime directory (`$XDG_RUNTIME_DIR`, falling back to `/run/user/<uid>`).
#[must_use]
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

pub(super) fn emit_socket_masks(
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

pub(super) fn find_binary_on_path(binary: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}
