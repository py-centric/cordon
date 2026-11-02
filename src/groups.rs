//! Pre-populated command groups (`coreutils`, `shell-builtins`, `search-tools`, etc.),
//! filesystem directory groups (`xdg-config`, `agent-state`, `toolchain-caches`, etc.),
//! and host binary resolution for live sandbox mounting (`allow-bin`, `allow-group`, `mount-group`).
//!
//! Complies with `ADR-L0-SEC-02` and `#![forbid(unsafe_code)]`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::expand_tilde;
use crate::domain::CordonProfile;
use crate::error::CordonError;

/// Pre-populated named group of commands/binaries that can be exposed or unmasked together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CommandGroup {
    /// Group identifier (`coreutils`, `shell-builtins`, `search-tools`, etc.).
    pub slug: &'static str,
    /// Human-readable description of the group.
    pub summary: &'static str,
    /// Member command or binary names in this group.
    pub programs: &'static [&'static str],
}

/// Serializable view of a [`CommandGroup`] for JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandGroupInfo {
    /// Group identifier.
    pub slug: String,
    /// Human-readable description.
    pub summary: String,
    /// Member program names.
    pub programs: Vec<String>,
}

/// Pre-populated named group of filesystem directories that can be mounted into the sandbox together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DirectoryGroup {
    /// Group identifier (`xdg-config`, `agent-state`, `ssl-certs`, etc.).
    pub slug: &'static str,
    /// Human-readable description of the directory bundle.
    pub summary: &'static str,
    /// Whether this directory group mounts read-write (`true`) or read-only (`false`) by default.
    pub default_writable: bool,
    /// Host directory or file paths included in the group (supports `~/` prefix).
    pub paths: &'static [&'static str],
}

/// Serializable view of a [`DirectoryGroup`] for JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryGroupInfo {
    /// Group identifier.
    pub slug: String,
    /// Human-readable description.
    pub summary: String,
    /// Default mount mode (`"ro"` or `"rw"`).
    pub default_mode: String,
    /// Member paths.
    pub paths: Vec<String>,
}

/// All built-in command group slugs advertised to CLI and REPL completion engines.
pub const COMMAND_GROUP_CANDIDATES: [&str; 8] = [
    "coreutils",
    "shell-builtins",
    "search-tools",
    "vcs-git",
    "rust-toolchain",
    "python-uv",
    "node-web",
    "net-diag",
];

/// All built-in filesystem directory group slugs advertised to CLI and REPL completion engines.
pub const DIRECTORY_GROUP_CANDIDATES: [&str; 6] = [
    "system-libs",
    "ssl-certs",
    "xdg-config",
    "agent-state",
    "toolchain-caches",
    "temp-scratch",
];

static COMMAND_GROUPS: [CommandGroup; 8] = [
    CommandGroup {
        slug: "coreutils",
        summary: "Standard POSIX file, text, and directory utilities",
        programs: &[
            "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "head", "tail", "sort", "uniq", "wc",
            "tr", "cut", "tee", "env", "pwd", "date", "touch", "ln", "chmod", "stat", "basename",
            "dirname", "realpath",
        ],
    },
    CommandGroup {
        slug: "shell-builtins",
        summary: "POSIX, Bash, and Fish shell builtin commands",
        programs: &[
            "cd", "echo", "printf", "export", "set", "unset", "alias", "unalias", "type",
            "command", "builtin", "history", "jobs", "fg", "bg", "wait", "ulimit", "umask",
            "source", "eval", "exec", "test", "true", "false",
        ],
    },
    CommandGroup {
        slug: "search-tools",
        summary: "Fast code search, syntax-highlighted viewing, and JSON/YAML processors (bat, ripgrep, fd, jq)",
        programs: &[
            "rg", "ripgrep", "fd", "fdfind", "bat", "batcat", "fzf", "jq", "yq", "grep", "egrep",
            "fgrep", "find", "xargs", "sed", "awk", "tree",
        ],
    },
    CommandGroup {
        slug: "vcs-git",
        summary: "Git version control, GitHub CLI, and diff/patch inspection tools",
        programs: &["git", "gh", "diff", "patch", "less"],
    },
    CommandGroup {
        slug: "rust-toolchain",
        summary: "Rust compiler, Cargo package manager, and static analysis tools",
        programs: &[
            "cargo",
            "rustc",
            "rustup",
            "rustfmt",
            "clippy-driver",
            "rust-analyzer",
        ],
    },
    CommandGroup {
        slug: "python-uv",
        summary: "Python 3 interpreter, Astral uv/ruff, and pytest runners",
        programs: &[
            "python3", "python", "uv", "uvx", "pip", "pytest", "ruff", "mypy",
        ],
    },
    CommandGroup {
        slug: "node-web",
        summary: "Node.js, Bun, Deno, and JavaScript/TypeScript package managers",
        programs: &["node", "npm", "npx", "pnpm", "yarn", "bun", "deno"],
    },
    CommandGroup {
        slug: "net-diag",
        summary: "Network transfer and diagnostic utilities (curl, wget, dig, ping, ss, ip)",
        programs: &["curl", "wget", "dig", "nslookup", "ping", "nc", "ss", "ip"],
    },
];

static DIRECTORY_GROUPS: [DirectoryGroup; 6] = [
    DirectoryGroup {
        slug: "system-libs",
        summary: "Core operating system binaries and shared libraries (read-only)",
        default_writable: false,
        paths: &["/usr", "/lib", "/lib64", "/bin", "/etc/ld.so.cache"],
    },
    DirectoryGroup {
        slug: "ssl-certs",
        summary: "Host TLS CA certificate bundles and DNS resolver config (read-only)",
        default_writable: false,
        paths: &[
            "/etc/ssl/certs",
            "/etc/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
        ],
    },
    DirectoryGroup {
        slug: "xdg-config",
        summary: "Developer CLI tool configs for git, bat, ripgrep, and fish (read-only)",
        default_writable: false,
        paths: &[
            "~/.config/git",
            "~/.config/bat",
            "~/.config/ripgrep",
            "~/.config/fish",
        ],
    },
    DirectoryGroup {
        slug: "agent-state",
        summary: "Persistent state directories for OpenCode and Antigravity AI coding agents (read-write)",
        default_writable: true,
        paths: &[
            "~/.config/opencode",
            "~/.local/share/opencode",
            "~/.local/state/opencode",
            "~/.gemini/antigravity/brain",
        ],
    },
    DirectoryGroup {
        slug: "toolchain-caches",
        summary: "Local package caches for Cargo, Rustup, uv, and pip (read-only)",
        default_writable: false,
        paths: &[
            "~/.cargo/registry",
            "~/.cargo/git",
            "~/.cargo/bin",
            "~/.rustup",
            "~/.cache/uv",
            "~/.cache/pip",
        ],
    },
    DirectoryGroup {
        slug: "temp-scratch",
        summary: "Host temporary scratch directories /tmp and /var/tmp (read-write)",
        default_writable: true,
        paths: &["/tmp", "/var/tmp"],
    },
];

/// Returns all built-in pre-populated command groups.
pub const fn list_command_groups() -> &'static [CommandGroup] {
    &COMMAND_GROUPS
}

/// Returns serializable info for all built-in command groups.
pub fn list_command_group_infos() -> Vec<CommandGroupInfo> {
    COMMAND_GROUPS
        .iter()
        .map(|g| CommandGroupInfo {
            slug: g.slug.to_owned(),
            summary: g.summary.to_owned(),
            programs: g.programs.iter().map(|s| (*s).to_owned()).collect(),
        })
        .collect()
}

/// Looks up a built-in [`CommandGroup`] by slug.
pub fn get_command_group(slug: &str) -> Result<&'static CommandGroup, CordonError> {
    let clean = slug.trim().to_ascii_lowercase();
    COMMAND_GROUPS
        .iter()
        .find(|g| g.slug == clean)
        .ok_or_else(|| {
            CordonError::InvalidInput(format!(
                "Unknown command group '{slug}'. Available groups: {}",
                COMMAND_GROUP_CANDIDATES.join(", ")
            ))
        })
}

/// Returns all built-in pre-populated filesystem directory groups.
pub const fn list_directory_groups() -> &'static [DirectoryGroup] {
    &DIRECTORY_GROUPS
}

/// Returns serializable info for all built-in directory groups.
pub fn list_directory_group_infos() -> Vec<DirectoryGroupInfo> {
    DIRECTORY_GROUPS
        .iter()
        .map(|g| DirectoryGroupInfo {
            slug: g.slug.to_owned(),
            summary: g.summary.to_owned(),
            default_mode: if g.default_writable {
                "rw".to_owned()
            } else {
                "ro".to_owned()
            },
            paths: g.paths.iter().map(|s| (*s).to_owned()).collect(),
        })
        .collect()
}

/// Looks up a built-in [`DirectoryGroup`] by slug (stripping any optional `:ro` or `:rw` suffix).
pub fn get_directory_group(slug: &str) -> Result<&'static DirectoryGroup, CordonError> {
    let base = slug
        .trim()
        .split_once(':')
        .map_or(slug.trim(), |(name, _)| name)
        .to_ascii_lowercase();
    DIRECTORY_GROUPS
        .iter()
        .find(|g| g.slug == base)
        .ok_or_else(|| {
            CordonError::InvalidInput(format!(
                "Unknown directory group '{slug}'. Available groups: {}",
                DIRECTORY_GROUP_CANDIDATES.join(", ")
            ))
        })
}

/// Returns candidate binary names for a given program alias (e.g. `ripgrep` -> `["ripgrep", "rg"]`, `bat` -> `["bat", "batcat"]`).
pub fn program_alias_candidates(prog: &str) -> Vec<String> {
    let trimmed = prog.trim();
    match trimmed {
        "ripgrep" | "rg" => vec!["rg".to_owned(), "ripgrep".to_owned()],
        "bat" | "batcat" => vec!["bat".to_owned(), "batcat".to_owned()],
        "fd" | "fdfind" => vec!["fd".to_owned(), "fdfind".to_owned()],
        other => vec![other.to_owned()],
    }
}

/// Resolves a binary name or path on the host via `$PATH` and standard user-local bin directories (`~/.cargo/bin`, `~/.local/bin`).
pub fn resolve_host_binary(prog: &str) -> Option<PathBuf> {
    let trimmed = prog.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('/') {
        let expanded = expand_tilde(trimmed);
        let p = PathBuf::from(expanded);
        return p.is_file().then_some(p);
    }

    let candidates = program_alias_candidates(trimmed);
    let mut search_dirs: Vec<PathBuf> = Vec::new();
    if let Some(path_os) = std::env::var_os("PATH") {
        search_dirs.extend(std::env::split_paths(&path_os));
    }
    if let Ok(home) = std::env::var("HOME") {
        let home_trim = home.trim_end_matches('/');
        search_dirs.push(PathBuf::from(format!("{home_trim}/.cargo/bin")));
        search_dirs.push(PathBuf::from(format!("{home_trim}/.local/bin")));
    }
    for sys_dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
        search_dirs.push(PathBuf::from(sys_dir));
    }

    for candidate in &candidates {
        for dir in &search_dirs {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// Exposes a program inside the sandbox profile by:
/// 1. Removing any matching entries from `profile.denied_binaries` (so `/dev/null` masking is lifted).
/// 2. Resolving the binary on the host (`$PATH`, `~/.cargo/bin`, `~/.local/bin`, `/usr/bin`) and, if it resides outside `/usr` and `/bin`,
///    adding its resolved path to `profile.extra_ro_binds` so it remains accessible even when `$HOME` is isolated with `tmpfs`.
pub fn apply_allowed_binary_to_profile(profile: &mut CordonProfile, prog: &str) -> Option<PathBuf> {
    let candidates = program_alias_candidates(prog);
    profile.denied_binaries.retain(|denied| {
        let denied_name = Path::new(denied)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(denied.as_str());
        !candidates.iter().any(|c| c == denied || c == denied_name)
    });

    if let Some(resolved) = resolve_host_binary(prog) {
        let resolved_str = resolved.to_string_lossy().into_owned();
        profile.denied_binaries.retain(|d| d != &resolved_str);
        if !resolved_str.starts_with("/usr/")
            && !resolved_str.starts_with("/bin/")
            && !resolved_str.starts_with("/sbin/")
            && !profile.extra_ro_binds.contains(&resolved_str)
        {
            profile.extra_ro_binds.push(resolved_str);
        }
        return Some(resolved);
    }
    None
}

/// Applies all programs in a named [`CommandGroup`] to `profile`, returning the list of program names enabled.
pub fn apply_command_group_to_profile(
    profile: &mut CordonProfile,
    group_slug: &str,
) -> Result<Vec<String>, CordonError> {
    let group = get_command_group(group_slug)?;
    let mut enabled = Vec::with_capacity(group.programs.len());
    for &prog in group.programs {
        let _ = apply_allowed_binary_to_profile(profile, prog);
        enabled.push(prog.to_owned());
    }
    Ok(enabled)
}

/// Applies a named [`DirectoryGroup`] (supporting optional `:ro` or `:rw` suffix override) to `profile`,
/// returning the list of expanded host paths added.
pub fn apply_directory_group_to_profile(
    profile: &mut CordonProfile,
    raw_spec: &str,
    writable_override: Option<bool>,
) -> Result<Vec<String>, CordonError> {
    let trimmed = raw_spec.trim();
    let (slug, inline_mode) = match trimmed.split_once(':') {
        Some((s, "rw")) => (s, Some(true)),
        Some((s, "ro")) => (s, Some(false)),
        Some((_, other)) => {
            return Err(CordonError::InvalidInput(format!(
                "Invalid directory group mode ':{other}' in '{trimmed}'. Expected ':ro' or ':rw'."
            )));
        }
        None => (trimmed, None),
    };
    let group = get_directory_group(slug)?;
    let is_rw = writable_override
        .or(inline_mode)
        .unwrap_or(group.default_writable);
    let mut added = Vec::with_capacity(group.paths.len());
    for &raw_path in group.paths {
        let expanded = expand_tilde(raw_path);
        if is_rw {
            if !profile.extra_rw_binds.contains(&expanded) {
                profile.extra_rw_binds.push(expanded.clone());
            }
        } else if !profile.extra_ro_binds.contains(&expanded) {
            profile.extra_ro_binds.push(expanded.clone());
        }
        added.push(expanded);
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::get_profile;

    #[test]
    fn command_groups_contain_coreutils_builtins_and_search_tools() -> Result<(), CordonError> {
        let groups = list_command_groups();
        assert_eq!(groups.len(), 8);

        let core = get_command_group("coreutils")?;
        assert!(core.programs.contains(&"ls"));
        assert!(core.programs.contains(&"cat"));

        let builtins = get_command_group("shell-builtins")?;
        assert!(builtins.programs.contains(&"cd"));
        assert!(builtins.programs.contains(&"export"));

        let search = get_command_group("search-tools")?;
        assert!(search.programs.contains(&"bat"));
        assert!(search.programs.contains(&"rg"));
        assert!(search.programs.contains(&"ripgrep"));
        Ok(())
    }

    #[test]
    fn allow_binary_unmasks_denied_binaries_and_resolves_host_tools() -> Result<(), CordonError> {
        let mut prof = get_profile("untrusted-code")?;
        assert!(prof.denied_binaries.contains(&"/usr/bin/curl".to_owned()));

        let _ = apply_allowed_binary_to_profile(&mut prof, "curl");
        assert!(!prof.denied_binaries.contains(&"/usr/bin/curl".to_owned()));

        let enabled = apply_command_group_to_profile(&mut prof, "search-tools")?;
        assert!(enabled.contains(&"bat".to_owned()));
        assert!(enabled.contains(&"rg".to_owned()));
        Ok(())
    }

    #[test]
    fn directory_groups_mount_ro_and_rw_with_override() -> Result<(), CordonError> {
        let mut prof = get_profile("ai-agent")?;
        let readonly_paths = apply_directory_group_to_profile(&mut prof, "xdg-config", None)?;
        assert_eq!(readonly_paths.len(), 4);
        assert!(
            prof.extra_ro_binds
                .iter()
                .any(|p| p.ends_with(".config/bat"))
        );

        let writable_paths = apply_directory_group_to_profile(&mut prof, "xdg-config:rw", None)?;
        assert_eq!(writable_paths.len(), 4);
        assert!(
            prof.extra_rw_binds
                .iter()
                .any(|p| p.ends_with(".config/bat"))
        );
        Ok(())
    }
}
