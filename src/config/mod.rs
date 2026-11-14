//! Reproducible sandbox environment configuration (`Cordonfile`, `Cordonfile.toml`, `cordon.json`)
//! and Docker/Podman-style volume specification parser.
//!
//! Complies with `ADR-L0-SEC-02` and `#![forbid(unsafe_code)]`.

mod compiler;
mod cordonfile;
mod templates;
#[cfg(test)]
mod tests;
mod toml_format;

pub use self::templates::{CordonConfigTemplate, get_config_template, list_config_templates};

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::{FilesystemMode, NetworkMode, RawMicroVmSpec};
use crate::error::CordonError;

/// Environment variable keys reserved by Cordon's trusted CA/proxy overlay and runtime hardening
/// layer. Config- or CLI-supplied values for these keys are rejected with
/// [`CordonError::InvalidInput`] unless `--allow-reserved-env` is explicitly passed (audited).
pub const RESERVED_ENV_KEYS: &[&str] = &[
    // TLS/CA trust overrides
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "DENO_CERT",
    "RUSTLS_NATIVE_CERTS",
    "CARGO_HTTP_CAINFO",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    // Outbound proxy redirection
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    // Dynamic loader / interpreter hook injection
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "BASH_ENV",
    "ENV",
    "PERL5OPT",
    "PERL5LIB",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
];

/// Options bundle for compiling a [`crate::domain::SandboxLaunchPlan`] from a [`CordonEnvironmentConfig`].
#[derive(Debug, Clone)]
pub struct PlanCompileOptions<'a> {
    /// Optional workspace path override.
    pub workspace_override: Option<&'a Path>,
    /// Optional CLI command override (takes precedence over `config.command`).
    pub cli_command_override: &'a [String],
    /// Additional read-only host mounts.
    pub readonly_mounts: &'a [String],
    /// Additional read-write host mounts.
    pub writable_mounts: &'a [String],
    /// Additional host binaries masked with `/dev/null`.
    pub extra_masked_bins: &'a [String],
    /// Additional environment variables injected into the sandbox.
    pub extra_env: &'a BTreeMap<String, String>,
    /// Whether reserved environment keys (`SSL_CERT_FILE`, `LD_PRELOAD`, etc.) are permitted.
    pub allow_reserved_env: bool,
}

/// Declarative, reproducible Cordon environment specification (analogous to `Dockerfile` / `compose.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CordonEnvironmentConfig {
    /// Environment name (`opencode-dev`, `antigravity-agent`, `python-runner`).
    #[serde(default = "default_env_name")]
    pub name: String,
    /// Base built-in profile slug (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`).
    #[serde(default = "default_base_profile")]
    pub base_profile: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Default workspace directory to bind.
    #[serde(default = "default_workspace")]
    pub workspace: String,
    /// Optional override for filesystem mode (`workspace_rw`, `workspace_ro`, `strict_ro`).
    #[serde(default)]
    pub filesystem_mode: Option<FilesystemMode>,
    /// Optional override for network mode (`inspected`, `allowlist_only`, `direct`, `none`).
    #[serde(default)]
    pub network_mode: Option<NetworkMode>,
    /// Optional override for `.git` read-only protection (`EC-01`).
    #[serde(default)]
    pub protect_git_dir: Option<bool>,
    /// Optional override for `$HOME` tmpfs isolation.
    #[serde(default)]
    pub isolate_home_tmpfs: Option<bool>,
    /// Optional override for local `TMPDIR` build scratch (`EC-02`).
    #[serde(default)]
    pub enable_build_scratch: Option<bool>,
    /// Optional override for ephemeral `/tmp` size in MB.
    #[serde(default)]
    pub tmpfs_size_mb: Option<u32>,
    /// Additional host directories or files mounted read-only (`--ro-bind`).
    #[serde(default)]
    pub ro_binds: Vec<String>,
    /// Additional host directories or files mounted read-write (`--bind`).
    #[serde(default)]
    pub rw_binds: Vec<String>,
    /// Additional host binaries masked with `/dev/null`.
    #[serde(default)]
    pub mask_binaries: Vec<String>,
    /// Directories overlaid with an empty `tmpfs` inside the sandbox (`MASK_DIR`).
    #[serde(default)]
    pub masked_dirs: Vec<String>,
    /// Host binaries explicitly exposed/unmasked inside the sandbox (`bat`, `rg`, `fd`, `jq`, etc.).
    #[serde(default)]
    pub allowed_binaries: Vec<String>,
    /// Pre-populated command groups enabled for this environment (`coreutils`, `search-tools`, etc.).
    #[serde(default)]
    pub command_groups: Vec<String>,
    /// Pre-populated directory groups mounted for this environment (`xdg-config`, `agent-state`, etc.).
    #[serde(default)]
    pub directory_groups: Vec<String>,
    /// Tmux-style Cordon plugins enabled for this environment (`cordon-fish`, `cordon-hud`).
    #[serde(default)]
    pub plugins: Vec<String>,
    /// Additional outbound domains permitted by L7 policy.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Additional hosts permitted to receive mutating HTTP methods (`POST`/`PUT`/`PATCH`/`DELETE`).
    #[serde(default)]
    pub post_allowed_hosts: Vec<String>,
    /// Additional explicitly denied outbound domains.
    #[serde(default)]
    pub denied_domains: Vec<String>,
    /// Environment variables injected into the sandbox (`--setenv`).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Default command vector executed when none is passed on the CLI.
    #[serde(default)]
    pub command: Vec<String>,
    /// Optional Gate 3.5 MicroVM settings (`[vm]` table / `VM_*` directives).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<RawMicroVmSpec>,
}

fn default_env_name() -> String {
    "cordon-env".to_owned()
}

fn default_base_profile() -> String {
    "ai-agent".to_owned()
}

fn default_workspace() -> String {
    ".".to_owned()
}

impl Default for CordonEnvironmentConfig {
    fn default() -> Self {
        Self {
            name: default_env_name(),
            base_profile: default_base_profile(),
            description: None,
            workspace: default_workspace(),
            filesystem_mode: None,
            network_mode: None,
            protect_git_dir: None,
            isolate_home_tmpfs: None,
            enable_build_scratch: None,
            tmpfs_size_mb: None,
            ro_binds: Vec::new(),
            rw_binds: Vec::new(),
            mask_binaries: Vec::new(),
            masked_dirs: Vec::new(),
            allowed_binaries: Vec::new(),
            command_groups: Vec::new(),
            directory_groups: Vec::new(),
            plugins: Vec::new(),
            allowed_domains: Vec::new(),
            post_allowed_hosts: Vec::new(),
            denied_domains: Vec::new(),
            env: BTreeMap::new(),
            command: Vec::new(),
            vm: None,
        }
    }
}

/// Expands a leading `~` or `~/` to the invoking user's `HOME` directory if available.
pub fn expand_tilde(raw_path: &str) -> String {
    let trimmed = raw_path.trim();
    if trimmed == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return home;
    }
    if let Some(rest) = trimmed.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{}/{rest}", home.trim_end_matches('/'));
    }
    trimmed.to_owned()
}

/// Parses a Docker/Podman-style volume mount specification.
pub fn parse_volume_spec(spec: &str) -> Result<(String, bool), CordonError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(CordonError::InvalidInput(
            "Volume mount specification cannot be empty".to_owned(),
        ));
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    match parts.as_slice() {
        [single] => Ok((expand_tilde(single), false)),
        [host_path, mode] if *mode == "ro" || *mode == "rw" => {
            Ok((expand_tilde(host_path), *mode == "rw"))
        }
        [host_path, target_path] => {
            let h = expand_tilde(host_path);
            let t = expand_tilde(target_path);
            if h != t {
                return Err(CordonError::InvalidInput(format!(
                    "Cordon mounts host paths at identical sandbox paths; got '{h}' -> '{t}'. Use '{h}:ro' or '{h}:rw'."
                )));
            }
            Ok((h, false))
        }
        [host_path, target_path, mode] if *mode == "ro" || *mode == "rw" => {
            let h = expand_tilde(host_path);
            let t = expand_tilde(target_path);
            if h != t {
                return Err(CordonError::InvalidInput(format!(
                    "Cordon mounts host paths at identical sandbox paths; got '{h}' -> '{t}'. Use '{h}:{mode}'."
                )));
            }
            Ok((h, *mode == "rw"))
        }
        _ => Err(CordonError::InvalidInput(format!(
            "Invalid volume specification '{trimmed}'. Expected '<path>[:ro|:rw]'."
        ))),
    }
}

/// Parses a `KEY=VALUE` environment variable assignment.
pub fn parse_env_assignment(raw: &str) -> Result<(String, String), CordonError> {
    let trimmed = raw.trim();
    let Some((key, val)) = trimmed.split_once('=') else {
        return Err(CordonError::InvalidInput(format!(
            "Invalid environment variable '{trimmed}'; expected KEY=VALUE."
        )));
    };
    let clean_key = key.trim();
    if clean_key.is_empty() {
        return Err(CordonError::InvalidInput(
            "Environment variable key cannot be empty.".to_owned(),
        ));
    }
    let clean_val = val.trim().trim_matches('"').trim_matches('\'');
    Ok((clean_key.to_owned(), clean_val.to_owned()))
}

pub(super) fn parse_fs_mode(val: &str) -> Result<FilesystemMode, CordonError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "workspace_rw" | "rw" => Ok(FilesystemMode::WorkspaceRw),
        "workspace_ro" | "ro" => Ok(FilesystemMode::WorkspaceRo),
        "strict_ro" | "strict" => Ok(FilesystemMode::StrictRo),
        other => Err(CordonError::InvalidInput(format!(
            "Unknown filesystem_mode '{other}'. Expected 'workspace_rw', 'workspace_ro', or 'strict_ro'."
        ))),
    }
}

pub(super) fn parse_net_mode(val: &str) -> Result<NetworkMode, CordonError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "inspected" => Ok(NetworkMode::Inspected),
        "allowlist_only" | "allowlist" => Ok(NetworkMode::AllowlistOnly),
        "direct" => Ok(NetworkMode::Direct),
        "none" | "airgapped" => Ok(NetworkMode::None),
        other => Err(CordonError::InvalidInput(format!(
            "Unknown network_mode '{other}'. Expected 'inspected', 'allowlist_only', 'direct', or 'none'."
        ))),
    }
}

pub(super) fn parse_string_array_literal(raw: &str) -> Vec<String> {
    let inner = raw
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    inner
        .split(',')
        .map(|item| {
            item.trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim()
                .to_owned()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

impl CordonEnvironmentConfig {
    /// Loads a [`CordonEnvironmentConfig`] from disk, auto-detecting JSON, TOML, or `Cordonfile` syntax.
    pub fn from_file(path: &Path) -> Result<Self, CordonError> {
        let content = std::fs::read_to_string(path)?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if Path::new(&file_name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            || content.trim_start().starts_with('{')
        {
            return Self::from_json_str(&content);
        }

        if Path::new(&file_name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            || content.lines().any(|line| {
                let t = line.trim();
                t.starts_with('[') && t.ends_with(']')
            })
        {
            return Self::from_toml_str(&content);
        }

        Self::from_cordonfile_str(&content)
    }

    /// Parses a JSON-formatted `cordon.json` string.
    pub fn from_json_str(raw: &str) -> Result<Self, CordonError> {
        serde_json::from_str(raw)
            .map_err(|e| CordonError::InvalidInput(format!("Invalid JSON config: {e}")))
    }
}
