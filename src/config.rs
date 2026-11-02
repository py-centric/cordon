//! Reproducible sandbox environment configuration (`Cordonfile`, `Cordonfile.toml`, `cordon.json`)
//! and Docker/Podman-style volume specification parser.
//!
//! Complies with `ADR-L0-SEC-02` and `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::{CordonProfile, FilesystemMode, NetworkMode, SandboxLaunchPlan};
use crate::error::CordonError;
use crate::groups::{
    apply_allowed_binary_to_profile, apply_command_group_to_profile,
    apply_directory_group_to_profile,
};
use crate::profiles::get_profile;
use crate::sandbox::compile_launch_plan_with_masks;

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

/// Metadata for a built-in reproducible Cordon environment template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CordonConfigTemplate {
    /// Template identifier (`opencode`, `antigravity`, `python-sandbox`, `package-build`).
    pub slug: String,
    /// Base Cordon profile slug.
    pub base_profile: String,
    /// Human-readable summary of what this template configures.
    pub summary: String,
    /// Recommended config filename.
    pub default_filename: String,
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

/// Parses a Docker/Podman-style volume mount specification:
/// - `/host/path` -> `(expanded_path, false)` (defaults to read-only `:ro`)
/// - `/host/path:ro` -> `(expanded_path, false)`
/// - `/host/path:rw` -> `(expanded_path, true)`
/// - `/host/path:/host/path:ro` or `:rw` -> `(expanded_path, is_rw)`
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

fn parse_fs_mode(val: &str) -> Result<FilesystemMode, CordonError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "workspace_rw" | "rw" => Ok(FilesystemMode::WorkspaceRw),
        "workspace_ro" | "ro" => Ok(FilesystemMode::WorkspaceRo),
        "strict_ro" | "strict" => Ok(FilesystemMode::StrictRo),
        other => Err(CordonError::InvalidInput(format!(
            "Unknown filesystem_mode '{other}'. Expected 'workspace_rw', 'workspace_ro', or 'strict_ro'."
        ))),
    }
}

fn parse_net_mode(val: &str) -> Result<NetworkMode, CordonError> {
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

fn parse_string_array_literal(raw: &str) -> Vec<String> {
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

    /// Parses a Dockerfile/Containerfile-style `Cordonfile` string.
    pub fn from_cordonfile_str(raw: &str) -> Result<Self, CordonError> {
        let mut cfg = Self::default();
        for (line_idx, raw_line) in raw.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((directive, rest)) = line.split_once(char::is_whitespace) else {
                return Err(CordonError::InvalidInput(format!(
                    "Cordonfile line {}: missing argument after directive '{line}'",
                    line_idx + 1
                )));
            };
            let arg = rest.trim().trim_matches('"').trim_matches('\'');
            match directive.to_ascii_uppercase().as_str() {
                "FROM" | "PROFILE" => arg.clone_into(&mut cfg.base_profile),
                "NAME" => arg.clone_into(&mut cfg.name),
                "DESCRIPTION" => cfg.description = Some(arg.to_owned()),
                "WORKDIR" => cfg.workspace = expand_tilde(arg),
                "FS_MODE" => cfg.filesystem_mode = Some(parse_fs_mode(arg)?),
                "NET_MODE" => cfg.network_mode = Some(parse_net_mode(arg)?),
                "PROTECT_GIT" => cfg.protect_git_dir = Some(arg.eq_ignore_ascii_case("true")),
                "ISOLATE_HOME" => cfg.isolate_home_tmpfs = Some(arg.eq_ignore_ascii_case("true")),
                "BUILD_SCRATCH" => {
                    cfg.enable_build_scratch = Some(arg.eq_ignore_ascii_case("true"));
                }
                "MOUNT" => {
                    let (mounted_path, is_rw) = parse_volume_spec(arg)?;
                    if is_rw {
                        cfg.rw_binds.push(mounted_path);
                    } else {
                        cfg.ro_binds.push(mounted_path);
                    }
                }
                "VOLUME_RO" => cfg.ro_binds.push(expand_tilde(arg)),
                "VOLUME_RW" => cfg.rw_binds.push(expand_tilde(arg)),
                "MASK_BIN" | "MASK" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.mask_binaries.push(expand_tilde(cleaned));
                        }
                    }
                }
                "ALLOW_BIN" | "EXPOSE_BIN" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.allowed_binaries.push(cleaned.to_owned());
                        }
                    }
                }
                "ALLOW_GROUP" | "COMMAND_GROUP" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.command_groups.push(cleaned.to_owned());
                        }
                    }
                }
                "MOUNT_GROUP" | "DIR_GROUP" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.directory_groups.push(cleaned.to_owned());
                        }
                    }
                }
                "PLUGIN" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.plugins.push(cleaned.to_owned());
                        }
                    }
                }
                "MASK_DIR" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.masked_dirs.push(expand_tilde(cleaned));
                        }
                    }
                }
                "ALLOW_DOMAIN" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.allowed_domains.push(cleaned.to_owned());
                        }
                    }
                }
                "ALLOW_POST" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.post_allowed_hosts.push(cleaned.to_owned());
                        }
                    }
                }
                "DENY_DOMAIN" => {
                    for item in rest.split_whitespace() {
                        let cleaned = item.trim_matches('"').trim_matches('\'');
                        if !cleaned.is_empty() {
                            cfg.denied_domains.push(cleaned.to_owned());
                        }
                    }
                }
                "ENV" => {
                    let (k, v) = parse_env_assignment(rest)?;
                    cfg.env.insert(k, v);
                }
                "CMD" => {
                    let trimmed_rest = rest.trim();
                    if trimmed_rest.starts_with('[') {
                        cfg.command = parse_string_array_literal(trimmed_rest);
                    } else {
                        cfg.command = trimmed_rest.split_whitespace().map(str::to_owned).collect();
                    }
                }
                other => {
                    return Err(CordonError::InvalidInput(format!(
                        "Cordonfile line {}: unsupported directive '{other}'",
                        line_idx + 1
                    )));
                }
            }
        }
        Ok(cfg)
    }

    /// Parses a declarative `Cordonfile.toml` / `cordon.toml` configuration string.
    pub fn from_toml_str(raw: &str) -> Result<Self, CordonError> {
        let mut cfg = Self::default();
        let mut section = String::new();
        let mut pending_key: Option<String> = None;
        let mut pending_array_buf = String::new();

        for (line_idx, raw_line) in raw.lines().enumerate() {
            let without_comment = match raw_line.find('#') {
                Some(idx) => &raw_line[..idx],
                None => raw_line,
            };
            let line = without_comment.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(ref key) = pending_key {
                pending_array_buf.push(' ');
                pending_array_buf.push_str(line);
                if line.ends_with(']') {
                    let arr = parse_string_array_literal(&pending_array_buf);
                    Self::apply_toml_array(&mut cfg, &section, key, arr)?;
                    pending_key = None;
                    pending_array_buf.clear();
                }
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                continue;
            }

            let Some((raw_k, raw_v)) = line.split_once('=') else {
                return Err(CordonError::InvalidInput(format!(
                    "TOML line {}: expected key = value, got '{line}'",
                    line_idx + 1
                )));
            };
            let key = raw_k.trim().trim_matches('"').trim_matches('\'');
            let val = raw_v.trim();

            if val.starts_with('[') && !val.ends_with(']') {
                pending_key = Some(key.to_owned());
                val.clone_into(&mut pending_array_buf);
                continue;
            }

            if val.starts_with('[') && val.ends_with(']') {
                let arr = parse_string_array_literal(val);
                Self::apply_toml_array(&mut cfg, &section, key, arr)?;
            } else {
                Self::apply_toml_scalar(&mut cfg, &section, key, val)?;
            }
        }

        if pending_key.is_some() {
            return Err(CordonError::InvalidInput(
                "Unclosed multi-line array in TOML configuration".to_owned(),
            ));
        }

        Ok(cfg)
    }

    fn apply_toml_array(
        cfg: &mut Self,
        section: &str,
        key: &str,
        arr: Vec<String>,
    ) -> Result<(), CordonError> {
        match (section, key) {
            ("mounts" | "filesystem" | "", "ro" | "ro_binds" | "readonly_mounts") => {
                cfg.ro_binds
                    .extend(arr.into_iter().map(|p| expand_tilde(&p)));
            }
            ("mounts" | "filesystem" | "", "rw" | "rw_binds" | "writable_mounts") => {
                cfg.rw_binds
                    .extend(arr.into_iter().map(|p| expand_tilde(&p)));
            }
            ("security" | "filesystem" | "", "mask_binaries" | "masked_binaries") => {
                cfg.mask_binaries
                    .extend(arr.into_iter().map(|p| expand_tilde(&p)));
            }
            ("security" | "filesystem" | "groups" | "sandbox" | "", "allowed_binaries" | "allow_bins") => {
                cfg.allowed_binaries.extend(arr);
            }
            ("security" | "groups" | "sandbox" | "", "command_groups" | "allow_groups") => {
                cfg.command_groups.extend(arr);
            }
            ("mounts" | "filesystem" | "groups" | "sandbox" | "", "directory_groups" | "mount_groups") => {
                cfg.directory_groups.extend(arr);
            }
            ("plugins" | "sandbox" | "", "plugins" | "enabled") => {
                cfg.plugins.extend(arr);
            }
            ("security" | "filesystem" | "", "masked_dirs") => {
                cfg.masked_dirs
                    .extend(arr.into_iter().map(|p| expand_tilde(&p)));
            }
            ("network" | "", "allowed_domains") => cfg.allowed_domains.extend(arr),
            ("network" | "", "post_allowed_hosts") => cfg.post_allowed_hosts.extend(arr),
            ("network" | "", "denied_domains") => cfg.denied_domains.extend(arr),
            ("command" | "runtime" | "sandbox" | "", "entrypoint" | "command" | "cmd") => {
                cfg.command = arr;
            }
            _ => {
                return Err(CordonError::InvalidInput(format!(
                    "Unknown TOML array key '[{section}].{key}'"
                )));
            }
        }
        Ok(())
    }

    fn apply_toml_scalar(
        cfg: &mut Self,
        section: &str,
        key: &str,
        raw_val: &str,
    ) -> Result<(), CordonError> {
        let clean = raw_val.trim().trim_matches('"').trim_matches('\'');
        if section == "env" {
            cfg.env.insert(key.to_owned(), clean.to_owned());
            return Ok(());
        }
        match (section, key) {
            ("sandbox" | "environment" | "", "name") => clean.clone_into(&mut cfg.name),
            ("sandbox" | "environment" | "", "base_profile" | "profile") => {
                clean.clone_into(&mut cfg.base_profile);
            }
            ("sandbox" | "environment" | "", "description") => {
                cfg.description = Some(clean.to_owned());
            }
            ("sandbox" | "environment" | "", "workspace" | "workdir") => {
                cfg.workspace = expand_tilde(clean);
            }
            ("sandbox" | "environment" | "", "filesystem_mode") => {
                cfg.filesystem_mode = Some(parse_fs_mode(clean)?);
            }
            ("sandbox" | "environment" | "network" | "", "network_mode") => {
                cfg.network_mode = Some(parse_net_mode(clean)?);
            }
            ("sandbox" | "security" | "", "protect_git_dir") => {
                cfg.protect_git_dir = Some(clean.eq_ignore_ascii_case("true"));
            }
            ("sandbox" | "security" | "", "isolate_home_tmpfs") => {
                cfg.isolate_home_tmpfs = Some(clean.eq_ignore_ascii_case("true"));
            }
            ("sandbox" | "security" | "", "enable_build_scratch") => {
                cfg.enable_build_scratch = Some(clean.eq_ignore_ascii_case("true"));
            }
            ("sandbox" | "", "tmpfs_size_mb") => {
                let parsed = clean.parse::<u32>().map_err(|_| {
                    CordonError::InvalidInput(format!("Invalid tmpfs_size_mb '{clean}'"))
                })?;
                cfg.tmpfs_size_mb = Some(parsed);
            }
            _ => {
                return Err(CordonError::InvalidInput(format!(
                    "Unknown TOML key '[{section}].{key}'"
                )));
            }
        }
        Ok(())
    }

    /// Serializes this configuration into a Dockerfile-style executable `Cordonfile`.
    pub fn to_cordonfile_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "#!/usr/bin/env -S cordon run -f");
        let _ = writeln!(
            out,
            "# Reproducible Cordon Environment (Cordonfile) - Governed by ADR-L0-SEC-02"
        );
        let _ = writeln!(out, "FROM {}", self.base_profile);
        let _ = writeln!(out, "NAME \"{}\"", self.name);
        if let Some(ref desc) = self.description {
            let _ = writeln!(out, "DESCRIPTION \"{desc}\"");
        }
        let _ = writeln!(out, "WORKDIR \"{}\"", self.workspace);
        if !self.command_groups.is_empty() {
            let _ = writeln!(out, "ALLOW_GROUP {}", self.command_groups.join(" "));
        }
        if !self.allowed_binaries.is_empty() {
            let _ = writeln!(out, "ALLOW_BIN {}", self.allowed_binaries.join(" "));
        }
        if !self.directory_groups.is_empty() {
            let _ = writeln!(out, "MOUNT_GROUP {}", self.directory_groups.join(" "));
        }
        if !self.plugins.is_empty() {
            let _ = writeln!(out, "PLUGIN {}", self.plugins.join(" "));
        }
        for ro in &self.ro_binds {
            let _ = writeln!(out, "VOLUME_RO \"{ro}\"");
        }
        for rw in &self.rw_binds {
            let _ = writeln!(out, "VOLUME_RW \"{rw}\"");
        }
        for mask in &self.mask_binaries {
            let _ = writeln!(out, "MASK_BIN \"{mask}\"");
        }
        for mask_dir in &self.masked_dirs {
            let _ = writeln!(out, "MASK_DIR \"{mask_dir}\"");
        }
        for dom in &self.allowed_domains {
            let _ = writeln!(out, "ALLOW_DOMAIN \"{dom}\"");
        }
        for post_dom in &self.post_allowed_hosts {
            let _ = writeln!(out, "ALLOW_POST \"{post_dom}\"");
        }
        for (k, v) in &self.env {
            let _ = writeln!(out, "ENV {k}=\"{v}\"");
        }
        if !self.command.is_empty() {
            let quoted: Vec<String> = self.command.iter().map(|c| format!("\"{c}\"")).collect();
            let _ = writeln!(out, "CMD [{}]", quoted.join(", "));
        }
        out
    }

    /// Serializes this configuration into a declarative `Cordonfile.toml`.
    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "#!/usr/bin/env -S cordon run -f");
        let _ = writeln!(
            out,
            "# Reproducible Cordon Environment (Cordonfile.toml) - Governed by ADR-L0-SEC-02"
        );
        let _ = writeln!(out, "[sandbox]");
        let _ = writeln!(out, "name = \"{}\"", self.name);
        let _ = writeln!(out, "base_profile = \"{}\"", self.base_profile);
        if let Some(ref desc) = self.description {
            let _ = writeln!(out, "description = \"{desc}\"");
        }
        let _ = writeln!(out, "workspace = \"{}\"", self.workspace);
        if let Some(protect_git) = self.protect_git_dir {
            let _ = writeln!(out, "protect_git_dir = {protect_git}");
        }
        if let Some(isolate_home) = self.isolate_home_tmpfs {
            let _ = writeln!(out, "isolate_home_tmpfs = {isolate_home}");
        }
        if let Some(scratch) = self.enable_build_scratch {
            let _ = writeln!(out, "enable_build_scratch = {scratch}");
        }

        if !self.command_groups.is_empty()
            || !self.allowed_binaries.is_empty()
            || !self.directory_groups.is_empty()
        {
            let _ = writeln!(out, "\n[groups]");
            if !self.command_groups.is_empty() {
                let cg: Vec<String> = self
                    .command_groups
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect();
                let _ = writeln!(out, "command_groups = [{}]", cg.join(", "));
            }
            if !self.allowed_binaries.is_empty() {
                let ab: Vec<String> = self
                    .allowed_binaries
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect();
                let _ = writeln!(out, "allowed_binaries = [{}]", ab.join(", "));
            }
            if !self.directory_groups.is_empty() {
                let dg: Vec<String> = self
                    .directory_groups
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect();
                let _ = writeln!(out, "directory_groups = [{}]", dg.join(", "));
            }
        }

        let _ = writeln!(out, "\n[mounts]");
        let readonly_list: Vec<String> = self.ro_binds.iter().map(|s| format!("\"{s}\"")).collect();
        let writable_list: Vec<String> = self.rw_binds.iter().map(|s| format!("\"{s}\"")).collect();
        let _ = writeln!(out, "ro = [{}]", readonly_list.join(", "));
        let _ = writeln!(out, "rw = [{}]", writable_list.join(", "));

        if !self.mask_binaries.is_empty() || !self.masked_dirs.is_empty() {
            let _ = writeln!(out, "\n[security]");
            let masked_quotes: Vec<String> = self
                .mask_binaries
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect();
            let _ = writeln!(out, "mask_binaries = [{}]", masked_quotes.join(", "));
            let masked_dir_quotes: Vec<String> =
                self.masked_dirs.iter().map(|s| format!("\"{s}\"")).collect();
            let _ = writeln!(out, "masked_dirs = [{}]", masked_dir_quotes.join(", "));
        }

        if !self.allowed_domains.is_empty() || !self.post_allowed_hosts.is_empty() {
            let _ = writeln!(out, "\n[network]");
            if !self.allowed_domains.is_empty() {
                let a_q: Vec<String> = self
                    .allowed_domains
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect();
                let _ = writeln!(out, "allowed_domains = [{}]", a_q.join(", "));
            }
            if !self.post_allowed_hosts.is_empty() {
                let p_q: Vec<String> = self
                    .post_allowed_hosts
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect();
                let _ = writeln!(out, "post_allowed_hosts = [{}]", p_q.join(", "));
            }
        }

        if !self.env.is_empty() {
            let _ = writeln!(out, "\n[env]");
            for (k, v) in &self.env {
                let _ = writeln!(out, "{k} = \"{v}\"");
            }
        }

        if !self.command.is_empty() {
            let _ = writeln!(out, "\n[command]");
            let c_q: Vec<String> = self.command.iter().map(|s| format!("\"{s}\"")).collect();
            let _ = writeln!(out, "entrypoint = [{}]", c_q.join(", "));
        }
        out
    }

    /// Merges this environment configuration onto its `base_profile` to produce a concrete [`CordonProfile`].
    pub fn build_profile(&self) -> Result<CordonProfile, CordonError> {
        let mut profile = get_profile(&self.base_profile)?;
        if let Some(ref desc) = self.description {
            profile.description.clone_from(desc);
        }
        if let Some(fs_mode) = self.filesystem_mode {
            profile.filesystem_mode = fs_mode;
        }
        if let Some(net_mode) = self.network_mode {
            profile.network_mode = net_mode;
        }
        if let Some(protect_git) = self.protect_git_dir {
            profile.protect_git_dir = protect_git;
        }
        if let Some(isolate_home) = self.isolate_home_tmpfs {
            profile.isolate_home_tmpfs = isolate_home;
        }
        if let Some(scratch) = self.enable_build_scratch {
            profile.enable_build_scratch = scratch;
        }
        if let Some(tmp_mb) = self.tmpfs_size_mb {
            profile.tmpfs_size_mb = tmp_mb;
        }

        for ro in &self.ro_binds {
            let expanded = expand_tilde(ro);
            if !profile.extra_ro_binds.contains(&expanded) {
                profile.extra_ro_binds.push(expanded);
            }
        }
        for rw in &self.rw_binds {
            let expanded = expand_tilde(rw);
            if !profile.extra_rw_binds.contains(&expanded) {
                profile.extra_rw_binds.push(expanded);
            }
        }
        for mask in &self.mask_binaries {
            let expanded = expand_tilde(mask);
            if !profile.denied_binaries.contains(&expanded) {
                profile.denied_binaries.push(expanded);
            }
        }
        for grp in &self.command_groups {
            let _ = apply_command_group_to_profile(&mut profile, grp)?;
        }
        for bin in &self.allowed_binaries {
            let _ = apply_allowed_binary_to_profile(&mut profile, bin);
        }
        for dir_grp in &self.directory_groups {
            let _ = apply_directory_group_to_profile(&mut profile, dir_grp, None)?;
        }
        for dom in &self.allowed_domains {
            if !profile.allowed_domains.contains(dom) {
                profile.allowed_domains.push(dom.clone());
            }
        }
        for post_dom in &self.post_allowed_hosts {
            if !profile.post_allowed_hosts.contains(post_dom) {
                profile.post_allowed_hosts.push(post_dom.clone());
            }
        }
        for denied in &self.denied_domains {
            if !profile.denied_domains.contains(denied) {
                profile.denied_domains.push(denied.clone());
            }
        }

        Ok(profile)
    }

    /// Compiles a verified [`SandboxLaunchPlan`] from this environment config and optional CLI overrides.
    /// Reserved environment keys (trusted CA/proxy and runtime hardening) are rejected by default.
    #[allow(clippy::too_many_arguments)]
    pub fn compile_plan(
        &self,
        workspace_override: Option<&Path>,
        cli_command_override: &[String],
        readonly_mounts: &[String],
        writable_mounts: &[String],
        extra_masked_bins: &[String],
        extra_env: &BTreeMap<String, String>,
    ) -> Result<(CordonProfile, SandboxLaunchPlan), CordonError> {
        self.compile_plan_with_policy(
            workspace_override,
            cli_command_override,
            readonly_mounts,
            writable_mounts,
            extra_masked_bins,
            extra_env,
            false,
        )
    }

    /// Compiles a [`SandboxLaunchPlan`] with an explicit reserved-environment policy.
    ///
    /// When `allow_reserved_env` is `false` (the default), config- or CLI-supplied environment
    /// keys in [`RESERVED_ENV_KEYS`] are rejected with [`CordonError::InvalidInput`] so user input
    /// can never override the trusted CA bundle / proxy overlay or inject dynamic loader and
    /// interpreter hooks. When `true` (explicit `--allow-reserved-env`), they are permitted and
    /// the caller is expected to record an audit event.
    #[allow(clippy::too_many_arguments)]
    pub fn compile_plan_with_policy(
        &self,
        workspace_override: Option<&Path>,
        cli_command_override: &[String],
        readonly_mounts: &[String],
        writable_mounts: &[String],
        extra_masked_bins: &[String],
        extra_env: &BTreeMap<String, String>,
        allow_reserved_env: bool,
    ) -> Result<(CordonProfile, SandboxLaunchPlan), CordonError> {
        let mut profile = self.build_profile()?;
        for ro in readonly_mounts {
            let expanded = expand_tilde(ro);
            if !profile.extra_ro_binds.contains(&expanded) {
                profile.extra_ro_binds.push(expanded);
            }
        }

        let effective_cmd = if cli_command_override.is_empty() {
            &self.command
        } else {
            cli_command_override
        };

        let expanded_ws = expand_tilde(&self.workspace);
        let ws_path = workspace_override.unwrap_or_else(|| Path::new(&expanded_ws));
        let expanded_extra_rw: Vec<String> =
            writable_mounts.iter().map(|p| expand_tilde(p)).collect();

        let mut plan = compile_launch_plan_with_masks(
            &profile,
            ws_path,
            effective_cmd,
            extra_masked_bins,
            &expanded_extra_rw,
            &self.masked_dirs,
        )?;

        // Inject custom environment variables from config and CLI
        let mut merged_env = self.env.clone();
        for (k, v) in extra_env {
            merged_env.insert(k.clone(), v.clone());
        }
        if !allow_reserved_env {
            for key in merged_env.keys() {
                if RESERVED_ENV_KEYS.contains(&key.as_str()) {
                    return Err(CordonError::InvalidInput(format!(
                        "Environment variable '{key}' is reserved by Cordon's trusted CA/proxy and runtime hardening layer; remove it from the config/CLI env or pass --allow-reserved-env to override (audited)"
                    )));
                }
            }
        }
        if !merged_env.is_empty() {
            let split_pos = plan
                .bwrap_argv
                .iter()
                .position(|arg| arg == "--chdir")
                .unwrap_or(plan.bwrap_argv.len());
            let mut env_flags = Vec::with_capacity(merged_env.len() * 3);
            for (k, v) in &merged_env {
                plan.env_overrides.insert(k.clone(), v.clone());
                env_flags.extend(["--setenv".to_owned(), k.clone(), v.clone()]);
            }
            plan.bwrap_argv.splice(split_pos..split_pos, env_flags);
            let mut full = plan.netns_exec_argv.clone();
            full.extend(crate::sandbox::aa_exec_confinement_prefix(&plan.profile_name));
            full.extend(plan.bwrap_argv.clone());
            plan.full_argv = full;
        }

        Ok((profile, plan))
    }
}

/// Lists all built-in reproducible Cordon environment templates.
pub fn list_config_templates() -> Vec<CordonConfigTemplate> {
    vec![
        CordonConfigTemplate {
            slug: "opencode".to_owned(),
            base_profile: "ai-agent".to_owned(),
            summary: "OpenCode CLI AI coding agent with RW workspace, RO .git protection, and LLM API L7 inspection.".to_owned(),
            default_filename: "Cordonfile.opencode".to_owned(),
        },
        CordonConfigTemplate {
            slug: "antigravity".to_owned(),
            base_profile: "ai-agent".to_owned(),
            summary: "Antigravity agentic coding environment with RO skills/config mount, RW workspace, RO .git, and L7 inspection.".to_owned(),
            default_filename: "Cordonfile.antigravity".to_owned(),
        },
        CordonConfigTemplate {
            slug: "python-sandbox".to_owned(),
            base_profile: "untrusted-code".to_owned(),
            summary: "Isolated Python script runner with RO workspace, masked $HOME, ephemeral /tmp, and zero network.".to_owned(),
            default_filename: "Cordonfile.python".to_owned(),
        },
        CordonConfigTemplate {
            slug: "package-build".to_owned(),
            base_profile: "package-build".to_owned(),
            summary: "Reproducible supply-chain build environment (cargo/npm/uv/pip) with GET-only registry allowlist.".to_owned(),
            default_filename: "package-build.cordon.toml".to_owned(),
        },
    ]
}

/// Retrieves a pre-configured [`CordonEnvironmentConfig`] by template slug.
pub fn get_config_template(slug: &str) -> Result<CordonEnvironmentConfig, CordonError> {
    match slug.trim().to_ascii_lowercase().as_str() {
        "opencode" => {
            let mut env = BTreeMap::new();
            env.insert("OPENCODE_SANDBOX".to_owned(), "cordon".to_owned());
            Ok(CordonEnvironmentConfig {
                name: "opencode-agent".to_owned(),
                base_profile: "ai-agent".to_owned(),
                description: Some(
                    "Reproducible OpenCode AI CLI agent sandbox with RO .git guard and L7 secret DLP."
                        .to_owned(),
                ),
                workspace: ".".to_owned(),
                protect_git_dir: Some(true),
                enable_build_scratch: Some(true),
                command_groups: vec![
                    "coreutils".to_owned(),
                    "shell-builtins".to_owned(),
                    "search-tools".to_owned(),
                    "vcs-git".to_owned(),
                ],
                allowed_binaries: vec!["bat".to_owned(), "rg".to_owned()],
                directory_groups: vec!["xdg-config".to_owned(), "agent-state".to_owned()],
                allowed_domains: vec![
                    "api.anthropic.com".to_owned(),
                    "api.openai.com".to_owned(),
                    "generativelanguage.googleapis.com".to_owned(),
                    "openrouter.ai".to_owned(),
                ],
                post_allowed_hosts: vec![
                    "api.anthropic.com".to_owned(),
                    "api.openai.com".to_owned(),
                    "generativelanguage.googleapis.com".to_owned(),
                    "openrouter.ai".to_owned(),
                ],
                env,
                command: vec!["opencode".to_owned()],
                ..CordonEnvironmentConfig::default()
            })
        }
        "antigravity" => {
            let mut env = BTreeMap::new();
            env.insert("ANTIGRAVITY_SANDBOX".to_owned(), "cordon".to_owned());
            Ok(CordonEnvironmentConfig {
                name: "antigravity-agent".to_owned(),
                base_profile: "ai-agent".to_owned(),
                description: Some(
                    "Reproducible Antigravity AI coding sandbox with RW project workspace, RO .git, and L7 inspection."
                        .to_owned(),
                ),
                workspace: ".".to_owned(),
                protect_git_dir: Some(true),
                enable_build_scratch: Some(true),
                command_groups: vec![
                    "coreutils".to_owned(),
                    "shell-builtins".to_owned(),
                    "search-tools".to_owned(),
                    "vcs-git".to_owned(),
                ],
                allowed_binaries: vec!["bat".to_owned(), "rg".to_owned()],
                directory_groups: vec!["xdg-config".to_owned(), "agent-state".to_owned()],
                allowed_domains: vec![
                    "generativelanguage.googleapis.com".to_owned(),
                    "aiplatform.googleapis.com".to_owned(),
                    "api.anthropic.com".to_owned(),
                    "api.openai.com".to_owned(),
                ],
                post_allowed_hosts: vec![
                    "generativelanguage.googleapis.com".to_owned(),
                    "aiplatform.googleapis.com".to_owned(),
                    "api.anthropic.com".to_owned(),
                    "api.openai.com".to_owned(),
                ],
                env,
                command: vec!["antigravity".to_owned()],
                ..CordonEnvironmentConfig::default()
            })
        }
        "python-sandbox" | "python" => {
            let mut env = BTreeMap::new();
            env.insert("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned());
            env.insert("PYTHONUNBUFFERED".to_owned(), "1".to_owned());
            Ok(CordonEnvironmentConfig {
                name: "python-isolated-runner".to_owned(),
                base_profile: "untrusted-code".to_owned(),
                description: Some(
                    "Reproducible airgapped Python execution environment with RO workspace and isolated $HOME."
                        .to_owned(),
                ),
                workspace: ".".to_owned(),
                protect_git_dir: Some(true),
                isolate_home_tmpfs: Some(true),
                env,
                command: vec!["python3".to_owned(), "main.py".to_owned()],
                ..CordonEnvironmentConfig::default()
            })
        }
        "package-build" | "build" => Ok(CordonEnvironmentConfig {
            name: "supply-chain-build".to_owned(),
            base_profile: "package-build".to_owned(),
            description: Some(
                "Supply-chain safe package build sandbox with GET-only registry allowlisting."
                    .to_owned(),
            ),
            workspace: ".".to_owned(),
            protect_git_dir: Some(true),
            enable_build_scratch: Some(true),
            command: vec!["cargo".to_owned(), "build".to_owned()],
            ..CordonEnvironmentConfig::default()
        }),
        other => Err(CordonError::InvalidInput(format!(
            "Unknown config template '{other}'. Available templates: opencode, antigravity, python-sandbox, package-build"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_dir_directive_and_toml_key_round_trip() {
        let cf = "FROM ai-agent\nNAME mask-test\nWORKDIR .\nMASK_DIR /opt/masked ~/.ssh\nCMD [\"true\"]\n";
        let cfg = CordonEnvironmentConfig::from_cordonfile_str(cf).unwrap_or_default();
        assert_eq!(cfg.masked_dirs.len(), 2);
        assert!(cfg.masked_dirs.contains(&"/opt/masked".to_owned()));

        let toml = "[security]\nmasked_dirs = [\"/opt/masked\", \"/var/lib/x\"]\n";
        let cfg_toml = CordonEnvironmentConfig::from_toml_str(toml).unwrap_or_default();
        assert!(cfg_toml.masked_dirs.contains(&"/opt/masked".to_owned()));
        assert!(cfg_toml.masked_dirs.contains(&"/var/lib/x".to_owned()));

        let rendered = cfg.to_cordonfile_string();
        assert!(rendered.contains("MASK_DIR \"/opt/masked\""));
        let rendered_toml = cfg.to_toml_string();
        assert!(rendered_toml.contains("masked_dirs = ["));
        assert!(
            CordonEnvironmentConfig::from_toml_str(&rendered_toml)
                .is_ok_and(|c| c.masked_dirs.len() == 2)
        );
    }

    #[test]
    fn reserved_env_keys_are_rejected_by_default() {
        for key in RESERVED_ENV_KEYS {
            let mut cfg = CordonEnvironmentConfig {
                command: vec!["true".to_owned()],
                ..Default::default()
            };
            cfg.env.insert((*key).to_owned(), "evil".to_owned());
            let result = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new());
            match result {
                Err(CordonError::InvalidInput(msg)) => {
                    assert!(msg.contains(key), "message must name the key: {msg}");
                }
                other => panic!("expected InvalidInput for {key}, got {:?}", other.err()),
            }

            // CLI-supplied env follows the same policy.
            let mut cli_env = BTreeMap::new();
            cli_env.insert((*key).to_owned(), "evil".to_owned());
            let cli_result = CordonEnvironmentConfig::default().compile_plan(
                None,
                &["true".to_owned()],
                &[],
                &[],
                &[],
                &cli_env,
            );
            assert!(matches!(cli_result, Err(CordonError::InvalidInput(_))));
        }
    }

    #[test]
    fn reserved_env_allowed_with_explicit_override() {
        let mut cfg = CordonEnvironmentConfig {
            command: vec!["true".to_owned()],
            ..Default::default()
        };
        cfg.env
            .insert("SSL_CERT_FILE".to_owned(), "/tmp/evil.pem".to_owned());
        let result = cfg.compile_plan_with_policy(None, &[], &[], &[], &[], &BTreeMap::new(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn benign_env_keys_pass_the_reserved_filter() {
        let mut cfg = CordonEnvironmentConfig {
            command: vec!["true".to_owned()],
            ..Default::default()
        };
        cfg.env
            .insert("OPENCODE_SANDBOX".to_owned(), "cordon".to_owned());
        let result = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new());
        assert!(result.is_ok());
    }

    #[test]
    fn reserved_env_key_set_matches_canonical_list() {
        let expected = [
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
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
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
        let mut sorted_const = RESERVED_ENV_KEYS.to_vec();
        sorted_const.sort_unstable();
        let mut sorted_expected = expected.to_vec();
        sorted_expected.sort_unstable();
        assert_eq!(sorted_const, sorted_expected);
    }
}
