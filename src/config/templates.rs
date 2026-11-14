//! Built-in reproducible Cordon environment configuration templates.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::CordonEnvironmentConfig;
use crate::error::CordonError;

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
