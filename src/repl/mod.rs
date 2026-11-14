//! Interactive Cordon Sandbox REPL (`cordon repl`) with `crossterm` line editing,
//! persistent history, `Ctrl-R` reverse search, `./` executable configs, `ls` shorthand,
//! live program/directory group mounting (`allow-bin`, `allow-group`, `mount-group`),
//! and the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`).

mod builtins;
mod commands;
mod exec;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::Result;

pub use commands::{run_interactive_repl, run_repl_with_io};
pub use exec::write_groups_summary;

use crate::config::CordonEnvironmentConfig;
use crate::domain::SandboxLaunchPlan;
use crate::plugins::{
    CordonPlugin, abbreviate_fish_path, builtin_cordon_fish_plugin, builtin_cordon_hud_plugin,
    detect_git_branch,
};
use crate::profiles::get_profile;
use crate::repl_editor::{HistoryStore, REPL_BUILTIN_COMMANDS, sanitize_terminal_line};

use exec::discover_cordon_configs;

/// Sanitizes untrusted text for safe single-line terminal rendering.
pub(super) fn ts(value: &str) -> String {
    sanitize_terminal_line(value)
}

/// Network override mode inside an interactive Cordon REPL session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplNetMode {
    /// Automatically use `ip netns` when provisioned as root, or fall back to direct `bwrap`.
    Auto,
    /// Force direct host network namespace inside `bwrap`.
    Direct,
    /// Force complete loopback air-gap (`bwrap --unshare-net`).
    Airgap,
    /// Require `ip netns exec` without fallback.
    Netns,
}

impl ReplNetMode {
    /// Returns the short label shown in the REPL prompt.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Direct => "direct",
            Self::Airgap => "airgap",
            Self::Netns => "netns",
        }
    }
}

/// Mutable state for an interactive `cordon repl` session.
#[derive(Debug, Clone)]
pub struct ReplSession {
    /// Active profile slug (`ai-agent`, `untrusted-code`, etc.).
    pub profile: String,
    /// Optional loaded `Cordonfile` / `Cordonfile.toml` / `cordon.json` path.
    pub config_path: Option<PathBuf>,
    /// Loaded environment configuration when `config_path` is active.
    pub loaded_config: Option<CordonEnvironmentConfig>,
    /// Active workspace directory bound inside Bubblewrap.
    pub workspace: PathBuf,
    /// Session read-only volume mounts.
    pub readonly_mounts: Vec<String>,
    /// Session read-write volume mounts.
    pub writable_mounts: Vec<String>,
    /// Session masked binaries.
    pub masked_binaries: Vec<String>,
    /// Session explicitly allowed/exposed host binaries (`bat`, `rg`, `fd`, `jq`, etc.).
    pub allowed_binaries: Vec<String>,
    /// Session enabled pre-populated command groups (`coreutils`, `search-tools`, etc.).
    pub command_groups: Vec<String>,
    /// Session mounted pre-populated directory groups (`xdg-config`, `agent-state`, etc.).
    pub directory_groups: Vec<String>,
    /// Session environment variable overrides (`KEY -> VALUE`).
    pub envs: BTreeMap<String, String>,
    /// Session additional allowed outbound domains.
    pub allowed_domains: Vec<String>,
    /// Session network override mode.
    pub net_mode: ReplNetMode,
    /// When true, `run` / `!<cmd>` prints the prepared command instead of spawning a child process.
    pub dry_run_only: bool,
    /// Enabled tmux-style Cordon plugins (`cordon-fish`, `cordon-hud`).
    pub active_plugins: Vec<CordonPlugin>,
    /// Active REPL command aliases (`alias -> expansion`).
    pub aliases: BTreeMap<String, String>,
    /// Persistent command history store.
    pub history: HistoryStore,
    /// Last sandboxed process exit code.
    pub last_exit_code: i32,
}

impl ReplSession {
    /// Creates a new [`ReplSession`] initialized with the given profile, optional config file, and workspace,
    /// loading the default `cordon-fish` and `cordon-hud` plugins.
    pub fn new(
        profile: &str,
        config_path: Option<PathBuf>,
        workspace: Option<PathBuf>,
        net_mode: ReplNetMode,
        dry_run_only: bool,
    ) -> Result<Self> {
        let _ = get_profile(profile)?;
        let loaded_config = if let Some(ref p) = config_path {
            Some(CordonEnvironmentConfig::from_file(p)?)
        } else {
            None
        };
        let active_profile = loaded_config
            .as_ref()
            .map_or_else(|| profile.to_owned(), |c| c.base_profile.clone());

        let mut session = Self {
            profile: active_profile,
            config_path,
            loaded_config,
            workspace: workspace.unwrap_or_else(|| PathBuf::from(".")),
            readonly_mounts: Vec::new(),
            writable_mounts: Vec::new(),
            masked_binaries: Vec::new(),
            allowed_binaries: Vec::new(),
            command_groups: Vec::new(),
            directory_groups: Vec::new(),
            envs: BTreeMap::new(),
            allowed_domains: Vec::new(),
            net_mode,
            dry_run_only,
            active_plugins: Vec::new(),
            aliases: BTreeMap::new(),
            history: HistoryStore::default(),
            last_exit_code: 0,
        };

        session.enable_plugin_instance(builtin_cordon_fish_plugin());
        session.enable_plugin_instance(builtin_cordon_hud_plugin());
        Ok(session)
    }

    /// Enables a [`CordonPlugin`] in the current session, merging its aliases and default groups.
    pub fn enable_plugin_instance(&mut self, plugin: CordonPlugin) {
        for (k, v) in &plugin.aliases {
            self.aliases.insert(k.clone(), v.clone());
        }
        for cg in &plugin.default_command_groups {
            if !self.command_groups.contains(cg) {
                self.command_groups.push(cg.clone());
            }
        }
        for dg in &plugin.default_directory_groups {
            if !self.directory_groups.contains(dg) {
                self.directory_groups.push(dg.clone());
            }
        }
        self.active_plugins.retain(|p| p.name != plugin.name);
        self.active_plugins.push(plugin);
    }

    /// Disables a plugin by name.
    pub fn disable_plugin(&mut self, name: &str) -> bool {
        let normalized = name
            .trim()
            .strip_prefix("cordon-plugins/")
            .unwrap_or(name.trim());
        let before = self.active_plugins.len();
        self.active_plugins
            .retain(|p| !p.name.eq_ignore_ascii_case(normalized));
        self.active_plugins.len() < before
    }

    /// Returns whether syntax highlighting is enabled by any active plugin.
    pub fn syntax_highlighting_enabled(&self) -> bool {
        self.active_plugins
            .iter()
            .any(|p| p.features.syntax_highlighting)
    }

    /// Returns whether Fish inline ghost autosuggestions are enabled by any active plugin.
    pub fn fish_autosuggest_enabled(&self) -> bool {
        self.active_plugins
            .iter()
            .any(|p| p.features.fish_autosuggest)
    }

    /// Returns whether Fish abbreviated prompt paths (`~/P/cordon`) are enabled.
    pub fn abbreviate_cwd_enabled(&self) -> bool {
        self.active_plugins
            .iter()
            .any(|p| p.features.abbreviate_cwd)
    }

    /// Returns whether the Cordon HUD multi-segment telemetry prompt is enabled.
    pub fn powerline_prompt_enabled(&self) -> bool {
        self.active_plugins
            .iter()
            .any(|p| p.features.powerline_prompt)
    }

    /// Compiles a [`SandboxLaunchPlan`] for the given command using the current REPL session state.
    pub fn compile_session_plan(&self, argv: &[String]) -> Result<SandboxLaunchPlan> {
        let mut cfg = self
            .loaded_config
            .clone()
            .unwrap_or_else(|| CordonEnvironmentConfig {
                base_profile: self.profile.clone(),
                ..CordonEnvironmentConfig::default()
            });
        cfg.base_profile.clone_from(&self.profile);
        for dom in &self.allowed_domains {
            if !cfg.allowed_domains.contains(dom) {
                cfg.allowed_domains.push(dom.clone());
            }
        }
        for bin in &self.allowed_binaries {
            if !cfg.allowed_binaries.contains(bin) {
                cfg.allowed_binaries.push(bin.clone());
            }
        }
        for cg in &self.command_groups {
            if !cfg.command_groups.contains(cg) {
                cfg.command_groups.push(cg.clone());
            }
        }
        for dg in &self.directory_groups {
            if !cfg.directory_groups.contains(dg) {
                cfg.directory_groups.push(dg.clone());
            }
        }
        let (_prof, plan) = cfg.compile_plan(
            Some(self.workspace.as_path()),
            argv,
            &self.readonly_mounts,
            &self.writable_mounts,
            &self.masked_binaries,
            &self.envs,
        )?;
        Ok(plan)
    }

    /// Formats the plain (non-ANSI) prompt string (`cordon[profile|net:mode|workspace]> `).
    pub fn prompt(&self) -> String {
        let cwd_str = ts(&if self.abbreviate_cwd_enabled() {
            abbreviate_fish_path(&self.workspace)
        } else {
            self.workspace.display().to_string()
        });
        let profile = ts(&self.profile);
        if self.powerline_prompt_enabled()
            && let Some(branch) = detect_git_branch(&self.workspace)
        {
            return format!(
                "cordon[{}|git:{}|net:{}|{}]> ",
                profile,
                ts(&branch),
                self.net_mode.as_str(),
                cwd_str
            );
        }
        format!(
            "cordon[{}|net:{}|{}]> ",
            profile,
            self.net_mode.as_str(),
            cwd_str
        )
    }

    /// Formats the ANSI-colorized prompt string along with its visible character width.
    pub fn prompt_colored(&self) -> (String, usize) {
        let plain = self.prompt();
        let visible_len = plain.chars().count();
        if !self.syntax_highlighting_enabled() {
            return (plain, visible_len);
        }
        let cwd_str = ts(&if self.abbreviate_cwd_enabled() {
            abbreviate_fish_path(&self.workspace)
        } else {
            self.workspace.display().to_string()
        });
        let profile = ts(&self.profile);
        let status_color = if self.last_exit_code == 0 {
            "\x1b[1;32m"
        } else {
            "\x1b[1;31m"
        };
        let colored = if self.powerline_prompt_enabled()
            && let Some(branch) = detect_git_branch(&self.workspace)
        {
            format!(
                "\x1b[1;36mcordon\x1b[0m[\x1b[1;35m{}\x1b[0m|\x1b[1;33mgit:{}\x1b[0m|\x1b[36mnet:{}\x1b[0m|\x1b[1;34m{}\x1b[0m]{status_color}>\x1b[0m ",
                profile,
                ts(&branch),
                self.net_mode.as_str(),
                cwd_str
            )
        } else {
            format!(
                "\x1b[1;36mcordon\x1b[0m[\x1b[1;35m{}\x1b[0m|\x1b[36mnet:{}\x1b[0m|\x1b[1;34m{}\x1b[0m]{status_color}>\x1b[0m ",
                profile,
                self.net_mode.as_str(),
                cwd_str
            )
        };
        (colored, visible_len)
    }

    pub(super) fn valid_command_set(&self) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        for &b in REPL_BUILTIN_COMMANDS {
            set.insert(b.to_owned());
        }
        for k in self.aliases.keys() {
            set.insert(k.clone());
        }
        for b in &self.allowed_binaries {
            set.insert(b.clone());
        }
        set
    }

    pub(super) fn completion_candidates(&self) -> Vec<String> {
        let mut out: Vec<String> = REPL_BUILTIN_COMMANDS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        for k in self.aliases.keys() {
            out.push(k.clone());
        }
        for cfg in discover_cordon_configs() {
            out.push(cfg);
        }
        out
    }
}
