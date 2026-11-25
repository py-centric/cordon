//! Tmux-style Cordon Plugin Ecosystem (`cordon-fish`, `cordon-hud`, and custom `plugin.toml` manifests).
//!
//! Supports `set -g @plugin 'cordon-plugins/<name>'` directives, REPL `plugin enable|disable|list|info`,
//! Fish-style abbreviated prompt paths (`~/P/cordon`), and Cordon HUD telemetry prompts & aliases.

mod manifest;
#[cfg(test)]
mod tests;

pub use self::manifest::{
    abbreviate_fish_path, detect_git_branch, load_plugin_manifest, parse_plugin_toml_str,
    parse_tmux_plugin_directive,
};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::expand_tilde;
use crate::domain::CanonicalPath;
use crate::error::CordonError;

/// Built-in plugin slugs advertised to CLI and REPL completion engines.
pub const PLUGIN_CANDIDATES: [&str; 2] = ["cordon-fish", "cordon-hud"];

/// Feature flags contributed by a Cordon plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PluginFeatures {
    /// Enable Fish-shell inline history/command ghost autosuggestions (`Right` or `Ctrl-F` to accept).
    pub fish_autosuggest: bool,
    /// Enable real-time token-level ANSI syntax highlighting in the REPL line editor.
    pub syntax_highlighting: bool,
    /// Abbreviate parent directory components in the prompt (`~/P/cordon`, like Fish `prompt_pwd`).
    pub abbreviate_cwd: bool,
    /// Render a Cordon HUD multi-segment telemetry prompt with git branch and exit status.
    pub powerline_prompt: bool,
    /// Display a compact security posture and shortcut banner on REPL startup.
    pub startup_banner: bool,
}

/// Declarative manifest for a Cordon plugin (`plugins/<name>/plugin.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CordonPlugin {
    /// Unique plugin slug (`cordon-fish`, `cordon-hud`).
    pub name: String,
    /// Tmux-style repository identifier (`cordon-plugins/cordon-fish`).
    pub repo_id: String,
    /// Semantic version.
    pub version: String,
    /// Human-readable description of what the plugin provides.
    pub description: String,
    /// Interactive shell features enabled by this plugin.
    pub features: PluginFeatures,
    /// REPL command aliases contributed by this plugin (`alias -> expansion`).
    pub aliases: BTreeMap<String, String>,
    /// Pre-populated command groups automatically enabled when this plugin is loaded.
    pub default_command_groups: Vec<String>,
    /// Pre-populated directory groups automatically mounted when this plugin is loaded.
    pub default_directory_groups: Vec<String>,
}

/// Returns the built-in `cordon-fish` plugin manifest.
pub fn builtin_cordon_fish_plugin() -> CordonPlugin {
    let mut aliases = BTreeMap::new();
    aliases.insert("c".to_owned(), "clear".to_owned());
    aliases.insert("h".to_owned(), "history".to_owned());
    aliases.insert("g".to_owned(), "groups".to_owned());

    CordonPlugin {
        name: "cordon-fish".to_owned(),
        repo_id: "cordon-plugins/cordon-fish".to_owned(),
        version: "0.2.0".to_owned(),
        description: "Fish-style interactive shell UX: live ANSI syntax highlighting, inline history ghost autosuggestions (Right/Ctrl-F), abbreviated prompt_pwd (~/P/cordon), and Tab completion.".to_owned(),
        features: PluginFeatures {
            fish_autosuggest: true,
            syntax_highlighting: true,
            abbreviate_cwd: true,
            powerline_prompt: false,
            startup_banner: false,
        },
        aliases,
        default_command_groups: vec!["coreutils".to_owned(), "shell-builtins".to_owned()],
        default_directory_groups: Vec::new(),
    }
}

/// Returns the built-in `cordon-hud` plugin manifest.
pub fn builtin_cordon_hud_plugin() -> CordonPlugin {
    let mut aliases = BTreeMap::new();
    aliases.insert("ll".to_owned(), "ls configs".to_owned());
    aliases.insert("lm".to_owned(), "ls mounts".to_owned());
    aliases.insert("lb".to_owned(), "ls bins".to_owned());
    aliases.insert("lg".to_owned(), "ls groups".to_owned());
    aliases.insert("lp".to_owned(), "ls plugins".to_owned());
    aliases.insert(
        "ag".to_owned(),
        "./configs/Cordonfile.antigravity".to_owned(),
    );
    aliases.insert("oc".to_owned(), "./configs/Cordonfile.opencode".to_owned());
    aliases.insert("py".to_owned(), "./configs/Cordonfile.python".to_owned());
    aliases.insert("airgap".to_owned(), "net airgap".to_owned());
    aliases.insert("hostnet".to_owned(), "net direct".to_owned());
    aliases.insert("bat-rg".to_owned(), "allow-group search-tools".to_owned());

    CordonPlugin {
        name: "cordon-hud".to_owned(),
        repo_id: "cordon-plugins/cordon-hud".to_owned(),
        version: "0.2.0".to_owned(),
        description: "Tactical Heads-Up Display (HUD): multi-segment telemetry prompt (profile, git branch, net mode, active groups), curated agent aliases (ag, oc, py, bat-rg, ll), and search-tools preloading.".to_owned(),
        features: PluginFeatures {
            fish_autosuggest: true,
            syntax_highlighting: true,
            abbreviate_cwd: true,
            powerline_prompt: true,
            startup_banner: true,
        },
        aliases,
        default_command_groups: vec![
            "coreutils".to_owned(),
            "shell-builtins".to_owned(),
            "search-tools".to_owned(),
            "vcs-git".to_owned(),
        ],
        default_directory_groups: vec!["xdg-config".to_owned()],
    }
}

/// Lists all available plugins (built-in plugins plus trusted-root `plugin.toml` manifests).
pub fn list_available_plugins() -> Vec<CordonPlugin> {
    list_available_plugins_in(None, false)
}

/// [`list_available_plugins`] with an explicit workspace-root opt-in for local plugin discovery.
pub fn list_available_plugins_with_workspace(allow_workspace_plugins: bool) -> Vec<CordonPlugin> {
    list_available_plugins_in(Some(Path::new(".")), allow_workspace_plugins)
}

/// Lists all available plugins, scanning `workspace_root/plugins` only when
/// `allow_workspace_plugins` is explicitly set. Built-in plugins always win over any
/// filesystem manifest with the same name.
pub fn list_available_plugins_in(
    workspace_root: Option<&Path>,
    allow_workspace_plugins: bool,
) -> Vec<CordonPlugin> {
    let mut map = BTreeMap::new();
    for builtin in [builtin_cordon_fish_plugin(), builtin_cordon_hud_plugin()] {
        map.insert(builtin.name.clone(), builtin);
    }

    for root in plugin_search_roots(workspace_root, allow_workspace_plugins) {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let manifest_path = entry.path().join("plugin.toml");
                if manifest_path.is_file()
                    && let Ok(custom) = load_plugin_manifest(&manifest_path)
                {
                    map.entry(custom.name.clone()).or_insert(custom);
                }
            }
        }
    }

    map.into_values().collect()
}

fn plugin_search_roots(
    workspace_root: Option<&Path>,
    allow_workspace_plugins: bool,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let home_cordon = PathBuf::from(format!("{}/.config/cordon", home.trim_end_matches('/')));
        roots.push(home_cordon.join("plugins"));
        roots.push(home_cordon);
    }
    if allow_workspace_plugins && let Some(ws) = workspace_root {
        roots.push(ws.join("plugins"));
        roots.push(ws.join("cordon-plugins"));
        roots.push(ws.to_path_buf());
    }
    roots
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    let Ok(resolved_candidate) = CanonicalPath::resolve(candidate) else {
        return false;
    };
    let Ok(resolved_root) = CanonicalPath::resolve(root) else {
        return false;
    };
    let candidate_path = Path::new(resolved_candidate.as_str());
    let root_path = Path::new(resolved_root.as_str());
    candidate_path == root_path || candidate_path.starts_with(root_path)
}

/// Resolves a plugin by short name (`cordon-fish`), tmux repo ID (`cordon-plugins/cordon-fish`), or manifest path.
pub fn resolve_plugin(identifier: &str) -> Result<CordonPlugin, CordonError> {
    resolve_plugin_in(identifier, Path::new("."), false)
}

/// [`resolve_plugin`] with an explicit workspace-plugin opt-in (CLI `--allow-workspace-plugins`).
pub fn resolve_plugin_with_policy(
    identifier: &str,
    allow_workspace_plugins: bool,
) -> Result<CordonPlugin, CordonError> {
    resolve_plugin_in(identifier, Path::new("."), allow_workspace_plugins)
}

/// [`resolve_plugin`] against an explicit workspace root (testable seam).
pub fn resolve_plugin_in(
    identifier: &str,
    workspace_root: &Path,
    allow_workspace_plugins: bool,
) -> Result<CordonPlugin, CordonError> {
    let trimmed = identifier.trim().trim_matches('"').trim_matches('\'');
    let normalized = trimmed.strip_prefix("cordon-plugins/").unwrap_or(trimmed);

    // 1. Built-in plugins always win (anti-shadowing, CH-05).
    for builtin in [builtin_cordon_fish_plugin(), builtin_cordon_hud_plugin()] {
        if builtin.name.eq_ignore_ascii_case(normalized)
            || builtin.repo_id.eq_ignore_ascii_case(trimmed)
        {
            return Ok(builtin);
        }
    }

    let trusted_roots = plugin_search_roots(Some(workspace_root), allow_workspace_plugins);

    // 2. Explicit manifest path (file or directory) when it lives inside a trusted root.
    let expanded = expand_tilde(trimmed);
    let as_path = if Path::new(&expanded).is_absolute() {
        PathBuf::from(expanded)
    } else {
        workspace_root.join(expanded)
    };
    let candidate_manifest = if as_path.is_dir() {
        as_path.join("plugin.toml")
    } else {
        as_path.clone()
    };
    if candidate_manifest.is_file()
        && trusted_roots
            .iter()
            .any(|root| path_is_within(&candidate_manifest, root))
    {
        return load_plugin_manifest(&candidate_manifest);
    }

    // 3. Name-based probes under trusted roots only.
    for root in &trusted_roots {
        for candidate in [
            root.join("plugins").join(normalized).join("plugin.toml"),
            root.join(normalized).join("plugin.toml"),
            root.join("cordon-plugins")
                .join(normalized)
                .join("plugin.toml"),
        ] {
            if candidate.is_file() {
                return load_plugin_manifest(&candidate);
            }
        }
    }

    // 4. Catalog lookup (builtins + trusted-root manifests).
    for plugin in list_available_plugins_in(Some(workspace_root), allow_workspace_plugins) {
        if plugin.name.eq_ignore_ascii_case(normalized)
            || plugin.repo_id.eq_ignore_ascii_case(trimmed)
        {
            return Ok(plugin);
        }
    }

    if !allow_workspace_plugins {
        return Err(CordonError::InvalidInput(format!(
            "Unknown Cordon plugin '{identifier}'. Available plugins: {}. Workspace-relative plugins are denied by default; pass --allow-workspace-plugins to load them.",
            PLUGIN_CANDIDATES.join(", ")
        )));
    }
    Err(CordonError::InvalidInput(format!(
        "Unknown Cordon plugin '{identifier}'. Available plugins: {}",
        PLUGIN_CANDIDATES.join(", ")
    )))
}
