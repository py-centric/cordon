//! Tmux-style Cordon Plugin Ecosystem (`cordon-fish`, `cordon-hud`, and custom `plugin.toml` manifests).
//!
//! Supports `set -g @plugin 'cordon-plugins/<name>'` directives, REPL `plugin enable|disable|list|info`,
//! Fish-style abbreviated prompt paths (`~/P/cordon`), and Cordon HUD telemetry prompts & aliases.

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
#[allow(clippy::struct_excessive_bools)]
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
    aliases.insert(
        "bat-rg".to_owned(),
        "allow-group search-tools".to_owned(),
    );

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
///
/// Filesystem discovery is restricted to `$HOME/.config/cordon/plugins` by default so a hostile
/// workspace cannot shadow or extend the plugin catalog. Workspace-relative discovery
/// (`./plugins/*/plugin.toml`) requires the explicit `--allow-workspace-plugins` opt-in.
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

/// Returns the filesystem roots trusted for plugin manifest discovery.
///
/// `$HOME/.config/cordon` (and its `plugins/` subdir) is always trusted. `workspace_root` (when
/// supplied) is only included with the explicit `allow_workspace_plugins` opt-in (default DENY).
fn plugin_search_roots(
    workspace_root: Option<&Path>,
    allow_workspace_plugins: bool,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let home_cordon = PathBuf::from(format!(
            "{}/.config/cordon",
            home.trim_end_matches('/')
        ));
        roots.push(home_cordon.join("plugins"));
        roots.push(home_cordon);
    }
    if allow_workspace_plugins
        && let Some(ws) = workspace_root
    {
        roots.push(ws.join("plugins"));
        roots.push(ws.join("cordon-plugins"));
        roots.push(ws.to_path_buf());
    }
    roots
}

/// Returns `true` when `candidate` resolves inside `root` (symlinks resolved when possible).
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
///
/// Built-in plugins resolve FIRST and can never be shadowed by a workspace manifest. Filesystem
/// manifests are only loaded from `$HOME/.config/cordon` by default; workspace-relative manifests
/// require `--allow-workspace-plugins` (see [`resolve_plugin_with_policy`]).
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
    let trimmed = identifier
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    let normalized = trimmed
        .strip_prefix("cordon-plugins/")
        .unwrap_or(trimmed);

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
    // Relative identifiers are resolved against the workspace root, never the raw process CWD.
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

/// Parses a `plugin.toml` manifest file from disk.
pub fn load_plugin_manifest(path: &Path) -> Result<CordonPlugin, CordonError> {
    let raw = std::fs::read_to_string(path)?;
    parse_plugin_toml_str(&raw)
}

/// Parses a declarative `plugin.toml` string into a [`CordonPlugin`].
pub fn parse_plugin_toml_str(raw: &str) -> Result<CordonPlugin, CordonError> {
    let mut plugin = CordonPlugin {
        name: "custom-plugin".to_owned(),
        repo_id: "cordon-plugins/custom-plugin".to_owned(),
        version: "0.1.0".to_owned(),
        description: String::new(),
        features: PluginFeatures::default(),
        aliases: BTreeMap::new(),
        default_command_groups: Vec::new(),
        default_directory_groups: Vec::new(),
    };

    let mut section = String::new();
    for raw_line in raw.lines() {
        let without_comment = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let line = without_comment.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().trim_matches('"').trim_matches('\'');
        let val = v.trim();
        let clean_scalar = val.trim_matches('"').trim_matches('\'');

        match (section.as_str(), key) {
            ("plugin" | "", "name") => clean_scalar.clone_into(&mut plugin.name),
            ("plugin" | "", "repo_id") => clean_scalar.clone_into(&mut plugin.repo_id),
            ("plugin" | "", "version") => clean_scalar.clone_into(&mut plugin.version),
            ("plugin" | "", "description") => clean_scalar.clone_into(&mut plugin.description),
            ("features", "fish_autosuggest") => {
                plugin.features.fish_autosuggest = clean_scalar.eq_ignore_ascii_case("true");
            }
            ("features", "syntax_highlighting") => {
                plugin.features.syntax_highlighting = clean_scalar.eq_ignore_ascii_case("true");
            }
            ("features", "abbreviate_cwd") => {
                plugin.features.abbreviate_cwd = clean_scalar.eq_ignore_ascii_case("true");
            }
            ("features", "powerline_prompt") => {
                plugin.features.powerline_prompt = clean_scalar.eq_ignore_ascii_case("true");
            }
            ("features", "startup_banner") => {
                plugin.features.startup_banner = clean_scalar.eq_ignore_ascii_case("true");
            }
            ("groups" | "plugin" | "", "default_command_groups") => {
                plugin.default_command_groups = parse_toml_inline_list(val);
            }
            ("groups" | "plugin" | "", "default_directory_groups") => {
                plugin.default_directory_groups = parse_toml_inline_list(val);
            }
            ("aliases", alias_name) => {
                plugin
                    .aliases
                    .insert(alias_name.to_owned(), clean_scalar.to_owned());
            }
            _ => {}
        }
    }

    Ok(plugin)
}

fn parse_toml_inline_list(raw: &str) -> Vec<String> {
    let inner = raw
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parses a tmux-style plugin declaration such as:
/// - `set -g @plugin 'cordon-plugins/cordon-fish'`
/// - `set -g @plugin "cordon-hud"`
pub fn parse_tmux_plugin_directive(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens.as_slice() {
        ["set", "-g", "@plugin", raw_target] | ["set", "@plugin", raw_target] => {
            let cleaned = raw_target.trim_matches('"').trim_matches('\'');
            (!cleaned.is_empty()).then(|| cleaned.to_owned())
        }
        _ => None,
    }
}

/// Formats a path in Fish-shell `prompt_pwd` style (`/home/v/Projects/cordon` -> `~/P/cordon`).
pub fn abbreviate_fish_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let home_replaced = if let Ok(home) = std::env::var("HOME") {
        let home_trim = home.trim_end_matches('/');
        if !home_trim.is_empty() && raw == home_trim {
            "~".to_owned()
        } else if let Some(rest) = raw.strip_prefix(&format!("{home_trim}/")) {
            format!("~/{rest}")
        } else {
            raw.into_owned()
        }
    } else {
        raw.into_owned()
    };

    let parts: Vec<&str> = home_replaced.split('/').collect();
    if parts.len() <= 2 {
        return home_replaced;
    }

    let mut out = Vec::with_capacity(parts.len());
    for (idx, part) in parts.iter().enumerate() {
        if idx == parts.len() - 1 || *part == "~" || part.is_empty() {
            out.push((*part).to_owned());
        } else if let Some(stripped) = part.strip_prefix('.') {
            let ch = stripped.chars().next().unwrap_or('.');
            out.push(format!(".{ch}"));
        } else if let Some(ch) = part.chars().next() {
            out.push(ch.to_string());
        }
    }
    out.join("/")
}

/// Reads `.git/HEAD` in `workspace` without spawning a subprocess to return the active git branch name.
pub fn detect_git_branch(workspace: &Path) -> Option<String> {
    let head_path = workspace.join(".git/HEAD");
    let content = std::fs::read_to_string(head_path).ok()?;
    let trimmed = content.trim();
    if let Some(ref_path) = trimmed.strip_prefix("ref: refs/heads/") {
        Some(ref_path.to_owned())
    } else if trimmed.len() >= 7 {
        Some(trimmed[..7].to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn make_tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cordon-plugins-{tag}-{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        assert!(
            std::fs::create_dir_all(&dir).is_ok(),
            "failed to create temp dir {}",
            dir.display()
        );
        dir
    }

    fn write_manifest(dir: &Path, manifest: &str) {
        assert!(
            std::fs::create_dir_all(dir).is_ok(),
            "failed to create {}",
            dir.display()
        );
        assert!(
            std::fs::write(dir.join("plugin.toml"), manifest).is_ok(),
            "failed to write manifest in {}",
            dir.display()
        );
    }

    #[test]
    fn resolves_builtin_fish_and_cordon_hud_plugins() -> Result<(), CordonError> {
        let fish = resolve_plugin("cordon-fish")?;
        assert!(fish.features.fish_autosuggest);
        assert!(fish.features.syntax_highlighting);

        let hud = resolve_plugin("cordon-plugins/cordon-hud")?;
        assert!(hud.features.powerline_prompt);
        assert_eq!(
            hud.aliases.get("ag").map(String::as_str),
            Some("./configs/Cordonfile.antigravity")
        );
        Ok(())
    }

    #[test]
    fn parses_tmux_plugin_directive_and_abbreviates_paths() {
        assert_eq!(
            parse_tmux_plugin_directive("set -g @plugin 'cordon-plugins/cordon-fish'"),
            Some("cordon-plugins/cordon-fish".to_owned())
        );
        let p = Path::new("/opt/workspaces/cordon-engine");
        assert_eq!(abbreviate_fish_path(p), "/o/w/cordon-engine");
    }

    #[test]
    fn hostile_workspace_manifest_cannot_shadow_builtins() {
        let tmp = make_tmp_dir("shadow");
        let hostile = tmp.join("cordon-fish");
        write_manifest(
            &hostile,
            "name = \"cordon-fish\"\nrepo_id = \"cordon-plugins/cordon-fish\"\nversion = \"9.9.9\"\n\
             [groups]\ndefault_command_groups = [\"net-diag\", \"coreutils\"]\n",
        );
        for allow_workspace in [false, true] {
            let resolved = resolve_plugin_in("cordon-fish", &tmp, allow_workspace)
                .unwrap_or_else(|e| panic!("builtin must resolve: {e}"));
            assert_eq!(resolved.version, "0.2.0");
            assert_eq!(resolved.repo_id, "cordon-plugins/cordon-fish");
            assert_eq!(
                resolved.default_command_groups,
                vec!["coreutils".to_owned(), "shell-builtins".to_owned()],
                "workspace manifest must not widen builtin policy (allow_workspace={allow_workspace})"
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn workspace_plugins_denied_by_default_and_allowed_with_opt_in() {
        let tmp = make_tmp_dir("optin");
        write_manifest(
            &tmp.join("plugins").join("custom-thing"),
            "name = \"custom-thing\"\nrepo_id = \"cordon-plugins/custom-thing\"\nversion = \"1.2.3\"\n",
        );
        assert!(
            resolve_plugin_in("custom-thing", &tmp, false).is_err(),
            "workspace plugin must be denied by default"
        );
        let resolved = resolve_plugin_in("custom-thing", &tmp, true)
            .unwrap_or_else(|e| panic!("opt-in workspace plugin must resolve: {e}"));
        assert_eq!(resolved.name, "custom-thing");
        assert_eq!(resolved.version, "1.2.3");

        let denied_list = list_available_plugins_in(Some(&tmp), false);
        assert!(!denied_list.iter().any(|p| p.name == "custom-thing"));
        let allowed_list = list_available_plugins_in(Some(&tmp), true);
        assert!(allowed_list.iter().any(|p| p.name == "custom-thing"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn explicit_manifest_path_outside_trusted_roots_is_rejected() {
        let tmp = make_tmp_dir("explicit");
        write_manifest(
            &tmp.join("evil"),
            "name = \"evil\"\nrepo_id = \"cordon-plugins/evil\"\nversion = \"0.0.1\"\n",
        );
        assert!(
            resolve_plugin_in("evil/plugin.toml", &tmp, false).is_err(),
            "workspace-relative manifest path must be denied by default"
        );
        let resolved = resolve_plugin_in("evil/plugin.toml", &tmp, true)
            .unwrap_or_else(|e| panic!("opt-in manifest path must resolve: {e}"));
        assert_eq!(resolved.name, "evil");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
