//! Plugin TOML manifest parser, tmux `@plugin` directive parser, and Fish/HUD path helpers.

use std::collections::BTreeMap;
use std::path::Path;

use super::{CordonPlugin, PluginFeatures};
use crate::error::CordonError;

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
