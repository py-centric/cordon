//! Contextual tab completion and live ANSI syntax highlighting for the Cordon REPL.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use crate::cli::PROFILE_CANDIDATES;
use crate::config::expand_tilde;
use crate::groups::{COMMAND_GROUP_CANDIDATES, DIRECTORY_GROUP_CANDIDATES, resolve_host_binary};
use crate::plugins::PLUGIN_CANDIDATES;

use super::REPL_BUILTIN_COMMANDS;

/// Completes a partial REPL command line using contextual argument candidates or filesystem paths.
pub fn complete_line(line: &str, custom_candidates: &[String]) -> Option<String> {
    let trimmed_start = line.trim_start();
    if trimmed_start.is_empty() {
        return None;
    }

    if !trimmed_start.contains(char::is_whitespace) {
        if let Some(completed_path) = complete_filesystem_token(trimmed_start) {
            return Some(completed_path);
        }
        for &builtin in REPL_BUILTIN_COMMANDS {
            if builtin.starts_with(trimmed_start) && builtin != trimmed_start {
                return Some(builtin.to_owned());
            }
        }
        for cand in custom_candidates {
            if cand.starts_with(trimmed_start) && cand != trimmed_start {
                return Some(cand.clone());
            }
        }
        return None;
    }

    let idx = line.rfind(char::is_whitespace)?;
    let (prefix_before_last, last_tok) = (&line[..=idx], &line[idx + 1..]);
    if last_tok.is_empty() {
        return None;
    }

    let tokens: Vec<&str> = line.split_whitespace().collect();
    let first = tokens.first().copied().unwrap_or_default();

    let pool: Vec<&str> = match first {
        "use" | "profile" => PROFILE_CANDIDATES.to_vec(),
        "allow-group" => COMMAND_GROUP_CANDIDATES.to_vec(),
        "mount-group" => DIRECTORY_GROUP_CANDIDATES.to_vec(),
        "plugin" | "plugins" => {
            if tokens.len() == 2 {
                vec!["list", "enable", "disable", "info"]
            } else {
                PLUGIN_CANDIDATES.to_vec()
            }
        }
        "ls" => vec!["configs", "mounts", "bins", "groups", "plugins"],
        "net" => vec!["auto", "direct", "airgap", "netns"],
        _ => Vec::new(),
    };

    for item in pool {
        if item.starts_with(last_tok) && item != last_tok {
            return Some(format!("{prefix_before_last}{item}"));
        }
    }

    if let Some(completed_path) = complete_filesystem_token(last_tok) {
        return Some(format!("{prefix_before_last}{completed_path}"));
    }

    None
}

fn complete_filesystem_token(partial: &str) -> Option<String> {
    if !partial.starts_with("./")
        && !partial.starts_with('/')
        && !partial.starts_with("~/")
        && !partial.starts_with("configs/")
    {
        return None;
    }
    let expanded = expand_tilde(partial);
    let path = Path::new(&expanded);
    let (dir_to_read, file_prefix, display_dir_prefix) = if expanded.ends_with('/') {
        (path, "", partial)
    } else {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let slash_pos = partial.rfind('/').map_or(0, |i| i + 1);
        (parent, fname, &partial[..slash_pos])
    };

    let entries = std::fs::read_dir(dir_to_read).ok()?;
    let mut matches: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(file_prefix) && name != file_prefix {
            let suffix = if entry.path().is_dir() { "/" } else { "" };
            matches.push(format!("{display_dir_prefix}{name}{suffix}"));
        }
    }
    matches.sort();
    matches.into_iter().next()
}

/// Renders a REPL command line with live ANSI syntax highlighting and an optional dimmed Fish ghost completion.
pub fn highlight_repl_line(
    line: &str,
    ghost_suffix: Option<&str>,
    valid_commands: &BTreeSet<String>,
) -> String {
    if line.trim_start().starts_with('#') {
        return format!("\x1b[90m{line}\x1b[0m");
    }

    let mut out = String::with_capacity(line.len() + 64);
    let mut chars = line.char_indices().peekable();
    let mut is_first_token = true;

    while let Some(&(start_idx, ch)) = chars.peek() {
        if ch.is_whitespace() {
            out.push(ch);
            let _ = chars.next();
            continue;
        }

        let mut end_idx = line.len();
        let mut in_quote: Option<char> = None;
        while let Some(&(idx, c)) = chars.peek() {
            if let Some(q) = in_quote {
                if c == q {
                    in_quote = None;
                }
                let _ = chars.next();
            } else if c == '"' || c == '\'' {
                in_quote = Some(c);
                let _ = chars.next();
            } else if c.is_whitespace() {
                end_idx = idx;
                break;
            } else {
                let _ = chars.next();
            }
        }

        let token = &line[start_idx..end_idx];
        let color_code = if is_first_token {
            is_first_token = false;
            classify_command_token(token, valid_commands)
        } else {
            classify_argument_token(token)
        };

        if color_code.is_empty() {
            out.push_str(token);
        } else {
            let _ = write!(out, "{color_code}{token}\x1b[0m");
        }
    }

    if let Some(ghost) = ghost_suffix
        && !ghost.is_empty()
    {
        let _ = write!(out, "\x1b[90m{ghost}\x1b[0m");
    }

    out
}

fn classify_command_token(token: &str, valid_commands: &BTreeSet<String>) -> &'static str {
    if let Some(bang_rest) = token.strip_prefix('!') {
        if bang_rest.is_empty() || resolve_host_binary(bang_rest).is_some() {
            return "\x1b[1;32m";
        }
        return "\x1b[1;31m";
    }
    if token.starts_with("./") || token.starts_with('/') || token.starts_with("~/") {
        let expanded = expand_tilde(token);
        if Path::new(&expanded).exists() {
            return "\x1b[1;4;32m";
        }
        return "\x1b[1;31m";
    }
    if REPL_BUILTIN_COMMANDS.contains(&token)
        || valid_commands.contains(token)
        || resolve_host_binary(token).is_some()
    {
        "\x1b[1;32m"
    } else {
        "\x1b[1;31m"
    }
}

fn classify_argument_token(token: &str) -> &'static str {
    if token.starts_with('-')
        || token.ends_with(":ro")
        || token.ends_with(":rw")
        || token == "@plugin"
    {
        return "\x1b[36m";
    }
    if (token.starts_with('"') && token.ends_with('"'))
        || (token.starts_with('\'') && token.ends_with('\''))
        || token.contains('=')
    {
        return "\x1b[33m";
    }
    if PROFILE_CANDIDATES.contains(&token)
        || COMMAND_GROUP_CANDIDATES.contains(&token)
        || DIRECTORY_GROUP_CANDIDATES.contains(&token)
        || PLUGIN_CANDIDATES.contains(&token)
        || matches!(
            token,
            "auto"
                | "direct"
                | "airgap"
                | "netns"
                | "configs"
                | "mounts"
                | "bins"
                | "groups"
                | "plugins"
        )
    {
        return "\x1b[1;35m";
    }
    let expanded = expand_tilde(token);
    if (token.contains('/') || token.starts_with("Cordonfile")) && Path::new(&expanded).exists() {
        return "\x1b[4;34m";
    }
    ""
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{complete_line, highlight_repl_line};

    #[test]
    fn complete_line_handles_builtins_arguments_and_paths() {
        let custom = vec!["my-custom-cmd".to_owned()];
        assert_eq!(complete_line("", &custom), None);
        assert_eq!(
            complete_line("my-cus", &custom).as_deref(),
            Some("my-custom-cmd")
        );
        assert_eq!(
            complete_line("use ai-ag", &custom).as_deref(),
            Some("use ai-agent")
        );
        assert_eq!(
            complete_line("allow-group py", &custom).as_deref(),
            Some("allow-group python-uv")
        );
        assert_eq!(
            complete_line("plugin en", &custom).as_deref(),
            Some("plugin enable")
        );
        assert_eq!(
            complete_line("ls con", &custom).as_deref(),
            Some("ls configs")
        );
        assert_eq!(
            complete_line("net air", &custom).as_deref(),
            Some("net airgap")
        );
        assert!(complete_line("configs/Cordonfile.", &custom).is_some());
    }

    #[test]
    fn highlight_repl_line_styles_comments_commands_flags_and_ghosts() {
        let mut valid = BTreeSet::new();
        valid.insert("use".to_owned());
        valid.insert("ls".to_owned());

        assert!(highlight_repl_line("# comment", None, &valid).contains("\x1b[90m"));
        let styled = highlight_repl_line(
            "use ai-agent --dry-run \"hello\" configs/Cordonfile.python",
            Some(" --help"),
            &valid,
        );
        assert!(styled.contains("ai-agent"));
        assert!(styled.contains("--help"));
        let bad = highlight_repl_line("nonexistent_cmd --flag", None, &valid);
        assert!(bad.contains("nonexistent_cmd"));
        assert!(
            highlight_repl_line("!ls /tmp:ro FOO=bar @plugin", None, &valid).contains("\x1b[1;32m")
        );
        assert!(highlight_repl_line("!nonexistent_bin_xyz", None, &valid).contains("\x1b[1;31m"));
        assert!(highlight_repl_line("./Cargo.toml", None, &valid).contains("\x1b[1;4;32m"));
        assert!(
            highlight_repl_line("./nonexistent_cordon_xyz", None, &valid).contains("\x1b[1;31m")
        );
    }
}
