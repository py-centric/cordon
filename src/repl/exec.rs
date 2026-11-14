//! REPL execution helpers (`./<config>`, `ls`, `plugin`, and sandboxed child process execution).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::config::{CordonEnvironmentConfig, expand_tilde};
use crate::groups::{list_command_groups, list_directory_groups};
use crate::plugins::{list_available_plugins, resolve_plugin};
use crate::repl_editor::{reset_terminal_after_child, sanitize_terminal_text};
use crate::sandbox::prepare_live_execution_argv;

use super::{ReplNetMode, ReplSession, ts};

pub(super) fn discover_cordon_configs() -> Vec<String> {
    let mut results = Vec::new();
    for dir in [".", "configs"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("Cordonfile")
                    || name.ends_with(".cordon")
                    || name.ends_with(".cordon.toml")
                    || name.ends_with(".cordon.json")
                {
                    let rel = if dir == "." {
                        format!("./{name}")
                    } else {
                        format!("./{dir}/{name}")
                    };
                    results.push(rel);
                }
            }
        }
    }
    results.sort();
    results
}

/// Writes a formatted summary of all pre-populated command groups and directory groups.
pub fn write_groups_summary<W: Write>(out: &mut W) -> Result<()> {
    writeln!(
        out,
        "Pre-Populated Command Groups (enable with 'allow-group <slug>'):"
    )?;
    for g in list_command_groups() {
        writeln!(
            out,
            "  {:<18} - {}\n                       [{}]",
            g.slug,
            g.summary,
            g.programs.join(", ")
        )?;
    }
    writeln!(
        out,
        "\nPre-Populated Filesystem Directory Groups (mount with 'mount-group <slug>[:ro|:rw]'):"
    )?;
    for d in list_directory_groups() {
        let mode = if d.default_writable { "rw" } else { "ro" };
        writeln!(
            out,
            "  {:<18} [default: {mode}] - {}\n                       [{}]",
            d.slug,
            d.summary,
            d.paths.join(", ")
        )?;
    }
    Ok(())
}

pub(super) fn expand_alias_if_present(session: &ReplSession, line: &str) -> String {
    let mut parts = line.splitn(2, char::is_whitespace);
    let first = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    if let Some(target) = session.aliases.get(first) {
        if rest.is_empty() {
            target.clone()
        } else {
            format!("{target} {rest}")
        }
    } else {
        line.to_owned()
    }
}

pub(super) fn execute_dot_slash_target<W: Write>(
    session: &mut ReplSession,
    line: &str,
    out: &mut W,
) -> Result<()> {
    let tokens: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let Some((target_str, extra_args)) = tokens.split_first() else {
        return Ok(());
    };
    let path = PathBuf::from(expand_tilde(target_str));
    if !path.exists() {
        writeln!(
            out,
            "Error: executable config or script '{}' does not exist.",
            path.display()
        )?;
        return Ok(());
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let looks_like_cordonfile = file_name.starts_with("Cordonfile")
        || file_name.ends_with(".cordon")
        || file_name.ends_with(".cordon.toml")
        || file_name.ends_with(".cordon.json")
        || std::fs::read_to_string(&path).is_ok_and(|content| {
            let first = content.lines().next().unwrap_or_default();
            first.contains("cordon run")
                || content.lines().any(|l| {
                    let t = l.trim();
                    t.starts_with("FROM ") || t.starts_with("[sandbox]")
                })
        });

    if looks_like_cordonfile {
        match CordonEnvironmentConfig::from_file(&path) {
            Ok(cfg) => {
                session.profile.clone_from(&cfg.base_profile);
                session.config_path = Some(path.clone());
                let cmd_to_run = if extra_args.is_empty() {
                    cfg.command.clone()
                } else {
                    extra_args.to_vec()
                };
                session.loaded_config = Some(cfg);
                writeln!(
                    out,
                    "[cordon-repl] Executing config '{}' (profile={}, cmd={:?})",
                    ts(&path.display().to_string()),
                    ts(&session.profile),
                    cmd_to_run
                )?;
                execute_repl_sandbox_cmd(session, &cmd_to_run, out)?;
            }
            Err(e) => writeln!(
                out,
                "Error parsing Cordonfile '{}': {}",
                ts(&path.display().to_string()),
                ts(&e.to_string())
            )?,
        }
    } else {
        execute_repl_sandbox_cmd(session, &tokens, out)?;
    }

    Ok(())
}

pub(super) fn handle_repl_ls<W: Write>(
    session: &ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    let target = args.first().copied().unwrap_or("configs");
    match target {
        "configs" | "cordonfiles" => {
            let configs = discover_cordon_configs();
            writeln!(
                out,
                "Available Executable Cordonfile Configurations (run with ./<path>):"
            )?;
            if configs.is_empty() {
                writeln!(out, "  (none found in ./ or ./configs)")?;
            } else {
                for cfg_path in configs {
                    let p = Path::new(&cfg_path);
                    if let Ok(parsed) = CordonEnvironmentConfig::from_file(p) {
                        writeln!(
                            out,
                            "  {:<34} [profile: {:<14} | cmd: {}]",
                            ts(&cfg_path),
                            ts(&parsed.base_profile),
                            ts(&parsed.command.join(" "))
                        )?;
                    } else {
                        writeln!(out, "  {}", ts(&cfg_path))?;
                    }
                }
            }
        }
        "mounts" | "dirs" => {
            writeln!(
                out,
                "Active Directory Groups: {:?}",
                session.directory_groups
            )?;
            writeln!(
                out,
                "Read-Only Mounts:        {:?}",
                session.readonly_mounts
            )?;
            writeln!(
                out,
                "Read-Write Mounts:       {:?}",
                session.writable_mounts
            )?;
        }
        "bins" | "programs" => {
            writeln!(out, "Active Command Groups:   {:?}", session.command_groups)?;
            writeln!(
                out,
                "Allowed Host Binaries:   {:?}",
                session.allowed_binaries
            )?;
            writeln!(
                out,
                "Masked Binaries:         {:?}",
                session.masked_binaries
            )?;
        }
        "groups" => write_groups_summary(out)?,
        "plugins" => handle_repl_plugin(&mut session.clone(), &["list"], out)?,
        dir_path => {
            let expanded = expand_tilde(dir_path);
            match std::fs::read_dir(&expanded) {
                Ok(entries) => {
                    writeln!(out, "Directory listing for '{}':", ts(&expanded))?;
                    let mut names: Vec<String> = entries
                        .flatten()
                        .map(|e| {
                            let n = e.file_name().to_string_lossy().into_owned();
                            if e.path().is_dir() {
                                format!("{n}/")
                            } else {
                                n
                            }
                        })
                        .collect();
                    names.sort();
                    for name in names {
                        writeln!(out, "  {}", ts(&name))?;
                    }
                }
                Err(e) => writeln!(
                    out,
                    "Error reading directory '{}': {}",
                    ts(&expanded),
                    ts(&e.to_string())
                )?,
            }
        }
    }
    Ok(())
}

pub(super) fn handle_repl_plugin<W: Write>(
    session: &mut ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    let sub = args.first().copied().unwrap_or("list");
    match sub {
        "list" | "ls" => {
            writeln!(out, "Cordon Tmux-Style Plugin Ecosystem:")?;
            for p in list_available_plugins() {
                let active = session.active_plugins.iter().any(|a| a.name == p.name);
                let badge = if active { "ENABLED " } else { "DISABLED" };
                writeln!(
                    out,
                    "  [{badge}] {:<16} ({}) v{} - {}",
                    ts(&p.name),
                    ts(&p.repo_id),
                    ts(&p.version),
                    ts(&p.description)
                )?;
            }
        }
        "enable" | "load" => {
            if let Some(&target) = args.get(1) {
                match resolve_plugin(target) {
                    Ok(plugin) => {
                        let name = plugin.name.clone();
                        session.enable_plugin_instance(plugin);
                        writeln!(out, "Enabled plugin '{}'.", ts(&name))?;
                    }
                    Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
                }
            } else {
                writeln!(out, "Usage: plugin enable <cordon-fish|cordon-hud|path>")?;
            }
        }
        "disable" | "unload" => {
            if let Some(&target) = args.get(1) {
                if session.disable_plugin(target) {
                    writeln!(out, "Disabled plugin '{}'.", ts(target))?;
                } else {
                    writeln!(out, "Plugin '{}' was not active.", ts(target))?;
                }
            } else {
                writeln!(out, "Usage: plugin disable <name>")?;
            }
        }
        "info" => {
            let target = args.get(1).copied().unwrap_or("cordon-hud");
            match resolve_plugin(target) {
                Ok(p) => {
                    writeln!(
                        out,
                        "Plugin:           {} ({}) v{}",
                        ts(&p.name),
                        ts(&p.repo_id),
                        ts(&p.version)
                    )?;
                    writeln!(out, "Description:      {}", ts(&p.description))?;
                    writeln!(out, "Features:         {:?}", p.features)?;
                    writeln!(out, "Command Groups:   {:?}", p.default_command_groups)?;
                    writeln!(out, "Directory Groups: {:?}", p.default_directory_groups)?;
                    writeln!(out, "Aliases:          {:?}", p.aliases)?;
                }
                Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
            }
        }
        _ => writeln!(out, "Usage: plugin <list|enable|disable|info> [name]")?,
    }
    Ok(())
}

pub(super) fn execute_repl_sandbox_cmd<W: Write>(
    session: &mut ReplSession,
    argv: &[String],
    out: &mut W,
) -> Result<()> {
    match session.compile_session_plan(argv) {
        Ok(plan) => {
            let (live_argv, notice) = if session.net_mode == ReplNetMode::Netns {
                (plan.full_argv.clone(), None)
            } else {
                prepare_live_execution_argv(
                    &plan,
                    session.net_mode == ReplNetMode::Airgap,
                    session.net_mode == ReplNetMode::Direct,
                )
            };
            if let Some(msg) = notice {
                writeln!(out, "[cordon-repl] {}", ts(&msg))?;
            }
            if session.dry_run_only {
                writeln!(out, "[dry-run] {}", ts(&live_argv.join(" ")))?;
                return Ok(());
            }
            if let Some((program, prog_args)) = live_argv.split_first() {
                let interactive_tty =
                    std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
                let spawn_result = if interactive_tty {
                    Command::new(program)
                        .args(prog_args)
                        .status()
                        .map(|status| status.code().unwrap_or(1))
                } else {
                    Command::new(program)
                        .args(prog_args)
                        .output()
                        .map(|output| {
                            let stdout_text = String::from_utf8_lossy(&output.stdout);
                            if !stdout_text.trim().is_empty() {
                                let _ = writeln!(out, "{}", sanitize_terminal_text(&stdout_text));
                            }
                            let stderr_text = String::from_utf8_lossy(&output.stderr);
                            if !stderr_text.trim().is_empty() {
                                let _ = writeln!(out, "{}", sanitize_terminal_text(&stderr_text));
                            }
                            output.status.code().unwrap_or(1)
                        })
                };
                match spawn_result {
                    Ok(code) => {
                        session.last_exit_code = code;
                        writeln!(out, "[cordon-repl] process exited with status {code}")?;
                    }
                    Err(e) => {
                        session.last_exit_code = 1;
                        writeln!(
                            out,
                            "[cordon-repl] failed to spawn '{}': {}",
                            ts(program),
                            ts(&e.to_string())
                        )?;
                    }
                }
                if interactive_tty {
                    reset_terminal_after_child(out)?;
                }
            }
        }
        Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
    }
    Ok(())
}
