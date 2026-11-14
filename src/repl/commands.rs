//! REPL loop runners (`run_interactive_repl`, `run_repl_with_io`) and top-level line dispatcher.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::{
    CordonEnvironmentConfig, expand_tilde, list_config_templates, parse_env_assignment,
    parse_volume_spec,
};
use crate::plugins::{parse_tmux_plugin_directive, resolve_plugin};
use crate::profiles::{get_profile, list_profiles};
use crate::repl_editor::{
    LineEditorRenderConfig, env_value_for_display, read_interactive_tty_line,
};
use crate::sandbox::{prepare_live_execution_argv, run_doctor_checks};

use super::builtins::{
    handle_allow_bin, handle_allow_group, handle_deny_bin, handle_eval, handle_history,
    handle_mount_group, write_repl_help, write_repl_status,
};
use super::exec::{
    execute_dot_slash_target, execute_repl_sandbox_cmd, expand_alias_if_present, handle_repl_ls,
    handle_repl_plugin, write_groups_summary,
};
use super::{ReplNetMode, ReplSession, ts};

/// Runs the interactive Cordon REPL using `crossterm` raw-mode line editing when connected to a TTY,
/// or falls back to line-buffered [`run_repl_with_io`] when piped.
pub fn run_interactive_repl(session: &mut ReplSession) -> Result<i32> {
    if !std::io::stdin().is_terminal() {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout().lock();
        return run_repl_with_io(session, stdin.lock(), &mut stdout);
    }

    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "\x1b[1;36mPyCentric Cordon Interactive Sandbox REPL\x1b[0m (plugins: \x1b[1;35m{}\x1b[0m | shortcuts: \x1b[36mUp/Down, Ctrl-R, Ctrl-U, Tab, Right\x1b[0m)",
        ts(&session
            .active_plugins
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", "))
    )?;
    writeln!(
        stdout,
        "Type \x1b[1;32mhelp\x1b[0m for commands, \x1b[1;32mls\x1b[0m to list configs, \x1b[1;32mallow-bin bat rg\x1b[0m to mount tools, or \x1b[1;32m./configs/Cordonfile.opencode\x1b[0m to run."
    )?;

    loop {
        let (prompt_str, prompt_len) = session.prompt_colored();
        let valid_cmds = session.valid_command_set();
        let candidates = session.completion_candidates();
        let maybe_line = read_interactive_tty_line(
            &mut stdout,
            &LineEditorRenderConfig {
                prompt_display: &prompt_str,
                prompt_visible_chars: prompt_len,
                history: &session.history,
                enable_syntax_highlight: session.syntax_highlighting_enabled(),
                enable_fish_autosuggest: session.fish_autosuggest_enabled(),
                valid_commands: &valid_cmds,
                completion_candidates: &candidates,
            },
        )?;

        let Some(line) = maybe_line else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        session.history.push(trimmed);
        if !handle_repl_line(session, trimmed, &mut stdout)? {
            break;
        }
    }
    Ok(0)
}

/// Runs the Cordon REPL loop over generic [`BufRead`] and [`Write`] streams.
pub fn run_repl_with_io<R: BufRead, W: Write>(
    session: &mut ReplSession,
    mut reader: R,
    out: &mut W,
) -> Result<i32> {
    writeln!(
        out,
        "PyCentric Cordon Interactive Sandbox REPL (type 'help' for commands, '!<cmd>' or 'run <cmd>' to execute, 'exit' to quit)"
    )?;
    let mut line_buf = String::new();
    loop {
        write!(out, "{}", session.prompt())?;
        out.flush()?;
        line_buf.clear();
        let bytes_read = reader.read_line(&mut line_buf)?;
        if bytes_read == 0 {
            writeln!(out)?;
            break;
        }
        let trimmed = line_buf.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        session.history.push(trimmed);
        if !handle_repl_line(session, trimmed, out)? {
            break;
        }
    }
    Ok(0)
}

pub(super) fn handle_repl_line<W: Write>(
    session: &mut ReplSession,
    line: &str,
    out: &mut W,
) -> Result<bool> {
    if let Some(plugin_id) = parse_tmux_plugin_directive(line) {
        match resolve_plugin(&plugin_id) {
            Ok(plugin) => {
                let name = plugin.name.clone();
                session.enable_plugin_instance(plugin);
                writeln!(
                    out,
                    "Enabled Cordon plugin '{}' via @plugin directive.",
                    ts(&name)
                )?;
            }
            Err(e) => writeln!(
                out,
                "Error loading plugin '{}': {}",
                ts(&plugin_id),
                ts(&e.to_string())
            )?,
        }
        return Ok(true);
    }

    let expanded_line = expand_alias_if_present(session, line);
    let active_line = expanded_line.as_str();

    if let Some(bang_cmd) = active_line.strip_prefix('!') {
        let argv: Vec<String> = bang_cmd.split_whitespace().map(str::to_owned).collect();
        execute_repl_sandbox_cmd(session, &argv, out)?;
        return Ok(true);
    }

    if active_line.starts_with("./") {
        execute_dot_slash_target(session, active_line, out)?;
        return Ok(true);
    }

    let parts: Vec<&str> = active_line.split_whitespace().collect();
    let Some((&cmd, args)) = parts.split_first() else {
        return Ok(true);
    };

    match cmd {
        "exit" | "quit" | "q" => return Ok(false),
        "help" | "?" => write_repl_help(out)?,
        "status" | "info" => write_repl_status(session, out)?,
        "ls" => handle_repl_ls(session, args, out)?,
        "groups" => write_groups_summary(out)?,
        "allow-bin" | "expose-bin" => handle_allow_bin(session, args, out)?,
        "deny-bin" | "mask-bin" => handle_deny_bin(session, args, out)?,
        "allow-group" => handle_allow_group(session, args, out)?,
        "mount-group" => handle_mount_group(session, args, out)?,
        "plugin" | "plugins" => handle_repl_plugin(session, args, out)?,
        "alias" => {
            if args.is_empty() {
                for (k, v) in &session.aliases {
                    writeln!(out, "  {:<12} = \"{}\"", ts(k), ts(v))?;
                }
            } else if let Some((k, v)) = args.join(" ").split_once('=') {
                let clean_k = k.trim();
                let clean_v = v.trim().trim_matches('"').trim_matches('\'');
                session
                    .aliases
                    .insert(clean_k.to_owned(), clean_v.to_owned());
                writeln!(out, "Defined alias {}=\"{}\"", ts(clean_k), ts(clean_v))?;
            } else {
                writeln!(out, "Usage: alias [name=command]")?;
            }
        }
        "history" => handle_history(session, args, out)?,
        "profiles" => {
            for p in list_profiles() {
                writeln!(
                    out,
                    "  {:<16} [{:?} | {:?}] - {}",
                    p.name, p.filesystem_mode, p.network_mode, p.description
                )?;
            }
        }
        "templates" => {
            for t in list_config_templates() {
                writeln!(
                    out,
                    "  {:<18} [base: {:<14} | file: {:<24}] - {}",
                    t.slug, t.base_profile, t.default_filename, t.summary
                )?;
            }
        }
        "use" | "profile" => {
            if let Some(&target) = args.first() {
                match get_profile(target) {
                    Ok(p) => {
                        session.profile = p.name;
                        writeln!(
                            out,
                            "Switched active profile to '{}'.",
                            ts(&session.profile)
                        )?;
                    }
                    Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
                }
            } else {
                writeln!(out, "Usage: use <profile>")?;
            }
        }
        "load" => {
            if let Some(&path_str) = args.first() {
                let path = PathBuf::from(expand_tilde(path_str));
                match CordonEnvironmentConfig::from_file(&path) {
                    Ok(cfg) => {
                        session.profile.clone_from(&cfg.base_profile);
                        session.config_path = Some(path.clone());
                        session.loaded_config = Some(cfg);
                        writeln!(
                            out,
                            "Loaded config '{}' (base_profile={}).",
                            ts(&path.display().to_string()),
                            ts(&session.profile)
                        )?;
                    }
                    Err(e) => writeln!(out, "Error loading config: {}", ts(&e.to_string()))?,
                }
            } else {
                writeln!(out, "Usage: load <path/to/Cordonfile>")?;
            }
        }
        "cd" | "workspace" => {
            if let Some(&dir_str) = args.first() {
                session.workspace = PathBuf::from(expand_tilde(dir_str));
                writeln!(
                    out,
                    "Active workspace set to '{}'.",
                    ts(&session.workspace.display().to_string())
                )?;
            } else {
                writeln!(out, "Usage: cd <workspace_dir>")?;
            }
        }
        "mount" | "vol" => {
            if let Some(&spec) = args.first() {
                match parse_volume_spec(spec) {
                    Ok((path, true)) => {
                        session.writable_mounts.push(path.clone());
                        writeln!(out, "Added read-write mount: {}", ts(&path))?;
                    }
                    Ok((path, false)) => {
                        session.readonly_mounts.push(path.clone());
                        writeln!(out, "Added read-only mount: {}", ts(&path))?;
                    }
                    Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
                }
            } else {
                writeln!(out, "Usage: mount <host_path[:ro|:rw]>")?;
            }
        }
        "env" => {
            if let Some(&raw) = args.first() {
                match parse_env_assignment(raw) {
                    Ok((k, v)) => {
                        session.envs.insert(k.clone(), v.clone());
                        writeln!(
                            out,
                            "Set sandbox env {}={}",
                            ts(&k),
                            env_value_for_display(&k, &v)
                        )?;
                    }
                    Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
                }
            } else {
                writeln!(out, "Usage: env KEY=VALUE")?;
            }
        }
        "allow" => {
            if let Some(&dom) = args.first() {
                session.allowed_domains.push(dom.to_owned());
                writeln!(out, "Added allowed outbound domain: {}", ts(dom))?;
            } else {
                writeln!(out, "Usage: allow <domain>")?;
            }
        }
        "net" => match args.first().copied() {
            Some("auto") => {
                session.net_mode = ReplNetMode::Auto;
                writeln!(out, "Network mode set to 'auto'.")?;
            }
            Some("direct" | "host") => {
                session.net_mode = ReplNetMode::Direct;
                writeln!(out, "Network mode set to 'direct' (host network).")?;
            }
            Some("airgap" | "offline" | "none") => {
                session.net_mode = ReplNetMode::Airgap;
                writeln!(out, "Network mode set to 'airgap' (bwrap --unshare-net).")?;
            }
            Some("netns") => {
                session.net_mode = ReplNetMode::Netns;
                writeln!(out, "Network mode set to 'netns'.")?;
            }
            _ => writeln!(out, "Usage: net <auto|direct|airgap|netns>")?,
        },
        "plan" | "inspect" => {
            let target_cmd: Vec<String> = if args.is_empty() {
                vec!["opencode".to_owned()]
            } else {
                args.iter().map(|s| (*s).to_owned()).collect()
            };
            match session.compile_session_plan(&target_cmd) {
                Ok(plan) => {
                    let (live_argv, notice) = prepare_live_execution_argv(
                        &plan,
                        session.net_mode == ReplNetMode::Airgap,
                        session.net_mode == ReplNetMode::Direct,
                    );
                    writeln!(out, "Gates: {}", ts(&plan.gates_applied.join(" -> ")))?;
                    if let Some(msg) = notice {
                        writeln!(out, "Note:  {}", ts(&msg))?;
                    }
                    writeln!(out, "Exec:  {}", ts(&live_argv.join(" ")))?;
                }
                Err(e) => writeln!(out, "Error compiling plan: {}", ts(&e.to_string()))?,
            }
        }
        "eval" | "url" => handle_eval(session, args, out)?,
        "doctor" => {
            let report = run_doctor_checks();
            writeln!(out, "Platform: {}", ts(&report.platform_summary))?;
            for c in &report.checks {
                let badge = if c.passed { "PASS" } else { "WARN" };
                writeln!(out, "  [{badge}] {:<18} {}", ts(&c.name), ts(&c.detail))?;
            }
        }
        "clear" => {
            session.readonly_mounts.clear();
            session.writable_mounts.clear();
            session.allowed_binaries.clear();
            session.command_groups.clear();
            session.directory_groups.clear();
            session.envs.clear();
            session.allowed_domains.clear();
            writeln!(
                out,
                "Cleared session mounts, allowed binaries/groups, env vars, and domain overrides."
            )?;
        }
        "shell" => {
            let shell_bin = if Path::new("/bin/bash").exists() {
                vec!["/bin/bash".to_owned(), "--norc".to_owned()]
            } else {
                vec!["/bin/sh".to_owned()]
            };
            execute_repl_sandbox_cmd(session, &shell_bin, out)?;
        }
        "run" | "exec" => {
            let target_cmd: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            execute_repl_sandbox_cmd(session, &target_cmd, out)?;
        }
        _ => {
            writeln!(
                out,
                "Unknown REPL command '{}'. Type 'help' for commands, 'ls' for configs, or '!<cmd>' / 'run <cmd>' to run inside sandbox.",
                ts(cmd)
            )?;
        }
    }

    Ok(true)
}
