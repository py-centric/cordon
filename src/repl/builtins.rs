//! Builtin REPL subcommand helpers (`help`, `status`, `allow-bin`, `deny-bin`, `allow-group`, `mount-group`, `history`, `eval`).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::groups::{get_command_group, get_directory_group, resolve_host_binary};
use crate::l7_policy::CordonPolicyEvaluator;
use crate::profiles::get_profile;
use crate::repl_editor::env_value_for_display;

use super::{ReplSession, ts};

pub(super) fn write_repl_help<W: Write>(out: &mut W) -> Result<()> {
    writeln!(
        out,
        "Cordon Interactive Sandbox REPL Commands:\n\
         \x20 help | ?                       Show this command and keyboard shortcut reference\n\
         \x20 status | info                  Show active profile, workspace, mounts, groups, and plugins\n\
         \x20 ls [configs|mounts|bins|groups|plugins|<dir>]\n\
         \x20                                List executable Cordonfiles, mounts, binaries, groups, or plugins\n\
         \x20 ./<Cordonfile|script> [args]   Execute a Cordonfile config or script directly inside the sandbox\n\
         \x20 allow-bin <prog...>            Unmask & mount specific host programs (e.g. allow-bin bat rg fd jq)\n\
         \x20 deny-bin <prog...>             Mask specific host binaries with /dev/null inside the sandbox\n\
         \x20 allow-group <group...>         Enable pre-populated command group (coreutils, search-tools, vcs-git, etc.)\n\
         \x20 mount-group <group[:ro|:rw]>   Mount pre-populated directory group (xdg-config, agent-state, ssl-certs, etc.)\n\
         \x20 groups                         List all 8 pre-populated command groups and 6 directory groups\n\
         \x20 plugin <list|enable|disable|info> [name]\n\
         \x20                                Manage tmux-style Cordon plugins (cordon-fish, cordon-hud)\n\
         \x20 set -g @plugin '<name>'        Tmux-style directive to load a Cordon plugin\n\
         \x20 alias [name=value]             List or define REPL command aliases (ag, oc, py, ll, bat-rg)\n\
         \x20 history [clear|search <q>]     Show, clear, or search persistent REPL command history\n\
         \x20 profiles | templates           List built-in profiles or reproducible Cordonfile templates\n\
         \x20 use <profile>                  Switch active profile (ai-agent, untrusted-code, etc.)\n\
         \x20 load <file>                    Load a Cordonfile, Cordonfile.toml, or cordon.json into session\n\
         \x20 cd <dir>                       Change active workspace directory\n\
         \x20 mount <path[:ro|:rw]>          Attach a host volume mount (:ro default or :rw)\n\
         \x20 env <KEY=VALUE>                Inject an environment variable into the sandbox\n\
         \x20 allow <domain>                 Add an allowed outbound domain to Gate 4 L7 policy\n\
         \x20 net <auto|direct|airgap|netns> Set network execution mode (airgap = --unshare-net)\n\
         \x20 plan [cmd...]                  Compile and display the 5-gate bwrap launch plan\n\
         \x20 eval <url> [METHOD] [BODY]     Test URL/method/body against Gate 4 L7 policy & secret scan\n\
         \x20 doctor                         Run 7-point host kernel LSM and binary checks\n\
         \x20 run <cmd...> | !<cmd...>       Execute command inside the Cordon Bubblewrap sandbox\n\
         \x20 shell                          Drop into an interactive bash shell inside the sandbox\n\
         \x20 clear                          Reset session mounts, env vars, and domain overrides\n\
         \x20 exit | quit                    Exit the Cordon REPL\n\n\
         Keyboard Shortcuts (Interactive Terminal Mode):\n\
         \x20 Up / Down (Ctrl-P / Ctrl-N)    Navigate persistent command history (~/.local/share/cordon/repl_history)\n\
         \x20 Right / Ctrl-F / End           Accept Fish inline ghost autosuggestion\n\
         \x20 Tab                            Contextual completion for commands, Cordonfiles, groups, and plugins\n\
         \x20 Ctrl-R                         Incremental reverse-i-search through command history\n\
         \x20 Ctrl-U / Ctrl-K / Ctrl-W       Kill line before cursor / kill to end / delete previous word\n\
         \x20 Ctrl-A / Ctrl-E / Ctrl-L       Start of line / end of line / clear terminal screen"
    )?;
    Ok(())
}

pub(super) fn write_repl_status<W: Write>(session: &ReplSession, out: &mut W) -> Result<()> {
    writeln!(out, "Profile:          {}", ts(&session.profile))?;
    writeln!(
        out,
        "Config File:      {}",
        ts(&session
            .config_path
            .as_ref()
            .map_or_else(|| "(none)".to_owned(), |p| p.display().to_string()))
    )?;
    writeln!(
        out,
        "Workspace:        {}",
        ts(&session.workspace.display().to_string())
    )?;
    writeln!(out, "Network Mode:     {}", session.net_mode.as_str())?;
    writeln!(out, "Command Groups:   {:?}", session.command_groups)?;
    writeln!(out, "Allowed Binaries: {:?}", session.allowed_binaries)?;
    writeln!(out, "Directory Groups: {:?}", session.directory_groups)?;
    writeln!(out, "RO Mounts:        {:?}", session.readonly_mounts)?;
    writeln!(out, "RW Mounts:        {:?}", session.writable_mounts)?;
    writeln!(out, "Extra Domains:    {:?}", session.allowed_domains)?;
    let redacted_envs: BTreeMap<&str, String> = session
        .envs
        .iter()
        .map(|(k, v)| (k.as_str(), env_value_for_display(k, v)))
        .collect();
    writeln!(out, "Env Overrides:    {redacted_envs:?}")?;
    writeln!(
        out,
        "Active Plugins:   {:?}",
        session
            .active_plugins
            .iter()
            .map(|p| &p.name)
            .collect::<Vec<_>>()
    )?;
    Ok(())
}

pub(super) fn handle_allow_bin<W: Write>(
    session: &mut ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    if args.is_empty() {
        writeln!(
            out,
            "Usage: allow-bin <prog1> [prog2...] (e.g. allow-bin bat rg fd jq)"
        )?;
        return Ok(());
    }
    for &prog in args {
        if !session.allowed_binaries.iter().any(|b| b == prog) {
            session.allowed_binaries.push(prog.to_owned());
        }
        session.masked_binaries.retain(|m| {
            Path::new(m).file_name().and_then(|n| n.to_str()) != Some(prog) && m != prog
        });
        if let Some(resolved) = resolve_host_binary(prog) {
            writeln!(
                out,
                "Exposed binary '{}' -> {} (mounted read-only inside sandbox)",
                ts(prog),
                ts(&resolved.display().to_string())
            )?;
        } else {
            writeln!(
                out,
                "Unmasked binary '{}' in sandbox policy (not currently found on host PATH)",
                ts(prog)
            )?;
        }
    }
    Ok(())
}

pub(super) fn handle_deny_bin<W: Write>(
    session: &mut ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    if args.is_empty() {
        writeln!(out, "Usage: deny-bin <prog1> [prog2...]")?;
        return Ok(());
    }
    for &prog in args {
        session.allowed_binaries.retain(|b| b != prog);
        let target = if prog.starts_with('/') {
            prog.to_owned()
        } else {
            format!("/usr/bin/{prog}")
        };
        if !session.masked_binaries.contains(&target) {
            session.masked_binaries.push(target.clone());
        }
        writeln!(
            out,
            "Masked binary '{}' ({} -> /dev/null)",
            ts(prog),
            ts(&target)
        )?;
    }
    Ok(())
}

pub(super) fn handle_allow_group<W: Write>(
    session: &mut ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    if args.is_empty() {
        writeln!(
            out,
            "Usage: allow-group <group...> (available: coreutils, shell-builtins, search-tools, vcs-git, rust-toolchain, python-uv, node-web, net-diag)"
        )?;
        return Ok(());
    }
    for &grp_slug in args {
        match get_command_group(grp_slug) {
            Ok(grp) => {
                if !session.command_groups.iter().any(|g| g == grp.slug) {
                    session.command_groups.push(grp.slug.to_owned());
                }
                writeln!(
                    out,
                    "Enabled command group '{}' ({} programs: {})",
                    grp.slug,
                    grp.programs.len(),
                    grp.programs.join(", ")
                )?;
            }
            Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
        }
    }
    Ok(())
}

pub(super) fn handle_mount_group<W: Write>(
    session: &mut ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    if args.is_empty() {
        writeln!(
            out,
            "Usage: mount-group <group[:ro|:rw]> (available: system-libs, ssl-certs, xdg-config, agent-state, toolchain-caches, temp-scratch)"
        )?;
        return Ok(());
    }
    for &spec in args {
        match get_directory_group(spec) {
            Ok(grp) => {
                if !session.directory_groups.iter().any(|g| g == spec) {
                    session.directory_groups.push(spec.to_owned());
                }
                writeln!(
                    out,
                    "Mounted directory group '{}' ({})",
                    spec,
                    grp.paths.join(", ")
                )?;
            }
            Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
        }
    }
    Ok(())
}

pub(super) fn handle_history<W: Write>(
    session: &mut ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    match args.first().copied() {
        Some("clear") => {
            session.history.clear();
            writeln!(out, "Cleared REPL command history.")?;
        }
        Some("search") => {
            let query = args.get(1).copied().unwrap_or("");
            let q_lower = query.to_ascii_lowercase();
            for (idx, entry) in session.history.entries().iter().enumerate() {
                if entry.to_ascii_lowercase().contains(&q_lower) {
                    writeln!(out, "  {:>4}  {}", idx + 1, ts(entry))?;
                }
            }
        }
        _ => {
            if let Some(p) = session.history.file_path() {
                writeln!(out, "History file: {}", ts(&p.display().to_string()))?;
            }
            for (idx, entry) in session.history.entries().iter().enumerate() {
                writeln!(out, "  {:>4}  {}", idx + 1, ts(entry))?;
            }
        }
    }
    Ok(())
}

pub(super) fn handle_eval<W: Write>(
    session: &ReplSession,
    args: &[&str],
    out: &mut W,
) -> Result<()> {
    if let Some(&url) = args.first() {
        let method = args.get(1).copied().unwrap_or("GET");
        let body = if args.len() > 2 {
            Some(args[2..].join(" "))
        } else {
            None
        };
        if let Ok(mut prof) = get_profile(&session.profile) {
            for dom in &session.allowed_domains {
                if !prof.allowed_domains.contains(dom) {
                    prof.allowed_domains.push(dom.clone());
                }
            }
            let evaluator = CordonPolicyEvaluator::new(prof);
            let d = evaluator.evaluate_request(url, method, body.as_deref());
            writeln!(
                out,
                "[{:?}] HTTP {} ({}) - {}",
                d.verdict,
                d.status_code,
                ts(&d.matched_rule),
                ts(&d.reason)
            )?;
        }
    } else {
        writeln!(out, "Usage: eval <url> [METHOD] [BODY]")?;
    }
    Ok(())
}
