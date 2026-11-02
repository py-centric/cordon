//! Interactive Cordon Sandbox REPL (`cordon repl`) with `crossterm` line editing,
//! persistent history, `Ctrl-R` reverse search, `./` executable configs, `ls` shorthand,
//! live program/directory group mounting (`allow-bin`, `allow-group`, `mount-group`),
//! and the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::config::{
    CordonEnvironmentConfig, expand_tilde, list_config_templates, parse_env_assignment,
    parse_volume_spec,
};
use crate::domain::SandboxLaunchPlan;
use crate::groups::{
    get_command_group, get_directory_group, list_command_groups, list_directory_groups,
    resolve_host_binary,
};
use crate::l7_policy::CordonPolicyEvaluator;
use crate::plugins::{
    CordonPlugin, abbreviate_fish_path, builtin_cordon_fish_plugin, builtin_cordon_hud_plugin,
    detect_git_branch, list_available_plugins, parse_tmux_plugin_directive, resolve_plugin,
};
use crate::profiles::{get_profile, list_profiles};
use crate::repl_editor::{
    HistoryStore, REPL_BUILTIN_COMMANDS, env_value_for_display, read_interactive_tty_line,
    reset_terminal_after_child, sanitize_terminal_line, sanitize_terminal_text,
};
use crate::sandbox::{prepare_live_execution_argv, run_doctor_checks};

/// Sanitizes untrusted text for safe single-line terminal rendering.
fn ts(value: &str) -> String {
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
    ///
    /// Untrusted components (profile name, git branch, workspace path) are sanitized so a
    /// crafted branch name or directory cannot inject terminal escape sequences.
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

    fn valid_command_set(&self) -> BTreeSet<String> {
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

    fn completion_candidates(&self) -> Vec<String> {
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

fn discover_cordon_configs() -> Vec<String> {
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

fn write_repl_help<W: Write>(out: &mut W) -> Result<()> {
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
            &prompt_str,
            prompt_len,
            &session.history,
            session.syntax_highlighting_enabled(),
            session.fish_autosuggest_enabled(),
            &valid_cmds,
            &candidates,
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

#[allow(clippy::too_many_lines)]
fn handle_repl_line<W: Write>(session: &mut ReplSession, line: &str, out: &mut W) -> Result<bool> {
    // 1. Check tmux-style plugin directive: `set -g @plugin 'cordon-plugins/cordon-fish'`
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

    // 2. Expand alias if the first token matches a registered alias
    let expanded_line = expand_alias_if_present(session, line);
    let active_line = expanded_line.as_str();

    // 3. Handle !<cmd> shorthand
    if let Some(bang_cmd) = active_line.strip_prefix('!') {
        let argv: Vec<String> = bang_cmd.split_whitespace().map(str::to_owned).collect();
        execute_repl_sandbox_cmd(session, &argv, out)?;
        return Ok(true);
    }

    // 4. Handle ./<path> executable config or workspace script shorthand
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
        "status" | "info" => {
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
            // Secret-like env values are redacted before display (Debug formatting also
            // escapes terminal control characters in keys and values).
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
        }
        "ls" => handle_repl_ls(session, args, out)?,
        "groups" => write_groups_summary(out)?,
        "allow-bin" | "expose-bin" => {
            if args.is_empty() {
                writeln!(
                    out,
                    "Usage: allow-bin <prog1> [prog2...] (e.g. allow-bin bat rg fd jq)"
                )?;
            } else {
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
            }
        }
        "deny-bin" | "mask-bin" => {
            if args.is_empty() {
                writeln!(out, "Usage: deny-bin <prog1> [prog2...]")?;
            } else {
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
            }
        }
        "allow-group" => {
            if args.is_empty() {
                writeln!(
                    out,
                    "Usage: allow-group <group...> (available: coreutils, shell-builtins, search-tools, vcs-git, rust-toolchain, python-uv, node-web, net-diag)"
                )?;
            } else {
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
            }
        }
        "mount-group" => {
            if args.is_empty() {
                writeln!(
                    out,
                    "Usage: mount-group <group[:ro|:rw]> (available: system-libs, ssl-certs, xdg-config, agent-state, toolchain-caches, temp-scratch)"
                )?;
            } else {
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
            }
        }
        "plugin" | "plugins" => handle_repl_plugin(session, args, out)?,
        "alias" => {
            if args.is_empty() {
                for (k, v) in &session.aliases {
                    writeln!(out, "  {:<12} = \"{}\"", ts(k), ts(v))?;
                }
            } else {
                let joined = args.join(" ");
                if let Some((k, v)) = joined.split_once('=') {
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
        }
        "history" => match args.first().copied() {
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
        },
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
                        // Secret-like values are redacted in the echo to keep them out of
                        // terminal scrollback and session recordings.
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
        "eval" | "url" => {
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
        }
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

fn expand_alias_if_present(session: &ReplSession, line: &str) -> String {
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

fn execute_dot_slash_target<W: Write>(
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

fn handle_repl_ls<W: Write>(session: &ReplSession, args: &[&str], out: &mut W) -> Result<()> {
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

fn handle_repl_plugin<W: Write>(
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

fn execute_repl_sandbox_cmd<W: Write>(
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
                    // Interactive runs inherit the raw TTY (sandboxed shells need it), so the
                    // terminal state is force-reset below once the child exits. Residual risk:
                    // while the child runs it can still emit OSC/CSI sequences to the live
                    // terminal; only the post-run reset mitigates persistence.
                    Command::new(program)
                        .args(prog_args)
                        .status()
                        .map(|status| status.code().unwrap_or(1))
                } else {
                    // Non-interactive runs pump child stdout/stderr through the sanitizer so
                    // sandboxed output cannot inject terminal escapes into logs or pipes.
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
                    // Force a terminal state reset (cursor visible, scroll region, bracketed
                    // paste off, SGR reset) so untrusted children cannot leave the TTY hijacked.
                    reset_terminal_after_child(out)?;
                }
            }
        }
        Err(e) => writeln!(out, "Error: {}", ts(&e.to_string()))?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn repl_supports_ls_groups_allow_bin_plugins_and_dot_slash_configs() -> Result<()> {
        let mut session = ReplSession::new("ai-agent", None, None, ReplNetMode::Airgap, true)?;
        let input = "\
            ls configs\n\
            ls groups\n\
            allow-bin bat rg\n\
            allow-group search-tools\n\
            mount-group xdg-config\n\
            plugin list\n\
            plugin info cordon-fish\n\
            set -g @plugin 'cordon-plugins/cordon-hud'\n\
            ./configs/Cordonfile.antigravity\n\
            history\n\
            exit\n";
        let mut out = Vec::new();
        let code = run_repl_with_io(&mut session, Cursor::new(input), &mut out)?;
        assert_eq!(code, 0);

        let text = String::from_utf8(out)?;
        assert!(text.contains("Available Executable Cordonfile Configurations"));
        assert!(text.contains("Pre-Populated Command Groups"));
        assert!(text.contains("Enabled command group 'search-tools'"));
        assert!(text.contains("Mounted directory group 'xdg-config'"));
        assert!(text.contains("cordon-fish"));
        assert!(text.contains("Executing config './configs/Cordonfile.antigravity'"));
        assert!(text.contains("[dry-run] bwrap"));
        Ok(())
    }
}
