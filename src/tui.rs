//! Interactive Terminal UI (`ratatui` + `crossterm`) control center and session launcher for Cordon.
//!
//! Provides both:
//! - [`render_tui_snapshot`] for headless non-TTY snapshot rendering and automated tests.
//! - [`run_interactive_tui`] for full-screen interactive keyboard navigation, group/config
//!   customization, and live sandbox session launching (`Shell`, `REPL`, `Command`, `Cordonfile`).

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use uuid::Uuid;

use crate::api::CordonControlPlane;
use crate::config::CordonEnvironmentConfig;
use crate::domain::{
    AuditEvent, CordonProfile, EnforcementPlane, SandboxLaunchPlan, Severity, Verdict,
};
use crate::error::CordonError;
use crate::groups::{
    apply_command_group_to_profile, apply_directory_group_to_profile, list_command_group_infos,
    list_directory_group_infos,
};
use crate::ports::AuditSinkPort;
use crate::profiles::{get_profile, list_profiles};
use crate::repl::{ReplNetMode, ReplSession, run_interactive_repl};
use crate::repl_editor::{reset_terminal_after_child, sanitize_terminal_line};
use crate::sandbox::{compile_launch_plan, prepare_live_execution_argv, run_doctor_checks};

/// Number of recent telemetry events shown in the TUI telemetry pane.
const TELEMETRY_EVENT_WINDOW: usize = 25;

/// Sanitizes untrusted text for safe single-line terminal rendering inside the TUI.
fn ts(value: &str) -> String {
    sanitize_terminal_line(value)
}

/// Returns a block title with a non-color focus marker when the pane is active.
fn focus_title(active: bool, title: &str) -> String {
    if active {
        format!("> {title}")
    } else {
        title.to_owned()
    }
}

/// Active focus pane in the interactive Cordon TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiPane {
    /// Universal workload profiles (`ai-agent`, `untrusted-code`, etc.).
    Profiles,
    /// Reproducible `configs/*` files (`Cordonfile.opencode`, `Cordonfile.antigravity`, etc.).
    Configs,
    /// Pre-populated command and directory groups toggled with `Space`.
    Groups,
    /// Audit telemetry feed and live 5-Gate launch plan inspector.
    Telemetry,
}

impl TuiPane {
    /// Cycles to the next focus pane (`Tab` / `Right`).
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Profiles => Self::Configs,
            Self::Configs => Self::Groups,
            Self::Groups => Self::Telemetry,
            Self::Telemetry => Self::Profiles,
        }
    }

    /// Cycles to the previous focus pane (`BackTab` / `Left`).
    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Profiles => Self::Telemetry,
            Self::Configs => Self::Profiles,
            Self::Groups => Self::Configs,
            Self::Telemetry => Self::Groups,
        }
    }
}

/// Pending session launch request triggered from inside the interactive TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiLaunchAction {
    /// Launch an interactive sandboxed `/bin/bash --norc` shell (`s` or `Enter`).
    SandboxShell,
    /// Launch the interactive Cordon REPL preloaded with the current TUI settings (`r`).
    InteractiveRepl,
    /// Run a custom command inside the sandbox (`c` / `:`).
    CustomCommand(Vec<String>),
    /// Run the selected reproducible `configs/*` file (`x`).
    RunSelectedConfig,
}

/// Interactive state for the Cordon Terminal UI (`cordon tui`).
#[derive(Debug)]
pub struct TuiApp {
    /// Control plane holding the audit telemetry ring buffer.
    pub plane: CordonControlPlane,
    /// Available built-in workload profiles.
    pub profiles: Vec<CordonProfile>,
    /// Selected index in `profiles`.
    pub selected_profile_idx: usize,
    /// Discovered config entries (`None` = use selected profile directly, `Some(path)` = load config file).
    pub config_entries: Vec<Option<PathBuf>>,
    /// Selected index in `config_entries`.
    pub selected_config_idx: usize,
    /// Available group entries (`(is_dir_group, slug, summary)`).
    pub group_entries: Vec<(bool, String, String)>,
    /// Selected index in `group_entries`.
    pub selected_group_idx: usize,
    /// Enabled command group slugs (`coreutils`, `search-tools`, etc.).
    pub enabled_command_groups: Vec<String>,
    /// Enabled directory group specs (`xdg-config:ro`, `agent-state:rw`, etc.).
    pub enabled_directory_groups: Vec<String>,
    /// Selected scroll offset in the audit telemetry feed.
    pub telemetry_scroll: usize,
    /// Current focused pane.
    pub active_pane: TuiPane,
    /// Active network execution mode (`Auto`, `Airgap`, `Direct`).
    pub net_mode: ReplNetMode,
    /// Active workspace directory.
    pub workspace: PathBuf,
    /// Whether the inline command prompt (`c` / `:`) is currently open.
    pub input_mode: bool,
    /// Current text buffer in the inline command prompt.
    pub command_input: String,
    /// Status banner message displayed in the footer.
    pub status_message: String,
    /// Flag indicating the user requested to exit the TUI (`q` / `Esc`).
    pub should_quit: bool,
    /// Pending session launch action to execute outside raw mode.
    pub pending_launch: Option<TuiLaunchAction>,
}

impl TuiApp {
    /// Initializes a new [`TuiApp`] scanning `./configs` and preloading default groups.
    pub fn new(initial_profile: &str, workspace: Option<PathBuf>) -> Self {
        let plane = CordonControlPlane::new();
        let profiles = list_profiles();
        let selected_profile_idx = profiles
            .iter()
            .position(|p| p.name == initial_profile)
            .unwrap_or(0);

        let mut config_entries: Vec<Option<PathBuf>> = vec![None];
        if let Ok(entries) = std::fs::read_dir("configs") {
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            paths.sort();
            for p in paths {
                config_entries.push(Some(p));
            }
        }

        let mut group_entries = Vec::new();
        for cg in list_command_group_infos() {
            group_entries.push((false, cg.slug, cg.summary));
        }
        for dg in list_directory_group_infos() {
            group_entries.push((true, format!("{}:{}", dg.slug, dg.default_mode), dg.summary));
        }

        let ws = workspace
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));

        Self {
            plane,
            profiles,
            selected_profile_idx,
            config_entries,
            selected_config_idx: 0,
            group_entries,
            selected_group_idx: 0,
            enabled_command_groups: vec![
                "coreutils".to_owned(),
                "shell-builtins".to_owned(),
                "search-tools".to_owned(),
                "vcs-git".to_owned(),
            ],
            enabled_directory_groups: vec!["xdg-config:ro".to_owned()],
            telemetry_scroll: 0,
            active_pane: TuiPane::Profiles,
            net_mode: ReplNetMode::Auto,
            workspace: ws,
            input_mode: false,
            command_input: String::new(),
            status_message: "Ready. Keys: [Tab] Switch Pane | [Up/Down] Select | [Space] Toggle Group | [s/Enter] Start Shell | [r] Start REPL | [c] Run Cmd | [n] Net Mode | [q] Quit".to_owned(),
            should_quit: false,
            pending_launch: None,
        }
    }

    /// Returns the currently selected profile slug.
    pub fn active_profile_name(&self) -> &str {
        self.profiles
            .get(self.selected_profile_idx)
            .map_or("ai-agent", |p| p.name.as_str())
    }

    /// Returns the currently selected optional config file path.
    pub fn active_config_path(&self) -> Option<&Path> {
        self.config_entries
            .get(self.selected_config_idx)
            .and_then(|opt| opt.as_deref())
    }

    /// Returns the maximum valid `telemetry_scroll` offset for the current event list.
    pub fn max_telemetry_scroll(&self) -> usize {
        self.plane
            .recent_events(TELEMETRY_EVENT_WINDOW)
            .len()
            .saturating_sub(1)
    }

    /// Clamps `telemetry_scroll` to the bounds of the current telemetry list.
    pub fn clamp_telemetry_scroll(&mut self) {
        let max_scroll = self.max_telemetry_scroll();
        if self.telemetry_scroll > max_scroll {
            self.telemetry_scroll = max_scroll;
        }
    }

    /// Builds the effective [`CordonProfile`] and [`SandboxLaunchPlan`] for the current TUI selections.
    pub fn compile_active_plan(
        &self,
        command: &[String],
    ) -> Result<(CordonProfile, SandboxLaunchPlan), CordonError> {
        let mut effective_cmd = command.to_vec();
        let mut profile = if let Some(cfg_path) = self.active_config_path() {
            let cfg = CordonEnvironmentConfig::from_file(cfg_path)?;
            if effective_cmd.is_empty() && !cfg.command.is_empty() {
                effective_cmd.clone_from(&cfg.command);
            }
            cfg.build_profile()?
        } else {
            get_profile(self.active_profile_name())?
        };

        if effective_cmd.is_empty() {
            effective_cmd = vec!["/bin/bash".to_owned(), "--norc".to_owned()];
        }

        for cg in &self.enabled_command_groups {
            apply_command_group_to_profile(&mut profile, cg)?;
        }
        for dg_spec in &self.enabled_directory_groups {
            apply_directory_group_to_profile(&mut profile, dg_spec, None)?;
        }

        let plan = compile_launch_plan(&profile, &self.workspace, &effective_cmd, &[], &[])?;
        Ok((profile, plan))
    }

    /// Toggles the currently highlighted command or directory group in `TuiPane::Groups`.
    pub fn toggle_selected_group(&mut self) {
        let Some((is_dir, slug, _)) = self.group_entries.get(self.selected_group_idx).cloned()
        else {
            return;
        };
        if is_dir {
            if let Some(pos) = self
                .enabled_directory_groups
                .iter()
                .position(|g| g == &slug)
            {
                self.enabled_directory_groups.remove(pos);
                self.status_message = format!("Unmounted directory group '{slug}'.");
            } else {
                self.enabled_directory_groups.push(slug.clone());
                self.status_message = format!("Mounted directory group '{slug}'.");
            }
        } else if let Some(pos) = self.enabled_command_groups.iter().position(|g| g == &slug) {
            self.enabled_command_groups.remove(pos);
            self.status_message = format!("Disabled command group '{slug}'.");
        } else {
            self.enabled_command_groups.push(slug.clone());
            self.status_message = format!("Enabled command group '{slug}'.");
        }
    }

    /// Records a custom audit telemetry event into the control plane buffer.
    pub fn record_event(&self, verdict: Verdict, subject: &str, reason: &str) {
        let mut details = BTreeMap::new();
        details.insert("reason".to_owned(), reason.to_owned());
        self.plane.record_event(AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: EnforcementPlane::Bwrap,
            severity: if verdict == Verdict::Block {
                Severity::Warning
            } else {
                Severity::Info
            },
            verdict,
            profile: self.active_profile_name().to_owned(),
            subject: subject.to_owned(),
            details,
        });
    }
}

/// Processes a single keyboard event against [`TuiApp`], updating navigation or queueing a launch action.
pub fn handle_tui_key_event(app: &mut TuiApp, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        if app.input_mode {
            app.input_mode = false;
            app.command_input.clear();
            "Cancelled command input.".clone_into(&mut app.status_message);
        } else {
            app.should_quit = true;
        }
        return;
    }

    if app.input_mode {
        match key.code {
            KeyCode::Esc => {
                app.input_mode = false;
                app.command_input.clear();
                "Command input cancelled.".clone_into(&mut app.status_message);
            }
            KeyCode::Enter => {
                let raw = app.command_input.trim().to_owned();
                app.input_mode = false;
                app.command_input.clear();
                if !raw.is_empty() {
                    let argv: Vec<String> = raw.split_whitespace().map(str::to_owned).collect();
                    app.pending_launch = Some(TuiLaunchAction::CustomCommand(argv));
                }
            }
            KeyCode::Backspace => {
                app.command_input.pop();
            }
            KeyCode::Char(ch) => {
                app.command_input.push(ch);
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Tab | KeyCode::Right => {
            app.active_pane = app.active_pane.next();
        }
        KeyCode::BackTab | KeyCode::Left => {
            app.active_pane = app.active_pane.prev();
        }
        KeyCode::Char('1') => app.active_pane = TuiPane::Profiles,
        KeyCode::Char('2') => app.active_pane = TuiPane::Configs,
        KeyCode::Char('3') => app.active_pane = TuiPane::Groups,
        KeyCode::Char('4') => app.active_pane = TuiPane::Telemetry,
        KeyCode::Up | KeyCode::Char('k') => match app.active_pane {
            TuiPane::Profiles => {
                if app.selected_profile_idx > 0 {
                    app.selected_profile_idx -= 1;
                }
            }
            TuiPane::Configs => {
                if app.selected_config_idx > 0 {
                    app.selected_config_idx -= 1;
                }
            }
            TuiPane::Groups => {
                if app.selected_group_idx > 0 {
                    app.selected_group_idx -= 1;
                }
            }
            TuiPane::Telemetry => {
                app.telemetry_scroll = app.telemetry_scroll.saturating_sub(1);
            }
        },
        KeyCode::Down | KeyCode::Char('j') => match app.active_pane {
            TuiPane::Profiles => {
                if app.selected_profile_idx + 1 < app.profiles.len() {
                    app.selected_profile_idx += 1;
                }
            }
            TuiPane::Configs => {
                if app.selected_config_idx + 1 < app.config_entries.len() {
                    app.selected_config_idx += 1;
                }
            }
            TuiPane::Groups => {
                if app.selected_group_idx + 1 < app.group_entries.len() {
                    app.selected_group_idx += 1;
                }
            }
            TuiPane::Telemetry => {
                app.telemetry_scroll = (app.telemetry_scroll + 1).min(app.max_telemetry_scroll());
            }
        },
        KeyCode::Char(' ') => {
            if app.active_pane == TuiPane::Groups {
                app.toggle_selected_group();
            }
        }
        KeyCode::Char('n') => {
            app.net_mode = match app.net_mode {
                ReplNetMode::Auto | ReplNetMode::Netns => ReplNetMode::Airgap,
                ReplNetMode::Airgap => ReplNetMode::Direct,
                ReplNetMode::Direct => ReplNetMode::Auto,
            };
            app.status_message = format!("Switched network execution mode to {:?}.", app.net_mode);
            app.record_event(
                Verdict::Allow,
                &format!("net_mode={:?}", app.net_mode),
                "TUI_NET_MODE_CHANGE",
            );
        }
        KeyCode::Char('d') => {
            let report = run_doctor_checks();
            let passed = report.checks.iter().filter(|c| c.passed).count();
            let total = report.checks.len();
            app.status_message = format!(
                "Host Doctor: {passed}/{total} checks passed (healthy={}).",
                report.healthy
            );
            app.record_event(
                if report.healthy {
                    Verdict::Allow
                } else {
                    Verdict::Block
                },
                &format!("doctor {passed}/{total} checks passed"),
                "TUI_DOCTOR_CHECK",
            );
        }
        KeyCode::Char('s') => {
            app.pending_launch = Some(TuiLaunchAction::SandboxShell);
        }
        KeyCode::Char('r') => {
            app.pending_launch = Some(TuiLaunchAction::InteractiveRepl);
        }
        KeyCode::Char('x') => {
            app.pending_launch = Some(TuiLaunchAction::RunSelectedConfig);
        }
        KeyCode::Char('c' | ':') => {
            app.input_mode = true;
            app.command_input.clear();
            "Type command to run inside Cordon sandbox and press Enter (Esc to cancel)."
                .clone_into(&mut app.status_message);
        }
        KeyCode::Enter => match app.active_pane {
            TuiPane::Groups => app.toggle_selected_group(),
            TuiPane::Configs if app.selected_config_idx > 0 => {
                app.pending_launch = Some(TuiLaunchAction::RunSelectedConfig);
            }
            _ => {
                app.pending_launch = Some(TuiLaunchAction::SandboxShell);
            }
        },
        _ => {}
    }
}

/// Draws the interactive Cordon TUI layout into a `ratatui` [`Frame`].
pub fn draw_interactive_tui(frame: &mut Frame<'_>, app: &TuiApp) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(6),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let net_badge = match app.net_mode {
        ReplNetMode::Auto | ReplNetMode::Netns => "AUTO (Netns / Fail-Closed Airgap)",
        ReplNetMode::Airgap => "AIRGAP (--unshare-net)",
        ReplNetMode::Direct => "DIRECT (--host-net)",
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " CORDON ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Interactive 5-Gate Sandbox Launcher & Telemetry | Profile: "),
        Span::styled(
            ts(app.active_profile_name()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | Net: "),
        Span::styled(
            net_badge,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Control Plane [1-4 / Tab to Switch Panes]"),
    );
    frame.render_widget(header, outer[0]);

    let body_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(34),
            Constraint::Percentage(38),
        ])
        .split(outer[1]);

    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(body_cols[0]);

    // Pane 1: Workload Profiles
    let profile_border = if app.active_pane == TuiPane::Profiles {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let profile_items: Vec<ListItem<'_>> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let marker = if idx == app.selected_profile_idx {
                ">"
            } else {
                " "
            };
            let style = if idx == app.selected_profile_idx {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::styled(
                format!(
                    "{marker} {} [{:?}|{:?}]",
                    ts(&p.name),
                    p.filesystem_mode,
                    p.network_mode
                ),
                style,
            ))
        })
        .collect();
    let profiles_widget = List::new(profile_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(profile_border)
            .title(focus_title(
                app.active_pane == TuiPane::Profiles,
                "[1] Workload Profiles (6)",
            )),
    );
    frame.render_widget(profiles_widget, left_rows[0]);

    // Pane 2: Reproducible Configs
    let config_border = if app.active_pane == TuiPane::Configs {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let config_items: Vec<ListItem<'_>> = app
        .config_entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let marker = if idx == app.selected_config_idx {
                ">"
            } else {
                " "
            };
            let label = entry.as_ref().map_or_else(
                || "(Use Profile Default)".to_owned(),
                |p| ts(&p.display().to_string()),
            );
            let style = if idx == app.selected_config_idx {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::styled(format!("{marker} {label}"), style))
        })
        .collect();
    let configs_widget = List::new(config_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(config_border)
            .title(focus_title(
                app.active_pane == TuiPane::Configs,
                "[2] Configs (Enter/x to Run)",
            )),
    );
    frame.render_widget(configs_widget, left_rows[1]);

    // Pane 3: Command & Directory Groups
    let groups_border = if app.active_pane == TuiPane::Groups {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let group_items: Vec<ListItem<'_>> = app
        .group_entries
        .iter()
        .enumerate()
        .map(|(idx, (is_dir, slug, _summary))| {
            let enabled = if *is_dir {
                app.enabled_directory_groups.contains(slug)
            } else {
                app.enabled_command_groups.contains(slug)
            };
            let check = if enabled { "[x]" } else { "[ ]" };
            let kind_tag = if *is_dir { "dir" } else { "cmd" };
            let pointer = if idx == app.selected_group_idx {
                ">"
            } else {
                " "
            };
            let style = if idx == app.selected_group_idx {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if enabled {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };
            ListItem::new(Line::styled(
                format!("{pointer} {check} ({kind_tag}) {slug}"),
                style,
            ))
        })
        .collect();
    let groups_widget = List::new(group_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(groups_border)
            .title(focus_title(
                app.active_pane == TuiPane::Groups,
                "[3] Tool & Dir Groups (Space)",
            )),
    );
    frame.render_widget(groups_widget, body_cols[1]);

    // Pane 4: Recent Audit Telemetry
    let telemetry_border = if app.active_pane == TuiPane::Telemetry {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let events = app.plane.recent_events(TELEMETRY_EVENT_WINDOW);
    let event_items: Vec<ListItem<'_>> = events
        .iter()
        .skip(app.telemetry_scroll.min(events.len().saturating_sub(1)))
        .map(|ev| {
            let color = match ev.verdict {
                Verdict::Allow => Color::Green,
                Verdict::Block => Color::Red,
                Verdict::Audit => Color::Yellow,
            };
            ListItem::new(Line::styled(
                format!(
                    "[{:?}] {:?}: {} ({})",
                    ev.plane,
                    ev.verdict,
                    ts(&ev.subject),
                    ts(&ev.profile)
                ),
                Style::default().fg(color),
            ))
        })
        .collect();
    let events_widget = List::new(event_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(telemetry_border)
            .title(focus_title(
                app.active_pane == TuiPane::Telemetry,
                "[4] Recent Audit Telemetry",
            )),
    );
    frame.render_widget(events_widget, body_cols[2]);

    // Live 5-Gate Launch Plan Preview Box
    let preview_text = match app.compile_active_plan(&[]) {
        Ok((_, plan)) => {
            let force_offline = app.net_mode == ReplNetMode::Airgap;
            let force_host_net = app.net_mode == ReplNetMode::Direct;
            let (live_argv, _) = prepare_live_execution_argv(&plan, force_offline, force_host_net);
            format!(
                "Workspace: {} | Masked Bins: {} | Active Cmd: {}\n{}",
                ts(&plan.canonical_workspace.to_string()),
                plan.masked_binaries.len(),
                ts(live_argv.first().map_or("bwrap", String::as_str)),
                ts(&live_argv.join(" "))
            )
        }
        Err(e) => format!("Launch plan error: {}", ts(&e.to_string())),
    };
    let preview_widget = Paragraph::new(preview_text)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Live 5-Gate Launch Plan Preview (bwrap + AppArmor + netns)"),
        );
    frame.render_widget(preview_widget, outer[2]);

    // Footer / Command Prompt Bar
    if app.input_mode {
        let prompt = Paragraph::new(format!("Run in Sandbox > {}_", ts(&app.command_input)))
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title("Execute Command in Sandbox (Enter to Launch, Esc to Cancel)"),
            );
        frame.render_widget(prompt, outer[3]);
    } else {
        let footer = Paragraph::new(format!(
            "{} | Developed by PyCentric | AGPL-3.0-only | Source: https://github.com/pycentric/cordon",
            ts(&app.status_message)
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Actions: [s/Enter] Sandbox Shell | [r] Cordon REPL | [c] Run Cmd | [x] Run Config | [n] Net | [d] Doctor | [q] Quit"),
        );
        frame.render_widget(footer, outer[3]);
    }
}

fn execute_pending_launch(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    action: TuiLaunchAction,
) -> Result<(), CordonError> {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    let result = match action {
        TuiLaunchAction::SandboxShell => {
            let shell_bin = if Path::new("/bin/bash").exists() {
                vec!["/bin/bash".to_owned(), "--norc".to_owned()]
            } else {
                vec!["/bin/sh".to_owned()]
            };
            match app.compile_active_plan(&shell_bin) {
                Ok((_, mut plan)) => {
                    let ps1 = format!("[cordon:{}:\\W]\\$ ", plan.profile_name);
                    if let Some(pos) = plan.bwrap_argv.iter().position(|a| a == "--chdir") {
                        plan.bwrap_argv.insert(pos, ps1);
                        plan.bwrap_argv.insert(pos, "PS1".to_owned());
                        plan.bwrap_argv.insert(pos, "--setenv".to_owned());
                    }
                    let force_offline = app.net_mode == ReplNetMode::Airgap;
                    let force_host_net = app.net_mode == ReplNetMode::Direct;
                    let (live_argv, notice) =
                        prepare_live_execution_argv(&plan, force_offline, force_host_net);
                    println!(
                        "\x1b[1;36m[cordon-tui]\x1b[0m Launching sandboxed shell (profile: \x1b[1;33m{}\x1b[0m, workspace: \x1b[32m{}\x1b[0m). Type \x1b[1;32mexit\x1b[0m to return to Cordon TUI.",
                        ts(&plan.profile_name),
                        ts(&plan.canonical_workspace.to_string())
                    );
                    if let Some(ref msg) = notice {
                        println!("\x1b[33m[cordon-tui] Notice: {}\x1b[0m", ts(msg));
                    }
                    if let Some((prog, args)) = live_argv.split_first() {
                        let status = Command::new(prog).args(args).status()?;
                        // Child inherited the raw TTY: force a terminal state reset before
                        // redrawing the TUI (see residual-risk note in the remediation report).
                        reset_terminal_after_child(&mut io::stdout())?;
                        let code = status.code().unwrap_or(1);
                        app.record_event(
                            if code == 0 {
                                Verdict::Allow
                            } else {
                                Verdict::Block
                            },
                            &format!("shell ({}) -> exit {code}", plan.profile_name),
                            "TUI_SANDBOX_SHELL",
                        );
                        app.status_message = format!("Sandbox shell exited with status {code}.");
                        if code != 0 {
                            wait_for_enter_to_resume();
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        TuiLaunchAction::InteractiveRepl => {
            let cfg_opt = app.active_config_path().map(Path::to_path_buf);
            match ReplSession::new(
                app.active_profile_name(),
                cfg_opt,
                Some(app.workspace.clone()),
                app.net_mode,
                false,
            ) {
                Ok(mut session) => {
                    for cg in &app.enabled_command_groups {
                        if !session.command_groups.contains(cg) {
                            session.command_groups.push(cg.clone());
                        }
                    }
                    for dg in &app.enabled_directory_groups {
                        if !session.directory_groups.contains(dg) {
                            session.directory_groups.push(dg.clone());
                        }
                    }
                    println!(
                        "\x1b[1;36m[cordon-tui]\x1b[0m Entering Cordon Interactive REPL. Type \x1b[1;32mexit\x1b[0m to return to Cordon TUI."
                    );
                    let code = run_interactive_repl(&mut session)
                        .map_err(|e| CordonError::InvalidInput(e.to_string()))?;
                    app.record_event(
                        Verdict::Allow,
                        &format!("repl ({}) -> exit {code}", session.profile),
                        "TUI_REPL_SESSION",
                    );
                    app.status_message = format!("Returned from Cordon REPL (exit {code}).");
                    Ok(())
                }
                Err(e) => Err(CordonError::InvalidInput(e.to_string())),
            }
        }
        TuiLaunchAction::CustomCommand(argv) => match app.compile_active_plan(&argv) {
            Ok((_, plan)) => {
                let force_offline = app.net_mode == ReplNetMode::Airgap;
                let force_host_net = app.net_mode == ReplNetMode::Direct;
                let (live_argv, notice) =
                    prepare_live_execution_argv(&plan, force_offline, force_host_net);
                println!(
                    "\x1b[1;36m[cordon-tui]\x1b[0m Running command in sandbox: \x1b[1;32m{}\x1b[0m",
                    ts(&argv.join(" "))
                );
                if let Some(ref msg) = notice {
                    println!("\x1b[33m[cordon-tui] Notice: {}\x1b[0m", ts(msg));
                }
                if let Some((prog, args)) = live_argv.split_first() {
                    let status = Command::new(prog).args(args).status()?;
                    reset_terminal_after_child(&mut io::stdout())?;
                    let code = status.code().unwrap_or(1);
                    app.record_event(
                        if code == 0 {
                            Verdict::Allow
                        } else {
                            Verdict::Block
                        },
                        &format!("cmd '{}' -> exit {code}", argv.join(" ")),
                        "TUI_CUSTOM_COMMAND",
                    );
                    app.status_message = format!(
                        "Command '{}' exited with status {code}.",
                        ts(&argv.join(" "))
                    );
                    wait_for_enter_to_resume();
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        TuiLaunchAction::RunSelectedConfig => match app.compile_active_plan(&[]) {
            Ok((_, plan)) => {
                let force_offline = app.net_mode == ReplNetMode::Airgap;
                let force_host_net = app.net_mode == ReplNetMode::Direct;
                let (live_argv, notice) =
                    prepare_live_execution_argv(&plan, force_offline, force_host_net);
                let label = app.active_config_path().map_or_else(
                    || app.active_profile_name().to_owned(),
                    |p| p.display().to_string(),
                );
                println!(
                    "\x1b[1;36m[cordon-tui]\x1b[0m Launching target '{}' inside Cordon sandbox...",
                    ts(&label)
                );
                if let Some(ref msg) = notice {
                    println!("\x1b[33m[cordon-tui] Notice: {}\x1b[0m", ts(msg));
                }
                if let Some((prog, args)) = live_argv.split_first() {
                    let status = Command::new(prog).args(args).status()?;
                    reset_terminal_after_child(&mut io::stdout())?;
                    let code = status.code().unwrap_or(1);
                    app.record_event(
                        if code == 0 {
                            Verdict::Allow
                        } else {
                            Verdict::Block
                        },
                        &format!("config '{label}' -> exit {code}"),
                        "TUI_CONFIG_LAUNCH",
                    );
                    app.status_message =
                        format!("Session '{}' exited with status {code}.", ts(&label));
                    wait_for_enter_to_resume();
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
    };

    if let Err(ref err) = result {
        app.status_message = format!("Session launch error: {}", ts(&err.to_string()));
        app.record_event(Verdict::Block, &err.to_string(), "TUI_LAUNCH_ERROR");
        println!(
            "\x1b[1;31m[cordon-tui] Error: {}\x1b[0m",
            ts(&err.to_string())
        );
        wait_for_enter_to_resume();
    }

    let _ = enable_raw_mode();
    let _ = execute!(terminal.backend_mut(), EnterAlternateScreen);
    let _ = terminal.clear();
    Ok(())
}

fn wait_for_enter_to_resume() {
    print!("\n\x1b[1;36m[cordon-tui]\x1b[0m Press Enter to return to Cordon TUI...");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
}

/// Runs the full-screen interactive `ratatui` + `crossterm` Terminal UI (`cordon tui`).
pub fn run_interactive_tui(
    initial_profile: &str,
    workspace: Option<PathBuf>,
) -> Result<i32, CordonError> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(e) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(CordonError::Io(e));
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            return Err(CordonError::Io(e));
        }
    };

    let mut app = TuiApp::new(initial_profile, workspace);

    let loop_res = (|| -> Result<(), CordonError> {
        loop {
            terminal.draw(|frame| draw_interactive_tui(frame, &app))?;

            if let Some(action) = app.pending_launch.take() {
                execute_pending_launch(&mut terminal, &mut app, action)?;
                continue;
            }

            if app.should_quit {
                break;
            }

            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) => handle_tui_key_event(&mut app, key),
                    Event::Resize(..) => {
                        // Explicit resize handling: clamp scroll offsets to the new
                        // viewport and force a clean full repaint of the alternate screen.
                        app.clamp_telemetry_scroll();
                        terminal.clear()?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    loop_res.map(|()| 0)
}

/// Renders a headless `ratatui` frame snapshot into a string for non-TTY inspection and testing.
pub fn render_tui_snapshot(
    plane: &CordonControlPlane,
    width: u16,
    height: u16,
) -> Result<String, CordonError> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    let profiles = list_profiles();
    let events = plane.recent_events(10);

    terminal.draw(|frame| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(frame.area());

        let header = Paragraph::new(Line::from(vec![
            Span::styled(
                " CORDON ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" 5-Gate Kernel Sandbox & L3-L7 Network Inspection Telemetry (Rust Edition)"),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Control Plane"),
        );
        frame.render_widget(header, chunks[0]);

        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(chunks[1]);

        let profile_items: Vec<ListItem<'_>> = profiles
            .iter()
            .map(|p| {
                ListItem::new(format!(
                    "{} [{:?} | {:?}]",
                    p.name, p.filesystem_mode, p.network_mode
                ))
            })
            .collect();
        let profiles_list = List::new(profile_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Workload Profiles (6)"),
        );
        frame.render_widget(profiles_list, body_chunks[0]);

        let event_items: Vec<ListItem<'_>> = events
            .iter()
            .map(|ev| {
                ListItem::new(format!(
                    "[{:?}] {:?}: {} ({})",
                    ev.plane,
                    ev.verdict,
                    ts(&ev.subject),
                    ts(&ev.profile)
                ))
            })
            .collect();
        let events_list = List::new(event_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recent Audit Telemetry"),
        );
        frame.render_widget(events_list, body_chunks[1]);

        let footer = Paragraph::new(
            "Developed by PyCentric | Zero-Unsafe Type-Safe Rust | AGPL-3.0-only | Source: https://github.com/pycentric/cordon",
        )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[2]);
    })?;

    let buffer = terminal.backend().buffer();
    let mut lines = Vec::with_capacity(usize::from(height));
    for y in 0..height {
        let mut row = String::with_capacity(usize::from(width));
        for x in 0..width {
            if let Some(cell) = buffer.cell((x, y)) {
                row.push_str(cell.symbol());
            }
        }
        lines.push(row.trim_end().to_owned());
    }
    Ok(lines.join("\n"))
}
