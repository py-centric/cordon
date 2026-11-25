//! Session launch execution, full-screen interactive event loop, and headless snapshot rendering.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::api::CordonControlPlane;
use crate::domain::Verdict;
use crate::error::CordonError;
use crate::ports::{AuditSinkPort, ProfileCatalogPort};
use crate::profiles::BuiltinProfileCatalog;
use crate::repl::{ReplNetMode, ReplSession, run_interactive_repl};
use crate::repl_editor::reset_terminal_after_child;
use crate::sandbox::prepare_live_execution_argv;

use super::input::handle_tui_key_event;
use super::view::draw_interactive_tui;
use super::{TuiApp, TuiLaunchAction, ts};

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
    let profiles = BuiltinProfileCatalog.list_profiles();
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

#[cfg(test)]
mod tests {
    use super::render_tui_snapshot;
    use crate::api::CordonControlPlane;

    #[test]
    fn render_tui_snapshot_produces_header_and_footer() {
        let plane = CordonControlPlane::new();
        let snap = render_tui_snapshot(&plane, 120, 36).unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert!(snap.contains("Developed by PyCentric"));
        assert!(snap.contains("Recent Audit Telemetry"));
    }
}
