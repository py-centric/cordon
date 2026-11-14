//! Keyboard event handling for the interactive Cordon TUI.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::domain::Verdict;
use crate::ports::SandboxCompilerPort;
use crate::repl::ReplNetMode;

use super::{TuiApp, TuiLaunchAction, TuiPane};

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
            let report = app.sandbox.run_doctor_checks();
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
