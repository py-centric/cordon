//! `ratatui` 4-pane frame rendering for the interactive Cordon TUI.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::domain::Verdict;
use crate::ports::AuditSinkPort;
use crate::repl::ReplNetMode;
use crate::sandbox::prepare_live_execution_argv;

use super::{TELEMETRY_EVENT_WINDOW, TuiApp, TuiPane, focus_title, ts};

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
