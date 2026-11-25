//! Raw-mode TTY line reader and frame renderer for `cordon repl`.

use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};

use crossterm::cursor;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{self, ClearType};

use super::{EditAction, HistoryStore, LineEditorState, highlight_repl_line};

struct RawModeGuard;

impl RawModeGuard {
    fn acquire() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

/// Bundled rendering and completion context for [`read_interactive_tty_line`].
pub struct LineEditorRenderConfig<'a> {
    pub prompt_display: &'a str,
    pub prompt_visible_chars: usize,
    pub history: &'a HistoryStore,
    pub enable_syntax_highlight: bool,
    pub enable_fish_autosuggest: bool,
    pub valid_commands: &'a BTreeSet<String>,
    pub completion_candidates: &'a [String],
}

/// Reads a single interactive line using `crossterm` raw mode when `stdin` is a TTY.
pub fn read_interactive_tty_line<W: Write>(
    out: &mut W,
    cfg: &LineEditorRenderConfig<'_>,
) -> std::io::Result<Option<String>> {
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }

    let _guard = RawModeGuard::acquire()?;
    let mut state = LineEditorState::new();

    loop {
        let ghost = if cfg.enable_fish_autosuggest && state.cursor == state.buffer.len() {
            cfg.history
                .suggest_ghost_suffix(&state.buffer, cfg.completion_candidates)
        } else {
            None
        };

        render_editor_frame(out, cfg, &state, ghost.as_deref())?;

        let ev = event::read()?;
        let Event::Key(key_ev) = ev else {
            continue;
        };
        if key_ev.kind == KeyEventKind::Release {
            continue;
        }

        match state.handle_key(
            key_ev,
            cfg.history,
            ghost.as_deref(),
            cfg.completion_candidates,
        ) {
            EditAction::Continue => {}
            EditAction::Submit(line) => {
                render_editor_frame(out, cfg, &state, None)?;
                write!(out, "\r\n")?;
                out.flush()?;
                return Ok(Some(line));
            }
            EditAction::CancelLine => {
                write!(out, "^C\r\n")?;
                out.flush()?;
                return Ok(Some(String::new()));
            }
            EditAction::Eof => {
                write!(out, "\r\n")?;
                out.flush()?;
                return Ok(None);
            }
            EditAction::ClearScreen => {
                crossterm::queue!(out, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
                out.flush()?;
            }
        }
    }
}

fn render_editor_frame<W: Write>(
    out: &mut W,
    cfg: &LineEditorRenderConfig<'_>,
    state: &LineEditorState,
    ghost_suffix: Option<&str>,
) -> std::io::Result<()> {
    crossterm::queue!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine)
    )?;

    if state.reverse_search_active {
        let matched = cfg
            .history
            .search_reverse(&state.reverse_search_query, state.reverse_search_skip)
            .unwrap_or("");
        write!(
            out,
            "\x1b[1;36m(reverse-i-search)\x1b[0m`{}': {}",
            state.reverse_search_query, matched
        )?;
        out.flush()?;
        return Ok(());
    }

    let rendered_line = if cfg.enable_syntax_highlight {
        highlight_repl_line(&state.buffer, ghost_suffix, cfg.valid_commands)
    } else if let Some(g) = ghost_suffix {
        format!("{}\x1b[90m{g}\x1b[0m", state.buffer)
    } else {
        state.buffer.clone()
    };

    write!(out, "{}{rendered_line}", cfg.prompt_display)?;
    let cursor_chars = state.buffer[..state.cursor].chars().count();
    let target_col = u16::try_from(cfg.prompt_visible_chars + cursor_chars).unwrap_or(u16::MAX);
    crossterm::queue!(out, cursor::MoveToColumn(target_col))?;
    out.flush()
}
