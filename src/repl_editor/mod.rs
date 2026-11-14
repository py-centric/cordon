//! Interactive terminal line editor (`crossterm`), persistent history (`HistoryStore`),
//! `Ctrl-R` reverse-i-search, `Ctrl-U` / `Ctrl-W` / `Ctrl-A` / `Ctrl-E` shortcuts,
//! Fish-style inline ghost autosuggestions, and live ANSI syntax highlighting for `cordon repl`.
//!
//! Complies with `ADR-L0-SEC-02` and `#![forbid(unsafe_code)]`.

mod highlight;
mod history;
#[cfg(test)]
mod tests;
mod tty;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub use highlight::{complete_line, highlight_repl_line};
pub use history::{
    HistoryStore, MAX_HISTORY_ENTRIES, REDACTED_PLACEHOLDER, default_history_file_path,
    env_value_for_display, is_secret_env_key, redact_history_line, reset_terminal_after_child,
    sanitize_terminal_line, sanitize_terminal_text,
};
pub use tty::{LineEditorRenderConfig, read_interactive_tty_line};

/// Built-in REPL commands recognized by the syntax highlighter and tab completer.
pub const REPL_BUILTIN_COMMANDS: &[&str] = &[
    "help",
    "?",
    "status",
    "info",
    "profiles",
    "templates",
    "use",
    "profile",
    "load",
    "cd",
    "workspace",
    "mount",
    "vol",
    "mount-group",
    "allow-bin",
    "deny-bin",
    "allow-group",
    "groups",
    "plugin",
    "plugins",
    "set",
    "alias",
    "ls",
    "history",
    "env",
    "allow",
    "net",
    "plan",
    "inspect",
    "eval",
    "url",
    "doctor",
    "run",
    "exec",
    "shell",
    "clear",
    "exit",
    "quit",
    "q",
];

/// Outcome of processing a single key event in the interactive line editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditAction {
    /// Continue editing the current line.
    Continue,
    /// User pressed Enter; submit the completed line.
    Submit(String),
    /// User pressed `Ctrl-C`; cancel current line and start a fresh prompt.
    CancelLine,
    /// User pressed `Ctrl-D` on an empty line; exit the REPL.
    Eof,
    /// User pressed `Ctrl-L`; clear terminal screen and redraw.
    ClearScreen,
}

/// Pure, testable state machine for the interactive REPL line editor.
#[derive(Debug, Clone)]
pub struct LineEditorState {
    /// Current UTF-8 line buffer.
    pub buffer: String,
    /// Byte index of the cursor within `buffer` (always on a char boundary).
    pub cursor: usize,
    /// Current index in `HistoryStore::entries()` when navigating with `Up`/`Down` (`None` = live draft).
    pub history_index: Option<usize>,
    /// Saved draft line before the user pressed `Up` to browse history.
    pub saved_draft: String,
    /// Whether `Ctrl-R` interactive reverse-i-search mode is currently active.
    pub reverse_search_active: bool,
    /// Current search query inside `Ctrl-R` mode.
    pub reverse_search_query: String,
    /// Match offset when pressing `Ctrl-R` repeatedly for the same query.
    pub reverse_search_skip: usize,
}

impl Default for LineEditorState {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditorState {
    /// Creates an empty [`LineEditorState`].
    pub const fn new() -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            history_index: None,
            saved_draft: String::new(),
            reverse_search_active: false,
            reverse_search_query: String::new(),
            reverse_search_skip: 0,
        }
    }

    fn prev_char_boundary(&self) -> usize {
        if self.cursor == 0 {
            return 0;
        }
        self.buffer[..self.cursor]
            .char_indices()
            .last()
            .map_or(0, |(idx, _)| idx)
    }

    fn next_char_boundary(&self) -> usize {
        if self.cursor >= self.buffer.len() {
            return self.buffer.len();
        }
        let mut iter = self.buffer[self.cursor..].char_indices();
        let _ = iter.next();
        iter.next()
            .map_or(self.buffer.len(), |(offset, _)| self.cursor + offset)
    }

    /// Processes a single [`KeyEvent`] against the line buffer and [`HistoryStore`].
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        history: &HistoryStore,
        ghost_suffix: Option<&str>,
        completion_candidates: &[String],
    ) -> EditAction {
        if self.reverse_search_active {
            return self.handle_reverse_search_key(key, history);
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => EditAction::Submit(self.buffer.clone()),
            KeyCode::Char('c') if ctrl => {
                self.buffer.clear();
                self.cursor = 0;
                self.history_index = None;
                EditAction::CancelLine
            }
            KeyCode::Char('d') if ctrl => {
                if self.buffer.is_empty() {
                    EditAction::Eof
                } else {
                    let next = self.next_char_boundary();
                    if next > self.cursor {
                        self.buffer.replace_range(self.cursor..next, "");
                    }
                    EditAction::Continue
                }
            }
            KeyCode::Char('l') if ctrl => EditAction::ClearScreen,
            KeyCode::Char('u') if ctrl => {
                self.buffer.replace_range(0..self.cursor, "");
                self.cursor = 0;
                EditAction::Continue
            }
            KeyCode::Char('k') if ctrl => {
                self.buffer.truncate(self.cursor);
                EditAction::Continue
            }
            KeyCode::Char('w') if ctrl => {
                if self.cursor > 0 {
                    let prefix = &self.buffer[..self.cursor];
                    let trimmed_len = prefix.trim_end().len();
                    let word_start = prefix[..trimmed_len]
                        .rfind(char::is_whitespace)
                        .map_or(0, |idx| idx + 1);
                    self.buffer.replace_range(word_start..self.cursor, "");
                    self.cursor = word_start;
                }
                EditAction::Continue
            }
            KeyCode::Char('a') if ctrl => {
                self.cursor = 0;
                EditAction::Continue
            }
            KeyCode::Home => {
                self.cursor = 0;
                EditAction::Continue
            }
            KeyCode::Char('e') if ctrl => {
                self.accept_ghost_to_end(ghost_suffix);
                EditAction::Continue
            }
            KeyCode::End => {
                self.accept_ghost_to_end(ghost_suffix);
                EditAction::Continue
            }
            KeyCode::Char('r') if ctrl => {
                self.reverse_search_active = true;
                self.reverse_search_query.clear();
                self.reverse_search_skip = 0;
                EditAction::Continue
            }
            KeyCode::Up => {
                self.navigate_history_up(history);
                EditAction::Continue
            }
            KeyCode::Char('p') if ctrl => {
                self.navigate_history_up(history);
                EditAction::Continue
            }
            KeyCode::Down => {
                self.navigate_history_down(history);
                EditAction::Continue
            }
            KeyCode::Char('n') if ctrl => {
                self.navigate_history_down(history);
                EditAction::Continue
            }
            KeyCode::Left => {
                self.cursor = self.prev_char_boundary();
                EditAction::Continue
            }
            KeyCode::Char('b') if ctrl => {
                self.cursor = self.prev_char_boundary();
                EditAction::Continue
            }
            KeyCode::Right => {
                self.advance_or_accept_ghost(ghost_suffix);
                EditAction::Continue
            }
            KeyCode::Char('f') if ctrl => {
                self.advance_or_accept_ghost(ghost_suffix);
                EditAction::Continue
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let prev = self.prev_char_boundary();
                    self.buffer.replace_range(prev..self.cursor, "");
                    self.cursor = prev;
                }
                EditAction::Continue
            }
            KeyCode::Delete => {
                if self.cursor < self.buffer.len() {
                    let next = self.next_char_boundary();
                    self.buffer.replace_range(self.cursor..next, "");
                }
                EditAction::Continue
            }
            KeyCode::Tab => {
                if let Some(completed) = complete_line(&self.buffer, completion_candidates) {
                    self.buffer = completed;
                    self.cursor = self.buffer.len();
                } else {
                    self.accept_ghost_to_end(ghost_suffix);
                }
                EditAction::Continue
            }
            KeyCode::Char(ch) if !ctrl => {
                self.buffer.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
                EditAction::Continue
            }
            _ => EditAction::Continue,
        }
    }

    fn accept_ghost_to_end(&mut self, ghost_suffix: Option<&str>) {
        if self.cursor == self.buffer.len()
            && let Some(ghost) = ghost_suffix
        {
            self.buffer.push_str(ghost);
        }
        self.cursor = self.buffer.len();
    }

    fn advance_or_accept_ghost(&mut self, ghost_suffix: Option<&str>) {
        if self.cursor == self.buffer.len()
            && let Some(ghost) = ghost_suffix
        {
            self.buffer.push_str(ghost);
            self.cursor = self.buffer.len();
        } else {
            self.cursor = self.next_char_boundary();
        }
    }

    fn navigate_history_up(&mut self, history: &HistoryStore) {
        let entries = history.entries();
        if entries.is_empty() {
            return;
        }
        let next_idx = match self.history_index {
            None => {
                self.saved_draft.clone_from(&self.buffer);
                entries.len() - 1
            }
            Some(0) => 0,
            Some(idx) => idx - 1,
        };
        self.history_index = Some(next_idx);
        self.buffer.clone_from(&entries[next_idx]);
        self.cursor = self.buffer.len();
    }

    fn navigate_history_down(&mut self, history: &HistoryStore) {
        let entries = history.entries();
        let Some(curr_idx) = self.history_index else {
            return;
        };
        if curr_idx + 1 < entries.len() {
            let next_idx = curr_idx + 1;
            self.history_index = Some(next_idx);
            self.buffer.clone_from(&entries[next_idx]);
        } else {
            self.history_index = None;
            self.buffer.clone_from(&self.saved_draft);
        }
        self.cursor = self.buffer.len();
    }

    fn handle_reverse_search_key(&mut self, key: KeyEvent, history: &HistoryStore) -> EditAction {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => {
                if let Some(matched) =
                    history.search_reverse(&self.reverse_search_query, self.reverse_search_skip)
                {
                    self.buffer = matched.to_owned();
                    self.cursor = self.buffer.len();
                }
                self.reverse_search_active = false;
                EditAction::Submit(self.buffer.clone())
            }
            KeyCode::Esc | KeyCode::Right | KeyCode::Left => {
                if let Some(matched) =
                    history.search_reverse(&self.reverse_search_query, self.reverse_search_skip)
                {
                    self.buffer = matched.to_owned();
                    self.cursor = self.buffer.len();
                }
                self.reverse_search_active = false;
                EditAction::Continue
            }
            KeyCode::Char('g' | 'c') if ctrl => {
                self.reverse_search_active = false;
                self.reverse_search_query.clear();
                self.reverse_search_skip = 0;
                EditAction::Continue
            }
            KeyCode::Char('r') if ctrl => {
                self.reverse_search_skip = self.reverse_search_skip.saturating_add(1);
                if history
                    .search_reverse(&self.reverse_search_query, self.reverse_search_skip)
                    .is_none()
                {
                    self.reverse_search_skip = 0;
                }
                EditAction::Continue
            }
            KeyCode::Backspace => {
                let _ = self.reverse_search_query.pop();
                self.reverse_search_skip = 0;
                EditAction::Continue
            }
            KeyCode::Char(ch) if !ctrl => {
                self.reverse_search_query.push(ch);
                self.reverse_search_skip = 0;
                EditAction::Continue
            }
            _ => EditAction::Continue,
        }
    }
}
