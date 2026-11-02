//! Interactive terminal line editor (`crossterm`), persistent history (`HistoryStore`),
//! `Ctrl-R` reverse-i-search, `Ctrl-U` / `Ctrl-W` / `Ctrl-A` / `Ctrl-E` shortcuts,
//! Fish-style inline ghost autosuggestions, and live ANSI syntax highlighting for `cordon repl`.
//!
//! Complies with `ADR-L0-SEC-02` and `#![forbid(unsafe_code)]`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{self, ClearType};

use crate::cli::PROFILE_CANDIDATES;
use crate::config::expand_tilde;
use crate::groups::{COMMAND_GROUP_CANDIDATES, DIRECTORY_GROUP_CANDIDATES, resolve_host_binary};
use crate::plugins::PLUGIN_CANDIDATES;

/// Maximum number of persistent history lines stored on disk.
pub const MAX_HISTORY_ENTRIES: usize = 2000;

/// Redaction placeholder substituted for secret-like environment values.
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Returns `true` when an environment variable name looks like it holds a secret value.
///
/// Matches `API_KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, and any `*_KEY` suffix
/// (case-insensitive) so history persistence and status output never leak the raw value.
pub fn is_secret_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.contains("API_KEY")
        || upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("CREDENTIAL")
        || upper.ends_with("_KEY")
        || upper == "KEY"
}

/// Returns the display-safe value for an env assignment (`<redacted>` for secret-like keys).
pub fn env_value_for_display(key: &str, value: &str) -> String {
    if is_secret_env_key(key) {
        REDACTED_PLACEHOLDER.to_owned()
    } else {
        sanitize_terminal_line(value)
    }
}

/// Redacts secret-like `env KEY=VALUE` assignments in a command line to `env KEY=<redacted>`.
///
/// Applied to every history entry before it is kept in memory or persisted to disk, so
/// `history`, `Ctrl-R` search, and Fish ghost suggestions never echo secret material.
pub fn redact_history_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("env ") else {
        return line.to_owned();
    };
    let mut parts = rest.splitn(2, char::is_whitespace);
    let assignment = parts.next().unwrap_or_default();
    let tail = parts.next().unwrap_or_default();
    let Some((key, _value)) = assignment.split_once('=') else {
        return line.to_owned();
    };
    if is_secret_env_key(key) {
        if tail.is_empty() {
            format!("env {key}={REDACTED_PLACEHOLDER}")
        } else {
            format!("env {key}={REDACTED_PLACEHOLDER} {tail}")
        }
    } else {
        line.to_owned()
    }
}

/// Neutralizes terminal escape sequences and control characters in untrusted text.
///
/// Strips `ESC`-introduced sequences (`CSI`, `OSC`, `DCS`, `SOS`, `PM`, `APC`, and
/// two-character escapes such as `ESC =`), C0 control characters (except `\n` and `\t`),
/// C1 controls (`U+0080..=U+009F`), and `DEL`. Newlines survive here; use
/// [`sanitize_terminal_line`] for single-line fields.
///
/// This defeats OSC-52 clipboard hijacking, cursor/state manipulation, CSI injection,
/// and log forging through embedded CR/LF sequences.
pub fn sanitize_terminal_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\x1b' => match chars.peek().copied() {
                Some('[') => {
                    let _ = chars.next();
                    // CSI: parameter/intermediate bytes end at a final byte 0x40..=0x7E.
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    let _ = chars.next();
                    // String sequences (OSC/DCS/SOS/PM/APC) end at BEL or ST (ESC \).
                    for c in chars.by_ref() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' {
                            if chars.peek() == Some(&'\\') {
                                let _ = chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Two-character escape sequences (ESC =, ESC >, ESC 7, ...).
                    let _ = chars.next();
                }
                None => {}
            },
            '\r' => {
                // Normalize CRLF to LF; lone CR becomes LF so log forging cannot hide lines.
                if chars.peek() != Some(&'\n') {
                    out.push('\n');
                }
            }
            '\u{007f}' | '\u{0080}'..='\u{009f}' => {}
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

/// Sanitizes untrusted text for a single-line terminal field (newlines and tabs become spaces).
pub fn sanitize_terminal_line(input: &str) -> String {
    sanitize_terminal_text(input).replace(['\n', '\t'], " ")
}

/// Forces a terminal state reset after an untrusted child process exits.
///
/// Children inherit the raw TTY and may hide the cursor, set scroll regions, enable
/// bracketed paste, or leave SGR attributes set; this restores a known-safe state.
pub fn reset_terminal_after_child<W: Write>(out: &mut W) -> std::io::Result<()> {
    write!(
        out,
        // Show cursor, reset scroll region, disable bracketed paste, reset SGR.
        "\x1b[?25h\x1b[r\x1b[?2004l\x1b[0m"
    )?;
    out.flush()
}

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

/// Persistent command history store with reverse search and Fish-style prefix autosuggestions.
#[derive(Debug, Clone)]
pub struct HistoryStore {
    entries: Vec<String>,
    file_path: Option<PathBuf>,
}

impl Default for HistoryStore {
    fn default() -> Self {
        Self::new(Some(default_history_file_path()))
    }
}

/// Resolves the default history file path (`$CORDON_HISTFILE` or `~/.local/share/cordon/repl_history`).
pub fn default_history_file_path() -> PathBuf {
    if let Ok(custom) = std::env::var("CORDON_HISTFILE")
        && !custom.trim().is_empty()
    {
        return PathBuf::from(expand_tilde(&custom));
    }
    if let Ok(home) = std::env::var("HOME") {
        let home_trim = home.trim_end_matches('/');
        return PathBuf::from(format!("{home_trim}/.local/share/cordon/repl_history"));
    }
    PathBuf::from(".cordon_history")
}

/// Forces owner-only (`0600`) permissions on the persistent history file (best-effort).
fn enforce_owner_only_permissions(path: &Path) {
    let perms = std::fs::Permissions::from_mode(0o600);
    if std::fs::set_permissions(path, perms).is_err() {
        // Best-effort: a failure here must not break REPL startup.
    }
}

impl HistoryStore {
    /// Creates a [`HistoryStore`] backed by an optional file on disk, loading existing entries if present.
    ///
    /// The backing file is forced to owner-only permissions (`0600`) on load so previously
    /// persisted history (which may predate the hardening) stops leaking to other local users.
    pub fn new(file_path: Option<PathBuf>) -> Self {
        let mut store = Self {
            entries: Vec::new(),
            file_path,
        };
        if let Some(ref p) = store.file_path {
            enforce_owner_only_permissions(p);
            if let Ok(content) = std::fs::read_to_string(p) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    let redacted = redact_history_line(trimmed);
                    if !redacted.is_empty()
                        && store.entries.last().map(String::as_str) != Some(redacted.as_str())
                    {
                        store.entries.push(redacted);
                    }
                }
                if store.entries.len() > MAX_HISTORY_ENTRIES {
                    let drain_count = store.entries.len() - MAX_HISTORY_ENTRIES;
                    store.entries.drain(0..drain_count);
                }
            }
        }
        store
    }

    /// Returns all recorded history entries in chronological order.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Returns the backing history file path, if configured.
    pub fn file_path(&self) -> Option<&Path> {
        self.file_path.as_deref()
    }

    /// Appends a command line to history (deduplicating consecutive identical entries) and persists to disk.
    ///
    /// Secret-like `env KEY=VALUE` values are redacted (see [`redact_history_line`]) before the
    /// entry is kept in memory or written to disk.
    pub fn push(&mut self, line: &str) {
        let trimmed = redact_history_line(line.trim());
        if trimmed.is_empty() {
            return;
        }
        if self.entries.last().map(String::as_str) != Some(trimmed.as_str()) {
            self.entries.push(trimmed);
            if self.entries.len() > MAX_HISTORY_ENTRIES {
                self.entries.remove(0);
            }
            let _ = self.save();
        }
    }

    /// Clears all in-memory and on-disk history entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        let _ = self.save();
    }

    /// Persists the current history buffer to `self.file_path`.
    ///
    /// The file is created and forced to owner-only permissions (`0600`) because history
    /// can contain sensitive command lines.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(ref path) = self.file_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut body = String::new();
        for entry in &self.entries {
            let _ = writeln!(body, "{entry}");
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(body.as_bytes())?;
        enforce_owner_only_permissions(path);
        Ok(())
    }

    /// Performs a case-insensitive reverse search (`Ctrl-R`) for `query`, skipping `skip_matches` newest matches.
    pub fn search_reverse(&self, query: &str, skip_matches: usize) -> Option<&str> {
        if query.is_empty() {
            return self.entries.last().map(String::as_str);
        }
        let q_lower = query.to_ascii_lowercase();
        self.entries
            .iter()
            .rev()
            .filter(|entry| entry.to_ascii_lowercase().contains(&q_lower))
            .nth(skip_matches)
            .map(String::as_str)
    }

    /// Returns a Fish-style inline ghost completion suffix for `current_line` (only the characters after `current_line`).
    pub fn suggest_ghost_suffix(
        &self,
        current_line: &str,
        fallback_candidates: &[String],
    ) -> Option<String> {
        if current_line.is_empty() {
            return None;
        }
        for entry in self.entries.iter().rev() {
            if entry.starts_with(current_line) && entry.len() > current_line.len() {
                return Some(entry[current_line.len()..].to_owned());
            }
        }
        for cand in fallback_candidates {
            if cand.starts_with(current_line) && cand.len() > current_line.len() {
                return Some(cand[current_line.len()..].to_owned());
            }
        }
        None
    }
}

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
                // Ctrl-U: kill from cursor to start of line
                self.buffer.replace_range(0..self.cursor, "");
                self.cursor = 0;
                EditAction::Continue
            }
            KeyCode::Char('k') if ctrl => {
                // Ctrl-K: kill from cursor to end of line
                self.buffer.truncate(self.cursor);
                EditAction::Continue
            }
            KeyCode::Char('w') if ctrl => {
                // Ctrl-W: delete previous word
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
                if self.cursor == self.buffer.len()
                    && let Some(ghost) = ghost_suffix
                {
                    self.buffer.push_str(ghost);
                }
                self.cursor = self.buffer.len();
                EditAction::Continue
            }
            KeyCode::End => {
                if self.cursor == self.buffer.len()
                    && let Some(ghost) = ghost_suffix
                {
                    self.buffer.push_str(ghost);
                }
                self.cursor = self.buffer.len();
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
                if self.cursor == self.buffer.len()
                    && let Some(ghost) = ghost_suffix
                {
                    self.buffer.push_str(ghost);
                    self.cursor = self.buffer.len();
                } else {
                    self.cursor = self.next_char_boundary();
                }
                EditAction::Continue
            }
            KeyCode::Char('f') if ctrl => {
                if self.cursor == self.buffer.len()
                    && let Some(ghost) = ghost_suffix
                {
                    self.buffer.push_str(ghost);
                    self.cursor = self.buffer.len();
                } else {
                    self.cursor = self.next_char_boundary();
                }
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
                } else if self.cursor == self.buffer.len()
                    && let Some(ghost) = ghost_suffix
                {
                    self.buffer.push_str(ghost);
                    self.cursor = self.buffer.len();
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

/// Completes a partial REPL command line using contextual argument candidates or filesystem paths.
pub fn complete_line(line: &str, custom_candidates: &[String]) -> Option<String> {
    let trimmed_start = line.trim_start();
    if trimmed_start.is_empty() {
        return None;
    }

    if !trimmed_start.contains(char::is_whitespace) {
        if let Some(completed_path) = complete_filesystem_token(trimmed_start) {
            return Some(completed_path);
        }
        for &builtin in REPL_BUILTIN_COMMANDS {
            if builtin.starts_with(trimmed_start) && builtin != trimmed_start {
                return Some(builtin.to_owned());
            }
        }
        for cand in custom_candidates {
            if cand.starts_with(trimmed_start) && cand != trimmed_start {
                return Some(cand.clone());
            }
        }
        return None;
    }

    let idx = line.rfind(char::is_whitespace)?;
    let (prefix_before_last, last_tok) = (&line[..=idx], &line[idx + 1..]);
    if last_tok.is_empty() {
        return None;
    }

    let tokens: Vec<&str> = line.split_whitespace().collect();
    let first = tokens.first().copied().unwrap_or_default();

    let pool: Vec<&str> = match first {
        "use" | "profile" => PROFILE_CANDIDATES.to_vec(),
        "allow-group" => COMMAND_GROUP_CANDIDATES.to_vec(),
        "mount-group" => DIRECTORY_GROUP_CANDIDATES.to_vec(),
        "plugin" | "plugins" => {
            if tokens.len() == 2 {
                vec!["list", "enable", "disable", "info"]
            } else {
                PLUGIN_CANDIDATES.to_vec()
            }
        }
        "ls" => vec!["configs", "mounts", "bins", "groups", "plugins"],
        "net" => vec!["auto", "direct", "airgap", "netns"],
        _ => Vec::new(),
    };

    for item in pool {
        if item.starts_with(last_tok) && item != last_tok {
            return Some(format!("{prefix_before_last}{item}"));
        }
    }

    if let Some(completed_path) = complete_filesystem_token(last_tok) {
        return Some(format!("{prefix_before_last}{completed_path}"));
    }

    None
}

fn complete_filesystem_token(partial: &str) -> Option<String> {
    if !partial.starts_with("./")
        && !partial.starts_with('/')
        && !partial.starts_with("~/")
        && !partial.starts_with("configs/")
    {
        return None;
    }
    let expanded = expand_tilde(partial);
    let path = Path::new(&expanded);
    let (dir_to_read, file_prefix, display_dir_prefix) = if expanded.ends_with('/') {
        (path, "", partial)
    } else {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let slash_pos = partial.rfind('/').map_or(0, |i| i + 1);
        (parent, fname, &partial[..slash_pos])
    };

    let entries = std::fs::read_dir(dir_to_read).ok()?;
    let mut matches: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(file_prefix) && name != file_prefix {
            let suffix = if entry.path().is_dir() { "/" } else { "" };
            matches.push(format!("{display_dir_prefix}{name}{suffix}"));
        }
    }
    matches.sort();
    matches.into_iter().next()
}

/// Renders a REPL command line with live ANSI syntax highlighting and an optional dimmed Fish ghost completion.
///
/// Color legend:
/// - **Bold Green (`\x1b[1;32m`)**: Recognized REPL builtin, alias, executable `./<config>`, or host binary.
/// - **Bold Red (`\x1b[1;31m`)**: Unknown command or missing `./<path>`.
/// - **Cyan (`\x1b[36m`)**: Flags (`-f`, `--offline`, `:ro`, `:rw`).
/// - **Yellow (`\x1b[33m`)**: Quoted strings (`"..."`, `'...'`) and `KEY=VALUE` assignments.
/// - **Bold Magenta (`\x1b[1;35m`)**: Built-in profile, command group, directory group, or plugin identifiers.
/// - **Underlined Blue (`\x1b[4;34m`)**: Existing filesystem paths (`configs/...`, `./...`, `/...`).
/// - **Dim Gray (`\x1b[90m`)**: Comments (`#...`) and inline Fish ghost autosuggestions.
pub fn highlight_repl_line(
    line: &str,
    ghost_suffix: Option<&str>,
    valid_commands: &BTreeSet<String>,
) -> String {
    if line.trim_start().starts_with('#') {
        return format!("\x1b[90m{line}\x1b[0m");
    }

    let mut out = String::with_capacity(line.len() + 64);
    let mut chars = line.char_indices().peekable();
    let mut is_first_token = true;

    while let Some(&(start_idx, ch)) = chars.peek() {
        if ch.is_whitespace() {
            out.push(ch);
            let _ = chars.next();
            continue;
        }

        let mut end_idx = line.len();
        let mut in_quote: Option<char> = None;
        while let Some(&(idx, c)) = chars.peek() {
            if let Some(q) = in_quote {
                if c == q {
                    in_quote = None;
                }
                let _ = chars.next();
            } else if c == '"' || c == '\'' {
                in_quote = Some(c);
                let _ = chars.next();
            } else if c.is_whitespace() {
                end_idx = idx;
                break;
            } else {
                let _ = chars.next();
            }
        }

        let token = &line[start_idx..end_idx];
        let color_code = if is_first_token {
            is_first_token = false;
            classify_command_token(token, valid_commands)
        } else {
            classify_argument_token(token)
        };

        if color_code.is_empty() {
            out.push_str(token);
        } else {
            let _ = write!(out, "{color_code}{token}\x1b[0m");
        }
    }

    if let Some(ghost) = ghost_suffix
        && !ghost.is_empty()
    {
        let _ = write!(out, "\x1b[90m{ghost}\x1b[0m");
    }

    out
}

fn classify_command_token(token: &str, valid_commands: &BTreeSet<String>) -> &'static str {
    if let Some(bang_rest) = token.strip_prefix('!') {
        if bang_rest.is_empty() || resolve_host_binary(bang_rest).is_some() {
            return "\x1b[1;32m";
        }
        return "\x1b[1;31m";
    }
    if token.starts_with("./") || token.starts_with('/') || token.starts_with("~/") {
        let expanded = expand_tilde(token);
        if Path::new(&expanded).exists() {
            return "\x1b[1;4;32m";
        }
        return "\x1b[1;31m";
    }
    if REPL_BUILTIN_COMMANDS.contains(&token)
        || valid_commands.contains(token)
        || resolve_host_binary(token).is_some()
    {
        "\x1b[1;32m"
    } else {
        "\x1b[1;31m"
    }
}

fn classify_argument_token(token: &str) -> &'static str {
    if token.starts_with('-')
        || token.ends_with(":ro")
        || token.ends_with(":rw")
        || token == "@plugin"
    {
        return "\x1b[36m";
    }
    if (token.starts_with('"') && token.ends_with('"'))
        || (token.starts_with('\'') && token.ends_with('\''))
        || token.contains('=')
    {
        return "\x1b[33m";
    }
    if PROFILE_CANDIDATES.contains(&token)
        || COMMAND_GROUP_CANDIDATES.contains(&token)
        || DIRECTORY_GROUP_CANDIDATES.contains(&token)
        || PLUGIN_CANDIDATES.contains(&token)
        || matches!(
            token,
            "auto"
                | "direct"
                | "airgap"
                | "netns"
                | "configs"
                | "mounts"
                | "bins"
                | "groups"
                | "plugins"
        )
    {
        return "\x1b[1;35m";
    }
    let expanded = expand_tilde(token);
    if (token.contains('/') || token.starts_with("Cordonfile")) && Path::new(&expanded).exists() {
        return "\x1b[4;34m";
    }
    ""
}

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

/// Reads a single interactive line using `crossterm` raw mode when `stdin` is a TTY.
#[allow(clippy::too_many_arguments)]
pub fn read_interactive_tty_line<W: Write>(
    out: &mut W,
    prompt_display: &str,
    prompt_visible_chars: usize,
    history: &HistoryStore,
    enable_syntax_highlight: bool,
    enable_fish_autosuggest: bool,
    valid_commands: &BTreeSet<String>,
    completion_candidates: &[String],
) -> std::io::Result<Option<String>> {
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }

    let _guard = RawModeGuard::acquire()?;
    let mut state = LineEditorState::new();

    loop {
        let ghost = if enable_fish_autosuggest && state.cursor == state.buffer.len() {
            history.suggest_ghost_suffix(&state.buffer, completion_candidates)
        } else {
            None
        };

        render_editor_frame(
            out,
            prompt_display,
            prompt_visible_chars,
            &state,
            history,
            ghost.as_deref(),
            enable_syntax_highlight,
            valid_commands,
        )?;

        let ev = event::read()?;
        let Event::Key(key_ev) = ev else {
            continue;
        };
        if key_ev.kind == KeyEventKind::Release {
            continue;
        }

        match state.handle_key(key_ev, history, ghost.as_deref(), completion_candidates) {
            EditAction::Continue => {}
            EditAction::Submit(line) => {
                // Redraw final line without ghost text and advance to next line
                render_editor_frame(
                    out,
                    prompt_display,
                    prompt_visible_chars,
                    &state,
                    history,
                    None,
                    enable_syntax_highlight,
                    valid_commands,
                )?;
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

#[allow(clippy::too_many_arguments, clippy::cast_possible_truncation)]
fn render_editor_frame<W: Write>(
    out: &mut W,
    prompt_display: &str,
    prompt_visible_chars: usize,
    state: &LineEditorState,
    history: &HistoryStore,
    ghost_suffix: Option<&str>,
    enable_syntax_highlight: bool,
    valid_commands: &BTreeSet<String>,
) -> std::io::Result<()> {
    crossterm::queue!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine)
    )?;

    if state.reverse_search_active {
        let matched = history
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

    let rendered_line = if enable_syntax_highlight {
        highlight_repl_line(&state.buffer, ghost_suffix, valid_commands)
    } else if let Some(g) = ghost_suffix {
        format!("{}\x1b[90m{g}\x1b[0m", state.buffer)
    } else {
        state.buffer.clone()
    };

    write!(out, "{prompt_display}{rendered_line}")?;
    let cursor_chars = state.buffer[..state.cursor].chars().count();
    let target_col = (prompt_visible_chars + cursor_chars) as u16;
    crossterm::queue!(out, cursor::MoveToColumn(target_col))?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_store_persists_searches_and_suggests_fish_ghost() {
        let tmp_path =
            std::env::temp_dir().join(format!("cordon_hist_test_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&tmp_path);

        let mut store = HistoryStore::new(Some(tmp_path.clone()));
        store.push("allow-group search-tools");
        store.push("./configs/Cordonfile.antigravity");
        store.push("allow-bin bat rg");

        assert_eq!(store.entries().len(), 3);
        assert_eq!(
            store.search_reverse("antigravity", 0),
            Some("./configs/Cordonfile.antigravity")
        );
        assert_eq!(
            store.suggest_ghost_suffix("allow-b", &[]),
            Some("in bat rg".to_owned())
        );

        let reloaded = HistoryStore::new(Some(tmp_path.clone()));
        assert_eq!(reloaded.entries().len(), 3);
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn line_editor_handles_up_down_ctrl_u_ctrl_w_ctrl_r_and_ghost_accept() {
        let mut store = HistoryStore::new(None);
        store.push("use ai-agent");
        store.push("allow-bin bat rg");

        let mut state = LineEditorState::new();
        // Up arrow -> "allow-bin bat rg"
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
            &store,
            None,
            &[],
        );
        assert_eq!(state.buffer, "allow-bin bat rg");

        // Up arrow again -> "use ai-agent"
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
            &store,
            None,
            &[],
        );
        assert_eq!(state.buffer, "use ai-agent");

        // Down arrow -> "allow-bin bat rg"
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &store,
            None,
            &[],
        );
        assert_eq!(state.buffer, "allow-bin bat rg");

        // Ctrl-W deletes "rg"
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
            &store,
            None,
            &[],
        );
        assert_eq!(state.buffer, "allow-bin bat ");

        // Ctrl-U clears line before cursor
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
            &store,
            None,
            &[],
        );
        assert_eq!(state.buffer, "");

        // Type "allow-" and accept ghost suffix "bin bat rg" with Right arrow
        for ch in "allow-".chars() {
            let _ = state.handle_key(
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
                &store,
                None,
                &[],
            );
        }
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
            &store,
            Some("bin bat rg"),
            &[],
        );
        assert_eq!(state.buffer, "allow-bin bat rg");

        // Ctrl-R reverse search for "ai-agent" and press Enter
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &store,
            None,
            &[],
        );
        assert!(state.reverse_search_active);
        for ch in "ai-agent".chars() {
            let _ = state.handle_key(
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
                &store,
                None,
                &[],
            );
        }
        let act = state.handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &store,
            None,
            &[],
        );
        assert_eq!(act, EditAction::Submit("use ai-agent".to_owned()));
    }

    #[test]
    fn syntax_highlighter_colors_valid_and_invalid_tokens() {
        let mut valid = BTreeSet::new();
        valid.insert("ag".to_owned());

        let colored_ok = highlight_repl_line(
            "allow-group search-tools --offline",
            Some(" coreutils"),
            &valid,
        );
        assert!(colored_ok.contains("\x1b[1;32mallow-group\x1b[0m"));
        assert!(colored_ok.contains("\x1b[1;35msearch-tools\x1b[0m"));
        assert!(colored_ok.contains("\x1b[36m--offline\x1b[0m"));
        assert!(colored_ok.contains("\x1b[90m coreutils\x1b[0m"));

        let colored_bad = highlight_repl_line("nonexistent_cmd_xyz", None, &valid);
        assert!(colored_bad.contains("\x1b[1;31mnonexistent_cmd_xyz\x1b[0m"));
    }

    #[test]
    fn sanitize_terminal_text_strips_escape_sequences_and_controls() {
        // CSI injection (cursor hiding) is neutralized.
        assert_eq!(sanitize_terminal_text("a\x1b[?25lb"), "ab");
        // OSC-52 clipboard hijack payloads are stripped entirely (through ST and BEL).
        assert_eq!(
            sanitize_terminal_text("x\x1b]52;c;AAAA\x07y"),
            "xy",
            "OSC + BEL must be stripped"
        );
        assert_eq!(
            sanitize_terminal_text("x\x1b]52;c;AAAA\x1b\\y"),
            "xy",
            "OSC + ST must be stripped"
        );
        // DCS / APC string sequences are stripped.
        assert_eq!(sanitize_terminal_text("a\x1bPpayload\x1b\\b"), "ab");
        assert_eq!(sanitize_terminal_text("a\x1b_payload\x07b"), "ab");
        // Two-character escapes are stripped.
        assert_eq!(sanitize_terminal_text("a\x1b=b"), "ab");
        // C1 controls and DEL are stripped.
        assert_eq!(sanitize_terminal_text("a\u{009b}\u{007f}b"), "ab");
        // CRLF is normalized; lone CR becomes LF (no hidden lines).
        assert_eq!(sanitize_terminal_text("a\r\nb"), "a\nb");
        assert_eq!(sanitize_terminal_text("fake\rfake"), "fake\nfake");
        // Single-line variant folds newlines and tabs into spaces.
        assert_eq!(sanitize_terminal_line("a\nb\tc"), "a b c");
        // Harmless text passes through untouched.
        assert_eq!(sanitize_terminal_text("plain text 123"), "plain text 123");
    }

    #[test]
    fn history_redacts_secret_env_assignments_and_uses_0600() {
        let tmp_path = std::env::temp_dir().join(format!(
            "cordon_hist_secret_test_{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp_path);

        assert!(is_secret_env_key("API_KEY"));
        assert!(is_secret_env_key("OPENAI_API_KEY"));
        assert!(is_secret_env_key("GITHUB_TOKEN"));
        assert!(is_secret_env_key("DB_PASSWORD"));
        assert!(is_secret_env_key("AWS_SECRET_ACCESS_KEY"));
        assert!(is_secret_env_key("SSH_CREDENTIAL"));
        assert!(is_secret_env_key("KEY"));
        assert!(!is_secret_env_key("FOO"));
        assert!(!is_secret_env_key("PATH"));

        let mut store = HistoryStore::new(Some(tmp_path.clone()));
        store.push("env OPENAI_API_KEY=sk-super-secret-value");
        store.push("env FOO=BAR");
        store.push("run opencode");

        assert_eq!(
            store.entries()[0],
            "env OPENAI_API_KEY=<redacted>",
            "secret values must never be retained in history"
        );
        assert_eq!(store.entries()[1], "env FOO=BAR");

        let persisted = std::fs::read_to_string(&tmp_path).unwrap_or_default();
        assert!(!persisted.contains("sk-super-secret-value"));
        assert!(persisted.contains("env OPENAI_API_KEY=<redacted>"));

        let mode = std::fs::metadata(&tmp_path).map_or(0, |m| m.permissions().mode() & 0o777);
        assert_eq!(mode, 0o600, "history file must be owner-only");

        // Legacy files with loose permissions are tightened on load.
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644));
        let _reloaded = HistoryStore::new(Some(tmp_path.clone()));
        let reloaded_mode =
            std::fs::metadata(&tmp_path).map_or(0, |m| m.permissions().mode() & 0o777);
        assert_eq!(reloaded_mode, 0o600);

        let _ = std::fs::remove_file(&tmp_path);
    }
}
