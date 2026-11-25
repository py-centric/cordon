//! Persistent command history (`HistoryStore`), secret redaction, and terminal escape sanitization.

use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::config::expand_tilde;

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
pub fn sanitize_terminal_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\x1b' => match chars.peek().copied() {
                Some('[') => {
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    let _ = chars.next();
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
                    let _ = chars.next();
                }
                None => {}
            },
            '\r' => {
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
pub fn reset_terminal_after_child<W: Write>(out: &mut W) -> std::io::Result<()> {
    write!(out, "\x1b[?25h\x1b[r\x1b[?2004l\x1b[0m")?;
    out.flush()
}

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

    /// Returns a Fish-style inline ghost completion suffix for `current_line`.
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
