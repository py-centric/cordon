use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

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
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.buffer, "allow-bin bat rg");

    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.buffer, "use ai-agent");

    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.buffer, "allow-bin bat rg");

    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    assert_eq!(state.buffer, "allow-bin bat ");

    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    assert_eq!(state.buffer, "");

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
    assert_eq!(sanitize_terminal_text("a\x1b[?25lb"), "ab");
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
    assert_eq!(sanitize_terminal_text("a\x1bPpayload\x1b\\b"), "ab");
    assert_eq!(sanitize_terminal_text("a\x1b_payload\x07b"), "ab");
    assert_eq!(sanitize_terminal_text("a\x1b=b"), "ab");
    assert_eq!(sanitize_terminal_text("a\u{009b}\u{007f}b"), "ab");
    assert_eq!(sanitize_terminal_text("a\r\nb"), "a\nb");
    assert_eq!(sanitize_terminal_text("fake\rfake"), "fake\nfake");
    assert_eq!(sanitize_terminal_line("a\nb\tc"), "a b c");
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

    let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644));
    let _reloaded = HistoryStore::new(Some(tmp_path.clone()));
    let reloaded_mode = std::fs::metadata(&tmp_path).map_or(0, |m| m.permissions().mode() & 0o777);
    assert_eq!(reloaded_mode, 0o600);

    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
fn line_editor_cursor_editing_and_control_keys() {
    let store = HistoryStore::new(None);
    let mut state = LineEditorState::default();

    for ch in "use ai-ag".chars() {
        let _ = state.handle_key(
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
            &store,
            None,
            &[],
        );
    }
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.buffer, "use ai-agent");

    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.cursor, 0);
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.cursor, 1);
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.cursor, 0);
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    assert_eq!(state.cursor, state.buffer.len());

    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    assert_eq!(state.cursor, 0);
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        &store,
        None,
        &[],
    );
    let _ = state.handle_key(
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    let act_l = state.handle_key(
        KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    assert_eq!(act_l, EditAction::ClearScreen);

    let act_c = state.handle_key(
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    assert_eq!(act_c, EditAction::CancelLine);

    let mut empty = LineEditorState::default();
    let act_d = empty.handle_key(
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
        &store,
        None,
        &[],
    );
    assert_eq!(act_d, EditAction::Eof);
}

#[test]
fn line_editor_history_navigation_reverse_search_and_word_edits() {
    let mut store = HistoryStore::new(None);
    store.push("status");
    store.push("profiles");
    store.push("plan echo hi");

    let mut state = LineEditorState::new();
    let cand = vec!["profiles".to_owned(), "plan".to_owned()];

    for ch in "pro".chars() {
        state.handle_key(
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
            &store,
            None,
            &cand,
        );
    }
    // Tab completion
    state.handle_key(
        KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    assert_eq!(state.buffer, "profiles");

    // Ctrl-W deletes word, Home/End/Ctrl-K/Ctrl-U
    state.handle_key(
        KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
        &store,
        Some(" --flag"),
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );

    // History Up/Down and Ctrl-P/Ctrl-N
    state.handle_key(
        KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );

    // Reverse-i-search: Ctrl-R, type 'p', Ctrl-R again, Backspace, Esc, then Ctrl-R + Enter, Ctrl-R + Ctrl-G
    state.handle_key(
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );

    state.handle_key(
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    let sub = state.handle_key(
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &store,
        None,
        &cand,
    );
    assert!(matches!(sub, EditAction::Submit(_)));

    state.handle_key(
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    state.handle_key(
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        &store,
        None,
        &cand,
    );
    assert!(!state.reverse_search_active);
}
