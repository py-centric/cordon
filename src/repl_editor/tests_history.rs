use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{EditAction, HistoryStore, LineEditorState};

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
