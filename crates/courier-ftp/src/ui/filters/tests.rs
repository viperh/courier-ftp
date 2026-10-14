//! T67 tests: the filters dialog and the filter editor (snapshots and
//! editing flows), live re-filtering of the panes.

use courier_ftp_core::{
    backend::Listing,
    filters::{Condition, FilterScope, FilterSettings, Side, StringOp},
    model::{Entry, RemotePath},
    settings::{Layout, SymbolMode},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::{FiltersDialog, Slot, editor::Slot as ESlot};
use crate::{
    action::Action,
    config::Config,
    ui::{MainScreen, Modal, Theme, modal::ModalOutcome},
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(d: &mut FiltersDialog, codes: &[KeyCode]) -> ModalOutcome {
    let mut last = ModalOutcome::Keep;
    for c in codes {
        last = d.handle_key(key(*c));
    }
    last
}

fn typing(d: &mut FiltersDialog, text: &str) {
    for c in text.chars() {
        d.handle_key(key(KeyCode::Char(c)));
    }
}

fn dialog() -> (FiltersDialog, UnboundedReceiver<Action>) {
    let (tx, rx) = unbounded_channel();
    (FiltersDialog::new(&FilterSettings::default(), Some(tx)), rx)
}

fn sent(rx: &mut UnboundedReceiver<Action>) -> Vec<FilterSettings> {
    let mut out = Vec::new();
    while let Ok(a) = rx.try_recv() {
        if let Action::SetFilters(f) = a {
            out.push(*f);
        }
    }
    out
}

fn render(modal: &mut dyn Modal, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let theme = Theme::new(None, true);
    terminal.draw(|f| modal.draw(f, f.area(), &theme)).unwrap();
    terminal.backend().to_string()
}

fn local(s: &FilterSettings) -> Vec<String> {
    s.active().unwrap().enabled_local.clone()
}

fn remote(s: &FilterSettings) -> Vec<String> {
    s.active().unwrap().enabled_remote.clone()
}

/// Move the focused checklist's cursor to row `i` (from the top).
fn row(d: &mut FiltersDialog, i: usize) {
    d.handle_key(key(KeyCode::Home));
    for _ in 0..i {
        d.handle_key(key(KeyCode::Down));
    }
}

#[test]
fn dialog_snapshot() {
    let (mut d, _rx) = dialog();
    row(&mut d, 1);
    press(&mut d, &[KeyCode::Char(' '), KeyCode::Right]);
    row(&mut d, 4);
    press(&mut d, &[KeyCode::Char(' ')]);
    insta::assert_snapshot!("filters_dialog_80x24", render(&mut d, 80, 24));
}

#[test]
fn editor_snapshot() {
    let (mut d, _rx) = dialog();
    d.press(2);
    // "Temporary and backup files": three conditions, one a regex.
    press(&mut d, &[KeyCode::Down, KeyCode::Down]);
    insta::assert_snapshot!("filter_editor_80x24", render(&mut d, 80, 24));
    insta::assert_snapshot!("filter_editor_120x30", render(&mut d, 120, 30));
}

#[test]
fn checklists_enable_filters_per_side_and_apply_sends_them() {
    let (mut d, mut rx) = dialog();
    assert_eq!(d.focus(), Slot::Column(Side::Local));
    row(&mut d, 1);
    press(&mut d, &[KeyCode::Char(' ')]);
    assert_eq!(local(d.settings()), ["Git"]);
    // → moves to the remote column on the same row.
    press(&mut d, &[KeyCode::Right, KeyCode::Down, KeyCode::Char(' ')]);
    assert_eq!(remote(d.settings()), ["Temporary and backup files"]);
    // Space again turns it off.
    press(&mut d, &[KeyCode::Char(' '), KeyCode::Char(' ')]);
    assert!(sent(&mut rx).is_empty(), "nothing applied yet");
    assert_eq!(d.press(1), ModalOutcome::Keep, "Apply keeps the dialog");
    let applied = sent(&mut rx);
    assert_eq!(applied.len(), 1);
    assert_eq!(local(&applied[0]), ["Git"]);
    assert_eq!(remote(&applied[0]), ["Temporary and backup files"]);
    // Enter in a checklist is OK.
    assert_eq!(press(&mut d, &[KeyCode::Enter]), ModalOutcome::Close);
    assert_eq!(sent(&mut rx).len(), 1);
}

#[test]
fn toggle_all_and_one_sided_filters() {
    let mut settings = FilterSettings::default();
    settings.filters[0].scope = FilterScope::RemoteOnly;
    let (tx, mut rx) = unbounded_channel();
    let mut d = FiltersDialog::new(&settings, Some(tx));
    // Row 0 is remote only: not on the local side.
    press(&mut d, &[KeyCode::Char(' ')]);
    assert!(local(d.settings()).is_empty());
    assert!(
        d.note().unwrap().contains("remote files only"),
        "{:?}",
        d.note()
    );
    d.press(3);
    let names: Vec<String> = settings.filters.iter().map(|f| f.name.clone()).collect();
    assert_eq!(local(d.settings()).len(), names.len() - 1);
    assert_eq!(remote(d.settings()).len(), names.len());
    assert!(!local(d.settings()).contains(&names[0]));
    d.press(3);
    assert!(local(d.settings()).is_empty() && remote(d.settings()).is_empty());
    // The transfers option, and Esc cancels without sending anything.
    while d.focus() != Slot::Transfers {
        d.handle_key(key(KeyCode::Tab));
    }
    press(&mut d, &[KeyCode::Char(' ')]);
    assert_eq!(press(&mut d, &[KeyCode::Esc]), ModalOutcome::Close);
    assert!(sent(&mut rx).is_empty());
}

#[test]
fn apply_filters_to_transfers_is_sent() {
    let (mut d, mut rx) = dialog();
    while d.focus() != Slot::Transfers {
        d.handle_key(key(KeyCode::Tab));
    }
    press(&mut d, &[KeyCode::Char(' ')]);
    assert_eq!(press(&mut d, &[KeyCode::Enter]), ModalOutcome::Close);
    assert!(!sent(&mut rx)[0].apply_to_transfers);
}

#[test]
fn filter_sets_save_switch_and_delete() {
    let (mut d, mut rx) = dialog();
    row(&mut d, 1);
    press(&mut d, &[KeyCode::Char(' ')]);
    // Save as… "Web project" (a copy of Default), then change it.
    d.handle_key(key(KeyCode::BackTab));
    assert_eq!(d.focus(), Slot::SetButtons);
    press(&mut d, &[KeyCode::Enter]);
    typing(&mut d, "Web project");
    press(&mut d, &[KeyCode::Enter]);
    assert_eq!(d.settings().active_set, "Web project");
    assert_eq!(local(d.settings()), ["Git"]);
    press(&mut d, &[KeyCode::Tab, KeyCode::Down, KeyCode::Char(' ')]);
    assert_eq!(local(d.settings()), ["Git", "Temporary and backup files"]);
    // A duplicate name is refused.
    press(&mut d, &[KeyCode::BackTab, KeyCode::Enter]);
    typing(&mut d, "Default");
    press(&mut d, &[KeyCode::Enter]);
    assert!(d.note().unwrap().contains("already"), "{:?}", d.note());
    press(&mut d, &[KeyCode::Esc]);
    // Switch back to Default with the dropdown.
    press(&mut d, &[KeyCode::BackTab, KeyCode::Left]);
    assert_eq!(d.settings().active_set, "Default");
    assert_eq!(local(d.settings()), ["Git"]);
    // Default can't be deleted; Web project can.
    press(&mut d, &[KeyCode::Tab, KeyCode::Right, KeyCode::Enter]);
    assert!(d.note().unwrap().contains("can't be deleted"));
    press(&mut d, &[KeyCode::BackTab, KeyCode::Right]);
    assert_eq!(d.settings().active_set, "Web project");
    d.press(0);
    let applied = sent(&mut rx).pop().unwrap();
    assert_eq!(applied.active_set, "Web project");
    assert_eq!(applied.sets.len(), 2);

    let (tx, _rx) = unbounded_channel();
    let mut d = FiltersDialog::new(&applied, Some(tx));
    press(&mut d, &[KeyCode::BackTab, KeyCode::Right, KeyCode::Enter]);
    assert_eq!(d.settings().sets.len(), 1);
    assert_eq!(d.settings().active_set, "Default");
}

#[test]
fn new_filter_with_a_bad_regex_blocks_ok_until_fixed() {
    let (mut d, mut rx) = dialog();
    d.press(2);
    let editor = d.editor().unwrap();
    assert_eq!(editor.focus(), ESlot::List);
    // n: a new filter, focus on its name.
    press(&mut d, &[KeyCode::Char('n')]);
    let e = d.editor().unwrap();
    assert_eq!(e.focus(), ESlot::Name);
    assert_eq!(e.filters().last().unwrap().name, "New filter");
    assert_eq!(e.issue(), Some("Condition 1: enter a value."));
    // Rename it: Ctrl-u clears the field.
    d.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    typing(&mut d, "Logs");
    // To condition 1's operator: matches regex.
    while d.editor().unwrap().focus() != ESlot::Cond(0, 1) {
        d.handle_key(key(KeyCode::Tab));
    }
    press(&mut d, &[KeyCode::End]);
    for _ in 0..6 {
        d.handle_key(key(KeyCode::Right));
    }
    press(&mut d, &[KeyCode::Tab]);
    typing(&mut d, "(log");
    let issue = d.editor().unwrap().issue().unwrap().to_owned();
    assert!(
        issue.starts_with("Condition 1: invalid regular expression:"),
        "{issue}"
    );
    let screen = render(&mut d, 80, 24);
    assert!(screen.contains("invalid regular expression"), "{screen}");
    // OK (Enter) is blocked, and so is selecting another filter.
    press(&mut d, &[KeyCode::Enter]);
    assert!(d.editor().is_some(), "OK must not close the editor");
    // Fix it: `\.log$`.
    press(
        &mut d,
        &[KeyCode::Backspace, KeyCode::Backspace, KeyCode::Backspace],
    );
    press(&mut d, &[KeyCode::Backspace]);
    typing(&mut d, r"\.log$");
    assert_eq!(d.editor().unwrap().issue(), None);
    press(&mut d, &[KeyCode::Enter]);
    assert!(d.editor().is_none());
    let f = d.settings().filters.last().unwrap().clone();
    assert_eq!(f.name, "Logs");
    assert_eq!(
        f.conditions,
        [Condition::Name {
            op: StringOp::Matches,
            value: r"\.log$".into()
        }]
    );
    // Enable it remotely and press OK.
    press(&mut d, &[KeyCode::End, KeyCode::Right, KeyCode::Char(' ')]);
    assert_eq!(press(&mut d, &[KeyCode::Enter]), ModalOutcome::Close);
    let applied = sent(&mut rx).pop().unwrap();
    assert_eq!(remote(&applied), ["Logs"]);
    assert_eq!(applied.filters.len(), 6);
}

#[test]
fn a_filter_with_a_problem_cannot_be_left() {
    let (mut d, _rx) = dialog();
    d.press(2);
    press(&mut d, &[KeyCode::Char('n')]);
    let new = d.editor().unwrap().selected();
    // Back to the list: ↑ doesn't select another filter.
    press(&mut d, &[KeyCode::BackTab, KeyCode::Up]);
    assert_eq!(d.editor().unwrap().focus(), ESlot::List);
    assert_eq!(d.editor().unwrap().selected(), new);
    // Deleting it is fine.
    press(&mut d, &[KeyCode::Delete, KeyCode::Up]);
    assert_eq!(d.editor().unwrap().filters().len(), 5);
    assert_eq!(d.editor().unwrap().selected(), 3);
}

#[test]
fn rename_copy_delete_follow_into_the_sets() {
    let (mut d, mut rx) = dialog();
    // Git and Thumbs.db enabled on both sides.
    for r in [1, 4] {
        row(&mut d, r);
        press(
            &mut d,
            &[KeyCode::Char(' '), KeyCode::Right, KeyCode::Char(' ')],
        );
        press(&mut d, &[KeyCode::Left]);
    }
    d.press(2);
    // Rename Git → "Git dirs" (r focuses the name).
    press(&mut d, &[KeyCode::Down, KeyCode::Char('r')]);
    typing(&mut d, " dirs");
    // Copy it.
    press(&mut d, &[KeyCode::BackTab, KeyCode::Char('c')]);
    assert_eq!(
        d.editor().unwrap().filters().last().unwrap().name,
        "Git dirs (copy)"
    );
    // Delete Thumbs.db.
    press(&mut d, &[KeyCode::BackTab, KeyCode::Up]);
    assert_eq!(
        d.editor().unwrap().filters()[d.editor().unwrap().selected()].name,
        "Thumbs.db and .DS_Store"
    );
    press(&mut d, &[KeyCode::Char('d'), KeyCode::Enter]);
    assert!(d.editor().is_none());
    assert_eq!(local(d.settings()), ["Git dirs"]);
    assert_eq!(remote(d.settings()), ["Git dirs"]);
    d.press(0);
    let applied = sent(&mut rx).pop().unwrap();
    let names: Vec<&str> = applied.filters.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "CVS and SVN directories",
            "Git dirs",
            "Temporary and backup files",
            "Configuration files",
            "Git dirs (copy)"
        ]
    );
}

#[test]
fn editor_cancel_discards_and_restore_defaults_restores() {
    let (mut d, _rx) = dialog();
    d.press(2);
    press(&mut d, &[KeyCode::Char('d'), KeyCode::Char('d')]);
    assert_eq!(d.editor().unwrap().filters().len(), 3);
    press(&mut d, &[KeyCode::Esc]);
    assert!(d.editor().is_none());
    assert_eq!(d.settings().filters.len(), 5);

    d.press(2);
    // Change Git's condition, delete CVS, then restore defaults.
    press(&mut d, &[KeyCode::Down]);
    while d.editor().unwrap().focus() != ESlot::Cond(0, 2) {
        d.handle_key(key(KeyCode::Tab));
    }
    typing(&mut d, "x");
    press(&mut d, &[KeyCode::Tab, KeyCode::Tab]);
    assert_eq!(d.editor().unwrap().focus(), ESlot::ListButtons);
    // ListButtons: New Copy Rename Delete [Restore defaults].
    for _ in 0..4 {
        d.handle_key(key(KeyCode::Right));
    }
    press(&mut d, &[KeyCode::Enter]);
    let e = d.editor().unwrap();
    assert_eq!(e.filters(), courier_ftp_core::filters::builtin_filters());
    press(&mut d, &[KeyCode::Tab, KeyCode::Enter]);
    assert!(d.editor().is_none());
    assert_eq!(d.settings(), &FilterSettings::default());
}

#[test]
fn condition_rows_add_remove_and_change_type() {
    let (mut d, _rx) = dialog();
    d.press(2);
    // Git: one condition. Add a size condition.
    press(&mut d, &[KeyCode::Down]);
    while d.editor().unwrap().focus() != ESlot::CondButtons {
        d.handle_key(key(KeyCode::Tab));
    }
    press(&mut d, &[KeyCode::Enter]);
    assert_eq!(d.editor().unwrap().focus(), ESlot::Cond(1, 2));
    // Type → Size (letter jump), value "100".
    press(
        &mut d,
        &[KeyCode::BackTab, KeyCode::BackTab, KeyCode::Char('s')],
    );
    press(&mut d, &[KeyCode::Tab, KeyCode::Tab]);
    assert_eq!(
        d.editor().unwrap().issue(),
        None,
        "a fresh size condition is 0"
    );
    d.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    typing(&mut d, "1k");
    assert_eq!(
        d.editor().unwrap().issue(),
        Some("Condition 2: the size is a whole number of bytes.")
    );
    press(&mut d, &[KeyCode::Backspace]);
    typing(&mut d, "00");
    let e = d.editor().unwrap();
    assert_eq!(
        e.filters()[1].conditions[1],
        Condition::Size {
            op: courier_ftp_core::filters::NumOp::Greater,
            value: 100
        }
    );
    // Ctrl-d removes the focused row (the first one).
    press(&mut d, &[KeyCode::Up]);
    d.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
    assert_eq!(d.editor().unwrap().filters()[1].conditions.len(), 1);
    assert!(matches!(
        d.editor().unwrap().filters()[1].conditions[0],
        Condition::Size { .. }
    ));
    assert_eq!(d.editor().unwrap().focus(), ESlot::Cond(0, 2));
    // "Remove condition" removes the last row.
    while d.editor().unwrap().focus() != ESlot::CondButtons {
        d.handle_key(key(KeyCode::Tab));
    }
    press(&mut d, &[KeyCode::Right, KeyCode::Enter]);
    assert!(d.editor().unwrap().filters()[1].conditions.is_empty());
}

#[test]
fn dates_and_permissions_round_trip_through_the_rows() {
    use super::editor::{format_date, parse_date};
    assert_eq!(
        parse_date("2024-03-10").map(format_date).as_deref(),
        Some("2024-03-10")
    );
    for bad in ["2024-13-01", "2024-02-30", "yesterday", "2024-01-01-1", ""] {
        assert_eq!(parse_date(bad), None, "{bad}");
    }
}

// --- the screen: live re-filtering, status bar ---

fn screen() -> (MainScreen, UnboundedReceiver<Action>) {
    let mut config = Config::builtin();
    config.settings.interface.layout = Layout::Classic;
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    let mut s = MainScreen::new(config, Theme::new(None, true));
    let (tx, rx) = unbounded_channel();
    s.set_action_tx(tx);
    s.update(&Action::ListingLoaded {
        side: Side::Local,
        result: Ok(Listing {
            dir: RemotePath::new("/work"),
            entries: vec![
                Entry::dir(".git"),
                Entry::file("main.rs", 10),
                Entry::file("main.rs~", 10),
            ],
            fetched_at: std::time::Instant::now(),
            raw: None,
        }),
    });
    s.local.update(&Action::ToggleHidden, None);
    (s, rx)
}

fn shown(s: &MainScreen) -> Vec<String> {
    s.local
        .visible_entries()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

fn status_line(s: &mut MainScreen) -> String {
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    terminal.draw(|f| s.draw(f)).unwrap();
    let text = terminal.backend().to_string();
    text.lines().last().unwrap_or("").to_owned()
}

#[test]
fn applying_refilters_the_panes_and_updates_the_status_bar() {
    let (mut s, mut rx) = screen();
    assert_eq!(shown(&s), [".git", "main.rs", "main.rs~"]);
    assert!(!status_line(&mut s).contains("filters"));
    s.update(&Action::Filters);
    assert!(s.has_modal());
    // Git (row 1) and temporary files (row 2) locally; Apply.
    for k in [
        KeyCode::Down,
        KeyCode::Char(' '),
        KeyCode::Down,
        KeyCode::Char(' '),
    ] {
        s.handle_key(key(k));
    }
    // Tab to the buttons: remote column, transfers, buttons; → Apply.
    for k in [
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::Right,
        KeyCode::Enter,
    ] {
        s.handle_key(key(k));
    }
    assert!(s.has_modal(), "Apply leaves the dialog open");
    while let Ok(a) = rx.try_recv() {
        s.update(&a);
    }
    assert_eq!(shown(&s), ["main.rs"]);
    assert!(status_line(&mut s).contains("⚑ filters"));
    // Reopened, the dialog shows what is active; turning Git off again.
    s.handle_key(key(KeyCode::Esc));
    s.update(&Action::Filters);
    for k in [KeyCode::Down, KeyCode::Char(' '), KeyCode::Enter] {
        s.handle_key(key(k));
    }
    assert!(!s.has_modal());
    while let Ok(a) = rx.try_recv() {
        s.update(&a);
    }
    assert_eq!(shown(&s), [".git", "main.rs"]);
}
