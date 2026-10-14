//! T62: chmod dialog (tri-state boxes, numeric value with `x`) and the
//! delete / overwrite question texts.

use courier_ftp_core::{
    model::{Entry, Permissions},
    transfer::recursive::{ApplyTo, ChmodSpec},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn draw(modal: &mut dyn Modal) -> String {
    let mut t = Terminal::new(TestBackend::new(70, 20)).unwrap();
    let theme = Theme::new(None, true);
    t.draw(|f| modal.draw(f, f.area(), &theme)).unwrap();
    t.backend().to_string()
}

fn file(name: &str, mode: Option<u32>) -> Entry {
    let mut e = Entry::file(name, 1);
    e.permissions = mode.map(Permissions::from_mode);
    e
}

fn dir(name: &str, mode: u32) -> Entry {
    let mut e = Entry::dir(name);
    e.permissions = Some(Permissions::from_mode(0o040_000 | mode));
    e
}

fn typed(d: &mut dyn Modal, text: &str) {
    for c in text.chars() {
        d.handle_key(key(KeyCode::Char(c)));
    }
}

fn clear_numeric(d: &mut ChmodDialog) {
    d.handle_key(key(KeyCode::Tab));
    assert_eq!(d.focus, Focus::Numeric);
    for _ in 0..3 {
        d.handle_key(key(KeyCode::Backspace));
    }
}

#[test]
fn single_file_shows_its_mode() {
    let (mut d, _rx) = ChmodDialog::new(&[file("index.html", Some(0o100_644))]);
    assert_eq!(d.numeric, "644");
    assert!(!d.tristate);
    insta::assert_snapshot!(draw(&mut d));
}

#[test]
fn differing_modes_are_tristate() {
    let (mut d, _rx) = ChmodDialog::new(&[
        file("a.sh", Some(0o755)),
        file("b.txt", Some(0o644)),
        dir("www", 0o755),
    ]);
    // Owner execute and group/other execute differ.
    assert_eq!(d.numeric, "xxx");
    assert_eq!(d.bits[0], TriState::On);
    assert_eq!(d.bits[2], TriState::Unchanged);
    assert!(d.tristate);
    assert!(d.has_dirs);
    insta::assert_snapshot!(draw(&mut d));
}

#[test]
fn unknown_mode_is_unchanged() {
    let (d, _rx) = ChmodDialog::new(&[file("a", None)]);
    assert_eq!(d.numeric, "xxx");
    assert_eq!(d.spec().mask, 0);
}

#[tokio::test]
async fn numeric_value_sets_the_boxes() {
    let (mut d, rx) = ChmodDialog::new(&[file("a", Some(0o644))]);
    clear_numeric(&mut d);
    typed(&mut d, "750");
    assert_eq!(d.numeric, "750");
    assert_eq!(d.bits[2], TriState::On, "owner execute");
    assert_eq!(d.bits[4], TriState::Off, "group write");
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    let spec = rx.await.unwrap().unwrap();
    assert_eq!(
        spec,
        ChmodSpec {
            mode: 0o750,
            mask: 0o777,
            recurse: false,
            apply_to: ApplyTo::All
        }
    );
}

#[tokio::test]
async fn x_digits_leave_groups_unchanged() {
    let (mut d, rx) = ChmodDialog::new(&[file("a", Some(0o755)), file("b", Some(0o600))]);
    clear_numeric(&mut d);
    typed(&mut d, "6x4");
    d.handle_key(key(KeyCode::Enter));
    let spec = rx.await.unwrap().unwrap();
    assert_eq!(spec.mask, 0o707);
    assert_eq!(spec.mode, 0o604);
    assert_eq!(spec.compute(Some(0o755)), Some(0o654));
    assert_eq!(spec.compute(Some(0o600)), Some(0o604));
}

#[test]
fn x_is_refused_for_a_single_known_mode() {
    let (mut d, _rx) = ChmodDialog::new(&[file("a", Some(0o644))]);
    clear_numeric(&mut d);
    typed(&mut d, "6x4");
    assert_eq!(d.numeric, "6x4");
    assert!(d.error.is_some());
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Keep);
    assert!(d.error.is_some(), "still explained");
}

#[test]
fn space_cycles_the_box_and_updates_the_number() {
    let (mut d, _rx) = ChmodDialog::new(&[file("a", Some(0o644))]);
    // Owner execute: right twice.
    d.handle_key(key(KeyCode::Right));
    d.handle_key(key(KeyCode::Right));
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.numeric, "744");
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.numeric, "644", "two states without differing modes");
    // Tri-state: on → unchanged → off → on.
    let (mut d, _rx) = ChmodDialog::new(&[file("a", Some(0o644)), file("b", Some(0o640))]);
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.bits[0], TriState::Unchanged);
    assert_eq!(d.numeric, "x4x");
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.bits[0], TriState::Off);
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.bits[0], TriState::On);
}

#[tokio::test]
async fn recursion_and_apply_to() {
    let (mut d, rx) = ChmodDialog::new(&[dir("www", 0o755)]);
    d.handle_key(key(KeyCode::Tab)); // numeric
    d.handle_key(key(KeyCode::Tab)); // recurse
    assert_eq!(d.focus, Focus::Recurse);
    d.handle_key(key(KeyCode::Char(' ')));
    d.handle_key(key(KeyCode::Tab));
    assert_eq!(d.focus, Focus::ApplyTo);
    d.handle_key(key(KeyCode::Right));
    insta::assert_snapshot!(draw(&mut d));
    d.handle_key(key(KeyCode::Enter));
    let spec = rx.await.unwrap().unwrap();
    assert!(spec.recurse);
    assert_eq!(spec.apply_to, ApplyTo::FilesOnly);
    assert_eq!((spec.mode, spec.mask), (0o755, 0o777));
}

#[tokio::test]
async fn escape_cancels() {
    let (mut d, rx) = ChmodDialog::new(&[file("a", Some(0o644))]);
    assert_eq!(d.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    assert_eq!(rx.await.unwrap(), None);
}

#[test]
fn delete_question_lists_names() {
    let entries = vec![
        Entry::dir("logs"),
        Entry::file("a.txt", 1),
        Entry::file("b.txt", 1),
        Entry::file("c.txt", 1),
        Entry::file("d.txt", 1),
        Entry::file("e.txt", 1),
        Entry::file("f.txt", 1),
    ];
    assert_eq!(
        delete_question(Side::Remote, &entries),
        "Really delete 6 files and 1 directory from the server?\n  logs/\n  a.txt\n  b.txt\n  \
         c.txt\n  d.txt\n  …and 2 more\nDirectories are deleted with everything in them."
    );
    assert_eq!(
        delete_question(Side::Local, &[Entry::file("x", 1)]),
        "Really delete 1 file from this computer?\n  x"
    );
}

#[test]
fn overwrite_questions() {
    assert_eq!(
        overwrite_question(&["b.txt".to_owned()]),
        "b.txt already exists. Replace it?"
    );
    assert_eq!(
        overwrite_question(&["a".to_owned(), "b".to_owned()]),
        "2 files already exist:\n  a\n  b\nReplace them?"
    );
}

#[tokio::test]
async fn command_line_walks_the_history() {
    let (mut d, rx) = CommandDialog::new(vec!["SITE HELP".to_owned(), "STAT".to_owned()]);
    typed(&mut d, "NO");
    d.handle_key(key(KeyCode::Up));
    assert_eq!(d.input.text(), "STAT");
    d.handle_key(key(KeyCode::Up));
    assert_eq!(d.input.text(), "SITE HELP");
    d.handle_key(key(KeyCode::Up));
    assert_eq!(d.input.text(), "SITE HELP", "stops at the oldest");
    d.handle_key(key(KeyCode::Down));
    d.handle_key(key(KeyCode::Down));
    assert_eq!(d.input.text(), "NO", "back to the draft");
    typed(&mut d, "OP");
    insta::assert_snapshot!(draw(&mut d));
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(rx.await.unwrap().as_deref(), Some("NOOP"));
}

#[tokio::test]
async fn empty_command_is_not_sent() {
    let (mut d, rx) = CommandDialog::new(Vec::new());
    typed(&mut d, "  ");
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Keep);
    assert_eq!(d.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    assert_eq!(rx.await.unwrap(), None);
}
