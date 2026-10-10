//! T42: file-exists prompt snapshots and key handling.

use courier_ftp_core::{
    events::{ApplyTo, FileExistsAnswer, PromptResponse},
    model::{Direction, Entry, LocalPath, Precision, RemotePath, Timestamp},
    settings::ExistsAction,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use time::macros::datetime;
use tokio::sync::oneshot;

use super::FileExistsDialog;
use crate::ui::{
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
}

fn draw(modal: &mut dyn Modal, w: u16, h: u16) -> Terminal<TestBackend> {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    let theme = Theme::new(None, true);
    t.draw(|f| modal.draw(f, f.area(), &theme)).unwrap();
    t
}
fn text(t: &Terminal<TestBackend>) -> String {
    t.backend().to_string()
}

fn entry(size: Option<u64>, time: Option<Timestamp>) -> Entry {
    let mut e = Entry::file("report.pdf", 0);
    e.size = size;
    e.modified = time;
    e
}

fn dialog(
    direction: Direction,
    unicode: bool,
) -> (FileExistsDialog, oneshot::Receiver<PromptResponse>) {
    let (tx, rx) = oneshot::channel();
    let source = entry(
        Some(1_258_291),
        Some(Timestamp::new(
            datetime!(2026-05-01 12:00:30 UTC),
            Precision::Second,
        )),
    );
    let target = entry(
        Some(819_200),
        Some(Timestamp::new(
            datetime!(2026-04-30 09:15 UTC),
            Precision::Minute,
        )),
    );
    let (source, target) = match direction {
        Direction::Download => (source, target),
        Direction::Upload => (source, entry(None, None)),
    };
    let d = FileExistsDialog::new(
        direction,
        source,
        target,
        LocalPath::new("/data/me/Documents/reports/2026/report.pdf"),
        RemotePath::new("/srv/ftp/pub/reports/2026/report.pdf"),
        unicode,
        tx,
    );
    (d, rx)
}

fn answer(rx: &mut oneshot::Receiver<PromptResponse>) -> FileExistsAnswer {
    match rx.try_recv() {
        Ok(PromptResponse::FileExists(a)) => a,
        other => panic!("no file-exists answer: {other:?}"),
    }
}

#[test]
fn snapshot_download() {
    let (mut d, _rx) = dialog(Direction::Download, true);
    insta::assert_snapshot!("download", text(&draw(&mut d, 80, 32)));
}

#[test]
fn snapshot_upload_rename_apply_to_all() {
    let (mut d, _rx) = dialog(Direction::Upload, true);
    for _ in 0..5 {
        d.handle_key(key(KeyCode::Down));
    }
    // Name field, then "Always".
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' ')));
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' ')));
    insta::assert_snapshot!("upload_rename_apply_to_all", text(&draw(&mut d, 80, 32)));
}

#[test]
fn snapshot_narrow_ascii() {
    let (mut d, _rx) = dialog(Direction::Download, false);
    insta::assert_snapshot!("narrow_ascii", text(&draw(&mut d, 50, 32)));
}

#[test]
fn enter_overwrites_this_file_only() {
    let (mut d, mut rx) = dialog(Direction::Download, true);
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(
        answer(&mut rx),
        FileExistsAnswer::once(ExistsAction::Overwrite)
    );
}

#[test]
fn esc_and_cancel_skip() {
    let (mut d, mut rx) = dialog(Direction::Download, true);
    assert_eq!(d.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    assert_eq!(answer(&mut rx), FileExistsAnswer::once(ExistsAction::Skip));
    let (mut d, mut rx) = dialog(Direction::Download, true);
    // A plain letter does nothing; Alt-C cancels.
    assert_eq!(d.handle_key(key(KeyCode::Char('c'))), ModalOutcome::Keep);
    assert!(rx.try_recv().is_err());
    assert_eq!(d.handle_key(alt('c')), ModalOutcome::Close);
    assert_eq!(answer(&mut rx).action, ExistsAction::Skip);
}

#[test]
fn rename_with_a_new_name() {
    let (mut d, mut rx) = dialog(Direction::Download, true);
    for _ in 0..5 {
        d.handle_key(key(KeyCode::Down));
    }
    d.handle_key(key(KeyCode::Tab));
    // Replace the suggested `report (1).pdf`.
    d.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    for c in "x/y".chars() {
        d.handle_key(key(KeyCode::Char(c)));
    }
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Keep);
    assert!(text(&draw(&mut d, 80, 32)).contains("must be a file name"));
    d.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    for c in "copy.pdf".chars() {
        d.handle_key(key(KeyCode::Char(c)));
    }
    assert_eq!(d.handle_key(alt('o')), ModalOutcome::Close);
    let a = answer(&mut rx);
    assert_eq!(a.action, ExistsAction::Rename);
    assert_eq!(a.new_name.as_deref(), Some("copy.pdf"));
    assert_eq!(a.apply_to, ApplyTo::Once);
}

#[test]
fn scope_checkboxes() {
    // The sub-options are skipped by Tab until "Always" is ticked.
    let (mut d, mut rx) = dialog(Direction::Download, true);
    d.handle_key(key(KeyCode::Down)); // overwrite if newer
    d.handle_key(key(KeyCode::Tab)); // Always (name field disabled)
    d.handle_key(key(KeyCode::Tab)); // buttons
    d.handle_key(key(KeyCode::Tab)); // back to the list
    d.handle_key(key(KeyCode::Tab)); // Always
    d.handle_key(key(KeyCode::Char(' ')));
    for _ in 0..3 {
        d.handle_key(key(KeyCode::Tab));
        d.handle_key(key(KeyCode::Char(' ')));
    }
    d.handle_key(key(KeyCode::Enter));
    assert_eq!(
        answer(&mut rx),
        FileExistsAnswer {
            action: ExistsAction::OverwriteIfNewer,
            apply_to: ApplyTo::AllInQueue,
            same_direction_only: true,
            same_server_only: true,
            new_name: None,
        }
    );

    // "Always" alone: the session, everywhere.
    let (mut d, mut rx) = dialog(Direction::Upload, true);
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' ')));
    d.handle_key(key(KeyCode::Enter));
    let a = answer(&mut rx);
    assert_eq!(a.apply_to, ApplyTo::AllInSession);
    assert!(!a.same_direction_only && !a.same_server_only);
}

#[test]
fn closes_when_the_core_stops_waiting() {
    let (d, rx) = dialog(Direction::Download, true);
    assert!(!d.is_done());
    drop(rx);
    assert!(d.is_done());
}

/// Escape sequences in hostile names never reach the terminal: ratatui drops
/// control characters when it fills the buffer (T91).
#[test]
fn escape_sequences_in_names_are_not_drawn() {
    let (tx, _rx) = oneshot::channel();
    let mut d = FileExistsDialog::new(
        Direction::Download,
        entry(Some(1), None),
        entry(Some(2), None),
        LocalPath::new("/data/\u{1b}]0;pwned\u{7}x"),
        RemotePath::new("/pub/\u{1b}[2J\u{1b}[31mred"),
        true,
        tx,
    );
    let t = draw(&mut d, 80, 32);
    let cells: String = t
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(!cells.chars().any(char::is_control), "{cells:?}");
    assert!(cells.contains("red"));
}
