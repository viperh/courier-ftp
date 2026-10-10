//! Integration tests of dialogs in the app (`AppHarness`) and of path completion on a
//! real directory (T52).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use pretty_assertions::assert_eq;
use ratatui::{Frame, layout::Rect};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{tests::k, *};
use crate::{
    components::{
        Component, DrawCx,
        main_screen::layout::Region,
        widgets::{
            Completion, LocalPathCompleter, Notice, PathCompleter, PathInput, TextInput, Widget,
            WidgetOutcome,
        },
    },
    config::Config,
    paths::AppPaths,
    testing::{AppHarness, unicode_env},
};

fn harness() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.render(80, 24);
    h
}

fn status(h: &AppHarness) -> String {
    h.app()
        .main
        .status()
        .map(|m| m.text.clone())
        .unwrap_or_default()
}

fn name_form() -> FormDialog<String> {
    FormDialog::new(
        "Edit",
        Form::builder()
            .field("name", "Name", FieldWidget::Text(TextInput::new("")))
            .build(),
        |v| Ok(v.text("name").to_owned()),
    )
}

#[test]
fn push_returns_result_over_oneshot() {
    let mut h = harness();
    let rx = h
        .app_mut()
        .modals
        .push(confirm("Overwrite", "Overwrite?", ConfirmOpts::new()));
    assert_eq!(h.mode(), crate::app::Mode::Dialog);
    h.keys("enter");
    assert!(h.app().modals.is_empty());
    let r = h.runtime().block_on(rx).unwrap();
    assert_eq!(r, Some(true));
    // A prompt delivers the text exactly as typed.
    let rx = h
        .app_mut()
        .modals
        .push(prompt_text("Rename", "Name", "", None));
    h.keys("space a space enter");
    assert_eq!(h.runtime().block_on(rx).unwrap(), Some(" a ".to_owned()));
}

#[test]
fn push_then_sends_action() {
    let mut h = harness();
    h.app_mut()
        .modals
        .push_then(prompt_text("Say", "Text", "", None), |r| {
            r.map(Action::StatusMessage)
        });
    h.keys("h i enter");
    assert_eq!(status(&h), "hi");
    // Cancel maps to no action.
    h.app_mut()
        .modals
        .push_then(prompt_text("Say", "Text", "", None), |r| {
            Some(Action::StatusMessage(format!("{r:?}")))
        });
    h.keys("x esc");
    assert_eq!(status(&h), "None");
}

#[test]
fn close_all_cancels_pending_receivers() {
    let mut h = harness();
    let a = h.app_mut().modals.push(name_form());
    let b = h
        .app_mut()
        .modals
        .push(confirm("Q", "?", ConfirmOpts::new()));
    let c = h
        .app_mut()
        .modals
        .push(message("M", "m", MessageLevel::Info));
    assert_eq!(h.app().modals.depth(), 3);
    h.app_mut().modals.close_all();
    assert!(h.app().modals.is_empty());
    assert_eq!(h.runtime().block_on(a).unwrap(), None);
    assert_eq!(h.runtime().block_on(b).unwrap(), None);
    assert_eq!(h.runtime().block_on(c).unwrap(), None);
}

#[test]
fn nested_dialog_focus_returns_to_form() {
    let mut h = harness();
    let rx = h.app_mut().modals.push(name_form());
    h.keys("a b c esc");
    assert_eq!(
        h.app().modals.kinds(),
        [Some("form"), Some("confirm")],
        "Discard changes? on top"
    );
    let screen = h.render(80, 24);
    assert!(screen.contains("Discard changes?"), "{screen}");
    // The confirm gets every key: `x` is not typed into the form.
    h.keys("x");
    assert_eq!(h.app().modals.depth(), 2);
    h.keys("esc");
    assert_eq!(h.app().modals.kinds(), [Some("form")]);
    h.keys("d enter");
    assert_eq!(
        h.runtime().block_on(rx).unwrap(),
        Some("abcd".to_owned()),
        "values intact, focus back in the form"
    );
}

#[test]
fn escape_on_dirty_form_asks_discard() {
    let mut h = harness();
    let rx = h.app_mut().modals.push(name_form());
    // Clean form: Esc closes at once.
    let clean = h.app_mut().modals.push(name_form());
    h.keys("esc");
    assert_eq!(h.runtime().block_on(clean).unwrap(), None);
    h.keys("n esc");
    assert_eq!(h.app().modals.kinds(), [Some("form"), Some("confirm")]);
    // Enter keeps editing (danger default).
    h.keys("enter");
    assert_eq!(h.app().modals.kinds(), [Some("form")]);
    // Discard closes both with `None`.
    h.keys("esc alt-d");
    assert!(h.app().modals.is_empty());
    assert_eq!(h.runtime().block_on(rx).unwrap(), None);
}

#[test]
fn paste_truncation_shows_status() {
    let mut h = harness();
    let field = TextInput::new("").max_chars(4);
    let form = Form::builder()
        .field("v", "Value", FieldWidget::Text(field))
        .build();
    h.app_mut().modals.push(FormDialog::new("Paste", form, |v| {
        Ok(v.text("v").to_owned())
    }));
    h.paste("abcdefgh");
    assert_eq!(status(&h), "Pasted text was cut to 4 characters");
}

fn tree() -> tempfile::TempDir {
    let d = tempfile::TempDir::new().unwrap();
    std::fs::write(d.path().join("alpha.txt"), "a").unwrap();
    std::fs::create_dir(d.path().join("alps")).unwrap();
    std::fs::write(d.path().join("beta"), "b").unwrap();
    std::fs::write(d.path().join(".hidden"), "h").unwrap();
    d
}

/// Tab, wait for the wake-up, poll.
async fn complete(p: &mut PathInput, wake: &mut mpsc::UnboundedReceiver<Action>) -> WidgetOutcome {
    let o = p.handle_key(k("tab"));
    if o == WidgetOutcome::Consumed && p.is_completing() {
        assert!(matches!(wake.recv().await, Some(Action::Wake)));
        assert!(p.poll());
    }
    o
}

#[tokio::test]
async fn local_path_completion_in_tempdir() {
    let d = tree();
    let base = format!("{}/", d.path().display());
    let (tx, mut wake) = mpsc::unbounded_channel();
    let c: Arc<dyn PathCompleter> = Arc::new(LocalPathCompleter);
    // Unique match.
    let mut p = PathInput::new(&format!("{base}b"), Some(Arc::clone(&c)), tx.clone());
    complete(&mut p, &mut wake).await;
    assert_eq!(p.value(), format!("{base}beta"));
    // Several: common prefix and a popup; `Enter` picks.
    let mut p = PathInput::new(&format!("{base}al"), Some(Arc::clone(&c)), tx.clone());
    complete(&mut p, &mut wake).await;
    assert_eq!(p.value(), format!("{base}alp"));
    assert_eq!(p.popup_items(), Some(vec!["alpha.txt", "alps/"]));
    p.handle_key(k("tab"));
    p.handle_key(k("tab"));
    p.handle_key(k("enter"));
    assert_eq!(p.value(), format!("{base}alps/"));
    assert_eq!(p.popup_items(), None);
    // Hidden entries only with a `.` prefix.
    let mut p = PathInput::new(&base, Some(Arc::clone(&c)), tx.clone());
    complete(&mut p, &mut wake).await;
    let items = p.popup_items().unwrap();
    assert!(!items.contains(&".hidden"), "{items:?}");
    assert_eq!(items.len(), 4 - 1);
    let mut p = PathInput::new(&format!("{base}."), Some(Arc::clone(&c)), tx.clone());
    complete(&mut p, &mut wake).await;
    assert_eq!(p.value(), format!("{base}.hidden"));
    // No match: the focus moves on; the next Tab is not consumed (cached).
    let mut p = PathInput::new(&format!("{base}zz"), Some(Arc::clone(&c)), tx.clone());
    complete(&mut p, &mut wake).await;
    assert_eq!(p.take_notice(), Some(Notice::NextField));
    assert_eq!(p.handle_key(k("tab")), WidgetOutcome::Ignored);
    // Not at the end: Tab is not a completion.
    let mut p = PathInput::new(&format!("{base}b"), Some(Arc::clone(&c)), tx.clone());
    p.handle_key(k("left"));
    assert_eq!(p.handle_key(k("tab")), WidgetOutcome::Ignored);
    // Missing directory: an error message, value unchanged.
    let mut p = PathInput::new(&format!("{base}nope/x"), Some(c), tx);
    complete(&mut p, &mut wake).await;
    assert_eq!(p.value(), format!("{base}nope/x"));
    assert!(
        matches!(p.take_notice(), Some(Notice::Status(s)) if s.starts_with("Completion failed: ")),
    );
}

#[tokio::test]
async fn local_path_no_match_falls_through_to_next_field() {
    let d = tree();
    let base = format!("{}/", d.path().display());
    let (tx, mut wake) = mpsc::unbounded_channel();
    let form = Form::builder()
        .field(
            "path",
            "Path",
            FieldWidget::Path(PathInput::new(
                &format!("{base}zz"),
                Some(Arc::new(LocalPathCompleter)),
                tx,
            )),
        )
        .field("next", "Next", FieldWidget::Text(TextInput::new("")))
        .build();
    let mut dlg = FormDialog::new("Go", form, |_| Ok(()));
    assert!(matches!(dlg.handle_key(k("tab")), DialogStep::Continue));
    assert!(matches!(wake.recv().await, Some(Action::Wake)));
    dlg.poll(tokio::time::Instant::now());
    assert_eq!(dlg.take_notice(), None);
    assert_eq!(dlg.form().focused_id(), Some("next"));
}

struct Stalled;

impl PathCompleter for Stalled {
    fn complete(&self, _input: String) -> BoxFuture<'static, Result<Vec<Completion>, String>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn local_path_completion_times_out() {
    let (tx, mut wake) = mpsc::unbounded_channel();
    let mut p = PathInput::new("/x", Some(Arc::new(Stalled)), tx);
    assert_eq!(p.handle_key(k("tab")), WidgetOutcome::Consumed);
    assert_eq!(p.handle_key(k("tab")), WidgetOutcome::Consumed, "in flight");
    let start = tokio::time::Instant::now();
    assert!(matches!(wake.recv().await, Some(Action::Wake)));
    assert!(start.elapsed() >= Duration::from_secs(3));
    p.poll();
    assert_eq!(
        p.take_notice(),
        Some(Notice::Status("Completion failed: timed out".into()))
    );
    assert_eq!(p.value(), "/x");
}

#[test]
fn progress_show_after_and_cancel() {
    let mut h = harness();
    // Finished within 300 ms: never drawn.
    let token = CancellationToken::new();
    let t = token.clone();
    let handle = h.with_app(move |a| {
        let (d, handle) = progress("Deleting", "Deleting files…", t, ProgressOpts::default());
        a.modals.push(d);
        handle
    });
    h.advance(Duration::from_millis(100));
    assert!(!h.render(80, 24).contains("Deleting"));
    handle.finish();
    assert!(!h.render(80, 24).contains("Deleting"));
    h.advance(Duration::from_millis(400));
    assert!(h.app().modals.is_empty());
    // Drawn after 300 ms; Cancel cancels the token and shows Cancelling… until finish.
    let t = token.clone();
    let handle = h.with_app(move |a| {
        let (d, handle) = progress("Deleting", "Deleting files…", t, ProgressOpts::default());
        a.modals.push(d);
        handle
    });
    h.advance(Duration::from_millis(200));
    assert!(!h.render(80, 24).contains("Deleting files"));
    h.advance(Duration::from_millis(150));
    assert!(h.render(80, 24).contains("Deleting files"));
    h.keys("enter");
    assert!(token.is_cancelled());
    h.advance(Duration::from_millis(1000));
    let screen = h.render(80, 24);
    assert!(screen.contains("Cancelling…"), "{screen}");
    assert_eq!(h.app().modals.depth(), 1);
    handle.finish();
    h.advance(Duration::from_millis(300));
    assert!(h.app().modals.is_empty());
}

/// A component that blocks quitting.
struct Blocker;

impl Component for Blocker {
    fn quit_blocker(&self) -> Option<String> {
        Some("2 transfers are running".into())
    }

    fn draw(&mut self, _f: &mut Frame, _a: Rect, _cx: &DrawCx) -> color_eyre::Result<()> {
        Ok(())
    }
}

#[test]
fn quit_confirm_uses_standard_confirm() {
    let mut h = harness();
    h.app_mut()
        .main
        .set_component(Region::Queue, Box::new(Blocker));
    h.keys("f10");
    assert_eq!(h.app().modals.kinds(), [Some("confirm")]);
    let screen = h.render(80, 24);
    assert!(
        screen.contains("[ Quit ]") && screen.contains("[ Cancel ]"),
        "{screen}"
    );
    assert!(screen.contains("• 2 transfers are running"), "{screen}");
    // `q` (mnemonic) quits.
    h.keys("q");
    assert!(h.app().should_quit());
}

#[test]
fn quit_from_inside_a_dialog_closes_it() {
    let mut h = harness();
    let rx = h.app_mut().modals.push(name_form());
    h.keys("ctrl-q");
    assert!(h.app().should_quit());
    assert!(h.app().modals.is_empty());
    assert_eq!(h.runtime().block_on(rx).unwrap(), None);
}

#[test]
fn startup_problems_dialog_shown() {
    let mut h = AppHarness::temp(unicode_env(), |p: &AppPaths| {
        std::fs::write(
            p.config_dir.join("config.json"),
            r#"{"keybindings": {"FileList": {"ctrl-foo": "Delete"}}}"#,
        )
        .unwrap();
    });
    assert!(h.app().modals.is_empty());
    h.advance(Duration::from_millis(20));
    assert_eq!(h.app().modals.kinds(), [Some("problems")]);
    let screen = h.render(80, 24);
    assert!(screen.contains("1 configuration problem"), "{screen}");
    assert!(screen.contains("ctrl-foo"), "{screen}");
    h.keys("enter");
    assert!(h.app().modals.is_empty());
}
