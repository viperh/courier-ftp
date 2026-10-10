//! Key sequences through the whole app ([`AppHarness`], paused clock), and the
//! keymap snapshots (T51).

use std::{cell::RefCell, rc::Rc, time::Duration};

use insta::assert_snapshot;
use pretty_assertions::assert_eq;
use ratatui::{Frame, layout::Rect};

use crate::{
    action::Action,
    app::Mode,
    components::{Component, DrawCx, KeyOutcome, main_screen::layout::Region},
    keymap::chord::KeyChord,
    paths::AppPaths,
    testing::{AppHarness, unicode_env},
};

/// A file list that records the actions it handles.
struct Recorder {
    seen: Rc<RefCell<Vec<String>>>,
    text_field: bool,
}

static HANDLED: &[Action] = &[
    Action::Top,
    Action::Bottom,
    Action::CursorDown,
    Action::CursorUp,
];

impl Component for Recorder {
    fn key_mode(&self) -> Mode {
        if self.text_field {
            Mode::Input
        } else {
            Mode::FileList
        }
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        if self.text_field
            && let Some(c) = key.printable()
        {
            self.seen.borrow_mut().push(format!("text:{c}"));
            return Ok(KeyOutcome::Consumed(None));
        }
        Ok(KeyOutcome::Ignored)
    }

    fn handled_actions(&self) -> &'static [Action] {
        HANDLED
    }

    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        if action.is_bindable() {
            self.seen.borrow_mut().push(action.to_string());
        }
        Ok(None)
    }

    fn draw(&mut self, _frame: &mut Frame, _area: Rect, _cx: &DrawCx) -> color_eyre::Result<()> {
        Ok(())
    }
}

fn harness_with(json: &'static str) -> AppHarness {
    AppHarness::temp(unicode_env(), move |p: &AppPaths| {
        if let Err(e) = std::fs::write(p.config_dir.join("config.json"), json) {
            panic!("write config: {e}");
        }
    })
}

/// A harness whose local list records actions.
fn recording(json: &'static str) -> (AppHarness, Rc<RefCell<Vec<String>>>) {
    let mut h = harness_with(json);
    let seen = Rc::new(RefCell::new(Vec::new()));
    h.app_mut().main.set_component(
        Region::LocalList,
        Box::new(Recorder {
            seen: Rc::clone(&seen),
            text_field: false,
        }),
    );
    (h, seen)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn status_text(h: &AppHarness) -> String {
    h.app()
        .main
        .status()
        .map(|m| m.text.clone())
        .unwrap_or_default()
}

#[test]
fn sequence_fires_within_timeout() {
    let (mut h, seen) = recording("{}");
    h.keys("g");
    assert_eq!(h.pending().as_deref(), Some("g"));
    h.advance(ms(999));
    assert_eq!(h.pending().as_deref(), Some("g"));
    h.keys("g");
    assert_eq!(*seen.borrow(), ["Top"]);
    assert!(h.pending().is_none());
}

#[test]
fn sequence_expires_at_timeout() {
    let (mut h, seen) = recording("{}");
    h.keys("g");
    h.advance(ms(1000));
    assert!(h.pending().is_none());
    assert!(seen.borrow().is_empty());
    // The second g starts a new sequence.
    h.keys("g");
    assert_eq!(h.pending().as_deref(), Some("g"));
    assert!(seen.borrow().is_empty());
    h.keys("g");
    assert_eq!(*seen.borrow(), ["Top"]);
}

#[test]
fn custom_timeout_3000ms() {
    let (mut h, seen) =
        recording(r#"{"settings": {"interface": {"key_sequence_timeout_ms": 3000}}}"#);
    h.keys("g");
    h.advance(ms(2500));
    h.keys("g");
    assert_eq!(*seen.borrow(), ["Top"]);
    h.keys("g");
    h.advance(ms(3000));
    assert!(h.pending().is_none());
}

#[test]
fn esc_cancels_pending() {
    let (mut h, seen) = recording("{}");
    h.keys("ctrl-x");
    assert_eq!(h.pending().as_deref(), Some("ctrl-x"));
    h.keys("esc");
    assert!(h.pending().is_none());
    // Esc was consumed by the cancel: FileList's `Escape` did not run.
    assert!(seen.borrow().is_empty());
    assert!(status_text(&h).is_empty(), "{}", status_text(&h));
}

#[test]
fn focus_change_clears_pending() {
    let (mut h, _) = recording("{}");
    h.keys("g");
    assert_eq!(h.pending().as_deref(), Some("g"));
    h.action(Action::FocusRegion(Region::Log));
    assert_eq!(h.mode(), Mode::Log);
    assert!(h.pending().is_none());
}

#[test]
fn unbound_continuation_reresolves_key() {
    let (mut h, seen) = recording("{}");
    h.keys("g j");
    assert_eq!(*seen.borrow(), ["CursorDown"]);
    assert!(h.pending().is_none());
}

#[test]
fn keys_in_text_field_never_reach_resolver() {
    let mut h = harness_with("{}");
    let seen = Rc::new(RefCell::new(Vec::new()));
    h.app_mut().main.set_component(
        Region::Quickconnect,
        Box::new(Recorder {
            seen: Rc::clone(&seen),
            text_field: true,
        }),
    );
    h.action(Action::FocusRegion1);
    assert_eq!(h.mode(), Mode::Input);
    h.keys("g g");
    assert_eq!(*seen.borrow(), ["text:g", "text:g"]);
    assert!(h.pending().is_none());
}

#[test]
fn unimplemented_action_shows_not_available() {
    let (mut h, seen) = recording("{}");
    h.keys("ctrl-x d");
    assert_eq!(
        status_text(&h),
        "Disconnect the current tab is not available yet"
    );
    h.keys("s n");
    assert_eq!(
        status_text(&h),
        "Sort by name (again = reverse) is not available yet"
    );
    assert!(seen.borrow().is_empty());
    // A handled action reaches the component instead.
    h.keys("G");
    assert_eq!(*seen.borrow(), ["Bottom"]);
}

#[test]
fn bad_user_config_starts_app() {
    let (mut h, seen) = recording(
        r#"{"keybindings": {
            "FileList": {"ctrl-foo": "Top", "x": "Remove", "g g g g g": "Top", "q": "Top"},
            "Nowhere": {"a": "Quit"},
            "Normal": {"G": "Help", "shift-g": "Quit"}
        }}"#,
    );
    h.advance(ms(20));
    assert_eq!(status_text(&h), "5 configuration problems — see the log");
    // The problems dialog (T52) is open; close it first.
    assert_eq!(h.app().modals.kinds(), [Some("problems")]);
    h.keys("esc");
    h.keys("q");
    assert_eq!(*seen.borrow(), ["Top"]);
}

#[test]
fn focus_region_keys_in_harness() {
    let mut h = harness_with("{}");
    h.render(160, 48);
    h.keys("ctrl-x 6");
    assert_eq!(h.focus(), Region::Log);
    h.keys("ctrl-x 3");
    assert_eq!(h.focus(), Region::LocalList);
    h.keys("ctrl-x 7");
    assert_eq!(h.focus(), Region::Queue);
    h.keys("g f");
    assert_eq!(h.focus(), Region::LocalList);
}

#[test]
fn which_key_appears_after_500ms() {
    let mut h = harness_with("{}");
    h.keys("ctrl-x");
    h.advance(ms(499));
    assert!(!h.render(80, 24).contains("Disconnect"));
    h.advance(ms(1));
    let screen = h.render(80, 24);
    assert!(screen.contains("Disconnect"), "{screen}");
    assert!(screen.contains("more (F1)"), "{screen}");
    h.keys("j");
    assert!(!h.render(80, 24).contains("Disconnect"));
    assert!(!h.app().main.options().show_queue);
}

#[test]
fn snap_which_key_ctrl_x_80x24() {
    let mut h = harness_with("{}");
    h.keys("ctrl-x");
    h.advance(ms(600));
    assert_snapshot!("snap_which_key_ctrl_x_80x24", h.render(80, 24));
}

#[test]
fn snap_which_key_ctrl_x_160x48() {
    let mut h = harness_with("{}");
    h.keys("ctrl-x");
    h.advance(ms(600));
    assert_snapshot!("snap_which_key_ctrl_x_160x48", h.render(160, 48));
}

#[test]
fn snap_pending_keys_status_80x24() {
    let mut h = harness_with("{}");
    h.keys("g");
    assert_snapshot!("snap_pending_keys_status_80x24", h.render(80, 24));
}

#[test]
fn snap_keymap_problems_status_80x24() {
    let mut h =
        harness_with(r#"{"keybindings": {"FileList": {"ctrl-foo": "Top", "x": "Remove"}}}"#);
    h.advance(ms(20));
    assert_snapshot!("snap_keymap_problems_status_80x24", h.render(80, 24));
}
