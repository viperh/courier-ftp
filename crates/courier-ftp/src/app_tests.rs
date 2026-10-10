//! Behaviour tests of the app shell through [`AppHarness`] (T50).

use std::{cell::RefCell, rc::Rc, time::Duration};

use courier_ftp_core::events::{
    CoreEvent, LogKind, MessagePrompt, NoticeLevel, PromptKind, SessionId,
};
use crossterm::event::KeyCode;
use pretty_assertions::assert_eq;
use ratatui::{Frame, layout::Rect, style::Color};

use crate::{
    action::Action,
    app::Mode,
    components::{Component, DrawCx, KeyOutcome, main_screen::layout::Region},
    keymap::chord::KeyChord,
    paths::AppPaths,
    runtime::TaskOwner,
    testing::{AppHarness, unicode_env},
    ui::symbols::TermEnv,
};

/// Shared counters of a test component.
#[derive(Debug, Default)]
struct Probe {
    keys: usize,
    updates: usize,
    core_events: usize,
    text: String,
}

/// A component that records what reaches it. `input` makes it a text field.
struct TestComponent {
    probe: Rc<RefCell<Probe>>,
    input: bool,
    blocker: Option<String>,
}

impl TestComponent {
    fn new(input: bool) -> (Self, Rc<RefCell<Probe>>) {
        let probe = Rc::new(RefCell::new(Probe::default()));
        (
            Self {
                probe: Rc::clone(&probe),
                input,
                blocker: None,
            },
            probe,
        )
    }
}

impl Component for TestComponent {
    fn key_mode(&self) -> Mode {
        if self.input {
            Mode::Input
        } else {
            Mode::FileList
        }
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        let mut p = self.probe.borrow_mut();
        p.keys += 1;
        if self.input
            && let Some(c) = key.printable()
        {
            p.text.push(c);
            return Ok(KeyOutcome::Consumed(None));
        }
        Ok(KeyOutcome::Ignored)
    }

    fn handle_paste(&mut self, text: &str) -> color_eyre::Result<KeyOutcome> {
        if !self.input {
            return Ok(KeyOutcome::Ignored);
        }
        self.probe.borrow_mut().text.push_str(text);
        Ok(KeyOutcome::Consumed(None))
    }

    fn update(&mut self, _action: &Action) -> color_eyre::Result<Option<Action>> {
        self.probe.borrow_mut().updates += 1;
        Ok(None)
    }

    fn on_core_event(&mut self, _event: &CoreEvent) -> color_eyre::Result<Option<Action>> {
        self.probe.borrow_mut().core_events += 1;
        Ok(None)
    }

    fn quit_blocker(&self) -> Option<String> {
        self.blocker.clone()
    }

    fn draw(&mut self, _frame: &mut Frame, _area: Rect, _cx: &DrawCx) -> color_eyre::Result<()> {
        Ok(())
    }
}

fn harness() -> AppHarness {
    AppHarness::temp(unicode_env(), |_| {})
}

/// A harness whose user `config.json` holds `json`.
fn harness_with(json: &'static str) -> AppHarness {
    AppHarness::temp(unicode_env(), move |p: &AppPaths| {
        if let Err(e) = std::fs::write(p.config_dir.join("config.json"), json) {
            panic!("write config: {e}");
        }
    })
}

fn trees_on() -> AppHarness {
    let mut h = harness_with(r#"{"settings": {"interface": {"show_tree": true}}}"#);
    h.render(160, 48);
    h
}

fn key(code: KeyCode) -> KeyChord {
    KeyChord::key(code)
}

fn status_text(h: &AppHarness) -> String {
    h.app()
        .main
        .status()
        .map(|m| m.text.clone())
        .unwrap_or_default()
}

#[test]
fn focus_tab_from_every_region() {
    let mut h = trees_on();
    for r in Region::FOCUSABLE {
        // Last focused list: RemoteList for half of the cases.
        h.action(Action::FocusRegion(Region::RemoteList));
        h.action(Action::FocusRegion(r));
        assert_eq!(h.focus(), r);
        h.key(key(KeyCode::Tab));
        let expected = if r.is_local() {
            Region::RemoteList
        } else if r.is_remote() {
            Region::LocalList
        } else {
            Region::RemoteList
        };
        assert_eq!(h.focus(), expected, "from {r:?}");
    }
    // Tab toggles back and forth.
    h.action(Action::FocusRegion(Region::LocalList));
    h.key(key(KeyCode::Tab)).key(key(KeyCode::Tab));
    assert_eq!(h.focus(), Region::LocalList);
}

#[test]
fn focus_shift_tab_cycles_visual_order() {
    let mut h = trees_on();
    h.action(Action::FocusRegion(Region::Quickconnect));
    let mut seen = vec![h.focus()];
    for _ in 0..7 {
        h.keys("backtab");
        seen.push(h.focus());
    }
    assert_eq!(
        seen,
        [
            Region::Quickconnect,
            Region::Log,
            Region::LocalTree,
            Region::LocalList,
            Region::RemoteTree,
            Region::RemoteList,
            Region::Queue,
            Region::Quickconnect,
        ]
    );
}

#[test]
fn focus_falls_back_when_region_hidden() {
    let mut h = harness();
    h.render(80, 24);
    h.action(Action::FocusLog);
    assert_eq!(h.focus(), Region::Log);
    h.keys("ctrl-l");
    assert_eq!(h.focus(), Region::LocalList);
    // The last focused list wins.
    h.keys("ctrl-l");
    h.action(Action::FocusRegion5).action(Action::FocusLog);
    assert_eq!(h.focus(), Region::Log);
    h.keys("ctrl-l");
    assert_eq!(h.focus(), Region::RemoteList);
    // Focusing the hidden log explains how to show it.
    h.action(Action::FocusLog);
    assert_eq!(h.focus(), Region::RemoteList);
    assert_eq!(status_text(&h), "Message log is hidden (Ctrl-l shows it)");
    // A resize into compact mode drops the tree focus.
    let mut h = trees_on();
    h.action(Action::FocusRegion(Region::RemoteTree));
    h.render(60, 16);
    assert_eq!(h.focus(), Region::LocalList);
}

#[test]
fn focus_region_n_targets() {
    let mut h = trees_on();
    for (a, r) in [
        (Action::FocusRegion1, Region::Quickconnect),
        (Action::FocusRegion2, Region::LocalTree),
        (Action::FocusRegion3, Region::LocalList),
        (Action::FocusRegion4, Region::RemoteTree),
        (Action::FocusRegion5, Region::RemoteList),
        (Action::FocusRegion6, Region::Log),
        (Action::FocusRegion7, Region::Queue),
    ] {
        h.action(a);
        assert_eq!(h.focus(), r);
    }
    let mut h = harness();
    h.render(160, 48);
    h.action(Action::FocusRegion2);
    assert_eq!(h.focus(), Region::LocalList);
    assert_eq!(
        status_text(&h),
        "Directory trees are hidden (Ctrl-e shows them)"
    );
    // Compact mode: hidden log and queue are shown when focused.
    h.keys("ctrl-l");
    h.render(60, 16);
    h.action(Action::FocusRegion6);
    assert_eq!(h.focus(), Region::Log);
    assert!(h.render(60, 16).contains("Message log"));
}

#[test]
fn modal_swallows_all_keys() {
    let mut h = harness();
    let (c, probe) = TestComponent::new(false);
    h.app_mut()
        .main
        .set_component(Region::LocalList, Box::new(c));
    h.keys("j");
    assert_eq!(probe.borrow().keys, 1);
    h.keys("f1");
    assert_eq!(h.app().modals.len(), 1);
    assert_eq!(h.mode(), Mode::Dialog);
    let keys_before = probe.borrow().keys;
    let updates_before = probe.borrow().updates;
    h.keys("j k x tab backtab ctrl-l enter G");
    assert_eq!(probe.borrow().keys, keys_before);
    assert_eq!(probe.borrow().updates, updates_before);
    assert_eq!(h.focus(), Region::LocalList);
    // Pastes stop at the modal too.
    h.paste("hello");
    h.keys("esc");
    assert!(h.app().modals.is_empty());
    assert_eq!(probe.borrow().keys, keys_before);
}

#[test]
fn input_mode_printables_to_widget_fkeys_to_global() {
    let mut h = harness();
    let (c, probe) = TestComponent::new(true);
    h.app_mut()
        .main
        .set_component(Region::Quickconnect, Box::new(c));
    h.action(Action::FocusRegion1);
    assert_eq!(h.mode(), Mode::Input);
    // `?` is Help in the Normal table, but the text field takes it.
    h.keys("a b ? G");
    assert_eq!(probe.borrow().text, "ab?G");
    assert!(h.app().modals.is_empty());
    h.paste("pasted");
    assert_eq!(probe.borrow().text, "ab?Gpasted");
    h.keys("f10");
    assert!(h.app().should_quit());
}

#[test]
fn quit_without_blockers_quits_immediately() {
    let mut h = harness();
    h.keys("ctrl-q");
    assert!(h.app().should_quit());
    assert!(h.app().modals.is_empty());
}

fn blocked() -> AppHarness {
    let mut h = harness();
    let (mut c, _) = TestComponent::new(false);
    c.blocker = Some("2 transfers are running".into());
    h.app_mut().main.set_component(Region::Queue, Box::new(c));
    h
}

#[test]
fn quit_with_blocker_default_cancel() {
    let mut h = blocked();
    h.keys("f10");
    assert!(!h.app().should_quit());
    assert_eq!(h.app().modals.len(), 1);
    let screen = h.render(80, 24);
    assert!(screen.contains("Quit courier-ftp?"), "{screen}");
    assert!(screen.contains("2 transfers are running"), "{screen}");
    h.key(key(KeyCode::Enter));
    assert!(!h.app().should_quit());
    assert!(h.app().modals.is_empty());
}

#[test]
fn quit_twice_confirms() {
    let mut h = blocked();
    h.keys("f10 f10");
    assert!(h.app().should_quit());
    let mut h = blocked();
    h.keys("ctrl-q ctrl-q");
    assert!(h.app().should_quit());
}

#[test]
fn quit_finishes_with_no_task_left() {
    let mut h = harness();
    for _ in 0..3 {
        h.with_app(|a| {
            a.runner.spawn(TaskOwner::Region(Region::LocalList), |_| {
                std::future::pending::<Action>()
            })
        });
    }
    h.keys("ctrl-l");
    h.keys("ctrl-q");
    assert!(h.app().should_quit());
    h.finish();
    assert_eq!(h.app().runner.len(), 0);
}

#[cfg(windows)]
#[test]
fn suspend_on_windows_shows_message() {
    let mut h = harness();
    h.keys("ctrl-z");
    assert_eq!(status_text(&h), "Suspend is not supported on Windows");
}

#[test]
fn prompt_without_dialog_is_dropped_and_logged() {
    let mut h = harness();
    let tx = h.app().events_sender().clone();
    let task = h.runtime().spawn(async move {
        tx.prompt(
            SessionId::APP,
            PromptKind::Message(MessagePrompt {
                level: NoticeLevel::Info,
                title: "t".into(),
                text: "x".into(),
            }),
        )
        .await
    });
    h.settle();
    let res = match h.runtime().block_on(task) {
        Ok(r) => r,
        Err(e) => panic!("join: {e}"),
    };
    assert!(res.is_err(), "the core sees a cancel");
}

#[test]
fn cancel_without_task_shows_hint() {
    let mut h = harness();
    h.keys("ctrl-c");
    assert_eq!(
        status_text(&h),
        "Nothing to cancel — press F10 or Ctrl-q to quit"
    );
    // With a task running for the focused region, Cancel cancels it.
    h.with_app(|a| {
        a.runner
            .spawn(TaskOwner::Region(Region::LocalList), |token| async move {
                token.cancelled().await;
                Action::StatusMessage("stopped".into())
            })
    });
    h.keys("ctrl-c");
    assert!(!h.app().runner.is_busy(TaskOwner::Region(Region::LocalList)));
    assert_eq!(status_text(&h), "stopped");
}

#[test]
fn spinner_animates_during_slow_task() {
    let mut h = harness();
    h.with_app(|a| {
        a.runner
            .spawn(TaskOwner::Region(Region::LocalList), |_| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Action::StatusMessage("done".into())
            })
    });
    let mut screens = Vec::new();
    let mut draws = Vec::new();
    for t in [200, 300, 400] {
        let at = Duration::from_millis(t);
        let now = h
            .app()
            .runner
            .busy_since(TaskOwner::Region(Region::LocalList));
        assert!(now.is_some());
        h.advance(at.saturating_sub(Duration::from_millis(if t == 200 { 0 } else { t - 100 })));
        screens.push(h.render(80, 24));
        draws.push(h.draw_count());
    }
    // The title row of the local list (row 6 at 80×24) differs every 100 ms.
    let title = |s: &str| s.lines().nth(6).unwrap_or_default().to_owned();
    assert_ne!(title(&screens[0]), title(&screens[1]));
    assert_ne!(title(&screens[1]), title(&screens[2]));
    assert!(draws[1] > draws[0] && draws[2] > draws[1], "{draws:?}");
    // Keys still work during the wait.
    h.advance(Duration::from_millis(600));
    h.key(key(KeyCode::Tab));
    assert_eq!(h.focus(), Region::RemoteList);
    assert!(h.app().runner.is_busy(TaskOwner::Region(Region::LocalList)));
    h.advance(Duration::from_secs(5));
    assert!(!h.app().runner.is_busy(TaskOwner::Region(Region::LocalList)));
    assert_eq!(status_text(&h), "done");
}

#[test]
fn idle_app_does_not_redraw() {
    let mut h = harness();
    h.advance(Duration::from_millis(50));
    assert_eq!(h.draw_count(), 1);
    h.advance(Duration::from_secs(10));
    assert_eq!(h.draw_count(), 1);
    // A key redraws once.
    h.keys("tab");
    h.advance(Duration::from_millis(50));
    assert_eq!(h.draw_count(), 2);
}

#[test]
fn toggle_log_persists_after_debounce() {
    let mut h = harness();
    let Some(paths) = h.paths() else {
        panic!("temp harness has paths");
    };
    let file = paths.config_dir.join("config.json");
    h.keys("ctrl-l");
    h.advance(Duration::from_millis(500));
    assert!(!file.exists(), "saved before the debounce");
    h.advance(Duration::from_millis(600));
    // The save runs on a blocking thread; wait for it in real time.
    for _ in 0..500 {
        if std::fs::read_to_string(&file).is_ok_and(|s| s.contains("\"show_log\": false")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    assert!(text.contains("\"show_log\": false"), "{text}");
    let config = match crate::config::Config::new(&paths) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    assert!(!config.settings.interface.show_log);
}

#[test]
fn core_events_reach_components_without_blocking_render() {
    let mut h = harness();
    let (c, probe) = TestComponent::new(false);
    h.app_mut().main.set_component(Region::Log, Box::new(c));
    h.advance(Duration::from_millis(20));
    let draws = h.draw_count();
    let tx = h.app().events_sender().clone();
    for i in 0..10_000 {
        tx.log(SessionId::APP, LogKind::Status, format!("line {i}"));
    }
    h.advance(Duration::from_millis(17));
    assert_eq!(probe.borrow().core_events, 10_000);
    assert_eq!(h.draw_count(), draws + 1, "one render for the whole drain");
}

#[test]
fn help_overlay_lists_effective_bindings() {
    let mut h = harness_with(
        r#"{"keybindings": {"FileList": {"x": "ToggleLog"}, "Normal": {"ctrl-h": "Help", "f1": "Redraw"}}}"#,
    );
    let config = {
        let Some(p) = h.paths() else { panic!() };
        match crate::config::Config::new(&p) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        }
    };
    let (resolver, _) = crate::keymap::resolver::KeyResolver::from_config(&config);
    let expected = resolver.keymap().bindings_for(Mode::FileList.chain());
    h.keys("ctrl-h");
    assert_eq!(h.app().modals.len(), 1);
    let screen = h.render(160, 48);
    // Grouped by the registry's groups, with descriptions.
    assert!(
        screen.contains("General") && screen.contains("Focus"),
        "{screen}"
    );
    assert!(screen.contains("Clear and redraw the screen"), "{screen}");
    assert!(screen.contains("?, ctrl-h"), "{screen}");
    // The user's f1 override replaced the default: f1 is Redraw, listed once.
    assert!(screen.contains("f1, g r "), "{screen}");
    assert_eq!(screen.matches("f1,").count(), 1, "{screen}");
    // FileList's own table comes first in the chain's bindings.
    assert_eq!(expected.first().map(|r| r.mode), Some(Mode::FileList));
    assert!(
        expected
            .iter()
            .any(|r| r.mode == Mode::Normal && r.keys_text() == "ctrl-l")
    );
    h.keys("/ T o g g l e L o g enter");
    let filtered = h.render(80, 24);
    assert!(
        filtered.contains("x, ctrl-l")
            && filtered.contains("ToggleLog")
            && !filtered.contains("Redraw"),
        "{filtered}"
    );
    h.keys("q");
    assert!(h.app().modals.is_empty());
}

#[test]
fn no_color_buffer_has_no_colours() {
    let env = TermEnv {
        no_color: true,
        ..unicode_env()
    };
    let mut h = AppHarness::temp(env, |_| {});
    h.action(Action::StatusMessage("an \x1b message".into()));
    for (w, ht) in [(80, 24), (160, 48), (60, 16)] {
        let buf = h.buffer(w, ht);
        for cell in buf.content() {
            assert_eq!(cell.fg, Color::Reset, "{cell:?}");
            assert_eq!(cell.bg, Color::Reset, "{cell:?}");
        }
    }
    // Focus is still visible: thick border and the marker.
    let screen = h.render(80, 24);
    assert!(screen.contains("┏▶Local"), "{screen}");
    h.keys("f1");
    let buf = h.buffer(80, 24);
    assert!(
        buf.content()
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
    );
}

#[test]
fn too_small_still_quits() {
    let mut h = harness();
    let screen = h.render(30, 8);
    let flat = screen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("Terminal too small: 30×8 (need 40×10)"),
        "{screen}"
    );
    h.keys("ctrl-q");
    assert!(h.app().should_quit());
}

#[test]
fn config_problems_are_reported_after_the_first_frame() {
    let mut h = harness_with(
        r#"{"keybindings": {"Normal": {"nokey": "Quit", "x": "Explode"}}, "styles": {"bogus": "red"}}"#,
    );
    assert!(status_text(&h).is_empty());
    h.advance(Duration::from_millis(20));
    assert_eq!(status_text(&h), "3 configuration problems — see the log");
}

#[test]
fn layout_toggles_change_the_screen() {
    let mut h = harness();
    let classic = h.render(160, 48);
    h.action(Action::LayoutExplorer);
    assert_ne!(classic, h.render(160, 48));
    h.action(Action::SwapPanes)
        .action(Action::ToggleQueuePane)
        .action(Action::ToggleQuickconnect)
        .action(Action::LayoutWidescreen);
    let i = h.app().main.options();
    assert!(i.swap_panes && !i.show_queue && !i.show_quickconnect);
    h.action(Action::LayoutClassic);
    assert_eq!(
        h.app().main.options().layout,
        courier_ftp_core::settings::Layout::Classic
    );
}

#[test]
fn template_leftovers_removed() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needles = [
        ["last_tick", "_key_events"].concat(),
        ["info!(\"Got", " action"].concat(),
        ["struct ", "Home"].concat(),
        ["home::", "Home"].concat(),
        ["Home", "::new"].concat(),
    ];
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                for n in &needles {
                    assert!(!text.contains(n.as_str()), "{} contains {n}", p.display());
                }
            }
        }
    }
    assert!(!src.join("components").join("home.rs").exists());
}
