//! Snapshot tests of the shell at 80×24 and 160×48 (D15), plus compact and too-small
//! sizes. Snapshots live in `src/snapshots/`.

use courier_ftp_core::{events::CoreEvent, settings::Layout};
use insta::assert_snapshot;

use crate::{
    action::Action,
    components::main_screen::layout::Region,
    config::Config,
    testing::{AppHarness, unicode_env},
    ui::symbols::{TermEnv, UnicodeSymbols},
};

fn harness(edit: impl FnOnce(&mut Config)) -> AppHarness {
    let mut c = Config::default();
    edit(&mut c);
    AppHarness::new(c)
}

#[test]
fn snap_classic_80x24() {
    let mut h = harness(|_| {});
    assert_snapshot!("snap_classic_80x24", h.render(80, 24));
}

#[test]
fn snap_classic_160x48() {
    let mut h = harness(|_| {});
    assert_snapshot!("snap_classic_160x48", h.render(160, 48));
}

#[test]
fn snap_classic_tree_160x48() {
    let mut h = harness(|c| c.settings.interface.show_tree = true);
    assert_snapshot!("snap_classic_tree_160x48", h.render(160, 48));
}

#[test]
fn snap_classic_no_log_no_queue_80x24() {
    let mut h = harness(|c| {
        c.settings.interface.show_log = false;
        c.settings.interface.show_queue = false;
    });
    assert_snapshot!("snap_classic_no_log_no_queue_80x24", h.render(80, 24));
}

#[test]
fn snap_classic_swapped_160x48() {
    let mut h = harness(|c| c.settings.interface.swap_panes = true);
    assert_snapshot!("snap_classic_swapped_160x48", h.render(160, 48));
}

#[test]
fn snap_explorer_80x24() {
    let mut h = harness(|c| c.settings.interface.layout = Layout::Explorer);
    assert_snapshot!("snap_explorer_80x24", h.render(80, 24));
}

#[test]
fn snap_explorer_tree_160x48() {
    let mut h = harness(|c| {
        c.settings.interface.layout = Layout::Explorer;
        c.settings.interface.show_tree = true;
        c.settings.interface.show_log = false;
        c.settings.interface.show_queue = false;
        c.settings.interface.show_quickconnect = false;
    });
    assert_snapshot!("snap_explorer_tree_160x48", h.render(160, 48));
}

#[test]
fn snap_widescreen_160x48() {
    let mut h = harness(|c| c.settings.interface.layout = Layout::Widescreen);
    assert_snapshot!("snap_widescreen_160x48", h.render(160, 48));
}

#[test]
fn snap_widescreen_80x24_falls_back() {
    let mut h = harness(|c| c.settings.interface.layout = Layout::Widescreen);
    let classic = harness(|_| {}).render(80, 24);
    let screen = h.render(80, 24);
    assert_eq!(screen, classic);
    assert_snapshot!("snap_widescreen_80x24_falls_back", screen);
}

#[test]
fn snap_compact_60x16_remote_focused() {
    let mut h = harness(|_| {});
    h.render(60, 16);
    h.keys("tab");
    assert_eq!(h.focus(), Region::RemoteList);
    let screen = h.render(60, 16);
    assert!(screen.contains("compact"));
    assert_snapshot!("snap_compact_60x16_remote_focused", screen);
}

#[test]
fn snap_compact_60x16_log_focused() {
    let mut h = harness(|_| {});
    h.render(60, 16);
    h.action(Action::FocusLog);
    // Core events reach the components without changing the layout.
    h.core_event(CoreEvent::QueueChanged);
    assert_eq!(h.focus(), Region::Log);
    assert_snapshot!("snap_compact_60x16_log_focused", h.render(60, 16));
}

#[test]
fn snap_too_small_30x8() {
    let mut h = harness(|_| {});
    assert_snapshot!("snap_too_small_30x8", h.render(30, 8));
}

#[test]
fn snap_help_filelist_80x24() {
    let mut h = harness(|_| {});
    h.keys("f1");
    assert_snapshot!("snap_help_filelist_80x24", h.render(80, 24));
}

#[test]
fn snap_help_filelist_160x48() {
    let mut h = harness(|_| {});
    h.keys("?");
    assert_snapshot!("snap_help_filelist_160x48", h.render(160, 48));
}

#[test]
fn snap_ascii_symbols_classic_80x24() {
    let mut c = Config::default();
    c.settings.interface.unicode_symbols = UnicodeSymbols::Never;
    let mut h = AppHarness::with_env(c, unicode_env());
    let screen = h.render(80, 24);
    assert!(screen.is_ascii(), "{screen}");
    assert_snapshot!("snap_ascii_symbols_classic_80x24", screen);
    // `auto` in a non-UTF-8 terminal picks the same set.
    let env = TermEnv {
        term: Some("linux".into()),
        ..TermEnv::default()
    };
    let mut h = AppHarness::with_env(Config::default(), env);
    assert_eq!(h.render(80, 24), screen);
}

#[test]
fn snap_status_message_sanitised_80x24() {
    let mut h = harness(|_| {});
    h.action(Action::StatusMessage(
        "evil \x1b[2J name\u{202e}txt.exe".into(),
    ));
    let screen = h.render(80, 24);
    assert!(
        screen.contains("evil ^[[2J name<U+202E>txt.exe"),
        "{screen}"
    );
    assert_snapshot!("snap_status_message_sanitised_80x24", screen);
}
