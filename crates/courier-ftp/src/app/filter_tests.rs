//! T67: filters chosen in the dialog are saved to the user's `config.json`
//! (T05 `save_user`, minimal diff) and load back the same.

use std::sync::Arc;

use courier_ftp_core::{backend::MockServer, filters::FilterSettings, settings::Settings};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;

use super::*;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Dispatch everything queued (the dialog sends its result right away).
fn drain(app: &mut App) {
    while let Ok(action) = app.action_rx.try_recv() {
        app.dispatch(action).unwrap();
    }
}

/// An app whose settings come from `config_dir/config.json`, as at startup.
fn app_in(config_dir: &std::path::Path) -> App {
    let mut config = Config::builtin();
    config.config.config_dir = config_dir.to_path_buf();
    let text = std::fs::read_to_string(config_dir.join("config.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    config.settings = Settings::from_value(&doc["settings"]).0;
    App::with_backends(config, Arc::new(MockServer::new()), 4.0, 60.0)
}

fn saved(config_dir: &std::path::Path) -> (serde_json::Value, FilterSettings) {
    let text = std::fs::read_to_string(config_dir.join("config.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let (settings, report) = Settings::from_value(&doc["settings"]);
    assert!(report.warnings.is_empty(), "{report:?}");
    (doc, settings.filters)
}

#[tokio::test]
async fn filters_round_trip_through_the_config_file() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    // Keys and unknown entries of an existing file are kept.
    std::fs::write(
        config_dir.join("config.json"),
        r#"{"keybindings": {}, "settings": {"interface": {"show_log": false}}}"#,
    )
    .unwrap();
    let mut app = app_in(&config_dir);

    // <Ctrl-x><f> opens the dialog; Git locally; then a new filter.
    app.handle_key_event(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL))
        .unwrap();
    app.handle_key_event(key(KeyCode::Char('f'))).unwrap();
    drain(&mut app);
    assert_eq!(app.screen.mode(), Mode::Dialog);
    for k in [KeyCode::Down, KeyCode::Char(' ')] {
        app.handle_key_event(key(k)).unwrap();
    }
    // Edit filter rules… (third button): new filter "Build output" with
    // `Path contains /target/`, remote only.
    for k in [
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::Right,
        KeyCode::Right,
        KeyCode::Enter,
        KeyCode::Char('n'),
    ] {
        app.handle_key_event(key(k)).unwrap();
    }
    app.handle_key_event(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
        .unwrap();
    app.screen.handle_paste("Build output");
    // Use on → Remote only (4 down from the name: applies to, match, case,
    // use on).
    for k in [
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::End,
        KeyCode::Right,
        KeyCode::Right,
        // Condition 1: type → Path.
        KeyCode::Down,
        KeyCode::Right,
        KeyCode::Tab,
        KeyCode::Tab,
    ] {
        app.handle_key_event(key(k)).unwrap();
    }
    app.screen.handle_paste("/target/");
    // OK in the editor, then the new filter (last row) on the remote side,
    // then OK.
    app.handle_key_event(key(KeyCode::Enter)).unwrap();
    for k in [
        KeyCode::BackTab,
        KeyCode::BackTab,
        KeyCode::BackTab,
        KeyCode::End,
        KeyCode::Right,
        KeyCode::Char(' '),
        KeyCode::Enter,
    ] {
        app.handle_key_event(key(k)).unwrap();
    }
    drain(&mut app);
    assert_eq!(app.screen.mode(), Mode::FileList, "the dialog closed");

    let (doc, filters) = saved(&config_dir);
    assert_eq!(doc["keybindings"], serde_json::json!({}));
    assert_eq!(doc["settings"]["interface"]["show_log"], false);
    assert_eq!(filters, app.settings.filters);
    let set = filters.active().unwrap();
    assert_eq!(set.enabled_local, ["Git"]);
    assert_eq!(set.enabled_remote, ["Build output"]);
    let build = filters.get("Build output").unwrap();
    assert_eq!(
        build.scope,
        courier_ftp_core::filters::FilterScope::RemoteOnly
    );
    assert_eq!(
        build.conditions,
        [courier_ftp_core::filters::Condition::Path {
            op: courier_ftp_core::filters::StringOp::Contains,
            value: "/target/".into()
        }]
    );

    // A fresh app over the same directory shows the same filters; turning
    // everything back off leaves only the new filter's definition.
    let mut app = app_in(&config_dir);
    assert_eq!(app.settings.filters, filters);
    app.dispatch(Action::Filters).unwrap();
    for k in [KeyCode::Down, KeyCode::Char(' ')] {
        app.handle_key_event(key(k)).unwrap();
    }
    for k in [
        KeyCode::End,
        KeyCode::Right,
        KeyCode::Char(' '),
        KeyCode::Enter,
    ] {
        app.handle_key_event(key(k)).unwrap();
    }
    drain(&mut app);
    let (doc, filters) = saved(&config_dir);
    let set = filters.active().unwrap();
    assert!(set.enabled_local.is_empty() && set.enabled_remote.is_empty());
    assert!(doc["settings"]["filters"].get("sets").is_none(), "{doc:#}");
    assert!(doc["settings"]["filters"].get("filters").is_some());
}
