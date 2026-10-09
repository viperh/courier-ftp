//! Saving settings and the live settings store (T05 AC4, AC5, AC6, AC8).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use courier_ftp_core::Error;
use courier_ftp_core::settings::{Column, ConnectTarget, Settings, SettingsStore};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn save_user_preserves_other_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("config.json");
    let keybindings = json!({"Normal": {"<Ctrl-q>": "Quit", "<F5>": "Copy"}});
    let styles = json!({"Normal": {"title": "bold red"}});
    let original = json!({
        "keybindings": keybindings,
        "styles": styles,
        "other": [1, 2, {"x": null}],
        "settings": {
            "future_key": {"a": 1},
            "ftp": {"future_ftp_key": true, "use_mlsd": false},
            "connection": {"timeout_secs": 99}
        }
    });
    fs::write(&file, serde_json::to_string(&original).unwrap()).unwrap();

    // Load what is in the file (with warnings for the unknown keys), change one value.
    let (mut s, warnings) = Settings::from_json_lenient(&original["settings"]);
    let mut paths: Vec<_> = warnings.iter().map(|w| w.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, vec!["ftp.future_ftp_key", "future_key"]);
    s.connection.timeout_secs = 20; // back to the default: must disappear from the file
    s.interface.connect_target = ConnectTarget::Replace;
    s.save_user(tmp.path()).unwrap();

    let saved = read_json(&file);
    assert_eq!(saved["keybindings"], keybindings);
    assert_eq!(saved["styles"], styles);
    assert_eq!(saved["other"], original["other"]);
    assert_eq!(
        saved["settings"],
        json!({
            "future_key": {"a": 1},
            "ftp": {"future_ftp_key": true, "use_mlsd": false},
            "interface": {"connect_target": "replace"}
        })
    );
    assert!(!tmp.path().join("config.json.tmp").exists());
    let text = fs::read_to_string(&file).unwrap();
    assert!(text.ends_with("}\n"));
    assert!(text.contains("\n  \"keybindings\""));

    // Reload gives equal settings.
    let (back, _) = Settings::from_json_lenient(&saved["settings"]);
    assert_eq!(back, s);
}

#[test]
fn save_user_drops_empty_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("config.json");
    fs::write(
        &file,
        r#"{"settings":{"ftp":{"use_mlsd":false}},"styles":{}}"#,
    )
    .unwrap();
    Settings::default().save_user(tmp.path()).unwrap();
    assert_eq!(read_json(&file), json!({"styles": {}}));
}

#[test]
fn save_user_refuses_invalid_json() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("config.json");
    let broken = "{ \"keybindings\": { oops ";
    fs::write(&file, broken).unwrap();
    let mut s = Settings::default();
    s.transfers.max_concurrent = 8;
    let err = s.save_user(tmp.path()).unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    assert!(err.to_string().contains("config.json is not valid JSON"));
    assert_eq!(fs::read_to_string(&file).unwrap(), broken);
}

#[test]
fn save_user_creates_file_and_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("a").join("config");
    let mut s = Settings::default();
    s.interface.sort.remote.column = Column::Modified;
    s.save_user(&dir).unwrap();
    assert_eq!(
        read_json(&dir.join("config.json")),
        json!({"settings": {"interface": {"sort": {"remote": {"column": "modified"}}}}})
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}

#[test]
fn save_user_io_error_names_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    // A file where the directory should be: creating the config dir fails.
    let blocker = tmp.path().join("blocker");
    fs::write(&blocker, "x").unwrap();
    let dir = blocker.join("config");
    let mut s = Settings::default();
    s.transfers.max_concurrent = 8;
    let err = s.save_user(&dir).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    assert!(err.to_string().contains("blocker"), "{err}");
}

#[tokio::test]
async fn settings_store_publishes_after_save() {
    let tmp = tempfile::tempdir().unwrap();
    let store = SettingsStore::new(Settings::default(), tmp.path().to_path_buf());
    let mut rx = store.subscribe();

    let warnings = store
        .update(|s| {
            s.transfers.max_concurrent = 8;
            s.connection.timeout_secs = 1; // invalid: reset with a warning
        })
        .unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].path, "connection.timeout_secs");
    assert!(rx.has_changed().unwrap());
    let seen = rx.borrow_and_update().clone();
    assert_eq!(seen.transfers.max_concurrent, 8);
    assert_eq!(seen.connection.timeout_secs, 20);
    assert_eq!(
        read_json(&tmp.path().join("config.json")),
        json!({"settings": {"transfers": {"max_concurrent": 8}}})
    );

    // Transient changes are published, not saved.
    store.set_transient(|s| s.transfers.speed_limit_enabled = true);
    assert!(rx.borrow_and_update().transfers.speed_limit_enabled);
    assert_eq!(
        read_json(&tmp.path().join("config.json")),
        json!({"settings": {"transfers": {"max_concurrent": 8}}})
    );

    // A failing save publishes nothing.
    let blocker = tmp.path().join("blocker");
    fs::write(&blocker, "x").unwrap();
    let bad = SettingsStore::new(Settings::default(), blocker.join("config"));
    let mut bad_rx = bad.subscribe();
    assert!(bad.update(|s| s.transfers.max_concurrent = 2).is_err());
    assert!(!bad_rx.has_changed().unwrap());
    assert_eq!(bad_rx.borrow_and_update().transfers.max_concurrent, 4);
    assert_eq!(bad.current().transfers.max_concurrent, 4);
}
