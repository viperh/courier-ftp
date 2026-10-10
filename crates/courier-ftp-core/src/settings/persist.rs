//! Lenient loading and minimal saving of [`Settings`].

use std::path::Path;

use serde_json::{Map, Value};

use super::Settings;
use crate::{Error, Result};

/// What [`Settings::from_value`] had to fix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// One line per field that was ignored or reset, e.g.
    /// `connection.timeout_secs: expected an integer; using the default`.
    pub warnings: Vec<String>,
}

impl Settings {
    /// Build settings from untrusted JSON (the `settings` key of the merged
    /// config). Never fails: fields with the wrong type, unknown enum values and
    /// out-of-range values are replaced by their defaults and listed in the
    /// report. Unknown keys are ignored silently (they may belong to a newer
    /// version).
    pub fn from_value(user: &Value) -> (Settings, LoadReport) {
        let mut report = LoadReport::default();
        let defaults = defaults_value();
        let mut accepted = Value::Object(Map::new());
        if !user.is_null() {
            accept(&defaults, &mut accepted, user, &mut Vec::new(), &mut report);
        }
        let mut settings: Settings =
            serde_json::from_value(merge(defaults, &accepted)).unwrap_or_default();
        report.warnings.extend(settings.validate());
        (settings, report)
    }

    /// Write the settings that differ from the defaults into `config.json` in
    /// `config_dir`, under the `settings` key. Everything else in the file
    /// (keybindings, styles, unknown keys) is kept. Creates the directory and the
    /// file when missing.
    pub fn save_user(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("config.json");
        let mut doc = match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => serde_json::from_str::<Value>(&text)
                .map_err(|e| Error::InvalidInput(format!("{}: {e}", path.display())))?,
            Ok(_) => Value::Object(Map::new()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Object(Map::new()),
            Err(e) => return Err(e.into()),
        };
        let Value::Object(obj) = &mut doc else {
            return Err(Error::InvalidInput(format!(
                "{}: the top level is not an object",
                path.display()
            )));
        };
        let current = serde_json::to_value(self)
            .map_err(|e| Error::InvalidInput(format!("settings: {e}")))?;
        match diff(&defaults_value(), &current) {
            Some(changed) => {
                obj.insert("settings".to_owned(), changed);
            }
            None => {
                obj.remove("settings");
            }
        }
        std::fs::create_dir_all(config_dir)?;
        let mut text = serde_json::to_string_pretty(&doc)
            .map_err(|e| Error::InvalidInput(format!("settings: {e}")))?;
        text.push('\n');
        // Write to a temporary file and rename, so a crash never leaves a
        // half-written config behind.
        let tmp = config_dir.join(".config.json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn defaults_value() -> Value {
    serde_json::to_value(Settings::default()).unwrap_or(Value::Null)
}

/// Accept as much of `user` as deserialises cleanly into [`Settings`].
///
/// Tries the whole value at `path` first; if that breaks deserialisation and
/// the value is an object whose default is also an object, recurses into its
/// keys. Leaves that still fail are reported and left at their defaults.
fn accept(
    defaults: &Value,
    accepted: &mut Value,
    user: &Value,
    path: &mut Vec<String>,
    report: &mut LoadReport,
) {
    let mut candidate = accepted.clone();
    set_at(&mut candidate, path, user.clone());
    let merged = merge(defaults.clone(), &candidate);
    let error = match serde_json::from_value::<Settings>(merged) {
        Ok(_) => {
            *accepted = candidate;
            return;
        }
        Err(e) => e,
    };
    let default_here = get_at(defaults, path);
    match (user, default_here) {
        (Value::Object(map), Some(Value::Object(_))) => {
            for (key, value) in map {
                path.push(key.clone());
                accept(defaults, accepted, value, path, report);
                path.pop();
            }
        }
        _ => report.warnings.push(format!(
            "{}: {}; using the default",
            display_path(path),
            short_error(&error)
        )),
    }
}

fn display_path(path: &[String]) -> String {
    if path.is_empty() {
        "settings".to_owned()
    } else {
        path.join(".")
    }
}

/// serde_json errors end with " at line 1 column 2"; that position means nothing
/// for a value built in memory.
fn short_error(e: &serde_json::Error) -> String {
    let s = e.to_string();
    match s.find(" at line ") {
        Some(i) => s[..i].to_owned(),
        None => s,
    }
}

fn get_at<'a>(v: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(v, |v, k| v.get(k))
}

fn set_at(v: &mut Value, path: &[String], new: Value) {
    let Some((last, parents)) = path.split_last() else {
        *v = new;
        return;
    };
    let mut cur = v;
    for key in parents {
        if !cur.is_object() {
            *cur = Value::Object(Map::new());
        }
        let Value::Object(map) = cur else { return };
        cur = map
            .entry(key.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if !cur.is_object() {
        *cur = Value::Object(Map::new());
    }
    if let Value::Object(map) = cur {
        map.insert(last.clone(), new);
    }
}

/// Deep-merge `over` into `base`: objects merge key by key, anything else in
/// `over` replaces.
fn merge(mut base: Value, over: &Value) -> Value {
    match (&mut base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                let merged = match b.remove(k) {
                    Some(existing) => merge(existing, v),
                    None => v.clone(),
                };
                b.insert(k.clone(), merged);
            }
            base
        }
        _ => over.clone(),
    }
}

/// The parts of `current` that differ from `defaults` (objects compared key by
/// key, anything else as a whole), or `None` when nothing differs.
fn diff(defaults: &Value, current: &Value) -> Option<Value> {
    match (defaults, current) {
        (Value::Object(d), Value::Object(c)) => {
            let mut out = Map::new();
            for (k, cv) in c {
                match d.get(k) {
                    Some(dv) => {
                        if let Some(changed) = diff(dv, cv) {
                            out.insert(k.clone(), changed);
                        }
                    }
                    None => {
                        out.insert(k.clone(), cv.clone());
                    }
                }
            }
            (!out.is_empty()).then_some(Value::Object(out))
        }
        _ if defaults == current => None,
        _ => Some(current.clone()),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;
    use crate::settings::{ExistsAction, SizeFormat};

    #[test]
    fn null_and_empty_are_default() {
        for v in [Value::Null, json!({})] {
            let (s, report) = Settings::from_value(&v);
            assert_eq!(s, Settings::default());
            assert!(report.warnings.is_empty(), "{report:?}");
        }
    }

    #[test]
    fn partial_overrides_only_named_fields() {
        let (s, report) = Settings::from_value(&json!({
            "interface": {"size_format": "si"},
            "transfers": {"on_exists_download": "overwrite_if_newer"}
        }));
        assert!(report.warnings.is_empty(), "{report:?}");
        let mut expected = Settings::default();
        expected.interface.size_format = SizeFormat::Si;
        expected.transfers.on_exists_download = ExistsAction::OverwriteIfNewer;
        assert_eq!(s, expected);
    }

    #[test]
    fn bad_types_fall_back_per_field() {
        let (s, report) = Settings::from_value(&json!({
            "connection": {"timeout_secs": "soon", "retries": 7},
            "interface": {"layout": "sideways", "dirs_first": false},
            "logging": 12
        }));
        let mut expected = Settings::default();
        expected.connection.retries = 7;
        expected.interface.dirs_first = false;
        assert_eq!(s, expected);
        assert_eq!(report.warnings.len(), 3, "{report:?}");
        assert!(
            report.warnings[0].starts_with("connection.timeout_secs:"),
            "{report:?}"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.starts_with("interface.layout:"))
        );
        assert!(report.warnings.iter().any(|w| w.starts_with("logging:")));
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let (s, report) = Settings::from_value(&json!({"future_section": {"x": 1}}));
        assert_eq!(s, Settings::default());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn save_user_writes_a_minimal_diff_and_keeps_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"keybindings": {"Normal": {"<q>": "Quit"}}, "custom": [1, 2]}"#,
        )
        .unwrap();
        let mut s = Settings::default();
        s.connection.timeout_secs = 45;
        s.interface.show_tree = true;
        s.save_user(dir.path()).unwrap();

        let text = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            doc["settings"],
            json!({"connection": {"timeout_secs": 45}, "interface": {"show_tree": true}})
        );
        assert_eq!(doc["keybindings"], json!({"Normal": {"<q>": "Quit"}}));
        assert_eq!(doc["custom"], json!([1, 2]));

        let (reloaded, report) = Settings::from_value(&doc["settings"]);
        assert!(report.warnings.is_empty());
        assert_eq!(reloaded, s);
    }

    #[test]
    fn save_user_removes_the_key_when_everything_is_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"settings": {"cache": {"listing_cache": false}}, "styles": {}}"#,
        )
        .unwrap();
        Settings::default().save_user(dir.path()).unwrap();
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(doc, json!({"styles": {}}));
    }

    #[test]
    fn save_user_creates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("new");
        let mut s = Settings::default();
        s.queue.persist = false;
        s.save_user(&config_dir).unwrap();
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(config_dir.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(doc, json!({"settings": {"queue": {"persist": false}}}));
    }

    #[test]
    fn save_user_refuses_to_clobber_a_broken_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "{ not json").unwrap();
        assert!(Settings::default().save_user(dir.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.json")).unwrap(),
            "{ not json"
        );
    }
}
