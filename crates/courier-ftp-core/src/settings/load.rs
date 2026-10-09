//! Lenient loading (`Settings::from_json_lenient`) and the user diff (`to_user_json`).

use serde_json::{Map, Value};

use super::SettingsWarning;
use super::model::Settings;

/// Hint for keys that look like passwords.
const PASSWORD_HINT: &str = "passwords are stored in the vault, not in the config file";

/// The defaults as a JSON tree. Serialising `Settings` cannot fail (string keys only).
pub(super) fn defaults_value() -> Value {
    serde_json::to_value(Settings::default()).unwrap_or(Value::Null)
}

pub(super) fn from_json_lenient(user: &Value) -> (Settings, Vec<SettingsWarning>) {
    let mut warnings = Vec::new();
    let mut acc = defaults_value();
    match user {
        Value::Null => {}
        Value::Object(map) => walk(&mut acc, map, &mut Vec::new(), &mut warnings),
        _ => warnings.push(SettingsWarning {
            path: "settings".to_owned(),
            message: "not an object; using defaults".to_owned(),
        }),
    }
    // Every accepted leaf was checked to deserialize, so this cannot fail.
    let mut settings: Settings = serde_json::from_value(acc).unwrap_or_default();
    warnings.extend(settings.validate());
    (settings, warnings)
}

/// JSON pointer for `path` (RFC 6901 escapes).
fn pointer(path: &[String]) -> String {
    let mut out = String::new();
    for seg in path {
        out.push('/');
        out.push_str(&seg.replace('~', "~0").replace('/', "~1"));
    }
    out
}

/// Depth-first walk of the user object; each leaf (non-object, or an object where the
/// defaults have a non-object) is merged on its own.
fn walk(
    acc: &mut Value,
    user: &Map<String, Value>,
    path: &mut Vec<String>,
    warnings: &mut Vec<SettingsWarning>,
) {
    for (key, value) in user {
        path.push(key.clone());
        let ptr = pointer(path);
        let dotted = path.join(".");
        match acc.pointer(&ptr) {
            None => {
                let message = if matches!(key.to_ascii_lowercase().as_str(), "password" | "pass") {
                    format!("unknown setting; {PASSWORD_HINT}")
                } else {
                    "unknown setting".to_owned()
                };
                warnings.push(SettingsWarning {
                    path: dotted,
                    message,
                });
            }
            Some(Value::Object(_)) if value.is_object() => {
                if let Value::Object(inner) = value {
                    walk(acc, inner, path, warnings);
                }
            }
            Some(_) => {
                if let Some(slot) = acc.pointer_mut(&ptr) {
                    let old = std::mem::replace(slot, value.clone());
                    if let Err(e) = serde_json::from_value::<Settings>(acc.clone()) {
                        if let Some(slot) = acc.pointer_mut(&ptr) {
                            *slot = old;
                        }
                        warnings.push(SettingsWarning {
                            path: dotted,
                            message: format!("invalid value: {e}"),
                        });
                    }
                }
            }
        }
        path.pop();
    }
}

/// Only the parts of `cur` that differ from `def`; objects are compared key by key,
/// everything else (arrays included) as a whole.
fn diff(cur: &Value, def: &Value) -> Option<Value> {
    match (cur, def) {
        (Value::Object(c), Value::Object(d)) => {
            let mut out = Map::new();
            for (k, v) in c {
                let changed = match d.get(k) {
                    Some(dv) => diff(v, dv),
                    None => Some(v.clone()),
                };
                if let Some(x) = changed {
                    out.insert(k.clone(), x);
                }
            }
            (!out.is_empty()).then_some(Value::Object(out))
        }
        _ => (cur != def).then(|| cur.clone()),
    }
}

pub(super) fn to_user_json(s: &Settings) -> Value {
    let cur = serde_json::to_value(s).unwrap_or(Value::Null);
    diff(&cur, &defaults_value()).unwrap_or_else(|| Value::Object(Map::new()))
}
