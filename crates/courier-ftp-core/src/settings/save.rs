//! Saving the user's changes into `<config_dir>/config.json` (`Settings::save_user`).

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use serde_json::{Map, Value};

use super::load::{defaults_value, to_user_json};
use super::model::Settings;
use crate::{Error, Result};

/// The file the settings are saved to, inside the config directory.
pub const USER_CONFIG_FILE: &str = "config.json";

/// An I/O error whose message names the file.
fn io_error(path: &Path, e: io::Error) -> Error {
    Error::Io(io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// Removes from `obj` every key path the settings model knows (`known` is the defaults
/// tree). Unknown keys stay; objects left empty are removed.
fn remove_known(obj: &mut Map<String, Value>, known: &Map<String, Value>) {
    obj.retain(|key, value| match (known.get(key), value) {
        (None, _) => true,
        (Some(Value::Object(k)), Value::Object(inner)) => {
            remove_known(inner, k);
            !inner.is_empty()
        }
        (Some(_), _) => false,
    });
}

/// Deep merge of `src` into `dst` (objects merged key by key, everything else replaced).
fn merge(dst: &mut Map<String, Value>, src: Map<String, Value>) {
    for (key, value) in src {
        match (dst.get_mut(&key), value) {
            (Some(Value::Object(d)), Value::Object(s)) => merge(d, s),
            (_, value) => {
                dst.insert(key, value);
            }
        }
    }
}

/// Creates the config directory (`0700` on Unix) when it is missing.
fn create_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| io_error(dir, e))
}

pub(super) fn save_user(settings: &Settings, config_dir: &Path) -> Result<()> {
    let file = config_dir.join(USER_CONFIG_FILE);
    let mut root = match fs::read_to_string(&file) {
        Ok(text) => serde_json::from_str::<Value>(&text).map_err(|_| {
            Error::InvalidInput(
                "config.json is not valid JSON; fix or remove it before saving settings".into(),
            )
        })?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Value::Object(Map::new()),
        Err(e) => return Err(io_error(&file, e)),
    };
    let Value::Object(root_map) = &mut root else {
        return Err(Error::InvalidInput(
            "config.json is not a JSON object; fix or remove it before saving settings".into(),
        ));
    };

    let mut user = match root_map.remove("settings") {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    if let Value::Object(known) = defaults_value() {
        remove_known(&mut user, &known);
    }
    if let Value::Object(diff) = to_user_json(settings) {
        merge(&mut user, diff);
    }
    if !user.is_empty() {
        root_map.insert("settings".to_owned(), Value::Object(user));
    }

    let mut text = serde_json::to_string_pretty(&root)
        .map_err(|e| Error::Internal(format!("cannot serialise config.json: {e}")))?;
    text.push('\n');

    create_dir(config_dir)?;
    let tmp = config_dir.join("config.json.tmp");
    let write = || -> io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(io_error(&tmp, e));
    }
    fs::rename(&tmp, &file).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error(&file, e)
    })
}
