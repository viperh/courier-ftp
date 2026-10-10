//! The application settings model (T05).
//!
//! [`Settings`] holds everything FileZilla puts in its Settings dialog plus courier-ftp's
//! own knobs. It lives under the `settings` key of the layered config files (D10); the
//! defaults have one source, [`Settings::default`]. Loading never fails on settings
//! content: [`Settings::from_json_lenient`] drops each bad value with a
//! [`SettingsWarning`] and keeps its default. [`SettingsStore`] owns the live settings
//! and hands out [`SharedSettings`] receivers; [`SettingsStore::update`] validates,
//! saves and then publishes.
//!
//! The settings registry (every key, default and range) is in
//! `tasks/05-settings-model.md`; `docs/settings.schema.json` is generated from this
//! module (`COURIER_FTP_BLESS=1 cargo test -p courier-ftp-core settings_schema`).

pub mod enums;
mod file_types;
mod load;
mod model;
mod save;
mod validate;

#[cfg(test)]
mod tests;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;

pub use enums::*;
pub use file_types::decide_transfer_type;
pub use model::*;
pub use save::USER_CONFIG_FILE;

use crate::Result;

/// A problem found while loading or validating. `path` is the dotted key
/// (`"ftp.active_port_range"`). The message may quote the offending value; log only the
/// path (T91 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsWarning {
    /// Dotted key path.
    pub path: String,
    /// What was wrong and what was done about it.
    pub message: String,
}

impl fmt::Display for SettingsWarning {
    /// `Setting ftp.active_port_range ignored: min (6000) > max (5000); using default`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Setting {} ignored: {}", self.path, self.message)
    }
}

impl Settings {
    /// Builds settings from the user's `settings` JSON object (may be `Null`).
    ///
    /// Leaf-by-leaf merge onto the defaults: a leaf that fails to deserialize is dropped
    /// with a warning; unknown keys produce a warning and are ignored. Then
    /// [`validate`](Self::validate).
    pub fn from_json_lenient(user: &serde_json::Value) -> (Settings, Vec<SettingsWarning>) {
        load::from_json_lenient(user)
    }

    /// Range and consistency checks. Invalid fields are reset to their default (bad list
    /// entries are dropped), one warning each.
    pub fn validate(&mut self) -> Vec<SettingsWarning> {
        validate::validate(self)
    }

    /// Only the leaves that differ from `Settings::default()` (arrays compared as a
    /// whole). An empty object when nothing differs.
    pub fn to_user_json(&self) -> serde_json::Value {
        load::to_user_json(self)
    }

    /// Merges [`to_user_json`](Self::to_user_json) into `<config_dir>/config.json` under
    /// the key `"settings"`: keys the model knows are replaced, unknown keys and every
    /// other top-level key (keybindings, styles, …) are kept. The write is atomic
    /// (temporary file, fsync, rename); a missing config dir is created (`0700` on Unix).
    ///
    /// Errors: `Io` (the message names the file), `InvalidInput` (the existing file is not
    /// valid JSON; nothing is written).
    pub fn save_user(&self, config_dir: &Path) -> Result<()> {
        save::save_user(self, config_dir)
    }

    /// JSON Schema (draft 2020-12) of `Settings` with doc comments and defaults.
    pub fn json_schema() -> serde_json::Value {
        schemars::schema_for!(Settings).to_value()
    }
}

/// Live settings shared by all components. Cheap to clone; read with
/// `borrow().clone()` per operation, `changed().await` to react.
pub type SharedSettings = watch::Receiver<Arc<Settings>>;

/// Owner of the live settings (created by the binary at startup).
#[derive(Debug)]
pub struct SettingsStore {
    tx: watch::Sender<Arc<Settings>>,
    config_dir: PathBuf,
    /// Serialises `update` / `set_transient` so concurrent edits are not lost.
    lock: Mutex<()>,
}

impl SettingsStore {
    /// A store publishing `initial`, saving to `config_dir`.
    pub fn new(initial: Settings, config_dir: PathBuf) -> Self {
        let (tx, _rx) = watch::channel(Arc::new(initial));
        Self {
            tx,
            config_dir,
            lock: Mutex::new(()),
        }
    }

    /// The settings in effect now.
    pub fn current(&self) -> Arc<Settings> {
        self.tx.borrow().clone()
    }

    /// A receiver of the live settings.
    pub fn subscribe(&self) -> SharedSettings {
        self.tx.subscribe()
    }

    /// The directory `update` saves to.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Applies `edit` to a copy, validates, saves (`save_user`), then publishes. On a
    /// save error nothing is published. Returns the validation warnings (fields that
    /// were reset).
    pub fn update(&self, edit: impl FnOnce(&mut Settings)) -> Result<Vec<SettingsWarning>> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.current()).clone();
        edit(&mut next);
        let warnings = next.validate();
        next.save_user(&self.config_dir)?;
        self.tx.send_replace(Arc::new(next));
        Ok(warnings)
    }

    /// Publishes without saving (runtime toggles such as the speed-limit key, T44/T57).
    pub fn set_transient(&self, edit: impl FnOnce(&mut Settings)) {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.current()).clone();
        edit(&mut next);
        self.tx.send_replace(Arc::new(next));
    }
}
