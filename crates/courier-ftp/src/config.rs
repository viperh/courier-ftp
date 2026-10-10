use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use courier_ftp_core::settings::{Settings, SettingsStore, SettingsWarning};

use serde::Deserialize;
use tracing::{error, warn};

use crate::{keymap::resolver::RawKeymap, paths::AppPaths};

/// The default config, baked into the binary at compile time. User config
/// files found in [`AppPaths::config_dir`] are layered on top of it.
const CONFIG: &str = include_str!("../config/config.json");

#[derive(Clone, Debug, Deserialize, Default)]
pub(crate) struct AppConfig {
    #[serde(default)]
    #[expect(dead_code, reason = "read by the log file (T71) and the vault (T30)")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub config_dir: PathBuf,
}

/// The layered config as the `config` crate deserialises it. `keybindings`, `styles`
/// and `settings` stay raw JSON so a bad entry never fails loading.
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default, flatten)]
    config: AppConfig,
    #[serde(default)]
    keybindings: serde_json::Value,
    #[serde(default)]
    styles: serde_json::Value,
    #[serde(default)]
    settings: serde_json::Value,
}

/// The built-in `config.json`, parsed once.
#[derive(Debug, Default)]
struct Defaults {
    keybindings: RawKeymap,
    styles: BTreeMap<String, String>,
}

static DEFAULTS: LazyLock<Defaults> = LazyLock::new(|| {
    let raw: RawConfig = match json5::from_str(CONFIG) {
        Ok(raw) => raw,
        Err(e) => {
            // Covered by a test; never happens in a release build.
            error!("built-in config: {e}");
            return Defaults::default();
        }
    };
    let mut problems = Vec::new();
    Defaults {
        keybindings: raw_keymap(&raw.keybindings, &mut problems),
        styles: raw_styles(&raw.styles, &mut problems),
    }
});

/// The built-in key bindings (T50, T51).
pub(crate) fn default_keybindings() -> &'static RawKeymap {
    &DEFAULTS.keybindings
}

/// The built-in style keys and their `default` theme values.
pub(crate) fn default_styles() -> &'static BTreeMap<String, String> {
    &DEFAULTS.styles
}

/// Reads `keybindings` (mode → key → action name); entries of the wrong JSON type
/// are skipped and reported.
fn raw_keymap(v: &serde_json::Value, problems: &mut Vec<String>) -> RawKeymap {
    let mut out = RawKeymap::new();
    let Some(modes) = v.as_object() else {
        if !v.is_null() {
            problems.push("keybindings: expected an object of modes".to_owned());
        }
        return out;
    };
    for (mode, table) in modes {
        let Some(table) = table.as_object() else {
            problems.push(format!("keybindings.{mode}: expected an object of keys"));
            continue;
        };
        let entries = out.entry(mode.clone()).or_default();
        for (key, action) in table {
            match action.as_str() {
                Some(a) => {
                    entries.insert(key.clone(), a.to_owned());
                }
                None => problems.push(format!("keybindings.{mode}.{key}: expected an action name")),
            }
        }
    }
    out
}

/// Reads the flat `styles` map (style key → style string).
fn raw_styles(v: &serde_json::Value, problems: &mut Vec<String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(map) = v.as_object() else {
        if !v.is_null() {
            problems.push("styles: expected an object".to_owned());
        }
        return out;
    };
    for (key, style) in map {
        match style.as_str() {
            Some(s) => {
                out.insert(key.clone(), s.to_owned());
            }
            None => problems.push(format!("styles.{key}: expected a style string")),
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    pub config: AppConfig,
    /// The user's `keybindings` (the resolver puts them over [`default_keybindings`]).
    pub keybindings: RawKeymap,
    /// The user's `styles` (the theme puts them over the preset).
    pub styles: BTreeMap<String, String>,
    /// The application settings (T05), defaults merged with the user's `settings` key.
    pub settings: Settings,
    /// Problems found in the user's `settings`; each bad value was replaced by its
    /// default. Shown once as `Error:` lines in the message log at startup (T55).
    pub settings_warnings: Vec<SettingsWarning>,
    /// Structural problems in `keybindings` / `styles` (wrong JSON types).
    pub config_problems: Vec<String>,
}

/// User config files loaded after `config.json`, so a `settings` key in one of them
/// would shadow settings saved to `config.json`.
const SHADOWING_FILES: [(&str, config::FileFormat); 3] = [
    ("config.yaml", config::FileFormat::Yaml),
    ("config.toml", config::FileFormat::Toml),
    ("config.ini", config::FileFormat::Ini),
];

/// Refuses (`InvalidInput`) when `config.yaml`, `config.toml` or `config.ini` in
/// `config_dir` has a top-level `settings` key: it is loaded after `config.json` and
/// would hide the saved values.
pub(crate) fn check_settings_not_shadowed(config_dir: &Path) -> courier_ftp_core::Result<()> {
    for (file, format) in SHADOWING_FILES {
        let path = config_dir.join(file);
        if !path.exists() {
            continue;
        }
        let table = config::Config::builder()
            .add_source(config::File::from(path.clone()).format(format))
            .build()
            .and_then(|c| c.try_deserialize::<HashMap<String, config::Value>>())
            .map_err(|e| courier_ftp_core::Error::InvalidInput(format!("{file}: {e}")))?;
        if table.contains_key("settings") {
            return Err(courier_ftp_core::Error::InvalidInput(format!(
                "{file} has a \"settings\" key that would override the saved settings; \
                 move it to config.json or remove it"
            )));
        }
    }
    Ok(())
}

/// Saves a settings change made in the app (T68): refuses when another config file
/// shadows `config.json`, then [`SettingsStore::update`].
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the settings screen (T68)")
)]
pub(crate) fn save_settings(
    store: &SettingsStore,
    edit: impl FnOnce(&mut Settings),
) -> courier_ftp_core::Result<Vec<SettingsWarning>> {
    check_settings_not_shadowed(store.config_dir())?;
    store.update(edit)
}

/// Upper-cased crate name, used as the prefix for the `*_DATA`, `*_CONFIG`
/// and `*_LOG_LEVEL` environment variables (see `.envrc`).
pub(crate) static PROJECT_NAME: LazyLock<String> =
    LazyLock::new(|| env!("CARGO_CRATE_NAME").to_uppercase().to_string());

impl Config {
    pub(crate) fn new(paths: &AppPaths) -> color_eyre::Result<Self, config::ConfigError> {
        let data_dir = &paths.data_dir;
        let config_dir = &paths.config_dir;
        let mut builder = config::Config::builder()
            .set_default("data_dir", data_dir.to_string_lossy().into_owned())?
            .set_default("config_dir", config_dir.to_string_lossy().into_owned())?;

        let config_files = [
            ("config.json5", config::FileFormat::Json5),
            ("config.json", config::FileFormat::Json),
            ("config.yaml", config::FileFormat::Yaml),
            ("config.toml", config::FileFormat::Toml),
            ("config.ini", config::FileFormat::Ini),
        ];
        let mut found_config = false;
        for (file, format) in &config_files {
            let source = config::File::from(config_dir.join(file))
                .format(*format)
                .required(false);
            builder = builder.add_source(source);
            if config_dir.join(file).exists() {
                found_config = true
            }
        }
        if !found_config {
            error!("No configuration file found. Application may not behave as expected");
        }

        let cfg: RawConfig = builder.build()?.try_deserialize()?;
        let mut config_problems = Vec::new();
        let keybindings = raw_keymap(&cfg.keybindings, &mut config_problems);
        let styles = raw_styles(&cfg.styles, &mut config_problems);
        for p in &config_problems {
            warn!("{p}");
        }

        let (settings, settings_warnings) = Settings::from_json_lenient(&cfg.settings);
        for w in &settings_warnings {
            // Only the key path: values can be hosts or paths (T91 §4).
            warn!(path = %w.path, "setting ignored; using its default");
        }

        Ok(Self {
            config: cfg.config,
            keybindings,
            styles,
            settings,
            settings_warnings,
            config_problems,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_config() -> color_eyre::Result<()> {
        use crate::{
            action::Action,
            app::Mode,
            keymap::{
                chord::KeyChord,
                resolver::{KeyResolver, Resolution},
            },
        };
        let tmp = tempfile::TempDir::new()?;
        let c = Config::new(&temp_paths(&tmp))?;
        let (mut r, problems) = KeyResolver::from_config(&c);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(matches!(
            r.resolve(
                KeyChord::ctrl('q'),
                Mode::Normal,
                tokio::time::Instant::now()
            ),
            Resolution::Action(Action::Quit)
        ));
        Ok(())
    }

    #[test]
    fn built_in_config_parses() {
        assert!(json5::from_str::<RawConfig>(CONFIG).is_ok());
        assert!(default_styles().contains_key("border_focused"));
        // Every mode has a section.
        for m in <crate::app::Mode as strum::IntoEnumIterator>::iter() {
            assert!(
                default_keybindings().contains_key(&format!("{m:?}")),
                "{m:?}"
            );
        }
    }

    #[test]
    fn wrong_json_types_are_problems_not_errors() -> color_eyre::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let paths = temp_paths(&tmp);
        std::fs::create_dir_all(&paths.config_dir)?;
        std::fs::write(
            paths.config_dir.join("config.json"),
            r#"{"keybindings": {"Normal": {"x": 3}, "Log": []}, "styles": {"border": {"a": 1}, "title": "bold"}}"#,
        )?;
        let c = Config::new(&paths)?;
        assert_eq!(c.config_problems.len(), 3, "{:?}", c.config_problems);
        assert_eq!(c.styles.get("title").map(String::as_str), Some("bold"));
        Ok(())
    }

    fn temp_paths(tmp: &tempfile::TempDir) -> AppPaths {
        AppPaths {
            config_dir: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            cache_dir: tmp.path().join("cache"),
        }
    }

    #[test]
    fn config_new_survives_bad_settings() -> color_eyre::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let paths = temp_paths(&tmp);
        std::fs::create_dir_all(&paths.config_dir)?;
        std::fs::write(
            paths.config_dir.join("config.json"),
            r#"{"settings": {"transfers": {"max_concurrent": 99}, "connection": {"timeout_secs": 30}},
                "keybindings": {"Normal": {"ctrl-x": "Quit"}}}"#,
        )?;
        let c = Config::new(&paths)?;
        assert_eq!(c.settings.transfers.max_concurrent, 4);
        assert_eq!(c.settings.connection.timeout_secs, 30);
        assert_eq!(c.settings_warnings.len(), 1);
        assert_eq!(c.settings_warnings[0].path, "transfers.max_concurrent");
        // Keybindings still load next to settings.
        assert_eq!(c.keybindings["Normal"]["ctrl-x"], "Quit");

        // No user settings at all: defaults, no warnings.
        let tmp = tempfile::TempDir::new()?;
        let c = Config::new(&temp_paths(&tmp))?;
        assert_eq!(c.settings, Settings::default());
        assert!(c.settings_warnings.is_empty());
        Ok(())
    }

    #[test]
    fn saved_settings_reload_through_config() -> color_eyre::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let paths = temp_paths(&tmp);
        let mut s = Settings::default();
        s.interface.show_tree = true;
        // Arrays, nested objects, data-carrying enums and chars survive the `config`
        // crate's own value model.
        s.file_types.ascii_extensions = vec!["txt".to_owned(), "md".to_owned()];
        s.ftp.active_port_range = Some(courier_ftp_core::settings::PortRange {
            min: 50000,
            max: 50100,
        });
        s.ftp.active_external_ip =
            courier_ftp_core::settings::ActiveExternalIp::FromUrl("http://ip.example/".into());
        s.transfers.invalid_char_replacement = '-';
        s.transfers.max_concurrent = 8;
        s.save_user(&paths.config_dir)?;
        let c = Config::new(&paths)?;
        assert_eq!(c.settings, s);
        assert!(c.settings_warnings.is_empty());
        Ok(())
    }

    // T47 AC10: filter settings survive `save_user` and a reload through `Config::new`.
    #[test]
    fn filter_settings_save_user_roundtrip() -> color_eyre::Result<()> {
        use courier_ftp_core::filters::{
            AppliesTo, Condition, Filter, FilterScope, FilterSet, MatchMode, NumOp, StringOp,
        };
        let tmp = tempfile::TempDir::new()?;
        let paths = temp_paths(&tmp);
        let mut s = Settings::default();
        let f = &mut s.filters;
        f.filters[1].conditions.push(Condition::Name {
            op: StringOp::Regex,
            value: r"^\.git(modules)?$".to_owned(),
        });
        f.filters.push(Filter {
            name: "Big old logs".to_owned(),
            applies_to: AppliesTo::Files,
            match_mode: MatchMode::All,
            case_sensitive: false,
            scope: FilterScope::RemoteOnly,
            conditions: vec![
                Condition::Name {
                    op: StringOp::Glob,
                    value: "*.LOG".to_owned(),
                },
                Condition::Size {
                    op: NumOp::Greater,
                    value: 1 << 20,
                },
                serde_json::from_value(serde_json::json!(
                    {"type": "date", "op": "before", "value": "2026-01-31"}
                ))?,
            ],
            builtin: false,
        });
        f.sets[0].remote = vec!["Git directories".to_owned(), "Big old logs".to_owned()];
        f.sets.push(FilterSet {
            name: "web".to_owned(),
            local: vec!["Configuration files".to_owned()],
            remote: vec![],
        });
        f.active_set = "web".to_owned();
        f.apply_to_transfers = false;
        s.save_user(&paths.config_dir)?;
        let c = Config::new(&paths)?;
        assert!(c.settings_warnings.is_empty(), "{:?}", c.settings_warnings);
        assert_eq!(c.settings, s);
        Ok(())
    }

    #[test]
    fn save_refused_when_toml_shadows_settings() -> color_eyre::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let dir = tmp.path();
        // A toml file without `settings` does not block saving.
        std::fs::write(dir.join("config.toml"), "[styles]\n")?;
        check_settings_not_shadowed(dir)?;
        let store = SettingsStore::new(Settings::default(), dir.to_path_buf());
        save_settings(&store, |s| s.interface.show_tree = true)?;

        std::fs::write(
            dir.join("config.toml"),
            "[settings.transfers]\nmax_concurrent = 2\n",
        )?;
        let before = std::fs::read_to_string(dir.join("config.json"))?;
        let err = save_settings(&store, |s| s.interface.show_log = false).unwrap_err();
        assert!(matches!(err, courier_ftp_core::Error::InvalidInput(_)));
        assert!(store.current().interface.show_log);
        assert!(err.to_string().contains("config.toml"), "{err}");
        assert_eq!(std::fs::read_to_string(dir.join("config.json"))?, before);

        std::fs::remove_file(dir.join("config.toml"))?;
        std::fs::write(
            dir.join("config.yaml"),
            "settings:\n  ftp:\n    use_mlsd: false\n",
        )?;
        assert!(check_settings_not_shadowed(dir).is_err());
        Ok(())
    }
}
