use std::{collections::HashMap, env, path::PathBuf, sync::LazyLock};

use directories::ProjectDirs;
use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, de::Deserializer};
use tracing::{debug, warn};

use courier_ftp_core::settings::Settings;

use crate::{app::Mode, keymap::KeyBindings};

/// The default config, baked into the binary at compile time. User config
/// files found in [`get_config_dir`] are layered on top of it.
const CONFIG: &str = include_str!("../config/default.json");

/// Reverse-domain qualifier and organisation used to locate the per-user
/// config and data directories. Change these when you rename the project.
const APP_QUALIFIER: &str = "com";
const APP_ORGANIZATION: &str = "viperh";

#[derive(Clone, Debug, Deserialize, Default)]
#[expect(
    dead_code,
    reason = "read by the settings screen (T68) to save the user config"
)]
pub(crate) struct AppConfig {
    #[serde(default)]
    pub(crate) data_dir: PathBuf,
    #[serde(default)]
    pub(crate) config_dir: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct Config {
    #[serde(default, flatten)]
    #[expect(dead_code, reason = "read by the settings screen (T68)")]
    pub(crate) config: AppConfig,
    #[serde(default)]
    pub(crate) keybindings: KeyBindings,
    #[serde(default)]
    pub(crate) styles: Styles,
    /// The `settings` key as found in the config files; turned into
    /// [`Config::settings`] by [`Settings::from_value`], which never fails.
    #[serde(default, rename = "settings")]
    settings_raw: serde_json::Value,
    /// Typed application settings (T05).
    #[serde(skip)]
    pub(crate) settings: Settings,
    /// Problems found while loading `settings`; each was replaced by its default.
    #[serde(skip)]
    pub(crate) settings_warnings: Vec<String>,
}

/// Upper-cased crate name, used as the prefix for the `*_HOME`, `*_DATA`,
/// `*_CONFIG` and `*_LOG_LEVEL` environment variables (see `.envrc`).
pub(crate) static PROJECT_NAME: LazyLock<String> =
    LazyLock::new(|| env!("CARGO_CRATE_NAME").to_uppercase().to_string());
/// `COURIER_FTP_HOME`: one directory for everything courier-ftp writes, used by
/// tests and CI. Config goes to `<home>/config`, data to `<home>/data`.
/// `COURIER_FTP_CONFIG` and `COURIER_FTP_DATA` win over it.
pub(crate) static HOME_FOLDER: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| non_empty_var(&format!("{}_HOME", PROJECT_NAME.clone())));
pub(crate) static DATA_FOLDER: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| non_empty_var(&format!("{}_DATA", PROJECT_NAME.clone())));
pub(crate) static CONFIG_FOLDER: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| non_empty_var(&format!("{}_CONFIG", PROJECT_NAME.clone())));

fn non_empty_var(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

impl Config {
    pub(crate) fn new() -> color_eyre::Result<Self, config::ConfigError> {
        let default_config: Config = json5::from_str(CONFIG)
            .map_err(|e| config::ConfigError::Message(format!("built-in config: {e}")))?;
        let data_dir = get_data_dir();
        let config_dir = get_config_dir();
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
            debug!(
                "no user config file in {}; using the defaults",
                config_dir.display()
            );
        }

        let mut cfg: Self = builder.build()?.try_deserialize()?;

        let (settings, report) = Settings::from_value(&cfg.settings_raw);
        for warning in &report.warnings {
            warn!("config: {warning}");
        }
        cfg.settings = settings;
        cfg.settings_warnings = report.warnings;

        cfg.keybindings.merge_defaults(&default_config.keybindings);
        for warning in default_config
            .keybindings
            .1
            .iter()
            .chain(&cfg.keybindings.1)
            .chain(&cfg.keybindings.conflicts())
        {
            warn!("config: {warning}");
            cfg.settings_warnings.push(warning.clone());
        }
        for (mode, default_styles) in default_config.styles.0.iter() {
            let user_styles = cfg.styles.0.entry(*mode).or_default();
            for (style_key, style) in default_styles.iter() {
                user_styles.entry(style_key.clone()).or_insert(*style);
            }
        }

        Ok(cfg)
    }
}

impl Config {
    /// Only the built-in defaults, ignoring user files and the environment
    /// (for tests).
    #[cfg(test)]
    pub(crate) fn builtin() -> Self {
        let mut cfg: Config = json5::from_str(CONFIG).expect("built-in config parses");
        let (settings, report) = Settings::from_value(&cfg.settings_raw);
        assert!(report.warnings.is_empty(), "{report:?}");
        cfg.settings = settings;
        cfg
    }
}

pub(crate) fn get_data_dir() -> PathBuf {
    if let Some(s) = DATA_FOLDER.clone() {
        s
    } else if let Some(home) = HOME_FOLDER.clone() {
        home.join("data")
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    }
}

pub(crate) fn get_config_dir() -> PathBuf {
    if let Some(s) = CONFIG_FOLDER.clone() {
        s
    } else if let Some(home) = HOME_FOLDER.clone() {
        home.join("config")
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.config_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".config")
    }
}

fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, env!("CARGO_PKG_NAME"))
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Styles(pub HashMap<Mode, HashMap<String, Style>>);

impl<'de> Deserialize<'de> for Styles {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parsed_map = HashMap::<Mode, HashMap<String, String>>::deserialize(deserializer)?;

        let styles = parsed_map
            .into_iter()
            .map(|(mode, inner_map)| {
                let converted_inner_map = inner_map
                    .into_iter()
                    .map(|(str, style)| (str, parse_style(&style)))
                    .collect();
                (mode, converted_inner_map)
            })
            .collect();

        Ok(Styles(styles))
    }
}

pub(crate) fn parse_style(line: &str) -> Style {
    let (foreground, background) =
        line.split_at(line.to_lowercase().find("on ").unwrap_or(line.len()));
    let foreground = process_color_string(foreground);
    let background = process_color_string(&background.replace("on ", ""));

    let mut style = Style::default();
    if let Some(fg) = parse_color(&foreground.0) {
        style = style.fg(fg);
    }
    if let Some(bg) = parse_color(&background.0) {
        style = style.bg(bg);
    }
    style = style.add_modifier(foreground.1 | background.1);
    style
}

fn process_color_string(color_str: &str) -> (String, Modifier) {
    let color = color_str
        .replace("grey", "gray")
        .replace("bright ", "")
        .replace("bold ", "")
        .replace("underline ", "")
        .replace("inverse ", "");

    let mut modifiers = Modifier::empty();
    if color_str.contains("underline") {
        modifiers |= Modifier::UNDERLINED;
    }
    if color_str.contains("bold") {
        modifiers |= Modifier::BOLD;
    }
    if color_str.contains("inverse") {
        modifiers |= Modifier::REVERSED;
    }

    (color, modifiers)
}

fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim_start();
    let s = s.trim_end();
    if s.contains("bright color") {
        let s = s.trim_start_matches("bright ");
        let c = s
            .trim_start_matches("color")
            .parse::<u8>()
            .unwrap_or_default();
        Some(Color::Indexed(c.wrapping_shl(8)))
    } else if s.contains("color") {
        let c = s
            .trim_start_matches("color")
            .parse::<u8>()
            .unwrap_or_default();
        Some(Color::Indexed(c))
    } else if s.contains("gray") {
        let c = 232
            + s.trim_start_matches("gray")
                .parse::<u8>()
                .unwrap_or_default();
        Some(Color::Indexed(c))
    } else if s.contains("rgb") {
        let red = (s.as_bytes()[3] as char).to_digit(10).unwrap_or_default() as u8;
        let green = (s.as_bytes()[4] as char).to_digit(10).unwrap_or_default() as u8;
        let blue = (s.as_bytes()[5] as char).to_digit(10).unwrap_or_default() as u8;
        let c = 16 + red * 36 + green * 6 + blue;
        Some(Color::Indexed(c))
    } else if s == "bold black" {
        Some(Color::Indexed(8))
    } else if s == "bold red" {
        Some(Color::Indexed(9))
    } else if s == "bold green" {
        Some(Color::Indexed(10))
    } else if s == "bold yellow" {
        Some(Color::Indexed(11))
    } else if s == "bold blue" {
        Some(Color::Indexed(12))
    } else if s == "bold magenta" {
        Some(Color::Indexed(13))
    } else if s == "bold cyan" {
        Some(Color::Indexed(14))
    } else if s == "bold white" {
        Some(Color::Indexed(15))
    } else if s == "black" {
        Some(Color::Indexed(0))
    } else if s == "red" {
        Some(Color::Indexed(1))
    } else if s == "green" {
        Some(Color::Indexed(2))
    } else if s == "yellow" {
        Some(Color::Indexed(3))
    } else if s == "blue" {
        Some(Color::Indexed(4))
    } else if s == "magenta" {
        Some(Color::Indexed(5))
    } else if s == "cyan" {
        Some(Color::Indexed(6))
    } else if s == "white" {
        Some(Color::Indexed(7))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_parse_style_default() {
        let style = parse_style("");
        assert_eq!(style, Style::default());
    }

    #[test]
    fn test_parse_style_foreground() {
        let style = parse_style("red");
        assert_eq!(style.fg, Some(Color::Indexed(1)));
    }

    #[test]
    fn test_parse_style_background() {
        let style = parse_style("on blue");
        assert_eq!(style.bg, Some(Color::Indexed(4)));
    }

    #[test]
    fn test_parse_style_modifiers() {
        let style = parse_style("underline red on blue");
        assert_eq!(style.fg, Some(Color::Indexed(1)));
        assert_eq!(style.bg, Some(Color::Indexed(4)));
    }

    #[test]
    fn test_process_color_string() {
        let (color, modifiers) = process_color_string("underline bold inverse gray");
        assert_eq!(color, "gray");
        assert!(modifiers.contains(Modifier::UNDERLINED));
        assert!(modifiers.contains(Modifier::BOLD));
        assert!(modifiers.contains(Modifier::REVERSED));
    }

    #[test]
    fn test_parse_color_rgb() {
        let color = parse_color("rgb123");
        let expected = 16 + 36 + 2 * 6 + 3;
        assert_eq!(color, Some(Color::Indexed(expected)));
    }

    #[test]
    fn test_parse_color_unknown() {
        let color = parse_color("unknown");
        assert_eq!(color, None);
    }

    /// `config/default.json` shows every setting with its default (T05). Run
    /// with `COURIER_FTP_BLESS=1` to rewrite the file after changing a default.
    #[test]
    fn default_json_lists_every_setting() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/default.json");
        let mut doc: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        let expected = serde_json::to_value(Settings::default()).unwrap();
        if env::var_os("COURIER_FTP_BLESS").is_some() {
            doc["settings"] = expected;
            let mut text = serde_json::to_string_pretty(&doc).unwrap();
            text.push('\n');
            std::fs::write(&path, text).unwrap();
            return;
        }
        assert_eq!(
            doc["settings"],
            expected,
            "{} is stale; rerun with COURIER_FTP_BLESS=1",
            path.display()
        );
        let (parsed, report) = Settings::from_value(&doc["settings"]);
        assert!(report.warnings.is_empty(), "{report:?}");
        assert_eq!(parsed, Settings::default());
    }

    #[test]
    fn builtin_keymap_is_clean() {
        let c = Config::builtin();
        assert!(c.keybindings.1.is_empty(), "{:?}", c.keybindings.1);
        assert!(
            c.keybindings.conflicts().is_empty(),
            "{:?}",
            c.keybindings.conflicts()
        );
        let quit = crate::keymap::parse_key_sequence("<Ctrl-q>").unwrap();
        assert_eq!(
            c.keybindings.lookup(Mode::Normal, &quit),
            Some(&crate::action::Action::Quit)
        );
    }
}
