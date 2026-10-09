use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use courier_ftp_core::settings::{Settings, SettingsStore, SettingsWarning};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, de::Deserializer};
use tracing::{error, warn};

use crate::{action::Action, app::Mode, paths::AppPaths};

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

/// The layered config as the `config` crate deserialises it. `settings` stays raw JSON
/// so a bad setting never fails loading (see [`Settings::from_json_lenient`]).
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default, flatten)]
    config: AppConfig,
    #[serde(default)]
    keybindings: KeyBindings,
    #[serde(default)]
    styles: Styles,
    #[serde(default)]
    settings: serde_json::Value,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    pub config: AppConfig,
    pub keybindings: KeyBindings,
    #[expect(dead_code, reason = "read by the themed panes (T50)")]
    pub styles: Styles,
    /// The application settings (T05), defaults merged with the user's `settings` key.
    pub settings: Settings,
    /// Problems found in the user's `settings`; each bad value was replaced by its
    /// default. Shown once as `Error:` lines in the message log at startup (T55).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "shown by the message log pane (T55)")
    )]
    pub settings_warnings: Vec<SettingsWarning>,
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the settings screen (T68)")
)]
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
        let default_config: RawConfig = json5::from_str(CONFIG)
            .map_err(|e| config::ConfigError::Message(format!("built-in config: {e}")))?;
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

        let mut cfg: RawConfig = builder.build()?.try_deserialize()?;

        for (mode, default_bindings) in default_config.keybindings.0.iter() {
            let user_bindings = cfg.keybindings.0.entry(*mode).or_default();
            for (key, cmd) in default_bindings.iter() {
                user_bindings
                    .entry(key.clone())
                    .or_insert_with(|| cmd.clone());
            }
        }
        for (mode, default_styles) in default_config.styles.0.iter() {
            let user_styles = cfg.styles.0.entry(*mode).or_default();
            for (style_key, style) in default_styles.iter() {
                user_styles.entry(style_key.clone()).or_insert(*style);
            }
        }

        let (settings, settings_warnings) = Settings::from_json_lenient(&cfg.settings);
        for w in &settings_warnings {
            // Only the key path: values can be hosts or paths (T91 §4).
            warn!(path = %w.path, "setting ignored; using its default");
        }

        Ok(Self {
            config: cfg.config,
            keybindings: cfg.keybindings,
            styles: cfg.styles,
            settings,
            settings_warnings,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct KeyBindings(pub HashMap<Mode, HashMap<Vec<KeyEvent>, Action>>);

impl<'de> Deserialize<'de> for KeyBindings {
    fn deserialize<D>(deserializer: D) -> color_eyre::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parsed_map = HashMap::<Mode, HashMap<String, Action>>::deserialize(deserializer)?;

        let keybindings = parsed_map
            .into_iter()
            .map(|(mode, inner_map)| {
                let converted_inner_map = inner_map
                    .into_iter()
                    .map(|(key_str, cmd)| {
                        parse_key_sequence(&key_str)
                            .map(|keys| (keys, cmd))
                            .map_err(serde::de::Error::custom)
                    })
                    .collect::<Result<_, D::Error>>()?;
                Ok((mode, converted_inner_map))
            })
            .collect::<Result<_, D::Error>>()?;

        Ok(KeyBindings(keybindings))
    }
}

fn parse_key_event(raw: &str) -> color_eyre::Result<KeyEvent, String> {
    let raw_lower = raw.to_ascii_lowercase();
    let (remaining, modifiers) = extract_modifiers(&raw_lower);
    parse_key_code_with_modifiers(remaining, modifiers)
}

fn extract_modifiers(raw: &str) -> (&str, KeyModifiers) {
    let mut modifiers = KeyModifiers::empty();
    let mut current = raw;

    loop {
        match current {
            rest if rest.starts_with("ctrl-") => {
                modifiers.insert(KeyModifiers::CONTROL);
                current = &rest[5..];
            }
            rest if rest.starts_with("alt-") => {
                modifiers.insert(KeyModifiers::ALT);
                current = &rest[4..];
            }
            rest if rest.starts_with("shift-") => {
                modifiers.insert(KeyModifiers::SHIFT);
                current = &rest[6..];
            }
            _ => break, // break out of the loop if no known prefix is detected
        };
    }

    (current, modifiers)
}

fn parse_key_code_with_modifiers(
    raw: &str,
    mut modifiers: KeyModifiers,
) -> color_eyre::Result<KeyEvent, String> {
    let c = match raw {
        "esc" => KeyCode::Esc,
        "enter" => KeyCode::Enter,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" => KeyCode::PageUp,
        "pagedown" => KeyCode::PageDown,
        "backtab" => {
            modifiers.insert(KeyModifiers::SHIFT);
            KeyCode::BackTab
        }
        "backspace" => KeyCode::Backspace,
        "delete" => KeyCode::Delete,
        "insert" => KeyCode::Insert,
        "f1" => KeyCode::F(1),
        "f2" => KeyCode::F(2),
        "f3" => KeyCode::F(3),
        "f4" => KeyCode::F(4),
        "f5" => KeyCode::F(5),
        "f6" => KeyCode::F(6),
        "f7" => KeyCode::F(7),
        "f8" => KeyCode::F(8),
        "f9" => KeyCode::F(9),
        "f10" => KeyCode::F(10),
        "f11" => KeyCode::F(11),
        "f12" => KeyCode::F(12),
        "space" => KeyCode::Char(' '),
        "hyphen" => KeyCode::Char('-'),
        "minus" => KeyCode::Char('-'),
        "tab" => KeyCode::Tab,
        c if c.chars().count() == 1 => {
            let Some(mut c) = c.chars().next() else {
                return Err(format!("Unable to parse {raw}"));
            };
            if modifiers.contains(KeyModifiers::SHIFT) {
                c = c.to_ascii_uppercase();
            }
            KeyCode::Char(c)
        }
        _ => return Err(format!("Unable to parse {raw}")),
    };
    Ok(KeyEvent::new(c, modifiers))
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "shown in the help and keybinding screens (T51)")
)]
pub(crate) fn key_event_to_string(key_event: &KeyEvent) -> String {
    let char;
    let key_code = match key_event.code {
        KeyCode::Backspace => "backspace",
        KeyCode::Enter => "enter",
        KeyCode::Left => "left",
        KeyCode::Right => "right",
        KeyCode::Up => "up",
        KeyCode::Down => "down",
        KeyCode::Home => "home",
        KeyCode::End => "end",
        KeyCode::PageUp => "pageup",
        KeyCode::PageDown => "pagedown",
        KeyCode::Tab => "tab",
        KeyCode::BackTab => "backtab",
        KeyCode::Delete => "delete",
        KeyCode::Insert => "insert",
        KeyCode::F(c) => {
            char = format!("f({c})");
            &char
        }
        KeyCode::Char(' ') => "space",
        KeyCode::Char(c) => {
            char = c.to_string();
            &char
        }
        KeyCode::Esc => "esc",
        KeyCode::Null => "",
        KeyCode::CapsLock => "",
        KeyCode::Menu => "",
        KeyCode::ScrollLock => "",
        KeyCode::Media(_) => "",
        KeyCode::NumLock => "",
        KeyCode::PrintScreen => "",
        KeyCode::Pause => "",
        KeyCode::KeypadBegin => "",
        KeyCode::Modifier(_) => "",
    };

    let mut modifiers = Vec::with_capacity(3);

    if key_event.modifiers.intersects(KeyModifiers::CONTROL) {
        modifiers.push("ctrl");
    }

    if key_event.modifiers.intersects(KeyModifiers::SHIFT) {
        modifiers.push("shift");
    }

    if key_event.modifiers.intersects(KeyModifiers::ALT) {
        modifiers.push("alt");
    }

    let mut key = modifiers.join("-");

    if !key.is_empty() {
        key.push('-');
    }
    key.push_str(key_code);

    key
}

pub(crate) fn parse_key_sequence(raw: &str) -> color_eyre::Result<Vec<KeyEvent>, String> {
    if raw.chars().filter(|c| *c == '>').count() != raw.chars().filter(|c| *c == '<').count() {
        return Err(format!("Unable to parse `{raw}`"));
    }
    let raw = if !raw.contains("><") {
        let raw = raw.strip_prefix('<').unwrap_or(raw);
        raw.strip_prefix('>').unwrap_or(raw)
    } else {
        raw
    };
    let sequences = raw
        .split("><")
        .map(|seq| {
            if let Some(s) = seq.strip_prefix('<') {
                s
            } else if let Some(s) = seq.strip_suffix('>') {
                s
            } else {
                seq
            }
        })
        .collect::<Vec<_>>();

    sequences.into_iter().map(parse_key_event).collect()
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn test_config() -> color_eyre::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let paths = AppPaths {
            config_dir: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            cache_dir: tmp.path().join("cache"),
        };
        let c = Config::new(&paths)?;
        assert_eq!(
            c.keybindings
                .0
                .get(&Mode::Normal)
                .unwrap()
                .get(&parse_key_sequence("<Ctrl-q>").unwrap())
                .unwrap(),
            &Action::Quit
        );
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
                "keybindings": {"Normal": {"<Ctrl-x>": "Quit"}}}"#,
        )?;
        let c = Config::new(&paths)?;
        assert_eq!(c.settings.transfers.max_concurrent, 4);
        assert_eq!(c.settings.connection.timeout_secs, 30);
        assert_eq!(c.settings_warnings.len(), 1);
        assert_eq!(c.settings_warnings[0].path, "transfers.max_concurrent");
        // Keybindings still load next to settings.
        assert!(
            c.keybindings.0[&Mode::Normal].contains_key(&parse_key_sequence("<Ctrl-x>").unwrap())
        );

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

    #[test]
    fn save_refused_when_toml_shadows_settings() -> color_eyre::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let dir = tmp.path();
        // A toml file without `settings` does not block saving.
        std::fs::write(dir.join("config.toml"), "[styles.Normal]\n")?;
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

    #[test]
    fn test_simple_keys() {
        assert_eq!(
            parse_key_event("a").unwrap(),
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty())
        );

        assert_eq!(
            parse_key_event("enter").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::empty())
        );

        assert_eq!(
            parse_key_event("esc").unwrap(),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::empty())
        );
    }

    #[test]
    fn test_with_modifiers() {
        assert_eq!(
            parse_key_event("ctrl-a").unwrap(),
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL)
        );

        assert_eq!(
            parse_key_event("alt-enter").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT)
        );

        assert_eq!(
            parse_key_event("shift-esc").unwrap(),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::SHIFT)
        );
    }

    #[test]
    fn test_multiple_modifiers() {
        assert_eq!(
            parse_key_event("ctrl-alt-a").unwrap(),
            KeyEvent::new(
                KeyCode::Char('a'),
                KeyModifiers::CONTROL | KeyModifiers::ALT
            )
        );

        assert_eq!(
            parse_key_event("ctrl-shift-enter").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL | KeyModifiers::SHIFT)
        );
    }

    #[test]
    fn test_reverse_multiple_modifiers() {
        assert_eq!(
            key_event_to_string(&KeyEvent::new(
                KeyCode::Char('a'),
                KeyModifiers::CONTROL | KeyModifiers::ALT
            )),
            "ctrl-alt-a".to_string()
        );
    }

    #[test]
    fn test_invalid_keys() {
        assert!(parse_key_event("invalid-key").is_err());
        assert!(parse_key_event("ctrl-invalid-key").is_err());
    }

    #[test]
    fn test_case_insensitivity() {
        assert_eq!(
            parse_key_event("CTRL-a").unwrap(),
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL)
        );

        assert_eq!(
            parse_key_event("AlT-eNtEr").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT)
        );
    }
}
