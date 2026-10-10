//! Themes: named styles from a preset plus the user's `styles` overrides (T50).
//!
//! The style keys and the `default` preset are the `styles` map of the built-in
//! `config/config.json`; other tasks add their keys there. `high_contrast` and
//! `monochrome` are derived from it. `NO_COLOR` forces `monochrome` and also strips
//! colours from user overrides, so no colour is ever emitted.

use std::collections::{BTreeMap, HashMap};

use ratatui::style::{Color, Modifier, Style};

/// The theme setting (T05), named `ThemePreset` here because [`Theme`] is the
/// resolved style table.
pub(crate) use courier_ftp_core::settings::enums::Theme as ThemePreset;

use crate::config::default_styles;

/// Resolved named styles.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Theme {
    styles: HashMap<String, Style>,
    /// Colours are off (`NO_COLOR` or the monochrome preset).
    pub no_color: bool,
}

/// High-contrast changes over the default preset.
const HIGH_CONTRAST: &[(&str, &str)] = &[
    ("border", "white"),
    ("border_focused", "bold yellow"),
    ("title", "bold white"),
    ("title_focused", "bold yellow"),
    ("status.bar", "white on black"),
    ("placeholder", "white"),
    ("help_key", "bold yellow"),
];

/// Monochrome styles that need a modifier so the information is not lost.
const MONOCHROME: &[(&str, Modifier)] = &[
    ("border_focused", Modifier::BOLD),
    ("title_focused", Modifier::BOLD),
    ("placeholder", Modifier::DIM),
    ("cursor", Modifier::REVERSED),
    ("selection", Modifier::BOLD.union(Modifier::UNDERLINED)),
    // Dialogs and widgets (T52).
    ("dialog_title", Modifier::BOLD),
    ("field_label_focused", Modifier::BOLD),
    ("field_error", Modifier::BOLD),
    // Trust prompts (T69): warnings stay bold without colour.
    ("prompt.danger", Modifier::BOLD),
    ("field_help", Modifier::DIM),
    // Vault screens (T60): errors and warnings bold, focus by the cursor and a bold
    // label.
    ("vault.title", Modifier::BOLD),
    ("vault.border", Modifier::BOLD),
    ("vault.dim", Modifier::DIM),
    ("vault.accent", Modifier::BOLD),
    ("vault.error", Modifier::BOLD),
    ("vault.warn", Modifier::BOLD),
    ("vault.overlay", Modifier::DIM),
    ("input", Modifier::UNDERLINED),
    ("input_placeholder", Modifier::DIM),
    ("button_focused", Modifier::REVERSED.union(Modifier::BOLD)),
    ("button_danger", Modifier::BOLD),
    ("list_cursor", Modifier::REVERSED),
    ("list_marked", Modifier::BOLD),
    ("list_header", Modifier::BOLD.union(Modifier::UNDERLINED)),
    // File list (T53).
    ("file_list.dir", Modifier::BOLD),
    ("file_list.symlink_target", Modifier::DIM),
    ("file_list.hidden", Modifier::DIM),
    ("file_list.special", Modifier::ITALIC),
    (
        "file_list.marked",
        Modifier::BOLD.union(Modifier::UNDERLINED),
    ),
    ("file_list.cursor", Modifier::REVERSED),
    ("file_list.cursor_inactive", Modifier::UNDERLINED),
    ("file_list.header", Modifier::BOLD),
    ("file_list.error", Modifier::BOLD),
    // Message log (T55).
    ("log.warning", Modifier::BOLD),
    ("log.error", Modifier::BOLD),
    ("log.trace", Modifier::DIM),
    ("log.listing", Modifier::DIM),
    ("log.time", Modifier::DIM),
    ("log.cursor", Modifier::BOLD.union(Modifier::UNDERLINED)),
    ("log.visual", Modifier::REVERSED),
    ("log.search_match", Modifier::REVERSED),
    ("log.border_focused", Modifier::BOLD),
    // Status bar (T57): plain FTP and attention never rely on colour.
    ("status.insecure", Modifier::REVERSED.union(Modifier::BOLD)),
    ("status.attention", Modifier::REVERSED),
    ("status.dim", Modifier::DIM),
    ("status.active", Modifier::BOLD),
    ("status.msg_warn", Modifier::BOLD),
    ("status.msg_error", Modifier::BOLD),
    ("status.hint_key", Modifier::BOLD),
    ("status.hint", Modifier::DIM),
];

fn strip_colours(s: Style) -> Style {
    Style {
        fg: None,
        bg: None,
        underline_color: None,
        ..s
    }
}

impl Theme {
    /// Builds the theme for `preset` with the user's `overrides` (style key → style
    /// string). Unknown keys and bad style strings are skipped and reported.
    pub(crate) fn load(
        preset: ThemePreset,
        overrides: &BTreeMap<String, String>,
        no_color: bool,
    ) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let preset = if no_color {
            ThemePreset::Monochrome
        } else {
            preset
        };
        let defaults = default_styles();
        let mut styles: HashMap<String, Style> = defaults
            .iter()
            .map(|(k, v)| (k.clone(), parse_style(v).unwrap_or_default()))
            .collect();
        match preset {
            ThemePreset::Default => {}
            ThemePreset::HighContrast => {
                for (k, v) in HIGH_CONTRAST {
                    if let (Some(slot), Ok(s)) = (styles.get_mut(*k), parse_style(v)) {
                        *slot = s;
                    }
                }
            }
            ThemePreset::Monochrome => {
                for s in styles.values_mut() {
                    *s = strip_colours(*s);
                }
                for (k, m) in MONOCHROME {
                    if let Some(slot) = styles.get_mut(*k) {
                        *slot = Style::default().add_modifier(*m);
                    }
                }
            }
        }
        let mono = preset == ThemePreset::Monochrome;
        for (key, value) in overrides {
            if !defaults.contains_key(key) {
                warnings.push(format!("styles: unknown style key `{key}`"));
                continue;
            }
            match parse_style(value) {
                Ok(s) => {
                    styles.insert(key.clone(), if mono { strip_colours(s) } else { s });
                }
                Err(e) => warnings.push(format!("styles.{key}: {e}")),
            }
        }
        (
            Self {
                styles,
                no_color: mono,
            },
            warnings,
        )
    }

    /// The style for `key`; an unknown key gives `Style::default()` (and fails tests).
    pub(crate) fn style(&self, key: &str) -> Style {
        let s = self.styles.get(key).copied();
        #[cfg(test)]
        assert!(s.is_some(), "unknown style key `{key}`");
        s.unwrap_or_default()
    }
}

/// Parses a style string: `[modifiers] [colour] [on [modifiers] colour]`.
///
/// Modifiers: `bold`, `dim`, `italic`, `underline`, `inverse` (`reverse`),
/// `crossed`. Colours: `black red green yellow blue magenta cyan white`, `gray`/`grey`,
/// `bright <name>`, `color<N>` (0–255), `gray<N>` (0–23, the grey ramp), `rgb<RGB>`
/// (each digit 0–5, the 6×6×6 cube) and `#rrggbb`. An empty string is the plain style.
pub(crate) fn parse_style(s: &str) -> Result<Style, String> {
    let mut style = Style::default();
    let mut background = false;
    let mut bright = false;
    for word in s.split_whitespace() {
        let w = word.to_ascii_lowercase();
        let modifier = match w.as_str() {
            "bold" => Some(Modifier::BOLD),
            "dim" => Some(Modifier::DIM),
            "italic" => Some(Modifier::ITALIC),
            "underline" | "underlined" => Some(Modifier::UNDERLINED),
            "inverse" | "reverse" | "reversed" => Some(Modifier::REVERSED),
            "crossed" => Some(Modifier::CROSSED_OUT),
            _ => None,
        };
        if let Some(m) = modifier {
            style = style.add_modifier(m);
            continue;
        }
        match w.as_str() {
            "on" if !background => {
                background = true;
                continue;
            }
            "bright" => {
                bright = true;
                continue;
            }
            _ => {}
        }
        let colour = parse_colour(&w, bright).ok_or_else(|| format!("unknown word `{word}`"))?;
        bright = false;
        style = if background {
            style.bg(colour)
        } else {
            style.fg(colour)
        };
    }
    if bright {
        return Err("`bright` needs a colour name".to_owned());
    }
    Ok(style)
}

fn parse_colour(w: &str, bright: bool) -> Option<Color> {
    const NAMES: [&str; 8] = [
        "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
    ];
    if let Some(i) = NAMES.iter().position(|n| *n == w) {
        let i = u8::try_from(i).ok()?;
        return Some(Color::Indexed(if bright { i + 8 } else { i }));
    }
    if bright {
        return None;
    }
    if w == "gray" || w == "grey" {
        return Some(Color::Indexed(8));
    }
    if let Some(n) = w.strip_prefix("color") {
        return n.parse::<u8>().ok().map(Color::Indexed);
    }
    if let Some(n) = w.strip_prefix("gray").or_else(|| w.strip_prefix("grey")) {
        return n
            .parse::<u8>()
            .ok()
            .filter(|n| *n < 24)
            .map(|n| Color::Indexed(232 + n));
    }
    if let Some(d) = w.strip_prefix("rgb") {
        let digits: Vec<u8> = d
            .chars()
            .map(|c| c.to_digit(6).and_then(|v| u8::try_from(v).ok()))
            .collect::<Option<_>>()?;
        if let [r, g, b] = digits[..] {
            return Some(Color::Indexed(16 + r * 36 + g * 6 + b));
        }
        return None;
    }
    if let Some(hex) = w.strip_prefix('#')
        && hex.len() == 6
    {
        let v = u32::from_str_radix(hex, 16).ok()?;
        return Some(Color::from_u32(v));
    }
    None
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn parse_style_forms() -> Result<(), String> {
        assert_eq!(parse_style("")?, Style::default());
        assert_eq!(parse_style("red")?.fg, Some(Color::Indexed(1)));
        assert_eq!(parse_style("on blue")?.bg, Some(Color::Indexed(4)));
        let s = parse_style("bold underline red on blue")?;
        assert_eq!(s.fg, Some(Color::Indexed(1)));
        assert_eq!(s.bg, Some(Color::Indexed(4)));
        assert!(
            s.add_modifier
                .contains(Modifier::BOLD | Modifier::UNDERLINED)
        );
        assert_eq!(
            parse_style("on rgb012")?.bg,
            Some(Color::Indexed(16 + 6 + 2))
        );
        assert_eq!(
            parse_style("rgb123")?.fg,
            Some(Color::Indexed(16 + 36 + 12 + 3))
        );
        assert_eq!(parse_style("bright red")?.fg, Some(Color::Indexed(9)));
        assert_eq!(parse_style("gray3")?.fg, Some(Color::Indexed(235)));
        assert_eq!(parse_style("color200")?.fg, Some(Color::Indexed(200)));
        assert_eq!(parse_style("#ff0000")?.fg, Some(Color::Rgb(255, 0, 0)));
        assert!(
            parse_style("inverse")?
                .add_modifier
                .contains(Modifier::REVERSED)
        );
        assert!(parse_style("unknown").is_err());
        assert!(parse_style("rgb999").is_err());
        assert!(parse_style("bright").is_err());
        Ok(())
    }

    #[test]
    fn theme_overrides_and_unknown_keys_warn() {
        let mut o = BTreeMap::new();
        o.insert("border".to_owned(), "green".to_owned());
        o.insert("no_such_key".to_owned(), "red".to_owned());
        o.insert("title".to_owned(), "purple-ish".to_owned());
        let (t, warnings) = Theme::load(ThemePreset::Default, &o, false);
        assert_eq!(t.style("border").fg, Some(Color::Indexed(2)));
        assert_eq!(t.style("title"), Style::default());
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("no_such_key")));
        assert!(warnings.iter().any(|w| w.contains("styles.title")));
    }

    #[test]
    fn no_color_strips_every_colour() {
        let mut o = BTreeMap::new();
        o.insert("border".to_owned(), "bold green on red".to_owned());
        let (t, w) = Theme::load(ThemePreset::HighContrast, &o, true);
        assert!(w.is_empty());
        assert!(t.no_color);
        for s in t.styles.values() {
            assert_eq!((s.fg, s.bg), (None, None));
        }
        assert!(t.style("border").add_modifier.contains(Modifier::BOLD));
        assert!(
            t.style("border_focused")
                .add_modifier
                .contains(Modifier::BOLD)
        );
    }

    #[test]
    fn high_contrast_differs_from_default() {
        let (d, _) = Theme::load(ThemePreset::Default, &BTreeMap::new(), false);
        let (h, _) = Theme::load(ThemePreset::HighContrast, &BTreeMap::new(), false);
        assert_ne!(d.style("border"), h.style("border"));
    }
}
