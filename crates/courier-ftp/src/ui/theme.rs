//! Colours (T50). Defaults here; the `styles` config section (keyed by
//! mode, then by the names below) overrides them; `NO_COLOR` drops colours
//! but keeps bold/reverse so focus and selection stay visible.

use std::collections::HashMap;

use courier_ftp_core::events::LogKind;
use ratatui::style::{Color, Modifier, Style};

/// The styles the UI uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Theme {
    pub(crate) border: Style,
    pub(crate) focused_border: Style,
    pub(crate) title: Style,
    pub(crate) selection: Style,
    pub(crate) dim: Style,
    pub(crate) dir: Style,
    pub(crate) status_bar: Style,
    pub(crate) key_hint: Style,
    pub(crate) error: Style,
    pub(crate) log_status: Style,
    pub(crate) log_command: Style,
    pub(crate) log_response: Style,
    pub(crate) log_error: Style,
    pub(crate) log_debug: Style,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            border: Style::new().fg(Color::DarkGray),
            focused_border: Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            title: Style::new().add_modifier(Modifier::BOLD),
            selection: Style::new().bg(Color::Blue).fg(Color::White),
            dim: Style::new().fg(Color::DarkGray),
            dir: Style::new().fg(Color::Blue).add_modifier(Modifier::BOLD),
            status_bar: Style::new().bg(Color::DarkGray).fg(Color::White),
            key_hint: Style::new().fg(Color::Yellow),
            error: Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            log_status: Style::new(),
            log_command: Style::new().fg(Color::Cyan),
            log_response: Style::new().fg(Color::Green),
            log_error: Style::new().fg(Color::Red),
            log_debug: Style::new().fg(Color::DarkGray),
        }
    }
}

impl Theme {
    /// The default theme with `overrides` applied (unknown names are ignored),
    /// made monochrome when `no_color` is set.
    pub(crate) fn new(overrides: Option<&HashMap<String, Style>>, no_color: bool) -> Self {
        let mut theme = Self::default();
        if let Some(map) = overrides {
            for (name, style) in map {
                if let Some(slot) = theme.slot(name) {
                    *slot = *style;
                }
            }
        }
        if no_color {
            theme.strip_colours();
        }
        theme
    }

    /// Whether `NO_COLOR` asks for no colours (<https://no-color.org>: set and
    /// not empty).
    pub(crate) fn no_color_requested() -> bool {
        std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
    }

    fn slot(&mut self, name: &str) -> Option<&mut Style> {
        Some(match name {
            "border" => &mut self.border,
            "focused_border" => &mut self.focused_border,
            "title" => &mut self.title,
            "selection" => &mut self.selection,
            "dim" => &mut self.dim,
            "dir" => &mut self.dir,
            "status_bar" => &mut self.status_bar,
            "key_hint" => &mut self.key_hint,
            "error" => &mut self.error,
            "log_status" => &mut self.log_status,
            "log_command" => &mut self.log_command,
            "log_response" => &mut self.log_response,
            "log_error" => &mut self.log_error,
            "log_debug" => &mut self.log_debug,
            _ => return None,
        })
    }

    fn strip_colours(&mut self) {
        let mono = |s: Style| Style {
            fg: None,
            bg: None,
            underline_color: None,
            ..s
        };
        for name in [
            "border",
            "focused_border",
            "title",
            "selection",
            "dim",
            "dir",
            "status_bar",
            "key_hint",
            "error",
            "log_status",
            "log_command",
            "log_response",
            "log_error",
            "log_debug",
        ] {
            if let Some(slot) = self.slot(name) {
                *slot = mono(*slot);
            }
        }
        // Without colour, selection and the status bar need another cue.
        self.selection = self.selection.add_modifier(Modifier::REVERSED);
        self.status_bar = self.status_bar.add_modifier(Modifier::REVERSED);
    }

    /// The style of a message-log line.
    pub(crate) fn log(&self, kind: LogKind) -> Style {
        match kind {
            LogKind::Status => self.log_status,
            LogKind::Command => self.log_command,
            LogKind::Response => self.log_response,
            LogKind::Error => self.log_error,
            LogKind::ListingRaw | LogKind::Debug(_) => self.log_debug,
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn no_color_removes_every_colour() {
        let t = Theme::new(None, true);
        for s in [
            t.border,
            t.focused_border,
            t.selection,
            t.dir,
            t.status_bar,
            t.log_error,
            t.log_command,
        ] {
            assert_eq!((s.fg, s.bg), (None, None), "{s:?}");
        }
        assert!(t.selection.add_modifier.contains(Modifier::REVERSED));
        assert!(t.focused_border.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn config_overrides_apply() {
        let mut map = HashMap::new();
        map.insert("log_error".to_owned(), Style::new().fg(Color::Magenta));
        map.insert("not_a_slot".to_owned(), Style::new().fg(Color::Red));
        let t = Theme::new(Some(&map), false);
        assert_eq!(t.log_error.fg, Some(Color::Magenta));
        assert_eq!(t.border, Theme::default().border);
    }
}
