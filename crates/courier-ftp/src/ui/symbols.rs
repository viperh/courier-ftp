//! Glyph sets: Unicode or ASCII, chosen from `interface.unicode_symbols` and the
//! terminal environment (T50).
//!
//! Other tasks add their glyphs as fields of [`Symbols`] here (T53 file-type marks, T57
//! status-bar glyphs), never as a second type.

use ratatui::symbols::border;

pub(crate) use courier_ftp_core::settings::enums::UnicodeSymbols;

/// Terminal environment snapshot, read once at startup (tests build it by hand).
#[derive(Debug, Clone, Default)]
pub(crate) struct TermEnv {
    /// `TERM`.
    pub term: Option<String>,
    /// `LC_ALL`.
    pub lc_all: Option<String>,
    /// `LC_CTYPE`.
    pub lc_ctype: Option<String>,
    /// `LANG`.
    pub lang: Option<String>,
    /// `WT_SESSION` set (Windows Terminal).
    pub wt_session: bool,
    /// `TERM_PROGRAM`.
    pub term_program: Option<String>,
    /// `NO_COLOR` set and non-empty.
    pub no_color: bool,
    /// `SSH_CONNECTION` set.
    pub ssh_connection: bool,
    /// `SSH_TTY` set.
    pub ssh_tty: bool,
    /// Running on Windows.
    pub windows: bool,
}

impl TermEnv {
    /// Reads the process environment.
    pub(crate) fn from_process() -> Self {
        let var = |k: &str| std::env::var(k).ok();
        let set = |k: &str| std::env::var_os(k).is_some();
        Self {
            term: var("TERM"),
            lc_all: var("LC_ALL"),
            lc_ctype: var("LC_CTYPE"),
            lang: var("LANG"),
            wt_session: set("WT_SESSION"),
            term_program: var("TERM_PROGRAM"),
            no_color: std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
            ssh_connection: set("SSH_CONNECTION"),
            ssh_tty: set("SSH_TTY"),
            windows: cfg!(windows),
        }
    }

    /// `SSH_CONNECTION` or `SSH_TTY` set (used by T55's clipboard).
    pub(crate) fn over_ssh(&self) -> bool {
        self.ssh_connection || self.ssh_tty
    }

    /// Whether `auto` picks Unicode glyphs.
    fn supports_unicode(&self) -> bool {
        if matches!(self.term.as_deref(), Some("linux" | "dumb" | "vt100")) {
            return false;
        }
        if self.windows {
            // The classic console host has neither variable.
            return self.wt_session || self.term_program.is_some();
        }
        let locale = [&self.lc_all, &self.lc_ctype, &self.lang]
            .into_iter()
            .flatten()
            .find(|v| !v.is_empty());
        locale.is_some_and(|l| {
            let l = l.to_ascii_lowercase();
            l.contains("utf-8") || l.contains("utf8")
        })
    }
}

/// The glyphs the UI draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Symbols {
    /// Unicode (true) or ASCII set.
    pub unicode: bool,
    /// Border set for unfocused regions.
    pub border: border::Set<'static>,
    /// Border set for the focused region (thick in Unicode).
    pub border_focused: border::Set<'static>,
    /// Focus marker before the focused region's title.
    pub focus_marker: &'static str,
    /// Expanded tree node.
    pub expanded: &'static str,
    /// Collapsed tree node.
    pub collapsed: &'static str,
    /// Connected / active.
    pub dot_on: &'static str,
    /// Disconnected / inactive.
    pub dot_off: &'static str,
    /// Bullet (also the password mask).
    pub bullet: &'static str,
    /// Success.
    pub check: &'static str,
    /// Warning.
    pub warning: &'static str,
    /// Separator between status-bar segments.
    pub separator: &'static str,
    /// Ellipsis for truncated text.
    pub ellipsis: &'static str,
    /// Spinner frames, one every 100 ms.
    pub spinner: &'static [&'static str],
    /// Selected radio button (T52).
    pub radio_on: &'static str,
    /// Unselected radio button.
    pub radio_off: &'static str,
    /// Drop-down marker of a closed `Select`.
    pub dropdown: &'static str,
    /// More content above (dialog scroll marker).
    pub scroll_up: &'static str,
    /// More content below.
    pub scroll_down: &'static str,
    /// Filled part of a progress bar.
    pub bar_full: &'static str,
    /// Empty part of a progress bar.
    pub bar_empty: &'static str,
    /// Encrypted connection (T57 status bar; ASCII segments use brackets instead).
    pub lock: &'static str,
    /// Unencrypted connection.
    pub unlock: &'static str,
    /// Locked vault.
    pub vault_locked: &'static str,
    /// Separator between status-bar segments, with its spaces.
    pub sep: &'static str,
    /// Speed-limit segment.
    pub speed: &'static str,
    /// Filters active.
    pub filter: &'static str,
    /// Synchronized browsing.
    pub sync: &'static str,
    /// Directory comparison.
    pub compare: &'static str,
    /// Sync status (T90).
    pub sync_status: &'static str,
    /// Not connected.
    pub dash: &'static str,
    /// Connecting.
    pub connecting: &'static str,
    /// Download rate.
    pub rate_down: &'static str,
    /// Upload rate.
    pub rate_up: &'static str,
}

const ASCII_BORDER: border::Set<'static> = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

const ASCII_BORDER_FOCUSED: border::Set<'static> = border::Set {
    top_left: "#",
    top_right: "#",
    bottom_left: "#",
    bottom_right: "#",
    vertical_left: "#",
    vertical_right: "#",
    horizontal_top: "=",
    horizontal_bottom: "=",
};

impl Symbols {
    /// The Unicode set.
    pub(crate) fn unicode() -> Self {
        Self {
            unicode: true,
            border: border::PLAIN,
            border_focused: border::THICK,
            focus_marker: "▶",
            expanded: "▾",
            collapsed: "▸",
            dot_on: "●",
            dot_off: "○",
            bullet: "•",
            check: "✓",
            warning: "⚠",
            separator: "│",
            ellipsis: "…",
            spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            radio_on: "(•)",
            radio_off: "( )",
            dropdown: "▾",
            scroll_up: "▲",
            scroll_down: "▼",
            bar_full: "█",
            bar_empty: "░",
            lock: "🔒",
            unlock: "🔓",
            vault_locked: "🔐",
            sep: " │ ",
            speed: "⇅",
            filter: "⚑",
            sync: "⇄",
            compare: "≠",
            sync_status: "⟳",
            dash: "–",
            connecting: "◌",
            rate_down: "↓",
            rate_up: "↑",
        }
    }

    /// The ASCII set.
    pub(crate) fn ascii() -> Self {
        Self {
            unicode: false,
            border: ASCII_BORDER,
            border_focused: ASCII_BORDER_FOCUSED,
            focus_marker: ">",
            expanded: "v",
            collapsed: ">",
            dot_on: "*",
            dot_off: "o",
            bullet: "*",
            check: "+",
            warning: "!",
            separator: "|",
            ellipsis: "~",
            spinner: &["|", "/", "-", "\\"],
            radio_on: "(*)",
            radio_off: "( )",
            dropdown: "v",
            scroll_up: "^",
            scroll_down: "v",
            bar_full: "#",
            bar_empty: "-",
            lock: "[TLS]",
            unlock: "[FTP!]",
            vault_locked: "[L]",
            sep: " | ",
            speed: "lim",
            filter: "[F]",
            sync: "<>",
            compare: "!=",
            sync_status: "sync",
            dash: "-",
            connecting: "..",
            rate_down: "v",
            rate_up: "^",
        }
    }

    /// The set for `setting` in this terminal.
    pub(crate) fn resolve(setting: UnicodeSymbols, env: &TermEnv) -> Self {
        let unicode = match setting {
            UnicodeSymbols::Always => true,
            UnicodeSymbols::Never => false,
            UnicodeSymbols::Auto => env.supports_unicode(),
        };
        if unicode {
            Self::unicode()
        } else {
            Self::ascii()
        }
    }

    /// The spinner frame for `elapsed_ms` (one frame every 100 ms).
    pub(crate) fn spinner_frame(&self, elapsed_ms: u128) -> &'static str {
        let len = self.spinner.len().max(1) as u128;
        let i = usize::try_from((elapsed_ms / 100) % len).unwrap_or(0);
        self.spinner.get(i).copied().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(f: impl FnOnce(&mut TermEnv)) -> TermEnv {
        let mut env = TermEnv {
            term: Some("xterm-256color".into()),
            ..TermEnv::default()
        };
        f(&mut env);
        env
    }

    fn auto(env: &TermEnv) -> bool {
        Symbols::resolve(UnicodeSymbols::Auto, env).unicode
    }

    #[test]
    fn symbols_auto_detection_table() {
        let utf8 = |e: &mut TermEnv| e.lang = Some("en_US.UTF-8".into());
        assert!(auto(&unix(utf8)));
        for term in ["linux", "dumb", "vt100"] {
            assert!(
                !auto(&unix(|e| {
                    utf8(e);
                    e.term = Some(term.into());
                })),
                "{term}"
            );
        }
        assert!(!auto(&unix(|e| e.lang = Some("C".into()))));
        assert!(!auto(&unix(|_| {})), "unset locale");
        assert!(auto(&unix(|e| e.lc_all = Some("en_US.UTF-8".into()))));
        assert!(auto(&unix(|e| e.lc_ctype = Some("de_DE.utf8".into()))));
        // LC_ALL wins over LANG.
        assert!(!auto(&unix(|e| {
            e.lc_all = Some("C".into());
            e.lang = Some("en_US.UTF-8".into());
        })));
        // An empty LC_ALL falls through to LANG.
        assert!(auto(&unix(|e| {
            e.lc_all = Some(String::new());
            e.lang = Some("en_US.UTF-8".into());
        })));
        // Windows: classic console vs Windows Terminal / other terminals.
        let win = |f: &dyn Fn(&mut TermEnv)| {
            let mut e = TermEnv {
                windows: true,
                ..TermEnv::default()
            };
            f(&mut e);
            e
        };
        assert!(!auto(&win(&|_| {})));
        assert!(auto(&win(&|e| e.wt_session = true)));
        assert!(auto(&win(&|e| e.term_program = Some("vscode".into()))));
        // Overrides.
        assert!(
            Symbols::resolve(
                UnicodeSymbols::Always,
                &unix(|e| e.term = Some("dumb".into()))
            )
            .unicode
        );
        assert!(!Symbols::resolve(UnicodeSymbols::Never, &unix(utf8)).unicode);
    }

    #[test]
    fn term_env_over_ssh() {
        assert!(!TermEnv::default().over_ssh());
        assert!(
            TermEnv {
                ssh_connection: true,
                ..TermEnv::default()
            }
            .over_ssh()
        );
        assert!(
            TermEnv {
                ssh_tty: true,
                ..TermEnv::default()
            }
            .over_ssh()
        );
    }

    #[test]
    fn status_glyphs_ascii_set_is_ascii() {
        let a = Symbols::ascii();
        for g in [
            a.lock,
            a.unlock,
            a.vault_locked,
            a.sep,
            a.speed,
            a.filter,
            a.sync,
            a.compare,
            a.sync_status,
            a.dash,
            a.connecting,
            a.rate_down,
            a.rate_up,
        ] {
            assert!(!g.is_empty() && g.is_ascii(), "{g:?}");
        }
        let u = Symbols::unicode();
        assert_eq!((u.lock, u.sep, u.rate_down), ("🔒", " │ ", "↓"));
    }

    #[test]
    fn spinner_frames_advance_every_100ms() {
        let s = Symbols::unicode();
        assert_eq!(s.spinner_frame(0), "⠋");
        assert_eq!(s.spinner_frame(99), "⠋");
        assert_eq!(s.spinner_frame(100), "⠙");
        assert_eq!(s.spinner_frame(1000), "⠋");
        assert_eq!(Symbols::ascii().spinner_frame(400), "|");
    }
}
