//! The splash screen (T74, `interface.show_splash`): the logo, the version
//! and "loading…" over the whole screen while the app starts.

use std::time::{Duration, Instant};

use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Clear, Paragraph},
};

use super::theme::Theme;

/// Shown at least this long (unless a key skips it).
pub(crate) const MIN_SHOWN: Duration = Duration::from_secs(1);
/// Never longer than this, even if startup is still busy.
pub(crate) const MAX_SHOWN: Duration = Duration::from_secs(5);

/// "courier-ftp"; every line the same width so they stay aligned when
/// centred.
const LOGO: &[&str] = &[
    r" _   _       _       _   _       _  ___  _ ",
    r"|   | | | | |_)  |  |_  |_)  _  |_   |  |_)",
    r"|_  |_| |_| | \  |  |_  | \     |    |  |  ",
];

/// The splash screen.
pub(crate) struct Splash {
    version: String,
    shown_at: Instant,
}

impl Splash {
    pub(crate) fn new(version: impl Into<String>, now: Instant) -> Self {
        Self {
            version: version.into(),
            shown_at: now,
        }
    }

    /// Whether to take it down: after [`MIN_SHOWN`] once startup is done,
    /// after [`MAX_SHOWN`] in any case.
    pub(crate) fn expired(&self, now: Instant, starting: bool) -> bool {
        let shown = now.saturating_duration_since(self.shown_at);
        shown >= MAX_SHOWN || (shown >= MIN_SHOWN && !starting)
    }

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        frame.render_widget(Clear, area);
        let wide = LOGO
            .iter()
            .all(|l| l.chars().count() <= usize::from(area.width));
        let mut lines: Vec<Line> = if wide {
            LOGO.iter()
                .map(|l| Line::styled(*l, theme.focused_border))
                .collect()
        } else {
            vec![Line::styled("courier-ftp", theme.focused_border)]
        };
        lines.push(Line::raw(""));
        lines.push(Line::raw(format!("v{}", self.version)));
        lines.push(Line::raw(""));
        lines.push(Line::styled("loading…", theme.dim));
        let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
        let top = area.y + area.height.saturating_sub(height) / 2;
        let rect = Rect::new(
            area.x,
            top,
            area.width,
            height.min(area.bottom().saturating_sub(top)),
        );
        frame.render_widget(Paragraph::new(lines).centered(), rect);
    }
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn render(width: u16, height: u16) -> String {
        let splash = Splash::new("1.2.3", Instant::now());
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|f| splash.draw(f, f.area(), &Theme::new(None, true)))
            .unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn splash_screen() {
        insta::assert_snapshot!(render(80, 24));
    }

    #[test]
    fn splash_screen_narrow() {
        // Too narrow for the logo: the name instead.
        insta::assert_snapshot!(render(30, 10));
    }

    #[test]
    fn splash_timing() {
        let t = Instant::now();
        let s = Splash::new("1.2.3", t);
        assert!(!s.expired(t, false));
        assert!(!s.expired(t + MIN_SHOWN - Duration::from_millis(1), false));
        assert!(s.expired(t + MIN_SHOWN, false));
        assert!(!s.expired(t + MIN_SHOWN, true));
        assert!(!s.expired(t + MAX_SHOWN - Duration::from_millis(1), true));
        assert!(s.expired(t + MAX_SHOWN, true));
    }
}
