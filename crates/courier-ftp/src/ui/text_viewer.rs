//! A scrollable, read-only text dialog (T71: "Show raw listing").
//!
//! Server text is shown as is, except control characters, which become `?`
//! (a hostile listing must not drive the terminal), and tabs, which become
//! spaces.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Clear, Paragraph},
};

use super::{
    modal::{Modal, ModalOutcome, centered},
    theme::Theme,
};

/// The dialog.
pub(crate) struct TextViewer {
    title: String,
    lines: Vec<String>,
    scroll: usize,
    hscroll: usize,
    /// Text rows of the last frame, for paging.
    rows: usize,
}

fn clean(line: &str) -> String {
    line.chars()
        .flat_map(|c| match c {
            '\t' => vec![' '; 4],
            c if c.is_control() => vec!['?'],
            c => vec![c],
        })
        .collect()
}

impl TextViewer {
    pub(crate) fn new(title: impl Into<String>, text: &str) -> Self {
        Self {
            title: format!(" {} ", title.into()),
            lines: text
                .split('\n')
                .map(|l| clean(l.trim_end_matches('\r')))
                .collect(),
            scroll: 0,
            hscroll: 0,
            rows: 1,
        }
    }

    fn max_scroll(&self) -> usize {
        self.lines.len().saturating_sub(self.rows)
    }

    fn scroll_by(&mut self, delta: isize) {
        self.scroll = self
            .scroll
            .saturating_add_signed(delta)
            .min(self.max_scroll());
    }
}

impl Modal for TextViewer {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let rect = centered(
            area,
            area.width.saturating_sub(4).max(20),
            area.height.saturating_sub(2).max(5),
        );
        // Two border rows and the hint row.
        self.rows = usize::from(rect.height.saturating_sub(3)).max(1);
        self.scroll = self.scroll.min(self.max_scroll());
        let mut body: Vec<Line> = self
            .lines
            .iter()
            .skip(self.scroll)
            .take(self.rows)
            .map(|l| Line::raw(l.chars().skip(self.hscroll).collect::<String>()))
            .collect();
        body.resize(self.rows, Line::raw(""));
        let total = self.lines.len();
        let last = (self.scroll + self.rows).min(total);
        body.push(Line::styled(
            format!(
                "{}–{last} of {total} · ↑/↓ PgUp/PgDn Home/End scroll · ←/→ sideways · Esc closes",
                (self.scroll + 1).min(total)
            ),
            theme.dim,
        ));
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(body).block(
                Block::bordered()
                    .title(self.title.as_str())
                    .border_style(theme.focused_border),
            ),
            rect,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        let page = isize::try_from(self.rows).unwrap_or(isize::MAX);
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => return ModalOutcome::Close,
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll_by(page),
            KeyCode::Char('d') if ctrl => self.scroll_by(page / 2),
            KeyCode::Char('u') if ctrl => self.scroll_by(-(page / 2)),
            KeyCode::PageUp => self.scroll_by(-page),
            KeyCode::Home | KeyCode::Char('g') => self.scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.scroll = self.max_scroll(),
            KeyCode::Right | KeyCode::Char('l') => self.hscroll += 8,
            KeyCode::Left | KeyCode::Char('h') => self.hscroll = self.hscroll.saturating_sub(8),
            _ => {}
        }
        ModalOutcome::Keep
    }
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn render(v: &mut TextViewer, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| v.draw(f, f.area(), &Theme::default())).unwrap();
        t.backend().to_string()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn scrolls_and_cleans_control_characters() {
        let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
        let mut v = TextViewer::new("Raw listing of /srv", &format!("\x1b[31mred\t|{text}"));
        let screen = render(&mut v, 60, 12);
        assert!(screen.contains("Raw listing of /srv"), "{screen}");
        assert!(screen.contains("?[31mred    |line 0"), "{screen}");
        assert!(!screen.contains('\x1b'));
        assert!(screen.contains("1–7 of 101"), "{screen}");

        v.handle_key(key(KeyCode::PageDown));
        let screen = render(&mut v, 60, 12);
        assert!(screen.contains("line 9 "), "{screen}");
        v.handle_key(key(KeyCode::End));
        let screen = render(&mut v, 60, 12);
        assert!(screen.contains("line 99"), "{screen}");
        assert!(screen.contains("95–101 of 101"), "{screen}");
        v.handle_key(key(KeyCode::Down));
        assert!(render(&mut v, 60, 12).contains("95–101 of 101"));
        v.handle_key(key(KeyCode::Home));
        v.handle_key(key(KeyCode::Right));
        assert!(render(&mut v, 60, 12).contains("|line 0"));
        assert_eq!(v.handle_key(key(KeyCode::Char('x'))), ModalOutcome::Keep);
        assert_eq!(v.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    }

    #[test]
    fn tiny_terminal_and_empty_text_draw() {
        let mut v = TextViewer::new("x", "");
        render(&mut v, 3, 2);
        render(&mut v, 40, 8);
    }
}
