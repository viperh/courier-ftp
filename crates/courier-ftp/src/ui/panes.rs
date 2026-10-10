//! Shared pane helpers and the remaining T50 shell: the tab bar (T61 replaces
//! its body).

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Paragraph},
};

use super::theme::Theme;

/// Braille spinner shown in a pane title while it waits for the network.
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub(crate) fn spinner_frame(tick: u64) -> char {
    SPINNER[(tick % SPINNER.len() as u64) as usize]
}

pub(crate) fn block<'a>(title: impl Into<Line<'a>>, focused: bool, theme: &Theme) -> Block<'a> {
    Block::bordered().title(title).border_style(if focused {
        theme.focused_border
    } else {
        theme.border
    })
}

pub(crate) fn draw_tabs(frame: &mut Frame, area: Rect, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Tabs: ", theme.dim),
            Span::styled("[1 local]", theme.title),
        ])),
        area,
    );
}

pub(crate) fn draw_hint(frame: &mut Frame, area: Rect, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            "Small terminal: one pane at a time, Tab switches",
            theme.dim,
        )),
        area,
    );
}
