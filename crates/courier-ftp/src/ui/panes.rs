//! Shared pane helpers and the remaining T50 shells: the queue (T56) and
//! tab bar (T61) tasks replace their bodies.

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

pub(crate) fn draw_queue(frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(Line::styled("The queue is empty.", theme.dim)).block(block(
            " Queue (0) · Failed (0) · Successful (0) ",
            focused,
            theme,
        )),
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
