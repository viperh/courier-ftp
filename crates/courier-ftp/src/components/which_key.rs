//! The which-key popup: the possible next keys of a pending sequence, drawn above the
//! status bar once the prefix has been pending for
//! [`WHICH_KEY_DELAY`](crate::keymap::resolver::WHICH_KEY_DELAY) (T51).

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::{
    action::Action,
    keymap::chord::KeyChord,
    ui::{symbols::Symbols, text::truncate_to_width, theme::Theme},
};

/// At most this many entries are listed; the rest are counted.
pub(crate) const MAX_ROWS: usize = 16;

/// Draws the popup for `prefix` (`"ctrl-x"`) listing `entries` (sorted by key) at the
/// bottom right of `screen`, above the status bar.
pub(crate) fn draw(
    frame: &mut Frame,
    screen: Rect,
    prefix: &str,
    entries: &[(KeyChord, Action)],
    theme: &Theme,
    symbols: &Symbols,
) {
    if entries.is_empty() || screen.height < 4 || screen.width < 12 {
        return;
    }
    let keys: Vec<String> = entries.iter().map(|(k, _)| k.to_string()).collect();
    let kw = keys.iter().map(|k| k.chars().count()).max().unwrap_or(1);
    let shown = entries.len().min(MAX_ROWS);
    let more = entries.len() - shown;
    let mut lines: Vec<Line<'static>> = entries
        .iter()
        .zip(&keys)
        .take(shown)
        .map(|((_, a), k)| {
            Line::from(vec![
                Span::styled(format!("{k:>kw$}"), theme.style("help_key")),
                Span::raw(format!(" {a}")),
            ])
        })
        .collect();
    if more > 0 {
        lines.push(Line::from(Span::styled(
            format!("{} {more} more (F1)", symbols.ellipsis),
            theme.style("placeholder"),
        )));
    }
    let content_w = lines.iter().map(Line::width).max().unwrap_or(1);
    let title = format!(" {prefix} ");
    let width = u16::try_from(content_w.max(title.chars().count()) + 2)
        .unwrap_or(u16::MAX)
        .min(screen.width);
    // Keep the status bar (last row) visible.
    let avail = screen.height - 1;
    let height = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(avail);
    let area = Rect {
        x: screen.x + screen.width - width,
        y: screen.y + avail - height,
        width,
        height,
    };
    let inner_w = usize::from(width.saturating_sub(2));
    let lines: Vec<Line<'static>> = lines
        .into_iter()
        .map(|l| {
            if l.width() <= inner_w {
                l
            } else {
                let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
                Line::from(truncate_to_width(&text, inner_w, symbols.ellipsis).into_owned())
            }
        })
        .collect();
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(symbols.border)
        .border_style(theme.style("dialog_border"))
        .title(Span::styled(title, theme.style("title_focused")));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
