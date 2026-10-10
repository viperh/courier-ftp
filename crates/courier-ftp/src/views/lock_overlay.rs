//! The lock overlay (sverb `views/lock_overlay.rs`, D13): while the vault is locked it
//! covers everything but the status bar, so nothing decrypted (and no server data) is
//! visible. The unlock box is drawn on top.

use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Clear, Paragraph},
};

use super::Look;

/// Cover `area` with the overlay. `quit_hint` is the Quit key (`Ctrl-q`). Infallible
/// at any size.
pub(crate) fn render(frame: &mut Frame<'_>, area: Rect, look: Look<'_>, quit_hint: &str) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .border_set(look.symbols.border)
        .border_style(look.style("overlay"))
        .style(look.style("text"));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = vec![
        Line::styled(
            format!("{} Vault locked", look.lock()),
            look.style("overlay"),
        ),
        Line::styled(
            look.text(&format!("{quit_hint} quit")).into_owned(),
            look.style("overlay"),
        ),
    ];
    // At the top: the unlock box sits in the middle of the screen.
    frame.render_widget(Paragraph::new(lines).centered(), inner);
}
