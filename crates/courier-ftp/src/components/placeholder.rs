//! Stand-in for a region whose component has not landed yet (T53–T58, T61).

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Component, DrawCx, region_block};
use crate::{app::Mode, components::main_screen::layout::Region};

/// A bordered block titled with the region name and a dim `(not available yet)`.
/// It is focusable where the real component will be.
#[derive(Debug)]
pub(crate) struct Placeholder {
    region: Region,
}

impl Placeholder {
    /// A placeholder for `region`.
    pub(crate) fn new(region: Region) -> Self {
        Self { region }
    }
}

const NOT_YET: &str = "(not available yet)";

impl Component for Placeholder {
    fn key_mode(&self) -> Mode {
        match self.region {
            Region::LocalList | Region::RemoteList => Mode::FileList,
            Region::LocalTree | Region::RemoteTree => Mode::Tree,
            Region::Log => Mode::Log,
            Region::Queue => Mode::Queue,
            // No text field until T58: the global table applies.
            Region::Quickconnect => Mode::Normal,
            Region::TabBar | Region::StatusBar => Mode::Normal,
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()> {
        let dim = cx.theme.style("placeholder");
        if area.height < 3 {
            // One-row regions (quickconnect): no border.
            let marker = if cx.focused {
                cx.symbols.focus_marker
            } else {
                " "
            };
            let title_style = if cx.focused {
                cx.theme.style("title_focused")
            } else {
                cx.theme.style("title")
            };
            let line = Line::from(vec![
                Span::styled(marker, cx.theme.style("border_focused")),
                Span::styled(self.region.name(), title_style),
                Span::raw(" "),
                Span::styled(NOT_YET, dim),
            ]);
            frame.render_widget(Paragraph::new(line), area);
            return Ok(());
        }
        let block = region_block(self.region.name(), cx);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(NOT_YET, dim))).block(block),
            area,
        );
        Ok(())
    }
}
