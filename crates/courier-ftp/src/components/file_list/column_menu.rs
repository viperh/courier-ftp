//! The column menu (`C`): a checkbox list of the columns; `space` toggles visibility,
//! `K`/`J` reorder, `Enter` applies, `Esc` cancels. Name stays visible.

use std::borrow::Cow;

use courier_ftp_core::settings::{Column, ColumnSpec};
use ratatui::{Frame, layout::Rect, text::Span, widgets::Paragraph};

use super::columns::{normalize, title};
use crate::{
    action::Action,
    components::{
        DrawCx,
        dialog::{Dialog, DialogSize, DialogStep, widget_cx},
        widgets::{ListRow, ListView, Widget, WidgetOutcome},
    },
    keymap::chord::KeyChord,
};

/// The column menu dialog.
#[derive(Debug)]
pub(crate) struct ColumnMenuDialog {
    list: ListView<Column>,
}

impl ColumnMenuDialog {
    /// The menu for `columns` (normalised: every column appears once).
    pub(crate) fn new(columns: &[ColumnSpec]) -> Self {
        let mut specs = normalize(columns);
        for c in Column::ALL {
            if !specs.iter().any(|s| s.column == c) {
                specs.push(ColumnSpec {
                    column: c,
                    visible: false,
                });
            }
        }
        let rows = specs
            .iter()
            .map(|s| ListRow::check(title(s.column), s.column, s.visible))
            .collect();
        Self {
            list: ListView::new(rows).reorderable(true).visible_rows(6),
        }
    }

    /// The configuration as shown.
    pub(crate) fn result(&self) -> Vec<ColumnSpec> {
        let specs: Vec<ColumnSpec> = self
            .list
            .rows()
            .iter()
            .filter_map(|r| match r {
                ListRow::Item { value, checked, .. } => Some(ColumnSpec {
                    column: *value,
                    visible: checked.unwrap_or(false),
                }),
                ListRow::Header(_) => None,
            })
            .collect();
        normalize(&specs)
    }
}

impl Dialog for ColumnMenuDialog {
    type Output = Vec<ColumnSpec>;

    fn kind(&self) -> &'static str {
        "column_menu"
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed("Columns")
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: 36,
            max_w: 50,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        (max_width.min(40), 8)
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<Self::Output> {
        match self.list.handle_key(key) {
            WidgetOutcome::Activated => DialogStep::Close(Some(self.result())),
            WidgetOutcome::Ignored => DialogStep::Ignored,
            _ => DialogStep::Continue,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<Self::Output> {
        match action {
            Action::DialogSubmit => DialogStep::Close(Some(self.result())),
            _ => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let list_h = area.height.saturating_sub(2);
        self.list.render(
            frame,
            Rect {
                height: list_h,
                ..area
            },
            &widget_cx(cx, true, true),
        );
        if area.height >= 2 {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "space show/hide · K/J move · enter apply",
                    cx.theme.style("field_help"),
                )),
                Rect::new(area.x, area.bottom() - 1, area.width, 1),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_and_reorder() {
        let mut d =
            ColumnMenuDialog::new(&courier_ftp_core::settings::PaneColumns::default().local);
        // Cursor on Name: space keeps it visible (normalised).
        let _ = d.handle_key(KeyChord::char(' '));
        let _ = d.handle_key(KeyChord::char('j'));
        let _ = d.handle_key(KeyChord::char(' ')); // hide Size
        let _ = d.handle_key(KeyChord::char('J')); // move Size below Type
        let r = d.result();
        assert_eq!(
            r[0],
            ColumnSpec {
                column: Column::Name,
                visible: true
            }
        );
        assert_eq!(r[1].column, Column::Type);
        assert_eq!(
            r[2],
            ColumnSpec {
                column: Column::Size,
                visible: false
            }
        );
        assert_eq!(r.len(), 6);
    }
}
