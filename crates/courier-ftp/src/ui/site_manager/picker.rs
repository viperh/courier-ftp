//! The site picker (FileZilla's Site Manager dropdown): type part of a
//! site's name, `Enter` connects to the best match.

use courier_ftp_core::{model::item::ItemId, sites::SiteTree};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::sync::oneshot;

use crate::ui::{
    dialog::{Field, TextInput, dialog_frame_styled},
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

/// Every site with its path (`Work/Production/web01`), in tree order.
pub(crate) fn site_paths(tree: &SiteTree) -> Vec<(ItemId, String)> {
    tree.sites()
        .filter_map(|s| tree.path_of(s.id).map(|p| (s.id, p)))
        .collect()
}

/// How well `query` matches `path` (higher is better), or `None`. The
/// query's characters must appear in order (case-insensitive); matches in
/// the site's own name, at the start of a word and in runs score higher.
pub(crate) fn score(query: &str, path: &str) -> Option<i64> {
    let query: Vec<char> = query
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if query.is_empty() {
        return Some(0);
    }
    let lower: Vec<char> = path.to_lowercase().chars().collect();
    let name_start = lower.iter().rposition(|c| *c == '/').map_or(0, |i| i + 1);
    let mut score = 0i64;
    let mut qi = 0;
    let mut last: Option<usize> = None;
    for (i, c) in lower.iter().enumerate() {
        if qi < query.len() && *c == query[qi] {
            score += 1;
            if i >= name_start {
                score += 4;
            }
            if i == name_start || i == 0 || matches!(lower[i - 1], '/' | ' ' | '-' | '_' | '.') {
                score += 6;
            }
            if last.is_some_and(|l| l + 1 == i) {
                score += 5;
            }
            last = Some(i);
            qi += 1;
        }
    }
    (qi == query.len()).then(|| score - i64::try_from(lower.len()).unwrap_or(0) / 8)
}

/// The picker dialog. Answers the chosen site's id.
pub(crate) struct SitePicker {
    query: TextInput,
    sites: Vec<(ItemId, String)>,
    matches: Vec<usize>,
    cursor: usize,
    reply: Option<oneshot::Sender<Option<ItemId>>>,
}

impl SitePicker {
    fn refresh(&mut self) {
        let q = self.query.text();
        let mut scored: Vec<(i64, usize)> = self
            .sites
            .iter()
            .enumerate()
            .filter_map(|(i, (_, p))| score(&q, p).map(|s| (s, i)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        self.matches = scored.into_iter().map(|(_, i)| i).collect();
        self.cursor = 0;
    }

    fn finish(&mut self, value: Option<ItemId>) -> ModalOutcome {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(value);
        }
        ModalOutcome::Close
    }
}

/// The picker over `sites` ([`site_paths`]).
pub(crate) fn site_picker(
    sites: Vec<(ItemId, String)>,
) -> (Box<dyn Modal>, oneshot::Receiver<Option<ItemId>>) {
    let (tx, rx) = oneshot::channel();
    let mut picker = SitePicker {
        query: TextInput::new("Site:").with_placeholder("type part of a site's name"),
        sites,
        matches: Vec::new(),
        cursor: 0,
        reply: Some(tx),
    };
    picker.refresh();
    (Box::new(picker), rx)
}

impl Modal for SitePicker {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let rows = u16::try_from(self.matches.len())
            .unwrap_or(u16::MAX)
            .clamp(1, 12);
        let Some(inner) = dialog_frame_styled(
            frame,
            area,
            "Connect to site",
            60,
            rows + 4,
            theme,
            theme.focused_border,
        ) else {
            return;
        };
        frame.render_widget(
            Paragraph::new(Span::styled("Site: ", theme.title)),
            Rect::new(inner.x, inner.y, 6, 1),
        );
        self.query.draw(
            frame,
            Rect::new(inner.x + 6, inner.y, inner.width.saturating_sub(6), 1),
            true,
            theme,
        );
        let list = Rect::new(inner.x, inner.y + 2, inner.width, rows);
        let lines: Vec<Line> = if self.matches.is_empty() {
            vec![Line::styled("No matching site", theme.dim)]
        } else {
            let start = self.cursor.saturating_sub(usize::from(rows) - 1);
            self.matches
                .iter()
                .enumerate()
                .skip(start)
                .take(usize::from(rows))
                .map(|(i, &m)| {
                    let line = Line::raw(self.sites[m].1.clone());
                    if i == self.cursor {
                        line.style(theme.selection)
                    } else {
                        line
                    }
                })
                .collect()
        };
        frame.render_widget(Paragraph::new(lines), list);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Enter connect · ↑/↓ choose · Esc cancel",
                theme.dim,
            )),
            Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => return self.finish(None),
            KeyCode::Enter => {
                let pick = self.matches.get(self.cursor).map(|&m| self.sites[m].0);
                return match pick {
                    Some(id) => self.finish(Some(id)),
                    None => ModalOutcome::Keep,
                };
            }
            KeyCode::Down | KeyCode::Tab => {
                self.cursor = (self.cursor + 1).min(self.matches.len().saturating_sub(1));
            }
            KeyCode::Char('n') if ctrl => {
                self.cursor = (self.cursor + 1).min(self.matches.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::BackTab => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Char('p') if ctrl => self.cursor = self.cursor.saturating_sub(1),
            _ => {
                let before = self.query.text();
                self.query.handle_key(key);
                if self.query.text() != before {
                    self.refresh();
                }
            }
        }
        ModalOutcome::Keep
    }

    fn handle_paste(&mut self, text: &str) {
        self.query.handle_paste(text);
        self.refresh();
    }
}
