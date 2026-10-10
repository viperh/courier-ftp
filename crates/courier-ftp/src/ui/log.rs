//! The message log pane (T55): protocol commands and replies, status and
//! errors, coloured by kind.
//!
//! A ring buffer of the last N lines. The view follows new lines until the
//! user scrolls up; then a "▼ N new" marker counts what arrived, and `G`
//! (Bottom) resumes following. `/` searches (`n`/`N` jump between matches,
//! which are highlighted), `v` starts a range, `y` copies the cursor line or
//! range, `w` wraps long lines (otherwise `h`/`l` scroll sideways), `e` shows
//! only errors, `t` shows every session instead of only the current tab's.
//! `Y` copies and `S` saves ("Save log as…") every line the filters show (T71).

use std::collections::{HashSet, VecDeque};

use courier_ftp_core::events::{LogKind, LogMessage, SessionId};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use time::{UtcOffset, macros::format_description};

use super::{panes::block, theme::Theme};
use crate::action::Action;

#[derive(Debug, Clone)]
struct Stored {
    seq: u64,
    msg: LogMessage,
}

#[derive(Debug, Clone, Default)]
struct Search {
    query: String,
    /// Still typing the query.
    editing: bool,
}

/// The message log.
#[derive(Debug)]
pub(crate) struct LogPane {
    lines: VecDeque<Stored>,
    capacity: usize,
    next_seq: u64,
    show_timestamps: bool,
    offset: UtcOffset,
    /// `None` = follow the newest line.
    cursor: Option<u64>,
    unseen: usize,
    anchor: Option<u64>,
    search: Option<Search>,
    wrap: bool,
    hscroll: usize,
    errors_only: bool,
    /// The sessions of the current tab (T61); `None` shows everything.
    sessions: Option<HashSet<SessionId>>,
    show_all: bool,
    /// Rows of the last frame, for paging.
    rows: usize,
}

const PREFIX_WIDTH: usize = 10;

fn prefix(kind: LogKind) -> &'static str {
    courier_ftp_core::logfile::kind_label(kind)
}

impl LogPane {
    pub(crate) fn new(capacity: usize, show_timestamps: bool, offset: UtcOffset) -> Self {
        Self {
            lines: VecDeque::new(),
            capacity: capacity.max(1),
            next_seq: 0,
            show_timestamps,
            offset,
            cursor: None,
            unseen: 0,
            anchor: None,
            search: None,
            wrap: false,
            hscroll: 0,
            errors_only: false,
            sessions: None,
            show_all: false,
            rows: 1,
        }
    }

    /// Add a line, dropping the oldest when full.
    pub(crate) fn push(&mut self, msg: LogMessage) {
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
        }
        let visible = self.passes(&msg);
        self.lines.push_back(Stored {
            seq: self.next_seq,
            msg,
        });
        self.next_seq += 1;
        if self.cursor.is_some() && visible {
            self.unseen += 1;
        }
        // A cursor on a line that fell out of the buffer moves to the oldest.
        if let (Some(c), Some(first)) = (self.cursor, self.lines.front())
            && c < first.seq
        {
            self.cursor = Some(first.seq);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    #[cfg(test)]
    pub(crate) fn is_following(&self) -> bool {
        self.cursor.is_none()
    }

    /// Show only these sessions (the current tab's), unless "all" is on.
    #[cfg_attr(not(test), expect(dead_code, reason = "per-tab logs arrive with T61"))]
    pub(crate) fn set_sessions(&mut self, sessions: Option<HashSet<SessionId>>) {
        self.sessions = sessions;
    }

    pub(crate) fn is_searching(&self) -> bool {
        self.search.as_ref().is_some_and(|s| s.editing)
    }

    fn passes(&self, msg: &LogMessage) -> bool {
        if self.errors_only && msg.kind != LogKind::Error {
            return false;
        }
        match (&self.sessions, self.show_all) {
            (Some(set), false) => set.contains(&msg.session),
            _ => true,
        }
    }

    /// Indices (into `lines`) of the lines currently shown.
    fn view(&self) -> Vec<usize> {
        (0..self.lines.len())
            .filter(|&i| self.passes(&self.lines[i].msg))
            .collect()
    }

    /// Position of the cursor in `view`.
    fn cursor_pos(&self, view: &[usize]) -> Option<usize> {
        if view.is_empty() {
            return None;
        }
        Some(match self.cursor {
            None => view.len() - 1,
            Some(seq) => view
                .iter()
                .position(|&i| self.lines[i].seq >= seq)
                .unwrap_or(view.len() - 1),
        })
    }

    fn set_cursor(&mut self, view: &[usize], pos: usize) {
        if view.is_empty() {
            self.cursor = None;
            return;
        }
        let pos = pos.min(view.len() - 1);
        if pos == view.len() - 1 && self.anchor.is_none() {
            self.follow();
        } else {
            self.cursor = Some(self.lines[view[pos]].seq);
        }
    }

    fn follow(&mut self) {
        self.cursor = None;
        self.unseen = 0;
    }

    fn move_by(&mut self, delta: isize) {
        let view = self.view();
        if let Some(pos) = self.cursor_pos(&view) {
            let target = pos.saturating_add_signed(delta);
            self.set_cursor(&view, target);
        }
    }

    /// The text of a line as shown (and copied).
    fn format(&self, msg: &LogMessage) -> String {
        let mut s = String::new();
        if self.show_timestamps {
            let format = format_description!("[hour]:[minute]:[second]");
            if let Ok(t) = msg.time.to_offset(self.offset).format(&format) {
                s.push_str(&t);
                s.push_str("  ");
            }
        }
        s.push_str(&format!("{:<PREFIX_WIDTH$}", prefix(msg.kind)));
        s.push_str(&msg.text);
        s
    }

    fn matches(&self, i: usize) -> bool {
        match &self.search {
            Some(s) if !s.query.is_empty() => self.lines[i]
                .msg
                .text
                .to_lowercase()
                .contains(&s.query.to_lowercase()),
            _ => false,
        }
    }

    fn jump_to_match(&mut self, forward: bool) {
        let view = self.view();
        let Some(pos) = self.cursor_pos(&view) else {
            return;
        };
        let n = view.len();
        let found = (1..=n)
            .map(|step| {
                if forward {
                    (pos + step) % n
                } else {
                    (pos + n - step % n) % n
                }
            })
            .find(|&p| self.matches(view[p]));
        if let Some(p) = found {
            self.cursor = Some(self.lines[view[p]].seq);
        }
    }

    /// Keys while typing a search query. Returns `false` when not searching.
    pub(crate) fn handle_search_key(&mut self, key: KeyEvent) -> bool {
        let Some(search) = self.search.as_mut().filter(|s| s.editing) else {
            return false;
        };
        match key.code {
            KeyCode::Esc => self.search = None,
            KeyCode::Enter => {
                search.editing = false;
                self.jump_to_match(false);
            }
            KeyCode::Backspace => {
                search.query.pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                search.query.push(c);
            }
            _ => {}
        }
        true
    }

    /// Apply a navigation or log action. May return a follow-up action.
    pub(crate) fn update(&mut self, action: &Action) -> Option<Action> {
        let page = self.rows.max(1) as isize;
        match action {
            Action::CursorDown => self.move_by(1),
            Action::CursorUp => self.move_by(-1),
            Action::PageDown => self.move_by(page),
            Action::PageUp => self.move_by(-page),
            Action::HalfPageDown => self.move_by(page / 2),
            Action::HalfPageUp => self.move_by(-(page / 2)),
            Action::Top => {
                let view = self.view();
                if !view.is_empty() {
                    self.cursor = Some(self.lines[view[0]].seq);
                }
            }
            Action::Bottom => {
                self.anchor = None;
                self.follow();
            }
            Action::QuickFilter => {
                self.search = Some(Search {
                    query: String::new(),
                    editing: true,
                });
            }
            Action::SearchNext => self.jump_to_match(true),
            Action::SearchPrev => self.jump_to_match(false),
            Action::VisualSelect => {
                self.anchor = match self.anchor {
                    Some(_) => None,
                    None => {
                        let view = self.view();
                        self.cursor_pos(&view).map(|p| self.lines[view[p]].seq)
                    }
                };
                if let Some(a) = self.anchor {
                    self.cursor.get_or_insert(a);
                }
            }
            Action::CopySelection => {
                let text = self.selected_text();
                self.anchor = None;
                if !text.is_empty() {
                    return Some(Action::CopyToClipboard(text));
                }
            }
            Action::CopyLog | Action::SaveLog => {
                let text = self.all_text();
                if text.is_empty() {
                    return None;
                }
                return Some(if matches!(action, Action::CopyLog) {
                    Action::CopyToClipboard(text)
                } else {
                    Action::SaveLogText(text)
                });
            }
            Action::ClearLog => {
                self.lines.clear();
                self.anchor = None;
                self.follow();
            }
            Action::ToggleWrap => {
                self.wrap = !self.wrap;
                self.hscroll = 0;
            }
            Action::ToggleLogAll => self.show_all = !self.show_all,
            Action::ToggleErrorsOnly => self.errors_only = !self.errors_only,
            Action::ScrollLeft => self.hscroll = self.hscroll.saturating_sub(8),
            Action::ScrollRight if !self.wrap => self.hscroll += 8,
            _ => {}
        }
        None
    }

    /// Every line the filters show, as copied or saved text (T71).
    fn all_text(&self) -> String {
        self.view()
            .iter()
            .map(|&i| self.format(&self.lines[i].msg))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The cursor line, or the visual range, as copied text.
    fn selected_text(&self) -> String {
        let view = self.view();
        let Some(cur) = self.cursor_pos(&view) else {
            return String::new();
        };
        let start = self
            .anchor
            .and_then(|a| view.iter().position(|&i| self.lines[i].seq >= a))
            .unwrap_or(cur);
        let (lo, hi) = (start.min(cur), start.max(cur));
        view[lo..=hi]
            .iter()
            .map(|&i| self.format(&self.lines[i].msg))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(crate) fn draw(&mut self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let mut title = vec![Span::styled(" Message log ", theme.title)];
        if self.errors_only {
            title.push(Span::styled("(errors) ", theme.key_hint));
        }
        if self.show_all && self.sessions.is_some() {
            title.push(Span::styled("(all sessions) ", theme.key_hint));
        }
        if let Some(s) = &self.search {
            let cursor = if s.editing { "▏" } else { "" };
            title.push(Span::styled(
                format!("/{}{cursor} ", s.query),
                theme.key_hint,
            ));
        }
        if self.cursor.is_some() && self.unseen > 0 {
            title.push(Span::styled(
                format!("▼ {} new ", self.unseen),
                theme.key_hint,
            ));
        }
        let block = block(Line::from(title), focused, theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let rows = usize::from(inner.height);
        let width = usize::from(inner.width).max(1);
        self.rows = rows;
        if rows == 0 {
            return;
        }

        let view = self.view();
        if view.is_empty() {
            return;
        }
        let cursor = self.cursor_pos(&view);
        let selection = match (self.anchor, cursor) {
            (Some(a), Some(c)) => {
                let a = view
                    .iter()
                    .position(|&i| self.lines[i].seq >= a)
                    .unwrap_or(c);
                Some((a.min(c), a.max(c)))
            }
            _ => None,
        };

        // Build rows from the cursor (or the bottom) upwards.
        let last = cursor.unwrap_or(0);
        let mut out: Vec<Line> = Vec::new();
        let mut pos = last as isize;
        // When paused, keep the cursor in the middle third if possible.
        let below = if self.cursor.is_some() {
            (rows / 3).min(view.len().saturating_sub(last + 1))
        } else {
            0
        };
        let mut lower: Vec<Line> = Vec::new();
        for p in last + 1..=last + below {
            if let Some(&i) = view.get(p) {
                lower.extend(self.render_rows(i, p, cursor, selection, focused, width, theme));
            }
        }
        lower.truncate(rows);
        let budget = rows - lower.len();
        while pos >= 0 && out.len() < budget {
            let p = pos as usize;
            let mut rendered =
                self.render_rows(view[p], p, cursor, selection, focused, width, theme);
            while let Some(line) = rendered.pop() {
                if out.len() < budget {
                    out.push(line);
                }
            }
            pos -= 1;
        }
        out.reverse();
        out.extend(lower);
        frame.render_widget(Paragraph::new(out), inner);
    }

    #[allow(clippy::too_many_arguments)]
    fn render_rows(
        &self,
        i: usize,
        pos: usize,
        cursor: Option<usize>,
        selection: Option<(usize, usize)>,
        focused: bool,
        width: usize,
        theme: &Theme,
    ) -> Vec<Line<'static>> {
        let msg = &self.lines[i].msg;
        let mut style = theme.log(msg.kind);
        if msg.kind == LogKind::Error {
            style = style.add_modifier(Modifier::BOLD);
        }
        let selected = selection.is_some_and(|(lo, hi)| (lo..=hi).contains(&pos));
        let at_cursor = focused && cursor == Some(pos) && self.cursor.is_some();
        if selected || at_cursor {
            style = style.patch(theme.selection);
        }
        let text: Vec<char> = self.format(msg).chars().collect();
        let chunks: Vec<String> = if self.wrap {
            text.chunks(width).map(|c| c.iter().collect()).collect()
        } else {
            vec![text.iter().skip(self.hscroll).take(width).collect()]
        };
        let query = self
            .search
            .as_ref()
            .map(|s| s.query.to_lowercase())
            .filter(|q| !q.is_empty());
        chunks
            .into_iter()
            .map(|chunk| highlight(chunk, query.as_deref(), style, theme.selection))
            .collect()
    }
}

/// `text` in `style`, with case-insensitive matches of `query` reversed.
fn highlight(text: String, query: Option<&str>, style: Style, hit: Style) -> Line<'static> {
    let Some(q) = query else {
        return Line::styled(text, style);
    };
    let lower = text.to_lowercase();
    if lower.len() != text.len() {
        // Lower-casing changed byte lengths; skip highlighting this line.
        return Line::styled(text, style);
    }
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(found) = lower[at..].find(q) {
        let start = at + found;
        let end = start + q.len();
        if start > at {
            spans.push(Span::styled(text[at..start].to_owned(), style));
        }
        spans.push(Span::styled(
            text[start..end].to_owned(),
            style.patch(hit).add_modifier(Modifier::REVERSED),
        ));
        at = end;
    }
    spans.push(Span::styled(text[at..].to_owned(), style));
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use ratatui::{Terminal, backend::TestBackend, style::Color};
    use time::macros::datetime;

    use super::*;

    fn msg(kind: LogKind, text: &str) -> LogMessage {
        LogMessage {
            time: datetime!(2026-10-10 12:34:56 UTC),
            session: SessionId(1),
            kind,
            text: text.to_owned(),
        }
    }

    fn pane() -> LogPane {
        LogPane::new(5000, true, UtcOffset::UTC)
    }

    fn render(p: &mut LogPane, w: u16, h: u16, theme: &Theme) -> Terminal<TestBackend> {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| p.draw(f, f.area(), true, theme)).unwrap();
        t
    }

    fn every_kind() -> LogPane {
        let mut p = pane();
        p.push(msg(LogKind::Status, "Connecting to 203.0.113.5:21..."));
        p.push(msg(LogKind::Response, "220 Welcome"));
        p.push(msg(LogKind::Command, "USER alice"));
        p.push(msg(LogKind::Command, "PASS ****"));
        p.push(msg(LogKind::Error, "530 Login incorrect."));
        p.push(msg(LogKind::Debug(3), "using EPSV"));
        p.push(msg(
            LogKind::ListingRaw,
            "drwxr-xr-x 2 alice users 4096 Jan 05 2021 www",
        ));
        p
    }

    #[test]
    fn every_kind_has_its_prefix_and_colour() {
        let theme = Theme::default();
        let mut p = every_kind();
        let t = render(&mut p, 80, 9, &theme);
        insta::assert_snapshot!("log_every_kind", t.backend());
        let buf = t.backend().buffer();
        // Column 10 is the first prefix character after "HH:MM:SS  ".
        let fg = |row: u16| buf[(11, row)].fg;
        assert_eq!(fg(1), theme.log_status.fg.unwrap_or(Color::Reset));
        assert_eq!(fg(2), Color::Green);
        assert_eq!(fg(3), Color::Cyan);
        assert_eq!(fg(5), Color::Red);
        assert!(
            buf[(11, 5)].modifier.contains(Modifier::BOLD),
            "errors are bold"
        );
        assert_eq!(fg(6), Color::DarkGray);
    }

    #[test]
    fn empty_and_tiny_logs_draw() {
        let theme = Theme::new(None, true);
        let mut p = pane();
        render(&mut p, 40, 5, &theme);
        render(&mut p, 2, 2, &theme);
        p.update(&Action::CursorUp);
        p.update(&Action::Top);
        p.update(&Action::SearchNext);
        assert_eq!(p.update(&Action::CopySelection), None);
        p.push(msg(LogKind::Status, "x"));
        render(&mut p, 1, 1, &theme);
        render(&mut p, 20, 3, &theme);
    }

    #[test]
    fn timestamps_are_optional() {
        let theme = Theme::new(None, true);
        let mut p = LogPane::new(10, false, UtcOffset::UTC);
        p.push(msg(LogKind::Status, "hi"));
        let t = render(&mut p, 40, 3, &theme);
        assert!(t.backend().to_string().contains("│Status:   hi"));
    }

    #[test]
    fn ring_buffer_caps_memory() {
        let mut p = LogPane::new(100, false, UtcOffset::UTC);
        for i in 0..10_000 {
            p.push(msg(LogKind::Status, &i.to_string()));
        }
        assert_eq!(p.len(), 100);
        assert_eq!(p.lines.front().unwrap().msg.text, "9900");
    }

    #[test]
    fn follows_until_scrolled_up_then_counts_new_lines() {
        let theme = Theme::new(None, true);
        let mut p = pane();
        for i in 0..20 {
            p.push(msg(LogKind::Status, &format!("line {i}")));
        }
        let shown = render(&mut p, 40, 5, &theme).backend().to_string();
        assert!(
            shown.contains("line 19") && !shown.contains("line 15"),
            "{shown}"
        );
        assert!(p.is_following());

        p.update(&Action::PageUp);
        assert!(!p.is_following());
        p.push(msg(LogKind::Status, "line 20"));
        p.push(msg(LogKind::Status, "line 21"));
        let shown = render(&mut p, 40, 5, &theme).backend().to_string();
        assert!(shown.contains("▼ 2 new"), "{shown}");
        assert!(
            !shown.contains("line 21"),
            "paused view doesn't jump: {shown}"
        );

        p.update(&Action::Bottom);
        assert!(p.is_following());
        let shown = render(&mut p, 40, 5, &theme).backend().to_string();
        assert!(
            shown.contains("line 21") && !shown.contains("new"),
            "{shown}"
        );

        // Moving down to the last line resumes following too.
        p.update(&Action::CursorUp);
        p.update(&Action::CursorDown);
        assert!(p.is_following());
    }

    #[test]
    fn search_highlights_and_jumps() {
        let theme = Theme::new(None, true);
        let mut p = pane();
        for t in ["alpha", "beta MATCH", "gamma", "delta match", "epsilon"] {
            p.push(msg(LogKind::Status, t));
        }
        p.update(&Action::QuickFilter);
        assert!(p.is_searching());
        for c in "match".chars() {
            p.handle_search_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        p.handle_search_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!p.is_searching());
        assert_eq!(
            p.selected_text().split("Status:   ").nth(1),
            Some("delta match")
        );
        p.update(&Action::SearchPrev);
        assert!(p.selected_text().ends_with("beta MATCH"));
        p.update(&Action::SearchPrev);
        assert!(p.selected_text().ends_with("delta match"), "wraps around");
        p.update(&Action::SearchNext);
        assert!(p.selected_text().ends_with("beta MATCH"));
        let t = render(&mut p, 50, 8, &theme);
        let buf = t.backend().buffer();
        let row = (0..8)
            .find(|&y| {
                (0..50)
                    .map(|x| buf[(x, y)].symbol().to_owned())
                    .collect::<String>()
                    .contains("beta MATCH")
            })
            .unwrap();
        let col = (0..50)
            .find(|&x| buf[(x, row)].symbol() == "M" && buf[(x + 1, row)].symbol() == "A")
            .unwrap();
        assert!(
            buf[(col, row)].modifier.contains(Modifier::REVERSED),
            "match highlighted"
        );
        assert!(t.backend().to_string().contains("/match"));
    }

    #[test]
    fn copy_and_save_the_whole_filtered_log() {
        let mut p = pane();
        assert_eq!(p.update(&Action::CopyLog), None);
        p.push(msg(LogKind::Status, "one"));
        p.push(msg(LogKind::Error, "two"));
        p.push(msg(LogKind::Status, "three"));
        let Some(Action::CopyToClipboard(text)) = p.update(&Action::CopyLog) else {
            panic!("nothing copied");
        };
        assert_eq!(text.lines().count(), 3);
        p.update(&Action::ToggleErrorsOnly);
        let Some(Action::SaveLogText(text)) = p.update(&Action::SaveLog) else {
            panic!("nothing to save");
        };
        assert_eq!(text, "12:34:56  Error:    two");
    }

    #[test]
    fn copy_line_and_range() {
        let mut p = pane();
        for t in ["one", "two", "three"] {
            p.push(msg(LogKind::Status, t));
        }
        let Some(Action::CopyToClipboard(text)) = p.update(&Action::CopySelection) else {
            panic!("nothing copied");
        };
        assert_eq!(text, "12:34:56  Status:   three");
        p.update(&Action::CursorUp);
        p.update(&Action::CursorUp);
        p.update(&Action::VisualSelect);
        p.update(&Action::CursorDown);
        let Some(Action::CopyToClipboard(text)) = p.update(&Action::CopySelection) else {
            panic!("nothing copied");
        };
        assert_eq!(text, "12:34:56  Status:   one\n12:34:56  Status:   two");
    }

    #[test]
    fn clear_wrap_and_filters() {
        let theme = Theme::new(None, true);
        let mut p = pane();
        p.push(msg(LogKind::Status, &"x".repeat(100)));
        p.push(msg(LogKind::Error, "boom"));
        let shown = render(&mut p, 30, 6, &theme).backend().to_string();
        assert_eq!(shown.matches('x').count(), 28 - 20, "one row, cut: {shown}");
        p.update(&Action::ToggleWrap);
        let shown = render(&mut p, 30, 8, &theme).backend().to_string();
        assert!(shown.matches('x').count() >= 80, "wrapped: {shown}");
        p.update(&Action::ToggleErrorsOnly);
        let shown = render(&mut p, 30, 6, &theme).backend().to_string();
        assert!(shown.contains("boom") && !shown.contains("xxx") && shown.contains("(errors)"));
        p.update(&Action::ClearLog);
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn per_tab_view_and_show_all() {
        let theme = Theme::new(None, true);
        let mut p = pane();
        let mut other = msg(LogKind::Status, "other tab");
        other.session = SessionId(2);
        p.push(msg(LogKind::Status, "this tab"));
        p.push(other);
        p.set_sessions(Some(HashSet::from([SessionId(1)])));
        let shown = render(&mut p, 40, 5, &theme).backend().to_string();
        assert!(shown.contains("this tab") && !shown.contains("other tab"));
        p.update(&Action::ToggleLogAll);
        let shown = render(&mut p, 40, 5, &theme).backend().to_string();
        assert!(shown.contains("other tab") && shown.contains("(all sessions)"));
    }
}
