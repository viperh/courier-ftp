//! The message log pane (T55): FileZilla's message log with per-tab rings and an
//! `All` view, follow mode, a cursor and visual range for copying, search, a kind
//! filter, wrap and horizontal scroll.
//!
//! - [`store`]: the bounded rings and the routing of core log lines.
//! - [`render`]: line layout and the anchor-based renderer.
//! - this file: [`MessageLogPane`], the component (keys, actions, drawing).

pub(crate) mod render;
pub(crate) mod store;

#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

use std::{collections::HashMap, sync::Arc};

use courier_ftp_core::{events::CoreEvent, settings::LoggingSettings};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    text::{Line, Span},
};
use tokio::time::{Duration, Instant};

use self::render::{
    Columns, RenderParams, Visible, anchor_for_top, index_of, local_offset, plain_line, render_body,
};
pub(crate) use self::{
    render::{KindFilter, LogStyles, Matcher, init_local_offset},
    store::{LogScope, LogStore, ServerKey},
};
use super::{
    Component, DrawCx, KeyOutcome, region_block,
    widgets::{TextInput, Widget, WidgetCx, WidgetOutcome},
};
use crate::{
    action::Action,
    app::Mode,
    config::Config,
    keymap::chord::KeyChord,
    tabs::TabId,
    ui::{
        clipboard::{ClipboardHandle, copy_status},
        text::{sanitize, width},
        theme::Theme,
    },
};

/// Maximum search query length (chars).
const MAX_QUERY_CHARS: usize = 256;
/// Above this many lines the match count waits for [`COUNT_DEBOUNCE`].
const DEBOUNCE_LINES: usize = 20_000;
/// Debounce of the match count on large rings.
const COUNT_DEBOUNCE: Duration = Duration::from_millis(100);
/// Columns per horizontal scroll step.
const HSCROLL_STEP: usize = 8;
/// Body size assumed before the first draw.
const DEFAULT_BODY: Rect = Rect::new(0, 0, 78, 10);

/// Search state of a view.
#[derive(Debug, Clone, Default)]
pub(crate) struct LogSearch {
    /// The query.
    pub query: String,
    /// The input row has the keyboard.
    pub editing: bool,
    /// The current match (line seq).
    pub current: Option<u64>,
    /// Number of matching lines in the scope.
    pub total: usize,
    /// 1-based position of `current` among the matches (oldest first).
    pub index: usize,
    /// The last `n`/`N` wrapped around.
    pub wrapped: bool,
}

/// Per-view UI state (one per tab + one for All; the pane shows one at a time).
#[derive(Debug)]
pub(crate) struct LogViewState {
    /// Which ring.
    pub scope: LogScope,
    /// Pinned to the newest line.
    pub follow: bool,
    /// Bottom visible line when not following.
    pub anchor_seq: Option<u64>,
    /// Focused line (only drawn when the pane has focus).
    pub cursor_seq: Option<u64>,
    /// Start of the visual line range.
    pub visual_anchor: Option<u64>,
    /// New lines since follow was turned off.
    pub unseen: u32,
    /// Newest seq of the ring when follow was turned off.
    unseen_mark: Option<u64>,
    /// Wrap long lines (default true).
    pub wrap: bool,
    /// Columns scrolled, only when `!wrap`.
    pub hscroll: u16,
    /// Kind filter.
    pub kind_filter: KindFilter,
    /// Search, while active.
    pub search: Option<LogSearch>,
}

impl LogViewState {
    /// Following, wrapping, no search.
    pub(crate) fn new(scope: LogScope) -> Self {
        Self {
            scope,
            follow: true,
            anchor_seq: None,
            cursor_seq: None,
            visual_anchor: None,
            unseen: 0,
            unseen_mark: None,
            wrap: true,
            hscroll: 0,
            kind_filter: KindFilter::Everything,
            search: None,
        }
    }
}

impl Default for LogViewState {
    fn default() -> Self {
        Self::new(LogScope::Tab(TabId::FIRST))
    }
}

/// Resolved log styles from `theme`.
pub(crate) fn log_styles(theme: &Theme) -> LogStyles {
    LogStyles {
        status: theme.style("log.status"),
        warning: theme.style("log.warning"),
        command: theme.style("log.command"),
        response: theme.style("log.response"),
        error: theme.style("log.error"),
        trace: theme.style("log.trace"),
        listing: theme.style("log.listing"),
        time: theme.style("log.time"),
        cursor: theme.style("log.cursor"),
        visual: theme.style("log.visual"),
        search_match: theme.style("log.search_match"),
        escape: theme.style("text.escape"),
    }
}

/// `▼ 3 new` / `v 3 new`, capped at `9999+`.
fn unseen_label(n: u32, unicode: bool) -> String {
    let arrow = if unicode { "▼" } else { "v" };
    if n > 9999 {
        format!("{arrow} 9999+ new")
    } else {
        format!("{arrow} {n} new")
    }
}

/// The message log component.
pub(crate) struct MessageLogPane {
    store: LogStore,
    view: LogViewState,
    views: HashMap<LogScope, LogViewState>,
    active_tab: TabId,
    clipboard: ClipboardHandle,
    show_timestamps: bool,
    input: TextInput,
    matcher: Option<Matcher>,
    count_due: Option<Instant>,
    focused: bool,
    unicode: bool,
    last_body: Option<Rect>,
}

impl std::fmt::Debug for MessageLogPane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageLogPane")
            .field("view", &self.view)
            .field("active_tab", &self.active_tab)
            .finish_non_exhaustive()
    }
}

const HANDLED: &[Action] = &[
    Action::LogCursorDown,
    Action::LogCursorUp,
    Action::LogHalfPageDown,
    Action::LogHalfPageUp,
    Action::LogPageDown,
    Action::LogPageUp,
    Action::LogTop,
    Action::LogBottom,
    Action::LogSearch,
    Action::LogSearchNext,
    Action::LogSearchPrev,
    Action::LogVisual,
    Action::LogCopy,
    Action::LogToggleWrap,
    Action::LogToggleScope,
    Action::LogCycleKindFilter,
    Action::LogScrollLeft,
    Action::LogScrollRight,
    Action::LogScrollHome,
    Action::ClearLog,
    Action::Escape,
    Action::Cancel,
];

impl MessageLogPane {
    /// An empty log with the `logging` settings, copying through `clipboard`.
    pub(crate) fn new(clipboard: ClipboardHandle, logging: &LoggingSettings) -> Self {
        Self {
            store: LogStore::new(logging.pane_max_lines as usize),
            view: LogViewState::new(LogScope::Tab(TabId::FIRST)),
            views: HashMap::new(),
            active_tab: TabId::FIRST,
            clipboard,
            show_timestamps: logging.show_timestamps,
            input: TextInput::new("").max_chars(MAX_QUERY_CHARS),
            matcher: None,
            count_due: None,
            focused: false,
            unicode: true,
            last_body: None,
        }
    }

    /// The store (T61 sets tab routes, T71 reads lines).
    #[cfg_attr(not(test), expect(dead_code, reason = "used by T61 and T71"))]
    pub(crate) fn store(&self) -> &LogStore {
        &self.store
    }

    /// The store, mutable (tab routes).
    #[cfg_attr(not(test), expect(dead_code, reason = "used by T53 and T61"))]
    pub(crate) fn store_mut(&mut self) -> &mut LogStore {
        &mut self.store
    }

    /// The view shown.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by T71"))]
    pub(crate) fn view(&self) -> &LogViewState {
        &self.view
    }

    /// The active tab changed (T61): lines of unknown sessions go to its ring, and a
    /// tab view switches to it.
    #[cfg_attr(not(test), expect(dead_code, reason = "called by T61"))]
    pub(crate) fn set_active_tab(&mut self, tab: TabId) {
        self.active_tab = tab;
        if matches!(self.view.scope, LogScope::Tab(_)) {
            self.switch_scope(LogScope::Tab(tab));
        }
    }

    fn switch_scope(&mut self, scope: LogScope) {
        if self.view.scope == scope {
            return;
        }
        let next = self
            .views
            .remove(&scope)
            .unwrap_or_else(|| LogViewState::new(scope));
        let old = std::mem::replace(&mut self.view, next);
        self.views.insert(old.scope, old);
        self.sync_matcher();
    }

    fn sync_matcher(&mut self) {
        self.matcher = self
            .view
            .search
            .as_ref()
            .and_then(|s| Matcher::new(&s.query));
        if let Some(s) = &self.view.search {
            self.input.set_value(&s.query);
        }
    }

    fn body(&self) -> Rect {
        self.last_body.unwrap_or(DEFAULT_BODY)
    }

    fn params(&self) -> RenderParams<'_> {
        let v = &self.view;
        RenderParams {
            follow: v.follow,
            anchor_seq: v.anchor_seq,
            cursor_seq: v.cursor_seq.filter(|_| self.focused),
            visual: v
                .visual_anchor
                .zip(v.cursor_seq)
                .map(|(a, c)| (a.min(c), a.max(c))),
            wrap: v.wrap,
            hscroll: usize::from(v.hscroll),
            filter: v.kind_filter,
            matcher: self.matcher.as_ref(),
            all_view: v.scope == LogScope::All,
            show_timestamps: self.show_timestamps,
            unicode: self.unicode,
            offset: local_offset(),
        }
    }

    /// What the body shows now (laid out into a scratch buffer).
    fn visible(&self) -> Visible {
        let body = self.body();
        let area = Rect::new(0, 0, body.width, body.height);
        let mut buf = Buffer::empty(area);
        render_body(
            &mut buf,
            area,
            self.store.lines(self.view.scope),
            &self.params(),
            &LogStyles::default(),
        )
    }

    fn passes_at(&self, idx: usize) -> bool {
        let lines = self.store.lines(self.view.scope);
        lines
            .get(idx)
            .is_some_and(|l| self.view.kind_filter.passes(l))
    }

    fn first_passing(&self) -> Option<usize> {
        (0..self.store.len(self.view.scope)).find(|i| self.passes_at(*i))
    }

    fn last_passing(&self) -> Option<usize> {
        (0..self.store.len(self.view.scope))
            .rev()
            .find(|i| self.passes_at(*i))
    }

    fn seq_at(&self, idx: usize) -> Option<u64> {
        self.store.lines(self.view.scope).get(idx).map(|l| l.seq)
    }

    fn newest_seq(&self) -> Option<u64> {
        self.store.lines(self.view.scope).back().map(|l| l.seq)
    }

    /// The bottom visible line (where the cursor starts).
    fn bottom_visible(&self) -> Option<u64> {
        self.visible()
            .seqs
            .last()
            .copied()
            .or_else(|| self.last_passing().and_then(|i| self.seq_at(i)))
    }

    fn ensure_cursor(&mut self) -> Option<u64> {
        let lines = self.store.lines(self.view.scope);
        let valid = self.view.cursor_seq.filter(|c| {
            lines
                .get(index_of(lines, *c))
                .is_some_and(|l| l.seq == *c && self.view.kind_filter.passes(l))
        });
        if valid.is_none() {
            self.view.cursor_seq = self.bottom_visible();
        }
        self.view.cursor_seq
    }

    fn stop_follow(&mut self) {
        if !self.view.follow {
            return;
        }
        let bottom = self.visible().seqs.last().copied();
        self.view.follow = false;
        self.view.anchor_seq = bottom.or_else(|| self.newest_seq());
        self.view.unseen = 0;
        self.view.unseen_mark = self.newest_seq();
    }

    fn resume_follow(&mut self) {
        self.view.follow = true;
        self.view.anchor_seq = None;
        self.view.unseen = 0;
        self.view.unseen_mark = None;
    }

    /// Moves the cursor `delta` shown lines (negative = up) and scrolls to it.
    fn move_cursor(&mut self, delta: isize) {
        let Some(cur) = self.ensure_cursor() else {
            return;
        };
        let lines = self.store.lines(self.view.scope);
        let mut idx = index_of(lines, cur);
        let mut left = delta.unsigned_abs();
        while left > 0 {
            let next = if delta < 0 {
                (0..idx).rev().find(|i| self.passes_at(*i))
            } else {
                (idx + 1..lines.len()).find(|i| self.passes_at(*i))
            };
            match next {
                Some(n) => idx = n,
                None => break,
            }
            left -= 1;
        }
        if delta < 0 {
            self.stop_follow();
        }
        self.view.cursor_seq = self.seq_at(idx);
        self.scroll_to_cursor();
    }

    /// Scrolls so the cursor line is visible.
    fn scroll_to_cursor(&mut self) {
        let Some(c) = self.view.cursor_seq else {
            return;
        };
        let vis = self.visible();
        let (Some(&top), Some(&bottom)) = (vis.seqs.first(), vis.seqs.last()) else {
            return;
        };
        let above = c < top || (c == top && vis.top_clipped && vis.seqs.len() > 1);
        let below = c > bottom || (c == bottom && vis.bottom_clipped && vis.seqs.len() > 1);
        if !(above || below) {
            return;
        }
        self.stop_follow();
        if below {
            self.view.anchor_seq = Some(c);
        } else {
            let lines = self.store.lines(self.view.scope);
            let body = self.body();
            self.view.anchor_seq = anchor_for_top(
                lines,
                index_of(lines, c),
                body.width,
                usize::from(body.height),
                &self.params(),
            );
        }
    }

    fn page(&self) -> isize {
        isize::try_from(self.body().height.max(1)).unwrap_or(1)
    }

    fn go_top(&mut self) {
        let Some(first) = self.first_passing() else {
            return;
        };
        self.stop_follow();
        self.view.cursor_seq = self.seq_at(first);
        let body = self.body();
        self.view.anchor_seq = anchor_for_top(
            self.store.lines(self.view.scope),
            first,
            body.width,
            usize::from(body.height),
            &self.params(),
        );
    }

    fn go_bottom(&mut self) {
        self.resume_follow();
        self.view.cursor_seq = self.last_passing().and_then(|i| self.seq_at(i));
    }

    // ---- search ----

    fn open_search(&mut self) {
        let query = self
            .view
            .search
            .as_ref()
            .map(|s| s.query.clone())
            .unwrap_or_default();
        self.input.set_value(&query);
        let s = self.view.search.get_or_insert_with(LogSearch::default);
        s.editing = true;
    }

    fn clear_search(&mut self) {
        self.view.search = None;
        self.matcher = None;
        self.count_due = None;
        self.input.set_value("");
    }

    fn on_query_changed(&mut self, now: Instant) {
        let query = self.input.value().to_owned();
        self.matcher = Matcher::new(&query);
        if let Some(s) = &mut self.view.search {
            s.query = query;
            s.wrapped = false;
        }
        if self.store.len(self.view.scope) > DEBOUNCE_LINES {
            self.count_due = Some(now + COUNT_DEBOUNCE);
        } else {
            self.recount();
        }
    }

    fn line_matches(&self, idx: usize) -> bool {
        let Some(m) = &self.matcher else {
            return false;
        };
        let lines = self.store.lines(self.view.scope);
        lines
            .get(idx)
            .is_some_and(|l| self.view.kind_filter.passes(l) && m.is_match(&l.text))
    }

    /// Counts the matches; keeps the current match if it still matches, else picks the
    /// nearest one at or above the bottom of the view.
    fn recount(&mut self) {
        self.count_due = None;
        let n = self.store.len(self.view.scope);
        let matches: Vec<usize> = (0..n).filter(|i| self.line_matches(*i)).collect();
        let lines = self.store.lines(self.view.scope);
        let keep = self
            .view
            .search
            .as_ref()
            .and_then(|s| s.current)
            .filter(|c| matches.iter().any(|i| lines[*i].seq == *c));
        let current = keep.or_else(|| {
            let bottom = self.visible().seqs.last().copied().unwrap_or(u64::MAX);
            matches
                .iter()
                .rev()
                .find(|i| lines[**i].seq <= bottom)
                .or(matches.last())
                .map(|i| lines[*i].seq)
        });
        let index = current.map_or(0, |c| {
            matches.iter().filter(|i| lines[**i].seq <= c).count()
        });
        if let Some(s) = &mut self.view.search {
            s.total = matches.len();
            s.current = current;
            s.index = index;
        }
    }

    /// `n` (older = true) / `N`: the next match, wrapping around.
    fn jump(&mut self, older: bool) {
        if self.matcher.is_none() {
            return;
        }
        let lines = self.store.lines(self.view.scope);
        let n = lines.len();
        let from = self
            .view
            .search
            .as_ref()
            .and_then(|s| s.current)
            .or(self.view.cursor_seq)
            .map(|s| index_of(lines, s));
        let (found, wrapped) = if older {
            let start = from.unwrap_or(n);
            match (0..start).rev().find(|i| self.line_matches(*i)) {
                Some(i) => (Some(i), false),
                None => ((start..n).rev().find(|i| self.line_matches(*i)), true),
            }
        } else {
            let start = from.map_or(0, |f| f + 1);
            match (start..n).find(|i| self.line_matches(*i)) {
                Some(i) => (Some(i), false),
                None => ((0..start.min(n)).find(|i| self.line_matches(*i)), true),
            }
        };
        let Some(idx) = found else {
            self.recount();
            return;
        };
        let seq = self.seq_at(idx);
        if let Some(s) = &mut self.view.search {
            s.current = seq;
        }
        self.recount();
        if let Some(s) = &mut self.view.search {
            s.wrapped = wrapped;
        }
        self.stop_follow();
        self.view.cursor_seq = seq;
        self.scroll_to_cursor();
    }

    // ---- copy, clear ----

    /// The text `y` copies: the visual range, else the cursor line, as displayed.
    pub(crate) fn copy_text(&mut self) -> Option<(String, usize)> {
        let cur = self.ensure_cursor()?;
        let (lo, hi) = match self.view.visual_anchor {
            Some(a) => (a.min(cur), a.max(cur)),
            None => (cur, cur),
        };
        let cols = Columns::new(
            self.body().width,
            self.view.scope == LogScope::All,
            self.show_timestamps,
        );
        let offset = local_offset();
        let lines = self.store.lines(self.view.scope);
        let picked: Vec<String> = lines
            .iter()
            .skip(index_of(lines, lo))
            .take_while(|l| l.seq <= hi)
            .filter(|l| self.view.kind_filter.passes(l))
            .map(|l| plain_line(l, &cols, offset))
            .collect();
        let n = picked.len();
        (n > 0).then(|| (picked.join("\n"), n))
    }

    fn copy(&mut self) -> Option<Action> {
        let (text, n) = self.copy_text()?;
        let text = zeroize::Zeroizing::new(text);
        let result = match self.clipboard.lock() {
            Ok(mut c) => c.copy(&text),
            Err(poisoned) => poisoned.into_inner().copy(&text),
        };
        self.view.visual_anchor = None;
        Some(Action::StatusMessage(copy_status(n, &result)))
    }

    fn clear(&mut self) -> Action {
        let scope = self.view.scope;
        self.store.clear(scope);
        let wrap = self.view.wrap;
        self.view = LogViewState::new(scope);
        self.view.wrap = wrap;
        self.matcher = None;
        self.count_due = None;
        Action::StatusMessage("Log cleared".to_owned())
    }

    /// After a push: unseen counters and anchors of evicted lines.
    fn after_push(&mut self, scopes: &[LogScope]) {
        let store = &self.store;
        for v in std::iter::once(&mut self.view).chain(self.views.values_mut()) {
            if !scopes.contains(&v.scope) {
                continue;
            }
            let lines = store.lines(v.scope);
            let Some(oldest) = lines.front().map(|l| l.seq) else {
                continue;
            };
            for s in [&mut v.anchor_seq, &mut v.cursor_seq, &mut v.visual_anchor] {
                if let Some(x) = s
                    && *x < oldest
                {
                    *x = oldest;
                }
            }
            if !v.follow {
                let since = v
                    .unseen_mark
                    .map_or(0, |m| lines.partition_point(|l| l.seq <= m));
                v.unseen = u32::try_from(lines.len() - since).unwrap_or(u32::MAX);
            }
        }
    }

    // ---- drawing ----

    fn title(&self) -> String {
        let sep = if self.unicode { "·" } else { "-" };
        let scope = match self.view.scope {
            LogScope::All => "All".to_owned(),
            LogScope::Tab(t) => format!("Tab {}", t.0 + 1),
        };
        match self.view.kind_filter.label() {
            Some(l) => format!("Message log {sep} {scope} {l}"),
            None => format!("Message log {sep} {scope}"),
        }
    }

    fn search_status(&self) -> String {
        let Some(s) = &self.view.search else {
            return String::new();
        };
        if self.matcher.is_none() {
            return String::new();
        }
        let mut out = if self.count_due.is_some() {
            "counting…".to_owned()
        } else if s.total == 0 {
            "no matches".to_owned()
        } else {
            format!("match {} of {}", s.index, s.total)
        };
        if s.wrapped {
            out.push_str(" (search wrapped)");
        }
        out
    }

    fn draw_search_row(&self, frame: &mut Frame, row: Rect, cx: &DrawCx) {
        let Some(s) = &self.view.search else {
            return;
        };
        frame
            .buffer_mut()
            .set_string(row.x, row.y, "/", cx.theme.style("log.time"));
        let status = self.search_status();
        let avail = row.width.saturating_sub(1);
        let status_w = u16::try_from(width(&status) + 2).unwrap_or(u16::MAX);
        let query_w = u16::try_from(width(&sanitize(&s.query)) + 1).unwrap_or(u16::MAX);
        let field_w = query_w
            .min(avail.saturating_sub(status_w).max(1))
            .min(avail);
        let field = Rect::new(row.x + 1, row.y, field_w, 1);
        if s.editing {
            let wcx = WidgetCx {
                theme: cx.theme,
                symbols: cx.symbols,
                focused: cx.focused,
                enabled: true,
                now: cx.now,
            };
            self.input.render(frame, field, &wcx);
            if cx.focused
                && let Some(pos) = self.input.cursor(field)
            {
                frame.set_cursor_position(pos);
            }
        } else {
            frame.buffer_mut().set_stringn(
                field.x,
                field.y,
                sanitize(&s.query),
                usize::from(field.width),
                ratatui::style::Style::default(),
            );
        }
        let x = field.x + field.width + 1;
        if x < row.x + row.width {
            frame.buffer_mut().set_stringn(
                x,
                row.y,
                &status,
                usize::from(row.x + row.width - x),
                cx.theme.style("log.time"),
            );
        }
    }
}

impl Component for MessageLogPane {
    fn register_config_handler(&mut self, config: Arc<Config>) -> color_eyre::Result<()> {
        let logging = &config.settings.logging;
        self.store.set_capacity(logging.pane_max_lines as usize);
        self.show_timestamps = logging.show_timestamps;
        Ok(())
    }

    fn key_mode(&self) -> Mode {
        if self.view.search.as_ref().is_some_and(|s| s.editing) {
            Mode::Input
        } else {
            Mode::Log
        }
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        if !self.view.search.as_ref().is_some_and(|s| s.editing) {
            return Ok(KeyOutcome::Ignored);
        }
        if key == KeyChord::key(KeyCode::Enter) {
            if self.input.value().is_empty() {
                self.clear_search();
            } else {
                if self.count_due.is_some() {
                    self.recount();
                }
                if let Some(s) = &mut self.view.search {
                    s.editing = false;
                }
                if let Some(c) = self.view.search.as_ref().and_then(|s| s.current) {
                    self.stop_follow();
                    self.view.cursor_seq = Some(c);
                    self.scroll_to_cursor();
                }
            }
            return Ok(KeyOutcome::Consumed(None));
        }
        if key == KeyChord::key(KeyCode::Esc) {
            self.clear_search();
            return Ok(KeyOutcome::Consumed(None));
        }
        Ok(match self.input.handle_key(key) {
            WidgetOutcome::Changed => {
                self.on_query_changed(Instant::now());
                KeyOutcome::Consumed(None)
            }
            WidgetOutcome::Ignored => KeyOutcome::Ignored,
            WidgetOutcome::Consumed | WidgetOutcome::Activated => KeyOutcome::Consumed(None),
        })
    }

    fn handle_paste(&mut self, text: &str) -> color_eyre::Result<KeyOutcome> {
        if !self.view.search.as_ref().is_some_and(|s| s.editing) {
            return Ok(KeyOutcome::Ignored);
        }
        if self.input.handle_paste(text) == WidgetOutcome::Changed {
            self.on_query_changed(Instant::now());
        }
        let notice = self.input.take_notice().and_then(|n| match n {
            crate::components::widgets::Notice::Status(s) => Some(Action::StatusMessage(s)),
            crate::components::widgets::Notice::NextField => None,
        });
        Ok(KeyOutcome::Consumed(notice))
    }

    fn handled_actions(&self) -> &'static [Action] {
        HANDLED
    }

    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        let half = (self.page() / 2).max(1);
        let page = self.page();
        match action {
            Action::Tick => {
                if self.count_due.is_some_and(|due| Instant::now() >= due) {
                    self.recount();
                    return Ok(Some(Action::Wake));
                }
            }
            Action::LogCursorDown => self.move_cursor(1),
            Action::LogCursorUp => self.move_cursor(-1),
            Action::LogHalfPageDown => self.move_cursor(half),
            Action::LogHalfPageUp => self.move_cursor(-half),
            Action::LogPageDown => self.move_cursor(page),
            Action::LogPageUp => self.move_cursor(-page),
            Action::LogTop => self.go_top(),
            Action::LogBottom => self.go_bottom(),
            Action::LogSearch => self.open_search(),
            Action::LogSearchNext => self.jump(true),
            Action::LogSearchPrev => self.jump(false),
            Action::LogVisual => {
                if self.view.visual_anchor.is_some() {
                    self.view.visual_anchor = None;
                } else {
                    self.view.visual_anchor = self.ensure_cursor();
                }
            }
            Action::LogCopy => return Ok(self.copy()),
            Action::LogToggleWrap => {
                self.view.wrap = !self.view.wrap;
                self.view.hscroll = 0;
            }
            Action::LogToggleScope => {
                let next = match self.view.scope {
                    LogScope::All => LogScope::Tab(self.active_tab),
                    LogScope::Tab(_) => LogScope::All,
                };
                self.switch_scope(next);
            }
            Action::LogCycleKindFilter => {
                self.view.kind_filter = self.view.kind_filter.next();
                if self.matcher.is_some() {
                    self.recount();
                }
            }
            Action::LogScrollLeft if !self.view.wrap => {
                self.view.hscroll = self
                    .view
                    .hscroll
                    .saturating_sub(u16::try_from(HSCROLL_STEP).unwrap_or(8));
            }
            Action::LogScrollRight if !self.view.wrap => {
                self.view.hscroll = self
                    .view
                    .hscroll
                    .saturating_add(u16::try_from(HSCROLL_STEP).unwrap_or(8));
            }
            Action::LogScrollHome => self.view.hscroll = 0,
            Action::ClearLog => return Ok(Some(self.clear())),
            Action::Escape | Action::Cancel if self.focused => {
                if self.view.visual_anchor.is_some() {
                    self.view.visual_anchor = None;
                } else if self.view.search.is_some() {
                    self.clear_search();
                }
            }
            _ => {}
        }
        Ok(None)
    }

    fn on_core_event(&mut self, event: &CoreEvent) -> color_eyre::Result<Option<Action>> {
        match event {
            CoreEvent::Log(msg) => {
                let scopes = self.store.push(msg.clone(), self.active_tab);
                self.after_push(&scopes);
            }
            CoreEvent::Connected { session, address } => {
                self.store.on_connected(*session, address);
            }
            CoreEvent::Disconnected { session, .. } => self.store.on_disconnected(*session),
            CoreEvent::SessionOpened {
                session, purpose, ..
            } => self.store.on_session_opened(*session, *purpose),
            CoreEvent::SessionClosed { session } => self.store.on_session_closed(*session),
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()> {
        let gained = cx.focused && !self.focused;
        self.focused = cx.focused;
        self.unicode = cx.symbols.unicode;
        let border = cx.theme.style(if cx.focused {
            "log.border_focused"
        } else {
            "log.border"
        });
        let mut block = region_block(&self.title(), cx).border_style(border);
        if !self.view.follow && self.view.unseen > 0 {
            block = block.title_bottom(
                Line::from(Span::styled(
                    format!(" {} ", unseen_label(self.view.unseen, self.unicode)),
                    cx.theme.style("title"),
                ))
                .right_aligned(),
            );
        }
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.width < 12 || area.height < 3 || inner.height == 0 {
            return Ok(());
        }
        let search_row = self.view.search.is_some() && inner.height >= 2;
        let body = if search_row {
            Rect {
                height: inner.height - 1,
                ..inner
            }
        } else {
            inner
        };
        self.last_body = Some(body);
        if gained {
            self.view.cursor_seq = None;
            self.ensure_cursor();
        }
        let styles = log_styles(cx.theme);
        let params = self.params();
        render_body(
            frame.buffer_mut(),
            body,
            self.store.lines(self.view.scope),
            &params,
            &styles,
        );
        if search_row {
            let row = Rect::new(inner.x, inner.y + inner.height - 1, inner.width, 1);
            self.draw_search_row(frame, row, cx);
        }
        Ok(())
    }
}
