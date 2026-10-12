//! The results list (T65 §2, §4): hits as they stream in, sortable and
//! filterable, with a selection for the result actions.

use std::{cmp::Ordering, collections::HashSet};

use courier_ftp_core::{
    local::display_native,
    model::RemotePath,
    search::{SearchHit, SearchProgress, SearchSummary},
    settings::{Settings, SizeFormat},
};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use time::UtcOffset;

use crate::ui::{Side, file_list::format, panes::spinner_frame, theme::Theme};

/// How sizes and dates are shown (the file lists' settings).
#[derive(Debug, Clone)]
pub(crate) struct Fmt {
    size_format: SizeFormat,
    separators: bool,
    date_format: String,
    time_format: String,
    offset: UtcOffset,
}

impl Fmt {
    pub(crate) fn new(settings: &Settings, offset: UtcOffset) -> Self {
        let ui = &settings.interface;
        Self {
            size_format: ui.size_format,
            separators: ui.thousands_separator,
            date_format: ui.date_format.clone(),
            time_format: ui.time_format.clone(),
            offset,
        }
    }

    fn date_width(&self) -> u16 {
        let sample = courier_ftp_core::model::Timestamp::new(
            time::macros::datetime!(2000-12-31 23:59:59 UTC),
            courier_ftp_core::model::Precision::Second,
        );
        let w = format::date(&sample, &self.date_format, &self.time_format, self.offset)
            .chars()
            .count();
        u16::try_from(w).unwrap_or(16)
    }
}

/// The column the results are sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortCol {
    /// The order they were found in.
    Found,
    Name,
    Path,
    Size,
    Modified,
    Permissions,
}

impl SortCol {
    fn next(self) -> Self {
        match self {
            SortCol::Found => SortCol::Name,
            SortCol::Name => SortCol::Path,
            SortCol::Path => SortCol::Size,
            SortCol::Size => SortCol::Modified,
            SortCol::Modified => SortCol::Permissions,
            SortCol::Permissions => SortCol::Found,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            SortCol::Found => "found",
            SortCol::Name => "name",
            SortCol::Path => "path",
            SortCol::Size => "size",
            SortCol::Modified => "modified",
            SortCol::Permissions => "permissions",
        }
    }
}

/// Where the search is.
#[derive(Debug, Clone)]
pub(crate) enum RunState {
    /// Started; the latest progress, and whether a stop was asked for.
    Running {
        progress: Option<SearchProgress>,
        stopping: bool,
    },
    Done(SearchSummary),
    Failed(String),
}

/// The results of one search.
pub(crate) struct Results {
    pub(crate) side: Side,
    pub(crate) root: RemotePath,
    hits: Vec<SearchHit>,
    /// Filtered, sorted indices into `hits`.
    view: Vec<usize>,
    dirty: bool,
    /// Index into `view`.
    cursor: usize,
    scroll: usize,
    selected: HashSet<RemotePath>,
    sort: SortCol,
    descending: bool,
    /// The `/` filter (case-insensitive, on the full path).
    pub(crate) filter: String,
    /// Typing the filter.
    pub(crate) typing: bool,
    pub(crate) state: RunState,
    /// Rows shown at the last draw (for page keys).
    rows: usize,
}

impl Results {
    pub(crate) fn new(side: Side, root: RemotePath) -> Self {
        Self {
            side,
            root,
            hits: Vec::new(),
            view: Vec::new(),
            dirty: false,
            cursor: 0,
            scroll: 0,
            selected: HashSet::new(),
            sort: SortCol::Found,
            descending: false,
            filter: String::new(),
            typing: false,
            state: RunState::Running {
                progress: None,
                stopping: false,
            },
            rows: 10,
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        matches!(self.state, RunState::Running { .. })
    }

    pub(crate) fn add(&mut self, hits: &[SearchHit]) {
        self.hits.extend_from_slice(hits);
        self.dirty = true;
    }

    /// Drop the hits at `removed` and everything below them.
    pub(crate) fn remove(&mut self, removed: &[RemotePath]) {
        let current = self.current().map(|h| h.path.clone());
        self.hits.retain(|h| {
            !removed
                .iter()
                .any(|r| h.path == *r || h.path.starts_with(r))
        });
        let hits = &self.hits;
        self.selected.retain(|p| hits.iter().any(|h| h.path == *p));
        self.rebuild(current);
    }

    /// The visible hits, in order (tests).
    #[cfg(test)]
    pub(crate) fn visible(&mut self) -> Vec<&SearchHit> {
        self.ensure();
        self.view.iter().map(|&i| &self.hits[i]).collect()
    }

    pub(crate) fn sort(&self) -> (SortCol, bool) {
        (self.sort, self.descending)
    }

    fn ensure(&mut self) {
        if self.dirty {
            let current = self.current_unsorted();
            self.rebuild(current);
        }
    }

    /// The hit under the cursor without rebuilding.
    fn current_unsorted(&self) -> Option<RemotePath> {
        self.view
            .get(self.cursor)
            .and_then(|&i| self.hits.get(i))
            .map(|h| h.path.clone())
    }

    /// Re-filter and re-sort, keeping the cursor on `keep`.
    fn rebuild(&mut self, keep: Option<RemotePath>) {
        self.dirty = false;
        let filter = self.filter.to_lowercase();
        self.view = (0..self.hits.len())
            .filter(|&i| {
                filter.is_empty() || self.hits[i].path.as_str().to_lowercase().contains(&filter)
            })
            .collect();
        let hits = &self.hits;
        let sort = self.sort;
        let cmp = |a: &usize, b: &usize| -> Ordering {
            let (x, y) = (&hits[*a], &hits[*b]);
            let o = match sort {
                SortCol::Found => a.cmp(b),
                SortCol::Name => {
                    courier_ftp_core::compare::natural_cmp(&x.entry.name, &y.entry.name)
                }
                SortCol::Path => x.path.cmp(&y.path),
                SortCol::Size => x.entry.size.cmp(&y.entry.size),
                SortCol::Modified => x
                    .entry
                    .modified
                    .as_ref()
                    .map(|t| t.time)
                    .cmp(&y.entry.modified.as_ref().map(|t| t.time)),
                SortCol::Permissions => x
                    .entry
                    .permissions
                    .as_ref()
                    .map(ToString::to_string)
                    .cmp(&y.entry.permissions.as_ref().map(ToString::to_string)),
            };
            o.then_with(|| a.cmp(b))
        };
        self.view.sort_by(cmp);
        if self.descending {
            self.view.reverse();
        }
        self.cursor = keep
            .and_then(|p| self.view.iter().position(|&i| self.hits[i].path == p))
            .unwrap_or(self.cursor)
            .min(self.view.len().saturating_sub(1));
    }

    pub(crate) fn current(&self) -> Option<&SearchHit> {
        self.view.get(self.cursor).and_then(|&i| self.hits.get(i))
    }

    /// The selected hits (in found order), or the one under the cursor.
    pub(crate) fn targets(&mut self) -> Vec<SearchHit> {
        self.ensure();
        if self.selected.is_empty() {
            return self.current().cloned().into_iter().collect();
        }
        self.hits
            .iter()
            .filter(|h| self.selected.contains(&h.path))
            .cloned()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn selected_count(&self) -> usize {
        self.selected.len()
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.ensure();
        let last = self.view.len().saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
    }

    pub(crate) fn page(&self) -> isize {
        isize::try_from(self.rows.max(1)).unwrap_or(10)
    }

    pub(crate) fn top(&mut self) {
        self.cursor = 0;
    }

    pub(crate) fn bottom(&mut self) {
        self.ensure();
        self.cursor = self.view.len().saturating_sub(1);
    }

    /// Space: toggle the hit under the cursor and move down.
    pub(crate) fn toggle(&mut self) {
        self.ensure();
        if let Some(path) = self.current().map(|h| h.path.clone()) {
            if !self.selected.remove(&path) {
                self.selected.insert(path);
            }
            self.move_cursor(1);
        }
    }

    /// Select every visible hit, or none when they all are.
    pub(crate) fn toggle_all(&mut self) {
        self.ensure();
        let visible: Vec<RemotePath> = self
            .view
            .iter()
            .map(|&i| self.hits[i].path.clone())
            .collect();
        if !visible.is_empty() && visible.iter().all(|p| self.selected.contains(p)) {
            for p in &visible {
                self.selected.remove(p);
            }
        } else {
            self.selected.extend(visible);
        }
    }

    pub(crate) fn set_sort(&mut self, col: SortCol, descending: bool) {
        self.sort = col;
        self.descending = descending;
        self.dirty = true;
    }

    pub(crate) fn next_sort(&mut self) {
        let keep = self.current_unsorted();
        self.sort = self.sort.next();
        self.descending = false;
        self.rebuild(keep);
    }

    pub(crate) fn reverse_sort(&mut self) {
        let keep = self.current_unsorted();
        self.descending = !self.descending;
        self.rebuild(keep);
    }

    pub(crate) fn set_filter(&mut self, filter: String) {
        let keep = self.current_unsorted();
        self.filter = filter;
        self.rebuild(keep);
    }

    fn status(&self, tick: u64, unicode: bool) -> (String, bool) {
        let found = self.hits.len();
        let plural =
            |n: u64, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        match &self.state {
            RunState::Running { progress, stopping } => {
                let spin = if unicode {
                    spinner_frame(tick).to_string()
                } else {
                    ["|", "/", "-", "\\"][(tick % 4) as usize].to_owned()
                };
                let dirs = progress.as_ref().map_or(0, |p| p.dirs_scanned);
                let mut s = format!(
                    "{spin} Searching… {} scanned · {} found",
                    plural(dirs, "dir", "dirs"),
                    found
                );
                if *stopping {
                    s.push_str(" · stopping…");
                }
                (s, false)
            }
            RunState::Done(summary) => {
                let mut s = format!(
                    "{} found · {} scanned in {:.1} s",
                    found,
                    plural(summary.dirs_scanned, "dir", "dirs"),
                    summary.elapsed.as_secs_f64()
                );
                if summary.cancelled {
                    s.push_str(" · stopped");
                }
                if summary.truncated {
                    s.push_str(" · result limit reached");
                }
                if summary.skipped_count > 0 {
                    s.push_str(&format!(
                        " · {} could not be searched",
                        plural(summary.skipped_count, "directory", "directories")
                    ));
                }
                (s, false)
            }
            RunState::Failed(e) => (format!("Search failed: {e}"), true),
        }
    }

    /// Draw the table and the status line into `area`.
    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        fmt: &Fmt,
        unicode: bool,
        tick: u64,
        theme: &Theme,
    ) {
        self.ensure();
        if area.height < 3 || area.width < 20 {
            return;
        }
        // Header, rows, status line.
        let rows_h = area.height - 2;
        self.rows = usize::from(rows_h).max(1);
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + self.rows {
            self.scroll = self.cursor + 1 - self.rows;
        }
        let size_w: u16 = 10;
        let date_w = fmt.date_width();
        let perm_w: u16 = 11;
        // Marker, then " " between the columns.
        let fixed = 2 + size_w + date_w + perm_w + 3;
        let rest = area.width.saturating_sub(fixed);
        let name_w = (rest * 2 / 5).max(8);
        let path_w = rest.saturating_sub(name_w + 1);
        let widths = [name_w, path_w, size_w, date_w, perm_w];
        let arrow = |col: SortCol| {
            if self.sort != col {
                ""
            } else if self.descending {
                if unicode { " ▼" } else { " v" }
            } else if unicode {
                " ▲"
            } else {
                " ^"
            }
        };
        let header = [
            format!("Name{}", arrow(SortCol::Name)),
            format!("Path{}", arrow(SortCol::Path)),
            format!("Size{}", arrow(SortCol::Size)),
            format!("Modified{}", arrow(SortCol::Modified)),
            format!("Permissions{}", arrow(SortCol::Permissions)),
        ];
        let mut spans = vec![Span::raw("  ")];
        for (i, (h, w)) in header.iter().zip(widths).enumerate() {
            let w = usize::from(w);
            let cell = if i == 2 {
                format!("{h:>w$.w$}")
            } else {
                format!("{h:<w$.w$}")
            };
            spans.push(Span::styled(cell, theme.title));
            if i < 4 {
                spans.push(Span::raw(" "));
            }
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(area.x, area.y, area.width, 1),
        );
        let mut lines = Vec::new();
        for (row, &i) in self
            .view
            .iter()
            .enumerate()
            .skip(self.scroll)
            .take(self.rows)
        {
            let hit = &self.hits[i];
            let selected = self.selected.contains(&hit.path);
            let mark = match (selected, unicode) {
                (true, true) => "✓ ",
                (true, false) => "* ",
                _ => "  ",
            };
            let mut name = hit.entry.name.clone();
            if hit.is_dir() {
                name.push('/');
            }
            let parent = hit.path.parent().unwrap_or_else(RemotePath::root);
            let path = match self.side {
                Side::Local => display_native(&parent),
                Side::Remote => parent.to_string(),
            };
            let size = if hit.is_dir() {
                String::new()
            } else {
                hit.entry
                    .size
                    .map(|b| format::size(b, fmt.size_format, fmt.separators))
                    .unwrap_or_default()
            };
            let modified = hit
                .entry
                .modified
                .as_ref()
                .map(|t| format::date(t, &fmt.date_format, &fmt.time_format, fmt.offset))
                .unwrap_or_default();
            let perms = hit
                .entry
                .permissions
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            let [nw, pw, sw, dw, mw] = widths.map(usize::from);
            let base = if row == self.cursor {
                theme.selection
            } else if selected {
                theme.title
            } else {
                Style::new()
            };
            let name_style = if hit.is_dir() && row != self.cursor {
                theme.dir.patch(base)
            } else {
                base
            };
            lines.push(Line::from(vec![
                Span::styled(mark, base),
                Span::styled(format!("{} ", fit(&name, nw)), name_style),
                Span::styled(
                    format!(
                        "{} {size:>sw$.sw$} {modified:<dw$.dw$} {perms:<mw$.mw$}",
                        fit(&path, pw)
                    ),
                    base,
                ),
            ]));
        }
        if self.view.is_empty() {
            let text = if self.hits.is_empty() {
                if self.is_running() {
                    "Nothing found yet"
                } else {
                    "Nothing found"
                }
            } else {
                "No result matches the filter"
            };
            lines.push(Line::styled(format!("  {text}"), theme.dim));
        }
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(area.x, area.y + 1, area.width, rows_h),
        );
        let (status, error) = self.status(tick, unicode);
        let mut right = Vec::new();
        if !self.selected.is_empty() {
            right.push(format!("{} selected", self.selected.len()));
        }
        if self.sort != SortCol::Found {
            right.push(format!(
                "by {}{}",
                self.sort.label(),
                if self.descending { " (desc)" } else { "" }
            ));
        }
        if self.typing || !self.filter.is_empty() {
            right.push(format!(
                "/{}{}",
                self.filter,
                if self.typing { "_" } else { "" }
            ));
        }
        let right = right.join(" · ");
        let y = area.bottom() - 1;
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!(" {status}"),
                if error { theme.error } else { theme.key_hint },
            )),
            Rect::new(area.x, y, area.width, 1),
        );
        if !right.is_empty() {
            let w = u16::try_from(right.chars().count() + 1).unwrap_or(area.width);
            let w = w.min(area.width);
            frame.render_widget(
                Paragraph::new(Span::styled(right, theme.key_hint)),
                Rect::new(area.right() - w, y, w, 1),
            );
        }
    }
}

/// `text` cut to `width` columns (with `…`) and padded; made safe to draw.
fn fit(text: &str, width: usize) -> String {
    crate::ui::safe_text::fit_right(text, width, '…')
}
