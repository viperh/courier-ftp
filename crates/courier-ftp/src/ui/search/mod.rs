//! File search (T65, FEATURES.md §4): FileZilla's "Search remote files"
//! dialog as a full-screen view, for remote and local directories.
//!
//! The view has two pages:
//!
//! - **The query form** ([`form`]): *Local* / *Remote*, the start directory
//!   (the pane's current directory), condition rows (the T67 filter
//!   condition editor), *All* / *Any*, case sensitivity and Files /
//!   Directories / Both.
//! - **The results** ([`results`]): hits stream in as the T49 engine finds
//!   them, with "Searching… N dirs scanned" and a spinner. `Esc`/`Ctrl-c`
//!   stop the search. Results sort (`s`, `S` reverses) and filter (`/`).
//!   Actions on the selection (or the hit under the cursor): `F5` download
//!   (remote) / upload (local) asks for the target directory and *keep
//!   directory structure* vs *flatten*; `F8`/`Delete` deletes after a
//!   confirmation; `Enter` goes to the hit in its pane and selects it.
//!
//! The view only asks; the app does the work ([`SearchRequest`] out,
//! [`SearchUpdate`] in). It stays alive for the session while hidden, so
//! `Ctrl-f` shows the last query (and its results) again.

mod form;
mod results;
#[cfg(test)]
mod tests;

use courier_ftp_core::{
    model::RemotePath,
    search::{ResultLayout, SearchHit, SearchProgress, SearchQuery, SearchSummary},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::Span,
    widgets::{Block, Clear, Paragraph},
};

use self::{
    form::{FormOutcome, QueryForm},
    results::{Results, RunState},
};
use super::{Side, theme::Theme};
pub(crate) use results::Fmt;

/// What the search view asks the app for.
#[derive(Debug, Clone)]
pub(crate) enum SearchRequest {
    /// Start this search (replacing a running one).
    Start(SearchQuery),
    /// Stop the running search.
    Cancel,
    /// Ask where to download / upload these hits.
    AskTransfer(Vec<SearchHit>),
    /// Queue the hits for `target` (from the dialog).
    Transfer {
        hits: Vec<SearchHit>,
        target: String,
        layout: ResultLayout,
    },
    /// Ask whether to delete these hits.
    AskDelete(Vec<SearchHit>),
    /// Delete them (confirmed).
    Delete(Vec<SearchHit>),
    /// Show the hit in its pane (the view hides itself).
    GoTo(SearchHit),
    /// F3 / F4: view or edit the hit in an external program (T63).
    Open(SearchHit, courier_ftp_core::edit::OpenKind),
    /// (From the app itself) the target directories are ready: queue these.
    Queue(Vec<courier_ftp_core::queue::NewItem>),
}

/// What the app tells the search view.
#[derive(Debug, Clone)]
pub(crate) enum SearchUpdate {
    Found(Vec<SearchHit>),
    Progress(SearchProgress),
    Done(SearchSummary),
    Failed(String),
    /// These hits (and what was below them) were deleted.
    Deleted(Vec<RemotePath>),
}

/// What the view needs when it opens.
#[derive(Debug, Clone)]
pub(crate) struct SearchOpts {
    /// The side to search (the focused pane's).
    pub(crate) side: Side,
    /// The current directory of the local and the remote pane, as typed.
    pub(crate) dirs: [String; 2],
    pub(crate) unicode: bool,
    pub(crate) fmt: Fmt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    Form,
    Results,
}

/// Key hints under the results, long and short.
const RESULT_HINTS: &str = "Space select · a all · Enter go to · F3 view · F4 edit · F5 copy · \
                            F8 delete · / filter · s/S sort · n new · Esc stop";
const RESULT_HINTS_SHORT: &str =
    "Space select · Enter go to · F5 copy · F8 delete · / filter · s sort · n new";

/// The search view; see the [module docs](self).
pub(crate) struct SearchView {
    page: Page,
    form: QueryForm,
    results: Option<Results>,
    requests: Vec<SearchRequest>,
    hidden: bool,
    unicode: bool,
    fmt: Fmt,
    /// A message on the form page (`true`: an error).
    message: Option<String>,
}

impl SearchView {
    pub(crate) fn new(opts: SearchOpts) -> Self {
        Self {
            page: Page::Form,
            form: QueryForm::new(opts.side, opts.dirs),
            results: None,
            requests: Vec::new(),
            hidden: false,
            unicode: opts.unicode,
            fmt: opts.fmt,
            message: None,
        }
    }

    /// `Ctrl-f` again: show the view. The form (when no search runs) starts
    /// from the panes' current directories.
    pub(crate) fn reopen(&mut self, opts: SearchOpts) {
        self.hidden = false;
        self.unicode = opts.unicode;
        self.fmt = opts.fmt;
        if self.page == Page::Form && !self.is_running() {
            self.form.reopen(opts.side, opts.dirs);
            self.message = None;
        }
    }

    pub(crate) fn is_hidden(&self) -> bool {
        self.hidden
    }

    pub(crate) fn hide(&mut self) {
        self.hidden = true;
    }

    pub(crate) fn is_running(&self) -> bool {
        self.results.as_ref().is_some_and(Results::is_running)
    }

    #[cfg(test)]
    pub(crate) fn page(&self) -> Page {
        self.page
    }

    #[cfg(test)]
    pub(crate) fn form(&self) -> &QueryForm {
        &self.form
    }

    #[cfg(test)]
    pub(crate) fn results_mut(&mut self) -> Option<&mut Results> {
        self.results.as_mut()
    }

    pub(crate) fn take_requests(&mut self) -> Vec<SearchRequest> {
        std::mem::take(&mut self.requests)
    }

    /// Something from the app.
    pub(crate) fn apply_update(&mut self, update: &SearchUpdate) {
        let Some(results) = self.results.as_mut() else {
            return;
        };
        match update {
            SearchUpdate::Found(hits) => results.add(hits),
            SearchUpdate::Progress(p) => {
                if let RunState::Running { progress, .. } = &mut results.state {
                    *progress = Some(p.clone());
                }
            }
            SearchUpdate::Done(summary) => results.state = RunState::Done(summary.clone()),
            SearchUpdate::Failed(e) => results.state = RunState::Failed(e.clone()),
            SearchUpdate::Deleted(paths) => results.remove(paths),
        }
    }

    pub(crate) fn handle_paste(&mut self, text: &str) {
        match self.page {
            Page::Form => self.form.handle_paste(text),
            Page::Results => {
                if let Some(r) = self.results.as_mut().filter(|r| r.typing) {
                    let mut filter = r.filter.clone();
                    filter.extend(text.chars().filter(|c| !c.is_control()));
                    r.set_filter(filter);
                }
            }
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        match self.page {
            Page::Form => match self.form.handle_key(key) {
                FormOutcome::Keep => {}
                FormOutcome::Close => self.hidden = true,
                FormOutcome::ShowResults => {
                    if self.results.is_some() {
                        self.page = Page::Results;
                    } else {
                        self.message = Some("No search yet".into());
                    }
                }
                FormOutcome::Search(query) => self.start(query),
            },
            Page::Results => self.results_key(key),
        }
    }

    fn start(&mut self, query: SearchQuery) {
        let Ok(root) = query.walk_root() else {
            return;
        };
        let side = match query.root {
            courier_ftp_core::search::SearchRoot::Local(_) => Side::Local,
            courier_ftp_core::search::SearchRoot::Remote(_) => Side::Remote,
        };
        let mut results = Results::new(side, root);
        // Keep the way the last results were looked at.
        if let Some(old) = &self.results {
            let (col, desc) = old.sort();
            results.set_sort(col, desc);
        }
        self.results = Some(results);
        self.page = Page::Results;
        self.message = None;
        self.requests.push(SearchRequest::Start(query));
    }

    fn stop(&mut self) {
        if let Some(r) = self.results.as_mut()
            && let RunState::Running { stopping, .. } = &mut r.state
            && !*stopping
        {
            *stopping = true;
            self.requests.push(SearchRequest::Cancel);
        }
    }

    fn results_key(&mut self, key: KeyEvent) {
        let Some(r) = self.results.as_mut() else {
            self.page = Page::Form;
            return;
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if r.typing {
            match key.code {
                KeyCode::Esc => {
                    r.typing = false;
                    r.set_filter(String::new());
                }
                KeyCode::Enter | KeyCode::Down | KeyCode::Up => r.typing = false,
                KeyCode::Backspace => {
                    let mut f = r.filter.clone();
                    f.pop();
                    r.set_filter(f);
                }
                KeyCode::Char('u') if ctrl => r.set_filter(String::new()),
                KeyCode::Char(c) if !ctrl => {
                    let mut f = r.filter.clone();
                    f.push(c);
                    r.set_filter(f);
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('c') if ctrl => self.stop(),
            KeyCode::Esc => {
                if r.is_running() {
                    self.stop();
                } else if !r.filter.is_empty() {
                    r.set_filter(String::new());
                } else {
                    self.page = Page::Form;
                }
            }
            KeyCode::Char('q') => self.hidden = true,
            KeyCode::Char('n' | 'e') => self.page = Page::Form,
            KeyCode::Down | KeyCode::Char('j') => r.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => r.move_cursor(-1),
            KeyCode::PageDown => r.move_cursor(r.page()),
            KeyCode::PageUp => r.move_cursor(-r.page()),
            KeyCode::Char('d') if ctrl => r.move_cursor(r.page() / 2),
            KeyCode::Char('u') if ctrl => r.move_cursor(-r.page() / 2),
            KeyCode::Home | KeyCode::Char('g') => r.top(),
            KeyCode::End | KeyCode::Char('G') => r.bottom(),
            KeyCode::Char(' ') | KeyCode::Insert => r.toggle(),
            KeyCode::Char('a') => r.toggle_all(),
            KeyCode::Char('/') => r.typing = true,
            KeyCode::Char('s') => r.next_sort(),
            KeyCode::Char('S') => r.reverse_sort(),
            KeyCode::F(5) | KeyCode::Char('t') => {
                let hits = r.targets();
                if !hits.is_empty() {
                    self.requests.push(SearchRequest::AskTransfer(hits));
                }
            }
            KeyCode::F(8) | KeyCode::Delete | KeyCode::Char('D') => {
                let hits = r.targets();
                if !hits.is_empty() {
                    self.requests.push(SearchRequest::AskDelete(hits));
                }
            }
            KeyCode::Enter | KeyCode::Char('o') => {
                if let Some(hit) = r.current().cloned() {
                    self.requests.push(SearchRequest::GoTo(hit));
                }
            }
            KeyCode::F(3) | KeyCode::F(4) => {
                if let Some(hit) = r.current().cloned() {
                    let kind = if key.code == KeyCode::F(3) {
                        courier_ftp_core::edit::OpenKind::View
                    } else {
                        courier_ftp_core::edit::OpenKind::Edit
                    };
                    self.requests.push(SearchRequest::Open(hit, kind));
                }
            }
            _ => {}
        }
    }

    /// Draw over `area` (the panes; the status bar stays).
    pub(crate) fn draw(&mut self, frame: &mut Frame, area: Rect, tick: u64, theme: &Theme) {
        frame.render_widget(Clear, area);
        if area.width < 40 || area.height < 12 {
            frame.render_widget(
                Paragraph::new("terminal too small").style(theme.error),
                area,
            );
            return;
        }
        let title = match (self.page, &self.results) {
            (Page::Results, Some(r)) => {
                let root = match r.side {
                    Side::Local => courier_ftp_core::local::display_native(&r.root),
                    Side::Remote => r.root.to_string(),
                };
                let side = match r.side {
                    Side::Local => "local",
                    Side::Remote => "remote",
                };
                format!(" Search results: {side} {root} ")
            }
            _ => " Search ".to_owned(),
        };
        let block = Block::bordered()
            .title(title)
            .border_style(theme.focused_border);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        match (self.page, self.results.as_mut()) {
            (Page::Results, Some(r)) => {
                let body = Rect::new(inner.x, inner.y, inner.width, inner.height - 1);
                r.draw(frame, body, &self.fmt, self.unicode, tick, theme);
                let hints = if usize::from(inner.width) > RESULT_HINTS.chars().count() {
                    RESULT_HINTS
                } else {
                    RESULT_HINTS_SHORT
                };
                frame.render_widget(
                    Paragraph::new(Span::styled(format!(" {hints}"), theme.dim)),
                    Rect::new(inner.x, inner.bottom() - 1, inner.width, 1),
                );
            }
            _ => {
                let body = Rect::new(
                    inner.x + 1,
                    inner.y,
                    inner.width.saturating_sub(2),
                    inner.height,
                );
                self.form.draw(frame, body, self.message.as_deref(), theme);
            }
        }
    }
}
