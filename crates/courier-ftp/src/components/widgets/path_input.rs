//! `PathInput`: a `TextInput` with asynchronous `Tab` completion through a
//! [`PathCompleter`] (local paths here; remote paths through the listing cache, T53/T62).
//!
//! `Tab` with the cursor at the end spawns `complete(value)` with a 3 s timeout; the
//! task sends `Action::Wake` and [`Widget::poll`] applies the result: none → the focus
//! moves on (and the empty result is remembered until the value changes), one →
//! replaces the value, several → inserts the longest common prefix and opens a popup.
//! Completions are untrusted (remote names): drawn sanitised, inserted as text only.

use std::{sync::Arc, time::Duration};

use crossterm::event::KeyCode;
use futures::future::BoxFuture;
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot},
    task::JoinHandle,
};

use super::{Notice, TextInput, Widget, WidgetCx, WidgetOutcome};
use crate::{
    action::Action,
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, truncate_to_width, width},
};

/// How long a completion may take.
pub(crate) const COMPLETION_TIMEOUT: Duration = Duration::from_secs(3);
/// Rows of the candidate popup.
const POPUP_ROWS: usize = 10;
/// Directory entries read at most.
const MAX_ENTRIES: usize = 1000;

/// One completion candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Completion {
    /// The whole new field value.
    pub replacement: String,
    /// Shown in the popup (`docs/`).
    pub display: String,
    /// A directory (gets a trailing separator).
    pub is_dir: bool,
}

/// Produces completions for a path field.
pub(crate) trait PathCompleter: Send + Sync + 'static {
    /// Candidates for `input`; each `replacement` is the whole new field value.
    fn complete(&self, input: String) -> BoxFuture<'static, Result<Vec<Completion>, String>>;
}

type Pending = (
    String,
    oneshot::Receiver<Result<Vec<Completion>, String>>,
    JoinHandle<()>,
);

#[derive(Debug)]
struct Popup {
    items: Vec<Completion>,
    cursor: Option<usize>,
}

/// A path field with completion.
pub(crate) struct PathInput {
    input: TextInput,
    completer: Option<Arc<dyn PathCompleter>>,
    wake: UnboundedSender<Action>,
    pending: Option<Pending>,
    no_match_for: Option<String>,
    popup: Option<Popup>,
    notice: Option<Notice>,
}

impl std::fmt::Debug for PathInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathInput")
            .field("input", &self.input)
            .field("completer", &self.completer.is_some())
            .field("pending", &self.pending.is_some())
            .field("popup", &self.popup)
            .finish_non_exhaustive()
    }
}

impl Drop for PathInput {
    fn drop(&mut self) {
        if let Some((_, _, h)) = self.pending.take() {
            h.abort();
        }
    }
}

fn is_sep(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

fn common_prefix(items: &[Completion]) -> String {
    let Some(first) = items.first() else {
        return String::new();
    };
    let mut prefix: &str = &first.replacement;
    for it in &items[1..] {
        let n: usize = prefix
            .chars()
            .zip(it.replacement.chars())
            .take_while(|(a, b)| a == b)
            .map(|(a, _)| a.len_utf8())
            .sum();
        prefix = &prefix[..n];
    }
    prefix.to_owned()
}

impl PathInput {
    /// A path field; without `completer`, `Tab` is never consumed.
    pub(crate) fn new(
        initial: &str,
        completer: Option<Arc<dyn PathCompleter>>,
        wake: UnboundedSender<Action>,
    ) -> Self {
        Self {
            input: TextInput::new(initial),
            completer,
            wake,
            pending: None,
            no_match_for: None,
            popup: None,
            notice: None,
        }
    }

    /// The value.
    pub(crate) fn value(&self) -> &str {
        self.input.value()
    }

    /// Replaces the value.
    pub(crate) fn set_value(&mut self, v: &str) {
        self.input.set_value(v);
    }

    /// The inner text field (validator, error).
    pub(crate) fn input_mut(&mut self) -> &mut TextInput {
        &mut self.input
    }

    /// The inner text field.
    pub(crate) fn input(&self) -> &TextInput {
        &self.input
    }

    /// Candidates of the open popup.
    pub(crate) fn popup_items(&self) -> Option<Vec<&str>> {
        self.popup
            .as_ref()
            .map(|p| p.items.iter().map(|c| c.display.as_str()).collect())
    }

    /// A completion request is running.
    pub(crate) fn is_completing(&self) -> bool {
        self.pending.is_some()
    }

    fn start(&mut self) -> WidgetOutcome {
        let Some(completer) = self.completer.clone() else {
            return WidgetOutcome::Ignored;
        };
        let value = self.input.value().to_owned();
        if self.no_match_for.as_deref() == Some(value.as_str()) {
            return WidgetOutcome::Ignored;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.notice = Some(Notice::Status("Completion failed: no runtime".to_owned()));
            return WidgetOutcome::Consumed;
        };
        let (tx, rx) = oneshot::channel();
        let wake = self.wake.clone();
        let fut = completer.complete(value.clone());
        let task = handle.spawn(async move {
            let res = match tokio::time::timeout(COMPLETION_TIMEOUT, fut).await {
                Ok(r) => r,
                Err(_) => Err("timed out".to_owned()),
            };
            let _ = tx.send(res);
            let _ = wake.send(Action::Wake);
        });
        self.pending = Some((value, rx, task));
        WidgetOutcome::Consumed
    }

    fn apply(&mut self, requested: &str, res: Result<Vec<Completion>, String>) {
        if self.input.value() != requested {
            // The user kept typing: the result is stale.
            return;
        }
        match res {
            Err(e) => {
                self.notice = Some(Notice::Status(format!(
                    "Completion failed: {}",
                    sanitize(&e)
                )));
            }
            Ok(items) if items.is_empty() => {
                self.no_match_for = Some(requested.to_owned());
                self.notice = Some(Notice::NextField);
            }
            Ok(items) if items.len() == 1 => {
                let c = &items[0];
                let mut v = c.replacement.clone();
                if c.is_dir && !v.ends_with(is_sep) {
                    v.push('/');
                }
                self.input.set_value(&v);
            }
            Ok(items) => {
                let prefix = common_prefix(&items);
                if prefix.chars().count() > requested.chars().count() {
                    self.input.set_value(&prefix);
                }
                self.popup = Some(Popup {
                    items: items.into_iter().take(MAX_ENTRIES).collect(),
                    cursor: None,
                });
            }
        }
    }

    fn popup_key(&mut self, key: KeyChord) -> Option<WidgetOutcome> {
        let p = self.popup.as_mut()?;
        let n = p.items.len();
        let shift = key.mods.contains(Mods::SHIFT);
        let next = |c: Option<usize>| c.map_or(0, |c| (c + 1) % n);
        let prev = |c: Option<usize>| c.map_or(n - 1, |c| (c + n - 1) % n);
        match key.code {
            KeyCode::Tab if !shift => p.cursor = Some(next(p.cursor)),
            KeyCode::Down => p.cursor = Some(next(p.cursor)),
            KeyCode::Tab | KeyCode::Up => p.cursor = Some(prev(p.cursor)),
            KeyCode::Esc => self.popup = None,
            KeyCode::Enter => {
                let pick = p.items.get(p.cursor.unwrap_or(0)).cloned();
                self.popup = None;
                if let Some(c) = pick {
                    let mut v = c.replacement;
                    if c.is_dir && !v.ends_with(is_sep) {
                        v.push('/');
                    }
                    self.input.set_value(&v);
                    return Some(WidgetOutcome::Changed);
                }
            }
            _ => {
                // Typing closes the popup; the key edits the field.
                self.popup = None;
                return None;
            }
        }
        Some(WidgetOutcome::Consumed)
    }
}

impl Widget for PathInput {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if let Some(o) = self.popup_key(key) {
            return o;
        }
        if key.code == KeyCode::Tab && key.mods == Mods::NONE && self.completer.is_some() {
            if self.pending.is_some() {
                return WidgetOutcome::Consumed;
            }
            let at_end =
                self.input.cursor_index() == super::text_input::grapheme_len(self.input.value());
            if at_end {
                return self.start();
            }
            return WidgetOutcome::Ignored;
        }
        self.input.handle_key(key)
    }

    fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        self.popup = None;
        self.input.handle_paste(text)
    }

    fn poll(&mut self) -> bool {
        let Some((requested, mut rx, task)) = self.pending.take() else {
            return false;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.apply(&requested, res);
                true
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.pending = Some((requested, rx, task));
                false
            }
            Err(oneshot::error::TryRecvError::Closed) => true,
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        self.input.render(frame, area, cx);
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect, bounds: Rect, cx: &WidgetCx) {
        let Some(p) = &self.popup else {
            return;
        };
        let rows = p.items.len().min(POPUP_ROWS);
        let y = area.y.saturating_add(1);
        let avail = bounds.bottom().saturating_sub(y);
        let h = u16::try_from(rows + 2).unwrap_or(u16::MAX).min(avail);
        if h < 3 || bounds.width < 4 {
            return;
        }
        let want = p
            .items
            .iter()
            .map(|c| width(&sanitize(&c.display)))
            .max()
            .unwrap_or(0)
            + 2;
        let w = u16::try_from(want)
            .unwrap_or(u16::MAX)
            .clamp(12, bounds.width)
            .min(bounds.width);
        let x = area.x.min(bounds.right().saturating_sub(w)).max(bounds.x);
        let r = Rect::new(x, y, w, h);
        let visible = usize::from(h - 2);
        let cursor = p.cursor.unwrap_or(0);
        let start = cursor.saturating_sub(visible.saturating_sub(1));
        let inner = usize::from(w - 2);
        let lines: Vec<Line> = p
            .items
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(i, c)| {
                let t = truncate_to_width(&sanitize(&c.display), inner, cx.symbols.ellipsis)
                    .into_owned();
                let pad = inner.saturating_sub(width(&t));
                let style = if p.cursor == Some(i) {
                    cx.theme.style("list_cursor")
                } else {
                    Style::default()
                };
                Line::from(Span::styled(format!("{t}{}", " ".repeat(pad)), style))
            })
            .collect();
        frame.render_widget(Clear, r);
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_set(cx.symbols.border)
                    .border_style(cx.theme.style("popup_border")),
            ),
            r,
        );
    }

    fn is_text(&self) -> bool {
        true
    }

    fn uses_vertical_keys(&self) -> bool {
        self.popup.is_some()
    }

    fn cursor(&self, area: Rect) -> Option<Position> {
        self.input.cursor(area)
    }

    fn take_notice(&mut self) -> Option<Notice> {
        self.notice.take().or_else(|| self.input.take_notice())
    }
}

/// Completes local paths with `tokio::fs` (see the module docs of T52): `~` expands
/// to the home directory, the last separator splits directory and prefix, hidden
/// entries only when the prefix starts with `.`, case-insensitive on Windows and macOS.
#[derive(Debug, Clone, Default)]
pub(crate) struct LocalPathCompleter;

fn home_dir() -> Option<std::path::PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

impl LocalPathCompleter {
    /// The completions for `input` (also used directly by tests).
    pub(crate) async fn complete_local(input: String) -> Result<Vec<Completion>, String> {
        let (dir_typed, prefix) = match input.rfind(is_sep) {
            Some(i) => input.split_at(i + 1),
            None => ("", input.as_str()),
        };
        let dir: std::path::PathBuf = if dir_typed.is_empty() {
            ".".into()
        } else if let Some(rest) = dir_typed
            .strip_prefix('~')
            .filter(|r| r.starts_with(is_sep))
        {
            let home = home_dir().ok_or_else(|| "no home directory".to_owned())?;
            home.join(rest.trim_start_matches(is_sep))
        } else {
            dir_typed.into()
        };
        let insensitive = cfg!(any(windows, target_os = "macos"));
        let matches = |name: &str| {
            if insensitive {
                name.to_lowercase().starts_with(&prefix.to_lowercase())
            } else {
                name.starts_with(prefix)
            }
        };
        let show_hidden = prefix.starts_with('.');
        let mut rd = tokio::fs::read_dir(&dir).await.map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        let mut read = 0;
        while read < MAX_ENTRIES {
            let Some(entry) = rd.next_entry().await.map_err(|e| e.to_string())? else {
                break;
            };
            read += 1;
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name.starts_with('.') && !show_hidden) || !matches(&name) {
                continue;
            }
            let is_dir = match entry.file_type().await {
                Ok(t) if t.is_symlink() => tokio::fs::metadata(entry.path())
                    .await
                    .is_ok_and(|m| m.is_dir()),
                Ok(t) => t.is_dir(),
                Err(_) => false,
            };
            let mut replacement = format!("{dir_typed}{name}");
            let mut display = name;
            if is_dir {
                replacement.push('/');
                display.push('/');
            }
            out.push(Completion {
                replacement,
                display,
                is_dir,
            });
        }
        out.sort_by(|a, b| a.display.cmp(&b.display));
        Ok(out)
    }
}

impl PathCompleter for LocalPathCompleter {
    fn complete(&self, input: String) -> BoxFuture<'static, Result<Vec<Completion>, String>> {
        Box::pin(Self::complete_local(input))
    }
}
