//! The transfer queue pane (T56, FEATURES.md §5): FileZilla's three tabs
//! (queued, failed, successful) over the shared [`Queue`] (T40).
//!
//! - The queued tab groups items under a server header row
//!   (`sftp://alice@web01 — 12 files, 30.0 MiB`), collapsible with Enter.
//!   Active transfers get a second line with a progress bar, bytes, speed,
//!   elapsed time and ETA; paused items show `⏸`.
//! - The title shows the three tabs (`1`/`2`/`3` switch), the bottom border
//!   the totals ("Queue: 12 files, 30.2 MiB, ~00:02:14 remaining") and
//!   whether the queue is being processed.
//! - Rows are rebuilt only when the queue's revision (or the tab, grouping
//!   or collapsed servers) changes, and only the rows on screen are drawn, so
//!   100 000 items stay responsive.
//! - Every control works on the selection: items marked with Insert, a
//!   visual range (`v`), or the row under the cursor (a server header stands
//!   for all its items). `m` opens a menu of every action.
//!
//! The pane edits the queue directly and reports each change as
//! [`Action::QueueEdited`]; the app then cancels the transfers the change
//! took out or paused, wakes the engine and schedules the persister's write.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use courier_ftp_core::{
    events::{CoreEvent, TransferId, TransferState},
    model::{Direction, ServerAddress},
    queue::{
        ItemState, Priority, Queue, QueueItem, QueueList, QueueStats, ServerKey, SharedQueue,
        SpeedMeter, lock_queue,
    },
    settings::ExistsAction,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::sync::mpsc::UnboundedSender;

use super::{
    dialog::{choose, confirm},
    file_list::Effect,
    panes::block,
    status::human_bytes,
    theme::Theme,
};
use crate::action::Action;

/// One row of the pane.
#[derive(Debug, Clone)]
enum Row {
    /// A server header with its items (in list order) and their remaining
    /// bytes.
    Header {
        key: ServerKey,
        ids: Vec<TransferId>,
        bytes: u64,
        collapsed: bool,
    },
    Item(TransferId),
}

impl Row {
    /// The same row after a rebuild.
    fn same(&self, other: &Row) -> bool {
        match (self, other) {
            (Row::Header { key: a, .. }, Row::Header { key: b, .. }) => a == b,
            (Row::Item(a), Row::Item(b)) => a == b,
            _ => false,
        }
    }
}

/// What the engine reported about an active transfer.
#[derive(Debug, Clone, Copy)]
struct Live {
    started: Instant,
    bytes: u64,
    total: Option<u64>,
    speed: u64,
    eta: Option<Duration>,
}

/// What the cached rows were built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Built {
    revision: u64,
    tab: QueueList,
    group: bool,
    collapse: u64,
}

/// Whether the engine processes the queue, whether it holds every
/// transfer (pause all), and the one-shot action after the queue finishes
/// (T45), for the pane's bottom line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RunState {
    pub(crate) processing: bool,
    pub(crate) paused: bool,
    pub(crate) after: Option<&'static str>,
}

/// See the module docs.
pub(crate) struct QueuePane {
    queue: SharedQueue,
    tab: QueueList,
    group: bool,
    collapsed: HashSet<ServerKey>,
    /// Bumped when `collapsed` changes.
    collapse_gen: u64,
    rows: Vec<Row>,
    built: Option<Built>,
    cursor: usize,
    scroll: usize,
    anchor: Option<usize>,
    marked: HashSet<TransferId>,
    live: HashMap<TransferId, Live>,
    meter: SpeedMeter,
    failed_at: HashMap<TransferId, OffsetDateTime>,
    unicode: bool,
    offset: UtcOffset,
    /// Item rows that fit the last frame, for paging.
    page: usize,
    /// Bumped when a transfer starts or stops (not on progress).
    live_gen: u64,
    /// Totals without the running transfers' bytes, by (revision, live_gen).
    stats_cache: Option<((u64, u64), QueueStats)>,
}

impl std::fmt::Debug for QueuePane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuePane")
            .field("tab", &self.tab)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

/// `sftp://alice@web01` (port only when it isn't the default).
pub(crate) fn server_url(a: &ServerAddress) -> String {
    let mut out = format!("{}://", a.protocol.scheme());
    if let Some(user) = &a.user {
        out.push_str(user);
        out.push('@');
    }
    if a.host.contains(':') {
        out.push_str(&format!("[{}]", a.host));
    } else {
        out.push_str(&a.host);
    }
    if a.port != a.default_port() {
        out.push_str(&format!(":{}", a.port));
    }
    out
}

fn server_label(key: &ServerKey) -> String {
    match key {
        ServerKey::Quick(address) => server_url(address),
        ServerKey::Site(id) => format!("saved site {id}"),
    }
}

/// `01:02:03`.
fn hms(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn priority_name(p: Priority) -> &'static str {
    match p {
        Priority::Lowest => "Lowest",
        Priority::Low => "Low",
        Priority::Normal => "Normal",
        Priority::High => "High",
        Priority::Highest => "Highest",
    }
}

fn exists_name(a: ExistsAction) -> &'static str {
    match a {
        ExistsAction::Ask => "Ask",
        ExistsAction::Overwrite => "Overwrite",
        ExistsAction::OverwriteIfNewer => "Overwrite if source newer",
        ExistsAction::OverwriteIfSizeDiffers => "Overwrite if size differs",
        ExistsAction::OverwriteIfNewerOrSizeDiffers => "Overwrite if newer or size differs",
        ExistsAction::Resume => "Resume",
        ExistsAction::Rename => "Rename",
        ExistsAction::Skip => "Skip",
    }
}

const EXISTS_CHOICES: [ExistsAction; 8] = [
    ExistsAction::Ask,
    ExistsAction::Overwrite,
    ExistsAction::OverwriteIfNewer,
    ExistsAction::OverwriteIfSizeDiffers,
    ExistsAction::OverwriteIfNewerOrSizeDiffers,
    ExistsAction::Resume,
    ExistsAction::Rename,
    ExistsAction::Skip,
];

/// `s` fitted into `width` columns: cut from the left (paths keep their
/// file name) with an ellipsis, padded on the right.
fn fit_left(s: &str, width: usize, unicode: bool) -> String {
    let n = s.chars().count();
    if n <= width {
        return format!("{s:<width$}");
    }
    if width == 0 {
        return String::new();
    }
    let keep: String = s.chars().skip(n - (width - 1)).collect();
    format!("{}{keep}", if unicode { '…' } else { '<' })
}

/// `s` fitted into `width` columns, cut on the right.
fn fit_right(s: &str, width: usize, unicode: bool) -> String {
    let n = s.chars().count();
    if n <= width {
        return format!("{s:<width$}");
    }
    if width == 0 {
        return String::new();
    }
    let keep: String = s.chars().take(width - 1).collect();
    format!("{keep}{}", if unicode { '…' } else { '>' })
}

/// A column: its title and fixed width, or `None` to share what is left.
type Col = (&'static str, Option<usize>);

fn widths(cols: &[Col], total: usize) -> Vec<usize> {
    let gaps = cols.len().saturating_sub(1);
    let fixed: usize = cols.iter().filter_map(|c| c.1).sum();
    let flex = cols.iter().filter(|c| c.1.is_none()).count().max(1);
    let rest = total.saturating_sub(fixed + gaps);
    let share = rest / flex;
    let mut extra = rest % flex;
    cols.iter()
        .map(|c| {
            c.1.unwrap_or_else(|| {
                let w = share + usize::from(extra > 0);
                extra = extra.saturating_sub(1);
                w
            })
        })
        .collect()
}

impl QueuePane {
    pub(crate) fn new(queue: SharedQueue, unicode: bool, offset: UtcOffset) -> Self {
        Self {
            queue,
            tab: QueueList::Queued,
            group: true,
            collapsed: HashSet::new(),
            collapse_gen: 0,
            rows: Vec::new(),
            built: None,
            cursor: 0,
            scroll: 0,
            anchor: None,
            marked: HashSet::new(),
            live: HashMap::new(),
            meter: SpeedMeter::default(),
            failed_at: HashMap::new(),
            unicode,
            offset,
            page: 1,
            live_gen: 0,
            stats_cache: None,
        }
    }

    /// The shared queue.
    pub(crate) fn shared(&self) -> &SharedQueue {
        &self.queue
    }

    #[cfg(test)]
    pub(crate) fn tab(&self) -> QueueList {
        self.tab
    }

    #[cfg(test)]
    pub(crate) fn set_offset(&mut self, offset: UtcOffset) {
        self.offset = offset;
    }

    /// Totals for the pane header and the status bar, and the current speed
    /// (0 when nothing runs).
    ///
    /// Walking 100 000 items every frame is too slow, so the totals are
    /// computed again only when the queue's revision or the set of running
    /// transfers changed; the running transfers' progress is added each time.
    pub(crate) fn stats(&mut self, now: Instant) -> (QueueStats, u64) {
        let q = lock_queue(&self.queue);
        let in_queue = |q: &Queue, id: &TransferId| {
            q.get(*id)
                .filter(|i| {
                    matches!(
                        i.state,
                        ItemState::Active { .. } | ItemState::Queued | ItemState::Paused
                    )
                })
                .and_then(QueueItem::remaining)
                .unwrap_or(0)
        };
        let key = (q.revision(), self.live_gen);
        let base = match self.stats_cache {
            Some((k, base)) if k == key => base,
            _ => {
                // Transfers removed while running send no event.
                self.live
                    .retain(|id, _| q.get(*id).is_some_and(|i| i.state.is_active()));
                let mut base = q.stats(None);
                for id in self.live.keys() {
                    base.bytes = base.bytes.saturating_sub(in_queue(&q, id));
                }
                self.stats_cache = Some((key, base));
                base
            }
        };
        let mut stats = base;
        for id in self.live.keys() {
            stats.bytes = stats.bytes.saturating_add(in_queue(&q, id));
        }
        drop(q);
        let speed = if stats.active > 0 {
            self.meter.bytes_per_sec(now)
        } else {
            None
        };
        stats.eta = speed.filter(|r| r.is_finite() && *r > 0.0).map(|r| {
            #[allow(clippy::cast_precision_loss)]
            let secs = stats.bytes as f64 / r;
            Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX)
        });
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let bps = speed.map_or(0, |s| s as u64);
        (stats, bps)
    }

    /// Something from the engine.
    pub(crate) fn handle_core(&mut self, event: &CoreEvent, now: Instant) {
        match event {
            CoreEvent::TransferProgress(p) => {
                let live = self.live.entry(p.id).or_insert(Live {
                    started: now,
                    bytes: p.bytes_done,
                    total: p.total,
                    speed: 0,
                    eta: None,
                });
                let delta = p.bytes_done.saturating_sub(live.bytes);
                live.bytes = p.bytes_done;
                live.total = p.total;
                live.speed = p.speed_bps;
                live.eta = p.eta;
                if delta > 0 {
                    self.meter.record(delta, now);
                }
            }
            CoreEvent::TransferStateChanged { id, state } => {
                self.live_gen += 1;
                match state {
                    TransferState::Active => {
                        let bytes = lock_queue(&self.queue)
                            .get(*id)
                            .map_or(0, |i| match i.state {
                                ItemState::Active { progress } => progress.bytes,
                                _ => 0,
                            });
                        self.live.insert(
                            *id,
                            Live {
                                started: now,
                                bytes,
                                total: None,
                                speed: 0,
                                eta: None,
                            },
                        );
                    }
                    TransferState::Failed(_) => {
                        self.live.remove(id);
                        self.failed_at.insert(*id, OffsetDateTime::now_utc());
                    }
                    _ => {
                        self.live.remove(id);
                    }
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ rows

    /// Rebuild the rows when the queue or the view changed, keeping the
    /// cursor on the same row.
    fn refresh(&mut self) {
        let q = lock_queue(&self.queue);
        let built = Built {
            revision: q.revision(),
            tab: self.tab,
            group: self.group,
            collapse: self.collapse_gen,
        };
        if self.built == Some(built) {
            return;
        }
        let keep = self.rows.get(self.cursor).cloned();
        let mut rows = Vec::with_capacity(q.count(self.tab));
        if self.group {
            for g in q.groups(self.tab) {
                let collapsed = self.collapsed.contains(&g.key);
                let items = if collapsed { Vec::new() } else { g.ids.clone() };
                rows.push(Row::Header {
                    key: g.key,
                    ids: g.ids,
                    bytes: g.bytes,
                    collapsed,
                });
                rows.extend(items.into_iter().map(Row::Item));
            }
        } else {
            rows.extend(q.ids(self.tab).map(Row::Item));
        }
        if !self.marked.is_empty() {
            self.marked.retain(|id| q.get(*id).is_some());
        }
        drop(q);
        let old_cursor = self.cursor;
        self.rows = rows;
        self.built = Some(built);
        self.cursor = keep
            .and_then(|k| self.rows.iter().position(|r| r.same(&k)))
            .unwrap_or(old_cursor)
            .min(self.rows.len().saturating_sub(1));
        if self.anchor.is_some_and(|a| a >= self.rows.len()) {
            self.anchor = None;
        }
    }

    fn row_ids(row: &Row) -> Vec<TransferId> {
        match row {
            Row::Header { ids, .. } => ids.clone(),
            Row::Item(id) => vec![*id],
        }
    }

    /// The items an action applies to: marked items, else the visual range,
    /// else the row under the cursor (a header: all its items).
    fn selection(&mut self) -> Vec<TransferId> {
        self.refresh();
        if !self.marked.is_empty() {
            let q = lock_queue(&self.queue);
            return q
                .ids(self.tab)
                .filter(|id| self.marked.contains(id))
                .collect();
        }
        let (lo, hi) = match self.anchor {
            Some(a) => (a.min(self.cursor), a.max(self.cursor)),
            None => (self.cursor, self.cursor),
        };
        let mut seen = HashSet::new();
        self.rows
            .get(lo..=hi.min(self.rows.len().saturating_sub(1)))
            .unwrap_or_default()
            .iter()
            .flat_map(Self::row_ids)
            .filter(|id| seen.insert(*id))
            .collect()
    }

    fn explicit_selection(&self) -> bool {
        !self.marked.is_empty() || self.anchor.is_some()
    }

    fn clear_selection(&mut self) {
        self.marked.clear();
        self.anchor = None;
    }

    fn move_cursor(&mut self, by: isize) {
        self.refresh();
        let last = self.rows.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + by).clamp(0, last.max(0)) as usize;
    }

    fn set_tab(&mut self, tab: QueueList) {
        if self.tab != tab {
            self.tab = tab;
            self.cursor = 0;
            self.scroll = 0;
            self.clear_selection();
        }
    }

    /// Esc drops the selection.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.code == KeyCode::Esc && self.explicit_selection() {
            self.clear_selection();
            return true;
        }
        false
    }

    // ------------------------------------------------------------ actions

    /// Whether `action` is one the pane handles when it has focus.
    pub(crate) fn handles(action: &Action) -> bool {
        matches!(
            action,
            Action::CursorDown
                | Action::CursorUp
                | Action::PageDown
                | Action::PageUp
                | Action::HalfPageDown
                | Action::HalfPageUp
                | Action::Top
                | Action::Bottom
                | Action::Open
                | Action::ToggleSelect
                | Action::VisualSelect
                | Action::SelectAll
                | Action::QueueToggleItem
                | Action::PriorityUp
                | Action::PriorityDown
                | Action::MoveItemUp
                | Action::MoveItemDown
                | Action::MoveItemTop
                | Action::MoveItemBottom
                | Action::RemoveItem
                | Action::Requeue
                | Action::QueueClear
                | Action::QueueGroupByServer
                | Action::QueueMenu
                | Action::QueueExistsMenu
        )
    }

    /// Actions that apply whatever has focus (tabs, answers of the pane's
    /// dialogs).
    pub(crate) fn handles_anywhere(action: &Action) -> bool {
        matches!(
            action,
            Action::QueueTabQueued
                | Action::QueueTabFailed
                | Action::QueueTabSuccessful
                | Action::QueueSetExists(_)
                | Action::QueueRemoveAll
        )
    }

    fn edited(cancel: Vec<TransferId>, wake: bool) -> Option<Effect> {
        Some(Effect::Action(Action::QueueEdited { cancel, wake }))
    }

    /// Apply an action. `tx` receives the answers of menus and dialogs.
    pub(crate) fn update(
        &mut self,
        action: &Action,
        tx: Option<&UnboundedSender<Action>>,
    ) -> Option<Effect> {
        let page = self.page.max(1) as isize;
        match action {
            Action::CursorDown => self.move_cursor(1),
            Action::CursorUp => self.move_cursor(-1),
            Action::PageDown => self.move_cursor(page),
            Action::PageUp => self.move_cursor(-page),
            Action::HalfPageDown => self.move_cursor((page / 2).max(1)),
            Action::HalfPageUp => self.move_cursor(-(page / 2).max(1)),
            Action::Top => self.move_cursor(isize::MIN / 2),
            Action::Bottom => self.move_cursor(isize::MAX / 2),
            Action::QueueTabQueued => self.set_tab(QueueList::Queued),
            Action::QueueTabFailed => self.set_tab(QueueList::Failed),
            Action::QueueTabSuccessful => self.set_tab(QueueList::Successful),
            Action::QueueGroupByServer => {
                self.group = !self.group;
                self.anchor = None;
            }
            Action::Open => {
                self.refresh();
                if let Some(Row::Header { key, collapsed, .. }) = self.rows.get(self.cursor) {
                    let key = key.clone();
                    if *collapsed {
                        self.collapsed.remove(&key);
                    } else {
                        self.collapsed.insert(key);
                    }
                    self.collapse_gen += 1;
                    self.anchor = None;
                }
            }
            Action::ToggleSelect => {
                self.refresh();
                if let Some(row) = self.rows.get(self.cursor) {
                    let ids = Self::row_ids(row);
                    let all = ids.iter().all(|id| self.marked.contains(id));
                    for id in ids {
                        if all {
                            self.marked.remove(&id);
                        } else {
                            self.marked.insert(id);
                        }
                    }
                }
                self.move_cursor(1);
            }
            Action::VisualSelect => {
                self.anchor = match self.anchor {
                    Some(_) => None,
                    None => Some(self.cursor),
                };
            }
            Action::SelectAll => {
                self.anchor = None;
                let q = lock_queue(&self.queue);
                self.marked = q.ids(self.tab).collect();
            }
            Action::QueueToggleItem => return self.toggle_pause(),
            Action::PriorityUp => return self.shift_priority(true),
            Action::PriorityDown => return self.shift_priority(false),
            Action::MoveItemUp
            | Action::MoveItemDown
            | Action::MoveItemTop
            | Action::MoveItemBottom => return self.reorder(action),
            Action::RemoveItem => return self.remove(),
            Action::Requeue => {
                if self.tab != QueueList::Failed {
                    return None;
                }
                let sel = self.selection();
                let n = lock_queue(&self.queue).requeue_failed(&sel);
                self.clear_selection();
                if n > 0 {
                    return Self::edited(Vec::new(), true);
                }
            }
            Action::QueueClear => return self.clear(tx),
            Action::QueueRemoveAll => {
                let removed = lock_queue(&self.queue).remove_all();
                self.clear_selection();
                if removed.count > 0 {
                    return Self::edited(removed.active, false);
                }
            }
            Action::QueueSetExists(choice) => {
                let sel = self.selection();
                let mut q = lock_queue(&self.queue);
                for id in &sel {
                    let _ = q.set_on_exists(*id, *choice);
                }
                drop(q);
                if !sel.is_empty() {
                    return Self::edited(Vec::new(), false);
                }
            }
            Action::QueueMenu => return self.menu(tx),
            Action::QueueExistsMenu => {
                let mut options = vec!["Use the setting".to_owned()];
                options.extend(EXISTS_CHOICES.iter().map(|a| exists_name(*a).to_owned()));
                let (modal, rx) = choose("If the target file exists", options);
                if let Some(tx) = tx.cloned() {
                    tokio::spawn(async move {
                        if let Ok(Some(i)) = rx.await {
                            let choice = i.checked_sub(1).and_then(|i| EXISTS_CHOICES.get(i));
                            let _ = tx.send(Action::QueueSetExists(choice.copied()));
                        }
                    });
                }
                return Some(Effect::Modal(modal));
            }
            _ => {}
        }
        None
    }

    /// Pause the selection, or resume it when all of it is paused.
    fn toggle_pause(&mut self) -> Option<Effect> {
        if self.tab != QueueList::Queued {
            return None;
        }
        let sel = self.selection();
        let mut q = lock_queue(&self.queue);
        let all_paused = !sel.is_empty()
            && sel
                .iter()
                .all(|id| q.get(*id).is_some_and(|i| i.state == ItemState::Paused));
        if all_paused {
            let n = q.resume(&sel);
            drop(q);
            (n > 0).then(|| Self::edited(Vec::new(), true)).flatten()
        } else {
            let before = q.revision();
            let active = q.pause(&sel);
            let changed = q.revision() != before;
            drop(q);
            changed.then(|| Self::edited(active, false)).flatten()
        }
    }

    fn shift_priority(&mut self, up: bool) -> Option<Effect> {
        let sel = self.selection();
        let mut q = lock_queue(&self.queue);
        let current = sel.first().and_then(|id| q.get(*id)).map(|i| i.priority)?;
        let i = Priority::ALL
            .iter()
            .position(|p| *p == current)
            .unwrap_or(2);
        let next = if up {
            Priority::ALL.get(i + 1)
        } else {
            i.checked_sub(1).and_then(|i| Priority::ALL.get(i))
        }
        .copied()
        .unwrap_or(current);
        let n = q.set_priority(&sel, next);
        drop(q);
        (n > 0).then(|| Self::edited(Vec::new(), true)).flatten()
    }

    fn reorder(&mut self, action: &Action) -> Option<Effect> {
        if self.tab != QueueList::Queued {
            return None;
        }
        let sel = self.selection();
        let mut q = lock_queue(&self.queue);
        let moved = match action {
            Action::MoveItemUp => q.move_up(&sel),
            Action::MoveItemDown => q.move_down(&sel),
            Action::MoveItemTop => q.move_to_top(&sel),
            _ => q.move_to_bottom(&sel),
        };
        drop(q);
        // The range moves with its items.
        self.anchor = None;
        moved.then(|| Self::edited(Vec::new(), true)).flatten()
    }

    /// `x`: remove the selection; on the successful tab without a selection,
    /// clear it.
    fn remove(&mut self) -> Option<Effect> {
        if self.tab == QueueList::Successful && !self.explicit_selection() {
            return self.clear(None);
        }
        let sel = self.selection();
        let removed = lock_queue(&self.queue).remove(&sel);
        self.clear_selection();
        (removed.count > 0)
            .then(|| Self::edited(removed.active, false))
            .flatten()
    }

    /// Empty the current tab (the queued tab asks first).
    fn clear(&mut self, tx: Option<&UnboundedSender<Action>>) -> Option<Effect> {
        match self.tab {
            QueueList::Queued => {
                let n = lock_queue(&self.queue).count(QueueList::Queued);
                if n == 0 {
                    return None;
                }
                let (modal, rx) = confirm(
                    "Remove all",
                    &format!(
                        "Remove all {n} file{} from the queue?",
                        if n == 1 { "" } else { "s" }
                    ),
                    false,
                );
                if let Some(tx) = tx.cloned() {
                    tokio::spawn(async move {
                        if let Ok(true) = rx.await {
                            let _ = tx.send(Action::QueueRemoveAll);
                        }
                    });
                }
                Some(Effect::Modal(modal))
            }
            QueueList::Failed => {
                let n = lock_queue(&self.queue).clear_failed();
                self.clear_selection();
                (n > 0).then(|| Self::edited(Vec::new(), false)).flatten()
            }
            QueueList::Successful => {
                let n = lock_queue(&self.queue).clear_successful();
                self.clear_selection();
                (n > 0).then(|| Self::edited(Vec::new(), false)).flatten()
            }
        }
    }

    /// The actions available for the selection on this tab, for the `m`
    /// menu.
    pub(crate) fn menu_entries(&self, processing: bool) -> Vec<(&'static str, Action)> {
        let mut v: Vec<(&'static str, Action)> = Vec::new();
        v.push((
            if processing {
                "Stop processing the queue"
            } else {
                "Process the queue"
            },
            Action::ProcessQueue,
        ));
        match self.tab {
            QueueList::Queued => {
                v.extend([
                    ("Pause / resume selected", Action::QueueToggleItem),
                    ("Priority up", Action::PriorityUp),
                    ("Priority down", Action::PriorityDown),
                    ("Move up", Action::MoveItemUp),
                    ("Move down", Action::MoveItemDown),
                    ("Move to top", Action::MoveItemTop),
                    ("Move to bottom", Action::MoveItemBottom),
                    ("If the target exists…", Action::QueueExistsMenu),
                    ("Remove selected", Action::RemoveItem),
                    ("Remove all…", Action::QueueClear),
                    (
                        "Pause / resume all transfers",
                        Action::ToggleTransfersPaused,
                    ),
                ]);
            }
            QueueList::Failed => {
                v.extend([
                    ("Reset and requeue selected", Action::Requeue),
                    ("If the target exists…", Action::QueueExistsMenu),
                    ("Remove selected", Action::RemoveItem),
                    ("Clear the failed list", Action::QueueClear),
                ]);
            }
            QueueList::Successful => {
                v.extend([
                    ("Remove selected", Action::RemoveItem),
                    ("Clear the successful list", Action::QueueClear),
                ]);
            }
        }
        v.extend([
            ("Action after queue completion…", Action::QueueAfterMenu),
            ("Group by server on/off", Action::QueueGroupByServer),
            ("Queued files", Action::QueueTabQueued),
            ("Failed transfers", Action::QueueTabFailed),
            ("Successful transfers", Action::QueueTabSuccessful),
        ]);
        v
    }

    fn menu(&mut self, tx: Option<&UnboundedSender<Action>>) -> Option<Effect> {
        let processing = lock_queue(&self.queue).is_processing();
        let entries = self.menu_entries(processing);
        let (modal, rx) = choose(
            "Queue",
            entries
                .iter()
                .map(|(label, _)| (*label).to_owned())
                .collect(),
        );
        if let Some(tx) = tx.cloned() {
            tokio::spawn(async move {
                if let Ok(Some(i)) = rx.await
                    && let Some((_, action)) = entries.into_iter().nth(i)
                {
                    let _ = tx.send(action);
                }
            });
        }
        Some(Effect::Modal(modal))
    }

    // ------------------------------------------------------------ drawing

    fn columns(&self) -> Vec<Col> {
        let dir = Some(if self.unicode { 1 } else { 2 });
        match self.tab {
            QueueList::Queued => vec![
                ("Local file", None),
                ("", dir),
                ("Remote file", None),
                ("Size", Some(10)),
                ("Priority", Some(8)),
                ("Status", Some(12)),
            ],
            QueueList::Failed => vec![
                ("Local file", None),
                ("", dir),
                ("Remote file", None),
                ("Size", Some(10)),
                ("Time", Some(8)),
                ("Reason", None),
            ],
            QueueList::Successful => vec![
                ("Local file", None),
                ("", dir),
                ("Remote file", None),
                ("Size", Some(10)),
                ("Time", Some(8)),
                ("Duration", Some(8)),
                ("Avg speed", Some(12)),
            ],
        }
    }

    fn time(&self, t: OffsetDateTime) -> String {
        t.to_offset(self.offset)
            .format(format_description!("[hour]:[minute]:[second]"))
            .unwrap_or_default()
    }

    fn cells(&self, item: &QueueItem, indent: bool) -> Vec<String> {
        let u = self.unicode;
        let mut local = item.local.to_display();
        if indent {
            local.insert_str(0, "  ");
        }
        let dir = match (item.direction, u) {
            (Direction::Upload, true) => "→",
            (Direction::Download, true) => "←",
            (Direction::Upload, false) => "->",
            (Direction::Download, false) => "<-",
        };
        let size = item.size.map(human_bytes).unwrap_or_default();
        let mut cells = vec![local, dir.to_owned(), item.remote.to_string(), size];
        match self.tab {
            QueueList::Queued => {
                cells.push(priority_name(item.priority).to_owned());
                cells.push(match &item.state {
                    ItemState::Active { .. } => "Transferring".to_owned(),
                    ItemState::Paused => {
                        if u {
                            "⏸ Paused".to_owned()
                        } else {
                            "|| Paused".to_owned()
                        }
                    }
                    ItemState::Queued if item.attempts > 0 => format!("Retry {}", item.attempts),
                    _ => "Queued".to_owned(),
                });
            }
            QueueList::Failed => {
                let at = self
                    .failed_at
                    .get(&item.id)
                    .copied()
                    .unwrap_or(item.added_at);
                cells.push(self.time(at));
                cells.push(match &item.state {
                    ItemState::Failed { error } => error.clone(),
                    _ => String::new(),
                });
            }
            QueueList::Successful => {
                if let ItemState::Done {
                    finished_at,
                    bytes,
                    duration,
                } = &item.state
                {
                    cells[3] = human_bytes(*bytes);
                    cells.push(self.time(*finished_at));
                    cells.push(hms(*duration));
                    let secs = duration.as_secs_f64().max(0.001);
                    #[allow(
                        clippy::cast_precision_loss,
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss
                    )]
                    let speed = (*bytes as f64 / secs) as u64;
                    cells.push(format!("{}/s", human_bytes(speed)));
                }
            }
        }
        cells
    }

    fn line_of(&self, cells: &[String], widths: &[usize], style: Style) -> Line<'static> {
        let u = self.unicode;
        let mut text = String::new();
        for (i, (cell, w)) in cells.iter().zip(widths).enumerate() {
            if i > 0 {
                text.push(' ');
            }
            // Paths keep their end; everything else its start.
            if i == 0 || i == 2 {
                text.push_str(&fit_left(cell, *w, u));
            } else {
                text.push_str(&fit_right(cell, *w, u));
            }
        }
        Line::styled(text, style)
    }

    fn progress_line(&self, item: &QueueItem, width: usize, now: Instant) -> String {
        let live = self.live.get(&item.id);
        let done = live.map_or_else(
            || match item.state {
                ItemState::Active { progress } => progress.bytes,
                _ => 0,
            },
            |l| l.bytes,
        );
        let total = live.and_then(|l| l.total).or(item.size);
        let fraction = match total {
            Some(0) => 1.0,
            #[allow(clippy::cast_precision_loss)]
            Some(t) => (done as f64 / t as f64).clamp(0.0, 1.0),
            None => 0.0,
        };
        let bar_width = 20usize.min(width / 4).max(4);
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let filled = (fraction * bar_width as f64).round() as usize;
        let (full, empty) = if self.unicode {
            ('█', '░')
        } else {
            ('#', '-')
        };
        let bar: String = std::iter::repeat_n(full, filled)
            .chain(std::iter::repeat_n(empty, bar_width - filled))
            .collect();
        let mut text = format!(
            "    [{bar}] {:>3}%  {} / {}",
            (fraction * 100.0).floor(),
            human_bytes(done),
            total.map(human_bytes).unwrap_or_else(|| "?".to_owned()),
        );
        if let Some(l) = live {
            if l.speed > 0 {
                text.push_str(&format!("  {}/s", human_bytes(l.speed)));
            }
            text.push_str(&format!(
                "  {} elapsed",
                hms(now.saturating_duration_since(l.started))
            ));
            if let Some(eta) = l.eta {
                text.push_str(&format!("  {} left", hms(eta)));
            }
        }
        text
    }

    fn header_line(&self, key: &ServerKey, items: usize, bytes: u64, collapsed: bool) -> String {
        let u = self.unicode;
        let arrow = match (collapsed, u) {
            (true, true) => "▸",
            (false, true) => "▾",
            (true, false) => ">",
            (false, false) => "v",
        };
        let mut text = format!(
            "{arrow} {} {} {items} file{}",
            server_label(key),
            if u { "—" } else { "-" },
            if items == 1 { "" } else { "s" },
        );
        // Bytes still to transfer only mean something for queued items.
        if self.tab == QueueList::Queued {
            text.push_str(&format!(", {}", human_bytes(bytes)));
        }
        text
    }

    fn title(&self, q: &Queue, theme: &Theme) -> Line<'static> {
        let sep = if self.unicode { " │ " } else { " | " };
        let mut spans = vec![Span::raw(" ")];
        for (i, (list, label)) in [
            (QueueList::Queued, "Queued files"),
            (QueueList::Failed, "Failed transfers"),
            (QueueList::Successful, "Successful transfers"),
        ]
        .into_iter()
        .enumerate()
        {
            if i > 0 {
                spans.push(Span::styled(sep, theme.dim));
            }
            let text = format!("{label} ({})", q.count(list));
            spans.push(if list == self.tab {
                Span::styled(text, theme.title.add_modifier(Modifier::UNDERLINED))
            } else {
                Span::styled(text, theme.dim)
            });
        }
        spans.push(Span::raw(" "));
        Line::from(spans)
    }

    /// "Queue: 12 files, 30.2 MiB, ~00:02:14 remaining".
    pub(crate) fn summary(stats: &QueueStats) -> String {
        if stats.items == 0 {
            return "Queue: empty".to_owned();
        }
        let mut s = format!(
            "Queue: {} file{}, {}",
            stats.items,
            if stats.items == 1 { "" } else { "s" },
            human_bytes(stats.bytes)
        );
        if let Some(eta) = stats.eta {
            s.push_str(&format!(", ~{} remaining", hms(eta)));
        }
        s
    }

    /// Lines an item takes (active transfers have a progress line).
    fn height_of(&self, q: &Queue, row: &Row) -> usize {
        match row {
            Row::Item(id)
                if self.tab == QueueList::Queued
                    && q.get(*id).is_some_and(|i| i.state.is_active()) =>
            {
                2
            }
            _ => 1,
        }
    }

    /// Keep the cursor row (and its progress line) on screen.
    fn scroll_to_cursor(&mut self, q: &Queue, lines: usize) {
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        }
        // The first row from which the cursor row still fits, walking up
        // from the cursor (at most a screen of rows).
        let mut used = 0;
        let mut first = self.cursor;
        loop {
            used += self.rows.get(first).map_or(1, |r| self.height_of(q, r));
            if used > lines && first < self.cursor {
                first += 1;
                break;
            }
            if first == 0 || first <= self.scroll {
                break;
            }
            first -= 1;
        }
        self.scroll = self.scroll.max(first);
    }

    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        focused: bool,
        run: RunState,
        theme: &Theme,
        now: Instant,
    ) {
        let RunState {
            processing,
            paused,
            after,
        } = run;
        self.refresh();
        let (stats, _) = self.stats(now);
        let queue = self.queue.clone();
        let q = lock_queue(&queue);
        let mut summary = Self::summary(&stats);
        summary.push_str(if paused {
            " · paused"
        } else if processing {
            " · processing"
        } else if stats.items > 0 {
            " · stopped (Ctrl-p starts)"
        } else {
            ""
        });
        if let Some(after) = after {
            summary.push_str(&format!(" · then: {after}"));
        }
        if !self.unicode {
            summary = summary.replace('·', "-");
        }
        let block = block(self.title(&q, theme), focused, theme)
            .title_bottom(Line::styled(format!(" {summary} "), theme.dim));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let width = usize::from(inner.width);
        let cols = self.columns();
        let ws = widths(&cols, width);
        let mut lines: Vec<Line> = Vec::new();
        let titles: Vec<String> = cols.iter().map(|c| c.0.to_owned()).collect();
        lines.push(self.line_of(&titles, &ws, theme.title));
        let body = usize::from(inner.height).saturating_sub(1);
        self.page = body.max(1);
        if self.rows.is_empty() {
            let empty = match self.tab {
                QueueList::Queued => "The queue is empty. F5 transfers the selected files.",
                QueueList::Failed => "No failed transfers.",
                QueueList::Successful => "No successful transfers.",
            };
            lines.push(Line::styled(empty, theme.dim));
            frame.render_widget(Paragraph::new(lines), inner);
            return;
        }
        self.scroll_to_cursor(&q, body);
        let range = self
            .anchor
            .map(|a| (a.min(self.cursor), a.max(self.cursor)));
        let cursor_style = if focused {
            theme.selection
        } else {
            Style::new().add_modifier(Modifier::UNDERLINED)
        };
        let mut i = self.scroll;
        while lines.len() <= body && i < self.rows.len() {
            let row = &self.rows[i];
            let in_range = range.is_some_and(|(lo, hi)| (lo..=hi).contains(&i));
            let mut style = Style::new();
            match row {
                Row::Header {
                    key,
                    ids,
                    bytes,
                    collapsed,
                } => {
                    style = style.patch(theme.dir);
                    if in_range
                        || (!ids.is_empty() && ids.iter().all(|id| self.marked.contains(id)))
                    {
                        style = style.patch(theme.key_hint).add_modifier(Modifier::BOLD);
                    }
                    if i == self.cursor {
                        style = style.patch(cursor_style);
                    }
                    let text = self.header_line(key, ids.len(), *bytes, *collapsed);
                    lines.push(Line::styled(fit_right(&text, width, self.unicode), style));
                }
                Row::Item(id) => {
                    let Some(item) = q.get(*id) else {
                        i += 1;
                        continue;
                    };
                    if item.state == ItemState::Paused {
                        style = style.patch(theme.dim);
                    }
                    if matches!(item.state, ItemState::Failed { .. }) {
                        style = style.patch(theme.log_error);
                    }
                    if in_range || self.marked.contains(id) {
                        style = style.patch(theme.key_hint).add_modifier(Modifier::BOLD);
                    }
                    if i == self.cursor {
                        style = style.patch(cursor_style);
                    }
                    let cells = self.cells(item, self.group);
                    lines.push(self.line_of(&cells, &ws, style));
                    if self.tab == QueueList::Queued
                        && item.state.is_active()
                        && lines.len() <= body
                    {
                        let text = self.progress_line(item, width, now);
                        lines.push(Line::styled(
                            fit_right(&text, width, self.unicode),
                            theme.log_response,
                        ));
                    }
                }
            }
            i += 1;
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

#[cfg(test)]
mod tests;
