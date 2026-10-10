//! [`Queue`]: the items, the three lists and every operation on them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use time::OffsetDateTime;

use super::item::{ItemState, NewItem, Priority, Progress, QueueItem};
use crate::events::TransferId;
use crate::settings::ExistsAction;

/// Default cap of the successful list (`queue.max_successful`).
pub const DEFAULT_MAX_SUCCESSFUL: usize = 1000;

/// The three lists of the queue pane (FileZilla's tabs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueueList {
    /// "Queued files": queued, active and paused items, in queue order.
    Queued,
    /// "Failed transfers".
    Failed,
    /// "Successful transfers", oldest first, capped.
    Successful,
}

/// Errors of the engine-facing operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    /// No item with this id (removed meanwhile).
    #[error("no queue item {0:?}")]
    UnknownItem(TransferId),
    /// The item is not in a state that allows the operation.
    #[error("queue item {id:?} is not {expected}")]
    WrongState {
        /// The item.
        id: TransferId,
        /// What it needed to be.
        expected: &'static str,
    },
}

/// What a removal took out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removed {
    /// Items removed.
    pub count: usize,
    /// Removed items that were active: the engine must cancel them.
    pub active: Vec<TransferId>,
}

/// What [`Queue::fail`] did with the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOutcome {
    /// Attempts left: back to queued, at its old position.
    Requeued,
    /// Out of attempts: moved to the failed list.
    Failed,
}

/// The transfer queue (see the [module docs](super)).
///
/// Every change that alters the persisted form bumps [`Queue::revision`],
/// which the persister watches. Starting, stopping and progress updates don't
/// (an active item is persisted as queued), nor does the processing flag.
#[derive(Debug, Clone)]
pub struct Queue {
    items: HashMap<TransferId, QueueItem>,
    queued: Vec<TransferId>,
    failed: Vec<TransferId>,
    successful: VecDeque<TransferId>,
    max_successful: usize,
    next_id: u64,
    revision: u64,
    processing: bool,
}

impl Default for Queue {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SUCCESSFUL)
    }
}

fn set_of(ids: &[TransferId]) -> HashSet<TransferId> {
    ids.iter().copied().collect()
}

impl Queue {
    /// An empty queue keeping at most `max_successful` successful items.
    pub fn new(max_successful: usize) -> Self {
        Self {
            items: HashMap::new(),
            queued: Vec::new(),
            failed: Vec::new(),
            successful: VecDeque::new(),
            max_successful,
            next_id: 1,
            revision: 0,
            processing: false,
        }
    }

    /// Rebuilds a queue from items in list order (used by persistence). Items
    /// are sorted into lists by state; an `Active` item becomes `Queued`.
    /// Duplicate ids keep the first.
    pub(super) fn from_items(items: Vec<QueueItem>, max_successful: usize) -> Self {
        let mut q = Self::new(max_successful);
        for mut item in items {
            if q.items.contains_key(&item.id) {
                continue;
            }
            q.next_id = q.next_id.max(item.id.0.saturating_add(1));
            match &item.state {
                ItemState::Active { .. } => {
                    item.state = ItemState::Queued;
                    q.queued.push(item.id);
                }
                ItemState::Queued | ItemState::Paused => q.queued.push(item.id),
                ItemState::Failed { .. } => q.failed.push(item.id),
                ItemState::Done { .. } => q.successful.push_back(item.id),
            }
            q.items.insert(item.id, item);
        }
        q.trim_successful();
        q
    }

    /// Merges a restored queue into this one: into an empty queue as is (ids
    /// kept), otherwise appended to each list with new ids. Keeps this
    /// queue's cap and processing flag. Returns how many items came in.
    pub(super) fn absorb(&mut self, other: Queue) -> usize {
        let n = other.items.len();
        if n == 0 {
            return 0;
        }
        if self.is_empty() {
            let (max, processing) = (self.max_successful, self.processing);
            *self = other;
            self.max_successful = max;
            self.processing = processing;
        } else {
            let Queue {
                mut items,
                queued,
                failed,
                successful,
                ..
            } = other;
            let mut take = |q: &mut Self, old: TransferId| {
                items.remove(&old).map(|mut item| {
                    item.id = q.alloc();
                    let id = item.id;
                    q.items.insert(id, item);
                    id
                })
            };
            for old in queued {
                if let Some(id) = take(self, old) {
                    self.queued.push(id);
                }
            }
            for old in failed {
                if let Some(id) = take(self, old) {
                    self.failed.push(id);
                }
            }
            for old in successful {
                if let Some(id) = take(self, old) {
                    self.successful.push_back(id);
                }
            }
        }
        self.trim_successful();
        self.touch();
        n
    }

    /// Bumped by every change that should be persisted.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn touch(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// Whether the user started processing the queue (T41 reads this). A
    /// loaded queue is never processing. Not persisted.
    pub fn is_processing(&self) -> bool {
        self.processing
    }

    /// Starts or stops processing (the engine stops active items itself).
    pub fn set_processing(&mut self, processing: bool) {
        self.processing = processing;
    }

    /// The successful-list cap.
    pub fn max_successful(&self) -> usize {
        self.max_successful
    }

    /// Changes the successful-list cap, dropping the oldest entries over it.
    pub fn set_max_successful(&mut self, max: usize) {
        self.max_successful = max;
        if self.trim_successful() {
            self.touch();
        }
    }

    fn trim_successful(&mut self) -> bool {
        let mut trimmed = false;
        while self.successful.len() > self.max_successful {
            if let Some(id) = self.successful.pop_front() {
                self.items.remove(&id);
                trimmed = true;
            }
        }
        trimmed
    }

    // ------------------------------------------------------------- reading

    /// The item `id`.
    pub fn get(&self, id: TransferId) -> Option<&QueueItem> {
        self.items.get(&id)
    }

    /// Items in all three lists.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// No items in any list.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The number of items in `list`.
    pub fn count(&self, list: QueueList) -> usize {
        match list {
            QueueList::Queued => self.queued.len(),
            QueueList::Failed => self.failed.len(),
            QueueList::Successful => self.successful.len(),
        }
    }

    /// The ids of `list`, in display order.
    pub fn ids(&self, list: QueueList) -> Box<dyn DoubleEndedIterator<Item = TransferId> + '_> {
        match list {
            QueueList::Queued => Box::new(self.queued.iter().copied()),
            QueueList::Failed => Box::new(self.failed.iter().copied()),
            QueueList::Successful => Box::new(self.successful.iter().copied()),
        }
    }

    /// The items of `list`, in display order.
    pub fn items(&self, list: QueueList) -> impl DoubleEndedIterator<Item = &QueueItem> + '_ {
        self.ids(list).filter_map(|id| self.items.get(&id))
    }

    /// The item at `index` of `list` (for the pane's cursor).
    pub fn nth(&self, list: QueueList, index: usize) -> Option<&QueueItem> {
        let id = match list {
            QueueList::Queued => self.queued.get(index),
            QueueList::Failed => self.failed.get(index),
            QueueList::Successful => self.successful.get(index),
        }?;
        self.items.get(id)
    }

    /// Items that would be lost on quit when the queue can't be saved:
    /// queued (incl. active and paused) and failed items.
    pub fn unsaved_count(&self) -> usize {
        self.queued.len() + self.failed.len()
    }

    /// Every item, queued list first, then failed, then successful (the
    /// persisted order).
    pub(super) fn all_in_order(&self) -> impl Iterator<Item = &QueueItem> + '_ {
        self.queued
            .iter()
            .chain(self.failed.iter())
            .chain(self.successful.iter())
            .filter_map(|id| self.items.get(id))
    }

    // ------------------------------------------------------------- adding

    fn alloc(&mut self) -> TransferId {
        let id = TransferId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Appends one item to the queued list.
    pub fn add(&mut self, item: NewItem, now: OffsetDateTime) -> TransferId {
        let id = self.alloc();
        self.items.insert(id, item.into_item(id, now));
        self.queued.push(id);
        self.touch();
        id
    }

    /// Appends items to the queued list, in order.
    pub fn add_batch(
        &mut self,
        items: impl IntoIterator<Item = NewItem>,
        now: OffsetDateTime,
    ) -> Vec<TransferId> {
        let items = items.into_iter();
        let (lower, _) = items.size_hint();
        self.items.reserve(lower);
        self.queued.reserve(lower);
        let mut ids = Vec::with_capacity(lower);
        for item in items {
            let id = self.alloc();
            self.items.insert(id, item.into_item(id, now));
            self.queued.push(id);
            ids.push(id);
        }
        if !ids.is_empty() {
            self.touch();
        }
        ids
    }

    /// Replaces the directory placeholder `id` (T43) by `children`, at its
    /// position in the queued list. Returns the children's ids.
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`]; [`QueueError::WrongState`] when `id` is
    /// not a placeholder in the queued list.
    pub fn expand_placeholder(
        &mut self,
        id: TransferId,
        children: impl IntoIterator<Item = NewItem>,
        now: OffsetDateTime,
    ) -> Result<Vec<TransferId>, QueueError> {
        let item = self.items.get(&id).ok_or(QueueError::UnknownItem(id))?;
        let pos = self.queued.iter().position(|q| *q == id);
        let (Some(pos), true) = (pos, item.is_dir_placeholder) else {
            return Err(QueueError::WrongState {
                id,
                expected: "a queued directory placeholder",
            });
        };
        let mut ids = Vec::new();
        for child in children {
            let cid = self.alloc();
            self.items.insert(cid, child.into_item(cid, now));
            ids.push(cid);
        }
        self.items.remove(&id);
        self.queued.splice(pos..=pos, ids.iter().copied());
        self.touch();
        Ok(ids)
    }

    // ------------------------------------------------------------- removing

    /// Removes the selected items from whichever list holds them.
    pub fn remove(&mut self, selected: &[TransferId]) -> Removed {
        let sel = set_of(selected);
        let mut out = Removed::default();
        for id in &sel {
            if let Some(item) = self.items.remove(id) {
                out.count += 1;
                if item.state.is_active() {
                    out.active.push(*id);
                }
            }
        }
        if out.count > 0 {
            self.queued.retain(|id| !sel.contains(id));
            self.failed.retain(|id| !sel.contains(id));
            self.successful.retain(|id| !sel.contains(id));
            out.active.sort_unstable();
            self.touch();
        }
        out
    }

    /// Removes every item of the queued list (incl. active and paused).
    pub fn remove_all(&mut self) -> Removed {
        let mut out = Removed::default();
        for id in std::mem::take(&mut self.queued) {
            if let Some(item) = self.items.remove(&id) {
                out.count += 1;
                if item.state.is_active() {
                    out.active.push(id);
                }
            }
        }
        if out.count > 0 {
            self.touch();
        }
        out
    }

    /// Empties the failed list. Returns how many were removed.
    pub fn clear_failed(&mut self) -> usize {
        let n = self.failed.len();
        for id in std::mem::take(&mut self.failed) {
            self.items.remove(&id);
        }
        if n > 0 {
            self.touch();
        }
        n
    }

    /// Empties the successful list. Returns how many were removed.
    pub fn clear_successful(&mut self) -> usize {
        let n = self.successful.len();
        for id in std::mem::take(&mut self.successful) {
            self.items.remove(&id);
        }
        if n > 0 {
            self.touch();
        }
        n
    }

    // ------------------------------------------------------------- ordering

    /// Applies `f` to the queued list with the selection; bumps the revision
    /// when the order changed.
    fn reorder(
        &mut self,
        selected: &[TransferId],
        f: impl FnOnce(&mut Vec<TransferId>, &HashSet<TransferId>) -> bool,
    ) -> bool {
        if selected.is_empty() {
            return false;
        }
        let sel = set_of(selected);
        let changed = f(&mut self.queued, &sel);
        if changed {
            self.touch();
        }
        changed
    }

    /// Moves each selected queued item up by one, past the nearest unselected
    /// item (a selected block moves as a block). Returns whether anything
    /// moved.
    pub fn move_up(&mut self, selected: &[TransferId]) -> bool {
        self.reorder(selected, |q, sel| {
            let mut changed = false;
            for i in 1..q.len() {
                if sel.contains(&q[i]) && !sel.contains(&q[i - 1]) {
                    q.swap(i - 1, i);
                    changed = true;
                }
            }
            changed
        })
    }

    /// Moves each selected queued item down by one (see [`Queue::move_up`]).
    pub fn move_down(&mut self, selected: &[TransferId]) -> bool {
        self.reorder(selected, |q, sel| {
            let mut changed = false;
            for i in (0..q.len().saturating_sub(1)).rev() {
                if sel.contains(&q[i]) && !sel.contains(&q[i + 1]) {
                    q.swap(i, i + 1);
                    changed = true;
                }
            }
            changed
        })
    }

    /// Moves the selected queued items to the top, keeping their order.
    pub fn move_to_top(&mut self, selected: &[TransferId]) -> bool {
        self.reorder(selected, |q, sel| {
            let (mut front, back): (Vec<_>, Vec<_>) = q.iter().partition(|id| sel.contains(id));
            if front.is_empty() || q.starts_with(&front) {
                return false;
            }
            front.extend(back);
            *q = front;
            true
        })
    }

    /// Moves the selected queued items to the bottom, keeping their order.
    pub fn move_to_bottom(&mut self, selected: &[TransferId]) -> bool {
        self.reorder(selected, |q, sel| {
            let (back, mut front): (Vec<_>, Vec<_>) = q.iter().partition(|id| sel.contains(id));
            if back.is_empty() || q.ends_with(&back) {
                return false;
            }
            front.extend(back);
            *q = front;
            true
        })
    }

    /// Sets the priority of the selected items (any list). Returns how many
    /// changed.
    pub fn set_priority(&mut self, selected: &[TransferId], priority: Priority) -> usize {
        let mut n = 0;
        for id in set_of(selected) {
            if let Some(item) = self.items.get_mut(&id)
                && item.priority != priority
            {
                item.priority = priority;
                n += 1;
            }
        }
        if n > 0 {
            self.touch();
        }
        n
    }

    /// Sets an item's file-exists override ("apply to all", T42).
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`].
    pub fn set_on_exists(
        &mut self,
        id: TransferId,
        action: Option<ExistsAction>,
    ) -> Result<(), QueueError> {
        let item = self.items.get_mut(&id).ok_or(QueueError::UnknownItem(id))?;
        if item.on_exists != action {
            item.on_exists = action;
            self.touch();
        }
        Ok(())
    }

    /// Records a size learned later (e.g. from `SIZE` or a stat).
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`].
    pub fn set_size(&mut self, id: TransferId, size: Option<u64>) -> Result<(), QueueError> {
        let item = self.items.get_mut(&id).ok_or(QueueError::UnknownItem(id))?;
        if item.size != size {
            item.size = size;
            self.touch();
        }
        Ok(())
    }

    // ------------------------------------------------------------- failed list

    /// "Reset and requeue": the selected failed items get their attempts reset
    /// and go back to the end of the queued list, in failed-list order.
    /// Returns how many moved.
    pub fn requeue_failed(&mut self, selected: &[TransferId]) -> usize {
        let sel = set_of(selected);
        let mut moved = Vec::new();
        self.failed.retain(|id| {
            if sel.contains(id) {
                moved.push(*id);
                false
            } else {
                true
            }
        });
        self.requeue(moved)
    }

    /// "Reset and requeue" for the whole failed list.
    pub fn requeue_all_failed(&mut self) -> usize {
        let moved = std::mem::take(&mut self.failed);
        self.requeue(moved)
    }

    fn requeue(&mut self, ids: Vec<TransferId>) -> usize {
        let n = ids.len();
        for id in &ids {
            if let Some(item) = self.items.get_mut(id) {
                item.attempts = 0;
                item.state = ItemState::Queued;
            }
        }
        self.queued.extend(ids);
        if n > 0 {
            self.touch();
        }
        n
    }

    // ------------------------------------------------------------- pause

    /// Pauses the selected queued or active items (excluded from scheduling).
    /// Returns the paused items that were active: the engine must stop them.
    pub fn pause(&mut self, selected: &[TransferId]) -> Vec<TransferId> {
        let mut active = Vec::new();
        let mut changed = false;
        for id in set_of(selected) {
            if let Some(item) = self.items.get_mut(&id) {
                match item.state {
                    ItemState::Queued => {}
                    ItemState::Active { .. } => active.push(id),
                    _ => continue,
                }
                item.state = ItemState::Paused;
                changed = true;
            }
        }
        if changed {
            self.touch();
        }
        active.sort_unstable();
        active
    }

    /// Resumes the selected paused items. Returns how many.
    pub fn resume(&mut self, selected: &[TransferId]) -> usize {
        let mut n = 0;
        for id in set_of(selected) {
            if let Some(item) = self.items.get_mut(&id)
                && item.state == ItemState::Paused
            {
                item.state = ItemState::Queued;
                n += 1;
            }
        }
        if n > 0 {
            self.touch();
        }
        n
    }

    // ------------------------------------------------------------- engine (T41)

    /// The next item to start: among `Queued` items for which `eligible`
    /// returns true (e.g. its server has a free connection slot), the one with
    /// the highest priority, earliest in queue order on a tie. Paused, active
    /// and failed items are never returned.
    pub fn next_runnable(
        &self,
        mut eligible: impl FnMut(&QueueItem) -> bool,
    ) -> Option<TransferId> {
        let mut best: Option<&QueueItem> = None;
        for id in &self.queued {
            let Some(item) = self.items.get(id) else {
                continue;
            };
            if !item.state.is_queued() || best.is_some_and(|b| item.priority <= b.priority) {
                continue;
            }
            if eligible(item) {
                if item.priority == Priority::Highest {
                    return Some(item.id);
                }
                best = Some(item);
            }
        }
        best.map(|b| b.id)
    }

    fn get_mut_in(
        &mut self,
        id: TransferId,
        ok: impl FnOnce(&ItemState) -> bool,
        expected: &'static str,
    ) -> Result<&mut QueueItem, QueueError> {
        let item = self.items.get_mut(&id).ok_or(QueueError::UnknownItem(id))?;
        if ok(&item.state) {
            Ok(item)
        } else {
            Err(QueueError::WrongState { id, expected })
        }
    }

    /// Marks a queued item active (the engine started it).
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`], [`QueueError::WrongState`] unless queued.
    pub fn start(&mut self, id: TransferId) -> Result<(), QueueError> {
        let item = self.get_mut_in(id, ItemState::is_queued, "queued")?;
        // No revision bump: an active item is persisted as queued anyway.
        item.state = ItemState::Active {
            progress: Progress::default(),
        };
        Ok(())
    }

    /// Updates an active item's progress. Doesn't bump the revision.
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`], [`QueueError::WrongState`] unless active.
    pub fn set_progress(&mut self, id: TransferId, bytes: u64) -> Result<(), QueueError> {
        let item = self.get_mut_in(id, ItemState::is_active, "active")?;
        item.state = ItemState::Active {
            progress: Progress { bytes },
        };
        Ok(())
    }

    /// Puts an active item back to queued at its position (the engine stopped
    /// it, e.g. processing was stopped).
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`], [`QueueError::WrongState`] unless active.
    pub fn stop(&mut self, id: TransferId) -> Result<(), QueueError> {
        let item = self.get_mut_in(id, ItemState::is_active, "active")?;
        item.state = ItemState::Queued;
        Ok(())
    }

    /// An active item finished: moves it to the successful list (dropping the
    /// oldest successful items over the cap).
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`], [`QueueError::WrongState`] unless active.
    pub fn finish(
        &mut self,
        id: TransferId,
        bytes: u64,
        duration: Duration,
        now: OffsetDateTime,
    ) -> Result<(), QueueError> {
        let item = self.get_mut_in(id, ItemState::is_active, "active")?;
        item.state = ItemState::Done {
            finished_at: now,
            bytes,
            duration,
        };
        self.queued.retain(|q| *q != id);
        self.successful.push_back(id);
        self.trim_successful();
        self.touch();
        Ok(())
    }

    /// An active item failed: counts the attempt; with attempts left
    /// (`attempts < max_attempts`) it goes back to queued at its position,
    /// otherwise to the end of the failed list.
    ///
    /// # Errors
    /// [`QueueError::UnknownItem`], [`QueueError::WrongState`] unless active.
    pub fn fail(
        &mut self,
        id: TransferId,
        error: impl Into<String>,
        max_attempts: u8,
    ) -> Result<FailOutcome, QueueError> {
        let item = self.get_mut_in(id, ItemState::is_active, "active")?;
        item.attempts = item.attempts.saturating_add(1);
        let outcome = if item.attempts < max_attempts {
            item.state = ItemState::Queued;
            FailOutcome::Requeued
        } else {
            item.state = ItemState::Failed {
                error: error.into(),
            };
            self.queued.retain(|q| *q != id);
            self.failed.push(id);
            FailOutcome::Failed
        };
        self.touch();
        Ok(outcome)
    }
}
