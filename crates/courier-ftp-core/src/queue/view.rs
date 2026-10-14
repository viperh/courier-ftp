//! Read-only helpers for the queue pane (T56) and status bar (T57): the render
//! model with optional server grouping, statistics and a recent-speed meter.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::item::{ItemState, QueueItem, ServerKey};
use super::model::{Queue, QueueList};
use crate::events::TransferId;

/// One row of the queue pane.
#[derive(Debug, Clone, PartialEq)]
pub enum QueueRow<'a> {
    /// A server header above its items (grouped view only).
    Server(ServerHeader),
    /// An item.
    Item(&'a QueueItem),
}

/// A server header row: the server, how many items it has in the list and
/// their known remaining bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHeader {
    /// The server.
    pub key: ServerKey,
    /// Items under it.
    pub items: usize,
    /// Known remaining bytes of those items.
    pub bytes: u64,
}

/// One server's items, in list order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGroup {
    /// The server.
    pub key: ServerKey,
    /// Its items, in list order.
    pub ids: Vec<TransferId>,
    /// Known remaining bytes of those items.
    pub bytes: u64,
}

/// Queue totals for the status bar and the pane header.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct QueueStats {
    /// Items in the queued list (incl. active and paused).
    pub items: usize,
    /// Of those, active.
    pub active: usize,
    /// Of those, paused.
    pub paused: usize,
    /// Of those, without a known size.
    pub unknown_size: usize,
    /// Known bytes still to transfer in the queued list.
    pub bytes: u64,
    /// Items in the failed list.
    pub failed: usize,
    /// Items in the successful list.
    pub successful: usize,
    /// `bytes` at the given recent average speed; `None` without a speed.
    pub eta: Option<Duration>,
}

impl Queue {
    /// The items of `list` grouped by server, groups in order of first
    /// appearance (as FileZilla groups queue rows under server headers).
    pub fn groups(&self, list: QueueList) -> Vec<ServerGroup> {
        let mut index: HashMap<ServerKey, usize> = HashMap::new();
        let mut groups: Vec<ServerGroup> = Vec::new();
        for item in self.items(list) {
            let key = item.server.key();
            let i = match index.get(&key) {
                Some(i) => *i,
                None => {
                    index.insert(key.clone(), groups.len());
                    groups.push(ServerGroup {
                        key,
                        ids: Vec::new(),
                        bytes: 0,
                    });
                    groups.len() - 1
                }
            };
            let g = &mut groups[i];
            g.ids.push(item.id);
            g.bytes = g.bytes.saturating_add(item.remaining().unwrap_or(0));
        }
        groups
    }

    /// The pane's rows for `list`: items in order, or, with `group_by_server`,
    /// a [`ServerHeader`] before each server's items.
    pub fn rows(&self, list: QueueList, group_by_server: bool) -> Vec<QueueRow<'_>> {
        if !group_by_server {
            return self.items(list).map(QueueRow::Item).collect();
        }
        let groups = self.groups(list);
        let mut rows = Vec::with_capacity(self.count(list) + groups.len());
        for g in groups {
            rows.push(QueueRow::Server(ServerHeader {
                key: g.key,
                items: g.ids.len(),
                bytes: g.bytes,
            }));
            rows.extend(
                g.ids
                    .iter()
                    .filter_map(|id| self.get(*id))
                    .map(QueueRow::Item),
            );
        }
        rows
    }

    /// Totals; `bytes_per_sec` (e.g. [`SpeedMeter::bytes_per_sec`]) gives the
    /// estimated time.
    pub fn stats(&self, bytes_per_sec: Option<f64>) -> QueueStats {
        let mut s = QueueStats {
            failed: self.count(QueueList::Failed),
            successful: self.count(QueueList::Successful),
            ..QueueStats::default()
        };
        for item in self.items(QueueList::Queued) {
            s.items += 1;
            match item.state {
                ItemState::Active { .. } => s.active += 1,
                ItemState::Paused => s.paused += 1,
                _ => {}
            }
            match item.remaining() {
                Some(b) => s.bytes = s.bytes.saturating_add(b),
                None => s.unknown_size += 1,
            }
        }
        s.eta = bytes_per_sec
            .filter(|r| r.is_finite() && *r > 0.0)
            .map(|r| {
                #[allow(clippy::cast_precision_loss)]
                let secs = s.bytes as f64 / r;
                Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX)
            });
        s
    }
}

/// Average transfer speed over a sliding window (default 10 s), fed with the
/// bytes each progress update adds.
#[derive(Debug, Clone)]
pub struct SpeedMeter {
    window: Duration,
    samples: VecDeque<(Instant, u64)>,
    total: u64,
}

impl Default for SpeedMeter {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl SpeedMeter {
    /// A meter averaging over `window`.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
            total: 0,
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some(&(t, b)) = self.samples.front() {
            if now.saturating_duration_since(t) > self.window {
                self.samples.pop_front();
                self.total = self.total.saturating_sub(b);
            } else {
                break;
            }
        }
    }

    /// Records `bytes` transferred at `now`.
    pub fn record(&mut self, bytes: u64, now: Instant) {
        self.expire(now);
        self.samples.push_back((now, bytes));
        self.total = self.total.saturating_add(bytes);
    }

    /// Bytes per second over the window ending at `now`; `None` with no
    /// samples in it.
    pub fn bytes_per_sec(&mut self, now: Instant) -> Option<f64> {
        self.expire(now);
        let first = self.samples.front()?.0;
        // At least one second, so a single burst doesn't read as a huge rate.
        let span = now
            .saturating_duration_since(first)
            .max(Duration::from_secs(1));
        #[allow(clippy::cast_precision_loss)]
        Some(self.total as f64 / span.as_secs_f64())
    }
}
