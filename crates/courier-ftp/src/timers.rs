//! One-shot UI timers (T60: auto-lock, unlock countdown, quit disarm): each kind is a
//! `tokio::time::sleep` task that sends an action when it fires. Scheduling a kind
//! cancels its previous timer, and [`Timers::take_due`] tells a current firing from a
//! stale one (an action already queued when the timer was re-armed or cancelled).

use std::{collections::HashMap, hash::Hash, time::Duration};

use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle, time::Instant};

use crate::action::Action;

/// Timers keyed by kind.
#[derive(Debug)]
pub(crate) struct Timers<K> {
    tasks: HashMap<K, (Instant, JoinHandle<()>)>,
    tx: UnboundedSender<Action>,
}

impl<K: Copy + Eq + Hash + Send + 'static> Timers<K> {
    /// Timers whose actions go to `tx`.
    pub(crate) fn new(tx: UnboundedSender<Action>) -> Self {
        Self {
            tasks: HashMap::new(),
            tx,
        }
    }

    /// (Re-)schedules `kind`: `action` is sent after `after`. Needs a tokio runtime.
    pub(crate) fn schedule(&mut self, kind: K, after: Duration, action: Action) {
        self.cancel(kind);
        let tx = self.tx.clone();
        let due = Instant::now() + after;
        let handle = tokio::spawn(async move {
            tokio::time::sleep_until(due).await;
            let _ = tx.send(action);
        });
        self.tasks.insert(kind, (due, handle));
    }

    /// Cancels `kind` (nothing happens when it is not scheduled).
    pub(crate) fn cancel(&mut self, kind: K) {
        if let Some((_, h)) = self.tasks.remove(&kind) {
            h.abort();
        }
    }

    /// Whether `kind` is scheduled.
    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests"))]
    pub(crate) fn is_scheduled(&self, kind: K) -> bool {
        self.tasks.contains_key(&kind)
    }

    /// A firing of `kind` arrived: true (and forgotten) when it is the current timer
    /// and due at `now`; false for a stale firing.
    pub(crate) fn take_due(&mut self, kind: K, now: Instant) -> bool {
        match self.tasks.get(&kind) {
            Some((due, _)) if now >= *due => {
                self.tasks.remove(&kind);
                true
            }
            _ => false,
        }
    }

    /// Cancels every timer.
    pub(crate) fn cancel_all(&mut self) {
        for (_, (_, h)) in self.tasks.drain() {
            h.abort();
        }
    }
}

impl<K> Drop for Timers<K> {
    fn drop(&mut self) {
        for (_, (_, h)) in self.tasks.drain() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn reschedule_cancels_and_stale_firings_are_refused() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut t = Timers::new(tx);
        t.schedule(1_u8, Duration::from_secs(5), Action::Tick);
        tokio::time::advance(Duration::from_secs(3)).await;
        t.schedule(1, Duration::from_secs(5), Action::Tick);
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err(), "the first timer was cancelled");
        assert!(!t.take_due(1, Instant::now()), "not due yet");
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(matches!(rx.try_recv(), Ok(Action::Tick)));
        assert!(t.take_due(1, Instant::now()));
        assert!(!t.is_scheduled(1));
        t.schedule(2, Duration::from_secs(1), Action::Tick);
        t.cancel_all();
        assert!(!t.take_due(2, Instant::now() + Duration::from_secs(9)));
    }
}
