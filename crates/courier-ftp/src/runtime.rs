//! Async work started by the UI (T50). UI code never awaits I/O in
//! `handle_key`/`update`/`draw`: it spawns a task here, and the task's output comes back
//! through the action channel, followed by [`Action::TaskFinished`].

use std::{collections::HashMap, future::Future, time::Duration};

use tokio::{sync::mpsc::UnboundedSender, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::{action::Action, components::main_screen::layout::Region, tabs::TabId};

/// Blocking jobs still running (tests only: `AppHarness` waits for them to finish).
#[cfg(test)]
pub(crate) static BLOCKING_IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// [`tokio::task::spawn_blocking`] for UI-started work. In tests the job is counted in
/// `BLOCKING_IN_FLIGHT` so the harness can wait for it; paused time does not.
pub(crate) fn spawn_blocking<R: Send + 'static>(
    f: impl FnOnce() -> R + Send + 'static,
) -> tokio::task::JoinHandle<R> {
    #[cfg(test)]
    {
        use std::sync::atomic::Ordering;
        struct Done;
        impl Drop for Done {
            fn drop(&mut self) {
                BLOCKING_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            }
        }
        BLOCKING_IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        tokio::task::spawn_blocking(move || {
            let _done = Done;
            f()
        })
    }
    #[cfg(not(test))]
    tokio::task::spawn_blocking(f)
}

/// Marks background work (a vault effect, T60) as in flight for as long as it lives:
/// in tests it counts in `BLOCKING_IN_FLIGHT`, so the harness waits for its result
/// (the engine's own blocking jobs do not count); a no-op in the app.
#[derive(Debug)]
pub(crate) struct InFlight(());

impl InFlight {
    /// Starts counting.
    pub(crate) fn new() -> Self {
        #[cfg(test)]
        BLOCKING_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        #[cfg(test)]
        BLOCKING_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A task started by the [`Runner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TaskId(u64);

/// Who a task belongs to (drives that owner's spinner and `Cancel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TaskOwner {
    /// A screen region.
    Region(Region),
    /// A tab.
    #[expect(dead_code, reason = "used by connection tabs (T61)")]
    Tab(TabId),
    /// The app itself (settings saves).
    App,
}

#[derive(Debug)]
struct TaskInfo {
    owner: TaskOwner,
    token: CancellationToken,
}

/// How long [`Runner::shutdown`] waits before aborting.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Spawns and tracks UI tasks.
#[derive(Debug)]
pub(crate) struct Runner {
    tasks: JoinSet<()>,
    action_tx: UnboundedSender<Action>,
    root: CancellationToken,
    next_id: u64,
    info: HashMap<TaskId, TaskInfo>,
    busy: HashMap<TaskOwner, (u32, Instant)>,
}

impl Runner {
    /// A runner sending task outputs to `action_tx`.
    pub(crate) fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            tasks: JoinSet::new(),
            action_tx,
            root: CancellationToken::new(),
            next_id: 0,
            info: HashMap::new(),
            busy: HashMap::new(),
        }
    }

    /// Spawns `make(token)`; its output action is sent to the action channel, then
    /// `Action::TaskFinished(id)`. `token` is a child of the app token.
    pub(crate) fn spawn<F, Fut>(&mut self, owner: TaskOwner, make: F) -> TaskId
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Action> + Send + 'static,
    {
        self.next_id += 1;
        let id = TaskId(self.next_id);
        let token = self.root.child_token();
        let fut = make(token.clone());
        let tx = self.action_tx.clone();
        self.tasks.spawn(async move {
            let action = fut.await;
            // The receiver is gone only while the app shuts down.
            let _ = tx.send(action);
            let _ = tx.send(Action::TaskFinished(id));
        });
        self.info.insert(id, TaskInfo { owner, token });
        let entry = self.busy.entry(owner).or_insert((0, Instant::now()));
        if entry.0 == 0 {
            entry.1 = Instant::now();
        }
        entry.0 += 1;
        trace!(?owner, "task spawned");
        id
    }

    /// Bookkeeping when `Action::TaskFinished(id)` arrives.
    pub(crate) fn finished(&mut self, id: TaskId) {
        while self.tasks.try_join_next().is_some() {}
        let Some(info) = self.info.remove(&id) else {
            return;
        };
        if let Some(entry) = self.busy.get_mut(&info.owner) {
            entry.0 = entry.0.saturating_sub(1);
            if entry.0 == 0 {
                self.busy.remove(&info.owner);
            }
        }
    }

    /// Requests cancellation of one task (its token).
    pub(crate) fn cancel(&mut self, id: TaskId) {
        if let Some(info) = self.info.get(&id) {
            info.token.cancel();
        }
    }

    /// Requests cancellation of every task of `owner`.
    pub(crate) fn cancel_owner(&mut self, owner: TaskOwner) {
        for info in self.info.values().filter(|i| i.owner == owner) {
            info.token.cancel();
        }
    }

    /// `owner` has unfinished tasks.
    pub(crate) fn is_busy(&self, owner: TaskOwner) -> bool {
        self.busy.contains_key(&owner)
    }

    /// Since when `owner` has been busy.
    pub(crate) fn busy_since(&self, owner: TaskOwner) -> Option<Instant> {
        self.busy.get(&owner).map(|(_, since)| *since)
    }

    /// Any owner other than `App` is busy (spinners animate).
    pub(crate) fn any_visible_busy(&self) -> bool {
        self.busy.keys().any(|o| *o != TaskOwner::App)
    }

    /// Tasks still in the join set.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests"))]
    pub(crate) fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Cancels everything; waits up to 2 s, then aborts the rest. No task outlives this.
    pub(crate) async fn shutdown(&mut self) {
        self.root.cancel();
        let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            warn!(
                tasks = self.tasks.len(),
                "tasks did not stop in time; aborting"
            );
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
        self.info.clear();
        self.busy.clear();
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn runner_shutdown_leaves_no_tasks() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut r = Runner::new(tx);
        for _ in 0..10 {
            r.spawn(TaskOwner::App, |_token| async {
                // Ignores its token on purpose.
                std::future::pending::<()>().await;
                Action::Tick
            });
        }
        assert_eq!(r.len(), 10);
        let start = Instant::now();
        r.shutdown().await;
        assert!(start.elapsed() <= Duration::from_millis(2100));
        assert_eq!(r.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn output_then_finished_and_busy_tracking() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut r = Runner::new(tx);
        let owner = TaskOwner::Region(Region::LocalList);
        let id = r.spawn(owner, |token| async move {
            token.cancelled().await;
            Action::StatusMessage("stopped".into())
        });
        assert!(r.is_busy(owner));
        assert!(r.any_visible_busy());
        r.cancel_owner(owner);
        assert!(matches!(rx.recv().await, Some(Action::StatusMessage(m)) if m == "stopped"));
        let Some(Action::TaskFinished(done)) = rx.recv().await else {
            panic!("expected TaskFinished");
        };
        assert_eq!(done, id);
        r.finished(done);
        assert!(!r.is_busy(owner));
        r.cancel(id);
    }
}
