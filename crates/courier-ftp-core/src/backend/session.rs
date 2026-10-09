//! [`SessionHandle`]: a [`Backend`] behind a mutex, with connect retries,
//! reconnect-once, keep-alive and cancellation.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::{Backend, BackendContext, Capabilities, Listing, SessionSecurityInfo};
use crate::events::{CoreEvent, DisconnectReason, SessionId, SessionPurpose};
use crate::model::{Entry, RemotePath};
use crate::settings::DebugLevel;
use crate::{Error, Result};

/// How long the drop of the last handle waits for the polite `disconnect()`.
const DROP_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Options of a [`SessionHandle`].
#[derive(Clone, Copy, Debug)]
pub struct SessionOptions {
    /// What the session is used for (reported in `SessionOpened`).
    pub purpose: SessionPurpose,
    /// Reconnect once when an operation fails with `is_connection_lost()`. Default true.
    pub reconnect: bool,
    /// Run the keep-alive task (also requires settings `connection.keepalive`). Default
    /// true.
    pub keepalive: bool,
}

impl SessionOptions {
    /// Defaults (reconnect and keep-alive on) for `purpose`.
    pub fn new(purpose: SessionPurpose) -> Self {
        Self {
            purpose,
            reconnect: true,
            keepalive: true,
        }
    }
}

impl Default for SessionOptions {
    /// A browsing session with reconnect and keep-alive on.
    fn default() -> Self {
        Self::new(SessionPurpose::Browse)
    }
}

/// Connection state of a [`SessionHandle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Not connected (new, disconnected on request, or connection lost).
    Disconnected,
    /// First connect in progress.
    Connecting,
    /// Connected and logged in.
    Connected,
    /// Connecting again after a lost connection.
    Reconnecting,
    /// Connecting failed (after retries); the message is the error's Display text.
    Failed(String),
}

/// The shared state of one session.
struct Inner {
    id: SessionId,
    ctx: BackendContext,
    opts: SessionOptions,
    backend: Arc<AsyncMutex<Box<dyn Backend>>>,
    state: watch::Sender<SessionState>,
    caps: Mutex<Capabilities>,
    security: Mutex<SessionSecurityInfo>,
    last_activity: Mutex<Instant>,
    /// The connection was lost (not closed on request): the next connect is a
    /// reconnect.
    lost: AtomicBool,
    /// Cancels the keep-alive task when the last handle is dropped.
    _stop_keepalive: DropGuard,
    keepalive_task: Mutex<Option<JoinHandle<()>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Inner {
    fn set_state(&self, state: SessionState) {
        self.state.send_replace(state);
    }

    fn touch(&self) {
        *lock(&self.last_activity) = Instant::now();
    }

    /// Refreshes the cached capabilities and security info from the backend; sends
    /// `CapabilitiesChanged` when the capabilities differ.
    fn refresh(&self, b: &dyn Backend) {
        let caps = b.capabilities();
        let changed = {
            let mut cached = lock(&self.caps);
            let changed = *cached != caps;
            *cached = caps;
            changed
        };
        *lock(&self.security) = b.security_info();
        if changed {
            self.ctx
                .events
                .send(CoreEvent::CapabilitiesChanged { session: self.id });
        }
    }

    /// The connection dropped: state `Disconnected`, event `Disconnected { Lost }` and
    /// a Status line.
    fn mark_lost(&self, err: &Error, status: &str) {
        self.lost.store(true, Ordering::Release);
        self.set_state(SessionState::Disconnected);
        tracing::info!(
            session = self.id.get(),
            error = err.code(),
            "connection lost"
        );
        self.ctx.events.send(CoreEvent::Disconnected {
            session: self.id,
            reason: DisconnectReason::Lost(err.to_string()),
        });
        self.ctx.log().status(status);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The keep-alive task is stopped by `_stop_keepalive`. Close the backend politely
        // in a detached task, when there is a runtime to run it.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let backend = Arc::clone(&self.backend);
            drop(rt.spawn(async move {
                let mut b = backend.lock_owned().await;
                if b.is_connected() {
                    let _ = tokio::time::timeout(DROP_DISCONNECT_TIMEOUT, b.disconnect()).await;
                }
            }));
        }
        tracing::debug!(session = self.id.get(), "session closed");
        self.ctx
            .events
            .send(CoreEvent::SessionClosed { session: self.id });
    }
}

/// A [`Backend`] behind a tokio mutex, plus keep-alive and reconnect logic.
/// Clone = the same session; the session closes when the last clone is dropped.
///
/// Every operation connects first if needed, races the caller's cancellation token,
/// and reconnects once when the connection was lost (see `SessionOptions::reconnect`).
#[derive(Clone)]
pub struct SessionHandle {
    inner: Arc<Inner>,
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.inner.id)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// Runs one backend operation with connect-first, cancellation and reconnect-once.
/// Evaluates to `Result<(Result<T>, bool)>`: the outer error is a connect failure or
/// cancellation while waiting for the backend, the bool says whether the operation ran
/// a second time after a reconnect.
macro_rules! run_op {
    ($self:ident, $cancel:ident, |$b:ident, $c:ident| $call:expr) => {
        async {
            let cancel: &CancellationToken = $cancel;
            let mut guard = $self.acquire(cancel).await?;
            let mut reconnected = $self.ensure_connected(&mut **guard, cancel).await?;
            let mut retried = false;
            let out: Result<(Result<_>, bool)> = loop {
                let res = {
                    let $b: &mut dyn Backend = &mut **guard;
                    #[allow(unused_variables)]
                    let $c = cancel.child_token();
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => Err(Error::Cancelled),
                        r = $call => r,
                    }
                };
                match res {
                    Err(e)
                        if e.is_connection_lost() && $self.inner.opts.reconnect && !reconnected =>
                    {
                        $self.inner.mark_lost(&e, "Connection lost, reconnecting");
                        $self.connect_locked(&mut **guard, cancel).await?;
                        reconnected = true;
                        retried = true;
                    }
                    res => {
                        $self.finish_op(&**guard, res.as_ref().err());
                        break Result::Ok((res, retried));
                    }
                }
            };
            out
        }
        .await
    };
}

impl SessionHandle {
    /// Wraps `backend` (not yet connected). Emits `SessionOpened` and, when
    /// `opts.keepalive` and a tokio runtime is current, spawns the keep-alive task.
    pub fn new(
        backend: Box<dyn Backend>,
        ctx: BackendContext,
        opts: SessionOptions,
        label: String,
    ) -> Self {
        let stop = CancellationToken::new();
        let task_stop = stop.child_token();
        let caps = backend.capabilities();
        let security = backend.security_info();
        let (state, _) = watch::channel(SessionState::Disconnected);
        let id = ctx.session;
        ctx.events.send(CoreEvent::SessionOpened {
            session: id,
            purpose: opts.purpose,
            label,
        });
        let inner = Arc::new(Inner {
            id,
            ctx,
            opts,
            backend: Arc::new(AsyncMutex::new(backend)),
            state,
            caps: Mutex::new(caps),
            security: Mutex::new(security),
            last_activity: Mutex::new(Instant::now()),
            lost: AtomicBool::new(false),
            _stop_keepalive: stop.drop_guard(),
            keepalive_task: Mutex::new(None),
        });
        if opts.keepalive
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let task = rt.spawn(keepalive_task(Arc::downgrade(&inner), task_stop));
            *lock(&inner.keepalive_task) = Some(task);
        }
        Self { inner }
    }

    /// The session id.
    pub fn id(&self) -> SessionId {
        self.inner.id
    }

    /// The current connection state.
    pub fn state(&self) -> SessionState {
        self.inner.state.borrow().clone()
    }

    /// A receiver that sees every state change.
    pub fn watch_state(&self) -> watch::Receiver<SessionState> {
        self.inner.state.subscribe()
    }

    /// The backend's capabilities; the copy is refreshed after every operation.
    pub fn capabilities(&self) -> Capabilities {
        *lock(&self.inner.caps)
    }

    /// The backend's security info; the copy is refreshed after every operation.
    pub fn security_info(&self) -> SessionSecurityInfo {
        lock(&self.inner.security).clone()
    }

    /// Connects (with retries, see `connection.retries`) unless already connected.
    ///
    /// # Errors
    ///
    /// `Cancelled` on `cancel`; otherwise the last connect error.
    pub async fn connect(&self, cancel: &CancellationToken) -> Result<()> {
        let mut guard = self.acquire(cancel).await?;
        self.ensure_connected(&mut **guard, cancel).await?;
        Ok(())
    }

    /// Closes the connection politely; state `Disconnected`, event
    /// `Disconnected { Requested }`.
    ///
    /// # Errors
    ///
    /// The backend's `disconnect` error.
    pub async fn disconnect(&self) -> Result<()> {
        let mut guard = Arc::clone(&self.inner.backend).lock_owned().await;
        let was_connected = guard.is_connected() || self.state() == SessionState::Connected;
        let res = if guard.is_connected() {
            guard.disconnect().await
        } else {
            Ok(())
        };
        self.inner.lost.store(false, Ordering::Release);
        self.inner.set_state(SessionState::Disconnected);
        self.inner.refresh(&**guard);
        if was_connected {
            self.inner.ctx.events.send(CoreEvent::Disconnected {
                session: self.inner.id,
                reason: DisconnectReason::Requested,
            });
            self.inner.ctx.log().status("Disconnected from server");
        }
        res
    }

    /// [`Backend::home_dir`].
    ///
    /// # Errors
    ///
    /// `Cancelled` on `cancel`; connect errors; the backend's error.
    pub async fn home_dir(&self, cancel: &CancellationToken) -> Result<RemotePath> {
        run_op!(self, cancel, |b, c| b.home_dir())?.0
    }

    /// [`Backend::list`].
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn list(&self, dir: &RemotePath, cancel: &CancellationToken) -> Result<Listing> {
        run_op!(self, cancel, |b, c| b.list(dir, c))?.0
    }

    /// [`Backend::stat`].
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn stat(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<Entry> {
        run_op!(self, cancel, |b, c| b.stat(path))?.0
    }

    /// [`Backend::mkdir`]. On the run after a reconnect, `AlreadyExists` counts as
    /// success (the first attempt probably succeeded).
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn mkdir(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()> {
        let (res, retried) = run_op!(self, cancel, |b, c| b.mkdir(path))?;
        self.idempotent(res, retried, |e| matches!(e, Error::AlreadyExists(_)))
    }

    /// [`Backend::rmdir`]. On the run after a reconnect, `NotFound` counts as success.
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn rmdir(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()> {
        let (res, retried) = run_op!(self, cancel, |b, c| b.rmdir(path))?;
        self.idempotent(res, retried, |e| matches!(e, Error::NotFound(_)))
    }

    /// [`Backend::remove_file`]. On the run after a reconnect, `NotFound` counts as
    /// success.
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn remove_file(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()> {
        let (res, retried) = run_op!(self, cancel, |b, c| b.remove_file(path))?;
        self.idempotent(res, retried, |e| matches!(e, Error::NotFound(_)))
    }

    /// [`Backend::rename`].
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn rename(
        &self,
        from: &RemotePath,
        to: &RemotePath,
        replace: bool,
        cancel: &CancellationToken,
    ) -> Result<()> {
        run_op!(self, cancel, |b, c| b.rename(from, to, replace))?.0
    }

    /// [`Backend::chmod`].
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn chmod(
        &self,
        path: &RemotePath,
        mode: u32,
        cancel: &CancellationToken,
    ) -> Result<()> {
        run_op!(self, cancel, |b, c| b.chmod(path, mode))?.0
    }

    /// [`Backend::set_mtime`].
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn set_mtime(
        &self,
        path: &RemotePath,
        time: OffsetDateTime,
        cancel: &CancellationToken,
    ) -> Result<()> {
        run_op!(self, cancel, |b, c| b.set_mtime(path, time))?.0
    }

    /// [`Backend::raw_command`]; `cmd` is passed unchanged.
    ///
    /// # Errors
    ///
    /// As [`home_dir`](Self::home_dir).
    pub async fn raw_command(&self, cmd: &str, cancel: &CancellationToken) -> Result<String> {
        run_op!(self, cancel, |b, c| b.raw_command(cmd))?.0
    }

    /// Exclusive access for multi-step work (e.g. a transfer started from the pane, T63
    /// view/edit download). Connects / reconnects first if needed; no automatic retry
    /// while the guard is held.
    ///
    /// # Errors
    ///
    /// `Cancelled` on `cancel`; the connect error if (re)connecting fails.
    pub async fn lock(&self, cancel: &CancellationToken) -> Result<BackendGuard> {
        let mut guard = self.acquire(cancel).await?;
        self.ensure_connected(&mut **guard, cancel).await?;
        Ok(BackendGuard {
            guard,
            inner: Arc::clone(&self.inner),
        })
    }

    // ------------------------------------------------------------ internals

    /// Waits for the backend mutex, racing `cancel`.
    async fn acquire(
        &self,
        cancel: &CancellationToken,
    ) -> Result<OwnedMutexGuard<Box<dyn Backend>>> {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            g = Arc::clone(&self.inner.backend).lock_owned() => Ok(g),
        }
    }

    /// Connects unless the state is `Connected` and the backend agrees. Returns whether
    /// it connected (this counts as the operation's one reconnect).
    async fn ensure_connected(
        &self,
        b: &mut dyn Backend,
        cancel: &CancellationToken,
    ) -> Result<bool> {
        if self.state() == SessionState::Connected {
            if b.is_connected() {
                return Ok(false);
            }
            let err = Error::Connection("connection closed".into());
            self.inner.mark_lost(&err, "Connection lost, reconnecting");
        }
        self.connect_locked(b, cancel).await?;
        Ok(true)
    }

    /// Connects with retries (see `connection.retries` / `connection.retry_delay_secs`).
    async fn connect_locked(&self, b: &mut dyn Backend, cancel: &CancellationToken) -> Result<()> {
        let inner = &*self.inner;
        let (retries, delay) = {
            let s = inner.ctx.settings.borrow();
            (
                u32::from(s.connection.retries),
                Duration::from_secs(u64::from(s.connection.retry_delay_secs)),
            )
        };
        let reconnecting = inner.lost.load(Ordering::Acquire);
        inner.set_state(if reconnecting {
            SessionState::Reconnecting
        } else {
            SessionState::Connecting
        });
        inner
            .ctx
            .events
            .send(CoreEvent::Connecting { session: inner.id });
        let log = inner.ctx.log();
        let attempts = 1 + retries;
        let mut attempt = 1;
        let result = loop {
            let res = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                r = b.connect(cancel.child_token()) => r,
            };
            let err = match res {
                Ok(()) => break Ok(()),
                Err(e) => e,
            };
            let retry = attempt < attempts
                && err.is_transient()
                && !matches!(err, Error::ConnectionLimit(_));
            if !matches!(err, Error::Cancelled) {
                log.status(format!("Connection attempt failed with \"{err}\"."));
                tracing::info!(
                    session = inner.id.get(),
                    error = err.code(),
                    "connection attempt failed"
                );
            }
            if !retry {
                break Err(err);
            }
            let left = attempts - attempt;
            let noun = if left == 1 { "attempt" } else { "attempts" };
            log.status(format!("Waiting to retry... ({left} {noun} left)"));
            let waited = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                () = tokio::time::sleep(delay) => Ok(()),
            };
            if let Err(e) = waited {
                break Err(e);
            }
            attempt += 1;
        };
        inner.touch();
        inner.refresh(b);
        match result {
            Ok(()) => {
                inner.lost.store(false, Ordering::Release);
                inner.set_state(SessionState::Connected);
                tracing::info!(session = inner.id.get(), "connected");
                if let Some(address) = b.address() {
                    tracing::debug!(session = inner.id.get(), host = %address.host, "connected to host");
                    inner.ctx.events.send(CoreEvent::Connected {
                        session: inner.id,
                        address: address.clone(),
                    });
                }
                Ok(())
            }
            Err(err) => {
                let msg = err.to_string();
                inner.set_state(SessionState::Failed(msg.clone()));
                inner.ctx.events.send(CoreEvent::Disconnected {
                    session: inner.id,
                    reason: DisconnectReason::Failed(msg),
                });
                if !matches!(err, Error::Cancelled) {
                    log.error("Could not connect to server");
                }
                Err(err)
            }
        }
    }

    /// Bookkeeping after an operation's final run.
    fn finish_op(&self, b: &dyn Backend, err: Option<&Error>) {
        let inner = &*self.inner;
        match err {
            Some(e) if e.is_connection_lost() => inner.mark_lost(e, "Connection lost"),
            Some(Error::Cancelled) if !b.is_connected() => {
                inner.lost.store(true, Ordering::Release);
                inner.set_state(SessionState::Disconnected);
            }
            _ => {}
        }
        inner.touch();
        inner.refresh(b);
    }

    /// Treats `ok_err` as success on a run after a reconnect.
    fn idempotent(&self, res: Result<()>, retried: bool, ok_err: fn(&Error) -> bool) -> Result<()> {
        match res {
            Err(e) if retried && ok_err(&e) => {
                self.inner.ctx.log().debug(
                    DebugLevel::Info as u8,
                    format!("Treating \"{e}\" after the reconnect as success"),
                );
                Ok(())
            }
            res => res,
        }
    }

    /// The keep-alive task's handle (tests).
    #[cfg(test)]
    pub(crate) fn take_keepalive_task(&self) -> Option<JoinHandle<()>> {
        lock(&self.inner.keepalive_task).take()
    }

    /// A weak reference to the shared state (tests).
    #[cfg(test)]
    pub(crate) fn weak_inner(&self) -> Weak<dyn std::any::Any + Send + Sync> {
        let any: Arc<dyn std::any::Any + Send + Sync> = self.inner.clone();
        Arc::downgrade(&any)
    }
}

/// The keep-alive loop: see the module docs of `SessionHandle` (T03 "Keep-alive task").
async fn keepalive_task(weak: Weak<Inner>, stop: CancellationToken) {
    loop {
        let interval = {
            let Some(inner) = weak.upgrade() else { return };
            let secs = inner
                .ctx
                .settings
                .borrow()
                .connection
                .keepalive_interval_secs;
            Duration::from_secs(u64::from(secs.max(1)))
        };
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
        let Some(inner) = weak.upgrade() else { return };
        let (enabled, timeout) = {
            let s = inner.ctx.settings.borrow();
            (
                s.connection.keepalive,
                Duration::from_secs(u64::from(s.connection.timeout_secs.max(1))),
            )
        };
        if !enabled || *inner.state.borrow() != SessionState::Connected {
            continue;
        }
        if lock(&inner.last_activity).elapsed() < interval {
            continue;
        }
        let Ok(mut b) = Arc::clone(&inner.backend).try_lock_owned() else {
            continue; // busy: skip this tick
        };
        let res = tokio::select! {
            biased;
            () = stop.cancelled() => return,
            r = tokio::time::timeout(timeout, b.keepalive()) => r.unwrap_or(Err(Error::Timeout)),
        };
        match res {
            Err(e) if e.is_connection_lost() => inner.mark_lost(&e, "Connection lost"),
            _ => inner.touch(),
        }
        inner.refresh(&**b);
    }
}

/// Exclusive access to a session's backend (from [`SessionHandle::lock`]): an owned
/// tokio mutex guard that derefs to `dyn Backend` and marks activity (and refreshes the
/// cached capabilities) on drop.
pub struct BackendGuard {
    // Field order: the mutex is released before the session reference is dropped.
    guard: OwnedMutexGuard<Box<dyn Backend>>,
    inner: Arc<Inner>,
}

impl fmt::Debug for BackendGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendGuard")
            .field("session", &self.inner.id)
            .finish_non_exhaustive()
    }
}

impl Deref for BackendGuard {
    type Target = dyn Backend;

    fn deref(&self) -> &Self::Target {
        &**self.guard
    }
}

impl DerefMut for BackendGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut **self.guard
    }
}

impl Drop for BackendGuard {
    fn drop(&mut self) {
        let b: &dyn Backend = &**self.guard;
        if *self.inner.state.borrow() == SessionState::Connected && !b.is_connected() {
            let err = Error::Connection("connection closed".into());
            self.inner.mark_lost(&err, "Connection lost");
        }
        self.inner.touch();
        self.inner.refresh(b);
    }
}
