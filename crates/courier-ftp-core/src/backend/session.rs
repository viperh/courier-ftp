//! [`SessionHandle`]: a shared backend with keep-alive and reconnect.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use time::OffsetDateTime;
use tokio::{
    sync::{Mutex, MutexGuard},
    time::Instant,
};
use tokio_util::sync::{CancellationToken, DropGuard};

use super::{Backend, Listing};
use crate::{
    Error, Result,
    model::{Entry, RemotePath},
};

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Owns one [`Backend`] for shared use by a tab.
///
/// - Calls are serialised through an async mutex: one operation at a time.
/// - When a call fails with [`Error::Connection`], the handle reconnects once
///   and retries the call (FileZilla behaviour). A second failure is returned.
/// - With a keep-alive interval, a background task calls
///   [`Backend::keepalive`] whenever the session has been idle that long. The
///   task stops when the handle is dropped.
///
/// Transfers use [`SessionHandle::lock`] and drive the streams themselves;
/// they are not retried here (the transfer engine has its own retry logic,
/// T41).
pub struct SessionHandle {
    inner: Arc<Inner>,
    _keepalive: Option<DropGuard>,
}

struct Inner {
    backend: Mutex<Box<dyn Backend>>,
    last_activity: std::sync::Mutex<Instant>,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("keepalive", &self._keepalive.is_some())
            .finish_non_exhaustive()
    }
}

impl Inner {
    fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    fn last(&self) -> Instant {
        self.last_activity
            .lock()
            .map_or_else(|_| Instant::now(), |l| *l)
    }
}

impl SessionHandle {
    /// Wrap `backend`. With `keepalive = Some(interval)` a keep-alive task is
    /// spawned (needs a tokio runtime).
    pub fn new(backend: Box<dyn Backend>, keepalive: Option<Duration>) -> Self {
        let inner = Arc::new(Inner {
            backend: Mutex::new(backend),
            last_activity: std::sync::Mutex::new(Instant::now()),
        });
        let guard = keepalive
            .filter(|i| !i.is_zero())
            .map(|interval| spawn_keepalive(Arc::clone(&inner), interval));
        Self {
            inner,
            _keepalive: guard,
        }
    }

    /// Connect the backend.
    pub async fn connect(&self, cancel: CancellationToken) -> Result<()> {
        let mut backend = self.inner.backend.lock().await;
        let result = backend.connect(cancel).await;
        self.inner.touch();
        result
    }

    /// Disconnect the backend.
    pub async fn disconnect(&self) -> Result<()> {
        let mut backend = self.inner.backend.lock().await;
        backend.disconnect().await
    }

    /// Exclusive access to the backend, for transfers and other multi-step
    /// work. Counts as activity for the keep-alive.
    pub async fn lock(&self) -> MutexGuard<'_, Box<dyn Backend>> {
        let guard = self.inner.backend.lock().await;
        self.inner.touch();
        guard
    }

    /// Run `op`, reconnecting once and retrying if it fails with
    /// [`Error::Connection`].
    pub async fn run<T, F>(&self, cancel: &CancellationToken, mut op: F) -> Result<T>
    where
        F: for<'a> FnMut(&'a mut dyn Backend) -> BoxFut<'a, T> + Send,
        T: Send,
    {
        let mut backend = self.inner.backend.lock().await;
        let first = op(&mut **backend).await;
        self.inner.touch();
        match first {
            Err(Error::Connection(reason)) => {
                tracing::debug!("connection lost ({reason}); reconnecting once");
                backend.connect(cancel.clone()).await?;
                let second = op(&mut **backend).await;
                self.inner.touch();
                second
            }
            other => other,
        }
    }

    /// [`Backend::home_dir`] with reconnect.
    pub async fn home_dir(&self, cancel: &CancellationToken) -> Result<RemotePath> {
        self.run(cancel, |b| Box::pin(b.home_dir())).await
    }

    /// [`Backend::list`] with reconnect.
    pub async fn list(&self, dir: &RemotePath, cancel: &CancellationToken) -> Result<Listing> {
        let token = cancel.clone();
        self.run(cancel, |b| {
            let dir = dir.clone();
            let token = token.clone();
            Box::pin(async move { b.list(&dir, token).await })
        })
        .await
    }

    /// [`Backend::stat`] with reconnect.
    pub async fn stat(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<Entry> {
        self.run(cancel, |b| {
            let path = path.clone();
            Box::pin(async move { b.stat(&path).await })
        })
        .await
    }

    /// [`Backend::mkdir`] with reconnect.
    pub async fn mkdir(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()> {
        self.run(cancel, |b| {
            let path = path.clone();
            Box::pin(async move { b.mkdir(&path).await })
        })
        .await
    }

    /// [`Backend::rmdir`] with reconnect.
    pub async fn rmdir(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()> {
        self.run(cancel, |b| {
            let path = path.clone();
            Box::pin(async move { b.rmdir(&path).await })
        })
        .await
    }

    /// [`Backend::remove_file`] with reconnect.
    pub async fn remove_file(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()> {
        self.run(cancel, |b| {
            let path = path.clone();
            Box::pin(async move { b.remove_file(&path).await })
        })
        .await
    }

    /// [`Backend::rename`] with reconnect.
    pub async fn rename(
        &self,
        from: &RemotePath,
        to: &RemotePath,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.run(cancel, |b| {
            let (from, to) = (from.clone(), to.clone());
            Box::pin(async move { b.rename(&from, &to).await })
        })
        .await
    }

    /// [`Backend::chmod`] with reconnect.
    pub async fn chmod(
        &self,
        path: &RemotePath,
        mode: u32,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.run(cancel, |b| {
            let path = path.clone();
            Box::pin(async move { b.chmod(&path, mode).await })
        })
        .await
    }

    /// [`Backend::set_mtime`] with reconnect.
    pub async fn set_mtime(
        &self,
        path: &RemotePath,
        time: OffsetDateTime,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.run(cancel, |b| {
            let path = path.clone();
            Box::pin(async move { b.set_mtime(&path, time).await })
        })
        .await
    }

    /// [`Backend::raw_command`] with reconnect.
    pub async fn raw_command(&self, cmd: &str, cancel: &CancellationToken) -> Result<String> {
        self.run(cancel, |b| {
            let cmd = cmd.to_owned();
            Box::pin(async move { b.raw_command(&cmd).await })
        })
        .await
    }
}

fn spawn_keepalive(inner: Arc<Inner>, interval: Duration) -> DropGuard {
    let token = CancellationToken::new();
    let stop = token.clone();
    tokio::spawn(async move {
        loop {
            let due = inner.last() + interval;
            tokio::select! {
                () = stop.cancelled() => break,
                () = tokio::time::sleep_until(due) => {}
            }
            if inner.last().elapsed() < interval {
                continue; // something happened while we slept
            }
            // Never wait behind a running operation: that is activity anyway.
            let Ok(mut backend) = inner.backend.try_lock() else {
                inner.touch();
                continue;
            };
            if backend.is_connected()
                && let Err(e) = backend.keepalive().await
            {
                tracing::debug!("keep-alive failed: {e}");
            }
            drop(backend);
            inner.touch();
        }
    });
    token.drop_guard()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::backend::{MockServer, TransferOpts, WriteMode};

    async fn connected(server: &MockServer, keepalive: Option<Duration>) -> SessionHandle {
        let handle = SessionHandle::new(Box::new(server.backend()), keepalive);
        handle.connect(CancellationToken::new()).await.unwrap();
        handle
    }

    #[tokio::test]
    async fn mock_round_trips() {
        let server = MockServer::new();
        server.add_file("/docs/a.txt", b"hello");
        let s = connected(&server, None).await;
        let c = CancellationToken::new();

        s.mkdir(&RemotePath::new("/docs/sub"), &c).await.unwrap();
        let names = |l: Listing| {
            let mut n: Vec<String> = l.entries.into_iter().map(|e| e.name).collect();
            n.sort();
            n
        };
        assert_eq!(
            names(s.list(&RemotePath::new("/docs"), &c).await.unwrap()),
            ["a.txt", "sub"]
        );

        s.rename(
            &RemotePath::new("/docs/a.txt"),
            &RemotePath::new("/docs/sub/b.txt"),
            &c,
        )
        .await
        .unwrap();
        assert_eq!(
            server.read_file("/docs/sub/b.txt").as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(
            s.stat(&RemotePath::new("/docs/sub/b.txt"), &c)
                .await
                .unwrap()
                .size,
            Some(5)
        );

        assert!(matches!(
            s.rmdir(&RemotePath::new("/docs/sub"), &c).await,
            Err(Error::Protocol {
                code: Some(550),
                ..
            })
        ));
        s.remove_file(&RemotePath::new("/docs/sub/b.txt"), &c)
            .await
            .unwrap();
        s.rmdir(&RemotePath::new("/docs/sub"), &c).await.unwrap();
        assert_eq!(
            names(s.list(&RemotePath::new("/docs"), &c).await.unwrap()),
            Vec::<String>::new()
        );
        assert!(matches!(
            s.stat(&RemotePath::new("/nope"), &c).await,
            Err(Error::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn mock_streams_and_write_modes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let server = MockServer::new();
        server.add_file("/f", b"0123456789");
        let s = connected(&server, None).await;
        let mut b = s.lock().await;
        let opts = TransferOpts::default();

        let mut r = b.open_read(&RemotePath::new("/f"), 4, &opts).await.unwrap();
        let mut got = String::new();
        r.read_to_string(&mut got).await.unwrap();
        assert_eq!(got, "456789");
        drop(r);
        b.finish_transfer().await.unwrap();

        let mut w = b
            .open_write(&RemotePath::new("/f"), WriteMode::ResumeAt(3), &opts)
            .await
            .unwrap();
        w.write_all(b"abc").await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        assert_eq!(server.read_file("/f").as_deref(), Some(&b"012abc"[..]));

        let mut w = b
            .open_write(&RemotePath::new("/f"), WriteMode::Append, &opts)
            .await
            .unwrap();
        w.write_all(b"!").await.unwrap();
        drop(w);
        assert_eq!(server.read_file("/f").as_deref(), Some(&b"012abc!"[..]));

        assert!(matches!(
            b.open_write(&RemotePath::new("/f"), WriteMode::Create, &opts)
                .await,
            Err(Error::AlreadyExists)
        ));
        let w = b
            .open_write(&RemotePath::new("/f"), WriteMode::Truncate, &opts)
            .await
            .unwrap();
        drop(w);
        assert_eq!(server.read_file("/f").as_deref(), Some(&b""[..]));
    }

    #[tokio::test]
    async fn reconnects_once_after_a_dropped_connection() {
        let server = MockServer::new();
        let s = connected(&server, None).await;
        server.fail_next(Error::Connection("reset by peer".into()));
        let c = CancellationToken::new();
        let listing = s.list(&RemotePath::root(), &c).await.unwrap();
        assert_eq!(listing.dir, RemotePath::root());
        assert_eq!(server.connects(), 2);
        assert_eq!(server.calls(), 2);
    }

    #[tokio::test]
    async fn second_consecutive_failure_surfaces() {
        let server = MockServer::new();
        let s = connected(&server, None).await;
        server
            .fail_next(Error::Connection("reset".into()))
            .fail_next(Error::Connection("reset again".into()));
        let result = s.list(&RemotePath::root(), &CancellationToken::new()).await;
        assert!(matches!(result, Err(Error::Connection(m)) if m == "reset again"));
        assert_eq!(server.connects(), 2);
    }

    #[tokio::test]
    async fn failed_reconnect_surfaces() {
        let server = MockServer::new();
        let s = connected(&server, None).await;
        server
            .fail_next(Error::Connection("reset".into()))
            .fail_connect(Error::Auth("password changed".into()));
        let result = s.home_dir(&CancellationToken::new()).await;
        assert!(matches!(result, Err(Error::Auth(_))));
    }

    #[tokio::test]
    async fn other_errors_are_not_retried() {
        let server = MockServer::new();
        let s = connected(&server, None).await;
        server.fail_next(Error::reply(550, "denied"));
        let result = s
            .mkdir(&RemotePath::new("/x"), &CancellationToken::new())
            .await;
        assert!(matches!(
            result,
            Err(Error::Protocol {
                code: Some(550),
                ..
            })
        ));
        assert_eq!(server.connects(), 1);
        assert!(!server.exists("/x"));
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_fires_after_idle_interval() {
        let server = MockServer::new();
        let s = connected(&server, Some(Duration::from_secs(30))).await;
        tokio::time::sleep(Duration::from_secs(29)).await;
        assert_eq!(server.keepalives(), 0);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(server.keepalives(), 1);

        // Activity postpones the next one.
        tokio::time::sleep(Duration::from_secs(20)).await;
        s.home_dir(&CancellationToken::new()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(server.keepalives(), 1);
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(server.keepalives(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_task_stops_when_the_handle_is_dropped() {
        let server = MockServer::new();
        let s = connected(&server, Some(Duration::from_secs(10))).await;
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(server.keepalives(), 1);
        let before = Arc::strong_count(&s.inner);
        assert_eq!(before, 2, "the task holds one reference");
        let weak = Arc::downgrade(&s.inner);
        drop(s);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(weak.strong_count(), 0, "keep-alive task leaked");
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert_eq!(server.keepalives(), 1);
    }
}
