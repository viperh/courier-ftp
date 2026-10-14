//! T63: the I/O of viewing and editing files externally — copying a remote
//! file to its temporary copy and back over a connection of its own, and
//! starting the program (in the foreground with the TUI suspended, or
//! detached). The decisions (which program, change detection, the copies'
//! directory) are in [`courier_ftp_core::edit`]; the app's side is
//! `app/edit.rs`.

use std::{
    io,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::Arc,
    time::Duration,
};

use courier_ftp_core::{
    Error, Result,
    backend::{Backend, BackendFactory, ConnectInfo, TransferOpts, WriteMode},
    edit::{ContentHash, Launch, RemoteStamp},
    events::{EventSender, SessionId},
    model::RemotePath,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// Copy buffer size.
const CHUNK: usize = 64 * 1024;

/// One copy between a remote file and its temporary copy, on a connection
/// opened for it (so the panes stay usable and the copy back works after
/// the pane disconnected or moved to another server).
#[derive(Clone)]
pub(crate) struct Copy {
    pub(crate) factory: Arc<dyn BackendFactory>,
    pub(crate) events: EventSender,
    pub(crate) info: ConnectInfo,
    pub(crate) remote: RemotePath,
    pub(crate) local: PathBuf,
    pub(crate) opts: TransferOpts,
    /// Timeout of each step (`connection.timeout_secs`); the data copy may
    /// take longer as long as it keeps moving.
    pub(crate) timeout: Duration,
    pub(crate) cancel: CancellationToken,
}

impl std::fmt::Debug for Copy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Copy")
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

/// What an upload found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Uploaded {
    /// Done; the server's file now looks like this.
    Done(RemoteStamp),
    /// Not uploaded: the server's file changed since it was downloaded
    /// (it looks like this now).
    Conflict(RemoteStamp),
}

impl Copy {
    async fn timed<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            () = self.cancel.cancelled() => Err(Error::Cancelled),
            r = tokio::time::timeout(self.timeout, fut) => r.unwrap_or(Err(Error::Timeout)),
        }
    }

    async fn connect(&self) -> Result<Box<dyn Backend>> {
        let mut backend = self
            .factory
            .create(&self.info, SessionId::next(), self.events.clone());
        // Logging in may wait on a prompt (password, host key): no step
        // timeout, the backend has its own connect timeout.
        tokio::select! {
            () = self.cancel.cancelled() => return Err(Error::Cancelled),
            r = backend.connect(self.cancel.clone()) => r?,
        }
        Ok(backend)
    }

    async fn close(&self, mut backend: Box<dyn Backend>) {
        let _ = tokio::time::timeout(self.timeout, backend.disconnect()).await;
    }

    /// Download the remote file over its copy; the server's size and time
    /// at the download.
    pub(crate) async fn download(&self) -> Result<RemoteStamp> {
        let mut backend = self.connect().await?;
        let result = self.download_on(backend.as_mut()).await;
        self.close(backend).await;
        result
    }

    async fn download_on(&self, b: &mut dyn Backend) -> Result<RemoteStamp> {
        let entry = self.timed(b.stat(&self.remote)).await?;
        if entry.is_dir_like() {
            return Err(Error::InvalidInput(format!(
                "{} is a directory",
                self.remote
            )));
        }
        let mut opts = self.opts;
        opts.preallocate_hint = entry.size;
        let mut stream = self.timed(b.open_read(&self.remote, 0, &opts)).await?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.local)
            .await?;
        let copied = self.copy(&mut stream, &mut file).await;
        drop(stream);
        let finished = self.timed(b.finish_transfer()).await;
        copied?;
        finished?;
        file.flush().await?;
        file.sync_all().await?;
        Ok(RemoteStamp::of(&entry))
    }

    /// Upload the copy over the remote file. With `expect`, first check that
    /// the server's file still looks like that (else [`Uploaded::Conflict`]).
    /// A file deleted on the server meanwhile is created again.
    pub(crate) async fn upload(&self, expect: Option<RemoteStamp>) -> Result<Uploaded> {
        let mut backend = self.connect().await?;
        let result = self.upload_on(backend.as_mut(), expect).await;
        self.close(backend).await;
        result
    }

    async fn upload_on(
        &self,
        b: &mut dyn Backend,
        expect: Option<RemoteStamp>,
    ) -> Result<Uploaded> {
        if let Some(expect) = expect {
            match self.timed(b.stat(&self.remote)).await {
                Ok(entry) => {
                    let now = RemoteStamp::of(&entry);
                    if expect.changed_since(&now) {
                        return Ok(Uploaded::Conflict(now));
                    }
                }
                Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => {
                    return Err(e);
                }
                Err(_) => {}
            }
        }
        let mut file = tokio::fs::File::open(&self.local).await?;
        let mut opts = self.opts;
        opts.preallocate_hint = file.metadata().await.ok().map(|m| m.len());
        let mut stream = self
            .timed(b.open_write(&self.remote, WriteMode::Truncate, &opts))
            .await?;
        let copied = self.copy(&mut file, &mut stream).await;
        let shut = match copied {
            Ok(_) => {
                self.timed(async { stream.shutdown().await.map_err(Error::from) })
                    .await
            }
            Err(_) => Ok(()),
        };
        drop(stream);
        let finished = self.timed(b.finish_transfer()).await;
        copied?;
        shut?;
        finished?;
        let after = self
            .timed(b.stat(&self.remote))
            .await
            .map(|e| RemoteStamp::of(&e))
            .unwrap_or_default();
        Ok(Uploaded::Done(after))
    }

    /// Copy until the end of `from`; each read and write has the step
    /// timeout, so a stalled transfer fails but a slow one doesn't.
    async fn copy(
        &self,
        from: &mut (impl AsyncRead + Unpin + ?Sized),
        to: &mut (impl AsyncWrite + Unpin + ?Sized),
    ) -> Result<u64> {
        let mut buf = vec![0u8; CHUNK];
        let mut total = 0u64;
        loop {
            let n = self
                .timed(async { from.read(&mut buf).await.map_err(Error::from) })
                .await?;
            if n == 0 {
                return Ok(total);
            }
            let chunk = buf.get(..n).unwrap_or_default();
            self.timed(async { to.write_all(chunk).await.map_err(Error::from) })
                .await?;
            total += n as u64;
        }
    }
}

/// SHA-256 of the copy, off the async threads.
pub(crate) async fn hash(path: PathBuf) -> io::Result<ContentHash> {
    tokio::task::spawn_blocking(move || courier_ftp_core::edit::hash_file(&path))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)))
}

/// Start `launch` on `file` detached: no terminal (its output would land in
/// the TUI), reaped in the background.
pub(crate) fn spawn_detached(launch: &Launch, file: &Path) -> io::Result<()> {
    let (program, args) = launch.command_for(file);
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(())
}

/// Run `launch` on `file` in this terminal and wait for it (the TUI must be
/// suspended).
pub(crate) fn run_foreground(launch: &Launch, file: &Path) -> io::Result<ExitStatus> {
    let (program, args) = launch.command_for(file);
    std::process::Command::new(program).args(args).status()
}

/// A program to run in the terminal, sent to the event loop as
/// [`Action::RunForeground`](crate::action::Action::RunForeground) (it owns
/// the terminal).
#[derive(Debug)]
pub(crate) struct Foreground {
    pub(crate) launch: Launch,
    pub(crate) file: PathBuf,
    /// The edited file to check for changes afterwards.
    pub(crate) edit: Option<u64>,
    /// A viewed copy: delete it afterwards.
    pub(crate) remove_after: bool,
}
