//! File operations on one side (T62): make directory (`mkdir -p`), new empty
//! file, rename and move (with an overwrite check), recursive delete, chmod
//! and raw commands.
//!
//! Each operation runs on the local filesystem ([`LocalBackend`]) or on the
//! remote pane's [`SessionHandle`] (locked for the whole operation, so the
//! pane's listings wait for it), with a timeout per call and the tab's
//! cancellation token. Our own changes patch the [`ListingCache`] (T46): the
//! panes and directory trees showing a changed directory are redrawn from
//! the patched listing, without listing again.
//!
//! Nothing here draws: the dialogs live in `ui::file_ops`, the glue in
//! `app::file_ops`.

use std::{future::Future, sync::Arc, time::Duration};

use courier_ftp_core::{
    Error, Result,
    backend::{Backend, SessionHandle, TransferOpts, WriteMode},
    cache::ListingCache,
    events::{EventSender, SessionId},
    filters::FilterEngine,
    local::LocalBackend,
    model::{Entry, RemotePath, ServerAddress},
    transfer::recursive::{
        ChmodSpec, RecursiveReport, Target, WalkOptions, chmod_recursive, delete_recursive,
    },
};
use tokio_util::sync::CancellationToken;

/// Where an operation runs.
#[derive(Clone)]
pub(crate) enum Place {
    /// The local filesystem.
    Local,
    /// The remote pane's connection.
    Remote(Arc<SessionHandle>),
}

impl std::fmt::Debug for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Place::Local => "Local",
            Place::Remote(_) => "Remote",
        })
    }
}

/// Everything an operation needs.
#[derive(Debug, Clone)]
pub(crate) struct OpCtx {
    pub(crate) place: Place,
    /// The cache key of the side (`None`: the local filesystem).
    pub(crate) server: Option<ServerAddress>,
    /// The session log lines and cache patches are reported under (the
    /// remote pane's session, or the local one), so the app knows the side.
    pub(crate) session: SessionId,
    pub(crate) cache: ListingCache,
    pub(crate) events: EventSender,
    /// Timeout of each backend call (`connection.timeout_secs`).
    pub(crate) timeout: Duration,
    /// Stops the operation (the progress dialog's Cancel, a disconnect).
    pub(crate) cancel: CancellationToken,
    /// The side's filters: filtered entries are left alone by recursive
    /// operations (T43, as FileZilla).
    pub(crate) filter: FilterEngine,
}

/// Exclusive access to the backend of a [`Place`].
enum Guard<'a> {
    Local(Box<LocalBackend>),
    Remote(tokio::sync::MutexGuard<'a, Box<dyn Backend>>),
}

impl Guard<'_> {
    fn backend(&mut self) -> &mut dyn Backend {
        match self {
            Guard::Local(b) => b.as_mut(),
            Guard::Remote(g) => &mut ***g,
        }
    }
}

impl OpCtx {
    /// Run `fut` with the per-call timeout and the cancellation token.
    async fn timed<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            () = self.cancel.cancelled() => Err(Error::Cancelled),
            r = tokio::time::timeout(self.timeout, fut) => r.unwrap_or(Err(Error::Timeout)),
        }
    }

    /// The backend, connected.
    async fn guard(&self) -> Result<Guard<'_>> {
        match &self.place {
            Place::Local => {
                let mut b = Box::new(LocalBackend::new());
                b.connect(self.cancel.clone()).await?;
                Ok(Guard::Local(b))
            }
            Place::Remote(handle) => {
                let mut g = self.timed(async { Ok(handle.lock().await) }).await?;
                if !g.is_connected() {
                    // The connection dropped since the last call: once more,
                    // as `SessionHandle::run` does.
                    let cancel = self.cancel.clone();
                    self.timed(g.connect(cancel)).await?;
                }
                Ok(Guard::Remote(g))
            }
        }
    }

    fn walk_options(&self) -> WalkOptions {
        let mut opts = match self.place {
            Place::Local => WalkOptions::local(self.session),
            Place::Remote(_) => WalkOptions::remote(self.session),
        };
        opts.timeout = self.timeout;
        opts.filter = self.filter.clone();
        opts.cache = Some(self.cache.clone());
        opts.events = Some(self.events.clone());
        opts
    }
}

/// `mkdir -p`: create `path` and any missing parents. Each created directory
/// is added to its parent's cached listing. Fails with
/// [`Error::AlreadyExists`] when `path` already exists.
pub(crate) async fn mkdir_p(ctx: &OpCtx, path: &RemotePath) -> Result<()> {
    let mut guard = ctx.guard().await?;
    let b = guard.backend();
    // The common case first: the parent exists.
    let first = ctx.timed(b.mkdir(path)).await;
    match first {
        Ok(()) => {
            created(ctx, b, path).await;
            return Ok(());
        }
        Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => return Err(e),
        Err(_) => {}
    }
    // Then one component at a time (servers don't create parents).
    let mut cur = RemotePath::root();
    let names: Vec<String> = path.components().map(str::to_owned).collect();
    for (i, name) in names.iter().enumerate() {
        cur = cur.join(name)?;
        let last = i + 1 == names.len();
        match ctx.timed(b.stat(&cur)).await {
            Ok(entry) if last => {
                return Err(if entry.is_dir_like() {
                    Error::AlreadyExists
                } else {
                    Error::InvalidInput(format!("{cur} exists and is not a directory"))
                });
            }
            Ok(entry) if entry.is_dir_like() => continue,
            Ok(_) => {
                return Err(Error::InvalidInput(format!(
                    "{cur} exists and is not a directory"
                )));
            }
            Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => return Err(e),
            Err(_) => {}
        }
        ctx.timed(b.mkdir(&cur)).await?;
        created(ctx, b, &cur).await;
    }
    Ok(())
}

/// Add the new `path` to its parent's cached listing, with the details the
/// backend reports (a bare directory entry when it can't say: only a stat
/// of a just-created file fails in practice, and then a relist fixes it).
async fn created(ctx: &OpCtx, b: &mut dyn Backend, path: &RemotePath) {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let entry = match ctx.timed(b.stat(path)).await {
        Ok(mut e) => {
            e.name = name.to_owned();
            e
        }
        Err(_) => Entry::dir(name),
    };
    ctx.cache
        .insert_entry(ctx.session, ctx.server.as_ref(), &parent, entry);
}

/// Create the empty file `path` (an upload of 0 bytes remotely). Fails with
/// [`Error::AlreadyExists`] when something is there already.
pub(crate) async fn create_file(ctx: &OpCtx, path: &RemotePath) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut guard = ctx.guard().await?;
    let b = guard.backend();
    // `WriteMode::Create` is exclusive locally; servers may not refuse, so
    // look first.
    match ctx.timed(b.stat(path)).await {
        Ok(_) => return Err(Error::AlreadyExists),
        Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => return Err(e),
        Err(_) => {}
    }
    let mut stream = ctx
        .timed(b.open_write(path, WriteMode::Create, &TransferOpts::default()))
        .await?;
    let shut = ctx
        .timed(async { stream.shutdown().await.map_err(Error::from) })
        .await;
    drop(stream);
    let finished = ctx.timed(b.finish_transfer()).await;
    shut?;
    finished?;
    created(ctx, b, path).await;
    Ok(())
}

/// Send `cmd` as is (FileZilla's "Enter custom command"); the reply text.
pub(crate) async fn raw_command(ctx: &OpCtx, cmd: &str) -> Result<String> {
    let mut guard = ctx.guard().await?;
    ctx.timed(guard.backend().raw_command(cmd)).await
}

/// One rename or move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rename {
    pub(crate) from: RemotePath,
    pub(crate) to: RemotePath,
}

/// What [`rename_all`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RenameReport {
    /// Renamed.
    pub(crate) done: Vec<Rename>,
    /// Targets that exist as files: nothing was done (without `overwrite`),
    /// so the user can be asked.
    pub(crate) conflicts: Vec<Rename>,
    /// Failures (a directory in the way, a server error), with the reason.
    pub(crate) failed: Vec<(Rename, String)>,
    /// Set when everything stopped (cancelled, connection lost).
    pub(crate) stopped: Option<String>,
}

/// Rename (or move) each of `renames`.
///
/// Without `overwrite`, every target is checked first: if any of them
/// exists as a file nothing is renamed and the clashes come back in
/// [`RenameReport::conflicts`] (SFTP's rename replaces silently, so the UI
/// must ask first). A target that is a directory is never replaced. With
/// `overwrite`, a backend that refuses to replace (local, most FTP servers)
/// gets the old file removed first. Case-only renames skip the check (the
/// "existing" file is the source itself on case-insensitive systems).
pub(crate) async fn rename_all(
    ctx: &OpCtx,
    renames: Vec<Rename>,
    overwrite: bool,
) -> Result<RenameReport> {
    let mut guard = ctx.guard().await?;
    let b = guard.backend();
    let mut report = RenameReport::default();
    let mut todo = Vec::new();
    for r in renames {
        if r.from == r.to {
            continue;
        }
        if r.to.starts_with(&r.from) {
            report
                .failed
                .push((r, "cannot move a directory into itself".to_owned()));
            continue;
        }
        let case_only = r.from.parent() == r.to.parent()
            && r.from.file_name().map(str::to_lowercase) == r.to.file_name().map(str::to_lowercase);
        let existing = if case_only {
            None
        } else {
            match ctx.timed(b.stat(&r.to)).await {
                Ok(entry) => Some(entry),
                Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => {
                    return Err(e);
                }
                Err(_) => None,
            }
        };
        match existing {
            Some(e) if e.is_dir_like() && !e.kind.is_symlink() => {
                report
                    .failed
                    .push((r, "a directory with that name already exists".to_owned()));
            }
            Some(_) if !overwrite => report.conflicts.push(r),
            Some(_) => todo.push((r, true)),
            None => todo.push((r, false)),
        }
    }
    if !report.conflicts.is_empty() {
        return Ok(report);
    }
    for (r, exists) in todo {
        let mut result = ctx.timed(b.rename(&r.from, &r.to)).await;
        if exists && matches!(result, Err(Error::AlreadyExists)) {
            result = match ctx.timed(b.remove_file(&r.to)).await {
                Ok(()) => ctx.timed(b.rename(&r.from, &r.to)).await,
                Err(e) => Err(e),
            };
        }
        match result {
            Ok(()) => {
                if exists {
                    ctx.cache
                        .remove_entry(ctx.session, ctx.server.as_ref(), &r.to);
                }
                ctx.cache
                    .rename(ctx.session, ctx.server.as_ref(), &r.from, &r.to);
                report.done.push(r);
            }
            Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => {
                report.stopped = Some(e.to_string());
                report.failed.push((r, e.to_string()));
                break;
            }
            Err(e) => report.failed.push((r, e.to_string())),
        }
    }
    Ok(report)
}

/// The kind of a path on the backend (`None`: it doesn't exist).
pub(crate) async fn stat(ctx: &OpCtx, path: &RemotePath) -> Result<Option<Entry>> {
    let mut guard = ctx.guard().await?;
    match ctx.timed(guard.backend().stat(path)).await {
        Ok(e) => Ok(Some(e)),
        Err(e @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => Err(e),
        Err(_) => Ok(None),
    }
}

/// Delete `targets` recursively (T43); progress goes out as
/// `CoreEvent::RecursiveProgress` under [`OpCtx::session`].
pub(crate) async fn delete(ctx: &OpCtx, targets: Vec<Target>) -> RecursiveReport {
    match ctx.guard().await {
        Ok(mut guard) => {
            delete_recursive(guard.backend(), targets, ctx.walk_options(), &ctx.cancel).await
        }
        Err(e) => stopped(e),
    }
}

/// Change permissions (T43), recursively when `spec.recurse`.
pub(crate) async fn chmod(ctx: &OpCtx, targets: Vec<Target>, spec: ChmodSpec) -> RecursiveReport {
    match ctx.guard().await {
        Ok(mut guard) => {
            chmod_recursive(
                guard.backend(),
                targets,
                spec,
                ctx.walk_options(),
                &ctx.cancel,
            )
            .await
        }
        Err(e) => stopped(e),
    }
}

fn stopped(e: Error) -> RecursiveReport {
    RecursiveReport {
        stopped: Some(e),
        ..RecursiveReport::default()
    }
}

/// A [`RecursiveReport`] for the UI (the report itself isn't `Clone`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OpSummary {
    pub(crate) files: u64,
    pub(crate) dirs: u64,
    pub(crate) unchanged: u64,
    /// The first problems: path and reason.
    pub(crate) problems: Vec<(RemotePath, String)>,
    pub(crate) problem_count: u64,
    /// Why it stopped early (`None`: it ran to the end).
    pub(crate) stopped: Option<String>,
    pub(crate) cancelled: bool,
}

impl From<&RecursiveReport> for OpSummary {
    fn from(r: &RecursiveReport) -> Self {
        Self {
            files: r.files,
            dirs: r.dirs,
            unchanged: r.unchanged,
            problems: r
                .problems
                .iter()
                .take(5)
                .map(|p| (p.path.clone(), p.reason.clone()))
                .collect(),
            problem_count: r.problem_count,
            stopped: r.stopped.as_ref().map(ToString::to_string),
            cancelled: matches!(r.stopped, Some(Error::Cancelled)),
        }
    }
}

#[cfg(test)]
mod tests;
