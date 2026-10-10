//! [`Walker`]: depth-first walk over any backend with bounded memory.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;

use super::{DEFAULT_MAX_DEPTH, group_thousands, is_fatal, timed};
use crate::{
    Error, Result,
    backend::Backend,
    cache::ListingCache,
    events::{CoreEvent, EventSender, LogKind, RecursiveOperation, RecursiveProgress, SessionId},
    filters::FilterEngine,
    local::remote_to_local,
    model::{Entry, EntryKind, RemotePath},
};

/// At most this many problems (skipped directories, failed entries) are
/// kept in a summary or report; the counts go on.
pub const MAX_REPORTED: usize = 1000;

/// Coalescing of [`CoreEvent::RecursiveProgress`].
const EVENT_INTERVAL: Duration = Duration::from_millis(100);
/// A "Listing … n files found" status line at most this often (and only for
/// walks that take longer than this).
const LOG_INTERVAL: Duration = Duration::from_secs(2);

/// How symlink loops are detected when following links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LoopCheck {
    /// Remote: each directory's real path (symlink targets resolved against
    /// the directory holding the link) is compared with the directories
    /// being walked.
    #[default]
    Paths,
    /// The local filesystem: (device, inode) on Unix, the canonical path
    /// elsewhere.
    Native,
}

/// How a [`Walker`] (and the operations built on it) behaves.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Descend into symlinked directories (`transfers.follow_symlinks`).
    /// Ignored by [`delete_recursive`](super::delete_recursive), which never
    /// follows links.
    pub follow_symlinks: bool,
    /// Loop detection for followed links.
    pub loop_check: LoopCheck,
    /// Directory levels below a selected entry before giving up on a branch
    /// (a backstop against loops that can't be detected).
    pub max_depth: usize,
    /// Timeout of each backend call (`connection.timeout_secs`).
    pub timeout: Duration,
    /// The filters of the walked side; excluded entries are skipped and
    /// excluded directories not descended.
    pub filter: FilterEngine,
    /// Listings are stored here (so panes benefit), and deletes and chmods
    /// patch it.
    pub cache: Option<ListingCache>,
    /// Read fresh listings from [`WalkOptions::cache`] instead of listing
    /// again.
    pub use_cached: bool,
    /// The session logged under.
    pub session: SessionId,
    /// Message log lines and [`CoreEvent::RecursiveProgress`].
    pub events: Option<EventSender>,
}

impl WalkOptions {
    /// Defaults for a remote backend: no links followed, 20 s timeout, no
    /// filters, cache or events.
    pub fn remote(session: SessionId) -> Self {
        Self {
            follow_symlinks: false,
            loop_check: LoopCheck::Paths,
            max_depth: DEFAULT_MAX_DEPTH,
            timeout: Duration::from_secs(20),
            filter: FilterEngine::default(),
            cache: None,
            use_cached: false,
            session,
            events: None,
        }
    }

    /// Defaults for the local filesystem ([`LoopCheck::Native`]).
    pub fn local(session: SessionId) -> Self {
        Self {
            loop_check: LoopCheck::Native,
            ..Self::remote(session)
        }
    }
}

/// A selected entry to start from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Its full path.
    pub path: RemotePath,
    /// Its listing entry (the kind decides whether it is descended).
    pub entry: Entry,
}

impl Target {
    /// A target from its path and entry.
    pub fn new(path: RemotePath, entry: Entry) -> Self {
        Self { path, entry }
    }
}

/// What the walk found next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkEvent {
    /// A file (or another non-directory, or a followed symlink to a file).
    File {
        /// Full path.
        path: RemotePath,
        /// Its entry.
        entry: Entry,
    },
    /// A symlink that isn't followed (links not followed, or the target's
    /// kind unknown).
    Symlink {
        /// Full path.
        path: RemotePath,
        /// Its entry.
        entry: Entry,
    },
    /// A directory about to be listed (pre-order). Its children follow, then
    /// a matching [`WalkEvent::LeaveDir`].
    EnterDir {
        /// Full path.
        path: RemotePath,
        /// Its entry.
        entry: Entry,
    },
    /// All children of a directory were yielded (post-order).
    LeaveDir {
        /// Full path.
        path: RemotePath,
        /// Its entry.
        entry: Entry,
        /// Every child was yielded and none was marked with
        /// [`Walker::mark_incomplete`] (nothing filtered, skipped or failed
        /// below it).
        complete: bool,
        /// Why it couldn't be listed, if it couldn't.
        error: Option<String>,
    },
}

/// An entry that was skipped or could not be processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The entry.
    pub path: RemotePath,
    /// Why.
    pub reason: String,
}

/// Totals of a walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkSummary {
    /// Directories entered.
    pub dirs: u64,
    /// Files and symlinks yielded.
    pub files: u64,
    /// Entries excluded by the filters.
    pub filtered: u64,
    /// Symlinked directories not descended because they lead back into the
    /// walk.
    pub loops: u64,
    /// Directories not walked (listing failed, too deep, loop), first
    /// [`MAX_REPORTED`].
    pub skipped: Vec<Problem>,
    /// How many directories were skipped in all.
    pub skipped_count: u64,
}

/// The result of [`delete_recursive`](super::delete_recursive) or
/// [`chmod_recursive`](super::chmod_recursive).
#[derive(Debug, Default)]
pub struct RecursiveReport {
    /// Files (and symlinks) deleted or changed.
    pub files: u64,
    /// Directories deleted or changed.
    pub dirs: u64,
    /// Entries left alone on purpose (chmod: not matching [`ApplyTo`](super::ApplyTo),
    /// symlinks, unknown permissions).
    pub unchanged: u64,
    /// Entries that remain or failed, with the reason (first
    /// [`MAX_REPORTED`]). For delete: everything still there, including the
    /// directories that couldn't be removed because something remained
    /// inside.
    pub problems: Vec<Problem>,
    /// How many problems in all.
    pub problem_count: u64,
    /// The walk's totals (filtered entries, skipped directories).
    pub walk: WalkSummary,
    /// Why the operation stopped early: [`Error::Cancelled`], a lost
    /// connection or a timeout. `None` when it ran to the end.
    pub stopped: Option<Error>,
}

impl RecursiveReport {
    /// Nothing failed and the operation wasn't stopped.
    pub fn is_complete(&self) -> bool {
        self.problem_count == 0 && self.stopped.is_none()
    }

    pub(super) fn problem(&mut self, path: RemotePath, reason: impl Into<String>) {
        self.problem_count += 1;
        if self.problems.len() < MAX_REPORTED {
            self.problems.push(Problem {
                path,
                reason: reason.into(),
            });
        }
    }
}

/// Identity of a directory for loop detection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DirId {
    Unknown,
    Path(RemotePath),
    #[allow(dead_code)] // which of these is used depends on the OS
    Native(PathBuf),
    #[allow(dead_code)]
    Inode(u64, u64),
}

impl DirId {
    fn same(&self, other: &DirId) -> bool {
        !matches!(self, DirId::Unknown) && self == other
    }
}

#[derive(Debug)]
struct Frame {
    path: RemotePath,
    entry: Entry,
    id: DirId,
    listed: bool,
    entries: std::vec::IntoIter<Entry>,
    complete: bool,
    error: Option<String>,
}

/// Status-bar events and occasional status lines.
#[derive(Debug)]
pub(super) struct Reporter {
    session: SessionId,
    events: Option<EventSender>,
    operation: RecursiveOperation,
    last_event: Option<Instant>,
    last_log: Instant,
    current: RemotePath,
    pub(super) dirs: u64,
    pub(super) files: u64,
    pub(super) done: u64,
}

impl Reporter {
    fn new(session: SessionId, events: Option<EventSender>, operation: RecursiveOperation) -> Self {
        let now = Instant::now();
        Self {
            session,
            events,
            operation,
            last_event: None,
            last_log: now,
            current: RemotePath::root(),
            dirs: 0,
            files: 0,
            done: 0,
        }
    }

    fn tick(&mut self) {
        let Some(events) = &self.events else { return };
        let now = Instant::now();
        if self
            .last_event
            .is_none_or(|t| now.duration_since(t) >= EVENT_INTERVAL)
        {
            self.last_event = Some(now);
            events.send(self.event(false));
        }
        if now.duration_since(self.last_log) >= LOG_INTERVAL {
            self.last_log = now;
            events.log(
                self.session,
                LogKind::Status,
                format!(
                    "Listing {} … {} files found",
                    self.current,
                    group_thousands(self.files)
                ),
            );
        }
    }

    fn event(&self, finished: bool) -> CoreEvent {
        CoreEvent::RecursiveProgress(RecursiveProgress {
            session: self.session,
            operation: self.operation,
            current: self.current.clone(),
            dirs: self.dirs,
            files: self.files,
            done: self.done,
            finished,
        })
    }

    fn finish(&mut self) {
        if let Some(events) = &self.events {
            events.send(self.event(true));
        }
    }

    fn log(&self, kind: LogKind, text: String) {
        if let Some(events) = &self.events {
            events.log(self.session, kind, text);
        }
    }
}

/// A depth-first walk; see the [module docs](super).
///
/// Pull events with [`Walker::next`] until it returns `Ok(None)`. An `Err`
/// (cancelled, connection lost, timeout) ends the walk. Memory is bounded
/// by the listings of the directories on the current path.
#[derive(Debug)]
pub struct Walker {
    opts: WalkOptions,
    roots: std::vec::IntoIter<Target>,
    stack: Vec<Frame>,
    /// Stack index of the directory holding the last yielded entry (`None`
    /// for a selected entry).
    last_container: Option<usize>,
    summary: WalkSummary,
    reporter: Reporter,
    peak_live: usize,
    finished: bool,
}

impl Walker {
    /// A walk over `targets` (the selection; they are never filtered).
    pub fn new(targets: Vec<Target>, opts: WalkOptions) -> Self {
        Self::with_operation(targets, opts, RecursiveOperation::Listing)
    }

    pub(super) fn with_operation(
        targets: Vec<Target>,
        opts: WalkOptions,
        operation: RecursiveOperation,
    ) -> Self {
        let reporter = Reporter::new(opts.session, opts.events.clone(), operation);
        Self {
            opts,
            roots: targets.into_iter(),
            stack: Vec::new(),
            last_container: None,
            summary: WalkSummary::default(),
            reporter,
            peak_live: 0,
            finished: false,
        }
    }

    /// The totals so far.
    pub fn summary(&self) -> &WalkSummary {
        &self.summary
    }

    /// Consume the walker, returning its totals.
    pub fn into_summary(self) -> WalkSummary {
        self.summary
    }

    /// Listing entries held right now (not yet yielded), across the
    /// directories on the current path.
    pub fn live_entries(&self) -> usize {
        self.stack.iter().map(|f| f.entries.len()).sum()
    }

    /// The most entries held at once so far.
    pub fn peak_live_entries(&self) -> usize {
        self.peak_live
    }

    /// Mark the directory holding the last yielded entry as incomplete
    /// (e.g. deleting that entry failed), so its `LeaveDir` reports
    /// `complete: false`.
    pub fn mark_incomplete(&mut self) {
        if let Some(i) = self.last_container
            && let Some(frame) = self.stack.get_mut(i)
        {
            frame.complete = false;
        }
    }

    /// Count one entry as done (deleted, changed) for the progress event.
    pub fn count_done(&mut self) {
        self.reporter.done += 1;
    }

    pub(super) fn options(&self) -> &WalkOptions {
        &self.opts
    }

    /// The next event, `Ok(None)` at the end.
    ///
    /// # Errors
    /// [`Error::Cancelled`], or a lost connection / timeout; the walk is
    /// over then.
    pub async fn next(
        &mut self,
        backend: &mut dyn Backend,
        cancel: &CancellationToken,
    ) -> Result<Option<WalkEvent>> {
        let result = self.step(backend, cancel).await;
        if !matches!(result, Ok(Some(_))) {
            self.finish();
        }
        result
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.reporter.finish();
        if self.summary.filtered > 0 {
            self.reporter.log(
                LogKind::Status,
                format!(
                    "{} entries excluded by filters",
                    group_thousands(self.summary.filtered)
                ),
            );
        }
    }

    async fn step(
        &mut self,
        backend: &mut dyn Backend,
        cancel: &CancellationToken,
    ) -> Result<Option<WalkEvent>> {
        loop {
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            // A directory announced with EnterDir: list it now.
            if let Some(top) = self.stack.last()
                && !top.listed
            {
                let path = top.path.clone();
                self.reporter.current = path.clone();
                self.reporter.tick();
                let listed = self.list(backend, &path, cancel).await;
                let Some(top) = self.stack.last_mut() else {
                    continue;
                };
                top.listed = true;
                match listed {
                    Ok(entries) => {
                        top.entries = entries.into_iter();
                        let live = self.live_entries();
                        self.peak_live = self.peak_live.max(live);
                    }
                    Err(e) if is_fatal(&e) => return Err(e),
                    Err(e) => {
                        top.complete = false;
                        top.error = Some(e.to_string());
                        self.reporter.log(
                            LogKind::Error,
                            format!("Could not list {path}: {e}; skipped"),
                        );
                        self.skip(path, e.to_string());
                    }
                }
                continue;
            }
            let container = self.stack.len().saturating_sub(1);
            if let Some(top) = self.stack.last_mut() {
                if let Some(entry) = top.entries.next() {
                    let parent = top.path.clone();
                    let path = match parent.join(&entry.name) {
                        Ok(p) => p,
                        Err(e) => {
                            top.complete = false;
                            tracing::debug!("skipping an entry with an invalid name: {e}");
                            continue;
                        }
                    };
                    if self.opts.filter.excluded(&entry, path.as_str()) {
                        top.complete = false;
                        self.summary.filtered += 1;
                        continue;
                    }
                    if let Some(event) = self
                        .classify(backend, path, entry, Some(container), cancel)
                        .await?
                    {
                        return Ok(Some(event));
                    }
                    continue;
                }
                let Some(frame) = self.stack.pop() else {
                    continue;
                };
                if !frame.complete
                    && let Some(parent) = self.stack.last_mut()
                {
                    parent.complete = false;
                }
                self.last_container = self.stack.len().checked_sub(1);
                return Ok(Some(WalkEvent::LeaveDir {
                    path: frame.path,
                    entry: frame.entry,
                    complete: frame.complete,
                    error: frame.error,
                }));
            }
            let Some(root) = self.roots.next() else {
                return Ok(None);
            };
            if let Some(event) = self
                .classify(backend, root.path, root.entry, None, cancel)
                .await?
            {
                return Ok(Some(event));
            }
        }
    }

    fn skip(&mut self, path: RemotePath, reason: String) {
        self.summary.skipped_count += 1;
        if self.summary.skipped.len() < MAX_REPORTED {
            self.summary.skipped.push(Problem { path, reason });
        }
    }

    fn mark(&mut self, container: Option<usize>) {
        if let Some(frame) = container.and_then(|i| self.stack.get_mut(i)) {
            frame.complete = false;
        }
    }

    async fn classify(
        &mut self,
        backend: &mut dyn Backend,
        path: RemotePath,
        entry: Entry,
        container: Option<usize>,
        cancel: &CancellationToken,
    ) -> Result<Option<WalkEvent>> {
        match &entry.kind {
            EntryKind::Dir => self.enter(path, entry, container, None).await,
            EntryKind::Symlink { target, .. } => {
                if !self.opts.follow_symlinks {
                    return Ok(Some(self.leaf(path, entry, container, true)));
                }
                let target = target.clone();
                match symlink_target_kind(backend, &path, &entry, self.opts.timeout, cancel).await?
                {
                    Some(true) => self.enter(path, entry, container, Some(target)).await,
                    Some(false) => Ok(Some(self.leaf(path, entry, container, false))),
                    None => Ok(Some(self.leaf(path, entry, container, true))),
                }
            }
            EntryKind::File | EntryKind::Other => {
                Ok(Some(self.leaf(path, entry, container, false)))
            }
        }
    }

    fn leaf(
        &mut self,
        path: RemotePath,
        entry: Entry,
        container: Option<usize>,
        symlink: bool,
    ) -> WalkEvent {
        self.last_container = container;
        self.summary.files += 1;
        self.reporter.files += 1;
        self.reporter.tick();
        if symlink {
            WalkEvent::Symlink { path, entry }
        } else {
            WalkEvent::File { path, entry }
        }
    }

    /// Push a directory (listed on the next call) and announce it.
    async fn enter(
        &mut self,
        path: RemotePath,
        entry: Entry,
        container: Option<usize>,
        via_link: Option<Option<String>>,
    ) -> Result<Option<WalkEvent>> {
        let depth = self.stack.len();
        if depth > self.opts.max_depth {
            self.mark(container);
            self.reporter.log(
                LogKind::Error,
                format!(
                    "Not descending into {path}: more than {} levels deep",
                    self.opts.max_depth
                ),
            );
            self.skip(
                path,
                format!("more than {} levels deep", self.opts.max_depth),
            );
            return Ok(None);
        }
        let id = self.dir_id(&path, container, via_link).await;
        if self.stack.iter().any(|f| f.id.same(&id)) {
            self.mark(container);
            self.summary.loops += 1;
            self.reporter.log(
                LogKind::Status,
                format!("Not following {path}: the link leads back into the tree (loop)"),
            );
            self.skip(path, "symlink loop".into());
            return Ok(None);
        }
        self.last_container = container;
        self.summary.dirs += 1;
        self.reporter.dirs += 1;
        self.stack.push(Frame {
            path: path.clone(),
            entry: entry.clone(),
            id,
            listed: false,
            entries: Vec::new().into_iter(),
            complete: true,
            error: None,
        });
        Ok(Some(WalkEvent::EnterDir { path, entry }))
    }

    async fn dir_id(
        &self,
        path: &RemotePath,
        container: Option<usize>,
        via_link: Option<Option<String>>,
    ) -> DirId {
        if !self.opts.follow_symlinks {
            return DirId::Unknown;
        }
        match self.opts.loop_check {
            LoopCheck::Native => native_id(path).await,
            LoopCheck::Paths => {
                let parent_real = match container.and_then(|i| self.stack.get(i)) {
                    Some(Frame {
                        id: DirId::Path(p), ..
                    }) => Some(p.clone()),
                    Some(_) => None,
                    None => path.parent(),
                };
                let Some(parent_real) = parent_real else {
                    return DirId::Path(path.clone());
                };
                match via_link {
                    None => parent_real
                        .join(path.file_name().unwrap_or_default())
                        .map_or(DirId::Unknown, DirId::Path),
                    Some(Some(target)) => DirId::Path(parent_real.join_path(&target)),
                    Some(None) => DirId::Unknown,
                }
            }
        }
    }

    async fn list(
        &self,
        backend: &mut dyn Backend,
        dir: &RemotePath,
        cancel: &CancellationToken,
    ) -> Result<Vec<Entry>> {
        list_dir(backend, dir, &self.opts, cancel).await
    }
}

/// List `dir` (from the cache when allowed), store the listing in the
/// cache, and return its entries sorted by name, without `.` and `..`.
pub(super) async fn list_dir(
    backend: &mut dyn Backend,
    dir: &RemotePath,
    opts: &WalkOptions,
    cancel: &CancellationToken,
) -> Result<Vec<Entry>> {
    let cached = opts
        .cache
        .as_ref()
        .filter(|_| opts.use_cached)
        .and_then(|c| c.get(backend.address(), dir));
    let listing = match cached {
        Some(l) => l,
        None => {
            let listing = timed(opts.timeout, cancel, backend.list(dir, cancel.clone())).await?;
            if let Some(cache) = &opts.cache {
                cache.put(backend.address(), listing.clone());
            }
            listing
        }
    };
    let mut entries = listing.entries;
    entries.retain(|e| e.name != "." && e.name != "..");
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Whether a symlink points at a directory: from the listing when known,
/// else by `stat`. `None` when that can't be found out.
pub(super) async fn symlink_target_kind(
    backend: &mut dyn Backend,
    path: &RemotePath,
    entry: &Entry,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Option<bool>> {
    if let EntryKind::Symlink {
        target_kind: Some(kind),
        ..
    } = &entry.kind
    {
        return Ok(Some(kind.is_dir_like()));
    }
    match timed(timeout, cancel, backend.stat(path)).await {
        Ok(stat) => Ok(match &stat.kind {
            EntryKind::Dir => Some(true),
            EntryKind::File | EntryKind::Other => Some(false),
            EntryKind::Symlink {
                target_kind: Some(kind),
                ..
            } => Some(kind.is_dir_like()),
            EntryKind::Symlink { .. } => None,
        }),
        Err(e) if is_fatal(&e) => Err(e),
        Err(e) => {
            tracing::debug!("cannot resolve a symlink: {e}");
            Ok(None)
        }
    }
}

/// The local directory's identity, following links.
async fn native_id(path: &RemotePath) -> DirId {
    let Some(native) = remote_to_local(path) else {
        return DirId::Unknown;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match tokio::fs::metadata(&native).await {
            Ok(m) => DirId::Inode(m.dev(), m.ino()),
            Err(_) => DirId::Unknown,
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::fs::canonicalize(&native).await {
            Ok(p) => DirId::Native(p),
            Err(_) => DirId::Unknown,
        }
    }
}
