//! Local and remote file search (T49, FEATURES.md §4): FileZilla's "Search
//! remote files" with its condition builder, over the local filesystem too.
//!
//! # How it works
//!
//! A [`SearchQuery`] names a root directory ([`SearchRoot`]), conditions
//! (the T47 filter [`Condition`]s), how they combine ([`MatchMode`]), case
//! sensitivity and which entries count ([`SearchType`]). Entries that
//! **match** are results — the inverse of a filter, where matching entries
//! are hidden. A query without conditions matches every entry of the chosen
//! type. The root itself is never a result. Non-matching directories are
//! still searched.
//!
//! The search walks the tree with the T43 [`Walker`]
//! (depth-first, bounded memory, symlink loop check, depth limit; directories
//! that can't be listed are skipped and reported). Listings come from the
//! T46 [`ListingCache`](crate::cache::ListingCache) when fresh and fill it as
//! the walk goes ([`SearchOptions::walk`]`.cache`, `use_cached` on by
//! default), so the panes benefit.
//!
//! Results stream through a bounded channel as [`SearchEvent`]s:
//! [`SearchEvent::Found`] for each match as soon as it is seen,
//! [`SearchEvent::Progress`] (at most every 100 ms, dropped when the
//! receiver lags), and exactly one final [`SearchEvent::Done`] (finished,
//! cancelled or truncated at [`SearchOptions::max_results`]) or
//! [`SearchEvent::Error`] (connection lost, timeout, root not listable).
//! The walker also sends [`CoreEvent::RecursiveProgress`](crate::events::CoreEvent::RecursiveProgress)
//! (operation `Listing`) and status lines when [`WalkOptions::events`] is set.
//!
//! # For the search UI (T65)
//!
//! 1. Build a [`SearchQuery`] from the form. [`SearchQuery::validate`]
//!    reports a bad regex or a relative local path before starting.
//! 2. **Remote**: open a *dedicated* session so the tab stays usable —
//!    `factory.create(&connect_info, session_id, events)` (the tab's
//!    [`BackendFactory`](crate::backend::BackendFactory) and
//!    [`ConnectInfo`](crate::backend::ConnectInfo)) — and hand the unconnected backend to
//!    [`spawn_search`] with [`SearchOptions::remote`]. It connects the
//!    backend (with the walk timeout), searches, and disconnects it at the
//!    end. Pass the tab's listing cache in `opts.walk.cache`.
//!    **Local**: [`spawn_local_search`] with [`SearchOptions::local`].
//! 3. Drain [`SearchHandle::recv`] (or `handle.events`) in the event loop;
//!    show "Searching… N dirs scanned" from [`SearchProgress`]. `Esc` calls
//!    [`SearchHandle::cancel`]; the final `Done { cancelled: true, .. }`
//!    arrives within a second (every backend call races the token).
//!    Dropping the handle also cancels.
//! 4. Result actions on the selected [`SearchHit`]s, with
//!    `root = query.walk_root()?`:
//!    - download (remote) / upload (local): [`download_items`] /
//!      [`upload_items`] with [`ResultLayout::KeepStructure`] or
//!      [`ResultLayout::Flatten`] (collisions renamed `name (2).ext`); add
//!      the returned items to the queue. Directory hits become directory
//!      placeholders, expanded by the transfer engine (T43).
//!    - delete: [`delete_results`] (or [`delete_targets`] for
//!      [`delete_recursive`](crate::transfer::recursive::delete_recursive)
//!      yourself) on a session of that side.
//!    - "go to": navigate the pane to `hit.path.parent()` and select
//!      `hit.entry.name`; local paths convert with [`SearchHit::local_path`].

mod actions;

#[cfg(test)]
mod tests;

use std::{
    future::Future,
    time::{Duration, Instant},
};

pub use actions::{ResultLayout, delete_results, delete_targets, download_items, upload_items};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    backend::Backend,
    events::SessionId,
    filters::{AppliesTo, Condition, Filter, FilterEngine, FilterScope, MatchMode},
    local::{LocalBackend, local_to_remote, remote_to_local},
    model::{Entry, LocalPath, RemotePath},
    transfer::recursive::{Problem, Target, WalkEvent, WalkOptions, Walker},
};

/// Which entries a search returns: files, directories or both (the T47
/// [`AppliesTo`]; symlinks count as directories when they point at one).
pub type SearchType = AppliesTo;

/// Where to search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchRoot {
    /// A directory on the server.
    Remote(RemotePath),
    /// A local directory (absolute).
    Local(LocalPath),
}

/// What to search for; see the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    /// The directory searched (not itself a result).
    pub root: SearchRoot,
    /// The conditions (the filter conditions of T47). None: everything of
    /// [`SearchQuery::search_type`] matches.
    pub conditions: Vec<Condition>,
    /// How the conditions combine (FileZilla offers All / Any).
    pub match_mode: MatchMode,
    /// Whether name and path comparisons are case-sensitive.
    pub case_sensitive: bool,
    /// Files, directories or both.
    pub search_type: SearchType,
}

impl SearchQuery {
    /// A query for everything under `root` (add conditions to narrow it).
    pub fn new(root: SearchRoot) -> Self {
        Self {
            root,
            conditions: Vec::new(),
            match_mode: MatchMode::All,
            case_sensitive: false,
            search_type: SearchType::Both,
        }
    }

    /// Check the query: valid regexes and an absolute local root.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] describing the problem.
    pub fn validate(&self) -> Result<()> {
        self.walk_root()?;
        self.matcher().map(|_| ())
    }

    /// The root as the walker sees it: the remote path, or the local path in
    /// the local backend's `RemotePath` form ([`local_to_remote`]). Result
    /// paths are below it; the result action helpers take it as `root`.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] for a relative local path.
    pub fn walk_root(&self) -> Result<RemotePath> {
        match &self.root {
            SearchRoot::Remote(p) => Ok(p.clone()),
            SearchRoot::Local(p) => {
                if !p.as_path().is_absolute() {
                    return Err(Error::InvalidInput(
                        "the search directory must be an absolute path".into(),
                    ));
                }
                local_to_remote(p.as_path())
            }
        }
    }

    /// The compiled conditions.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] for an invalid regex.
    pub fn matcher(&self) -> Result<SearchMatcher> {
        SearchMatcher::new(self)
    }
}

/// A query's conditions, compiled (regexes built once).
#[derive(Debug, Clone)]
pub struct SearchMatcher {
    search_type: SearchType,
    /// `None` when the query has no conditions.
    engine: Option<FilterEngine>,
}

impl SearchMatcher {
    fn new(query: &SearchQuery) -> Result<Self> {
        if query.conditions.is_empty() {
            return Ok(Self {
                search_type: query.search_type,
                engine: None,
            });
        }
        let filter = Filter {
            name: "search".into(),
            applies_to: query.search_type,
            match_mode: query.match_mode,
            case_sensitive: query.case_sensitive,
            conditions: query.conditions.clone(),
            scope: FilterScope::Both,
        };
        filter.validate()?;
        let (engine, warnings) = FilterEngine::new([&filter]);
        if let Some(w) = warnings.into_iter().next() {
            return Err(Error::InvalidInput(w));
        }
        Ok(Self {
            search_type: query.search_type,
            engine: Some(engine),
        })
    }

    /// Whether `entry` at `full_path` is a result.
    pub fn matches(&self, entry: &Entry, full_path: &str) -> bool {
        match &self.engine {
            // The filter engine checks the type itself.
            Some(engine) => engine.excluded(entry, full_path),
            None => match self.search_type {
                AppliesTo::Both => true,
                AppliesTo::Files => !entry.is_dir_like(),
                AppliesTo::Dirs => entry.is_dir_like(),
            },
        }
    }
}

/// How a search runs.
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// The walk: timeout per call, symlinks, depth limit, listing cache
    /// (`use_cached` is on), session and events. Its `filter` stays empty by
    /// default: a search looks at everything, as in FileZilla.
    pub walk: WalkOptions,
    /// Stop after this many results ([`SearchSummary::truncated`]). `None`:
    /// no limit.
    pub max_results: Option<u64>,
    /// Capacity of the event channel; the walk waits when the receiver
    /// falls this far behind.
    pub channel_capacity: usize,
}

/// Default [`SearchOptions::channel_capacity`].
pub const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// [`SearchEvent::Progress`] at most this often.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// How long closing a dedicated session may take.
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

impl SearchOptions {
    /// Defaults for a remote search ([`WalkOptions::remote`], cached
    /// listings used, no result limit).
    pub fn remote(session: SessionId) -> Self {
        Self::with_walk(WalkOptions::remote(session))
    }

    /// Defaults for a local search ([`WalkOptions::local`]).
    pub fn local(session: SessionId) -> Self {
        Self::with_walk(WalkOptions::local(session))
    }

    fn with_walk(mut walk: WalkOptions) -> Self {
        walk.use_cached = true;
        Self {
            walk,
            max_results: None,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

/// One result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Its full path (for a local search, in the local backend's
    /// `RemotePath` form; see [`SearchHit::local_path`]).
    pub path: RemotePath,
    /// Its listing entry (name, size, modified, permissions).
    pub entry: Entry,
}

impl SearchHit {
    /// The path relative to the search root (`a/b.txt`), `None` when the
    /// hit is not below `root`.
    pub fn relative<'a>(&'a self, root: &RemotePath) -> Option<&'a str> {
        self.path.strip_prefix(root).filter(|r| !r.is_empty())
    }

    /// The native path of a local search's hit.
    pub fn local_path(&self) -> Option<LocalPath> {
        remote_to_local(&self.path).map(LocalPath::new)
    }

    /// Whether this hit is a directory (or a link to one).
    pub fn is_dir(&self) -> bool {
        self.entry.is_dir_like()
    }
}

/// Counters for the progress line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchProgress {
    /// Directories listed (or being listed) so far, the root included.
    pub dirs_scanned: u64,
    /// Entries looked at so far.
    pub entries_scanned: u64,
    /// Results so far.
    pub matches: u64,
    /// The directory being listed.
    pub current: RemotePath,
}

/// The totals of a finished search.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchSummary {
    /// Directories listed, the root included.
    pub dirs_scanned: u64,
    /// Entries looked at.
    pub entries_scanned: u64,
    /// Results sent.
    pub matches: u64,
    /// Stopped at [`SearchOptions::max_results`].
    pub truncated: bool,
    /// Stopped by [`SearchHandle::cancel`].
    pub cancelled: bool,
    /// Directories that couldn't be searched (listing failed, too deep,
    /// symlink loop), the first [`MAX_REPORTED`](crate::transfer::recursive::MAX_REPORTED).
    pub skipped: Vec<Problem>,
    /// How many directories were skipped in all.
    pub skipped_count: u64,
    /// How long the search took.
    pub elapsed: Duration,
}

/// What a running search reports; see the [module docs](self).
#[derive(Debug)]
pub enum SearchEvent {
    /// A result, sent as soon as it is found.
    Found(SearchHit),
    /// Progress counters (coalesced; may be dropped when the receiver lags).
    Progress(SearchProgress),
    /// The search ended: finished, cancelled or truncated. Always last.
    Done(SearchSummary),
    /// The search failed: connecting failed, the connection was lost, a call
    /// timed out, or the root couldn't be listed. Always last.
    Error(Error),
}

/// A search running in a background task. Dropping it cancels the search.
#[derive(Debug)]
pub struct SearchHandle {
    /// The event stream; ends after `Done` or `Error`.
    pub events: mpsc::Receiver<SearchEvent>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl SearchHandle {
    /// The next event, `None` once the search is over and drained.
    pub async fn recv(&mut self) -> Option<SearchEvent> {
        self.events.recv().await
    }

    /// The next event if one is ready (for a UI tick without awaiting).
    pub fn try_recv(&mut self) -> Option<SearchEvent> {
        self.events.try_recv().ok()
    }

    /// Stop the search. A final `Done { cancelled: true, .. }` follows.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// The token the search runs under.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Whether the background task has ended.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for SearchHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Start a search on `backend`, a **dedicated** session the search owns
/// (connected first if needed, disconnected at the end). Must be called
/// inside a tokio runtime.
///
/// # Errors
/// [`Error::InvalidInput`] for an invalid query ([`SearchQuery::validate`]);
/// everything later arrives as [`SearchEvent::Error`].
pub fn spawn_search(
    mut backend: Box<dyn Backend>,
    query: SearchQuery,
    opts: SearchOptions,
) -> Result<SearchHandle> {
    let root = query.walk_root()?;
    let matcher = query.matcher()?;
    let (tx, rx) = mpsc::channel(opts.channel_capacity.max(1));
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let task = tokio::spawn(async move {
        let event = if backend.is_connected() {
            Ok(())
        } else {
            timed(
                opts.walk.timeout,
                &token,
                backend.connect(token.child_token()),
            )
            .await
        };
        let last = match event {
            Ok(()) => run(backend.as_mut(), &root, &matcher, opts, &tx, &token).await,
            Err(Error::Cancelled) => SearchEvent::Done(SearchSummary {
                cancelled: true,
                ..SearchSummary::default()
            }),
            Err(e) => SearchEvent::Error(e),
        };
        // Wait for room if the receiver lags, unless cancelled (then only
        // if there is room right away).
        let permit = tokio::select! {
            biased;
            () = token.cancelled() => tx.try_reserve().ok(),
            permit = tx.reserve() => permit.ok(),
        };
        if let Some(permit) = permit {
            permit.send(last);
        }
        if backend.is_connected() {
            let _ = tokio::time::timeout(DISCONNECT_TIMEOUT, backend.disconnect()).await;
        }
    });
    Ok(SearchHandle {
        events: rx,
        cancel,
        task,
    })
}

/// Start a search of the local filesystem ([`spawn_search`] with a
/// [`LocalBackend`]).
///
/// # Errors
/// As [`spawn_search`].
pub fn spawn_local_search(query: SearchQuery, opts: SearchOptions) -> Result<SearchHandle> {
    spawn_search(Box::new(LocalBackend::new()), query, opts)
}

/// Run a search on a session the caller holds (e.g. a locked
/// [`SessionHandle`](crate::backend::SessionHandle) for a small tree),
/// sending results to `tx` as found. Returns the final event instead of
/// sending it.
///
/// # Errors
/// [`Error::InvalidInput`] for an invalid query.
pub async fn search(
    backend: &mut dyn Backend,
    query: &SearchQuery,
    opts: SearchOptions,
    tx: &mpsc::Sender<SearchEvent>,
    cancel: &CancellationToken,
) -> Result<SearchEvent> {
    let root = query.walk_root()?;
    let matcher = query.matcher()?;
    Ok(run(backend, &root, &matcher, opts, tx, cancel).await)
}

/// The walk; returns the final event.
async fn run(
    backend: &mut dyn Backend,
    root: &RemotePath,
    matcher: &SearchMatcher,
    opts: SearchOptions,
    tx: &mpsc::Sender<SearchEvent>,
    cancel: &CancellationToken,
) -> SearchEvent {
    let started = Instant::now();
    let max_results = opts.max_results;
    let root_entry = Entry::dir(root.file_name().unwrap_or("/"));
    let mut walker = Walker::new(vec![Target::new(root.clone(), root_entry)], opts.walk);
    let mut summary = SearchSummary::default();
    let mut current = root.clone();
    let mut last_progress: Option<Instant> = None;

    let outcome = loop {
        let event = match walker.next(backend, cancel).await {
            Ok(Some(event)) => event,
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        };
        let (path, entry) = match event {
            WalkEvent::EnterDir { path, entry } => {
                current = path.clone();
                if path == *root {
                    send_progress(tx, &mut last_progress, &walker, &summary, &current);
                    continue;
                }
                (path, entry)
            }
            WalkEvent::File { path, entry } | WalkEvent::Symlink { path, entry } => (path, entry),
            WalkEvent::LeaveDir { path, error, .. } => {
                if path == *root
                    && let Some(error) = error
                {
                    break Err(Error::InvalidInput(format!(
                        "cannot search {path}: {error}"
                    )));
                }
                continue;
            }
        };
        summary.entries_scanned += 1;
        if matcher.matches(&entry, path.as_str()) {
            let hit = SearchEvent::Found(SearchHit { path, entry });
            tokio::select! {
                biased;
                () = cancel.cancelled() => break Err(Error::Cancelled),
                sent = tx.send(hit) => if sent.is_err() {
                    // Nobody is listening any more.
                    break Err(Error::Cancelled);
                },
            }
            summary.matches += 1;
            if max_results.is_some_and(|max| summary.matches >= max) {
                summary.truncated = true;
                break Ok(());
            }
        }
        send_progress(tx, &mut last_progress, &walker, &summary, &current);
    };

    let walk = walker.into_summary();
    summary.dirs_scanned = walk.dirs;
    summary.skipped = walk.skipped;
    summary.skipped_count = walk.skipped_count;
    summary.elapsed = started.elapsed();
    match outcome {
        Ok(()) => SearchEvent::Done(summary),
        Err(Error::Cancelled) => {
            summary.cancelled = true;
            SearchEvent::Done(summary)
        }
        Err(e) => SearchEvent::Error(e),
    }
}

fn send_progress(
    tx: &mpsc::Sender<SearchEvent>,
    last: &mut Option<Instant>,
    walker: &Walker,
    summary: &SearchSummary,
    current: &RemotePath,
) {
    let now = Instant::now();
    if last.is_some_and(|t| now.duration_since(t) < PROGRESS_INTERVAL) {
        return;
    }
    *last = Some(now);
    // Progress is advisory: drop it rather than wait for a lagging receiver.
    let _ = tx.try_send(SearchEvent::Progress(SearchProgress {
        dirs_scanned: walker.summary().dirs,
        entries_scanned: summary.entries_scanned,
        matches: summary.matches,
        current: current.clone(),
    }));
}

/// Run `fut` with a timeout, racing `cancel`.
async fn timed<T>(
    timeout: Duration,
    cancel: &CancellationToken,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = tokio::time::timeout(timeout, fut) => r.unwrap_or(Err(Error::Timeout)),
    }
}
