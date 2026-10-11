//! T65: the app's side of the search view — running a search (remote on a
//! dedicated session from the tab's backend factory, local on the
//! filesystem) and the result actions: queue downloads / uploads, delete,
//! go to.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use courier_ftp_core::{
    Error,
    backend::{Backend, ConnectInfo, SessionHandle},
    events::{LogKind, SessionId},
    local::{LocalBackend, display_native},
    model::{LocalPath, LogonType, RemotePath},
    queue::{NewItem, QueueServer, lock_queue},
    search::{
        ResultLayout, SearchEvent, SearchHandle, SearchHit, SearchOptions, SearchQuery, SearchRoot,
        delete_results, download_items, spawn_local_search, spawn_search, upload_items,
    },
    transfer::recursive::{RecursiveReport, WalkOptions},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::App;
use crate::{
    action::{Action, Shared},
    ui::{
        Side,
        dialog::{Form, FormDialog, RadioGroup, TextInput, confirm},
        search::{SearchRequest, SearchUpdate},
    },
};

/// Results forwarded to the UI in one action at most.
const BATCH: usize = 512;

/// The last search started, running or finished.
pub(crate) struct SearchRun {
    id: u64,
    cancel: CancellationToken,
    side: Side,
    /// The walk root (result paths are below it).
    root: RemotePath,
    /// Remote: the connection searched.
    info: Option<ConnectInfo>,
}

fn next_run() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The queue's server for a connection (as F5 queues it).
fn queue_server(info: &ConnectInfo) -> QueueServer {
    let password = match &info.logon {
        LogonType::Normal { password, .. } | LogonType::Account { password, .. } => {
            Some(password.clone())
        }
        _ => None,
    };
    QueueServer::Quick {
        address: info.address.clone(),
        password,
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Drain `handle` into the action channel: hits in batches, then progress
/// and the final event.
fn forward(mut handle: SearchHandle, run: u64, tx: mpsc::UnboundedSender<Action>) {
    let send = move |update: SearchUpdate| {
        tx.send(Action::SearchUpdate {
            run,
            update: Shared::new(update),
        })
        .is_ok()
    };
    tokio::spawn(async move {
        while let Some(event) = handle.recv().await {
            let mut hits = Vec::new();
            let mut other = None;
            match event {
                SearchEvent::Found(hit) => hits.push(hit),
                e => other = Some(e),
            }
            if other.is_none() {
                while hits.len() < BATCH {
                    match handle.try_recv() {
                        Some(SearchEvent::Found(hit)) => hits.push(hit),
                        Some(e) => {
                            other = Some(e);
                            break;
                        }
                        None => break,
                    }
                }
            }
            if !hits.is_empty() && !send(SearchUpdate::Found(hits)) {
                return;
            }
            let update = match other {
                None => continue,
                Some(SearchEvent::Found(_)) => continue,
                Some(SearchEvent::Progress(p)) => SearchUpdate::Progress(p),
                Some(SearchEvent::Done(s)) => SearchUpdate::Done(s),
                Some(SearchEvent::Error(e)) => SearchUpdate::Failed(e.to_string()),
            };
            if !send(update) {
                return;
            }
        }
    });
}

/// `mkdir -p` on the server: create `dir` and its missing parents. Errors
/// are left for the transfers to report.
async fn ensure_remote_dir(handle: &SessionHandle, dir: &RemotePath, cancel: &CancellationToken) {
    let mut missing = Vec::new();
    let mut cur = Some(dir.clone());
    while let Some(path) = cur {
        match handle.stat(&path, cancel).await {
            Ok(_) => break,
            Err(Error::NotFound(_)) => {
                cur = path.parent();
                missing.push(path);
            }
            Err(_) => {
                missing.push(path);
                break;
            }
        }
    }
    for path in missing.into_iter().rev() {
        let _ = handle.mkdir(&path, cancel).await;
    }
}

/// The hits a delete removed: all of them when it finished cleanly, else
/// those not reported as remaining (nothing when the report is cut short or
/// the delete was stopped).
fn removed_by(hits: &[SearchHit], report: &RecursiveReport) -> Vec<RemotePath> {
    if report.stopped.is_some() || report.problem_count > report.problems.len() as u64 {
        return Vec::new();
    }
    hits.iter()
        .filter(|h| {
            !report
                .problems
                .iter()
                .any(|p| p.path == h.path || p.path.starts_with(&h.path))
        })
        .map(|h| h.path.clone())
        .collect()
}

impl App {
    /// The search view asked for something.
    pub(super) fn search_request(&mut self, request: &SearchRequest) {
        match request {
            SearchRequest::Start(query) => self.start_search(query.clone()),
            SearchRequest::Cancel => {
                if let Some(run) = &self.search {
                    run.cancel.cancel();
                }
            }
            SearchRequest::AskTransfer(hits) => self.ask_search_transfer(hits.clone()),
            SearchRequest::Transfer {
                hits,
                target,
                layout,
            } => self.transfer_hits(hits, target, *layout),
            SearchRequest::AskDelete(hits) => self.ask_search_delete(hits.clone()),
            SearchRequest::Delete(hits) => self.delete_hits(hits.clone()),
            SearchRequest::Queue(items) => self.queue_items(items),
            SearchRequest::GoTo(hit) => self.go_to_hit(hit),
        }
    }

    /// News from a search (dropped when it isn't the last one started).
    pub(super) fn search_update(&mut self, run: u64, update: &SearchUpdate) {
        let Some(current) = self.search.as_ref().filter(|r| r.id == run) else {
            return;
        };
        let side = current.side;
        match update {
            SearchUpdate::Done(summary) => {
                let text = if summary.cancelled {
                    format!("Search stopped: {} found", summary.matches)
                } else {
                    format!(
                        "Search finished: {} found in {}",
                        summary.matches,
                        plural(
                            usize::try_from(summary.dirs_scanned).unwrap_or(usize::MAX),
                            "directory",
                            "directories"
                        )
                    )
                };
                self.events_tx
                    .log(self.local_session, LogKind::Status, text);
            }
            SearchUpdate::Failed(e) => {
                self.events_tx.log(
                    self.local_session,
                    LogKind::Error,
                    format!("Search failed: {e}"),
                );
            }
            SearchUpdate::Deleted(paths) => {
                let mut dirs: Vec<RemotePath> =
                    paths.iter().filter_map(RemotePath::parent).collect();
                dirs.sort();
                dirs.dedup();
                for dir in dirs {
                    self.screen.refresh_dir(side, &dir);
                }
            }
            SearchUpdate::Found(_) | SearchUpdate::Progress(_) => {}
        }
        self.screen.search_update(update);
    }

    /// Whether the remote pane is connected to the server `run` searched.
    fn connected_to(&self, run: &SearchRun) -> bool {
        let Some(info) = &run.info else {
            return false;
        };
        self.remote
            .as_ref()
            .is_some_and(|r| r.connected && r.info.address == info.address)
    }

    /// Start a search, stopping the one before.
    fn start_search(&mut self, query: SearchQuery) {
        if let Some(old) = self.search.take() {
            old.cancel.cancel();
        }
        let id = next_run();
        let session = SessionId::next();
        let root = query.walk_root().unwrap_or_default();
        let (side, mut opts, backend, info) = match &query.root {
            SearchRoot::Local(_) => (Side::Local, SearchOptions::local(session), None, None),
            SearchRoot::Remote(_) => match self.remote.as_ref().filter(|r| r.connected) {
                Some(remote) => (
                    Side::Remote,
                    SearchOptions::remote(session),
                    // A session of its own, so the tab stays usable.
                    Some(
                        self.backends
                            .create(&remote.info, session, self.events_tx.clone()),
                    ),
                    Some(remote.info.clone()),
                ),
                None => (Side::Remote, SearchOptions::remote(session), None, None),
            },
        };
        let cancel = CancellationToken::new();
        self.search = Some(SearchRun {
            id,
            cancel: cancel.clone(),
            side,
            root: root.clone(),
            info: info.clone(),
        });
        let fail = |app: &mut App, why: String| {
            let _ = app.action_tx.send(Action::SearchUpdate {
                run: id,
                update: Shared::new(SearchUpdate::Failed(why)),
            });
        };
        if side == Side::Remote && info.is_none() {
            fail(self, "Not connected".to_owned());
            return;
        }
        opts.walk.cache = Some(self.cache.clone());
        opts.walk.timeout = Duration::from_secs(self.settings.connection.timeout_secs.max(1));
        let started = match backend {
            Some(backend) => spawn_search(backend, query, opts),
            None => spawn_local_search(query, opts),
        };
        let handle = match started {
            Ok(handle) => handle,
            Err(e) => {
                fail(self, e.to_string());
                return;
            }
        };
        if let Some(run) = self.search.as_mut() {
            run.cancel = handle.cancel_token().clone();
        }
        let shown = match side {
            Side::Local => display_native(&root),
            Side::Remote => root.to_string(),
        };
        self.events_tx.log(
            self.local_session,
            LogKind::Status,
            format!("Searching {shown}"),
        );
        forward(handle, id, self.action_tx.clone());
    }

    /// `F5` on results: ask for the target directory and the layout.
    fn ask_search_transfer(&mut self, hits: Vec<SearchHit>) {
        let Some(run) = self.search.as_ref() else {
            return;
        };
        let side = run.side;
        let (verb, default) = match side {
            Side::Remote => (
                "Download",
                self.screen
                    .local
                    .dir
                    .as_ref()
                    .map(display_native)
                    .unwrap_or_default(),
            ),
            Side::Local => {
                if !self.remote.as_ref().is_some_and(|r| r.connected) {
                    self.screen.flash("Connect to a server to upload");
                    return;
                }
                (
                    "Upload",
                    self.screen
                        .remote
                        .dir
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                )
            }
        };
        let form = Form::new(&["OK", "Cancel"])
            .field(
                "target",
                TextInput::new("Target directory:").with_value(&default),
            )
            .field(
                "layout",
                RadioGroup::new(
                    "Layout:",
                    vec!["Keep directory structure".into(), "Flatten".into()],
                    0,
                ),
            );
        let title = format!("{verb} {}", plural(hits.len(), "result", "results"));
        let (dialog, rx) = FormDialog::new(title, 70, form, move |v| {
            let target = v.text("target").trim().to_owned();
            let ok = match side {
                Side::Remote => PathBuf::from(&target).is_absolute(),
                Side::Local => target.starts_with('/'),
            };
            if !ok {
                return Err("Enter the full path of the target directory.".to_owned());
            }
            let layout = if v.index("layout") == Some(1) {
                ResultLayout::Flatten
            } else {
                ResultLayout::KeepStructure
            };
            Ok((target, layout))
        });
        self.screen.push_modal(Box::new(dialog));
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some((target, layout))) = rx.await {
                let _ = tx.send(Action::SearchRequest(Shared::new(
                    SearchRequest::Transfer {
                        hits,
                        target,
                        layout,
                    },
                )));
            }
        });
    }

    /// Queue the hits for `target` and start the queue. The directories
    /// the files go into are created first (the transfer engine expects
    /// them; only queued directories create their own).
    fn transfer_hits(&mut self, hits: &[SearchHit], target: &str, layout: ResultLayout) {
        let Some(run) = self.search.as_ref() else {
            return;
        };
        let tx = self.action_tx.clone();
        let cache = self.cache.clone();
        match run.side {
            Side::Remote => {
                let Some(info) = &run.info else {
                    return;
                };
                let t = &self.settings.transfers;
                let replace = t
                    .replace_invalid_chars
                    .then_some(t.invalid_char_replacement);
                let items = download_items(
                    &queue_server(info),
                    &run.root,
                    hits,
                    &LocalPath::new(PathBuf::from(target)),
                    layout,
                    replace,
                );
                let mut dirs: Vec<PathBuf> = items
                    .iter()
                    .filter_map(|i| i.local.as_path().parent().map(PathBuf::from))
                    .collect();
                dirs.sort();
                dirs.dedup();
                tokio::spawn(async move {
                    for dir in dirs {
                        if tokio::fs::create_dir_all(&dir).await.is_ok()
                            && let Some(parent) = dir.parent()
                            && let Ok(parent) = courier_ftp_core::local::local_to_remote(parent)
                        {
                            cache.invalidate(None, &parent);
                        }
                    }
                    let _ = tx.send(Action::SearchRequest(Shared::new(SearchRequest::Queue(
                        items,
                    ))));
                });
            }
            Side::Local => {
                let Some(remote) = self.remote.as_ref().filter(|r| r.connected) else {
                    self.screen.flash("Not connected");
                    return;
                };
                let items = upload_items(
                    &queue_server(&remote.info),
                    &run.root,
                    hits,
                    &RemotePath::new(target),
                    layout,
                );
                let mut dirs: Vec<RemotePath> =
                    items.iter().filter_map(|i| i.remote.parent()).collect();
                dirs.sort();
                dirs.dedup();
                let handle = Arc::clone(&remote.handle);
                let cancel = remote.cancel.clone();
                let server = remote.info.address.clone();
                tokio::spawn(async move {
                    for dir in dirs {
                        ensure_remote_dir(&handle, &dir, &cancel).await;
                        if let Some(parent) = dir.parent() {
                            cache.invalidate(Some(&server), &parent);
                        }
                    }
                    let _ = tx.send(Action::SearchRequest(Shared::new(SearchRequest::Queue(
                        items,
                    ))));
                });
            }
        }
    }

    /// The directories are ready: add the items and start the queue.
    fn queue_items(&mut self, items: &[NewItem]) {
        let transfer_type = self.screen.transfer_type();
        let mut items = items.to_vec();
        for item in &mut items {
            item.transfer_type = transfer_type;
        }
        let n = items.len();
        if n == 0 {
            self.screen.flash("Nothing to transfer");
            return;
        }
        lock_queue(&self.transfers.queue).add_batch(items, time::OffsetDateTime::now_utc());
        self.transfers.edited(&[], true);
        if !self.transfers.processing() {
            self.transfers.engine.start();
        }
        self.screen
            .flash(format!("Queued {}", plural(n, "result", "results")));
    }

    /// `F8` on results: confirm first.
    fn ask_search_delete(&mut self, hits: Vec<SearchHit>) {
        let Some(run) = self.search.as_ref() else {
            return;
        };
        if run.side == Side::Remote && !self.connected_to(run) {
            self.screen.flash("Not connected to the server searched");
            return;
        }
        let dirs = hits.iter().filter(|h| h.is_dir()).count();
        let mut text = match hits.as_slice() {
            [one] => format!("Delete {}?", one.path),
            _ => format!("Delete {}?", plural(hits.len(), "result", "results")),
        };
        if dirs > 0 {
            text.push_str("\n\nDirectories are deleted with everything in them.");
        }
        let (modal, rx) = confirm("Delete", &text, false);
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(true) = rx.await {
                let _ = tx.send(Action::SearchRequest(Shared::new(SearchRequest::Delete(
                    hits,
                ))));
            }
        });
    }

    /// Delete the hits (confirmed) on the side searched, in the background.
    fn delete_hits(&mut self, hits: Vec<SearchHit>) {
        let Some(run) = self.search.as_ref() else {
            return;
        };
        let id = run.id;
        let tx = self.action_tx.clone();
        let events = self.events_tx.clone();
        let log_session = self.local_session;
        let cache = self.cache.clone();
        let timeout = Duration::from_secs(self.settings.connection.timeout_secs.max(1));
        let finish = move |hits: Vec<SearchHit>, report: RecursiveReport| {
            let removed = removed_by(&hits, &report);
            let gone = format!(
                "Deleted {} and {}",
                plural(usize::try_from(report.files).unwrap_or(0), "file", "files"),
                plural(
                    usize::try_from(report.dirs).unwrap_or(0),
                    "directory",
                    "directories"
                )
            );
            if report.is_complete() {
                events.log(log_session, LogKind::Status, gone);
            } else {
                let why = report
                    .stopped
                    .as_ref()
                    .map(ToString::to_string)
                    .or_else(|| {
                        report
                            .problems
                            .first()
                            .map(|p| format!("{}: {}", p.path, p.reason))
                    })
                    .unwrap_or_default();
                events.log(
                    log_session,
                    LogKind::Error,
                    format!(
                        "{gone}; {} could not be deleted ({why})",
                        plural(
                            usize::try_from(report.problem_count).unwrap_or(0),
                            "entry",
                            "entries"
                        )
                    ),
                );
            }
            let _ = tx.send(Action::SearchUpdate {
                run: id,
                update: Shared::new(SearchUpdate::Deleted(removed)),
            });
        };
        match run.side {
            Side::Local => {
                let mut opts = WalkOptions::local(self.local_session);
                opts.cache = Some(cache);
                opts.timeout = timeout;
                tokio::spawn(async move {
                    let cancel = CancellationToken::new();
                    let mut backend = LocalBackend::new();
                    let report = match backend.connect(cancel.clone()).await {
                        Ok(()) => delete_results(&mut backend, &hits, opts, &cancel).await,
                        Err(e) => RecursiveReport {
                            stopped: Some(e),
                            ..RecursiveReport::default()
                        },
                    };
                    finish(hits, report);
                });
            }
            Side::Remote => {
                if !self.connected_to(run) {
                    self.screen.flash("Not connected to the server searched");
                    return;
                }
                let Some(remote) = self.remote.as_ref() else {
                    return;
                };
                let handle = Arc::clone(&remote.handle);
                let cancel = remote.cancel.clone();
                let mut opts = WalkOptions::remote(remote.session);
                opts.cache = Some(cache);
                opts.timeout = timeout;
                tokio::spawn(async move {
                    let report = {
                        let mut backend = handle.lock().await;
                        delete_results(&mut **backend, &hits, opts, &cancel).await
                    };
                    finish(hits, report);
                });
            }
        }
    }

    /// `Enter` on a result: show it in its pane.
    fn go_to_hit(&mut self, hit: &SearchHit) {
        let Some(run) = self.search.as_ref() else {
            return;
        };
        if run.side == Side::Remote && !self.connected_to(run) {
            self.screen.flash("Not connected to the server searched");
            return;
        }
        let Some(dir) = hit.path.parent() else {
            return;
        };
        let side = run.side;
        self.screen.reveal(side, dir, hit.entry.name.clone());
    }
}
