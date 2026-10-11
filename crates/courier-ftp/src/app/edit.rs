//! T63: the app's side of viewing and editing files externally — F3 View and
//! F4 Edit on the file lists and search results, the temporary copies of
//! remote files, watching them and offering to upload them back, the
//! "Files being edited" dialog, and the quit warning and cleanup.
//!
//! A remote file is downloaded to a private copy (`courier_ftp_core::edit`)
//! over a connection of its own, then opened: terminal programs run in the
//! foreground with the TUI suspended ([`Action::RunForeground`]), windowed
//! ones detached. Edited copies are polled every second; a save with new
//! content asks "Upload it back?" through the prompt queue (T69), so a
//! stray key can't answer it. Before an upload the server's size and time
//! are compared with those at the download; a difference asks before
//! overwriting. Local files open in place: no copy, no upload.

use std::{
    io,
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use courier_ftp_core::{
    backend::{ConnectInfo, TransferOpts, decide_transfer_type},
    edit::{
        ChangeTracker, ContentHash, EditArea, EditorEnv, Launch, OpenKind, Poll, RemoteStamp,
        file_looks_like_text, resolve_program,
    },
    events::{LogKind, PromptKind, PromptResponse},
    local::remote_to_local,
    model::{LogonType, RemotePath},
    settings::TransferTypeChoice,
};
use tokio_util::sync::CancellationToken;

use super::{App, server_label};
use crate::{
    action::{Action, Shared},
    edit::{Copy, Foreground, Uploaded, run_foreground, spawn_detached},
    tui::Tui,
    ui::{
        Side,
        dialog::{ask, choose, confirm},
    },
};

/// How often edited copies are looked at.
const POLL_EVERY: Duration = Duration::from_secs(1);
/// Copies of earlier runs older than this are deleted when editing starts.
const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
const MIB: u64 = 1024 * 1024;

/// The buttons of the "file changed" prompt.
/// (Short: four buttons fit the dialog; the text explains *Always*.)
const CHANGED_BUTTONS: [&str; 4] = ["Yes", "No", "Always", "Stop watching"];
/// The buttons of an entry in the "Files being edited" dialog.
const FILE_BUTTONS: [&str; 5] = [
    "Upload now",
    "Open again",
    "Stop watching",
    "Discard",
    "Cancel",
];

/// What to open.
#[derive(Debug, Clone)]
pub(crate) enum EditTarget {
    /// A local file, opened in place.
    Local(PathBuf),
    /// A remote file on the server `info` connects to.
    Remote {
        info: Box<ConnectInfo>,
        path: RemotePath,
        /// From the listing, for the large-file question.
        size: Option<u64>,
    },
}

/// Steps and results of viewing and editing, sent back as
/// [`Action::EditMsg`].
#[derive(Debug)]
pub(crate) enum EditMsg {
    /// Open this (a large download was confirmed).
    Open(OpenKind, EditTarget),
    /// The download of copy `id` finished.
    Downloaded {
        id: u64,
        result: Result<RemoteStamp, String>,
    },
    /// The answer to "File X has changed. Upload it back?".
    ChangedAnswer { id: u64, choice: Option<usize> },
    /// Upload copy `id` (`force`: without the conflict check).
    Upload { id: u64, force: bool },
    /// An upload finished; `hash` is the content uploaded.
    Uploaded {
        id: u64,
        hash: Option<ContentHash>,
        result: Result<Uploaded, String>,
    },
    /// A file picked in "Files being edited".
    Picked(u64),
    /// A button pressed for a file in "Files being edited".
    FileAction { id: u64, action: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CopyState {
    Downloading,
    Idle,
    /// The "upload it back?" prompt is out.
    Asking,
    Uploading,
}

/// A remote file being viewed or edited through a temporary copy.
#[derive(Debug)]
pub(super) struct EditedFile {
    pub(super) id: u64,
    pub(super) kind: OpenKind,
    pub(super) local: PathBuf,
    /// The connection it came from; uploads go back the same way.
    pub(super) info: ConnectInfo,
    pub(super) remote: RemotePath,
    /// The server's file at the last download or upload.
    pub(super) stamp: RemoteStamp,
    /// `None` until downloaded.
    pub(super) tracker: Option<ChangeTracker>,
    pub(super) state: CopyState,
    /// "Always for this file": upload changes without asking.
    pub(super) always: bool,
    /// The copy is gone (deleted outside the program).
    pub(super) missing: bool,
    /// Stops its download, upload and prompt.
    cancel: CancellationToken,
}

impl EditedFile {
    fn name(&self) -> &str {
        self.remote.file_name().unwrap_or("file")
    }

    /// Changes not on the server yet.
    pub(super) fn is_dirty(&self) -> bool {
        self.tracker.as_ref().is_some_and(ChangeTracker::is_dirty)
            || matches!(self.state, CopyState::Asking | CopyState::Uploading)
    }

    fn status(&self) -> &'static str {
        match self.state {
            CopyState::Downloading => "downloading",
            CopyState::Uploading => "uploading",
            CopyState::Asking => "changed, asking",
            CopyState::Idle if self.missing => "copy deleted",
            CopyState::Idle if self.is_dirty() => "changed, not uploaded",
            CopyState::Idle => "unchanged",
        }
    }
}

/// Viewing and editing state (T63).
#[derive(Debug, Default)]
pub(crate) struct Edits {
    /// Where the copies go (the cache directory); `None` (tests that don't
    /// edit): opening remote files is unavailable.
    pub(super) root: Option<PathBuf>,
    /// `$VISUAL`, `$EDITOR`, `$PAGER` (empty in tests).
    pub(super) env: EditorEnv,
    area: Option<EditArea>,
    pub(super) files: Vec<EditedFile>,
    next_id: u64,
    last_poll: Option<Instant>,
    /// Copies no longer watched but with changes not uploaded: kept at exit.
    pub(super) kept: Vec<PathBuf>,
}

impl Edits {
    /// The production setup: copies under the cache directory, programs
    /// from the environment.
    pub(crate) fn from_environment() -> Self {
        Self {
            root: Some(crate::config::get_cache_dir()),
            env: EditorEnv::from_process(),
            ..Self::default()
        }
    }

    fn get(&mut self, id: u64) -> Option<&mut EditedFile> {
        self.files.iter_mut().find(|f| f.id == id)
    }

    fn take(&mut self, id: u64) -> Option<EditedFile> {
        let i = self.files.iter().position(|f| f.id == id)?;
        Some(self.files.remove(i))
    }

    /// The vault was locked: typed passwords are forgotten (asked again on
    /// upload), as for the transfer queue.
    pub(super) fn forget_passwords(&mut self) {
        for f in &mut self.files {
            if let LogonType::Normal { user, .. } | LogonType::Account { user, .. } = &f.info.logon
            {
                f.info.logon = LogonType::AskForPassword { user: user.clone() };
            }
        }
    }
}

impl App {
    /// The view/edit part of [`App::dispatch`].
    pub(super) fn edit_action(&mut self, action: &Action) {
        match action {
            Action::View => self.open_selected(OpenKind::View),
            Action::Edit => self.open_selected(OpenKind::Edit),
            Action::EditedFiles => self.show_edited_files(),
            Action::EditMsg(msg) => self.edit_msg(&msg.0),
            // Without the terminal (tests): run it as it is.
            Action::RunForeground(job) => {
                let result = run_foreground(&job.0.launch, &job.0.file);
                self.foreground_done(&job.0, result);
            }
            Action::Tick => self.poll_edits(Instant::now(), false),
            _ => {}
        }
    }

    /// [`Action::RunForeground`] with the terminal: suspend the TUI (leave
    /// the alternate screen, raw mode off, input reader stopped), run the
    /// program, restore the TUI and redraw everything.
    pub(super) fn run_in_terminal(
        &mut self,
        tui: &mut Tui,
        job: &Foreground,
    ) -> color_eyre::Result<()> {
        tui.exit()?;
        // The event loop thread waits for the program; transfers and
        // keep-alives go on in the other runtime threads.
        let result = tokio::task::block_in_place(|| run_foreground(&job.launch, &job.file));
        tui.enter()?;
        tui.force_redraw()?;
        self.foreground_done(job, result);
        Ok(())
    }

    fn foreground_done(&mut self, job: &Foreground, result: io::Result<ExitStatus>) {
        if let Err(e) = &result {
            self.edit_report(
                false,
                format!("Could not start {}: {e}", job.launch.program()),
            );
        }
        if job.remove_after {
            self.remove_copy(&job.file);
        }
        if let Some(id) = job.edit {
            self.poll_one(id);
        }
    }

    fn edit_report(&mut self, ok: bool, text: String) {
        let kind = if ok { LogKind::Status } else { LogKind::Error };
        self.events_tx.log(self.local_session, kind, text.clone());
        self.screen.flash(text);
    }

    fn edit_msg(&mut self, msg: &EditMsg) {
        match msg {
            EditMsg::Open(kind, target) => self.open_target(*kind, target.clone(), true),
            EditMsg::Downloaded { id, result } => self.downloaded(*id, result),
            EditMsg::ChangedAnswer { id, choice } => self.changed_answer(*id, *choice),
            EditMsg::Upload { id, force } => self.upload_copy(*id, *force),
            EditMsg::Uploaded { id, hash, result } => self.uploaded(*id, *hash, result),
            EditMsg::Picked(id) => self.edited_file_menu(*id),
            EditMsg::FileAction { id, action } => self.edited_file_action(*id, *action),
        }
    }

    // ------------------------------------------------------------ opening

    /// F3 / F4 on a file list: the file under the cursor.
    fn open_selected(&mut self, kind: OpenKind) {
        let Some(side) = self.screen.focused_list_side() else {
            self.screen
                .flash("Move the cursor to a file in a file list");
            return;
        };
        let pane = self.screen.pane_mut(side);
        let (Some(dir), Some(entry)) = (pane.dir.clone(), pane.current().cloned()) else {
            self.screen.flash("Move the cursor to a file");
            return;
        };
        if entry.is_dir_like() {
            self.screen.flash("That is a directory: choose a file");
            return;
        }
        let Ok(path) = dir.join(&entry.name) else {
            return;
        };
        let target = match side {
            Side::Local => match remote_to_local(&path) {
                Some(local) => EditTarget::Local(local),
                None => return,
            },
            Side::Remote => match self.remote.as_ref().filter(|r| r.connected) {
                Some(remote) => EditTarget::Remote {
                    info: Box::new(remote.info.clone()),
                    path,
                    size: entry.size,
                },
                None => {
                    self.screen.flash("Not connected");
                    return;
                }
            },
        };
        self.open_target(kind, target, false);
    }

    /// Open `target` (`confirmed`: a large download was agreed to).
    pub(super) fn open_target(&mut self, kind: OpenKind, target: EditTarget, confirmed: bool) {
        match target {
            EditTarget::Local(path) => self.open_local(kind, &path),
            EditTarget::Remote { info, path, size } => {
                let limit = self.settings.editing.max_size_mib.saturating_mul(MIB);
                if let Some(size) = size.filter(|&s| !confirmed && limit > 0 && s > limit) {
                    let name = path.file_name().unwrap_or("This file").to_owned();
                    let (modal, rx) = confirm(
                        "Large file",
                        &format!(
                            "{name} is {} MiB. Download it to {}?",
                            size.div_ceil(MIB),
                            match kind {
                                OpenKind::View => "view it",
                                OpenKind::Edit => "edit it",
                            }
                        ),
                        false,
                    );
                    self.screen.push_modal(modal);
                    let tx = self.action_tx.clone();
                    let target = EditTarget::Remote {
                        info,
                        path,
                        size: Some(size),
                    };
                    tokio::spawn(async move {
                        if let Ok(true) = rx.await {
                            let msg = EditMsg::Open(kind, target);
                            let _ = tx.send(Action::EditMsg(Shared::new(msg)));
                        }
                    });
                    return;
                }
                self.open_remote(kind, *info, path);
            }
        }
    }

    /// A local file: opened in place with the program for it.
    fn open_local(&mut self, kind: OpenKind, path: &Path) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let is_text = file_looks_like_text(path).unwrap_or(true);
        match resolve_program(
            &self.settings.editing,
            &name,
            kind,
            is_text,
            &self.edits.env,
        ) {
            Ok(launch) => self.launch(launch, path.to_path_buf(), None, false),
            Err(e) => self.edit_report(false, format!("Cannot open {name}: {e}")),
        }
    }

    /// Start `launch` on `file`: in the terminal through the event loop, or
    /// detached.
    fn launch(&mut self, launch: Launch, file: PathBuf, edit: Option<u64>, remove_after: bool) {
        if launch.terminal {
            let job = Foreground {
                launch,
                file,
                edit,
                remove_after,
            };
            let _ = self.action_tx.send(Action::RunForeground(Shared::new(job)));
            return;
        }
        match spawn_detached(&launch, &file) {
            Ok(()) => {
                let name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.screen
                    .flash(format!("Opened {name} in {}", launch.program()));
            }
            Err(e) => self.edit_report(false, format!("Could not start {}: {e}", launch.program())),
        }
    }

    /// This run's copy directory, created (and old runs swept) on first use.
    fn edit_area(&mut self) -> Result<EditArea, String> {
        if let Some(area) = &self.edits.area {
            return Ok(area.clone());
        }
        let root = self
            .edits
            .root
            .clone()
            .ok_or_else(|| "editing remote files is not available".to_owned())?;
        if let Err(e) = EditArea::sweep_stale(&root, STALE_AFTER, SystemTime::now()) {
            tracing::debug!(error = %e, "old edit copies not swept");
        }
        let area = EditArea::create(&root).map_err(|e| {
            tracing::debug!(error = %e, root = %root.display(), "edit directory not created");
            format!("could not create the directory for temporary copies: {e}")
        })?;
        self.edits.area = Some(area.clone());
        Ok(area)
    }

    fn copy_job(
        &self,
        info: ConnectInfo,
        remote: RemotePath,
        local: PathBuf,
        cancel: CancellationToken,
    ) -> Copy {
        let name = remote.file_name().unwrap_or_default().to_owned();
        let mut file_types = self.settings.file_types.clone();
        let choice = self.screen.transfer_type();
        if choice != TransferTypeChoice::Auto {
            file_types.default_type = choice;
        }
        Copy {
            factory: Arc::clone(&self.backends),
            events: self.events_tx.clone(),
            info,
            remote,
            local,
            opts: TransferOpts {
                transfer_type: decide_transfer_type(&name, &file_types),
                preallocate_hint: None,
            },
            timeout: Duration::from_secs(self.settings.connection.timeout_secs.max(1)),
            cancel,
        }
    }

    /// A remote file: download it to a new copy, then open it.
    fn open_remote(&mut self, kind: OpenKind, info: ConnectInfo, path: RemotePath) {
        // Already being edited: open the copy again rather than a second one.
        if kind == OpenKind::Edit
            && let Some(f) = self.edits.files.iter().find(|f| {
                f.kind == OpenKind::Edit && f.info.address == info.address && f.remote == path
            })
        {
            let id = f.id;
            if f.state == CopyState::Downloading {
                self.screen.flash("That file is still downloading");
            } else {
                self.screen
                    .flash("Already being edited: opening the copy again");
                self.launch_copy(id);
            }
            return;
        }
        let name = path.file_name().unwrap_or("file").to_owned();
        let local = match self.edit_area().and_then(|area| {
            area.new_file(&name)
                .map_err(|e| format!("could not create the temporary copy: {e}"))
        }) {
            Ok(local) => local,
            Err(e) => {
                self.edit_report(false, format!("Cannot open {name}: {e}"));
                return;
            }
        };
        self.edits.next_id += 1;
        let id = self.edits.next_id;
        let cancel = CancellationToken::new();
        let job = self.copy_job(info.clone(), path.clone(), local.clone(), cancel.clone());
        self.edits.files.push(EditedFile {
            id,
            kind,
            local,
            info,
            remote: path,
            stamp: RemoteStamp::default(),
            tracker: None,
            state: CopyState::Downloading,
            always: false,
            missing: false,
            cancel,
        });
        self.screen.flash(format!("Downloading {name}…"));
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let result = job.download().await.map_err(|e| e.to_string());
            let msg = EditMsg::Downloaded { id, result };
            let _ = tx.send(Action::EditMsg(Shared::new(msg)));
        });
    }

    fn downloaded(&mut self, id: u64, result: &Result<RemoteStamp, String>) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        let stamp = match result {
            Ok(stamp) => *stamp,
            Err(e) => {
                let text = format!("Could not download {}: {e}", f.remote);
                if let Some(f) = self.edits.take(id) {
                    self.remove_copy(&f.local);
                }
                self.edit_report(false, text);
                return;
            }
        };
        f.stamp = stamp;
        f.state = CopyState::Idle;
        match ChangeTracker::new(&f.local) {
            Ok(tracker) => f.tracker = Some(tracker),
            Err(e) => {
                let text = format!("Cannot watch the copy of {}: {e}", f.remote);
                self.edit_report(false, text);
                return;
            }
        }
        self.events_tx.log(
            self.local_session,
            LogKind::Status,
            format!(
                "Downloaded {} for {}",
                f.remote,
                match f.kind {
                    OpenKind::View => "viewing",
                    OpenKind::Edit => "editing",
                }
            ),
        );
        self.launch_copy(id);
    }

    /// Open copy `id` with the program for it. A viewed copy isn't watched:
    /// it leaves the list (deleted after a terminal viewer, at exit
    /// otherwise).
    fn launch_copy(&mut self, id: u64) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        let (kind, local, name) = (f.kind, f.local.clone(), f.name().to_owned());
        let is_text = file_looks_like_text(&local).unwrap_or(true);
        let launch = match resolve_program(
            &self.settings.editing,
            &name,
            kind,
            is_text,
            &self.edits.env,
        ) {
            Ok(launch) => launch,
            Err(e) => {
                self.edit_report(false, format!("Cannot open {name}: {e}"));
                return;
            }
        };
        match kind {
            OpenKind::View => {
                self.edits.take(id);
                let terminal = launch.terminal;
                self.launch(launch, local, None, terminal);
            }
            OpenKind::Edit => self.launch(launch, local, Some(id), false),
        }
    }

    fn remove_copy(&mut self, file: &Path) {
        if let Some(area) = &self.edits.area
            && let Err(e) = area.remove(file)
        {
            tracing::debug!(error = %e, "temporary copy not removed");
        }
    }

    /// `Ctrl-x n` created a remote file: open it in the editor, as
    /// FileZilla does (T62). Not without a copy directory (tests).
    pub(super) fn edit_new_file(&mut self, side: Side, path: &RemotePath) {
        if side != Side::Remote || self.edits.root.is_none() {
            return;
        }
        if let Some(remote) = self.remote.as_ref().filter(|r| r.connected) {
            let target = EditTarget::Remote {
                info: Box::new(remote.info.clone()),
                path: path.clone(),
                size: Some(0),
            };
            self.open_target(OpenKind::Edit, target, true);
        }
    }

    /// F3 / F4 on a search result (T65): a local hit opens in place, a
    /// remote one through a copy from the connection searched.
    pub(super) fn open_search_hit(
        &mut self,
        kind: OpenKind,
        side: Side,
        info: Option<&ConnectInfo>,
        hit: &courier_ftp_core::search::SearchHit,
    ) {
        if hit.is_dir() {
            self.screen.flash("That is a directory: choose a file");
            return;
        }
        let target = match (side, info) {
            (Side::Local, _) => match hit.local_path() {
                Some(local) => EditTarget::Local(local.into_path_buf()),
                None => return,
            },
            (Side::Remote, Some(info)) => EditTarget::Remote {
                info: Box::new(info.clone()),
                path: hit.path.clone(),
                size: hit.entry.size,
            },
            (Side::Remote, None) => return,
        };
        self.open_target(kind, target, false);
    }

    // ----------------------------------------------------------- watching

    /// Look at the edited copies (every [`POLL_EVERY`], or now with
    /// `force`) when `editing.watch_and_prompt_upload` is on.
    pub(super) fn poll_edits(&mut self, now: Instant, force: bool) {
        if self.edits.files.is_empty() || !self.settings.editing.watch_and_prompt_upload {
            return;
        }
        if !force
            && self
                .edits
                .last_poll
                .is_some_and(|t| now.saturating_duration_since(t) < POLL_EVERY)
        {
            return;
        }
        self.edits.last_poll = Some(now);
        let ids: Vec<u64> = self.edits.files.iter().map(|f| f.id).collect();
        for id in ids {
            self.poll_one(id);
        }
    }

    /// Look at copy `id` now; new content asks to upload it (or uploads it,
    /// "always").
    fn poll_one(&mut self, id: u64) {
        if !self.settings.editing.watch_and_prompt_upload {
            return;
        }
        let Some(f) = self.edits.get(id) else {
            return;
        };
        if f.kind != OpenKind::Edit || f.state != CopyState::Idle {
            return;
        }
        let Some(tracker) = f.tracker.as_mut() else {
            return;
        };
        match tracker.poll(&f.local) {
            Poll::Unchanged => f.missing = false,
            Poll::Missing => f.missing = true,
            Poll::Changed if !tracker.is_dirty() => {}
            Poll::Changed if f.always => self.upload_copy(id, false),
            Poll::Changed => self.ask_upload(id),
        }
    }

    /// "File X has changed. Upload it back to the server?" through the
    /// prompt queue.
    fn ask_upload(&mut self, id: u64) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        f.state = CopyState::Asking;
        let kind = PromptKind::Choice {
            title: "File changed".to_owned(),
            text: format!(
                "{} has changed.\nUpload it back to {}{}?\n\n\
                 Always: upload this file's changes without asking.",
                f.name(),
                server_label(&f.info.address),
                f.remote
            ),
            buttons: CHANGED_BUTTONS.iter().map(|b| (*b).to_owned()).collect(),
            default: 0,
        };
        let cancel = f.cancel.clone();
        let events = self.events_tx.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let choice = match events.ask(None, kind, &cancel).await {
                Ok(PromptResponse::Choice(i)) => Some(i),
                _ => None,
            };
            let msg = EditMsg::ChangedAnswer { id, choice };
            let _ = tx.send(Action::EditMsg(Shared::new(msg)));
        });
    }

    fn changed_answer(&mut self, id: u64, choice: Option<usize>) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        if f.state == CopyState::Asking {
            f.state = CopyState::Idle;
        }
        match choice {
            Some(0) => self.upload_copy(id, false),
            Some(2) => {
                f.always = true;
                self.upload_copy(id, false);
            }
            Some(3) => self.stop_watching(id),
            // No (or Esc): asked again at the next change.
            _ => {}
        }
    }

    // ------------------------------------------------------------- upload

    /// Upload copy `id` back where it came from (`force`: without comparing
    /// the server's file with the one downloaded).
    fn upload_copy(&mut self, id: u64, force: bool) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        if matches!(f.state, CopyState::Downloading | CopyState::Uploading) {
            self.screen
                .flash("Wait for the transfer of that file to finish");
            return;
        }
        f.state = CopyState::Uploading;
        let expect = (!force).then_some(f.stamp);
        let (info, remote, local, cancel) = (
            f.info.clone(),
            f.remote.clone(),
            f.local.clone(),
            f.cancel.clone(),
        );
        let job = self.copy_job(info, remote.clone(), local.clone(), cancel);
        self.screen.flash(format!("Uploading {remote}…"));
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            // The content as uploaded: a save during the upload stays a
            // change.
            let hash = crate::edit::hash(local).await.ok();
            let result = job.upload(expect).await.map_err(|e| e.to_string());
            let msg = EditMsg::Uploaded { id, hash, result };
            let _ = tx.send(Action::EditMsg(Shared::new(msg)));
        });
    }

    fn uploaded(&mut self, id: u64, hash: Option<ContentHash>, result: &Result<Uploaded, String>) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        f.state = CopyState::Idle;
        let remote = f.remote.clone();
        match result {
            Ok(Uploaded::Done(stamp)) => {
                f.stamp = *stamp;
                if let (Some(tracker), Some(hash)) = (f.tracker.as_mut(), hash) {
                    tracker.synced(hash);
                }
                let server = f.info.address.clone();
                self.edit_report(true, format!("Uploaded {remote}"));
                if let Some(dir) = remote.parent() {
                    self.cache.invalidate(Some(&server), &dir);
                    if self
                        .remote
                        .as_ref()
                        .is_some_and(|r| r.connected && r.info.address == server)
                    {
                        self.screen.refresh_dir(Side::Remote, &dir);
                    }
                }
            }
            Ok(Uploaded::Conflict(_)) => {
                let (modal, rx) = ask(
                    "File changed on the server",
                    &format!(
                        "{remote} was changed on the server since it was downloaded \
                         for editing.\nOverwrite it with your version?"
                    ),
                    &["Overwrite", "Cancel"],
                    1,
                );
                self.screen.push_modal(modal);
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    if let Ok(Some(0)) = rx.await {
                        let msg = EditMsg::Upload { id, force: true };
                        let _ = tx.send(Action::EditMsg(Shared::new(msg)));
                    }
                });
                self.events_tx.log(
                    self.local_session,
                    LogKind::Error,
                    format!("{remote} changed on the server meanwhile: not uploaded"),
                );
            }
            Err(e) => self.edit_report(false, format!("Could not upload {remote}: {e}")),
        }
    }

    // --------------------------------------------- "Files being edited"

    /// `<Ctrl-x><e>`: the files being edited.
    fn show_edited_files(&mut self) {
        // Statuses as of now.
        self.poll_edits(Instant::now(), true);
        let files: Vec<(u64, String)> = self
            .edits
            .files
            .iter()
            .filter(|f| f.kind == OpenKind::Edit)
            .map(|f| {
                (
                    f.id,
                    // The status early: long paths are cut at the right.
                    format!(
                        "{} [{}] {}{}",
                        f.name(),
                        f.status(),
                        server_label(&f.info.address),
                        f.remote,
                    ),
                )
            })
            .collect();
        if files.is_empty() {
            self.screen.flash("No files are being edited");
            return;
        }
        let (ids, labels): (Vec<u64>, Vec<String>) = files.into_iter().unzip();
        let (modal, rx) = choose("Files being edited", labels);
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some(i)) = rx.await
                && let Some(&id) = ids.get(i)
            {
                let _ = tx.send(Action::EditMsg(Shared::new(EditMsg::Picked(id))));
            }
        });
    }

    fn edited_file_menu(&mut self, id: u64) {
        let Some(f) = self.edits.get(id) else {
            return;
        };
        let text = format!(
            "{}{}\nCopy: {}\nStatus: {}",
            server_label(&f.info.address),
            f.remote,
            f.local.display(),
            f.status()
        );
        let title = f.name().to_owned();
        let (modal, rx) = ask(&title, &text, &FILE_BUTTONS, 0);
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some(action)) = rx.await {
                let msg = EditMsg::FileAction { id, action };
                let _ = tx.send(Action::EditMsg(Shared::new(msg)));
            }
        });
    }

    fn edited_file_action(&mut self, id: u64, action: usize) {
        match action {
            0 => {
                self.poll_one(id);
                self.upload_copy(id, false);
            }
            1 => self.launch_copy(id),
            2 => self.stop_watching(id),
            3 => {
                if let Some(f) = self.edits.take(id) {
                    f.cancel.cancel();
                    self.remove_copy(&f.local);
                    self.screen
                        .flash(format!("Discarded the copy of {}", f.remote));
                }
            }
            _ => {}
        }
    }

    /// Stop watching copy `id`. An unchanged copy is deleted; one with
    /// changes not uploaded is kept (also at exit), and the log says where.
    fn stop_watching(&mut self, id: u64) {
        let Some(f) = self.edits.take(id) else {
            return;
        };
        f.cancel.cancel();
        if f.is_dirty() && !f.missing {
            self.events_tx.log(
                self.local_session,
                LogKind::Status,
                format!(
                    "Stopped watching {}; the changed copy is kept at {}",
                    f.remote,
                    f.local.display()
                ),
            );
            self.screen
                .flash(format!("Stopped watching {} (copy kept)", f.remote));
            self.edits.kept.push(f.local);
        } else {
            self.remove_copy(&f.local);
            self.screen.flash(format!("Stopped watching {}", f.remote));
        }
    }

    // ---------------------------------------------------------- quitting

    /// The quit warning about edited files with changes not uploaded.
    pub(super) fn edit_quit_reason(&mut self) -> Option<String> {
        self.poll_edits(Instant::now(), true);
        let n = self
            .edits
            .files
            .iter()
            .filter(|f| f.kind == OpenKind::Edit && f.is_dirty())
            .count();
        if n == 0 {
            return None;
        }
        let dir = self
            .edits
            .area
            .as_ref()
            .map(|a| a.dir().display().to_string())
            .unwrap_or_default();
        Some(format!(
            "{n} edited file{} changes that were not uploaded. The cop{} kept in {dir}.",
            if n == 1 { " has" } else { "s have" },
            if n == 1 { "y is" } else { "ies are" },
        ))
    }

    /// At exit: stop everything and delete the copies, except edited ones
    /// with changes not uploaded.
    pub(super) fn cleanup_edits(&mut self) {
        let Some(area) = self.edits.area.take() else {
            return;
        };
        let keep: Vec<PathBuf> = self
            .edits
            .files
            .iter()
            .filter(|f| f.kind == OpenKind::Edit && f.is_dirty())
            .map(|f| f.local.clone())
            .chain(self.edits.kept.drain(..))
            .collect();
        for f in self.edits.files.drain(..) {
            f.cancel.cancel();
        }
        match area.cleanup(&keep) {
            Ok(0) => {}
            Ok(kept) => {
                tracing::warn!("{kept} edited files with changes not uploaded were kept");
                tracing::debug!(dir = %area.dir().display(), "kept edit copies");
            }
            Err(e) => tracing::debug!(error = %e, "temporary copies not cleaned up"),
        }
    }
}
