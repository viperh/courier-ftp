//! T62: the app's side of the file operations — the dialogs for make
//! directory (F7, Shift-F7), new file (`Ctrl-x n`), rename (F2), move (F6),
//! delete (F8), chmod (`c`), custom commands (`:`) and copy URL (`yu`), the
//! background work (`crate::file_ops`), progress, and keeping the panes
//! current from the patched listing cache.

use std::{path::Path, sync::Arc, time::Duration};

use courier_ftp_core::{
    events::{CoreEvent, LogKind, RecursiveOperation, SessionId},
    local::{display_native, local_to_remote},
    model::{Entry, LogonType, RemotePath, ServerUrl},
    transfer::recursive::{ChmodSpec, Target},
};
use tokio_util::sync::CancellationToken;

use super::App;
use crate::{
    action::{Action, Shared},
    file_ops::{self, OpCtx, OpSummary, Place, Rename, RenameReport},
    ui::{
        Side,
        dialog::{ProgressDialog, ProgressHandle, choose, confirm, message, prompt_text},
        file_ops::{
            ChmodDialog, CommandDialog, count_text, delete_question, overwrite_question, plural,
        },
    },
};

/// The name FileZilla suggests for a new directory.
const NEW_DIR: &str = "New directory";
/// Custom commands remembered for Up/Down.
const HISTORY: usize = 50;

/// Steps and results of file operations, sent back to the app as
/// [`Action::FileOp`].
#[derive(Debug, Clone)]
pub(crate) enum FileOpMsg {
    /// The make-directory dialog was answered.
    Mkdir {
        side: Side,
        input: String,
        enter: bool,
    },
    /// The rename dialog was answered.
    Rename {
        side: Side,
        from: RemotePath,
        input: String,
    },
    /// The move dialog was answered.
    Move {
        side: Side,
        sources: Vec<RemotePath>,
        input: String,
    },
    /// Run these renames (`overwrite`: replacing existing files was
    /// confirmed).
    RunRenames {
        side: Side,
        renames: Vec<Rename>,
        overwrite: bool,
    },
    /// Renames finished (or found files in the way).
    Renamed {
        side: Side,
        renames: Vec<Rename>,
        result: Result<RenameReport, String>,
    },
    /// Delete confirmed.
    Delete { side: Side, targets: Vec<Target> },
    /// Chmod dialog answered.
    Chmod {
        side: Side,
        targets: Vec<Target>,
        spec: ChmodSpec,
    },
    /// The new file dialog was answered.
    NewFile { side: Side, input: String },
    /// A new file was created (or not).
    FileCreated {
        side: Side,
        path: RemotePath,
        result: Result<(), String>,
    },
    /// The custom command line was answered.
    Command(String),
    /// The server's reply to a custom command.
    CommandDone {
        command: String,
        result: Result<String, String>,
    },
    /// Copy this text (a URL or path) to the clipboard.
    Clipboard(String),
    /// A delete or chmod finished.
    Finished {
        side: Side,
        operation: RecursiveOperation,
        summary: OpSummary,
        /// The directories shown when it started (refreshed when they are
        /// not cached).
        dirs: Vec<RemotePath>,
    },
}

/// File operations running (T62).
#[derive(Debug, Default)]
pub(crate) struct FileOps {
    /// The progress dialog of the running delete / chmod: its session and
    /// operation (to match `RecursiveProgress` events) and handle.
    pub(super) progress: Option<(SessionId, RecursiveOperation, ProgressHandle)>,
    /// Shift-F7: enter this directory once created.
    enter: Option<(Side, RemotePath)>,
    /// Custom commands sent this run, oldest first.
    history: Vec<String>,
}

/// What a path typed on `side` means, relative to `dir`: absolute paths
/// stand alone, `..` goes up, `/` (and `\` on Windows locally) separates
/// directories.
pub(crate) fn resolve_input(
    side: Side,
    dir: &RemotePath,
    input: &str,
) -> Result<RemotePath, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Enter a name".to_owned());
    }
    let path = match side {
        Side::Local if Path::new(input).is_absolute() => {
            local_to_remote(Path::new(input)).map_err(|e| e.to_string())?
        }
        Side::Local if cfg!(windows) => dir.join_path(&input.replace('\\', "/")),
        Side::Local | Side::Remote => dir.join_path(input),
    };
    if path.is_root() {
        return Err("That is the root directory".to_owned());
    }
    Ok(path)
}

/// A path as the user knows it (native on the local side).
fn shown(side: Side, path: &RemotePath) -> String {
    match side {
        Side::Local => display_native(path),
        Side::Remote => path.to_string(),
    }
}

impl App {
    /// The file-operation part of [`App::dispatch`].
    pub(super) fn file_op_action(&mut self, action: &Action) {
        match action {
            Action::Mkdir => self.ask_mkdir(false),
            Action::MkdirEnter => self.ask_mkdir(true),
            Action::NewFile => self.ask_new_file(),
            Action::CommandLine => self.ask_command(),
            Action::CopyUrl => self.ask_copy_url(),
            Action::Rename => self.ask_rename(),
            Action::Move => self.ask_move(),
            Action::Delete => self.ask_delete(),
            Action::Chmod => self.ask_chmod(),
            Action::MakeDir { side, dir } => self.make_dir(*side, dir.clone()),
            Action::DirMade { side, dir, result } => self.dir_made(*side, dir, result),
            Action::FileOp(msg) => self.file_op(&msg.0),
            _ => {}
        }
    }

    /// Core events for the running operation: progress in its dialog and
    /// the status bar.
    pub(super) fn file_op_event(&mut self, event: &CoreEvent) {
        let CoreEvent::RecursiveProgress(p) = event else {
            return;
        };
        let Some((session, operation, handle)) = &self.file_ops.progress else {
            return;
        };
        if p.session != *session || p.operation != *operation {
            return;
        }
        let verb = match p.operation {
            RecursiveOperation::Delete => "Deleting",
            RecursiveOperation::Chmod => "Changing permissions",
            RecursiveOperation::Listing => "Listing",
        };
        let found = p.files + p.dirs;
        handle.update(format!("{verb}: {}", p.current), p.done, Some(found));
        self.screen
            .flash(format!("{verb}: {} of {found} done", p.done));
    }

    /// A patched cached listing (T46): the panes showing it are redrawn
    /// from the cache, without listing again.
    pub(super) fn listing_patched(&mut self, side: Side, dir: &RemotePath) {
        let server = match side {
            Side::Local => None,
            Side::Remote => match &self.remote {
                Some(r) => Some(r.info.address.clone()),
                None => return,
            },
        };
        if let Some(listing) = self.cache.get(server.as_ref(), dir) {
            self.screen.listing_patched(side, &listing);
        }
    }

    /// The operation context of `side`, or why there is none.
    fn op_ctx(&mut self, side: Side) -> Result<OpCtx, &'static str> {
        let timeout = Duration::from_secs(self.settings.connection.timeout_secs.max(1));
        let filter = self.screen.pane_mut(side).filters().clone();
        let (place, server, session, cancel) = match side {
            Side::Local => (
                Place::Local,
                None,
                self.local_session,
                CancellationToken::new(),
            ),
            Side::Remote => {
                let remote = self
                    .remote
                    .as_ref()
                    .filter(|r| r.connected)
                    .ok_or("Not connected")?;
                (
                    Place::Remote(Arc::clone(&remote.handle)),
                    Some(remote.info.address.clone()),
                    remote.session,
                    remote.cancel.child_token(),
                )
            }
        };
        Ok(OpCtx {
            place,
            server,
            session,
            cache: self.cache.clone(),
            events: self.events_tx.clone(),
            timeout,
            cancel,
            filter,
        })
    }

    /// Run `work` in the background; its message comes back as
    /// [`Action::FileOp`].
    fn spawn_op(&self, work: impl Future<Output = FileOpMsg> + Send + 'static) {
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let msg = work.await;
            let _ = tx.send(Action::FileOp(Shared::new(msg)));
        });
    }

    /// The answer of a dialog, as a [`FileOpMsg`], when there is one.
    fn on_answer<T: Send + 'static>(
        &self,
        rx: tokio::sync::oneshot::Receiver<T>,
        then: impl FnOnce(T) -> Option<FileOpMsg> + Send + 'static,
    ) {
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(answer) = rx.await
                && let Some(msg) = then(answer)
            {
                let _ = tx.send(Action::FileOp(Shared::new(msg)));
            }
        });
    }

    fn log(&self, side: Side, kind: LogKind, text: impl Into<String>) {
        let session = match side {
            Side::Remote => self.current_session().unwrap_or(self.local_session),
            Side::Local => self.local_session,
        };
        self.events_tx.log(session, kind, text);
    }

    /// Log and flash a result line.
    fn report(&mut self, side: Side, ok: bool, text: String) {
        let kind = if ok { LogKind::Status } else { LogKind::Error };
        self.log(side, kind, text.clone());
        self.screen.flash(text);
    }

    /// The focused list's side and directory, or say why not.
    fn list_side(&mut self) -> Option<(Side, RemotePath)> {
        let Some(side) = self.screen.focused_list_side() else {
            self.screen.flash("Select entries in a file list first");
            return None;
        };
        self.side_dir(side)
    }

    fn side_dir(&mut self, side: Side) -> Option<(Side, RemotePath)> {
        if side == Side::Remote && !self.remote.as_ref().is_some_and(|r| r.connected) {
            self.screen.flash("Not connected");
            return None;
        }
        match self.screen.pane_mut(side).dir.clone() {
            Some(dir) => Some((side, dir)),
            None => {
                self.screen.flash("No directory is shown");
                None
            }
        }
    }

    /// The selected entries (or the one under the cursor) as targets.
    fn targets(&mut self, side: Side, dir: &RemotePath) -> Vec<Target> {
        self.screen
            .pane_mut(side)
            .target_entries()
            .into_iter()
            .filter_map(|e| Some(Target::new(dir.join(&e.name).ok()?, e)))
            .collect()
    }

    // ---------------------------------------------------------------- mkdir

    /// F7 / Shift-F7: the name of the new directory, prefilled with the
    /// current path and "New directory" as in FileZilla.
    fn ask_mkdir(&mut self, enter: bool) {
        let Some(side) = self.screen.focused_side() else {
            self.screen
                .flash("Focus a file list to create a directory there");
            return;
        };
        let Some((side, dir)) = self.side_dir(side) else {
            return;
        };
        let initial = dir
            .join(NEW_DIR)
            .map(|p| shown(side, &p))
            .unwrap_or_default();
        let title = if enter {
            "Create directory and enter it"
        } else {
            "Create directory"
        };
        let (modal, rx) = prompt_text(title, "Name:", &initial);
        self.screen.push_modal(modal);
        self.on_answer(rx, move |input| {
            input.map(|input| FileOpMsg::Mkdir { side, input, enter })
        });
    }

    /// Create `dir` (and missing parents) on `side`; [`Action::DirMade`]
    /// reports the result. Also synchronized browsing's "create it" (T66).
    pub(super) fn make_dir(&mut self, side: Side, dir: RemotePath) {
        let tx = self.action_tx.clone();
        let ctx = match self.op_ctx(side) {
            Ok(ctx) => ctx,
            Err(why) => {
                let _ = tx.send(Action::DirMade {
                    side,
                    dir,
                    result: Err(why.to_owned()),
                });
                return;
            }
        };
        tokio::spawn(async move {
            let result = file_ops::mkdir_p(&ctx, &dir)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(Action::DirMade { side, dir, result });
        });
    }

    fn dir_made(&mut self, side: Side, dir: &RemotePath, result: &Result<(), String>) {
        let enter = self
            .file_ops
            .enter
            .take_if(|(s, d)| *s == side && d == dir)
            .is_some();
        match result {
            Ok(()) => {
                self.report(
                    side,
                    true,
                    format!("Created directory {}", shown(side, dir)),
                );
                if let Some(parent) = dir.parent() {
                    self.refresh_uncached(side, &[parent]);
                }
                if enter {
                    self.screen.go_to(side, dir.clone());
                }
            }
            Err(e) => self.report(
                side,
                false,
                format!("Could not create {}: {e}", shown(side, dir)),
            ),
        }
    }

    /// List `dirs` again where `side` shows them and our change couldn't
    /// patch a cached listing (cache off, or the listing evicted).
    fn refresh_uncached(&mut self, side: Side, dirs: &[RemotePath]) {
        let server = match side {
            Side::Local => None,
            Side::Remote => self.remote.as_ref().map(|r| r.info.address.clone()),
        };
        for dir in dirs {
            if self.cache.get(server.as_ref(), dir).is_none() {
                self.screen.refresh_dir(side, dir);
                self.screen.tree_mut(side).invalidate(dir);
            }
        }
    }

    // ------------------------------------------------------- rename / move

    /// F2: rename the entry under the cursor. A name with `/` moves it to
    /// another directory.
    fn ask_rename(&mut self) {
        let Some((side, dir)) = self.list_side() else {
            return;
        };
        let Some(entry) = self.screen.pane_mut(side).current().cloned() else {
            self.screen.flash("Nothing to rename");
            return;
        };
        let Ok(from) = dir.join(&entry.name) else {
            return;
        };
        let (modal, rx) = prompt_text("Rename", "New name:", &entry.name);
        self.screen.push_modal(modal);
        self.on_answer(rx, move |input| {
            input.map(|input| FileOpMsg::Rename { side, from, input })
        });
    }

    /// F6: move the selection to another directory on the same side (or,
    /// for one entry, to another path).
    fn ask_move(&mut self) {
        let Some((side, dir)) = self.list_side() else {
            return;
        };
        let targets = self.targets(side, &dir);
        let (text, initial) = match targets.as_slice() {
            [] => {
                self.screen.flash("Nothing to move");
                return;
            }
            [one] => (
                format!("Move {} to:", one.entry.name),
                shown(side, &one.path),
            ),
            many => (
                format!(
                    "Move {} to directory:",
                    plural(many.len(), "entry", "entries")
                ),
                shown(side, &dir),
            ),
        };
        let sources: Vec<RemotePath> = targets.into_iter().map(|t| t.path).collect();
        let (modal, rx) = prompt_text("Move", &text, &initial);
        self.screen.push_modal(modal);
        self.on_answer(rx, move |input| {
            input.map(|input| FileOpMsg::Move {
                side,
                sources,
                input,
            })
        });
    }

    /// Whether `side` can move entries between directories; flashes why
    /// not.
    fn can_move_across(&mut self, side: Side, renames: &[Rename]) -> bool {
        let across = renames.iter().any(|r| r.from.parent() != r.to.parent());
        let able = match side {
            Side::Local => true,
            Side::Remote => self
                .remote
                .as_ref()
                .and_then(|r| r.capabilities)
                .is_none_or(|c| c.server_side_rename_across_dirs),
        };
        if across && !able {
            self.screen
                .flash("This server can't move entries to another directory");
            return false;
        }
        true
    }

    fn run_renames(&mut self, side: Side, renames: Vec<Rename>, overwrite: bool) {
        if renames.is_empty() || !self.can_move_across(side, &renames) {
            return;
        }
        let ctx = match self.op_ctx(side) {
            Ok(ctx) => ctx,
            Err(why) => {
                self.screen.flash(why);
                return;
            }
        };
        self.spawn_op(async move {
            let result = file_ops::rename_all(&ctx, renames.clone(), overwrite)
                .await
                .map_err(|e| e.to_string());
            FileOpMsg::Renamed {
                side,
                renames,
                result,
            }
        });
    }

    fn renamed(&mut self, side: Side, renames: &[Rename], result: &Result<RenameReport, String>) {
        let report = match result {
            Ok(r) => r,
            Err(e) => {
                self.report(side, false, format!("Rename failed: {e}"));
                return;
            }
        };
        for (r, why) in &report.failed {
            self.log(
                side,
                LogKind::Error,
                format!(
                    "Could not move {} to {}: {why}",
                    shown(side, &r.from),
                    shown(side, &r.to)
                ),
            );
        }
        if !report.conflicts.is_empty() {
            let names: Vec<String> = report
                .conflicts
                .iter()
                .map(|r| shown(side, &r.to))
                .collect();
            let failed: Vec<&Rename> = report.failed.iter().map(|(r, _)| r).collect();
            let retry: Vec<Rename> = renames
                .iter()
                .filter(|r| !failed.contains(r))
                .cloned()
                .collect();
            let (modal, rx) = confirm("Target exists", &overwrite_question(&names), false);
            self.screen.push_modal(modal);
            self.on_answer(rx, move |yes| {
                yes.then_some(FileOpMsg::RunRenames {
                    side,
                    renames: retry,
                    overwrite: true,
                })
            });
            return;
        }
        let text = match report.done.as_slice() {
            [] => None,
            [one] if one.from.parent() == one.to.parent() => Some(format!(
                "Renamed {} to {}",
                one.from.file_name().unwrap_or_default(),
                one.to.file_name().unwrap_or_default()
            )),
            [one] => Some(format!(
                "Moved {} to {}",
                shown(side, &one.from),
                shown(side, &one.to)
            )),
            many => Some(format!("Moved {}", plural(many.len(), "entry", "entries"))),
        };
        let ok = report.failed.is_empty() && report.stopped.is_none();
        let text = match (text, ok) {
            (Some(t), true) => t,
            (Some(t), false) => format!("{t}; {} failed (see the log)", report.failed.len()),
            (None, _) => format!(
                "Nothing moved; {} failed (see the log)",
                report.failed.len()
            ),
        };
        self.report(side, ok, text);
        let mut dirs: Vec<RemotePath> = Vec::new();
        for r in &report.done {
            for d in [r.from.parent(), r.to.parent()].into_iter().flatten() {
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
        self.refresh_uncached(side, &dirs);
    }

    // --------------------------------------------------------------- delete

    /// F8: delete the selection (or the entry under the cursor), after
    /// asking unless `interface.confirm_delete` is off.
    fn ask_delete(&mut self) {
        let Some((side, dir)) = self.list_side() else {
            return;
        };
        let targets = self.targets(side, &dir);
        if targets.is_empty() {
            self.screen.flash("Nothing to delete");
            return;
        }
        if !self.settings.interface.confirm_delete {
            self.file_op(&FileOpMsg::Delete { side, targets });
            return;
        }
        let entries: Vec<Entry> = targets.iter().map(|t| t.entry.clone()).collect();
        let (modal, rx) = confirm("Delete", &delete_question(side, &entries), false);
        self.screen.push_modal(modal);
        self.on_answer(rx, move |yes| {
            yes.then_some(FileOpMsg::Delete { side, targets })
        });
    }

    /// Start a delete or chmod with a progress dialog (Cancel stops it).
    fn run_recursive(
        &mut self,
        side: Side,
        operation: RecursiveOperation,
        targets: Vec<Target>,
        spec: Option<ChmodSpec>,
    ) {
        if self.file_ops.progress.is_some() {
            self.screen
                .flash("Another operation is running; wait for it or cancel it");
            return;
        }
        let ctx = match self.op_ctx(side) {
            Ok(ctx) => ctx,
            Err(why) => {
                self.screen.flash(why);
                return;
            }
        };
        let title = match operation {
            RecursiveOperation::Delete => "Deleting",
            _ => "Changing permissions",
        };
        let (dialog, handle) = ProgressDialog::new(title);
        handle.update(
            format!("{title} {}…", plural(targets.len(), "entry", "entries")),
            0,
            None,
        );
        self.screen.push_modal(Box::new(dialog));
        // Cancel in the dialog stops the operation.
        let stop = ctx.cancel.clone();
        let pressed = handle.cancel_token().clone();
        tokio::spawn(async move {
            tokio::select! {
                () = pressed.cancelled() => stop.cancel(),
                () = stop.cancelled() => {}
            }
        });
        self.file_ops.progress = Some((ctx.session, operation, handle));
        let dirs: Vec<RemotePath> = self.screen.pane_mut(side).dir.iter().cloned().collect();
        self.spawn_op(async move {
            let report = match spec {
                Some(spec) => file_ops::chmod(&ctx, targets, spec).await,
                None => file_ops::delete(&ctx, targets).await,
            };
            // Ends the cancel link above.
            ctx.cancel.cancel();
            FileOpMsg::Finished {
                side,
                operation,
                summary: OpSummary::from(&report),
                dirs,
            }
        });
    }

    fn finished(
        &mut self,
        side: Side,
        operation: RecursiveOperation,
        s: &OpSummary,
        dirs: &[RemotePath],
    ) {
        if let Some((_, _, handle)) = self.file_ops.progress.take() {
            handle.finish();
        }
        for (path, why) in &s.problems {
            self.log(
                side,
                LogKind::Error,
                format!("{}: {why}", shown(side, path)),
            );
        }
        let done = count_text(
            usize::try_from(s.files).unwrap_or(usize::MAX),
            usize::try_from(s.dirs).unwrap_or(usize::MAX),
        );
        let mut text = match operation {
            RecursiveOperation::Delete => format!("Deleted {done}"),
            _ => format!("Changed the permissions of {done}"),
        };
        if s.problem_count > 0 {
            text.push_str(&format!(
                "; {} (see the log)",
                plural(
                    usize::try_from(s.problem_count).unwrap_or(usize::MAX),
                    "problem",
                    "problems"
                )
            ));
        }
        if s.cancelled {
            text.push_str(" (cancelled)");
        } else if let Some(why) = &s.stopped {
            text.push_str(&format!(" (stopped: {why})"));
        }
        // The core logged the totals already; the status bar says it too.
        self.screen.flash(text);
        self.refresh_uncached(side, dirs);
    }

    // ---------------------------------------------------------------- chmod

    /// `c`: FileZilla's file attributes dialog for the selection.
    fn ask_chmod(&mut self) {
        let Some((side, dir)) = self.list_side() else {
            return;
        };
        let supported = match side {
            Side::Local => cfg!(unix),
            Side::Remote => self
                .remote
                .as_ref()
                .and_then(|r| r.capabilities)
                .is_none_or(|c| c.chmod),
        };
        if !supported {
            let (modal, _) = message(
                "File attributes",
                match side {
                    Side::Local => "Changing permissions isn't supported on this system.",
                    Side::Remote => {
                        "This server doesn't support changing permissions (for example, \
                         an FTP server without SITE CHMOD)."
                    }
                },
            );
            self.screen.push_modal(modal);
            return;
        }
        let targets = self.targets(side, &dir);
        if targets.is_empty() {
            self.screen.flash("Nothing selected");
            return;
        }
        let entries: Vec<Entry> = targets.iter().map(|t| t.entry.clone()).collect();
        let (dialog, rx) = ChmodDialog::new(&entries);
        self.screen.push_modal(Box::new(dialog));
        self.on_answer(rx, move |spec| {
            spec.map(|spec| FileOpMsg::Chmod {
                side,
                targets,
                spec,
            })
        });
    }

    // ------------------------------------------------------------ messages

    fn file_op(&mut self, msg: &FileOpMsg) {
        match msg {
            FileOpMsg::Mkdir { side, input, enter } => {
                let Some((side, dir)) = self.side_dir(*side) else {
                    return;
                };
                match resolve_input(side, &dir, input) {
                    Ok(path) => {
                        if *enter {
                            self.file_ops.enter = Some((side, path.clone()));
                        }
                        self.make_dir(side, path);
                    }
                    Err(e) => self.screen.flash(e),
                }
            }
            FileOpMsg::Rename { side, from, input } => {
                let Some(dir) = from.parent() else {
                    return;
                };
                match resolve_input(*side, &dir, input) {
                    Ok(to) => self.run_renames(
                        *side,
                        vec![Rename {
                            from: from.clone(),
                            to,
                        }],
                        false,
                    ),
                    Err(e) => self.screen.flash(e),
                }
            }
            FileOpMsg::Move {
                side,
                sources,
                input,
            } => self.start_move(*side, sources.clone(), input),
            FileOpMsg::RunRenames {
                side,
                renames,
                overwrite,
            } => self.run_renames(*side, renames.clone(), *overwrite),
            FileOpMsg::Renamed {
                side,
                renames,
                result,
            } => self.renamed(*side, renames, result),
            FileOpMsg::Delete { side, targets } => {
                self.run_recursive(*side, RecursiveOperation::Delete, targets.clone(), None);
            }
            FileOpMsg::Chmod {
                side,
                targets,
                spec,
            } => self.run_recursive(
                *side,
                RecursiveOperation::Chmod,
                targets.clone(),
                Some(*spec),
            ),
            FileOpMsg::Finished {
                side,
                operation,
                summary,
                dirs,
            } => self.finished(*side, *operation, summary, dirs),
            FileOpMsg::NewFile { side, input } => self.new_file(*side, input),
            FileOpMsg::FileCreated { side, path, result } => {
                self.file_created(*side, path, result);
            }
            FileOpMsg::Command(command) => self.send_command(command),
            FileOpMsg::CommandDone { command, result } => self.command_done(command, result),
            FileOpMsg::Clipboard(text) => {
                let _ = self.action_tx.send(Action::CopyToClipboard(text.clone()));
            }
        }
    }

    /// Move: into the target when it is an existing directory, else (one
    /// entry) to that path.
    fn start_move(&mut self, side: Side, sources: Vec<RemotePath>, input: &str) {
        let Some((side, dir)) = self.side_dir(side) else {
            return;
        };
        let target = match resolve_input(side, &dir, input) {
            Ok(t) => t,
            Err(e) => {
                self.screen.flash(e);
                return;
            }
        };
        let ctx = match self.op_ctx(side) {
            Ok(ctx) => ctx,
            Err(why) => {
                self.screen.flash(why);
                return;
            }
        };
        self.spawn_op(async move {
            let into = match file_ops::stat(&ctx, &target).await {
                Ok(e) => e.is_some_and(|e| e.is_dir_like()),
                Err(e) => {
                    return FileOpMsg::Renamed {
                        side,
                        renames: Vec::new(),
                        result: Err(e.to_string()),
                    };
                }
            };
            let renames: Vec<Rename> = if into {
                sources
                    .iter()
                    .filter_map(|from| {
                        let to = target.join(from.file_name()?).ok()?;
                        Some(Rename {
                            from: from.clone(),
                            to,
                        })
                    })
                    .collect()
            } else if let [from] = sources.as_slice() {
                vec![Rename {
                    from: from.clone(),
                    to: target.clone(),
                }]
            } else {
                return FileOpMsg::Renamed {
                    side,
                    renames: Vec::new(),
                    result: Err(format!("{} is not a directory", shown(side, &target))),
                };
            };
            FileOpMsg::RunRenames {
                side,
                renames,
                overwrite: false,
            }
        });
    }

    // ------------------------------------------------------------ new file

    /// `Ctrl-x n`: create an empty file in the focused pane's directory.
    fn ask_new_file(&mut self) {
        let Some((side, _)) = self.list_side() else {
            return;
        };
        let (modal, rx) = prompt_text("Create new file", "Name:", "");
        self.screen.push_modal(modal);
        self.on_answer(rx, move |input| {
            input.map(|input| FileOpMsg::NewFile { side, input })
        });
    }

    fn new_file(&mut self, side: Side, input: &str) {
        let Some((side, dir)) = self.side_dir(side) else {
            return;
        };
        let path = match resolve_input(side, &dir, input) {
            Ok(p) => p,
            Err(e) => {
                self.screen.flash(e);
                return;
            }
        };
        let ctx = match self.op_ctx(side) {
            Ok(ctx) => ctx,
            Err(why) => {
                self.screen.flash(why);
                return;
            }
        };
        self.spawn_op(async move {
            let result = file_ops::create_file(&ctx, &path)
                .await
                .map_err(|e| e.to_string());
            FileOpMsg::FileCreated { side, path, result }
        });
    }

    fn file_created(&mut self, side: Side, path: &RemotePath, result: &Result<(), String>) {
        match result {
            Ok(()) => {
                self.report(side, true, format!("Created file {}", shown(side, path)));
                if let Some(parent) = path.parent() {
                    self.refresh_uncached(side, &[parent]);
                }
                self.edit_new_file(side, path);
            }
            Err(e) => self.report(
                side,
                false,
                format!("Could not create {}: {e}", shown(side, path)),
            ),
        }
    }

    // ------------------------------------------------------ custom command

    /// `:`: a raw command for the server, with the history of this run.
    fn ask_command(&mut self) {
        let Some(remote) = self.remote.as_ref().filter(|r| r.connected) else {
            self.screen
                .flash("Not connected: custom commands go to the server");
            return;
        };
        if remote.capabilities.is_some_and(|c| !c.raw_commands) {
            let (modal, _) = message(
                "Custom command",
                "This connection doesn't take custom commands (SFTP has no raw \
                 command channel; FTP servers do).",
            );
            self.screen.push_modal(modal);
            return;
        }
        let (dialog, rx) = CommandDialog::new(self.file_ops.history.clone());
        self.screen.push_modal(Box::new(dialog));
        self.on_answer(rx, |command| command.map(FileOpMsg::Command));
    }

    fn send_command(&mut self, command: &str) {
        let history = &mut self.file_ops.history;
        history.retain(|c| c != command);
        history.push(command.to_owned());
        if history.len() > HISTORY {
            history.remove(0);
        }
        let ctx = match self.op_ctx(Side::Remote) {
            Ok(ctx) => ctx,
            Err(why) => {
                self.screen.flash(why);
                return;
            }
        };
        let command = command.to_owned();
        self.spawn_op(async move {
            let result = file_ops::raw_command(&ctx, &command)
                .await
                .map_err(|e| e.to_string());
            FileOpMsg::CommandDone { command, result }
        });
    }

    /// The protocol logs the command and every reply line (T55); the status
    /// bar shows the last one. The directory may have changed under us.
    fn command_done(&mut self, command: &str, result: &Result<String, String>) {
        match result {
            Ok(reply) => {
                let last = reply.lines().last().unwrap_or("(no reply)").to_owned();
                self.screen.flash(last);
            }
            Err(e) => self.report(Side::Remote, false, format!("Custom command failed: {e}")),
        }
        // `DELE`, `MKD`, `SITE CHMOD`… change things the cache doesn't know.
        let verb = command
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if !matches!(
            verb.as_str(),
            "NOOP" | "PWD" | "XPWD" | "SYST" | "STAT" | "HELP" | "FEAT"
        ) {
            if let Some(remote) = &self.remote {
                self.cache.clear_server(Some(&remote.info.address));
            }
            if let Some(dir) = self.screen.remote.dir.clone() {
                self.screen.refresh_dir(Side::Remote, &dir);
                self.screen.tree_mut(Side::Remote).invalidate(&dir);
            }
        }
    }

    // ------------------------------------------------------------ copy URL

    /// `yu`: copy the URL of the selection (or the entry under the cursor,
    /// or the directory). Remotely a menu picks with or without the port
    /// and password; locally the native paths are copied.
    fn ask_copy_url(&mut self) {
        let Some((side, dir)) = self.list_side() else {
            return;
        };
        let mut paths: Vec<RemotePath> = self
            .targets(side, &dir)
            .into_iter()
            .map(|t| t.path)
            .collect();
        if paths.is_empty() {
            paths.push(dir);
        }
        if side == Side::Local {
            let text = paths
                .iter()
                .map(|p| shown(side, p))
                .collect::<Vec<_>>()
                .join("\n");
            let _ = self.action_tx.send(Action::CopyToClipboard(text));
            return;
        }
        let Some(remote) = &self.remote else {
            return;
        };
        let password = match &remote.info.logon {
            LogonType::Normal { password, .. } => Some(password.clone()),
            _ => None,
        };
        let urls = |port: bool, with_password: bool| -> String {
            paths
                .iter()
                .map(|p| {
                    ServerUrl {
                        address: remote.info.address.clone(),
                        password: password.clone(),
                        path: Some(p.clone()),
                    }
                    .to_text(port, with_password)
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let plain = urls(false, false);
        let mut labels = vec!["Without the port".to_owned()];
        let mut texts = vec![plain.clone()];
        let with_port = urls(true, false);
        if with_port != plain {
            labels.push("With the port".to_owned());
            texts.push(with_port);
        }
        if password.is_some() {
            labels.push("With the port and password".to_owned());
            texts.push(urls(true, true));
        }
        if texts.len() == 1 {
            let _ = self
                .action_tx
                .send(Action::CopyToClipboard(texts[0].clone()));
            return;
        }
        let title = match paths.len() {
            1 => "Copy URL".to_owned(),
            n => format!("Copy {n} URLs"),
        };
        let (modal, rx) = choose(&title, labels);
        self.screen.push_modal(modal);
        self.on_answer(rx, move |i| {
            i.and_then(|i| texts.get(i).cloned())
                .map(FileOpMsg::Clipboard)
        });
    }
}
