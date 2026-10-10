//! Recursive delete and chmod over a [`Walker`].

use tokio_util::sync::CancellationToken;

use super::{
    group_thousands, is_fatal, timed,
    walk::{RecursiveReport, Target, WalkEvent, WalkOptions, Walker},
};
use crate::{
    Error,
    backend::Backend,
    events::{LogKind, RecursiveOperation},
    model::{Entry, Permissions, RemotePath},
};

/// Which entries a recursive chmod changes (FileZilla's "Apply to all files
/// and directories / Apply to files only / Apply to directories only").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ApplyTo {
    /// Files and directories.
    #[default]
    All,
    /// Files only.
    FilesOnly,
    /// Directories only.
    DirsOnly,
}

/// What a chmod sets: the bits in `mask` are set from `mode`, the others
/// are left as they are (the tri-state checkboxes of T62's dialog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChmodSpec {
    /// The wanted bits (`0o7777` range).
    pub mode: u32,
    /// The bits to change; the rest are "leave unchanged".
    pub mask: u32,
    /// Recurse into subdirectories.
    pub recurse: bool,
    /// Which entries to change.
    pub apply_to: ApplyTo,
}

impl ChmodSpec {
    /// Set every permission bit to `mode` (no "leave unchanged"), without
    /// recursion.
    pub fn exact(mode: u32) -> Self {
        Self {
            mode: mode & 0o7777,
            mask: 0o7777,
            recurse: false,
            apply_to: ApplyTo::All,
        }
    }

    /// Set one bit (`0o400`, `0o4000`, …): `Some(true)` set, `Some(false)`
    /// clear, `None` leave unchanged.
    pub fn set_bit(&mut self, bit: u32, state: Option<bool>) {
        let bit = bit & 0o7777;
        match state {
            Some(on) => {
                self.mask |= bit;
                if on {
                    self.mode |= bit;
                } else {
                    self.mode &= !bit;
                }
            }
            None => {
                self.mask &= !bit;
                self.mode &= !bit;
            }
        }
    }

    /// The new permission bits for an entry whose current bits are `old`.
    /// With `old` unknown, only a mask covering all rwx bits gives an answer
    /// (setuid/setgid/sticky then count as clear); otherwise `None`.
    pub fn compute(&self, old: Option<u32>) -> Option<u32> {
        let old = match old {
            Some(o) => o,
            None if self.mask & 0o777 == 0o777 => 0,
            None => return None,
        };
        Some(apply_mask(old, self.mode, self.mask))
    }

    fn applies(&self, is_dir: bool) -> bool {
        match self.apply_to {
            ApplyTo::All => true,
            ApplyTo::FilesOnly => !is_dir,
            ApplyTo::DirsOnly => is_dir,
        }
    }
}

/// `(old & !mask) | (new & mask)`, limited to the permission bits
/// (`0o7777`).
pub fn apply_mask(old: u32, new: u32, mask: u32) -> u32 {
    ((old & !mask) | (new & mask)) & 0o7777
}

/// Delete `targets` and everything below them, bottom-up.
///
/// Files and symlinks are removed with `remove_file` (links are never
/// followed: a link to a directory is removed, not its contents), then each
/// directory with `rmdir` once everything inside it is gone. Filtered
/// entries are kept, and so are the directories holding them. A failure is
/// recorded and the rest goes on; [`RecursiveReport::problems`] then lists
/// what remains. Cancellation, a lost connection or a timeout stop it
/// ([`RecursiveReport::stopped`]).
pub async fn delete_recursive(
    backend: &mut dyn Backend,
    targets: Vec<Target>,
    mut opts: WalkOptions,
    cancel: &CancellationToken,
) -> RecursiveReport {
    opts.follow_symlinks = false;
    let mut walker = Walker::with_operation(targets, opts, RecursiveOperation::Delete);
    let mut report = RecursiveReport::default();
    loop {
        let event = match walker.next(backend, cancel).await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                report.stopped = Some(e);
                break;
            }
        };
        let (path, is_dir) = match event {
            WalkEvent::File { path, .. } | WalkEvent::Symlink { path, .. } => (path, false),
            WalkEvent::EnterDir { .. } => continue,
            WalkEvent::LeaveDir {
                path,
                complete,
                error,
                ..
            } => {
                if !complete {
                    let reason = error.unwrap_or_else(|| "not empty: entries inside remain".into());
                    report.problem(path, reason);
                    walker.mark_incomplete();
                    continue;
                }
                (path, true)
            }
        };
        let timeout = walker.options().timeout;
        let result = if is_dir {
            timed(timeout, cancel, backend.rmdir(&path)).await
        } else {
            timed(timeout, cancel, backend.remove_file(&path)).await
        };
        match result {
            Ok(()) => {
                walker.count_done();
                if is_dir {
                    report.dirs += 1;
                } else {
                    report.files += 1;
                }
                if let Some(cache) = &walker.options().cache {
                    let server = backend.address();
                    let session = walker.options().session;
                    if is_dir {
                        cache.invalidate_subtree(server, &path);
                    }
                    cache.remove_entry(session, server, &path);
                }
            }
            Err(e) => {
                let fatal = is_fatal(&e);
                walker.mark_incomplete();
                report.problem(path, e.to_string());
                if fatal {
                    report.stopped = Some(e);
                    break;
                }
            }
        }
    }
    reporter_log(
        &walker,
        if report.is_complete() {
            LogKind::Status
        } else {
            LogKind::Error
        },
        format!(
            "Deleted {} files and {} directories{}{}",
            group_thousands(report.files),
            group_thousands(report.dirs),
            remaining_text(report.problem_count),
            stopped_text(report.stopped.as_ref()),
        ),
    );
    report.walk = walker.into_summary();
    report
}

/// Change the permissions of `targets` (and, with
/// [`ChmodSpec::recurse`], everything below them) per `spec`.
///
/// [`ApplyTo`] is honoured for the selected entries too. Symlinks are left
/// alone (changing them would change their target, possibly outside the
/// tree). Entries whose current permissions are unknown are left alone
/// unless the mask covers all rwx bits. A directory is changed before its
/// contents are listed, unless the new mode takes away the owner's read or
/// execute bit; then after (so it can still be listed). Failures are
/// recorded and the rest goes on.
pub async fn chmod_recursive(
    backend: &mut dyn Backend,
    targets: Vec<Target>,
    spec: ChmodSpec,
    mut opts: WalkOptions,
    cancel: &CancellationToken,
) -> RecursiveReport {
    let mut report = RecursiveReport::default();
    if !spec.recurse {
        // Only the selection: no listing at all.
        opts.max_depth = 0;
        let mut walker = Walker::with_operation(Vec::new(), opts, RecursiveOperation::Chmod);
        for target in targets {
            if cancel.is_cancelled() {
                report.stopped = Some(Error::Cancelled);
                break;
            }
            let is_dir = target.entry.is_dir_like() && !target.entry.kind.is_symlink();
            if target.entry.kind.is_symlink() || !spec.applies(is_dir) {
                report.unchanged += 1;
                continue;
            }
            if let Err(e) = chmod_one(
                backend,
                &mut walker,
                &mut report,
                &target.path,
                &target.entry,
                spec,
                is_dir,
                cancel,
            )
            .await
            {
                report.stopped = Some(e);
                break;
            }
        }
        finish_chmod(&walker, &report);
        report.walk = walker.into_summary();
        return report;
    }
    opts.follow_symlinks = false;
    let mut walker = Walker::with_operation(targets, opts, RecursiveOperation::Chmod);
    loop {
        let event = match walker.next(backend, cancel).await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                report.stopped = Some(e);
                break;
            }
        };
        let (path, entry, is_dir) = match event {
            WalkEvent::Symlink { .. } => {
                report.unchanged += 1;
                continue;
            }
            WalkEvent::File { path, entry } => (path, entry, false),
            WalkEvent::EnterDir { path, entry } => {
                if !dir_first(spec, &entry) {
                    continue;
                }
                (path, entry, true)
            }
            WalkEvent::LeaveDir { path, entry, .. } => {
                if dir_first(spec, &entry) {
                    continue;
                }
                (path, entry, true)
            }
        };
        if !spec.applies(is_dir) {
            report.unchanged += 1;
            continue;
        }
        if let Err(e) = chmod_one(
            backend,
            &mut walker,
            &mut report,
            &path,
            &entry,
            spec,
            is_dir,
            cancel,
        )
        .await
        {
            report.stopped = Some(e);
            break;
        }
    }
    finish_chmod(&walker, &report);
    report.walk = walker.into_summary();
    report
}

/// Change a directory before listing it (pre-order) unless the new mode
/// takes away the owner's read or execute bit.
fn dir_first(spec: ChmodSpec, entry: &Entry) -> bool {
    if !spec.applies(true) {
        return true;
    }
    let old = entry.permissions.as_ref().and_then(Permissions::bits);
    spec.compute(old).is_none_or(|new| new & 0o500 == 0o500)
}

/// chmod one entry; `Err` only for an error that stops everything.
#[allow(clippy::too_many_arguments)]
async fn chmod_one(
    backend: &mut dyn Backend,
    walker: &mut Walker,
    report: &mut RecursiveReport,
    path: &RemotePath,
    entry: &Entry,
    spec: ChmodSpec,
    is_dir: bool,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let timeout = walker.options().timeout;
    let mut old_mode = entry.permissions.as_ref().and_then(|p| p.mode);
    if old_mode.is_none() && spec.mask & 0o777 != 0o777 {
        // Not in the listing (e.g. a selected entry built by hand): ask.
        match timed(timeout, cancel, backend.stat(path)).await {
            Ok(e) => old_mode = e.permissions.and_then(|p| p.mode),
            Err(e) if is_fatal(&e) => return Err(e),
            Err(_) => {}
        }
    }
    let Some(new) = spec.compute(old_mode.map(|m| m & 0o7777)) else {
        report.unchanged += 1;
        report.problem(path.clone(), "current permissions unknown; left unchanged");
        return Ok(());
    };
    if old_mode.map(|m| m & 0o7777) == Some(new) {
        report.unchanged += 1;
        return Ok(());
    }
    match timed(timeout, cancel, backend.chmod(path, new)).await {
        Ok(()) => {
            walker.count_done();
            if is_dir {
                report.dirs += 1;
            } else {
                report.files += 1;
            }
            if let Some(cache) = &walker.options().cache {
                let full = old_mode.map_or(new, |m| (m & !0o7777) | new);
                cache.set_permissions(
                    walker.options().session,
                    backend.address(),
                    path,
                    Permissions::from_mode(full),
                );
            }
            Ok(())
        }
        Err(e) if is_fatal(&e) => {
            report.problem(path.clone(), e.to_string());
            Err(e)
        }
        Err(e) => {
            report.problem(path.clone(), e.to_string());
            Ok(())
        }
    }
}

fn finish_chmod(walker: &Walker, report: &RecursiveReport) {
    reporter_log(
        walker,
        if report.is_complete() {
            LogKind::Status
        } else {
            LogKind::Error
        },
        format!(
            "Changed permissions of {} files and {} directories{}{}",
            group_thousands(report.files),
            group_thousands(report.dirs),
            if report.problem_count > 0 {
                format!("; {} problems", group_thousands(report.problem_count))
            } else {
                String::new()
            },
            stopped_text(report.stopped.as_ref()),
        ),
    );
}

fn reporter_log(walker: &Walker, kind: LogKind, text: String) {
    if let Some(events) = &walker.options().events {
        events.log(walker.options().session, kind, text);
    }
}

fn remaining_text(n: u64) -> String {
    if n == 0 {
        String::new()
    } else {
        format!("; {} entries remain", group_thousands(n))
    }
}

fn stopped_text(stopped: Option<&Error>) -> String {
    match stopped {
        None => String::new(),
        Some(Error::Cancelled) => " (cancelled)".into(),
        Some(e) => format!(" (stopped: {e})"),
    }
}
