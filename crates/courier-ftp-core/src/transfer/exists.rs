//! The file-exists policy (T42): what to do when a transfer's target
//! already exists.
//!
//! - [`decide`] is the pure rule for one [`ExistsAction`]: overwrite (create,
//!   truncate), resume at an offset, skip, rename, or ask the user.
//! - [`FileExistsPolicy`] is the engine's [`ExistsPolicy`]: it picks the
//!   action (the item's own `on_exists`, else a remembered answer, else the
//!   `on_exists_download` / `on_exists_upload` setting), applies [`decide`],
//!   and asks through the event bus ([`PromptKind::FileExists`]) when that
//!   says so.
//! - Answers can be remembered ([`ApplyTo`]) for the current queue run or
//!   the session, optionally only for the same direction and/or server.
//!   Only one file-exists prompt is out at a time: concurrent workers that
//!   need to ask wait for it, then use a remembered answer when one now
//!   applies. Other workers keep transferring meanwhile.
//! - Renaming picks the first free `name (1).ext`, `name (2).ext`, … in the
//!   target directory ([`first_free_name`], called by the worker) and opens
//!   it with [`WriteMode::Create`], so it never overwrites.

use std::{cmp::Ordering, sync::Mutex, time::Duration};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::hooks::{ExistsContext, ExistsDecision, ExistsPolicy};
use crate::{
    Error, Result,
    backend::{Backend, WriteMode},
    events::{
        ApplyTo, EventSender, FileExistsAnswer, LogKind, PromptKind, PromptResponse, SessionId,
    },
    model::{Direction, Entry, EntryKind, RemotePath},
    queue::ServerKey,
    settings::ExistsAction,
};

/// What [`decide`] says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Transfer with this write mode: [`WriteMode::Create`] (no target),
    /// [`WriteMode::Truncate`] (overwrite) or [`WriteMode::ResumeAt`].
    Transfer {
        /// How the target is opened.
        mode: WriteMode,
    },
    /// Leave the target alone.
    Skip,
    /// Write to the first free `name (n).ext` instead.
    Rename,
    /// The user has to choose.
    AskUser,
}

/// Whether `source` is newer than `target`, compared at the coarser of the
/// two precisions; equal is not newer. `None` when a time is unknown.
pub fn is_newer(source: &Entry, target: &Entry) -> Option<bool> {
    let (s, t) = (source.modified.as_ref()?, target.modified.as_ref()?);
    Some(s.cmp_coarse(t) == Ordering::Greater)
}

/// Whether the sizes differ. `None` when a size is unknown.
pub fn size_differs(source: &Entry, target: &Entry) -> Option<bool> {
    Some(source.size? != target.size?)
}

/// What to do with `target` (`None`: it doesn't exist) for `action`.
/// `can_resume`: both sides support resuming and the transfer is binary.
///
/// - No target: `Create`, whatever the action.
/// - *Overwrite if newer / size differs / either*: overwrite when the
///   condition holds, skip when it is known not to, overwrite when a time
///   or size it needs is unknown (as FileZilla does).
/// - *Resume*: resume at the target's size when it is smaller than the
///   source (overwrite when resuming isn't possible or the target is
///   empty), skip when it is at least as large ("already complete"), ask
///   when a size is unknown.
pub fn decide(
    source: &Entry,
    target: Option<&Entry>,
    action: ExistsAction,
    can_resume: bool,
) -> Decision {
    const OVERWRITE: Decision = Decision::Transfer {
        mode: WriteMode::Truncate,
    };
    let Some(target) = target else {
        return Decision::Transfer {
            mode: WriteMode::Create,
        };
    };
    let overwrite_if = |cond: Option<bool>| match cond {
        Some(false) => Decision::Skip,
        Some(true) | None => OVERWRITE,
    };
    match action {
        ExistsAction::Ask => Decision::AskUser,
        ExistsAction::Overwrite => OVERWRITE,
        ExistsAction::OverwriteIfNewer => overwrite_if(is_newer(source, target)),
        ExistsAction::OverwriteIfSizeDiffers => overwrite_if(size_differs(source, target)),
        ExistsAction::OverwriteIfNewerOrSizeDiffers => {
            match (is_newer(source, target), size_differs(source, target)) {
                (Some(true), _) | (_, Some(true)) => OVERWRITE,
                (Some(false), Some(false)) => Decision::Skip,
                _ => OVERWRITE,
            }
        }
        ExistsAction::Resume => match (source.size, target.size) {
            (Some(s), Some(t)) if t >= s => Decision::Skip,
            (Some(_), Some(0)) => OVERWRITE,
            (Some(_), Some(t)) if can_resume => Decision::Transfer {
                mode: WriteMode::ResumeAt(t),
            },
            (Some(_), Some(_)) => OVERWRITE,
            _ => Decision::AskUser,
        },
        ExistsAction::Rename => Decision::Rename,
        ExistsAction::Skip => Decision::Skip,
    }
}

/// `name` with ` (n)` before its extension: `a.txt` → `a (2).txt`,
/// `.bashrc` → `.bashrc (2)`, `archive` → `archive (2)`.
pub fn numbered_name(name: &str, n: u32) -> String {
    match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{} ({n}){}", &name[..dot], &name[dot..]),
        _ => format!("{name} ({n})"),
    }
}

/// How many numbered names [`first_free_name`] tries.
pub const MAX_RENAME_ATTEMPTS: u32 = 1000;

/// The first of `name`, `name (1).ext`, `name (2).ext`, … that doesn't exist
/// in `dir` on `backend` (checked with `stat`; anything but "not found"
/// counts as taken or fails). Every `stat` has `timeout` and races `cancel`.
pub async fn first_free_name(
    backend: &mut dyn Backend,
    dir: &RemotePath,
    name: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<String> {
    for n in 0..=MAX_RENAME_ATTEMPTS {
        let candidate = if n == 0 {
            name.to_owned()
        } else {
            numbered_name(name, n)
        };
        let path = dir.join(&candidate)?;
        let stat = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Error::Cancelled),
            r = tokio::time::timeout(timeout, backend.stat(&path)) => r.unwrap_or(Err(Error::Timeout)),
        };
        match stat {
            Err(Error::NotFound(_)) => return Ok(candidate),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::AlreadyExists)
}

/// A remembered "apply to all" answer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    action: ExistsAction,
    scope: ApplyTo,
    direction: Option<Direction>,
    server: Option<ServerKey>,
}

impl Rule {
    fn matches(&self, direction: Direction, server: &ServerKey) -> bool {
        self.direction.is_none_or(|d| d == direction)
            && self.server.as_ref().is_none_or(|s| s == server)
    }
}

/// The engine's file-exists policy; see the module docs.
///
/// One instance lives as long as the engine (the session): answers with
/// [`ApplyTo::AllInSession`] are kept until it is dropped, answers with
/// [`ApplyTo::AllInQueue`] until the engine reports the queue run finished
/// ([`ExistsPolicy::queue_finished`]).
pub struct FileExistsPolicy {
    events: EventSender,
    log_session: SessionId,
    rules: Mutex<Vec<Rule>>,
    /// Held while a file-exists prompt is out.
    asking: tokio::sync::Mutex<()>,
}

impl FileExistsPolicy {
    /// A policy that asks through `events`.
    pub fn new(events: EventSender) -> Self {
        Self {
            events,
            log_session: SessionId::next(),
            rules: Mutex::new(Vec::new()),
            asking: tokio::sync::Mutex::new(()),
        }
    }

    fn rules(&self) -> std::sync::MutexGuard<'_, Vec<Rule>> {
        self.rules.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The newest remembered answer that applies.
    fn remembered(&self, direction: Direction, server: &ServerKey) -> Option<ExistsAction> {
        self.rules()
            .iter()
            .rev()
            .find(|r| r.matches(direction, server))
            .map(|r| r.action)
    }

    /// Remember `answer` (unless it is for this file only).
    fn remember(&self, answer: &FileExistsAnswer, direction: Direction, server: &ServerKey) {
        if answer.apply_to == ApplyTo::Once || answer.action == ExistsAction::Ask {
            return;
        }
        self.rules().push(Rule {
            action: answer.action,
            scope: answer.apply_to,
            direction: answer.same_direction_only.then_some(direction),
            server: answer.same_server_only.then(|| server.clone()),
        });
    }

    /// Forget every remembered answer (e.g. after a settings reset).
    pub fn forget_all(&self) {
        self.rules().clear();
    }

    fn log(&self, text: String) {
        self.events.log(self.log_session, LogKind::Status, text);
    }

    /// Maps a [`Decision`] that isn't `AskUser`, logging skips.
    fn finish(
        &self,
        decision: Decision,
        ctx: &ExistsContext<'_>,
        why: ExistsAction,
    ) -> ExistsDecision {
        match decision {
            Decision::Transfer {
                mode: WriteMode::ResumeAt(offset),
            } => ExistsDecision::Resume { offset },
            Decision::Transfer { .. } => ExistsDecision::Overwrite,
            Decision::Rename => ExistsDecision::Rename {
                name: ctx
                    .target
                    .map_or_else(|| ctx.source.name.clone(), |t| t.name.clone()),
            },
            Decision::Skip | Decision::AskUser => {
                let reason = match why {
                    ExistsAction::Resume => "already complete",
                    ExistsAction::OverwriteIfNewer => "the target is not older",
                    ExistsAction::OverwriteIfSizeDiffers => "same size",
                    ExistsAction::OverwriteIfNewerOrSizeDiffers => "not older and same size",
                    _ => "the target exists",
                };
                self.log(format!("Skipped {}: {reason}", ctx.source.name));
                ExistsDecision::Skip
            }
        }
    }

    /// The decision for the user's answer.
    fn answered(
        &self,
        answer: &FileExistsAnswer,
        ctx: &ExistsContext<'_>,
    ) -> Result<ExistsDecision> {
        if answer.action == ExistsAction::Rename
            && let Some(name) = answer.new_name.as_deref().filter(|n| !n.is_empty())
        {
            if name.contains(['/', '\0'])
                || (cfg!(windows) && name.contains('\\'))
                || name == "."
                || name == ".."
            {
                return Err(Error::InvalidInput(format!("{name:?} is not a file name")));
            }
            return Ok(ExistsDecision::Rename {
                name: name.to_owned(),
            });
        }
        let target = ctx.target;
        match decide(ctx.source, target, answer.action, ctx.can_resume) {
            // The user chose Resume although a size is unknown: resume at the
            // target's size when known, else there is nothing safe to do.
            Decision::AskUser => match (answer.action, target.and_then(|t| t.size)) {
                (ExistsAction::Resume, Some(offset)) if ctx.can_resume && offset > 0 => {
                    Ok(ExistsDecision::Resume { offset })
                }
                (ExistsAction::Resume, Some(_)) => Ok(ExistsDecision::Overwrite),
                _ => Ok(self.finish(Decision::Skip, ctx, answer.action)),
            },
            d => Ok(self.finish(d, ctx, answer.action)),
        }
    }
}

impl std::fmt::Debug for FileExistsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileExistsPolicy")
            .field("rules", &*self.rules())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ExistsPolicy for FileExistsPolicy {
    async fn decide(
        &self,
        ctx: ExistsContext<'_>,
        cancel: &CancellationToken,
    ) -> Result<ExistsDecision> {
        let Some(target) = ctx.target else {
            return Ok(ExistsDecision::Overwrite);
        };
        if matches!(target.kind, EntryKind::Dir) {
            return Err(Error::InvalidInput(format!(
                "{} exists and is a directory",
                target.name
            )));
        }
        let item = ctx.item;
        let direction = item.direction;
        let server = item.server.key();
        let default = match direction {
            Direction::Download => ctx.settings.on_exists_download,
            Direction::Upload => ctx.settings.on_exists_upload,
        };
        let pick = || {
            item.on_exists
                .filter(|a| *a != ExistsAction::Ask)
                .or_else(|| self.remembered(direction, &server))
                .unwrap_or(default)
        };
        let action = pick();
        let decision = decide(ctx.source, Some(target), action, ctx.can_resume);
        if decision != Decision::AskUser {
            return Ok(self.finish(decision, &ctx, action));
        }

        // One prompt at a time; another worker's answer may apply by the time
        // it is our turn.
        let _turn = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Error::Cancelled),
            guard = self.asking.lock() => guard,
        };
        let action = pick();
        let decision = decide(ctx.source, Some(target), action, ctx.can_resume);
        if decision != Decision::AskUser {
            return Ok(self.finish(decision, &ctx, action));
        }
        let kind = PromptKind::FileExists {
            direction,
            source: Box::new(ctx.source.clone()),
            target: Box::new(target.clone()),
            local: item.local.clone(),
            remote: item.remote.clone(),
        };
        match self.events.ask(None, kind, cancel).await {
            Ok(PromptResponse::FileExists(answer)) => {
                self.remember(&answer, direction, &server);
                self.answered(&answer, &ctx)
            }
            // Dismissed without an answer (the transfer itself wasn't
            // cancelled): leave the target alone.
            Ok(_) => Ok(self.finish(Decision::Skip, &ctx, ExistsAction::Skip)),
            Err(Error::Cancelled) if !cancel.is_cancelled() => {
                Ok(self.finish(Decision::Skip, &ctx, ExistsAction::Skip))
            }
            Err(e) => Err(e),
        }
    }

    fn queue_finished(&self) {
        self.rules().retain(|r| r.scope == ApplyTo::AllInSession);
    }
}

#[cfg(test)]
#[path = "exists_tests.rs"]
mod tests;
