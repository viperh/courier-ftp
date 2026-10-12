//! Recursive operations (T43): directories expanded into individual
//! transfers, deletes and permission changes — lazily, cancellably, with the
//! filters (T47) applied (FEATURES.md §4, §5, §6, §8).
//!
//! # Pieces
//!
//! - [`Walker`]: an async, depth-first walk over any [`Backend`](crate::backend::Backend), local or
//!   remote. It holds only the listings of the directories on the current
//!   path (bounded memory, never the whole tree), yields
//!   [`WalkEvent`]s pre-order (`EnterDir`, `File`, `Symlink`) and post-order
//!   (`LeaveDir`), applies a [`FilterEngine`](crate::filters::FilterEngine), skips subdirectories it cannot
//!   list (logged, listed in the [`WalkSummary`]), stops at
//!   [`WalkOptions::max_depth`] and detects symlink loops when it follows
//!   links ([`LoopCheck`]). Progress goes to the message log ("Listing /a/b …
//!   1 234 files found") and as [`CoreEvent::RecursiveProgress`](crate::events::CoreEvent::RecursiveProgress) for the
//!   status bar.
//! - [`RecursiveExpander`]: the engine's [`DirExpander`](super::DirExpander)
//!   hook. A selected directory is queued as one placeholder
//!   ([`dir_placeholder`]); when the engine reaches it, the expander lists
//!   that one level and the placeholder is replaced in place by the files
//!   and by one placeholder per subdirectory (FileZilla's lazy recursion,
//!   so the queue stays fast for huge trees). It creates target directories
//!   as needed (see [`EmptyDirs`](crate::settings::EmptyDirs)) and never
//!   queues filtered entries.
//! - [`delete_recursive`]: post-order `remove_file` then `rmdir`; never
//!   follows symlinks (a link is removed, not its target). Entries it could
//!   not remove, and the directories above them, are reported.
//! - [`chmod_recursive`]: FileZilla's chmod dialog — recurse or not, apply
//!   to all / files only / directories only ([`ApplyTo`]), and per-bit
//!   "leave unchanged" ([`ChmodSpec`]: `(old & !mask) | (new & mask)`).
//!   Symlinks are left alone (chmod would change their target).
//!
//! Filtered-out entries are left untouched by every operation: a filtered
//! directory is neither descended, deleted nor changed.
//!
//! # For the file operations UI (T62)
//!
//! T62 asks for confirmation, then runs [`delete_recursive`] /
//! [`chmod_recursive`] in a background task with a [`CancellationToken`]
//! and the selected entries as [`Target`]s. The functions take a
//! `&mut dyn Backend`: lock the tab's
//! [`SessionHandle`](crate::backend::SessionHandle) for small selections,
//! or open a dedicated session for big trees so browsing stays responsive.
//! Pass the tab's [`ListingCache`](crate::cache::ListingCache) in
//! [`WalkOptions::cache`] so the panes are patched as entries disappear or
//! change. The returned [`RecursiveReport`] lists what was not done.

mod expand;
mod ops;
mod walk;

#[cfg(test)]
mod tests;

use std::{future::Future, time::Duration};

pub use expand::{RecursiveExpander, dir_placeholder};
pub use ops::{ApplyTo, ChmodSpec, apply_mask, chmod_recursive, delete_recursive};
use tokio_util::sync::CancellationToken;
pub use walk::{
    LoopCheck, MAX_REPORTED, Problem, RecursiveReport, Target, WalkEvent, WalkOptions, WalkSummary,
    Walker,
};

use crate::{Error, Result};

/// Default depth limit (directory levels below a selected entry).
pub const DEFAULT_MAX_DEPTH: usize = 256;

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

/// Errors that end a whole recursive operation instead of skipping one
/// entry: cancellation, a lost connection, a timeout (the session is
/// probably hung).
fn is_fatal(err: &Error) -> bool {
    matches!(
        err,
        Error::Cancelled | Error::Connection(_) | Error::Timeout
    )
}

/// `1234567` as `1 234 567`.
fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}
