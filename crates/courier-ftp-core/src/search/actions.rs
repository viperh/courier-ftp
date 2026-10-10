//! Helpers for the result actions of the search UI (T65): queue downloads or
//! uploads of selected results, keeping the directory structure or
//! flattening it, and delete selected results.

use std::collections::HashSet;

use tokio_util::sync::CancellationToken;

use super::SearchHit;
use crate::{
    backend::Backend,
    local::{remote_to_local, sanitize_local_name},
    model::{Direction, LocalPath, RemotePath},
    queue::{NewItem, QueueServer},
    transfer::recursive::{
        RecursiveReport, Target, WalkOptions, delete_recursive, dir_placeholder,
    },
};

/// Where transferred results go below the target directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ResultLayout {
    /// Recreate each result's path relative to the search root
    /// (`root/a/b.txt` → `target/a/b.txt`).
    #[default]
    KeepStructure,
    /// Put every result directly in the target directory; a name already
    /// taken by another selected result becomes `name (2).ext`, `name (3).ext`…
    /// (compared case-insensitively, so it is safe on every filesystem).
    Flatten,
}

/// Queue items downloading the selected `hits` of a remote search under
/// `root` into `target`. Directory hits become directory placeholders
/// (downloaded recursively by the transfer engine); hits inside a selected
/// directory are left out, since the directory brings them. With
/// `replace_invalid`, characters the local filesystem can't store are
/// replaced (`transfers.replace_invalid_chars`).
pub fn download_items(
    server: &QueueServer,
    root: &RemotePath,
    hits: &[SearchHit],
    target: &LocalPath,
    layout: ResultLayout,
    replace_invalid: Option<char>,
) -> Vec<NewItem> {
    plan(root, hits, layout)
        .into_iter()
        .map(|(hit, rel)| {
            let mut local = target.clone();
            for c in &rel {
                local = match replace_invalid {
                    Some(r) => local.join(sanitize_local_name(c, r)),
                    None => local.join(c),
                };
            }
            item(server, Direction::Download, local, hit.path.clone(), hit)
        })
        .collect()
}

/// Queue items uploading the selected `hits` of a local search under `root`
/// (from [`SearchQuery::walk_root`](super::SearchQuery::walk_root)) to the
/// remote directory `target`. Same rules as [`download_items`]; a hit whose
/// name the server path can't hold is left out.
pub fn upload_items(
    server: &QueueServer,
    root: &RemotePath,
    hits: &[SearchHit],
    target: &RemotePath,
    layout: ResultLayout,
) -> Vec<NewItem> {
    plan(root, hits, layout)
        .into_iter()
        .filter_map(|(hit, rel)| {
            let local = remote_to_local(&hit.path)?;
            let mut remote = target.clone();
            for c in &rel {
                remote = remote.join(c).ok()?;
            }
            Some(item(
                server,
                Direction::Upload,
                LocalPath::new(local),
                remote,
                hit,
            ))
        })
        .collect()
}

fn item(
    server: &QueueServer,
    direction: Direction,
    local: LocalPath,
    remote: RemotePath,
    hit: &SearchHit,
) -> NewItem {
    if hit.is_dir() {
        dir_placeholder(server.clone(), direction, local, remote)
    } else {
        NewItem::file(server.clone(), direction, local, remote, hit.entry.size)
    }
}

/// Each selected hit not inside another selected directory, with its
/// destination path components below the target.
fn plan<'a>(
    root: &RemotePath,
    hits: &'a [SearchHit],
    layout: ResultLayout,
) -> Vec<(&'a SearchHit, Vec<String>)> {
    let mut taken = HashSet::new();
    without_nested(hits)
        .into_iter()
        .map(|hit| {
            let rel = match layout {
                ResultLayout::KeepStructure => match hit.relative(root) {
                    Some(rel) => rel.split('/').map(str::to_owned).collect(),
                    // Not below the root: keep just the name.
                    None => vec![hit.entry.name.clone()],
                },
                ResultLayout::Flatten => vec![unique_name(&hit.entry.name, &mut taken)],
            };
            (hit, rel)
        })
        .collect()
}

/// `name`, or `name (n).ext` with the smallest free `n ≥ 2`; records it.
fn unique_name(name: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(name.to_lowercase()) {
        return name.to_owned();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    (2u64..)
        .map(|n| format!("{stem} ({n}){ext}"))
        .find(|candidate| taken.insert(candidate.to_lowercase()))
        .unwrap_or_else(|| name.to_owned())
}

/// The hits, in order and without duplicates, leaving out those below a
/// selected directory.
fn without_nested(hits: &[SearchHit]) -> Vec<&SearchHit> {
    let dirs: Vec<&RemotePath> = hits
        .iter()
        .filter(|h| h.is_dir())
        .map(|h| &h.path)
        .collect();
    let mut seen = HashSet::new();
    hits.iter()
        .filter(|h| !dirs.iter().any(|d| **d != h.path && h.path.starts_with(d)))
        .filter(|h| seen.insert(h.path.clone()))
        .collect()
}

/// The selected hits as [`Target`]s for
/// [`delete_recursive`], leaving out those inside a selected directory.
pub fn delete_targets(hits: &[SearchHit]) -> Vec<Target> {
    without_nested(hits)
        .into_iter()
        .map(|h| Target::new(h.path.clone(), h.entry.clone()))
        .collect()
}

/// Delete the selected hits (directories with everything in them) on
/// `backend`, a session of the searched side. Pass the tab's listing cache
/// in `opts.cache` so the panes are patched. The UI confirms first.
pub async fn delete_results(
    backend: &mut dyn Backend,
    hits: &[SearchHit],
    opts: WalkOptions,
    cancel: &CancellationToken,
) -> RecursiveReport {
    delete_recursive(backend, delete_targets(hits), opts, cancel).await
}
