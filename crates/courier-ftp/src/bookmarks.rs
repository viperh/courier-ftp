//! The app's side of the bookmarks menu (T64): the operations the menu asks
//! for, run in background tasks on the Site Manager's vault (the
//! [`SitesSlot`]) and answered with a [`BookmarksReply`], like the Site
//! Manager's [`SiteOp`](crate::sites::SiteOp)s.

use std::sync::Arc;

use courier_ftp_core::{
    model::item::ItemId,
    sites::{Bookmark, Bookmarks, SiteError, SiteManager},
};

use crate::sites::{SitesSlot, Snapshot};

/// An operation the bookmarks menu asks for.
#[derive(Debug, Clone)]
pub(crate) enum BookmarkOp {
    /// Read every bookmark.
    Load,
    /// Add a bookmark at the end of its scope.
    Add(Box<Bookmark>),
    /// Save a changed bookmark (scope and position are kept).
    Edit(Box<Bookmark>),
    Delete(ItemId),
    /// Move a bookmark to `index` within its scope.
    Reorder {
        id: ItemId,
        index: usize,
    },
}

/// How an operation went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BookmarkOutcome {
    Loaded,
    /// Added or saved: select it.
    Saved(ItemId),
    Deleted,
    /// Moved: keep it selected.
    Moved(ItemId),
    Failed(String),
}

/// The answer to a [`BookmarkOp`]: every bookmark as it is now and the
/// Site Manager's tree (its Bookmarks tab lists site bookmarks); both
/// `None` when the vault is locked.
#[derive(Debug, Clone)]
pub(crate) struct BookmarksReply {
    pub(crate) bookmarks: Option<Vec<Bookmark>>,
    pub(crate) sites: Option<Snapshot>,
    pub(crate) outcome: BookmarkOutcome,
}

/// Runs `op` on the bookmarks of the vault behind `slot`.
pub(crate) async fn run(slot: &SitesSlot, op: BookmarkOp) -> BookmarksReply {
    let guard = slot.lock().await;
    let Some(sites) = guard.as_ref() else {
        return BookmarksReply {
            bookmarks: None,
            sites: None,
            outcome: BookmarkOutcome::Failed("The vault is locked".to_owned()),
        };
    };
    let mut all = match load(sites).await {
        Ok(all) => all,
        Err(e) => {
            return BookmarksReply {
                bookmarks: None,
                sites: None,
                outcome: BookmarkOutcome::Failed(format!("Could not load the bookmarks: {e}")),
            };
        }
    };
    let outcome = match apply(&mut all, op).await {
        Ok(outcome) => outcome,
        Err(e) => {
            // A failed write may have changed part of the scope (reorder).
            if let Err(e) = all.reload().await {
                tracing::debug!(error = %e, "bookmarks not reloaded");
            }
            BookmarkOutcome::Failed(e.to_string())
        }
    };
    let changed = !matches!(outcome, BookmarkOutcome::Loaded);
    BookmarksReply {
        bookmarks: Some(all.all().to_vec()),
        sites: if changed {
            Some(crate::sites::snapshot(sites).await)
        } else {
            None
        },
        outcome,
    }
}

async fn load(sites: &SiteManager) -> Result<Bookmarks, SiteError> {
    Bookmarks::load(Arc::clone(sites.vault()), Arc::clone(sites.local_store())).await
}

async fn apply(all: &mut Bookmarks, op: BookmarkOp) -> Result<BookmarkOutcome, SiteError> {
    Ok(match op {
        BookmarkOp::Load => BookmarkOutcome::Loaded,
        BookmarkOp::Add(b) => BookmarkOutcome::Saved(all.add(*b).await?),
        BookmarkOp::Edit(b) => {
            let id = b.id;
            all.edit(*b).await?;
            BookmarkOutcome::Saved(id)
        }
        BookmarkOp::Delete(id) => {
            all.delete(id).await?;
            BookmarkOutcome::Deleted
        }
        BookmarkOp::Reorder { id, index } => {
            all.reorder(id, index).await?;
            BookmarkOutcome::Moved(id)
        }
    })
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::{
        model::{LocalPath, Protocol, RemotePath},
        sites::{MemSiteLocalStore, Site, SiteLogon},
        vault::MemItemVault,
    };
    use pretty_assertions::assert_eq;

    use super::*;

    fn names(reply: &BookmarksReply) -> Vec<String> {
        reply
            .bookmarks
            .as_ref()
            .unwrap()
            .iter()
            .map(|b| b.name.clone())
            .collect()
    }

    #[tokio::test]
    async fn add_edit_reorder_delete_and_locked() {
        let mut sites = SiteManager::load(
            Arc::new(MemItemVault::unlocked()),
            Arc::new(MemSiteLocalStore::new()),
        )
        .await
        .unwrap();
        let mut site = Site::new("web", Protocol::Sftp, "web.example.com");
        site.logon = SiteLogon::Normal {
            user: "deploy".into(),
            password: None,
        };
        let site_id = site.id;
        sites.save_site(site).await.unwrap();
        let slot: SitesSlot = Arc::new(tokio::sync::Mutex::new(Some(sites)));

        let mut a = Bookmark::global("a");
        a.local_dir = Some(LocalPath::new("/tmp"));
        let reply = run(&slot, BookmarkOp::Add(Box::new(a.clone()))).await;
        assert_eq!(reply.outcome, BookmarkOutcome::Saved(a.id));
        let b = Bookmark::global("b");
        let mut b = Bookmark {
            remote_dir: Some(RemotePath::new("/srv")),
            ..b
        };
        run(&slot, BookmarkOp::Add(Box::new(b.clone()))).await;
        let s = Bookmark::for_site(site_id, "logs", RemotePath::new("/var/log"));
        let reply = run(&slot, BookmarkOp::Add(Box::new(s.clone()))).await;
        assert_eq!(names(&reply), ["a", "b", "logs"]);
        // The Site Manager's tree comes back with the site's bookmark.
        let snapshot = reply.sites.unwrap();
        assert_eq!(snapshot.bookmarks.get(&site_id).unwrap(), &["logs"]);

        // A clash is refused and nothing changes.
        let reply = run(&slot, BookmarkOp::Add(Box::new(Bookmark::global("A")))).await;
        assert!(matches!(reply.outcome, BookmarkOutcome::Failed(_)));
        assert_eq!(names(&reply), ["a", "b", "logs"]);

        b.name = "bee".into();
        run(&slot, BookmarkOp::Edit(Box::new(b.clone()))).await;
        let reply = run(&slot, BookmarkOp::Reorder { id: b.id, index: 0 }).await;
        assert_eq!(reply.outcome, BookmarkOutcome::Moved(b.id));
        assert_eq!(names(&reply), ["bee", "a", "logs"]);
        let reply = run(&slot, BookmarkOp::Delete(a.id)).await;
        assert_eq!(names(&reply), ["bee", "logs"]);
        let reply = run(&slot, BookmarkOp::Load).await;
        assert_eq!(reply.outcome, BookmarkOutcome::Loaded);
        assert!(reply.sites.is_none());

        *slot.lock().await = None;
        let reply = run(&slot, BookmarkOp::Load).await;
        assert!(reply.bookmarks.is_none());
        assert!(matches!(reply.outcome, BookmarkOutcome::Failed(_)));
    }
}
