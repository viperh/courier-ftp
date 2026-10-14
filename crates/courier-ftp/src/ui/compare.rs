//! Directory comparison and synchronized browsing (T66), as FileZilla's.
//!
//! The comparison itself is the core's ([`courier_ftp_core::compare`]); this
//! module holds the state the main screen keeps for it: the synchronized
//! base pair, a directory change waiting for the other side, the comparison
//! options and their dialog.

use courier_ftp_core::{
    compare::{CompareMode, CompareOpts, ComparedListing, compare_with_filters},
    model::RemotePath,
};
use tokio::sync::mpsc::UnboundedSender;

use super::{
    Side,
    dialog::{Checkbox, Form, FormDialog, NumberInput, RadioGroup},
    file_list::{CompareRow, FileList},
    modal::Modal,
};
use crate::action::Action;

/// The other pane.
pub(crate) fn other(side: Side) -> Side {
    match side {
        Side::Local => Side::Remote,
        Side::Remote => Side::Local,
    }
}

/// The directories synchronized browsing started from (L0, R0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncBase {
    pub(crate) local: RemotePath,
    pub(crate) remote: RemotePath,
}

impl SyncBase {
    fn base(&self, side: Side) -> &RemotePath {
        match side {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    /// The directory of the other side that corresponds to `dir` on `side`:
    /// the same path relative to the base. `None` when `dir` is outside
    /// (above) the base of `side`.
    pub(crate) fn map(&self, side: Side, dir: &RemotePath) -> Option<RemotePath> {
        let rel = dir.strip_prefix(self.base(side))?;
        let target = self.base(other(side));
        Some(if rel.is_empty() {
            target.clone()
        } else {
            target.join_path(rel)
        })
    }
}

/// Where a synchronized directory change stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NavStage {
    /// Asking whether to leave the base (and turn sync browsing off).
    AskLeave,
    /// The other pane is listing the target.
    Following,
    /// The target is missing on the other side; asking what to do.
    AskMissing,
    /// The target is being created on the other side.
    Creating,
}

/// A directory change in one pane, held back until the other pane has
/// followed (or the user answered).
#[derive(Debug, Clone)]
pub(crate) struct SyncNav {
    /// The pane the user navigated in.
    pub(crate) lead: Side,
    /// Its [`Action::ListDir`], sent once the other side followed.
    pub(crate) held: Action,
    /// The corresponding directory on the other side.
    pub(crate) target: Option<RemotePath>,
    pub(crate) stage: NavStage,
}

/// The comparison shown in both panes.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompareState {
    pub(crate) listing: ComparedListing,
    /// The panes' generations the listing was built from; `None` forces a
    /// rebuild.
    pub(crate) built_from: Option<(u64, u64)>,
}

impl CompareState {
    /// Compare what the panes show and give both their rows. Returns whether
    /// the sides are filtered differently (filters or hidden files).
    pub(crate) fn rebuild(
        &mut self,
        local: &mut FileList,
        remote: &mut FileList,
        opts: &CompareOpts,
    ) -> bool {
        let left = local.visible_entries();
        let right = remote.visible_entries();
        let listing = compare_with_filters(&left, &right, opts, local.filters(), remote.filters());
        let rows = |pane: &FileList, side: Side| -> Vec<CompareRow> {
            listing
                .rows
                .iter()
                .map(|r| CompareRow {
                    entry: r.index(side).and_then(|i| pane.entry_index(i)),
                    highlight: r.highlight(side),
                })
                .collect()
        };
        let (l, r) = (rows(local, Side::Local), rows(remote, Side::Remote));
        local.set_comparison(Some(l));
        remote.set_comparison(Some(r));
        self.built_from = Some((local.generation(), remote.generation()));
        // Hidden files shown on one side only also make rows "missing".
        let hidden_differ = local.show_hidden() != remote.show_hidden()
            && (local.has_hidden() || remote.has_hidden());
        let differ = listing.filters_differ || hidden_differ;
        self.listing = listing;
        differ
    }

    /// Whether the panes changed since the last rebuild.
    pub(crate) fn stale(&self, local: &FileList, remote: &FileList) -> bool {
        self.built_from != Some((local.generation(), remote.generation()))
            || !local.is_comparing()
            || !remote.is_comparing()
    }
}

/// The comparison options dialog; the result arrives as
/// [`Action::SetCompareOptions`].
pub(crate) fn options_dialog(
    opts: &CompareOpts,
    tx: Option<&UnboundedSender<Action>>,
) -> Box<dyn Modal> {
    let base = opts.clone();
    let form = Form::new(&["OK", "Cancel"])
        .field(
            "mode",
            RadioGroup::new(
                "Compare by",
                vec!["File size".to_owned(), "Modification time".to_owned()],
                usize::from(opts.mode == CompareMode::ModificationTime),
            ),
        )
        .field(
            "threshold",
            NumberInput::new(
                "Time threshold (minutes)",
                i64::from(opts.threshold_minutes),
                0,
                24 * 60,
            ),
        )
        .field(
            "hide",
            Checkbox::new("Hide identical files", opts.hide_identical),
        );
    let (dialog, rx) = FormDialog::new("Directory comparison", 48, form, move |v| {
        Ok(CompareOpts {
            mode: if v.index("mode") == Some(1) {
                CompareMode::ModificationTime
            } else {
                CompareMode::Size
            },
            threshold_minutes: v
                .number("threshold")
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(base.threshold_minutes),
            hide_identical: v.bool("hide"),
            ..base.clone()
        })
    });
    if let Some(tx) = tx.cloned() {
        tokio::spawn(async move {
            if let Ok(Some(opts)) = rx.await {
                let _ = tx.send(Action::SetCompareOptions(Box::new(opts)));
            }
        });
    }
    Box::new(dialog)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn base() -> SyncBase {
        SyncBase {
            local: RemotePath::new("/home/me/site"),
            remote: RemotePath::new("/var/www"),
        }
    }

    #[test]
    fn relative_moves_map_to_the_other_side() {
        let b = base();
        let map = |side, dir: &str| b.map(side, &RemotePath::new(dir)).map(|p| p.to_string());
        assert_eq!(map(Side::Local, "/home/me/site"), Some("/var/www".into()));
        assert_eq!(
            map(Side::Local, "/home/me/site/img/icons"),
            Some("/var/www/img/icons".into())
        );
        assert_eq!(
            map(Side::Remote, "/var/www/css"),
            Some("/home/me/site/css".into())
        );
        // Names with spaces and leading dashes survive.
        assert_eq!(
            map(Side::Remote, "/var/www/my dir/-x"),
            Some("/home/me/site/my dir/-x".into())
        );
    }

    #[test]
    fn leaving_the_base_maps_to_nothing() {
        let b = base();
        let map = |side, dir: &str| b.map(side, &RemotePath::new(dir));
        assert_eq!(map(Side::Local, "/home/me"), None);
        assert_eq!(
            map(Side::Local, "/home/me/site2"),
            None,
            "not a prefix by components"
        );
        assert_eq!(map(Side::Remote, "/"), None);
        assert_eq!(map(Side::Remote, "/etc"), None);
    }

    #[test]
    fn a_root_base_maps_everything() {
        let b = SyncBase {
            local: RemotePath::new("/srv/mirror"),
            remote: RemotePath::root(),
        };
        assert_eq!(
            b.map(Side::Remote, &RemotePath::new("/pub/linux"))
                .map(|p| p.to_string()),
            Some("/srv/mirror/pub/linux".into())
        );
        assert_eq!(
            b.map(Side::Local, &RemotePath::new("/srv/mirror/pub"))
                .map(|p| p.to_string()),
            Some("/pub".into())
        );
    }
}
