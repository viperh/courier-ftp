//! Focusable regions and how focus moves between them (T50).

use super::{Side, layout::Regions};

/// A region that can have keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Region {
    Quickconnect,
    LocalTree,
    LocalList,
    RemoteTree,
    RemoteList,
    Log,
    Queue,
}

impl Region {
    /// The file list of a side.
    pub(crate) fn list(side: Side) -> Self {
        match side {
            Side::Local => Region::LocalList,
            Side::Remote => Region::RemoteList,
        }
    }

    /// The side a pane region belongs to.
    pub(crate) fn side(self) -> Option<Side> {
        match self {
            Region::LocalTree | Region::LocalList => Some(Side::Local),
            Region::RemoteTree | Region::RemoteList => Some(Side::Remote),
            _ => None,
        }
    }

    /// `Tab` / `Shift-Tab`: from one side's pane to the other side's list;
    /// from anywhere else back to the local list (Midnight Commander style).
    pub(crate) fn toggled(self) -> Self {
        match self.side() {
            Some(side) => Region::list(side.other()),
            None => Region::LocalList,
        }
    }

    /// Whether the region is on screen.
    pub(crate) fn visible_in(self, r: &Regions) -> bool {
        match self {
            Region::Quickconnect => r.quickconnect.is_some(),
            Region::LocalTree => r.local_tree.is_some(),
            Region::LocalList => r.local_list.is_some(),
            Region::RemoteTree => r.remote_tree.is_some(),
            Region::RemoteList => r.remote_list.is_some(),
            Region::Log => r.log.is_some(),
            Region::Queue => r.queue.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn tab_switches_between_the_lists() {
        assert_eq!(Region::LocalList.toggled(), Region::RemoteList);
        assert_eq!(Region::RemoteList.toggled(), Region::LocalList);
        assert_eq!(Region::LocalTree.toggled(), Region::RemoteList);
        assert_eq!(Region::RemoteTree.toggled(), Region::LocalList);
        assert_eq!(Region::Log.toggled(), Region::LocalList);
        assert_eq!(Region::Queue.toggled(), Region::LocalList);
        assert_eq!(Region::Quickconnect.toggled(), Region::LocalList);
    }
}
