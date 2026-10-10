//! Connection tabs (T50 creates the id; T55 adds `TabRoute`, T53/T61 extend it).

use serde::{Deserialize, Serialize};

/// A tab. Before T61 the only tab is `TabId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct TabId(pub u32);

impl TabId {
    /// The first (and before T61 the only) tab.
    pub(crate) const FIRST: Self = Self(0);
}

/// How the message log routes lines to a tab (T55; T53 and T61 set it): the tab's
/// browsing session and the identity of the server it shows. Transfer and keep-alive
/// sessions of the same server reach the tab through `server`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TabRoute {
    /// The tab's browsing session.
    pub browsing: Option<courier_ftp_core::events::SessionId>,
    /// The server the tab shows.
    pub server: Option<crate::components::message_log::ServerKey>,
}
