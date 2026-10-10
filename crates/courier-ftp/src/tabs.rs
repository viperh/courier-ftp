//! Connection tabs (T50 creates the id; T55 adds `TabRoute`, T53/T61 extend it).

use serde::{Deserialize, Serialize};

/// A tab. Before T61 the only tab is `TabId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct TabId(pub u32);

impl TabId {
    /// The first (and before T61 the only) tab.
    pub(crate) const FIRST: Self = Self(0);
}
