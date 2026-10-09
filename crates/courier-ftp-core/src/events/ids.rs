//! Process-local identifiers carried by events (T04).

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// One connection/session (a tab's browsing session, a transfer worker, a search
/// session). Process-local, never persisted. `0` ([`SessionId::APP`]) is the
/// application itself (vault, config, sync).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_PROMPT: AtomicU64 = AtomicU64::new(1);

impl SessionId {
    /// The application itself (vault, config, sync).
    pub const APP: SessionId = SessionId(0);

    /// The next id from a process-wide counter starting at 1.
    pub fn next() -> Self {
        Self(NEXT_SESSION.fetch_add(1, Ordering::Relaxed))
    }

    /// The raw value (for display, e.g. `[s3]` in the session log file, T71).
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Queue item id. Assigned by the queue (T40), which reuses this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TransferId(pub u64);

/// A long-running non-transfer operation (recursive delete/chmod, search, import).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(pub u64);

impl OperationId {
    /// The next id from a process-wide counter starting at 1.
    pub fn next() -> Self {
        Self(NEXT_OPERATION.fetch_add(1, Ordering::Relaxed))
    }
}

/// Identifies one prompt; assigned by [`EventSender`](super::EventSender) from a
/// process-wide counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PromptId(u64);

impl PromptId {
    pub(crate) fn next() -> Self {
        Self(NEXT_PROMPT.fetch_add(1, Ordering::Relaxed))
    }

    /// The raw value.
    pub fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_nonzero() {
        let a = SessionId::next();
        let b = SessionId::next();
        assert_ne!(a, b);
        assert_ne!(a, SessionId::APP);
        assert_eq!(SessionId::APP.get(), 0);
        assert_ne!(OperationId::next(), OperationId::next());
        assert_ne!(PromptId::next(), PromptId::next());
    }
}
