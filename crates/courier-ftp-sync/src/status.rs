//! What the engine tells the UI: the sync status for the status bar, and
//! events (applied remote changes, toasts, item errors). T90 bridges them into
//! the UI's event loop (T04).

use std::fmt;

use courier_ftp_core::model::item::{ItemId, VaultId};

/// The sync status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Everything is pushed and the last pull succeeded.
    Synced,
    /// A sync cycle is running.
    Syncing,
    /// The server is unreachable; `pending` local changes are queued
    /// (offline edits stay queued indefinitely).
    Offline {
        /// Outbox rows.
        pending: u64,
    },
    /// Something needs attention: a failing request, items that can't be
    /// pushed or decrypted.
    Error(String),
    /// The refresh token was rejected (or the password changed on another
    /// device): sign in again. Sync is paused.
    NeedsLogin,
}

impl SyncStatus {
    /// The status bar segment: `⟳ synced`, `⟳ syncing`, `⟳ offline (3)`,
    /// `⟳ error`, `⟳ login needed`.
    #[must_use]
    pub fn short(&self) -> String {
        match self {
            Self::Synced => "⟳ synced".into(),
            Self::Syncing => "⟳ syncing".into(),
            Self::Offline { pending } => format!("⟳ offline ({pending})"),
            Self::Error(_) => "⟳ error".into(),
            Self::NeedsLogin => "⟳ login needed".into(),
        }
    }
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(message) => write!(f, "sync error: {message}"),
            Self::Offline { pending } => write!(f, "offline ({pending} pending)"),
            other => f.write_str(&other.short()),
        }
    }
}

/// Toast severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    /// Informational (a resurrected item, a merged conflict).
    Info,
    /// Something to look at (clock skew, access revoked).
    Warn,
    /// A change could not be uploaded.
    Error,
}

/// An event for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    /// The status changed.
    Status(SyncStatus),
    /// Remote changes were committed locally (the vault engine's index is
    /// already updated): refresh views showing these items (e.g.
    /// `SiteManager::reload`).
    Applied {
        /// The vault.
        vault: VaultId,
        /// Items written (replaced, merged) or removed, tombstones included.
        items: Vec<ItemId>,
    },
    /// A toast.
    Toast {
        /// Severity.
        level: ToastLevel,
        /// Text.
        message: String,
    },
    /// A stamp from another device was ahead of this clock (once per device
    /// per engine): "Clock skew detected on device X".
    ClockSkew {
        /// The other device (short id).
        device: String,
        /// How far ahead its stamp was.
        ahead_secs: u64,
    },
    /// A local change is held back and kept on this device (read-only
    /// access, too large, kept conflicting, does not decrypt). Shown next to
    /// the item until a later push succeeds.
    ItemError {
        /// The item.
        item: ItemId,
        /// Why.
        message: String,
    },
    /// A synced value that acts on this machine (local key path, SSH agent)
    /// was set or changed remotely: its approval was revoked and the connect
    /// path asks before using it (T91 §8).
    ApprovalNeeded {
        /// The item.
        item: ItemId,
        /// The field.
        field: &'static str,
    },
    /// This account's access to a vault was granted, revoked or its key
    /// rotated (`vault_access`); the vault list was refreshed.
    VaultAccess {
        /// The vault.
        vault: VaultId,
    },
}
