//! One queue entry: [`QueueItem`] and its parts.

use std::fmt;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::events::TransferId;
use crate::model::item::ItemId;
use crate::model::{Direction, LocalPath, RemotePath, ServerAddress};
use crate::settings::{ExistsAction, TransferTypeChoice};

/// A saved site, by its vault item id (T31).
pub type SiteId = ItemId;

/// Which server an item transfers to or from.
#[derive(Clone)]
pub enum QueueServer {
    /// A Site Manager entry; credentials come from the vault at connect time.
    Site(SiteId),
    /// A quickconnect server, inline.
    Quick {
        /// Where to connect (with the user, if any).
        address: ServerAddress,
        /// The password typed into the quickconnect bar. `None` = ask for it
        /// when the item runs (e.g. after an import). Kept in memory as a
        /// `SecretString` and only ever persisted inside the encrypted queue
        /// blob; never exported.
        password: Option<SecretString>,
    },
}

impl QueueServer {
    /// The grouping key (no secrets).
    pub fn key(&self) -> ServerKey {
        match self {
            QueueServer::Site(id) => ServerKey::Site(*id),
            QueueServer::Quick { address, .. } => ServerKey::Quick(address.clone()),
        }
    }

    /// A quickconnect server with no password: the engine must ask for one.
    pub fn needs_password(&self) -> bool {
        matches!(self, QueueServer::Quick { password: None, .. })
    }
}

impl fmt::Debug for QueueServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueServer::Site(id) => f.debug_tuple("Site").field(id).finish(),
            QueueServer::Quick { address, password } => f
                .debug_struct("Quick")
                .field("address", address)
                .field("password", &password.as_ref().map(|_| "****"))
                .finish(),
        }
    }
}

impl PartialEq for QueueServer {
    /// Plain (not constant-time) comparison including the password: for tests
    /// and change detection, not authentication.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (QueueServer::Site(a), QueueServer::Site(b)) => a == b,
            (
                QueueServer::Quick {
                    address: a,
                    password: pa,
                },
                QueueServer::Quick {
                    address: b,
                    password: pb,
                },
            ) => {
                a == b
                    && pa.as_ref().map(ExposeSecret::expose_secret)
                        == pb.as_ref().map(ExposeSecret::expose_secret)
            }
            _ => false,
        }
    }
}

/// Identifies a server for grouping queue rows (FileZilla shows a server header
/// above its items). Carries no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerKey {
    /// A saved site.
    Site(SiteId),
    /// A quickconnect address.
    Quick(ServerAddress),
}

/// Scheduling priority: the scheduler takes the highest first, then queue order.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Lowest.
    Lowest,
    /// Low.
    Low,
    /// Normal (the default).
    #[default]
    Normal,
    /// High.
    High,
    /// Highest.
    Highest,
}

impl Priority {
    /// All priorities, lowest first.
    pub const ALL: [Priority; 5] = [
        Priority::Lowest,
        Priority::Low,
        Priority::Normal,
        Priority::High,
        Priority::Highest,
    ];
}

/// Progress of an active transfer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// Bytes of the file done so far (including a resumed offset).
    pub bytes: u64,
}

/// Where an item is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// Waiting to be scheduled.
    Queued,
    /// Being transferred by the engine (T41).
    Active {
        /// How far it got.
        progress: Progress,
    },
    /// Excluded from scheduling until resumed.
    Paused,
    /// Gave up after [`QueueItem::attempts`] attempts; in the failed list.
    Failed {
        /// The last error, for the failed list.
        error: String,
    },
    /// Finished; in the successful list.
    Done {
        /// When it finished.
        #[serde(with = "time::serde::rfc3339")]
        finished_at: OffsetDateTime,
        /// Bytes transferred.
        bytes: u64,
        /// How long it took.
        duration: Duration,
    },
}

impl ItemState {
    /// [`ItemState::Queued`].
    pub fn is_queued(&self) -> bool {
        matches!(self, ItemState::Queued)
    }

    /// [`ItemState::Active`].
    pub fn is_active(&self) -> bool {
        matches!(self, ItemState::Active { .. })
    }
}

/// One transfer in the queue (FEATURES.md §5).
#[derive(Debug, Clone, PartialEq)]
pub struct QueueItem {
    /// Unique within the queue (assigned by [`Queue::add`](super::Queue::add)).
    pub id: TransferId,
    /// The server.
    pub server: QueueServer,
    /// Download or upload.
    pub direction: Direction,
    /// The local file (or directory, for a placeholder).
    pub local: LocalPath,
    /// The remote file (or directory, for a placeholder).
    pub remote: RemotePath,
    /// Size when known (from the listing).
    pub size: Option<u64>,
    /// ASCII/binary choice for FTP.
    pub transfer_type: TransferTypeChoice,
    /// Scheduling priority.
    pub priority: Priority,
    /// Per-item file-exists action, set by "apply to all" (T42); `None` = the
    /// setting.
    pub on_exists: Option<ExistsAction>,
    /// The state.
    pub state: ItemState,
    /// Failed attempts so far (reset by "reset and requeue").
    pub attempts: u8,
    /// When it was queued.
    pub added_at: OffsetDateTime,
    /// A directory to be expanded one level when reached (T43).
    pub is_dir_placeholder: bool,
}

impl QueueItem {
    /// Bytes still to transfer, when the size is known.
    pub fn remaining(&self) -> Option<u64> {
        let size = self.size?;
        let done = match &self.state {
            ItemState::Active { progress } => progress.bytes,
            ItemState::Done { .. } => size,
            _ => 0,
        };
        Some(size.saturating_sub(done))
    }
}

/// What to add: a [`QueueItem`] without the fields the queue fills in (id,
/// state, attempts, added time).
#[derive(Debug, Clone, PartialEq)]
pub struct NewItem {
    /// The server.
    pub server: QueueServer,
    /// Download or upload.
    pub direction: Direction,
    /// The local path.
    pub local: LocalPath,
    /// The remote path.
    pub remote: RemotePath,
    /// Size when known.
    pub size: Option<u64>,
    /// ASCII/binary choice.
    pub transfer_type: TransferTypeChoice,
    /// Priority.
    pub priority: Priority,
    /// Per-item file-exists action.
    pub on_exists: Option<ExistsAction>,
    /// A directory placeholder (T43).
    pub is_dir_placeholder: bool,
}

impl NewItem {
    /// A file transfer with default type, priority and exists action.
    pub fn file(
        server: QueueServer,
        direction: Direction,
        local: impl Into<LocalPath>,
        remote: impl Into<RemotePath>,
        size: Option<u64>,
    ) -> Self {
        Self {
            server,
            direction,
            local: local.into(),
            remote: remote.into(),
            size,
            transfer_type: TransferTypeChoice::Auto,
            priority: Priority::Normal,
            on_exists: None,
            is_dir_placeholder: false,
        }
    }

    pub(super) fn into_item(self, id: TransferId, added_at: OffsetDateTime) -> QueueItem {
        QueueItem {
            id,
            server: self.server,
            direction: self.direction,
            local: self.local,
            remote: self.remote,
            size: self.size,
            transfer_type: self.transfer_type,
            priority: self.priority,
            on_exists: self.on_exists,
            state: ItemState::Queued,
            attempts: 0,
            added_at,
            is_dir_placeholder: self.is_dir_placeholder,
        }
    }
}
