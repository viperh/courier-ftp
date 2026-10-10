//! Extension points injected into the engine: [`ServerResolver`],
//! [`ExistsPolicy`] (T42), [`RateLimiter`] (T44), [`DirExpander`] (T43) and
//! the local-side [`LocalBackendFactory`].

use async_trait::async_trait;
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    backend::{Backend, Capabilities, ConnectInfo},
    events::{EventSender, PromptKind, PromptResponse},
    local::LocalBackend,
    model::{Direction, Entry, LogonType},
    queue::{NewItem, QueueItem, QueueServer},
    settings::TransferSettings,
};

/// Turns a queue item's server into what the
/// [`BackendFactory`](crate::backend::BackendFactory) needs.
///
/// The binary implements it with the Site Manager (`SiteManager::connect`,
/// T31) for [`QueueServer::Site`] and [`quick_connect_info`] for
/// quickconnect servers. [`QuickResolver`] covers quickconnect only.
#[async_trait]
pub trait ServerResolver: Send + Sync {
    /// The connect info for a new transfer connection to `server`. Called
    /// once per new connection (pooled connections are reused without it).
    /// May prompt (e.g. for a password); `cancel` fires when the transfer is
    /// cancelled.
    async fn resolve(
        &self,
        server: &QueueServer,
        cancel: &CancellationToken,
    ) -> Result<ConnectInfo>;

    /// The site's "limit number of simultaneous connections"
    /// (`limit_connections`), known without connecting. `None` = only the
    /// global limits apply.
    fn connection_limit(&self, server: &QueueServer) -> Option<u32> {
        let _ = server;
        None
    }
}

/// Connect info for a quickconnect server: `Normal` with the user and
/// password, `AskForPassword` with a user and no password, else
/// `Anonymous`.
pub fn quick_connect_info(
    address: &crate::model::ServerAddress,
    password: Option<&SecretString>,
) -> ConnectInfo {
    let logon = match (&address.user, password) {
        (Some(user), Some(pw)) => LogonType::Normal {
            user: user.clone(),
            password: pw.clone(),
        },
        (Some(user), None) => LogonType::AskForPassword { user: user.clone() },
        (None, _) => LogonType::Anonymous,
    };
    ConnectInfo::new(address.clone(), logon)
}

/// A [`ServerResolver`] for quickconnect servers only; a quickconnect server
/// with a user but no password is asked for one through the event bus.
/// Saved sites fail with [`Error::InvalidInput`].
#[derive(Debug, Clone)]
pub struct QuickResolver {
    events: Option<EventSender>,
}

impl QuickResolver {
    /// A resolver that prompts for missing passwords through `events`
    /// (`None`: leave the logon as "ask for password" for the backend).
    pub fn new(events: Option<EventSender>) -> Self {
        Self { events }
    }
}

#[async_trait]
impl ServerResolver for QuickResolver {
    async fn resolve(
        &self,
        server: &QueueServer,
        cancel: &CancellationToken,
    ) -> Result<ConnectInfo> {
        match server {
            QueueServer::Site(_) => Err(Error::InvalidInput(
                "saved sites need the Site Manager's resolver".into(),
            )),
            QueueServer::Quick { address, password } => {
                if password.is_none()
                    && let (Some(user), Some(events)) = (&address.user, &self.events)
                {
                    let answer = events
                        .ask(
                            None,
                            PromptKind::Password {
                                for_: format!("{user}@{}", address.host),
                            },
                            cancel,
                        )
                        .await?;
                    if let PromptResponse::Secret(pw) = answer {
                        return Ok(quick_connect_info(address, Some(&pw)));
                    }
                    return Err(Error::Cancelled);
                }
                Ok(quick_connect_info(address, password.as_ref()))
            }
        }
    }
}

/// What the [`ExistsPolicy`] sees.
#[derive(Debug, Clone, Copy)]
pub struct ExistsContext<'a> {
    /// The queue item (its `on_exists` override included).
    pub item: &'a QueueItem,
    /// The source file.
    pub source: &'a Entry,
    /// The target, when it exists.
    pub target: Option<&'a Entry>,
    /// What the target side supports (resume, …).
    pub target_caps: Capabilities,
    /// Whether resuming is possible for this transfer (capability and binary
    /// mode).
    pub can_resume: bool,
}

/// What to do with the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExistsDecision {
    /// Write from scratch (create or truncate).
    Overwrite,
    /// Keep the first `offset` bytes of the target and continue from there.
    Resume {
        /// Bytes to keep.
        offset: u64,
    },
    /// Don't transfer; the item is removed from the queue as skipped.
    Skip,
    /// Write to this file name in the same directory instead (never
    /// overwrites: opened with [`WriteMode::Create`](crate::backend::WriteMode::Create)).
    Rename {
        /// The new file name (one component).
        name: String,
    },
}

/// The file-exists hook (T42): the engine calls it once per transfer, after
/// stat-ing source and target and before opening any stream, except when it
/// resumes a retried transfer at its own offset.
///
/// It may prompt (the T42 "ask" flow); other workers continue meanwhile.
#[async_trait]
pub trait ExistsPolicy: Send + Sync {
    /// Decide. An error fails the item (transient errors are retried).
    async fn decide(
        &self,
        ctx: ExistsContext<'_>,
        cancel: &CancellationToken,
    ) -> Result<ExistsDecision>;
}

/// The default [`ExistsPolicy`]: always overwrite.
#[derive(Debug, Clone, Copy, Default)]
pub struct OverwriteAll;

#[async_trait]
impl ExistsPolicy for OverwriteAll {
    async fn decide(&self, _: ExistsContext<'_>, _: &CancellationToken) -> Result<ExistsDecision> {
        Ok(ExistsDecision::Overwrite)
    }
}

/// The speed-limit hook (T44). Every chunk goes through
/// [`RateLimiter::acquire`] before it is written. The engine races the call
/// against the transfer's cancellation, so it need not watch for that.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Wait until `bytes` may be transferred in `direction`.
    async fn acquire(&self, direction: Direction, bytes: usize);

    /// The chunk size to read for `direction` (T44 caps it to about a tenth
    /// of the rate). `preferred` is the engine's buffer size.
    fn chunk_size(&self, direction: Direction, preferred: usize) -> usize {
        let _ = direction;
        preferred
    }

    /// The settings changed (the engine's `SettingsChanged` command).
    fn settings_changed(&self, settings: &TransferSettings) {
        let _ = settings;
    }
}

/// The default [`RateLimiter`]: no limit.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unlimited;

#[async_trait]
impl RateLimiter for Unlimited {
    async fn acquire(&self, _: Direction, _: usize) {}
}

/// The directory-placeholder hook (T43). Without one, placeholders are never
/// scheduled. With one, a placeholder takes a slot like a transfer, the
/// expander lists it, and the engine replaces it by the returned items
/// ([`Queue::expand_placeholder`](crate::queue::Queue::expand_placeholder)).
#[async_trait]
pub trait DirExpander: Send + Sync {
    /// The items one level below the placeholder `item`. `remote` is a
    /// connected transfer session for the item's server, `local` the local
    /// filesystem.
    async fn expand(
        &self,
        item: &QueueItem,
        remote: &mut dyn Backend,
        local: &mut dyn Backend,
        cancel: &CancellationToken,
    ) -> Result<Vec<NewItem>>;
}

/// Creates the local side of transfers. The default is [`LocalBackend`];
/// tests substitute a mock.
pub trait LocalBackendFactory: Send + Sync {
    /// A new, not yet connected local backend.
    fn create(&self) -> Box<dyn Backend>;
}

/// [`LocalBackendFactory`] for the real filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealLocal;

impl LocalBackendFactory for RealLocal {
    fn create(&self) -> Box<dyn Backend> {
        Box::new(LocalBackend::new())
    }
}

#[cfg(any(test, feature = "test-util"))]
impl LocalBackendFactory for crate::backend::MockServer {
    fn create(&self) -> Box<dyn Backend> {
        Box::new(self.backend())
    }
}
