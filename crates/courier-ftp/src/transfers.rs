//! The app's transfer machinery (T56): the shared queue, the transfer
//! engine (T41) and the queue persister (T40), plus the two seams they need
//! from the program:
//!
//! - [`VaultSlot`]: the vault engine once the database is open, as the
//!   persister's [`DeviceBlobVault`] (locked, or no vault: nothing is read or
//!   written) and as the source of saved sites.
//! - [`AppResolver`]: turns a queue item's server into connect info.
//!   Quickconnect servers reuse the [`ConnectInfo`] of a connection made this
//!   run when there is one (key file, charset, proxy… and the typed password),
//!   else [`quick_connect_info`] (a missing password is asked for by the
//!   backend, which looks in the session credential cache first). Saved sites
//!   go through the Site Manager data (`SiteManager::connect`, T31) over the
//!   unlocked vault.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    backend::{BackendFactory, ConnectInfo},
    cache::ListingCache,
    events::{EventSender, SessionId, TransferId},
    model::{LogonType, RemotePath, ServerAddress},
    queue::{Queue, QueuePersister, QueueServer, SharedQueue, SiteId},
    settings::Settings,
    sites::SiteManager,
    transfer::{
        EngineHandle, FileExistsPolicy, ServerResolver, SpeedLimiter, TransferEngine,
        quick_connect_info, recursive::RecursiveExpander,
    },
    vault::{DeviceBlobVault, VaultError},
};
use courier_ftp_store::vault::VaultEngine;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::ui::Side;

/// How long quitting waits for the engine to close its connections.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The vault engine, once the database is open. Clones share it.
#[derive(Debug, Default)]
pub(crate) struct VaultSlot {
    engine: RwLock<Option<VaultEngine>>,
}

impl VaultSlot {
    pub(crate) fn set(&self, engine: Option<VaultEngine>) {
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
    }

    fn get(&self) -> Option<VaultEngine> {
        self.engine
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl DeviceBlobVault for VaultSlot {
    async fn is_unlocked(&self) -> bool {
        match self.get() {
            Some(engine) => engine.is_unlocked().await,
            None => false,
        }
    }

    async fn load_blob(
        &self,
        name: &str,
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match self.get() {
            Some(engine) => engine.load_blob(name).await,
            None => Err(VaultError::Locked),
        }
    }

    async fn save_blob(&self, name: &str, plaintext: &[u8]) -> std::result::Result<(), VaultError> {
        match self.get() {
            Some(engine) => engine.save_blob(name, plaintext).await,
            None => Err(VaultError::Locked),
        }
    }

    async fn delete_blob(&self, name: &str) -> std::result::Result<bool, VaultError> {
        match self.get() {
            Some(engine) => engine.delete_blob(name).await,
            None => Ok(false),
        }
    }
}

/// See the module docs.
#[derive(Debug)]
pub(crate) struct AppResolver {
    vault: Arc<VaultSlot>,
    /// Connect info of the connections made this run, by address.
    known: Mutex<HashMap<ServerAddress, ConnectInfo>>,
    /// `limit_connections` of the sites resolved so far.
    site_limits: Mutex<HashMap<SiteId, u32>>,
}

impl AppResolver {
    pub(crate) fn new(vault: Arc<VaultSlot>) -> Self {
        Self {
            vault,
            known: Mutex::new(HashMap::new()),
            site_limits: Mutex::new(HashMap::new()),
        }
    }

    /// A connection to `info.address` was opened: transfers to that server
    /// connect the same way.
    pub(crate) fn remember(&self, info: &ConnectInfo) {
        self.known
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(info.address.clone(), info.clone());
    }

    /// Forget typed passwords (the vault was locked).
    pub(crate) fn forget_passwords(&self) {
        let mut known = self.known.lock().unwrap_or_else(PoisonError::into_inner);
        for info in known.values_mut() {
            if let LogonType::Normal { user, .. } | LogonType::Account { user, .. } = &info.logon {
                info.logon = LogonType::AskForPassword { user: user.clone() };
            }
        }
    }

    fn quick(
        &self,
        address: &ServerAddress,
        password: Option<&secrecy::SecretString>,
    ) -> ConnectInfo {
        let known = self
            .known
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(address)
            .cloned();
        match known {
            Some(mut info) => {
                if let (Some(password), Some(user)) = (password, &address.user)
                    && matches!(
                        info.logon,
                        LogonType::AskForPassword { .. } | LogonType::Normal { .. }
                    )
                {
                    info.logon = LogonType::Normal {
                        user: user.clone(),
                        password: password.clone(),
                    };
                }
                info
            }
            None => quick_connect_info(address, password),
        }
    }

    async fn site(&self, id: SiteId) -> Result<ConnectInfo> {
        let engine = self
            .vault
            .get()
            .ok_or_else(|| Error::Vault("the vault is not open".into()))?;
        let sites = SiteManager::load(Arc::new(engine.clone()), Arc::new(engine.store().clone()))
            .await
            .map_err(|e| Error::Vault(e.to_string()))?;
        let connect = sites
            .connect(id)
            .await
            .map_err(|e| Error::InvalidInput(format!("saved site: {e}")))?;
        if let Some(limit) = connect.info.connection_limit {
            self.site_limits
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, limit);
        }
        Ok(connect.info)
    }
}

#[async_trait]
impl ServerResolver for AppResolver {
    async fn resolve(
        &self,
        server: &QueueServer,
        cancel: &CancellationToken,
    ) -> Result<ConnectInfo> {
        match server {
            QueueServer::Quick { address, password } => Ok(self.quick(address, password.as_ref())),
            QueueServer::Site(id) => tokio::select! {
                () = cancel.cancelled() => Err(Error::Cancelled),
                info = self.site(*id) => info,
            },
        }
    }

    fn connection_limit(&self, server: &QueueServer) -> Option<u32> {
        match server {
            QueueServer::Quick { address, .. } => self
                .known
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(address)
                .and_then(|info| info.connection_limit),
            QueueServer::Site(id) => self
                .site_limits
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(id)
                .copied(),
        }
    }
}

/// The queue, its engine and its persister, running in the background.
pub(crate) struct Transfers {
    pub(crate) queue: SharedQueue,
    pub(crate) persister: Arc<QueuePersister>,
    pub(crate) engine: EngineHandle,
    pub(crate) resolver: Arc<AppResolver>,
    pub(crate) vault: Arc<VaultSlot>,
    /// Directories to list again (a transfer into them finished), applied on
    /// the next tick so a burst of small files refreshes once.
    pub(crate) refresh: HashSet<(Side, RemotePath)>,
    persist_cancel: CancellationToken,
    persist_task: Option<JoinHandle<()>>,
    engine_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Transfers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transfers").finish_non_exhaustive()
    }
}

impl Transfers {
    /// Start the engine and the persister for `queue` (needs a tokio
    /// runtime). Transfer connections come from `factory`.
    pub(crate) fn start(
        queue: SharedQueue,
        factory: Arc<dyn BackendFactory>,
        events: EventSender,
        cache: ListingCache,
        settings: &Settings,
    ) -> Self {
        let vault = Arc::new(VaultSlot::default());
        let persister = QueuePersister::new(
            queue.clone(),
            Arc::clone(&vault) as Arc<dyn DeviceBlobVault>,
            settings.queue.persist,
        );
        let resolver = Arc::new(AppResolver::new(Arc::clone(&vault)));
        let on_changed = Arc::clone(&persister);
        let expander = RecursiveExpander::new(settings)
            .with_events(events.clone(), SessionId::next())
            .with_cache(cache);
        let (engine, handle) = TransferEngine::builder(
            queue.clone(),
            factory,
            Arc::clone(&resolver) as Arc<dyn ServerResolver>,
            events.clone(),
        )
        .settings(settings.clone())
        // T42: the file-exists rules and prompt; T43: directories expanded
        // level by level; T44: the speed limits.
        .exists_policy(Arc::new(FileExistsPolicy::new(events)))
        .dir_expander(Arc::new(expander))
        .rate_limiter(Arc::new(SpeedLimiter::new(&settings.transfers)))
        .on_queue_changed(move || on_changed.changed())
        .build();
        let engine_task = Some(engine.spawn());
        let persist_cancel = CancellationToken::new();
        let persist_task = Some(persister.spawn(persist_cancel.clone()));
        Self {
            queue,
            persister,
            engine: handle,
            resolver,
            vault,
            refresh: HashSet::new(),
            persist_cancel,
            persist_task,
            engine_task,
        }
    }

    /// The UI changed the queue: cancel the transfers it took out or paused,
    /// schedule the persister's write and, with `wake`, let the engine look
    /// for work now.
    pub(crate) fn edited(&self, cancel: &[TransferId], wake: bool) {
        for id in cancel {
            self.engine.cancel(*id);
        }
        self.persister.changed();
        if wake {
            self.engine.wake();
        }
    }

    /// Whether the queue is being processed.
    pub(crate) fn processing(&self) -> bool {
        courier_ftp_core::queue::lock_queue(&self.queue).is_processing()
    }

    /// Stop everything: the engine closes its connections (bounded), then the
    /// persister makes its final write.
    pub(crate) async fn shutdown(&mut self) {
        self.engine.shutdown();
        if let Some(task) = self.engine_task.take() {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, task).await;
        }
        self.persist_cancel.cancel();
        if let Some(task) = self.persist_task.take() {
            let _ = task.await;
        }
    }
}

/// A queue with the configured successful-list cap.
pub(crate) fn new_queue(settings: &Settings) -> SharedQueue {
    Arc::new(Mutex::new(Queue::new(settings.queue.max_successful)))
}
