//! Shared helpers for the sync client tests: a real `courier-ftp-server`
//! (in-memory store) on `127.0.0.1:<random port>`, and "devices": each a data
//! directory with its own store and vault engine.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc
)]

pub mod proxy;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{ItemId, ItemKind, Site};
use courier_ftp_core::vault::{ItemVault, ItemVaultExt, MemKeyring};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_crypto::opaque::CourierKsf;
use courier_ftp_proto::auth::DeviceInfo;
use courier_ftp_server::auth::store::mem::MemStore;
use courier_ftp_server::auth::{AuthRuntime, AuthStore, ManualClock as ServerClock};
use courier_ftp_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use courier_ftp_server::registration::RegistrationMode;
use courier_ftp_server::{AppState, Config, app, serve};
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store};
use courier_ftp_sync::account::{self, LoginRequest, PreparedRegistration, RegistrationToken};
use courier_ftp_sync::{AccountConfig, SyncSession};
use secrecy::SecretString;

/// A strong master password.
pub const PW: &str = "correct horse battery staple violin";
/// Another strong password.
pub const PW2: &str = "tangerine submarine quantum lighthouse";
/// A third strong password.
pub const PW3: &str = "obsidian marmalade galaxy accordion";

/// A secret from text.
pub fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// 32 bytes of hex: a valid server secret.
const SECRET_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// A running in-process server.
pub struct Server {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    /// The app state (store, config, clock).
    pub state: AppState,
    /// The server clock.
    pub clock: Arc<ServerClock>,
    /// The in-memory store.
    pub mem: Arc<MemStore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    /// Starts a server with open registration.
    pub async fn start() -> Self {
        Self::start_with_mode(RegistrationMode::Open).await
    }

    /// Starts a server in `mode`.
    pub async fn start_with_mode(mode: RegistrationMode) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let env: HashMap<String, String> = HashMap::from([
            ("COURIER_SERVER_SECRET".into(), SECRET_A.into()),
            (
                "COURIER_PUBLIC_URL".into(),
                "https://sync.example.test".into(),
            ),
        ]);
        let cfg = Config::from_sources(None, |k| env.get(k).cloned()).expect("config");
        let n = NonZeroU32::new(100_000).unwrap();
        let limits = RateLimiters::new(LoginLimits {
            per_email_per_minute: n,
            per_ip_per_minute: n,
        });
        let mem = Arc::new(MemStore::new());
        let pool =
            courier_ftp_server::db::connect_lazy("postgres://courier@127.0.0.1:1/unreachable")
                .unwrap();
        let clock = Arc::new(ServerClock::new());
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        let state = AppState::with_auth(cfg, pool, limits, auth);
        serve::startup_checks(&state).await.expect("startup checks");
        mem.with_data(|d| d.registration_mode = mode);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self {
            url: format!("http://{addr}"),
            state,
            clock,
            mem,
            task,
        }
    }

    /// Sets the setup token.
    pub fn set_setup_token(&self, token: &str) {
        self.mem.with_data(|d| d.set_setup_token(token));
    }

    /// A recovery code for `email` (what the server would mail).
    pub async fn recovery_code(&self, email: &str) -> String {
        use courier_ftp_server::auth::Clock as _;
        courier_ftp_server::routes::account::issue_recovery_code(
            self.state.auth().store(),
            email,
            self.clock.now(),
        )
        .await
        .unwrap()
        .unwrap()
    }
}

/// The account settings of a test device (cheap KSF, no TLS needed).
pub fn cfg(name: &str) -> AccountConfig {
    let mut c = AccountConfig::new(name);
    c.ksf = Arc::new(CourierKsf::insecure_for_tests());
    c.device = DeviceInfo {
        name: name.to_owned(),
        platform: "test".into(),
    };
    c.http_timeout = Duration::from_secs(10);
    c
}

/// One device: a data directory with its store and vault engine.
pub struct Device {
    pub name: String,
    pub dir: tempfile::TempDir,
    pub clock: Arc<ManualClock>,
    pub keyring: MemKeyring,
    pub store: Store,
    pub vault: VaultEngine,
    pub cfg: AccountConfig,
}

impl Device {
    /// A new device whose vault is initialized with `password`.
    pub async fn new(name: &str, password: &str) -> Self {
        let d = Self::uninitialized(name);
        d.vault.initialize(&secret(password), false).await.unwrap();
        d
    }

    /// A new device with no vault yet.
    pub fn uninitialized(name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let clock = Arc::new(ManualClock::new(i64::try_from(now).unwrap()));
        let keyring = MemKeyring::new();
        let store = Store::open_at(dir.path().join("courier-ftp.db"), clock.clone()).unwrap();
        let vault = VaultEngine::new(store.clone(), Arc::new(keyring.clone()), Argon2Cost::TEST);
        Self {
            name: name.to_owned(),
            dir,
            clock,
            keyring,
            store,
            vault,
            cfg: cfg(name),
        }
    }

    /// Reopens the store and engine (a restart); the vault is locked.
    pub fn restart(&mut self) {
        self.store =
            Store::open_at(self.dir.path().join("courier-ftp.db"), self.clock.clone()).unwrap();
        self.vault = VaultEngine::new(
            self.store.clone(),
            Arc::new(self.keyring.clone()),
            Argon2Cost::TEST,
        );
    }

    /// Saves a site; returns its id.
    pub async fn add_site(&self, name: &str, host: &str, user: &str) -> ItemId {
        let mut site = Site::new(name, Protocol::Sftp, host);
        site.user = user.to_owned();
        let id = ItemId::new();
        self.vault.put_view(id, None, site).await.unwrap();
        id
    }

    /// Edits a site.
    pub async fn edit_site(&self, id: ItemId, f: impl FnOnce(&mut Site)) {
        let mut site: Site = self.site(id).await.unwrap();
        f(&mut site);
        self.vault.put_view(id, None, site).await.unwrap();
    }

    /// A site by id.
    pub async fn site(&self, id: ItemId) -> Option<Site> {
        self.vault
            .get(id)
            .await
            .unwrap()
            .map(|i| i.view::<Site>().unwrap())
    }

    /// Every live site, sorted by name: `(name, host, user)`.
    pub async fn sites(&self) -> Vec<(String, String, String)> {
        let mut out: Vec<_> = self
            .vault
            .list(ItemKind::Site)
            .await
            .unwrap()
            .into_iter()
            .map(|i| {
                let s = i.view::<Site>().unwrap();
                (s.name, s.host, s.user)
            })
            .collect();
        out.sort();
        out
    }

    /// Registers this device's vault at `server` with `email` (password
    /// [`PW`] unless given).
    pub async fn register(&self, server: &Server, email: &str, password: &str) -> SyncSession {
        let mut prepared = self.prepare(server, email, password).await;
        confirm(&mut prepared);
        let (_, session) = account::finish_registration(&self.vault, &prepared, None, &self.cfg)
            .await
            .unwrap();
        session
    }

    /// Step 1 of a registration.
    pub async fn prepare(
        &self,
        server: &Server,
        email: &str,
        password: &str,
    ) -> PreparedRegistration {
        account::prepare_registration(
            &self.vault,
            &server.url,
            email,
            &secret(password),
            &self.cfg,
        )
        .await
        .unwrap()
    }

    /// A login request.
    pub fn login_request(server: &Server, email: &str, password: &str) -> LoginRequest {
        LoginRequest {
            server_url: server.url.clone(),
            email: email.to_owned(),
            password: secret(password),
            totp: None,
        }
    }

    /// Logs in (keep-both for duplicates) and commits.
    pub async fn login(&self, server: &Server, email: &str, password: &str) -> SyncSession {
        let req = Self::login_request(server, email, password);
        let session = account::start_login(&self.vault, &req, &self.cfg)
            .await
            .unwrap();
        session.commit().await.unwrap().1
    }
}

/// Types the three requested recovery words.
pub fn confirm(prepared: &mut PreparedRegistration) {
    let words = prepared.recovery_words();
    let n = prepared.confirm_word_numbers();
    let answers = [words[n[0] - 1], words[n[1] - 1], words[n[2] - 1]];
    assert!(prepared.confirm_words(&answers));
}

/// A setup token value.
pub fn setup_token(t: &str) -> RegistrationToken {
    RegistrationToken::Setup(secret(t))
}

/// Uploads every queued item of `device` (a bare-bones push for the account
/// tests, which run without the sync engine). Returns how many were accepted.
pub async fn push_all(device: &Device, session: &SyncSession) -> usize {
    use courier_ftp_proto::sync::{PushChange, PushRequest, PushStatus};
    let mut accepted = 0;
    for vault in device.vault.loaded_vaults().await {
        let rows = device.store.outbox().list(vault).await.unwrap();
        if rows.is_empty() {
            continue;
        }
        let mut changes = Vec::new();
        for r in &rows {
            let item = device.store.items().get(r.item_id).await.unwrap().unwrap();
            changes.push(PushChange {
                id: r.item_id.uuid(),
                base_revision: u64::try_from(r.base_revision).unwrap(),
                key_version: item.key_version,
                envelope: item.envelope,
                deleted: item.deleted,
            });
        }
        let token = session.tokens().access().await.unwrap();
        let resp = session
            .tokens()
            .api()
            .push(&token, vault.uuid(), &PushRequest { changes })
            .await
            .unwrap();
        for (r, res) in rows.iter().zip(resp.results) {
            assert_eq!(res.status, PushStatus::Ok, "{res:?}");
            device
                .store
                .items()
                .mark_pushed(
                    r.item_id,
                    i64::try_from(res.revision.unwrap()).unwrap(),
                    r.queued_at,
                )
                .await
                .unwrap();
            accepted += 1;
        }
    }
    accepted
}
