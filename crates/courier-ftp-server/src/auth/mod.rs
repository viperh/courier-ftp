//! Authentication: OPAQUE, tokens, TOTP, the bearer extractor and persistence.
//!
//! * [`opaque`]: the server half of OPAQUE and the `ServerSetup` stored sealed in
//!   `server_secrets`;
//! * [`tokens`]: access/refresh/reauth tokens (hash-only storage, TTLs), recovery
//!   codes;
//! * [`totp`]: the optional second factor;
//! * [`extractor`]: `Authorization: Bearer` → [`AuthCtx`];
//! * [`store`]: persistence (PostgreSQL, plus an in-memory model);
//! * [`clock`]: injectable time.
//!
//! The routes live in `crate::routes::{auth, account, devices}`.

pub mod clock;
pub mod extractor;
pub mod opaque;
pub mod store;
pub mod tokens;
pub mod totp;

use std::sync::Arc;

use courier_ftp_crypto::opaque::ServerSetup;
use time::OffsetDateTime;
use tokio::sync::OnceCell;

pub use clock::{Clock, SystemClock, TestClock};
pub use extractor::AuthCtx;

use crate::error::ApiError;
use crate::secrets::ServerSecrets;
use store::Store;

/// Clock and the OPAQUE `ServerSetup` cache (part of `AppState`).
pub struct AuthRuntime {
    clock: Arc<dyn Clock>,
    setup: OnceCell<Arc<ServerSetup>>,
}

impl std::fmt::Debug for AuthRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRuntime")
            .field("setup_loaded", &self.setup.initialized())
            .finish_non_exhaustive()
    }
}

impl AuthRuntime {
    /// A runtime on `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            setup: OnceCell::new(),
        }
    }

    /// The current time.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The OPAQUE `ServerSetup`, loaded from `server_secrets` (or generated and
    /// stored on first use) once per process.
    ///
    /// # Errors
    /// Store errors, or a setup that can't be decrypted or parsed.
    pub async fn server_setup(
        &self,
        store: &Store,
        secrets: &ServerSecrets,
    ) -> Result<Arc<ServerSetup>, ApiError> {
        self.setup
            .get_or_try_init(|| async { opaque::load_or_init(store, secrets).await.map(Arc::new) })
            .await
            .cloned()
    }
}

impl Default for AuthRuntime {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}
