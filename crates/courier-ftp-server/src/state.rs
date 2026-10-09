//! Shared application state handed to every handler.

use std::sync::Arc;

use courier_ftp_crypto::opaque::ServerSetup;

use crate::auth::store::Store;
use crate::auth::{AuthRuntime, Clock, SystemClock};
use crate::config::Config;
use crate::error::ApiError;
use crate::events::EventSink;
use crate::middleware::rate_limit::RateLimiters;
use crate::secrets::ServerSecrets;

struct Inner {
    config: Config,
    store: Store,
    secrets: ServerSecrets,
    auth: AuthRuntime,
    rate_limits: Arc<RateLimiters>,
    events: Arc<dyn EventSink>,
}

/// Shared, cheap-to-clone application state.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.0.config)
            .field("store", &self.0.store)
            .field("auth", &self.0.auth)
            .field("rate_limits", &self.0.rate_limits)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Production state: system clock, default rate limits. Derives the
    /// at-rest key from the configured secret.
    #[must_use]
    pub fn new(config: Config, store: Store, events: Arc<dyn EventSink>) -> Self {
        Self::with_runtime(
            config,
            store,
            events,
            Arc::new(SystemClock),
            RateLimiters::default(),
        )
    }

    /// Like [`Self::new`] with a custom clock and rate limiters (tests).
    #[must_use]
    pub fn with_runtime(
        config: Config,
        store: Store,
        events: Arc<dyn EventSink>,
        clock: Arc<dyn Clock>,
        rate_limits: RateLimiters,
    ) -> Self {
        let secrets = ServerSecrets::new(&config.server_secret);
        Self(Arc::new(Inner {
            config,
            store,
            secrets,
            auth: AuthRuntime::new(clock),
            rate_limits: Arc::new(rate_limits),
            events,
        }))
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.0.store
    }

    /// The at-rest key helper.
    #[must_use]
    pub fn secrets(&self) -> &ServerSecrets {
        &self.0.secrets
    }

    /// Clock and OPAQUE setup cache.
    #[must_use]
    pub fn auth(&self) -> &AuthRuntime {
        &self.0.auth
    }

    /// The rate limiters.
    #[must_use]
    pub fn rate_limits(&self) -> &Arc<RateLimiters> {
        &self.0.rate_limits
    }

    /// The event sink.
    #[must_use]
    pub fn events(&self) -> &Arc<dyn EventSink> {
        &self.0.events
    }

    /// The OPAQUE `ServerSetup` (loaded or created once).
    ///
    /// # Errors
    /// Store errors, or a setup that does not decrypt.
    pub async fn server_setup(&self) -> Result<Arc<ServerSetup>, ApiError> {
        self.0
            .auth
            .server_setup(&self.0.store, &self.0.secrets)
            .await
    }
}
