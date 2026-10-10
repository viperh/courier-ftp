//! Server side of OPAQUE.
//!
//! The cipher suite and message handling are `courier_ftp_crypto::opaque` (shared
//! with the client); this module owns the `ServerSetup` lifecycle and the sealing
//! of login states.
//!
//! * The `ServerSetup` is generated on first need and stored in `server_secrets`
//!   under [`OPAQUE_SERVER_SETUP`], sealed with the server-secret key. Insertion
//!   is first-writer-wins (`ON CONFLICT DO NOTHING` + re-read), so replicas
//!   starting together agree on one setup. `serve` loads it at startup.
//! * Login states (the KE2 server state, which holds key material) are sealed with
//!   the same key and AAD `"courier-ftp/login-state/v1" || id` before they go to
//!   `login_states`.

use courier_ftp_crypto::opaque::{ServerLoginState, ServerSetup};
use courier_ftp_crypto::random::os_rng;
use uuid::Uuid;

use super::store::Store;
use crate::error::ApiError;
pub use crate::secrets::OPAQUE_SERVER_SETUP;
use crate::secrets::{SecretsError, ServerSecrets};

/// AAD prefix of a sealed login state.
pub const LOGIN_STATE_AAD: &[u8] = b"courier-ftp/login-state/v1";

fn open_setup(secrets: &ServerSecrets, blob: &[u8]) -> Result<ServerSetup, ApiError> {
    let plain = secrets
        .open(OPAQUE_SERVER_SETUP.as_bytes(), blob)
        .ok_or_else(|| {
            ApiError::internal(SecretsError::WrongSecret {
                name: OPAQUE_SERVER_SETUP.to_owned(),
            })
        })?;
    ServerSetup::from_bytes(&plain).map_err(ApiError::internal)
}

/// Loads the setup, generating and storing it first if there is none.
///
/// # Errors
/// Store errors; a row that does not decrypt with the configured secret.
pub async fn load_or_init(store: &Store, secrets: &ServerSecrets) -> Result<ServerSetup, ApiError> {
    if let Some(blob) = store.get_secret(OPAQUE_SERVER_SETUP).await? {
        return open_setup(secrets, &blob);
    }
    let fresh = ServerSetup::generate(&mut os_rng());
    let sealed = secrets.seal_api(OPAQUE_SERVER_SETUP.as_bytes(), &fresh.to_bytes())?;
    store
        .insert_secret_if_absent(OPAQUE_SERVER_SETUP, &sealed)
        .await?;
    // Another replica may have stored its setup first: use whatever won.
    let blob = store
        .get_secret(OPAQUE_SERVER_SETUP)
        .await?
        .ok_or_else(|| ApiError::internal_msg("OPAQUE setup vanished"))?;
    let setup = open_setup(secrets, &blob)?;
    tracing::info!("OPAQUE server setup created");
    Ok(setup)
}

fn login_state_aad(id: Uuid) -> Vec<u8> {
    let mut aad = LOGIN_STATE_AAD.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

/// Seals a login state for storage.
///
/// # Errors
/// `Internal` (practically never).
pub fn seal_login_state(
    secrets: &ServerSecrets,
    id: Uuid,
    state: &ServerLoginState,
) -> Result<Vec<u8>, ApiError> {
    secrets.seal_api(&login_state_aad(id), &state.to_bytes())
}

/// Opens a stored login state; `None` if it does not decrypt or parse.
#[must_use]
pub fn open_login_state(
    secrets: &ServerSecrets,
    id: Uuid,
    blob: &[u8],
) -> Option<ServerLoginState> {
    let plain = secrets.open(&login_state_aad(id), blob)?;
    ServerLoginState::from_bytes(&plain).ok()
}
