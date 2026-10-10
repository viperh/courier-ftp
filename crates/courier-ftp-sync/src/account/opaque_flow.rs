//! The OPAQUE exchanges shared by the flows: login (and reauth), and a new
//! registration record (signup, password change, recovery). The key
//! stretching runs on the blocking pool.

use std::sync::Arc;

use courier_ftp_crypto::account::EXPORT_KEY_LEN;
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_crypto::opaque::{
    ClientRegistrationFinish, ClientRegistrationState, CourierKsf, client_login_start,
};
use courier_ftp_proto::auth::{
    LoginDevice, LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginStartResponse,
};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::{AccountConfig, AccountError, login_error};
use crate::http::ApiClient;

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AccountError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AccountError::Local(format!("background task failed: {e}")))
}

/// OPAQUE login (start + finish). Returns the export key and the finish
/// response (`SessionResponse` for a login, `ReauthResponse` for a reauth).
pub(crate) async fn opaque_login<T: DeserializeOwned>(
    api: &ApiClient,
    email: &str,
    password: &SecretString,
    cfg: &AccountConfig,
    purpose: LoginPurpose,
    device: LoginDevice,
    totp: Option<&SecretString>,
) -> Result<(Zeroizing<[u8; EXPORT_KEY_LEN]>, T), AccountError> {
    let (state, ke1) = client_login_start(&mut os_rng(), password.expose_secret().as_bytes())?;
    let start: LoginStartResponse = api
        .post_v1(
            "/auth/login/start",
            &LoginStartRequest {
                email: email.to_owned(),
                credential_request: ke1,
            },
            None,
        )
        .await
        .map_err(login_error)?;
    let ksf: Arc<CourierKsf> = Arc::clone(&cfg.ksf);
    let pw = Zeroizing::new(password.expose_secret().as_bytes().to_vec());
    let ke2 = start.credential_response;
    let fin = blocking(move || state.finish(&mut os_rng(), &pw, &ke2, &ksf))
        .await?
        // A wrong password (or unknown account) fails here, client side.
        .map_err(|_| AccountError::LoginFailed)?;
    let resp: T = api
        .post_v1(
            "/auth/login/finish",
            &LoginFinishRequest {
                login_state_id: start.login_state_id,
                credential_finalization: fin.finalization.clone(),
                totp: totp.map(|t| t.expose_secret().to_owned()),
                device,
                purpose,
            },
            None,
        )
        .await
        .map_err(login_error)?;
    Ok((fin.export_key, resp))
}

/// Finishes a client registration with the server's response (KSF on the
/// blocking pool).
pub(crate) async fn finish_registration_record(
    state: ClientRegistrationState,
    password: &SecretString,
    response: Vec<u8>,
    cfg: &AccountConfig,
) -> Result<ClientRegistrationFinish, AccountError> {
    let ksf = Arc::clone(&cfg.ksf);
    let pw = Zeroizing::new(password.expose_secret().as_bytes().to_vec());
    Ok(blocking(move || state.finish(&mut os_rng(), &pw, &response, &ksf)).await??)
}
