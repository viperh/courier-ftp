//! `/v1/account*`: TOTP, password change, recovery, deletion.
//!
//! # Fresh-login proof (reauth)
//! Password change and account deletion need a `reauth_token` from a
//! `login/finish` with `purpose: "reauth"` in the last 5 minutes (single use), in
//! addition to the bearer token.
//!
//! # Recovery (sverb proposal)
//! 1. A one-time code reaches the user: mailed by `POST /v1/account/recovery/code`
//!    when SMTP is configured, otherwise issued by the operator (T86
//!    `admin user recovery-code`, which calls [`issue_recovery_code`]).
//! 2. `POST /v1/account/recovery/start {email, code, registration_request}`
//!    returns the `recovery_bundle_enc`, an OPAQUE registration response for the
//!    new password and the current version. Wrong codes count; 5 failures delete
//!    the code.
//! 3. The client opens the bundle with the 24-word recovery key, re-seals the
//!    private bundle under the new AKEK and signs
//!    `courier_ftp_crypto::opaque::recovery_proof_message` with the account
//!    Ed25519 key.
//! 4. `POST /v1/account/recovery` checks code, version and signature, replaces
//!    record and bundle (`version + 1`) and revokes every device.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router};
use courier_ftp_crypto::opaque::{
    credential_identifier, recovery_proof_message, registration_finish,
};
use courier_ftp_crypto::sign;
use courier_ftp_proto::auth::{
    AccountDeleteRequest, KeyVersionResponse, PasswordChangeRequest, PasswordStartRequest,
    PasswordStartResponse, RecoveryCodeRequest, RecoveryFinishRequest, RecoveryStartRequest,
    RecoveryStartResponse, TotpRequest, TotpSetupResponse, TotpStatus,
};
use courier_ftp_proto::limits::{ACCOUNT_BUNDLE_LEN, ED25519_PUB_LEN, SIGNATURE_LEN};
use courier_ftp_proto::validate::normalize_email;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::store::{
    KEY_VERSION_CHANGED_MESSAGE, NewCredentials, REAUTH_REQUIRED_MESSAGE,
    RECOVERY_CODE_INVALID_MESSAGE, RecoveryInfo, Store,
};
use crate::auth::tokens::{
    RECOVERY_CODE_TTL, generate_recovery_code, hash_presented, hash_recovery_code,
};
use crate::auth::{AuthCtx, totp};
use crate::error::ApiError;
use crate::events::{BusEvent, publish_devices_revoked};
use crate::mail;
use crate::middleware::client_ip::ClientIp;
use crate::routes::auth::totp_invalid;
use crate::state::AppState;

/// `/account...` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/account", delete(delete_account))
        .route("/account/totp", post(totp_enable).delete(totp_disable))
        .route("/account/password/start", post(password_start))
        .route("/account/password", post(password_change))
        .route("/account/recovery/code", post(recovery_code))
        .route("/account/recovery/start", post(recovery_start))
        .route("/account/recovery", post(recovery_finish))
}

fn user_aad(prefix: &[u8], user_id: Uuid) -> Vec<u8> {
    let mut aad = prefix.to_vec();
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

/// AAD of an enabled TOTP secret: `"courier-ftp/totp/v1" || user_id`.
#[must_use]
pub fn totp_aad(user_id: Uuid) -> Vec<u8> {
    user_aad(b"courier-ftp/totp/v1", user_id)
}

/// AAD of a pending TOTP secret: `"courier-ftp/totp-pending/v1" || user_id`.
#[must_use]
pub fn totp_pending_aad(user_id: Uuid) -> Vec<u8> {
    user_aad(b"courier-ftp/totp-pending/v1", user_id)
}

fn unix_now(state: &AppState) -> u64 {
    u64::try_from(state.auth().now().unix_timestamp()).unwrap_or(0)
}

fn reauth_hash(token: &str) -> Result<crate::auth::tokens::TokenHash, ApiError> {
    hash_presented(token).ok_or_else(|| ApiError::AuthRequired(REAUTH_REQUIRED_MESSAGE.into()))
}

fn new_credentials(upload: &[u8], bundle: &[u8], version: u32) -> Result<NewCredentials, ApiError> {
    if bundle.len() != ACCOUNT_BUNDLE_LEN {
        return Err(ApiError::Invalid(format!(
            "private_bundle_enc must be {ACCOUNT_BUNDLE_LEN} bytes"
        )));
    }
    let version = i32::try_from(version)
        .map_err(|_| ApiError::Conflict(KEY_VERSION_CHANGED_MESSAGE.into()))?;
    let opaque_record = registration_finish(upload)
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration upload".into()))?;
    Ok(NewCredentials {
        opaque_record,
        private_bundle_enc: bundle.to_vec(),
        version,
    })
}

fn publish_account_changed(state: &AppState, user_id: Uuid, version: u32, origin: Option<Uuid>) {
    state.events().publish(BusEvent::AccountChanged {
        user_id,
        key_version: version,
        origin_device: origin,
    });
}

/// `POST /v1/account/totp`: without `code`, start enabling (a new pending
/// secret and its otpauth URI); with `code`, confirm the pending secret.
async fn totp_enable(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<TotpRequest>,
) -> Result<Response, ApiError> {
    let store = state.store();
    let current = store.totp_state(ctx.user_id).await?;
    if current.secret_enc.is_some() {
        return Err(ApiError::Conflict("totp already enabled".into()));
    }
    let Some(code) = req.code else {
        let user = store
            .user_by_id(ctx.user_id)
            .await?
            .ok_or_else(|| ApiError::AuthRequired("invalid or expired token".into()))?;
        let secret = totp::generate_secret();
        let sealed = state
            .secrets()
            .seal_api(&totp_pending_aad(ctx.user_id), &secret)?;
        store.set_totp_pending(ctx.user_id, &sealed).await?;
        return Ok(Json(TotpSetupResponse {
            otpauth_uri: totp::otpauth_uri(&secret, &user.email),
            secret_base32: totp::base32(&secret),
        })
        .into_response());
    };
    let pending = current
        .pending_enc
        .ok_or_else(|| ApiError::Invalid("no pending totp setup".into()))?;
    let secret = state
        .secrets()
        .open(&totp_pending_aad(ctx.user_id), &pending)
        .ok_or_else(|| ApiError::internal_msg("pending TOTP secret does not decrypt"))?;
    let step = totp::verify(&secret, &code, unix_now(&state))
        .and_then(|s| i64::try_from(s).ok())
        .ok_or_else(totp_invalid)?;
    let sealed = state.secrets().seal_api(&totp_aad(ctx.user_id), &secret)?;
    if !store.confirm_totp(ctx.user_id, &sealed, step).await? {
        return Err(ApiError::Conflict("totp already enabled".into()));
    }
    tracing::info!(user_id = %ctx.user_id, "TOTP enabled");
    Ok(Json(TotpStatus { enabled: true }).into_response())
}

/// `DELETE /v1/account/totp {code}`.
async fn totp_disable(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<TotpRequest>,
) -> Result<StatusCode, ApiError> {
    let store = state.store();
    let Some(enc) = store.totp_state(ctx.user_id).await?.secret_enc else {
        return Err(ApiError::Invalid("totp is not enabled".into()));
    };
    let code = req.code.ok_or_else(totp_invalid)?;
    let secret = state
        .secrets()
        .open(&totp_aad(ctx.user_id), &enc)
        .ok_or_else(|| ApiError::internal_msg("TOTP secret does not decrypt"))?;
    let step = totp::verify(&secret, &code, unix_now(&state))
        .and_then(|s| i64::try_from(s).ok())
        .ok_or_else(totp_invalid)?;
    if !store.consume_totp_step(ctx.user_id, step).await? {
        return Err(totp_invalid());
    }
    store.disable_totp(ctx.user_id).await?;
    tracing::info!(user_id = %ctx.user_id, "TOTP disabled");
    Ok(StatusCode::NO_CONTENT)
}

async fn password_start(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<PasswordStartRequest>,
) -> Result<Json<PasswordStartResponse>, ApiError> {
    let user = state
        .store()
        .user_by_id(ctx.user_id)
        .await?
        .ok_or_else(|| ApiError::AuthRequired("invalid or expired token".into()))?;
    let setup = state.server_setup().await?;
    let registration_response = setup
        .registration_start(
            &req.registration_request,
            &credential_identifier(&user.email),
        )
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration request".into()))?;
    Ok(Json(PasswordStartResponse {
        registration_response,
    }))
}

/// `POST /v1/account/password` (online password change).
async fn password_change(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<PasswordChangeRequest>,
) -> Result<Json<KeyVersionResponse>, ApiError> {
    let reauth = reauth_hash(&req.reauth_token)?;
    let new = new_credentials(
        &req.registration_upload,
        &req.private_bundle_enc,
        req.version,
    )?;
    let others = state
        .store()
        .change_password(ctx, &reauth, &new, state.auth().now())
        .await?;
    tracing::info!(user_id = %ctx.user_id, device_id = %ctx.device_id, version = req.version, "password changed");
    publish_account_changed(&state, ctx.user_id, req.version, Some(ctx.device_id));
    publish_devices_revoked(state.events().as_ref(), &others);
    Ok(Json(KeyVersionResponse {
        version: req.version,
    }))
}

/// Issues a recovery code for `email` (replacing any previous one) and returns it
/// for delivery; `None` for an unknown email. Used by the mail endpoint and T86's
/// `admin user recovery-code`.
///
/// # Errors
/// Store errors.
pub async fn issue_recovery_code(
    store: &Store,
    email: &str,
    now: OffsetDateTime,
) -> Result<Option<zeroize::Zeroizing<String>>, ApiError> {
    let code = generate_recovery_code();
    let issued = store
        .issue_recovery_code(email, &hash_recovery_code(&code), now + RECOVERY_CODE_TTL)
        .await?;
    Ok(issued.map(|_| code))
}

/// `POST /v1/account/recovery/code`: 202 whether or not the account exists or
/// SMTP is configured.
async fn recovery_code(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryCodeRequest>,
) -> Result<StatusCode, ApiError> {
    let email = normalize_email(&req.email)?;
    state.rate_limits().check(&email, ip)?;
    let Some(smtp) = state.config().smtp.clone() else {
        tracing::debug!("recovery code requested without SMTP: the operator issues it");
        return Ok(StatusCode::ACCEPTED);
    };
    if let Some(code) = issue_recovery_code(state.store(), &email, state.auth().now()).await? {
        let body = mail::recovery_body(&code, &state.config().public_url);
        tokio::spawn(async move {
            if let Err(e) = mail::send(&smtp, &email, mail::RECOVERY_SUBJECT, body).await {
                tracing::warn!(error = %e, "could not mail a recovery code");
            }
        });
    }
    Ok(StatusCode::ACCEPTED)
}

async fn checked_code(
    state: &AppState,
    ip: std::net::IpAddr,
    email: &str,
    code: &str,
) -> Result<(String, [u8; 32], RecoveryInfo), ApiError> {
    let email = normalize_email(email)?;
    state.rate_limits().check(&email, ip)?;
    let hash = hash_recovery_code(code);
    let info = state
        .store()
        .check_recovery_code(&email, &hash, state.auth().now())
        .await?
        .ok_or_else(|| ApiError::AuthRequired(RECOVERY_CODE_INVALID_MESSAGE.into()))?;
    Ok((email, hash, info))
}

async fn recovery_start(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryStartRequest>,
) -> Result<Json<RecoveryStartResponse>, ApiError> {
    let (email, _, info) = checked_code(&state, ip, &req.email, &req.code).await?;
    let recovery_bundle_enc = info
        .recovery_bundle_enc
        .ok_or_else(|| ApiError::NotFound("this account has no recovery bundle".into()))?;
    let setup = state.server_setup().await?;
    let registration_response = setup
        .registration_start(&req.registration_request, &credential_identifier(&email))
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration request".into()))?;
    Ok(Json(RecoveryStartResponse {
        user_id: info.user_id,
        recovery_bundle_enc,
        registration_response,
        version: u32::try_from(info.version).unwrap_or(0),
    }))
}

async fn recovery_finish(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryFinishRequest>,
) -> Result<Json<KeyVersionResponse>, ApiError> {
    let sig: [u8; SIGNATURE_LEN] = req
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Invalid("signature must be 64 bytes".into()))?;
    let (_, hash, info) = checked_code(&state, ip, &req.email, &req.code).await?;
    let new = new_credentials(
        &req.registration_upload,
        &req.private_bundle_enc,
        req.version,
    )?;
    if info.version.checked_add(1) != Some(new.version) {
        return Err(ApiError::Conflict(KEY_VERSION_CHANGED_MESSAGE.into()));
    }
    let ed_pub: [u8; ED25519_PUB_LEN] = info
        .ed25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal_msg("stored ed25519_pub has the wrong length"))?;
    let msg = recovery_proof_message(
        info.user_id.as_bytes(),
        req.version,
        &req.registration_upload,
        &req.private_bundle_enc,
    );
    sign::verify(&ed_pub, &msg, &sig)
        .map_err(|_| ApiError::Forbidden("recovery proof signature does not verify".into()))?;
    let revoked = state
        .store()
        .finish_recovery(info.user_id, &hash, &new, state.auth().now())
        .await?;
    tracing::info!(user_id = %info.user_id, version = req.version, "account recovered");
    publish_account_changed(&state, info.user_id, req.version, None);
    publish_devices_revoked(state.events().as_ref(), &revoked);
    Ok(Json(KeyVersionResponse {
        version: req.version,
    }))
}

/// `DELETE /v1/account`.
async fn delete_account(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<AccountDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    let reauth = reauth_hash(&req.reauth_token)?;
    let devices = state
        .store()
        .delete_account(ctx.user_id, &reauth, state.auth().now())
        .await?;
    tracing::info!(user_id = %ctx.user_id, "account deleted");
    publish_devices_revoked(state.events().as_ref(), &devices);
    Ok(StatusCode::NO_CONTENT)
}
