//! `/v1/auth/*`: registration, login, token refresh, logout.
//!
//! # Enumeration resistance
//! `login/start` answers every syntactically valid email the same way: a known
//! account gets a KE2 from its record, an unknown one a KE2 from a dummy record
//! (`login_start(None)`), both with a stored login state. `login/finish` then
//! fails with the same status and body ([`LOGIN_FAILED_MESSAGE`]) for an unknown
//! state id, an expired state, a wrong password, an unknown email and a disabled
//! account. Only after the password has been verified does the TOTP step answer
//! differently (`totp_required` / `totp_invalid`). Registration does reveal
//! whether an email exists (409), as in sverb.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use courier_ftp_crypto::grant::{Grant, verify_grant};
use courier_ftp_crypto::opaque::{credential_identifier, registration_finish};
use courier_ftp_crypto::random::os_rng;
use courier_ftp_proto::auth::{
    AccountKeysView, LoginDevice, LoginFinishRequest, LoginPurpose, LoginStartRequest,
    LoginStartResponse, ReauthResponse, RefreshRequest, RegisterFinishRequest,
    RegisterStartRequest, RegisterStartResponse, SessionResponse,
};
use courier_ftp_proto::error::{LOGIN_FAILED_MESSAGE, TOTP_INVALID_HINT, TOTP_REQUIRED_HINT};
use courier_ftp_proto::limits::{
    ACCOUNT_BUNDLE_LEN, ED25519_PUB_LEN, MAX_NAME_ENC_BYTES, SIGNATURE_LEN, X25519_PUB_LEN,
};
use courier_ftp_proto::validate::{device_field, normalize_email};
use uuid::Uuid;

use crate::auth::store::{
    AccountKeysRow, DeviceChoice, LoginStateRow, LoginUser, NewAccount, NewDevice, RefreshOutcome,
};
use crate::auth::tokens::{
    self, IssuedTokens, LOGIN_STATE_TTL, NewToken, REAUTH_TTL, hash_presented,
};
use crate::auth::{AuthCtx, opaque, totp};
use crate::error::ApiError;
use crate::events::publish_devices_revoked;
use crate::middleware::client_ip::ClientIp;
use crate::registration;
use crate::routes::account::totp_aad;
use crate::state::AppState;

/// Message of the 401 for an unknown, expired, used or revoked refresh token.
pub const REFRESH_INVALID_MESSAGE: &str = "invalid or expired refresh token";
/// Message of the 401 when a used refresh token is presented again.
pub const REFRESH_REUSE_MESSAGE: &str = "refresh token reuse detected; this device must log in again";

/// `/auth/...` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register/start", post(register_start))
        .route("/auth/register/finish", post(register_finish))
        .route("/auth/login/start", post(login_start))
        .route("/auth/login/finish", post(login_finish))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
}

fn login_failed() -> ApiError {
    ApiError::AuthRequired(LOGIN_FAILED_MESSAGE.into())
}

/// The 401 for a wrong or replayed TOTP code.
#[must_use]
pub fn totp_invalid() -> ApiError {
    ApiError::AuthRequired(format!(
        "{TOTP_INVALID_HINT}: invalid or already used TOTP code"
    ))
}

fn invalid(msg: impl Into<String>) -> ApiError {
    ApiError::Invalid(msg.into())
}

/// Checks a `register/finish` body (every length and format before any crypto)
/// and builds the rows to insert: normalized email; non-nil ids; the OPAQUE
/// upload; 32-byte keys; key version 1; both bundles exactly
/// `account::BUNDLE_LEN`; `name_enc` 1..=4096 bytes; the self-grant (key version
/// 1, 64-byte signature, parsable wrapped key, signature verified against the
/// uploaded Ed25519 key for `(vault_id, user_id, 1)`).
///
/// # Errors
/// `Invalid` with a message naming the offending field.
pub fn validate_registration(req: &RegisterFinishRequest) -> Result<NewAccount, ApiError> {
    let email = normalize_email(&req.email)?;
    if req.user_id.is_nil() || req.personal_vault.id.is_nil() {
        return Err(invalid("ids must not be nil"));
    }
    let k = &req.account_keys;
    let v = &req.personal_vault;
    let g = &v.self_grant;
    // Shapes first (cheap), then the parsers and the signature.
    if k.x25519_pub.len() != X25519_PUB_LEN {
        return Err(invalid("x25519_pub must be 32 bytes"));
    }
    let ed_pub: [u8; ED25519_PUB_LEN] = k
        .ed25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| invalid("ed25519_pub must be 32 bytes"))?;
    if k.version != 1 {
        return Err(invalid("account key version must be 1"));
    }
    if k.private_bundle_enc.len() != ACCOUNT_BUNDLE_LEN
        || k.recovery_bundle_enc.len() != ACCOUNT_BUNDLE_LEN
    {
        return Err(invalid(format!(
            "private and recovery bundles must be {ACCOUNT_BUNDLE_LEN} bytes"
        )));
    }
    if v.name_enc.is_empty() || v.name_enc.len() > MAX_NAME_ENC_BYTES {
        return Err(invalid("invalid encrypted vault name"));
    }
    if g.key_version != 1 {
        return Err(invalid("vault key version must be 1"));
    }
    let signature: [u8; SIGNATURE_LEN] = g
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| invalid("grant signature must be 64 bytes"))?;
    let name = device_field(Some(&req.device.name))?;
    let platform = device_field(Some(&req.device.platform))?;
    let opaque_record = registration_finish(&req.registration_upload)
        .map_err(|_| invalid("malformed OPAQUE registration upload"))?;
    let grant = Grant {
        wrapped: g.wrapped_vault_key.clone(),
        signature,
    };
    Grant::from_bytes(&grant.to_bytes()).map_err(|_| invalid("malformed wrapped vault key"))?;
    verify_grant(
        &grant,
        v.id.as_bytes(),
        req.user_id.as_bytes(),
        g.key_version,
        &ed_pub,
    )
    .map_err(|_| invalid("self-grant signature does not verify"))?;
    Ok(NewAccount {
        user_id: req.user_id,
        email,
        opaque_record,
        keys: AccountKeysRow {
            x25519_pub: k.x25519_pub.clone(),
            ed25519_pub: k.ed25519_pub.clone(),
            private_bundle_enc: k.private_bundle_enc.clone(),
            recovery_bundle_enc: Some(k.recovery_bundle_enc.clone()),
            version: 1,
        },
        vault_id: v.id,
        vault_name_enc: v.name_enc.clone(),
        grant_wrapped: g.wrapped_vault_key.clone(),
        grant_signature: g.signature.clone(),
        grant_key_version: 1,
        device: NewDevice {
            id: Uuid::now_v7(),
            name,
            platform,
        },
    })
}

/// The wire form of the account keys.
#[must_use]
pub fn keys_view(k: AccountKeysRow) -> AccountKeysView {
    AccountKeysView {
        x25519_pub: k.x25519_pub,
        ed25519_pub: k.ed25519_pub,
        private_bundle_enc: k.private_bundle_enc,
        version: u32::try_from(k.version).unwrap_or(0),
    }
}

async fn register_start(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    state.rate_limits().check(&email, ip)?;
    let cred = registration::credential(req.setup_token.as_deref(), req.invite_token.as_deref());
    // The full policy check first: no OPAQUE work for refused requests.
    state
        .store()
        .check_registration(&email, cred, state.auth().now())
        .await?;
    let setup = state.server_setup().await?;
    let registration_response = setup
        .registration_start(&req.registration_request, &credential_identifier(&email))
        .map_err(|_| invalid("malformed OPAQUE registration request"))?;
    Ok(Json(RegisterStartResponse {
        registration_response,
        user_id: Uuid::now_v7(),
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    let acct = validate_registration(&req)?;
    let cred = registration::credential(req.setup_token.as_deref(), req.invite_token.as_deref());
    let now = state.auth().now();
    let tokens = IssuedTokens::issue(now);
    let outcome = state
        .store()
        .register(&acct, cred, &tokens, Uuid::now_v7(), now)
        .await?;
    tracing::info!(
        user_id = %acct.user_id,
        device_id = %acct.device.id,
        instance_admin = outcome.is_instance_admin,
        "account registered"
    );
    Ok(Json(SessionResponse {
        user_id: acct.user_id,
        device_id: acct.device.id,
        tokens: tokens.to_pair(),
        account_keys: keys_view(acct.keys),
        is_instance_admin: outcome.is_instance_admin,
    }))
}

async fn login_start(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    state.rate_limits().check(&email, ip)?;
    let setup = state.server_setup().await?;
    let user = state.store().user_by_email(&email).await?;
    let cred_id = credential_identifier(&email);
    let mut rng = os_rng();
    let started = match &user {
        Some(u) => setup
            .login_start(
                &mut rng,
                Some(&u.opaque_record),
                &req.credential_request,
                &cred_id,
            )
            .or_else(|_| {
                // A bad request fails again below; a corrupt record is logged and
                // answered like an unknown account.
                let r = setup.login_start(&mut rng, None, &req.credential_request, &cred_id);
                if r.is_ok() {
                    tracing::error!(user_id = %u.id, "stored OPAQUE record does not parse");
                }
                r
            }),
        None => setup.login_start(&mut rng, None, &req.credential_request, &cred_id),
    };
    let (credential_response, server_state) =
        started.map_err(|_| invalid("malformed OPAQUE credential request"))?;
    let id = Uuid::now_v7();
    let now = state.auth().now();
    let row = LoginStateRow {
        id,
        user_id: user.map(|u| u.id),
        state_enc: opaque::seal_login_state(state.secrets(), id, &server_state)?,
        expires_at: now + LOGIN_STATE_TTL,
    };
    state.store().put_login_state(&row, now).await?;
    Ok(Json(LoginStartResponse {
        credential_response,
        login_state_id: id,
    }))
}

/// Verifies KE3 against the stored state; every failure is the generic one.
async fn verify_login(state: &AppState, req: &LoginFinishRequest) -> Result<LoginUser, ApiError> {
    let row = state
        .store()
        .take_login_state(req.login_state_id, state.auth().now())
        .await?
        .ok_or_else(login_failed)?;
    let server_state = opaque::open_login_state(state.secrets(), row.id, &row.state_enc)
        .ok_or_else(login_failed)?;
    let verified = server_state.finish(&req.credential_finalization).is_ok();
    let user = match row.user_id {
        Some(id) => state.store().user_by_id(id).await?,
        None => None,
    };
    match user {
        Some(u) if verified && !u.disabled => Ok(u),
        Some(u) if verified => {
            tracing::warn!(user_id = %u.id, "login with the correct password for a disabled account");
            Err(login_failed())
        }
        _ => Err(login_failed()),
    }
}

/// The second factor, after the password has been verified.
///
/// # Errors
/// `AuthRequired` with a `totp_required` or `totp_invalid` message.
pub async fn check_totp(
    state: &AppState,
    user: &LoginUser,
    code: Option<&str>,
) -> Result<(), ApiError> {
    let Some(enc) = &user.totp_secret_enc else {
        return Ok(());
    };
    let Some(code) = code else {
        return Err(ApiError::AuthRequired(format!(
            "{TOTP_REQUIRED_HINT}: this account requires a TOTP code"
        )));
    };
    let secret = state
        .secrets()
        .open(&totp_aad(user.id), enc)
        .ok_or_else(|| ApiError::internal_msg("TOTP secret does not decrypt"))?;
    let now = u64::try_from(state.auth().now().unix_timestamp()).unwrap_or(0);
    let step = totp::verify(&secret, code, now)
        .and_then(|s| i64::try_from(s).ok())
        .ok_or_else(totp_invalid)?;
    if state.store().consume_totp_step(user.id, step).await? {
        Ok(())
    } else {
        Err(totp_invalid())
    }
}

fn device_choice(d: &LoginDevice) -> Result<DeviceChoice, ApiError> {
    let new = NewDevice {
        id: Uuid::now_v7(),
        name: device_field(d.name.as_deref())?,
        platform: device_field(d.platform.as_deref())?,
    };
    Ok(match d.id {
        Some(id) => DeviceChoice::Existing(id, new),
        None => DeviceChoice::New(new),
    })
}

async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Response, ApiError> {
    // Field checks before any crypto (the device is ignored for reauth).
    let choice = match req.purpose {
        LoginPurpose::Login => Some(device_choice(&req.device)?),
        LoginPurpose::Reauth => None,
    };
    let user = verify_login(&state, &req).await?;
    check_totp(&state, &user, req.totp.as_deref()).await?;
    let now = state.auth().now();
    let Some(choice) = choice else {
        let token = NewToken::generate();
        state
            .store()
            .insert_reauth(&token.hash, user.id, now + REAUTH_TTL)
            .await?;
        tracing::info!(user_id = %user.id, "reauth");
        return Ok(Json(ReauthResponse {
            user_id: user.id,
            reauth_token: token.wire.to_string(),
            reauth_expires_in_s: tokens::secs(REAUTH_TTL),
        })
        .into_response());
    };
    let issued = IssuedTokens::issue(now);
    let device_id = state
        .store()
        .start_session(user.id, &choice, &issued, Uuid::now_v7(), now)
        .await?;
    let keys = state
        .store()
        .account_keys(user.id)
        .await?
        .ok_or_else(|| ApiError::internal_msg("account keys missing"))?;
    tracing::info!(user_id = %user.id, %device_id, "login");
    Ok(Json(SessionResponse {
        user_id: user.id,
        device_id,
        tokens: issued.to_pair(),
        account_keys: keys_view(keys),
        is_instance_admin: user.is_instance_admin,
    })
    .into_response())
}

async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<courier_ftp_proto::auth::TokenPair>, ApiError> {
    let invalid_refresh = || ApiError::AuthRequired(REFRESH_INVALID_MESSAGE.into());
    let hash = hash_presented(&req.refresh_token).ok_or_else(invalid_refresh)?;
    let now = state.auth().now();
    let issued = IssuedTokens::issue(now);
    match state.store().refresh(&hash, &issued, now).await? {
        RefreshOutcome::Rotated { .. } => Ok(Json(issued.to_pair())),
        RefreshOutcome::Reused {
            device_id,
            user_id,
            family,
        } => {
            tracing::warn!(%user_id, %device_id, %family, "refresh token reuse detected: token family revoked");
            Err(ApiError::AuthRequired(REFRESH_REUSE_MESSAGE.into()))
        }
        RefreshOutcome::Invalid => Err(invalid_refresh()),
    }
}

async fn logout(State(state): State<AppState>, ctx: AuthCtx) -> Result<StatusCode, ApiError> {
    state
        .store()
        .logout(ctx.device_id, state.auth().now())
        .await?;
    tracing::info!(user_id = %ctx.user_id, device_id = %ctx.device_id, "logout");
    publish_devices_revoked(state.events().as_ref(), &[ctx.device_id]);
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use courier_ftp_crypto::account::{derive_akek, generate_account_keys, seal_private_bundle};
    use courier_ftp_crypto::grant::self_grant;
    use courier_ftp_crypto::opaque::{CourierKsf, ServerSetup, client_registration_start};
    use courier_ftp_crypto::random::random_key32;
    use courier_ftp_crypto::recovery::{recovery_key_generate, seal_recovery_bundle};
    use courier_ftp_proto::auth::{AccountKeysUpload, DeviceInfo, GrantUpload, PersonalVaultUpload};

    use super::*;

    /// A complete, valid `register/finish` body.
    fn valid() -> RegisterFinishRequest {
        let mut rng = os_rng();
        let email = "val@example.test";
        let setup = ServerSetup::generate(&mut rng);
        let (state, request) = client_registration_start(&mut rng, b"pw").unwrap();
        let response = setup
            .registration_start(&request, &credential_identifier(email))
            .unwrap();
        let fin = state
            .finish(&mut rng, b"pw", &response, &CourierKsf::insecure_for_tests())
            .unwrap();
        let user_id = Uuid::now_v7();
        let vault_id = Uuid::now_v7();
        let keys = generate_account_keys(&mut rng);
        let akek = derive_akek(&fin.export_key);
        let private = seal_private_bundle(&akek, user_id.as_bytes(), 1, &keys, &mut rng).unwrap();
        let (recovery, _) = recovery_key_generate(&mut rng);
        let rbundle = seal_recovery_bundle(&recovery, user_id.as_bytes(), &keys, &mut rng).unwrap();
        let vk = random_key32(&mut rng);
        let grant = self_grant(&vk, vault_id.as_bytes(), 1, user_id.as_bytes(), &keys, &mut rng)
            .unwrap();
        let pubk = keys.public();
        RegisterFinishRequest {
            email: email.into(),
            user_id,
            registration_upload: fin.upload.clone(),
            account_keys: AccountKeysUpload {
                x25519_pub: pubk.x25519.to_vec(),
                ed25519_pub: pubk.ed25519.to_vec(),
                private_bundle_enc: private,
                recovery_bundle_enc: rbundle,
                version: 1,
            },
            personal_vault: PersonalVaultUpload {
                id: vault_id,
                name_enc: b"sealed-name".to_vec(),
                self_grant: GrantUpload {
                    wrapped_vault_key: grant.wrapped.clone(),
                    signature: grant.signature.to_vec(),
                    key_version: 1,
                },
            },
            device: DeviceInfo {
                name: "laptop".into(),
                platform: "linux".into(),
            },
            invite_token: None,
            setup_token: None,
        }
    }

    #[test]
    fn validate_registration_rejects_each_bad_field() {
        let base = valid();
        let acct = validate_registration(&base).unwrap();
        assert_eq!(acct.email, "val@example.test");
        assert_eq!(acct.keys.version, 1);
        assert_eq!(acct.device.name, "laptop");

        type Mutate = fn(&mut RegisterFinishRequest);
        let other_keys = generate_account_keys(&mut os_rng());
        let stranger_ed = other_keys.public().ed25519.to_vec();
        let cases: Vec<(Mutate, &str)> = vec![
            (|r| r.email = "nope".into(), "invalid email"),
            (|r| r.user_id = Uuid::nil(), "ids must not be nil"),
            (|r| r.personal_vault.id = Uuid::nil(), "ids must not be nil"),
            (
                |r| r.registration_upload = vec![0; 10],
                "malformed OPAQUE registration upload",
            ),
            (
                |r| r.account_keys.x25519_pub = vec![1; 31],
                "x25519_pub must be 32 bytes",
            ),
            (
                |r| r.account_keys.ed25519_pub = vec![1; 33],
                "ed25519_pub must be 32 bytes",
            ),
            (
                |r| r.account_keys.private_bundle_enc.pop().map_or((), drop),
                "private and recovery bundles must be",
            ),
            (
                |r| r.account_keys.recovery_bundle_enc.push(0),
                "private and recovery bundles must be",
            ),
            (
                |r| r.account_keys.version = 2,
                "account key version must be 1",
            ),
            (
                |r| r.personal_vault.self_grant.key_version = 2,
                "vault key version must be 1",
            ),
            (
                |r| r.personal_vault.self_grant.signature = vec![0; 63],
                "grant signature must be 64 bytes",
            ),
            (
                |r| r.personal_vault.self_grant.signature = vec![0; 64],
                "self-grant signature does not verify",
            ),
            (
                // Signed for another user id.
                |r| r.user_id = Uuid::now_v7(),
                "self-grant signature does not verify",
            ),
            (
                |r| r.personal_vault.name_enc = Vec::new(),
                "invalid encrypted vault name",
            ),
            (
                |r| r.personal_vault.name_enc = vec![0; MAX_NAME_ENC_BYTES + 1],
                "invalid encrypted vault name",
            ),
            (|r| r.device.name = "a\nb".into(), "invalid device"),
        ];
        for (mutate, want) in cases {
            let mut r = base.clone();
            mutate(&mut r);
            match validate_registration(&r) {
                Err(ApiError::Invalid(msg)) => assert!(msg.contains(want), "{msg} !~ {want}"),
                other => panic!("{want}: expected Invalid, got {other:?}"),
            }
        }
        // A grant by another key does not verify either.
        let mut r = base;
        r.account_keys.ed25519_pub = stranger_ed;
        assert!(matches!(
            validate_registration(&r),
            Err(ApiError::Invalid(m)) if m == "self-grant signature does not verify"
        ));
    }
}
