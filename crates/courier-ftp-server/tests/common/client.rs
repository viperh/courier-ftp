//! The client side of the auth flows, with the real OPAQUE client and account
//! crypto (cheap test KSF). Every secret value is registered as a log canary.

use axum::http::StatusCode;
use courier_ftp_crypto::account::{
    AccountKeys, derive_akek, generate_account_keys, open_private_bundle, seal_private_bundle,
};
use courier_ftp_crypto::grant::self_grant;
use courier_ftp_crypto::opaque::{
    CourierKsf, client_login_start, client_registration_start, recovery_proof_message,
};
use courier_ftp_crypto::random::{os_rng, random_key32};
use courier_ftp_crypto::recovery::{
    RecoveryKey, open_recovery_bundle, recovery_key_generate, seal_recovery_bundle,
};
use courier_ftp_crypto::sign;
use courier_ftp_proto::auth::{
    AccountKeysUpload, DeviceInfo, GrantUpload, LoginDevice, LoginFinishRequest, LoginPurpose,
    LoginStartRequest, LoginStartResponse, PasswordChangeRequest, PasswordStartRequest,
    PasswordStartResponse, RecoveryFinishRequest, RecoveryStartRequest, RecoveryStartResponse,
    RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse, SessionResponse,
};
use courier_ftp_server::auth::totp;
use serde_json::{Value, json};
use uuid::Uuid;

use super::Harness;

/// The test KSF.
pub fn ksf() -> CourierKsf {
    CourierKsf::insecure_for_tests()
}

/// A registered account as the client sees it.
pub struct Account {
    /// Email as typed.
    pub email: String,
    /// Master password.
    pub password: String,
    /// User id.
    pub user_id: Uuid,
    /// The registering device.
    pub device_id: Uuid,
    /// Current access token.
    pub access: String,
    /// Current refresh token.
    pub refresh: String,
    /// The account keys.
    pub keys: AccountKeys,
    /// The 24-word recovery key.
    pub recovery: RecoveryKey,
    /// Personal vault id.
    pub vault_id: Uuid,
    /// Instance admin flag from the session response.
    pub is_instance_admin: bool,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// Registration options.
#[derive(Debug, Clone, Default)]
pub struct RegOpts {
    /// Invite token.
    pub invite: Option<String>,
    /// Setup token.
    pub setup: Option<String>,
    /// Use this personal vault id instead of a fresh one.
    pub vault_id: Option<Uuid>,
}

fn canary_b64(h: &Harness, bytes: &[u8]) {
    use base64::Engine as _;
    h.canary(base64::engine::general_purpose::STANDARD.encode(bytes));
    h.canary(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    h.canary(hex::encode(bytes));
}

/// Registers `email`; `Err((status, body))` when the server refuses.
pub async fn try_register(
    h: &Harness,
    email: &str,
    password: &str,
    opts: RegOpts,
) -> Result<Account, (StatusCode, Value)> {
    h.canary(email);
    h.canary(password);
    let mut rng = os_rng();
    let (reg_state, request) = client_registration_start(&mut rng, password.as_bytes()).unwrap();
    canary_b64(h, &request);
    let start = RegisterStartRequest {
        email: email.into(),
        registration_request: request,
        invite_token: opts.invite.clone(),
        setup_token: opts.setup.clone(),
    };
    let (s, v) = h
        .post(
            "/v1/auth/register/start",
            None,
            serde_json::to_value(&start).unwrap(),
        )
        .await;
    if s != StatusCode::OK {
        return Err((s, v));
    }
    let start: RegisterStartResponse = serde_json::from_value(v).unwrap();
    canary_b64(h, &start.registration_response);
    let fin = reg_state
        .finish(
            &mut rng,
            password.as_bytes(),
            &start.registration_response,
            &ksf(),
        )
        .unwrap();
    canary_b64(h, &fin.upload);
    let user_id = start.user_id;
    let vault_id = opts.vault_id.unwrap_or_else(Uuid::now_v7);
    let keys = generate_account_keys(&mut rng);
    let akek = derive_akek(&fin.export_key);
    let private = seal_private_bundle(&akek, user_id.as_bytes(), 1, &keys, &mut rng).unwrap();
    let (recovery, _) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, user_id.as_bytes(), &keys, &mut rng).unwrap();
    canary_b64(h, &private);
    canary_b64(h, &rbundle);
    let vk = random_key32(&mut rng);
    let grant =
        self_grant(&vk, vault_id.as_bytes(), 1, user_id.as_bytes(), &keys, &mut rng).unwrap();
    let pubk = keys.public();
    let finish = RegisterFinishRequest {
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
        personal_vault: courier_ftp_proto::auth::PersonalVaultUpload {
            id: vault_id,
            name_enc: b"sealed vault name".to_vec(),
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
        invite_token: opts.invite,
        setup_token: opts.setup,
    };
    let (s, v) = h
        .post(
            "/v1/auth/register/finish",
            None,
            serde_json::to_value(&finish).unwrap(),
        )
        .await;
    if s != StatusCode::OK {
        return Err((s, v));
    }
    let session: SessionResponse = serde_json::from_value(v).unwrap();
    h.canary(session.tokens.access_token.clone());
    h.canary(session.tokens.refresh_token.clone());
    Ok(Account {
        email: email.into(),
        password: password.into(),
        user_id: session.user_id,
        device_id: session.device_id,
        access: session.tokens.access_token,
        refresh: session.tokens.refresh_token,
        keys,
        recovery,
        vault_id,
        is_instance_admin: session.is_instance_admin,
    })
}

/// Registers in `open` mode (sets it) and panics on failure.
pub async fn register(h: &Harness, email: &str, password: &str) -> Account {
    h.open().await;
    try_register(h, email, password, RegOpts::default())
        .await
        .unwrap_or_else(|(s, v)| panic!("register {email}: {s} {v}"))
}

/// Login options.
#[derive(Debug, Clone, Default)]
pub struct LoginOpts {
    /// Resume this device.
    pub device_id: Option<Uuid>,
    /// TOTP code.
    pub totp: Option<String>,
    /// Reauth instead of a session.
    pub reauth: bool,
}

/// `login/start` only: the raw response and the client state.
pub async fn login_start(
    h: &Harness,
    email: &str,
    password: &str,
) -> (
    StatusCode,
    Value,
    courier_ftp_crypto::opaque::ClientLoginState,
) {
    h.canary(email);
    h.canary(password);
    let (state, ke1) = client_login_start(&mut os_rng(), password.as_bytes()).unwrap();
    canary_b64(h, &ke1);
    let (s, v) = h
        .post(
            "/v1/auth/login/start",
            None,
            serde_json::to_value(&LoginStartRequest {
                email: email.into(),
                credential_request: ke1,
            })
            .unwrap(),
        )
        .await;
    (s, v, state)
}

/// A full login; `(status, body)` of `login/finish` (or of `login/start` when
/// that failed). On a client-side OPAQUE failure (wrong password) a garbage KE3
/// is sent, like a client that cannot finish would.
pub async fn login(h: &Harness, email: &str, password: &str, opts: LoginOpts) -> (StatusCode, Value) {
    let (s, v, state) = login_start(h, email, password).await;
    if s != StatusCode::OK {
        return (s, v);
    }
    let start: LoginStartResponse = serde_json::from_value(v).unwrap();
    canary_b64(h, &start.credential_response);
    let ke3 = match state.finish(
        &mut os_rng(),
        password.as_bytes(),
        &start.credential_response,
        &ksf(),
    ) {
        Ok(fin) => fin.finalization,
        Err(_) => vec![0u8; 64],
    };
    canary_b64(h, &ke3);
    if let Some(code) = &opts.totp {
        h.canary(format!("\"{code}\""));
    }
    let req = LoginFinishRequest {
        login_state_id: start.login_state_id,
        credential_finalization: ke3,
        totp: opts.totp,
        device: LoginDevice {
            id: opts.device_id,
            name: Some("second".into()),
            platform: Some("macos".into()),
        },
        purpose: if opts.reauth {
            LoginPurpose::Reauth
        } else {
            LoginPurpose::Login
        },
    };
    let (s, v) = h
        .post(
            "/v1/auth/login/finish",
            None,
            serde_json::to_value(&req).unwrap(),
        )
        .await;
    if s == StatusCode::OK {
        for key in ["reauth_token"] {
            if let Some(t) = v[key].as_str() {
                h.canary(t);
            }
        }
        for key in ["access_token", "refresh_token"] {
            if let Some(t) = v["tokens"][key].as_str() {
                h.canary(t);
            }
        }
    }
    (s, v)
}

/// A successful session login.
pub async fn login_ok(h: &Harness, email: &str, password: &str, opts: LoginOpts) -> SessionResponse {
    let (s, v) = login(h, email, password, opts).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

/// A reauth token.
pub async fn reauth(h: &Harness, a: &Account, totp: Option<String>) -> String {
    let (s, v) = login(
        h,
        &a.email,
        &a.password,
        LoginOpts {
            reauth: true,
            totp,
            ..LoginOpts::default()
        },
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["reauth_token"].as_str().unwrap().to_owned()
}

/// `POST /v1/auth/refresh`.
pub async fn refresh(h: &Harness, token: &str) -> (StatusCode, Value) {
    let (s, v) = h
        .post("/v1/auth/refresh", None, json!({ "refresh_token": token }))
        .await;
    if s == StatusCode::OK {
        for key in ["access_token", "refresh_token"] {
            if let Some(t) = v[key].as_str() {
                h.canary(t);
            }
        }
    }
    (s, v)
}

/// `GET /v1/devices` status with `access`.
pub async fn devices_status(h: &Harness, access: &str) -> StatusCode {
    h.get("/v1/devices", Some(access)).await.0
}

/// The current TOTP code of a base32 secret at the harness clock.
pub fn totp_code(h: &Harness, secret_b32: &str, offset_steps: i64) -> String {
    let secret = totp::from_base32(secret_b32).unwrap();
    let now = h.now().unix_timestamp() + offset_steps * 30;
    let code = totp::code_at(&secret, u64::try_from(now).unwrap());
    h.canary(format!("\"{code}\""));
    code
}

/// Enables TOTP; returns the base32 secret.
pub async fn enable_totp(h: &Harness, a: &Account) -> String {
    let (s, v) = h
        .post("/v1/account/totp", Some(&a.access), json!({ "code": null }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let secret = v["secret_base32"].as_str().unwrap().to_owned();
    h.canary(secret.clone());
    h.canary(v["otpauth_uri"].as_str().unwrap());
    let code = totp_code(h, &secret, 0);
    let (s, v) = h
        .post("/v1/account/totp", Some(&a.access), json!({ "code": code }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({ "enabled": true }));
    secret
}

/// Online password change from `a`'s device; returns the response.
pub async fn change_password(
    h: &Harness,
    a: &Account,
    reauth_token: &str,
    new_password: &str,
    version: u32,
) -> (StatusCode, Value) {
    h.canary(new_password);
    let mut rng = os_rng();
    let (st, request) = client_registration_start(&mut rng, new_password.as_bytes()).unwrap();
    canary_b64(h, &request);
    let (s, v) = h
        .post(
            "/v1/account/password/start",
            Some(&a.access),
            serde_json::to_value(&PasswordStartRequest {
                registration_request: request,
            })
            .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let start: PasswordStartResponse = serde_json::from_value(v).unwrap();
    let fin = st
        .finish(
            &mut rng,
            new_password.as_bytes(),
            &start.registration_response,
            &ksf(),
        )
        .unwrap();
    canary_b64(h, &fin.upload);
    let akek = derive_akek(&fin.export_key);
    let bundle =
        seal_private_bundle(&akek, a.user_id.as_bytes(), version, &a.keys, &mut rng).unwrap();
    canary_b64(h, &bundle);
    h.post(
        "/v1/account/password",
        Some(&a.access),
        serde_json::to_value(&PasswordChangeRequest {
            reauth_token: reauth_token.into(),
            registration_upload: fin.upload,
            private_bundle_enc: bundle,
            version,
        })
        .unwrap(),
    )
    .await
}

/// Checks that the session's private bundle opens with the password's export key.
pub async fn bundle_opens(h: &Harness, email: &str, password: &str, user_id: Uuid) -> bool {
    let (s, v, state) = login_start(h, email, password).await;
    assert_eq!(s, StatusCode::OK);
    let start: LoginStartResponse = serde_json::from_value(v).unwrap();
    let Ok(fin) = state.finish(
        &mut os_rng(),
        password.as_bytes(),
        &start.credential_response,
        &ksf(),
    ) else {
        return false;
    };
    let req = LoginFinishRequest {
        login_state_id: start.login_state_id,
        credential_finalization: fin.finalization,
        totp: None,
        device: LoginDevice::default(),
        purpose: LoginPurpose::Login,
    };
    let (s, v) = h
        .post(
            "/v1/auth/login/finish",
            None,
            serde_json::to_value(&req).unwrap(),
        )
        .await;
    if s != StatusCode::OK {
        return false;
    }
    let session: SessionResponse = serde_json::from_value(v).unwrap();
    h.canary(session.tokens.access_token.clone());
    h.canary(session.tokens.refresh_token.clone());
    let akek = derive_akek(&fin.export_key);
    open_private_bundle(
        &akek,
        user_id.as_bytes(),
        session.account_keys.version,
        &session.account_keys.private_bundle_enc,
    )
    .is_ok()
}

/// Issues a recovery code as the operator would (T86 `admin user
/// recovery-code`).
pub async fn recovery_code(h: &Harness, email: &str) -> String {
    let code = courier_ftp_server::routes::account::issue_recovery_code(h.store(), email, h.now())
        .await
        .unwrap()
        .expect("known email");
    h.canary(code.as_str());
    h.canary(code.replace('-', ""));
    h.canary(code.to_lowercase());
    code.to_string()
}

/// What a recovery attempt sends.
pub struct RecoveryAttempt {
    /// The finish request.
    pub request: RecoveryFinishRequest,
}

/// `recovery/start` + client work; returns the finish request ready to send
/// (`Err` with the start response when start failed).
pub async fn prepare_recovery(
    h: &Harness,
    a: &Account,
    code: &str,
    new_password: &str,
) -> Result<RecoveryAttempt, (StatusCode, Value)> {
    h.canary(new_password);
    let mut rng = os_rng();
    let (st, request) = client_registration_start(&mut rng, new_password.as_bytes()).unwrap();
    canary_b64(h, &request);
    let (s, v) = h
        .post(
            "/v1/account/recovery/start",
            None,
            serde_json::to_value(&RecoveryStartRequest {
                email: a.email.clone(),
                code: code.into(),
                registration_request: request,
            })
            .unwrap(),
        )
        .await;
    if s != StatusCode::OK {
        return Err((s, v));
    }
    let start: RecoveryStartResponse = serde_json::from_value(v).unwrap();
    assert_eq!(start.user_id, a.user_id);
    let keys = open_recovery_bundle(&a.recovery, a.user_id.as_bytes(), &start.recovery_bundle_enc)
        .expect("recovery bundle opens with the recovery key");
    let fin = st
        .finish(
            &mut rng,
            new_password.as_bytes(),
            &start.registration_response,
            &ksf(),
        )
        .unwrap();
    canary_b64(h, &fin.upload);
    let version = start.version + 1;
    let akek = derive_akek(&fin.export_key);
    let bundle =
        seal_private_bundle(&akek, a.user_id.as_bytes(), version, &keys, &mut rng).unwrap();
    canary_b64(h, &bundle);
    let msg = recovery_proof_message(a.user_id.as_bytes(), version, &fin.upload, &bundle);
    let signature = sign::sign(keys.ed25519_signing_key(), &msg);
    Ok(RecoveryAttempt {
        request: RecoveryFinishRequest {
            email: a.email.clone(),
            code: code.into(),
            registration_upload: fin.upload,
            private_bundle_enc: bundle,
            version,
            signature: signature.to_vec(),
        },
    })
}

/// Sends a recovery finish request.
pub async fn finish_recovery(h: &Harness, req: &RecoveryFinishRequest) -> (StatusCode, Value) {
    h.post(
        "/v1/account/recovery",
        None,
        serde_json::to_value(req).unwrap(),
    )
    .await
}
