//! Registration, login, tokens, devices, TOTP, password change, recovery and
//! account deletion (T84).
//!
//! Binary fields (OPAQUE messages, keys, bundles, grants) are base64url without
//! padding ([`crate::b64`]). Tokens are opaque base64url strings.
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/auth/register/start` | [`RegisterStartRequest`] | [`RegisterStartResponse`] |
//! | `POST /v1/auth/register/finish` | [`RegisterFinishRequest`] | [`SessionResponse`] |
//! | `POST /v1/auth/login/start` | [`LoginStartRequest`] | [`LoginStartResponse`] |
//! | `POST /v1/auth/login/finish` | [`LoginFinishRequest`] | [`SessionResponse`] or [`ReauthResponse`] |
//! | `POST /v1/auth/refresh` | [`RefreshRequest`] | [`TokenPair`] |
//! | `POST /v1/auth/logout` | – | 204 |
//! | `GET /v1/devices` | – | `[`[`DeviceView`]`]` |
//! | `DELETE /v1/devices/{id}` | – | 204 |
//! | `POST /v1/account/totp` | [`TotpRequest`] | [`TotpSetupResponse`] / [`TotpStatus`] |
//! | `DELETE /v1/account/totp` | [`TotpRequest`] | 204 |
//! | `POST /v1/account/password/start` | [`PasswordStartRequest`] | [`PasswordStartResponse`] |
//! | `POST /v1/account/password` | [`PasswordChangeRequest`] | [`KeyVersionResponse`] |
//! | `POST /v1/account/recovery/code` | [`RecoveryCodeRequest`] | 202 |
//! | `POST /v1/account/recovery/start` | [`RecoveryStartRequest`] | [`RecoveryStartResponse`] |
//! | `POST /v1/account/recovery` | [`RecoveryFinishRequest`] | [`KeyVersionResponse`] |
//! | `DELETE /v1/account` | [`AccountDeleteRequest`] | 204 |

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{REDACTED, redact_opt};

// ------------------------------------------------------------ registration

/// `POST /v1/auth/register/start`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    /// Account email.
    pub email: String,
    /// OPAQUE `RegistrationRequest`.
    #[serde(with = "crate::b64")]
    pub registration_request: Vec<u8>,
    /// Invite token (instance or org invite), if any. Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    /// The bootstrap setup token (first account only). Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
}

impl fmt::Debug for RegisterStartRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterStartRequest")
            .field("email", &self.email)
            .field("registration_request", &self.registration_request)
            .field("invite_token", &redact_opt(self.invite_token.as_ref()))
            .field("setup_token", &redact_opt(self.setup_token.as_ref()))
            .finish()
    }
}

/// Response to [`RegisterStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE `RegistrationResponse`.
    #[serde(with = "crate::b64")]
    pub registration_response: Vec<u8>,
    /// Fresh UUIDv7 proposed by the server; the client binds the bundle AAD and the
    /// self-grant signature to it and echoes it in [`RegisterFinishRequest`].
    pub user_id: Uuid,
}

/// Public keys and sealed bundles uploaded at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeysUpload {
    /// X25519 public key ([`crate::limits::X25519_PUB_LEN`] bytes).
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key ([`crate::limits::ED25519_PUB_LEN`] bytes).
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
    /// Private bundle sealed under the AKEK ([`crate::limits::ACCOUNT_BUNDLE_LEN`] bytes).
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// Recovery bundle sealed under the recovery key
    /// ([`crate::limits::ACCOUNT_BUNDLE_LEN`] bytes).
    #[serde(with = "crate::b64")]
    pub recovery_bundle_enc: Vec<u8>,
    /// Account key version; 1 at registration.
    pub version: u32,
}

/// A signed, HPKE-wrapped vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantUpload {
    /// The wrapped vault key (T80 grant wire format).
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// Ed25519 signature ([`crate::limits::SIGNATURE_LEN`] bytes).
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// Vault key version.
    pub key_version: u32,
}

/// The personal vault created at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalVaultUpload {
    /// The local personal vault id (kept).
    pub id: Uuid,
    /// Vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// The owner's self-grant.
    pub self_grant: GrantUpload,
}

/// A device as described by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Human-readable name ("laptop").
    pub name: String,
    /// `"linux"`, `"macos"`, `"windows"` or another platform name.
    pub platform: String,
}

/// `POST /v1/auth/register/finish` → [`SessionResponse`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    /// Account email (as in start).
    pub email: String,
    /// The id from [`RegisterStartResponse::user_id`].
    pub user_id: Uuid,
    /// OPAQUE `RegistrationUpload`.
    #[serde(with = "crate::b64")]
    pub registration_upload: Vec<u8>,
    /// Keys and bundles.
    pub account_keys: AccountKeysUpload,
    /// The personal vault and its self-grant.
    pub personal_vault: PersonalVaultUpload,
    /// This device.
    pub device: DeviceInfo,
    /// Invite token (checked and consumed here). Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    /// Setup token (checked and consumed here). Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
}

impl fmt::Debug for RegisterFinishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterFinishRequest")
            .field("email", &self.email)
            .field("user_id", &self.user_id)
            .field("registration_upload", &self.registration_upload)
            .field("account_keys", &self.account_keys)
            .field("personal_vault", &self.personal_vault)
            .field("device", &self.device)
            .field("invite_token", &redact_opt(self.invite_token.as_ref()))
            .field("setup_token", &redact_opt(self.setup_token.as_ref()))
            .finish()
    }
}

// ------------------------------------------------------------------- login

/// `POST /v1/auth/login/start` (same response shape for unknown emails).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartRequest {
    /// Account email.
    pub email: String,
    /// OPAQUE `CredentialRequest` (KE1).
    #[serde(with = "crate::b64")]
    pub credential_request: Vec<u8>,
}

/// Response to [`LoginStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// OPAQUE `CredentialResponse` (KE2).
    #[serde(with = "crate::b64")]
    pub credential_response: Vec<u8>,
    /// Handle of the server-side login state (expires after 60 s).
    pub login_state_id: Uuid,
}

/// What a login is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPurpose {
    /// A normal login: creates or resumes a device and issues tokens.
    #[default]
    Login,
    /// A fresh password proof for a sensitive operation (password change, account
    /// deletion): returns a short-lived reauth token and no session tokens.
    Reauth,
}

/// The device a login is for. All fields optional; the default is a new device
/// named `"unknown"`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginDevice {
    /// Existing, unrevoked device of this account to resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Name for a new device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Platform for a new device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// `POST /v1/auth/login/finish` → [`SessionResponse`] (login) or
/// [`ReauthResponse`] (reauth).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    /// From [`LoginStartResponse`].
    pub login_state_id: Uuid,
    /// OPAQUE `CredentialFinalization` (KE3).
    #[serde(with = "crate::b64")]
    pub credential_finalization: Vec<u8>,
    /// Current TOTP code, when the account has TOTP enabled. Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// The device (ignored for [`LoginPurpose::Reauth`]).
    #[serde(default)]
    pub device: LoginDevice,
    /// Login or reauth.
    #[serde(default)]
    pub purpose: LoginPurpose,
}

impl fmt::Debug for LoginFinishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFinishRequest")
            .field("login_state_id", &self.login_state_id)
            .field("credential_finalization", &self.credential_finalization)
            .field("totp", &redact_opt(self.totp.as_ref()))
            .field("device", &self.device)
            .field("purpose", &self.purpose)
            .finish()
    }
}

/// Access and refresh token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPair {
    /// Bearer token for API calls: 43 chars base64url (32 random bytes). Secret.
    pub access_token: String,
    /// Single-use refresh token, rotated on every use. Secret.
    pub refresh_token: String,
    /// Access-token lifetime in seconds (900).
    pub access_expires_in_s: u64,
    /// Refresh-token lifetime in seconds (2 592 000).
    pub refresh_expires_in_s: u64,
}

impl fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenPair")
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("access_expires_in_s", &self.access_expires_in_s)
            .field("refresh_expires_in_s", &self.refresh_expires_in_s)
            .finish()
    }
}

/// The account key material a device needs after login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeysView {
    /// X25519 public key.
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key.
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
    /// Private bundle sealed under the AKEK (bound to `version`).
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// Account key version.
    pub version: u32,
}

/// Successful registration or login. Its `Debug` redacts the tokens through
/// [`TokenPair`]'s `Debug`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// The account.
    pub user_id: Uuid,
    /// The device the tokens are bound to.
    pub device_id: Uuid,
    /// Tokens.
    pub tokens: TokenPair,
    /// Account keys.
    pub account_keys: AccountKeysView,
    /// Whether the account is the instance admin.
    #[serde(default)]
    pub is_instance_admin: bool,
}

/// Successful [`LoginPurpose::Reauth`] login.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReauthResponse {
    /// The account.
    pub user_id: Uuid,
    /// Single-use proof of a fresh login. Secret.
    pub reauth_token: String,
    /// Lifetime in seconds (300).
    pub reauth_expires_in_s: u64,
}

impl fmt::Debug for ReauthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReauthResponse")
            .field("user_id", &self.user_id)
            .field("reauth_token", &REDACTED)
            .field("reauth_expires_in_s", &self.reauth_expires_in_s)
            .finish()
    }
}

/// `POST /v1/auth/refresh` → [`TokenPair`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// The current refresh token. Secret.
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshRequest([REDACTED])")
    }
}

// ----------------------------------------------------------------- devices

/// One entry of `GET /v1/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceView {
    /// Device id.
    pub id: Uuid,
    /// Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Creation time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub created_at: Option<OffsetDateTime>,
    /// Last token use (at most 5 minutes stale).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_seen_at: Option<OffsetDateTime>,
    /// Whether this is the calling device.
    pub current: bool,
    /// Revocation time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub revoked_at: Option<OffsetDateTime>,
}

// ----------------------------------------------------------------- account

/// `POST|DELETE /v1/account/totp`.
///
/// `POST` without `code` starts enabling (the server returns a
/// [`TotpSetupResponse`]); `POST` with `code` confirms ([`TotpStatus`]). `DELETE`
/// requires a current `code`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpRequest {
    /// Current 6-digit code. Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl fmt::Debug for TotpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpRequest")
            .field("code", &redact_opt(self.code.as_ref()))
            .finish()
    }
}

/// A pending TOTP secret for the authenticator app.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    /// `otpauth://totp/…` URI (for a QR code; contains the secret).
    pub otpauth_uri: String,
    /// The secret in base32 (manual entry). Secret.
    pub secret_base32: String,
}

impl fmt::Debug for TotpSetupResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSetupResponse([REDACTED])")
    }
}

/// TOTP state after a confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpStatus {
    /// Whether login now requires a code.
    pub enabled: bool,
}

/// `POST /v1/account/password/start`: OPAQUE registration step 1 for the new
/// password (authenticated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStartRequest {
    /// OPAQUE `RegistrationRequest` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_request: Vec<u8>,
}

/// Response to [`PasswordStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStartResponse {
    /// OPAQUE `RegistrationResponse`.
    #[serde(with = "crate::b64")]
    pub registration_response: Vec<u8>,
}

/// `POST /v1/account/password` → [`KeyVersionResponse`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordChangeRequest {
    /// From a [`LoginPurpose::Reauth`] login within the last 5 minutes. Secret.
    pub reauth_token: String,
    /// OPAQUE `RegistrationUpload` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_upload: Vec<u8>,
    /// Private bundle re-sealed under the new AKEK and `version`.
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// The current account key version + 1.
    pub version: u32,
}

impl fmt::Debug for PasswordChangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordChangeRequest")
            .field("reauth_token", &REDACTED)
            .field("registration_upload", &self.registration_upload)
            .field("private_bundle_enc", &self.private_bundle_enc)
            .field("version", &self.version)
            .finish()
    }
}

/// The account key version after a password change or recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVersionResponse {
    /// The new account key version.
    pub version: u32,
}

/// `POST /v1/account/recovery/code`: mail a one-time recovery code (202 either way).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCodeRequest {
    /// Account email.
    pub email: String,
}

/// `POST /v1/account/recovery/start` → [`RecoveryStartResponse`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStartRequest {
    /// Account email.
    pub email: String,
    /// One-time recovery code. Secret.
    pub code: String,
    /// OPAQUE `RegistrationRequest` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_request: Vec<u8>,
}

impl fmt::Debug for RecoveryStartRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryStartRequest")
            .field("email", &self.email)
            .field("code", &REDACTED)
            .field("registration_request", &self.registration_request)
            .finish()
    }
}

/// Response to [`RecoveryStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStartResponse {
    /// The account.
    pub user_id: Uuid,
    /// Recovery bundle sealed under the recovery key.
    #[serde(with = "crate::b64")]
    pub recovery_bundle_enc: Vec<u8>,
    /// OPAQUE `RegistrationResponse` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_response: Vec<u8>,
    /// The current account key version (the new one is this + 1).
    pub version: u32,
}

/// `POST /v1/account/recovery` → [`KeyVersionResponse`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryFinishRequest {
    /// Account email.
    pub email: String,
    /// The same one-time code (consumed here). Secret.
    pub code: String,
    /// OPAQUE `RegistrationUpload` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_upload: Vec<u8>,
    /// Private bundle sealed under the new AKEK and `version`.
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// The current version + 1.
    pub version: u32,
    /// Ed25519 by the account key over T80 `opaque::recovery_proof_message(user_id,
    /// version, registration_upload, private_bundle_enc)`.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl fmt::Debug for RecoveryFinishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryFinishRequest")
            .field("email", &self.email)
            .field("code", &REDACTED)
            .field("registration_upload", &self.registration_upload)
            .field("private_bundle_enc", &self.private_bundle_enc)
            .field("version", &self.version)
            .field("signature", &self.signature)
            .finish()
    }
}

/// `DELETE /v1/account`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDeleteRequest {
    /// From a [`LoginPurpose::Reauth`] login within the last 5 minutes. Secret.
    pub reauth_token: String,
}

impl fmt::Debug for AccountDeleteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountDeleteRequest([REDACTED])")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::orgs::{InviteCreated, Role};
    use crate::ws::ClientMsg;

    #[test]
    fn binary_fields_are_base64url_unpadded() {
        let req = LoginStartRequest {
            email: "a@example.com".into(),
            credential_request: vec![0xfb, 0xff],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["credential_request"], "-_8");
        let back: LoginStartRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
        for bad in ["-_8=", "+/8"] {
            let s = format!(r#"{{"email":"a@b.c","credential_request":"{bad}"}}"#);
            assert!(serde_json::from_str::<LoginStartRequest>(&s).is_err());
        }
    }

    #[test]
    fn login_finish_defaults() {
        let req: LoginFinishRequest = serde_json::from_value(serde_json::json!({
            "login_state_id": Uuid::nil(),
            "credential_finalization": "AA",
        }))
        .unwrap();
        assert_eq!(req.purpose, LoginPurpose::Login);
        assert_eq!(req.device, LoginDevice::default());
        assert!(req.totp.is_none());
        let reauth: LoginPurpose = serde_json::from_str(r#""reauth""#).unwrap();
        assert_eq!(reauth, LoginPurpose::Reauth);
    }

    #[test]
    fn secrets_redacted_in_debug() {
        const C: &str = "CANARY-TOKEN-0123456789";
        let canary = || C.to_owned();
        let keys = AccountKeysUpload {
            x25519_pub: vec![1],
            ed25519_pub: vec![2],
            private_bundle_enc: vec![3],
            recovery_bundle_enc: vec![4],
            version: 1,
        };
        let vault = PersonalVaultUpload {
            id: Uuid::nil(),
            name_enc: vec![5],
            self_grant: GrantUpload {
                wrapped_vault_key: vec![6],
                signature: vec![7],
                key_version: 1,
            },
        };
        let tokens = TokenPair {
            access_token: canary(),
            refresh_token: canary(),
            access_expires_in_s: 900,
            refresh_expires_in_s: 2_592_000,
        };
        let session = SessionResponse {
            user_id: Uuid::nil(),
            device_id: Uuid::nil(),
            tokens: tokens.clone(),
            account_keys: AccountKeysView {
                x25519_pub: vec![1],
                ed25519_pub: vec![2],
                private_bundle_enc: vec![3],
                version: 1,
            },
            is_instance_admin: false,
        };
        let outputs = [
            format!("{tokens:?}"),
            format!("{session:?}"),
            format!(
                "{:?}",
                RefreshRequest {
                    refresh_token: canary()
                }
            ),
            format!(
                "{:?}",
                RegisterStartRequest {
                    email: "a@b.c".into(),
                    registration_request: vec![1],
                    invite_token: Some(canary()),
                    setup_token: Some(canary()),
                }
            ),
            format!(
                "{:?}",
                RegisterFinishRequest {
                    email: "a@b.c".into(),
                    user_id: Uuid::nil(),
                    registration_upload: vec![1],
                    account_keys: keys,
                    personal_vault: vault,
                    device: DeviceInfo {
                        name: "laptop".into(),
                        platform: "linux".into(),
                    },
                    invite_token: Some(canary()),
                    setup_token: Some(canary()),
                }
            ),
            format!(
                "{:?}",
                LoginFinishRequest {
                    login_state_id: Uuid::nil(),
                    credential_finalization: vec![1],
                    totp: Some(canary()),
                    device: LoginDevice::default(),
                    purpose: LoginPurpose::Login,
                }
            ),
            format!(
                "{:?}",
                ReauthResponse {
                    user_id: Uuid::nil(),
                    reauth_token: canary(),
                    reauth_expires_in_s: 300,
                }
            ),
            format!(
                "{:?}",
                TotpRequest {
                    code: Some(canary())
                }
            ),
            format!(
                "{:?}",
                TotpSetupResponse {
                    otpauth_uri: format!("otpauth://totp/x?secret={C}"),
                    secret_base32: canary(),
                }
            ),
            format!(
                "{:?}",
                PasswordChangeRequest {
                    reauth_token: canary(),
                    registration_upload: vec![1],
                    private_bundle_enc: vec![2],
                    version: 2,
                }
            ),
            format!(
                "{:?}",
                RecoveryStartRequest {
                    email: "a@b.c".into(),
                    code: canary(),
                    registration_request: vec![1],
                }
            ),
            format!(
                "{:?}",
                RecoveryFinishRequest {
                    email: "a@b.c".into(),
                    code: canary(),
                    registration_upload: vec![1],
                    private_bundle_enc: vec![2],
                    version: 2,
                    signature: vec![3],
                }
            ),
            format!(
                "{:?}",
                AccountDeleteRequest {
                    reauth_token: canary()
                }
            ),
            format!(
                "{:?}",
                InviteCreated {
                    id: Uuid::nil(),
                    org_id: Uuid::nil(),
                    email: None,
                    role: Role::Member,
                    expires_at: OffsetDateTime::UNIX_EPOCH,
                    link: Some(format!("https://sync.example/invite/{C}")),
                    emailed: false,
                }
            ),
            format!("{:?}", ClientMsg::Auth { token: canary() }),
        ];
        for out in outputs {
            assert!(!out.contains("CANARY"), "secret leaked: {out}");
            assert!(out.contains("REDACTED"), "no redaction marker: {out}");
        }
        // Absent secrets print as `None`.
        let none = format!("{:?}", TotpRequest { code: None });
        assert_eq!(none, "TotpRequest { code: None }");
    }
}
