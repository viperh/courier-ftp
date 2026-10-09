//! The sync protocol: request, response and live-update types shared by
//! `courier-ftp-sync` and `courier-ftp-server` (T83, adapted from sverb).
//!
//! Serde only, no I/O: client and server can never disagree about a field name or a
//! limit, and the JSON decoders can be fuzzed in isolation ([`fuzz_decode_all`]).
//!
//! Common rules for every DTO:
//!
//! * unknown JSON fields are ignored on decode (a newer server may add fields);
//! * optional fields are omitted when `None`;
//! * ids are [`uuid::Uuid`], timestamps RFC 3339 UTC, binary fields base64url without
//!   padding ([`b64`]), revisions `u64`, key versions `u32`;
//! * DTOs with a secret field (tokens, TOTP codes, recovery codes, invite links)
//!   implement `Debug` by hand and print `[REDACTED]` instead.
//!
//! Layering: depends only on `courier-ftp-crypto`; used by `core`, `sync` and
//! the server.

pub mod auth;
pub mod b64;
pub mod error;
pub mod limits;
pub mod orgs;
pub mod rotation;
pub mod sync;
pub mod users;
pub mod validate;
pub mod vaults;
pub mod version;
pub mod ws;

pub use error::{ErrorBody, ErrorCode, ErrorEnvelope, ProtoError};

/// The redaction marker printed by hand-written `Debug` impls.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// `Debug` value for an optional secret: `Some("[REDACTED]")` or `None`.
pub(crate) const fn redact_opt(v: Option<&String>) -> Option<&'static str> {
    match v {
        Some(_) => Some(REDACTED),
        None => None,
    }
}

/// Fuzz body of the `sync_dto_decode` target (T91 §7): decodes `data` as every
/// request and response type, [`ws::ServerMsg`], [`ws::ClientMsg`] and
/// [`rotation::RotateRequest`], and runs every validation function. It must never
/// panic; `tests/props.rs` runs it on random input on stable.
#[doc(hidden)]
pub fn fuzz_decode_all(data: &[u8]) {
    fn dec<T: serde::de::DeserializeOwned>(data: &[u8]) -> Option<T> {
        serde_json::from_slice(data).ok()
    }
    macro_rules! decode_all {
        ($($t:ty),* $(,)?) => { $( let _ = dec::<$t>(data); )* };
    }

    decode_all!(
        error::ErrorEnvelope,
        error::ErrorBody,
        error::ErrorCode,
        auth::RegisterStartRequest,
        auth::RegisterStartResponse,
        auth::AccountKeysUpload,
        auth::GrantUpload,
        auth::PersonalVaultUpload,
        auth::DeviceInfo,
        auth::RegisterFinishRequest,
        auth::LoginStartRequest,
        auth::LoginStartResponse,
        auth::LoginPurpose,
        auth::LoginDevice,
        auth::LoginFinishRequest,
        auth::TokenPair,
        auth::AccountKeysView,
        auth::SessionResponse,
        auth::ReauthResponse,
        auth::RefreshRequest,
        Vec<auth::DeviceView>,
        auth::TotpRequest,
        auth::TotpSetupResponse,
        auth::TotpStatus,
        auth::PasswordStartRequest,
        auth::PasswordStartResponse,
        auth::PasswordChangeRequest,
        auth::KeyVersionResponse,
        auth::RecoveryCodeRequest,
        auth::RecoveryStartRequest,
        auth::RecoveryStartResponse,
        auth::RecoveryFinishRequest,
        auth::AccountDeleteRequest,
        Vec<sync::VaultView>,
        sync::PullQuery,
        sync::PullResponse,
        sync::PushResponse,
        users::UserPublicKeys,
        orgs::CreateOrgRequest,
        Vec<orgs::OrgView>,
        Vec<orgs::MemberView>,
        orgs::UpdateMemberRequest,
        orgs::CreateInviteRequest,
        orgs::InviteCreated,
        orgs::InviteAccepted,
        orgs::AuditQuery,
        orgs::AuditPage,
        vaults::CreateVaultRequest,
        vaults::GrantRequest,
        vaults::VaultMembersView,
        Vec<vaults::OrgVaultView>,
        rotation::RotateResponse,
        ws::ClientMsg,
        ws::ServerMsg,
    );

    if let Some(req) = dec::<sync::PushRequest>(data) {
        let _ = req.validate();
    }
    if let Some(req) = dec::<rotation::RotateRequest>(data) {
        let _ = req.validate();
    }
    if let Some(members) = dec::<vaults::VaultMembersView>(data) {
        for m in &members.members {
            let _ = m.effective();
        }
    }
    let _ = version::negotiate(Some(data));
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = b64::decode(s);
        let _ = validate::normalize_email(s);
        let _ = validate::device_field(Some(s));
        let _ = validate::validate_org_name(s);
        let _ = sync::Permission::parse(s);
        let _ = sync::VaultKind::parse(s);
        let _ = orgs::Role::parse(s);
    }
}
