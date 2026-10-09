//! Registration policy and first-start bootstrap.
//!
//! * **Modes** (`settings.registration_mode`): `open` (anyone; an invite is
//!   optional), `invite-only` (default; needs a valid invite or the setup token),
//!   `closed` (nobody; invites are rejected too). The **setup token** works in
//!   every mode while no account exists.
//! * **Setup token**: at `serve` start, while `users` is empty, [`bootstrap`]
//!   stores the hex SHA-256 of a fresh 32-byte token (replacing any previous one)
//!   and [`log_setup_token`] logs the token once at `warn`. The first registration
//!   with it becomes the instance admin and deletes the hash in the same
//!   transaction. Hashes are compared in constant time.
//! * **Invites**: valid iff not accepted, unexpired, the token hash matches and the
//!   bound email (if any) equals the normalized email. `org_id IS NULL` rows are
//!   instance invites (T86 `admin invite`); org invites are returned to T89.
//!
//! [`authorize`] is the single policy decision; both store backends gather the
//! [`PolicyFacts`] (PostgreSQL with row locks, inside the registration
//! transaction) and apply its [`Decision`].

use std::str::FromStr;

use courier_ftp_crypto::random;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::store::{RegistrationCredential, Store};
use crate::error::ApiError;
use crate::settings_kv;

/// 403 when the mode is `closed`.
pub const CLOSED_MESSAGE: &str = "registration is closed";
/// 403 in `invite-only` mode without an invite.
pub const INVITE_REQUIRED_MESSAGE: &str = "registration requires an invite";
/// 403 for an unknown, used, expired or foreign invite.
pub const INVALID_INVITE_MESSAGE: &str = "invalid or expired invite";
/// 403 for a wrong or used setup token.
pub const INVALID_SETUP_TOKEN_MESSAGE: &str = "invalid setup token";
/// 409 when the email is taken.
pub const EMAIL_TAKEN_MESSAGE: &str = "email already registered";
/// 409 when the personal vault id is taken.
pub const VAULT_TAKEN_MESSAGE: &str = "vault id already exists";

/// Who may register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistrationMode {
    /// Anyone.
    Open,
    /// Only with an invite or the setup token (the default).
    #[default]
    InviteOnly,
    /// Nobody (except the setup token while no account exists).
    Closed,
}

impl RegistrationMode {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InviteOnly => "invite-only",
            Self::Closed => "closed",
        }
    }

    /// The stored value; a missing row is `invite-only`, an unknown value `closed`
    /// (the safe choice).
    #[must_use]
    pub fn from_stored(value: Option<&str>) -> Self {
        value.map_or(Self::InviteOnly, |v| v.parse().unwrap_or(Self::Closed))
    }
}

impl std::fmt::Display for RegistrationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RegistrationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "open" => Ok(Self::Open),
            "invite-only" => Ok(Self::InviteOnly),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "unknown registration mode `{other}` (open, invite-only, closed)"
            )),
        }
    }
}

/// The credential a registration presents: the setup token wins over an invite.
#[must_use]
pub fn credential<'a>(
    setup_token: Option<&'a str>,
    invite_token: Option<&'a str>,
) -> RegistrationCredential<'a> {
    match (setup_token, invite_token) {
        (Some(t), _) => RegistrationCredential::SetupToken(t),
        (None, Some(t)) => RegistrationCredential::InviteToken(t),
        (None, None) => RegistrationCredential::None,
    }
}

/// A fresh 256-bit token, base64url without padding (43 chars).
#[must_use]
pub fn generate_token() -> Zeroizing<String> {
    let key = random::random_key32(&mut random::os_rng());
    Zeroizing::new(courier_ftp_proto::b64::encode(key.expose_secret()))
}

/// SHA-256 of a token as presented (trimmed): how setup and invite tokens are
/// stored.
#[must_use]
pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.trim().as_bytes()).into()
}

/// An `invites` row as the policy needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteFacts {
    /// Id.
    pub id: Uuid,
    /// The org of an org invite; `None` for an instance invite.
    pub org_id: Option<Uuid>,
    /// Bound email (normalized), if any.
    pub email: Option<String>,
    /// Stored token hash.
    pub token_hash: Vec<u8>,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Accepted already.
    pub accepted: bool,
}

/// What [`authorize`] decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFacts {
    /// The registration mode.
    pub mode: RegistrationMode,
    /// No account exists yet.
    pub no_users: bool,
    /// `settings.setup_token_hash` (hex), if present.
    pub setup_token_hash: Option<String>,
    /// The invite whose hash matches the presented invite token, if any.
    pub invite: Option<InviteFacts>,
}

/// The outcome of a successful [`authorize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Decision {
    /// The setup token was used: the account becomes instance admin and the hash
    /// is deleted.
    pub consume_setup_token: bool,
    /// The invite to mark accepted.
    pub accept_invite: Option<Uuid>,
    /// The org invite to apply once the account exists (T89).
    pub org_invite: Option<Uuid>,
}

/// The registration policy (see the module docs).
///
/// # Errors
/// [`ApiError::Forbidden`] with one of the documented messages.
pub fn authorize(
    facts: &PolicyFacts,
    email: &str,
    cred: RegistrationCredential<'_>,
    now: OffsetDateTime,
) -> Result<Decision, ApiError> {
    let forbidden = |m: &str| ApiError::Forbidden(m.to_owned());
    match cred {
        RegistrationCredential::SetupToken(token) => {
            let presented = hex::encode(hash_token(token));
            let matches = facts.setup_token_hash.as_deref().is_some_and(|stored| {
                bool::from(stored.as_bytes().ct_eq(presented.as_bytes()))
            });
            if facts.no_users && matches {
                Ok(Decision {
                    consume_setup_token: true,
                    ..Decision::default()
                })
            } else {
                Err(forbidden(INVALID_SETUP_TOKEN_MESSAGE))
            }
        }
        _ if facts.mode == RegistrationMode::Closed => Err(forbidden(CLOSED_MESSAGE)),
        RegistrationCredential::InviteToken(token) => {
            let hash = hash_token(token);
            let valid = facts.invite.as_ref().filter(|i| {
                bool::from(i.token_hash.as_slice().ct_eq(&hash))
                    && !i.accepted
                    && i.expires_at > now
                    && i.email.as_deref().is_none_or(|e| e == email)
            });
            match valid {
                Some(i) => Ok(Decision {
                    accept_invite: Some(i.id),
                    org_invite: i.org_id.map(|_| i.id),
                    ..Decision::default()
                }),
                None => Err(forbidden(INVALID_INVITE_MESSAGE)),
            }
        }
        RegistrationCredential::None => match facts.mode {
            RegistrationMode::Open => Ok(Decision::default()),
            _ => Err(forbidden(INVITE_REQUIRED_MESSAGE)),
        },
    }
}

/// First-start bootstrap: while no account exists, stores the hash of a fresh
/// setup token (replacing any previous one) and returns the token for
/// [`log_setup_token`].
///
/// # Errors
/// Store errors.
pub async fn bootstrap(
    store: &Store,
    now: OffsetDateTime,
) -> Result<Option<Zeroizing<String>>, ApiError> {
    if store.user_count().await? > 0 {
        return Ok(None);
    }
    let token = generate_token();
    store
        .set_setting(
            settings_kv::SETUP_TOKEN_HASH,
            &hex::encode(hash_token(&token)),
            now,
        )
        .await?;
    Ok(Some(token))
}

/// Logs the setup token once at `warn`: the only log line that ever carries a
/// token value (deliberately, for the operator).
pub fn log_setup_token(token: &str) {
    tracing::warn!(
        setup_token = token,
        "no account exists yet: register the first account with this setup token"
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn facts(mode: RegistrationMode) -> PolicyFacts {
        PolicyFacts {
            mode,
            no_users: true,
            setup_token_hash: Some(hex::encode(hash_token("setup"))),
            invite: None,
        }
    }

    fn invite(token: &str, email: Option<&str>) -> InviteFacts {
        InviteFacts {
            id: Uuid::now_v7(),
            org_id: None,
            email: email.map(str::to_owned),
            token_hash: hash_token(token).to_vec(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::days(7),
            accepted: false,
        }
    }

    fn code(r: Result<Decision, ApiError>) -> Result<Decision, String> {
        r.map_err(|e| e.to_string())
    }

    #[test]
    fn mode_parse_and_credential_precedence() {
        for m in [
            RegistrationMode::Open,
            RegistrationMode::InviteOnly,
            RegistrationMode::Closed,
        ] {
            assert_eq!(m.as_str().parse::<RegistrationMode>().unwrap(), m);
        }
        assert!("sometimes".parse::<RegistrationMode>().is_err());
        assert_eq!(
            RegistrationMode::from_stored(None),
            RegistrationMode::InviteOnly
        );
        assert_eq!(
            RegistrationMode::from_stored(Some("bogus")),
            RegistrationMode::Closed
        );

        // The setup token wins over an invite.
        assert_eq!(
            credential(Some("s"), Some("i")),
            RegistrationCredential::SetupToken("s")
        );
        assert_eq!(
            credential(None, Some("i")),
            RegistrationCredential::InviteToken("i")
        );
        assert_eq!(credential(None, None), RegistrationCredential::None);

        let now = OffsetDateTime::now_utc();
        let e = "a@example.test";
        // Setup token: every mode while there are no users; once only.
        for mode in [
            RegistrationMode::Open,
            RegistrationMode::InviteOnly,
            RegistrationMode::Closed,
        ] {
            let d = authorize(&facts(mode), e, RegistrationCredential::SetupToken("setup"), now)
                .unwrap();
            assert!(d.consume_setup_token);
        }
        let mut f = facts(RegistrationMode::InviteOnly);
        assert_eq!(
            code(authorize(&f, e, RegistrationCredential::SetupToken("nope"), now)),
            Err(INVALID_SETUP_TOKEN_MESSAGE.into())
        );
        f.no_users = false;
        assert_eq!(
            code(authorize(&f, e, RegistrationCredential::SetupToken("setup"), now)),
            Err(INVALID_SETUP_TOKEN_MESSAGE.into())
        );

        // Nothing presented: only `open`.
        assert!(authorize(&facts(RegistrationMode::Open), e, RegistrationCredential::None, now).is_ok());
        assert_eq!(
            code(authorize(
                &facts(RegistrationMode::InviteOnly),
                e,
                RegistrationCredential::None,
                now
            )),
            Err(INVITE_REQUIRED_MESSAGE.into())
        );
        assert_eq!(
            code(authorize(&facts(RegistrationMode::Closed), e, RegistrationCredential::None, now)),
            Err(CLOSED_MESSAGE.into())
        );

        // Invites: bound email, single use, expiry, and `closed` rejects them.
        let mut f = facts(RegistrationMode::InviteOnly);
        f.invite = Some(invite("inv", Some(e)));
        let d = authorize(&f, e, RegistrationCredential::InviteToken("inv"), now).unwrap();
        assert_eq!(d.accept_invite, f.invite.as_ref().map(|i| i.id));
        assert_eq!(d.org_invite, None);
        assert!(!d.consume_setup_token);
        assert_eq!(
            code(authorize(&f, "b@example.test", RegistrationCredential::InviteToken("inv"), now)),
            Err(INVALID_INVITE_MESSAGE.into())
        );
        assert_eq!(
            code(authorize(&f, e, RegistrationCredential::InviteToken("other"), now)),
            Err(INVALID_INVITE_MESSAGE.into())
        );
        let later = now + time::Duration::days(8);
        assert!(authorize(&f, e, RegistrationCredential::InviteToken("inv"), later).is_err());
        if let Some(i) = f.invite.as_mut() {
            i.accepted = true;
        }
        assert!(authorize(&f, e, RegistrationCredential::InviteToken("inv"), now).is_err());
        let mut f = facts(RegistrationMode::Closed);
        f.invite = Some(invite("inv", None));
        assert_eq!(
            code(authorize(&f, e, RegistrationCredential::InviteToken("inv"), now)),
            Err(CLOSED_MESSAGE.into())
        );
        // An org invite is reported for T89.
        let mut f = facts(RegistrationMode::Open);
        let mut org = invite("org", None);
        org.org_id = Some(Uuid::now_v7());
        f.invite = Some(org);
        let d = authorize(&f, e, RegistrationCredential::InviteToken("org"), now).unwrap();
        assert!(d.org_invite.is_some());
    }

    #[test]
    fn tokens_are_random_and_hash_stably() {
        let a = generate_token();
        assert_ne!(*a, *generate_token());
        assert_eq!(a.len(), 43);
        assert_eq!(hash_token(&a), hash_token(&format!(" {}\n", a.as_str())));
    }
}
