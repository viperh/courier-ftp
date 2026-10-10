//! `/v1/ws` notification messages and close codes (T85 server, T88 client).
//!
//! JSON text messages tagged by `type`. The access token is never put in the
//! URL: the client's first message must be [`ClientMsg::Auth`] within
//! [`AUTH_TIMEOUT_SECS`], otherwise the server closes with
//! [`CLOSE_AUTH_REQUIRED`] (`4401`).
//!
//! | Direction | Message |
//! |---|---|
//! | client → server | `{"type":"auth","token":"..."}` (first message) |
//! | server → client | `{"type":"vault_changed","vault_id":"...","head_revision":7}` |
//! | server → client | `{"type":"vault_access","vault_id":"...","change":"granted\|revoked\|rotated"}` |
//! | server → client | `{"type":"account_changed","key_version":2}` |
//! | both | `{"type":"ping"}` / `{"type":"pong"}` every [`PING_INTERVAL_SECS`] |
//!
//! Close codes: [`CLOSE_AUTH_REQUIRED`] (no or invalid auth message, expired
//! access token, revoked device, disabled account: refresh, then reconnect)
//! and [`CLOSE_PING_TIMEOUT`] ([`MAX_MISSED_PONGS`] unanswered pings:
//! reconnect with backoff).
//!
//! Notifications are hints only; correctness comes from pulling, so a missed
//! message is harmless. Receivers must skip message types they don't know
//! (newer servers may add some): parsing fails for them, so log at debug and
//! carry on.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Path of the notification socket (under [`crate::version::API_PREFIX`]).
pub const WS_PATH: &str = "/ws";

/// Close code: authentication required or no longer valid.
pub const CLOSE_AUTH_REQUIRED: u16 = 4401;

/// Close code: the peer missed [`MAX_MISSED_PONGS`] pongs in a row.
pub const CLOSE_PING_TIMEOUT: u16 = 4408;

/// The auth message must arrive within this many seconds of the upgrade.
pub const AUTH_TIMEOUT_SECS: u64 = 5;

/// Both sides send `ping` this often.
pub const PING_INTERVAL_SECS: u64 = 30;

/// A side closes after this many consecutive pings without a `pong`.
pub const MAX_MISSED_PONGS: u32 = 2;

/// Largest text message either side accepts.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Client → server.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// The first message: the access token (never logged).
    Auth {
        /// The access token.
        token: String,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a server `ping`.
    Pong,
}

impl std::fmt::Debug for ClientMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth { .. } => f.write_str("Auth { token: [REDACTED] }"),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
        }
    }
}

/// What happened to the caller's access to a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChange {
    /// The caller became a member: fetch `GET /v1/vaults` for the wrapped key.
    Granted,
    /// The caller is no longer a member: drop the vault locally.
    Revoked,
    /// The vault key was rotated: refresh the vault key.
    Rotated,
}

/// Server → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// A push committed: pull if `head_revision` is beyond the local cursor.
    VaultChanged {
        /// The vault.
        vault_id: Uuid,
        /// Its new head revision.
        head_revision: u64,
    },
    /// Membership or key change.
    VaultAccess {
        /// The vault.
        vault_id: Uuid,
        /// What changed.
        change: AccessChange,
    },
    /// The account password / key bundle changed on another device.
    AccountChanged {
        /// The new account key version.
        key_version: u32,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a client `ping`.
    Pong,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn auth_token_is_redacted() {
        let m = ClientMsg::Auth {
            token: "secret".into(),
        };
        assert!(!format!("{m:?}").contains("secret"));
    }

    #[test]
    fn unknown_types_fail_so_receivers_can_skip_them() {
        assert!(serde_json::from_str::<ServerMsg>(r#"{"type":"future_thing"}"#).is_err());
        assert!(serde_json::from_str::<ServerMsg>(r#"{"type":"share_join_request"}"#).is_err());
    }

    #[test]
    fn extra_fields_are_ignored() {
        let m: ServerMsg =
            serde_json::from_str(r#"{"type":"account_changed","key_version":3,"new":1}"#).unwrap();
        assert_eq!(m, ServerMsg::AccountChanged { key_version: 3 });
    }
}
