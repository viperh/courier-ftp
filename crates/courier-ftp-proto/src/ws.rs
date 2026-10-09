//! `/v1/ws` live updates (T85): messages, close codes and timing.
//!
//! Text frames carry one JSON object each, tagged by `"type"`. The first client
//! frame must be [`ClientMsg::Auth`] within [`AUTH_TIMEOUT_SECS`]. Both sides send
//! `ping` every [`PING_INTERVAL_SECS`] and close after [`MAX_MISSED_PONGS`]
//! unanswered pings. Receivers ignore unknown types ([`ServerMsg::Unknown`]).

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The WebSocket path, under [`crate::version::API_PREFIX`].
pub const WS_PATH: &str = "/ws";
/// Close code: missing, invalid or late `auth`, or the token expired or was revoked.
pub const CLOSE_AUTH_REQUIRED: u16 = 4401;
/// Close code: too many unanswered pings.
pub const CLOSE_PING_TIMEOUT: u16 = 4408;
/// Close code: server error.
pub const CLOSE_INTERNAL: u16 = 1011;
/// Seconds the server waits for the `auth` message.
pub const AUTH_TIMEOUT_SECS: u64 = 5;
/// Both sides send `ping` this often.
pub const PING_INTERVAL_SECS: u64 = 30;
/// A side closes after this many consecutive pings without a `pong`.
pub const MAX_MISSED_PONGS: u32 = 2;
/// Largest client frame the server accepts.
pub const MAX_CLIENT_MESSAGE_BYTES: usize = 16 * 1024;

/// Client → server.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// The first message: the access token.
    Auth {
        /// The access token. Secret.
        token: String,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a server `ping`.
    Pong,
}

impl fmt::Debug for ClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth { .. } => f
                .debug_struct("Auth")
                .field("token", &crate::REDACTED)
                .finish(),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
        }
    }
}

/// What changed about the caller's access to a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChange {
    /// Access granted (or permission changed): refresh `GET /v1/vaults`.
    Granted,
    /// Access revoked: drop the local copy.
    Revoked,
    /// The vault key was rotated: refresh grants and pull.
    Rotated,
}

/// Server → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// A vault has new revisions: pull.
    VaultChanged {
        /// The vault.
        vault_id: Uuid,
        /// Its new head revision.
        head_revision: u64,
    },
    /// The caller's access to a vault changed.
    VaultAccess {
        /// The vault.
        vault_id: Uuid,
        /// What changed.
        change: AccessChange,
    },
    /// The account keys changed (password change or recovery on another device).
    AccountChanged {
        /// The new account key version.
        key_version: u32,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a client `ping`.
    Pong,
    /// Any `type` this client version does not know; ignored by receivers.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_type_is_ignored() {
        let m: ServerMsg = serde_json::from_str(
            r#"{"type":"share_join_request","share_id":"x","nested":{"a":[1,2]}}"#,
        )
        .unwrap();
        assert_eq!(m, ServerMsg::Unknown);
        // A known type with extra fields still decodes.
        let m: ServerMsg =
            serde_json::from_str(r#"{"type":"account_changed","key_version":3,"x":1}"#).unwrap();
        assert_eq!(m, ServerMsg::AccountChanged { key_version: 3 });
        // No `type` at all is an error.
        assert!(serde_json::from_str::<ServerMsg>(r#"{"key_version":3}"#).is_err());
    }

    #[test]
    fn wire_forms() {
        let m = ServerMsg::VaultChanged {
            vault_id: Uuid::from_u128(1),
            head_revision: 42,
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"vault_changed","vault_id":"00000000-0000-0000-0000-000000000001","head_revision":42}"#
        );
        let c = ClientMsg::Auth { token: "t".into() };
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"type":"auth","token":"t"}"#
        );
        assert_eq!(
            serde_json::from_str::<ClientMsg>(r#"{"type":"ping"}"#).unwrap(),
            ClientMsg::Ping
        );
        assert_eq!(format!("{:?}", ClientMsg::Pong), "Pong");
    }
}
