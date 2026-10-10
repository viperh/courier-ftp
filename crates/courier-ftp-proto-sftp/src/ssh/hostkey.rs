//! The host-key verification hook.
//!
//! [`connect`](super::connect) asks a [`HostKeyVerifier`] about the key the
//! server presents during the key exchange (russh's `check_server_key`); the
//! connection proceeds only when the verifier accepts it. The real verifier
//! (trusted keys in the vault, the trust prompt) is T21. This module only
//! defines the seam and [`AcceptAnyHostKey`], which is for tests.

use std::fmt;

use async_trait::async_trait;
use courier_ftp_core::{
    Result,
    events::{EventSender, SessionId},
    net::HostPort,
};
use russh::keys::{HashAlg, PublicKey};
use tokio_util::sync::CancellationToken;

/// What a verifier gets besides the key: the connection it is for and the
/// means to ask the user (through [`EventSender::ask`] with `session` and
/// `cancel`).
#[derive(Debug, Clone, Copy)]
pub struct HostKeyContext<'a> {
    /// The server as configured (not the proxy).
    pub host: &'a HostPort,
    /// The connection asking.
    pub session: SessionId,
    /// The event bus, for log lines and prompts.
    pub events: &'a EventSender,
    /// Fires when the connection attempt is abandoned.
    pub cancel: &'a CancellationToken,
}

/// Decides whether a server's host key is trusted.
///
/// Called once per connection, during the key exchange, after russh has
/// checked that the server holds the private key. For an OpenSSH host
/// certificate the certified key is passed.
#[async_trait]
pub trait HostKeyVerifier: Send + Sync + fmt::Debug {
    /// `Ok(true)` to go on, `Ok(false)` to abort with
    /// [`Error::HostKey`](courier_ftp_core::Error::HostKey). Any error aborts
    /// the connection with that error (e.g.
    /// [`Error::Cancelled`](courier_ftp_core::Error::Cancelled) when the user
    /// dismissed the prompt).
    async fn verify(&self, ctx: HostKeyContext<'_>, key: &PublicKey) -> Result<bool>;
}

/// **Tests only.** Accepts every host key, which disables protection against
/// man-in-the-middle attacks. Never use it for real connections; T21 provides
/// the verifier the application uses.
#[derive(Debug, Clone, Copy)]
pub struct AcceptAnyHostKey {
    _private: (),
}

impl AcceptAnyHostKey {
    /// The insecure verifier. The name is the warning.
    pub fn insecure_for_tests() -> Self {
        Self { _private: () }
    }
}

#[async_trait]
impl HostKeyVerifier for AcceptAnyHostKey {
    async fn verify(&self, _ctx: HostKeyContext<'_>, key: &PublicKey) -> Result<bool> {
        tracing::warn!(
            key = %describe_key(key),
            "host key accepted WITHOUT verification (test verifier)"
        );
        Ok(true)
    }
}

/// `ssh-ed25519 SHA256:…`: the key type and its SHA-256 fingerprint.
pub fn describe_key(key: &PublicKey) -> String {
    format!(
        "{} {}",
        key.algorithm().as_str(),
        key.fingerprint(HashAlg::Sha256)
    )
}
