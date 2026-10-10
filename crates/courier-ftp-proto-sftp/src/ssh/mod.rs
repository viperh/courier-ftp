//! SSH connections over russh (T20). **All russh API usage stays in `ssh/`, `keys/` and
//! `agent/`**, so an upstream rename touches only these modules (as in sverb).
//!
//! [`SshConnection::connect`]: TCP through the T07 network layer → SSH handshake (host
//! key via the [`HostKeyVerifier`] seam, T21) → the authentication chain
//! ([`auth`]) → keepalive. Prompts go to the UI through the T04 prompt mechanism; no
//! secret is ever logged. T22 opens the `sftp` subsystem on the result.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{Error, events::SessionLog};
use russh::{ChannelMsg, client};
use tokio_util::sync::CancellationToken;

pub mod algorithms;
pub mod auth;
mod connect;
pub mod errors;
pub mod handler;
mod logon;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

pub use auth::{
    KBD_ROUNDS, MAX_AUTH_ATTEMPTS, MAX_KBD_PROMPTS, MAX_PROMPT_TEXT, PASSPHRASE_TRIES,
    PASSWORD_PROMPTS,
};
pub use errors::SshError;
#[cfg(any(test, feature = "test-util"))]
pub use handler::InsecureAcceptAnyHostKey;
pub use handler::{
    HostKeyVerdict, HostKeyVerifier, MAX_BANNER_CHARS, MAX_BANNER_LINES, ServerKey,
    UnverifiedHostKeys, VerifyCtx,
};
pub use logon::{NOT_FOR_SFTP, SshConnectParams, SshLogon};

use crate::agent::AgentConnector;
use handler::{ClientHandler, Shared};

/// What was negotiated (shown by the server info dialog, T57).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshSessionInfo {
    /// Sanitized, e.g. `"SSH-2.0-OpenSSH_9.6p1"`.
    pub server_version: String,
    /// Key exchange.
    pub kex: String,
    /// Host-key algorithm.
    pub host_key_algorithm: String,
    /// `"SHA256:…"`.
    pub host_key_fingerprint: String,
    /// Cipher.
    pub cipher: String,
    /// `"(implicit)"` for AEAD ciphers.
    pub mac: String,
    /// Compression.
    pub compression: String,
    /// The method that succeeded: `"password"`, `"publickey"`, …
    pub auth_method: String,
}

/// How long [`SshConnection::disconnect`] waits for the message to be sent.
pub const DISCONNECT_WAIT: Duration = Duration::from_secs(2);

/// An authenticated SSH connection.
pub struct SshConnection {
    handle: client::Handle<ClientHandler>,
    shared: Arc<Shared>,
    info: SshSessionInfo,
    keepalive_secs: u64,
    timeout: Duration,
    peer_addr: std::net::SocketAddr,
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl SshConnection {
    /// TCP (through T07) → SSH handshake (host key via `verifier`) → authentication.
    /// Prompts are sent through `log.events` (T04) for session `log.session` and
    /// awaited; `cancel` aborts at any point.
    ///
    /// # Errors
    /// See the T20 "Errors" table: `InvalidInput`, T07's `Connection`/`Timeout`/`Proxy`,
    /// `Timeout` (handshake), `Connection` (no common algorithm, server disconnect),
    /// `HostKey`, `Auth`, `Cancelled`, `ConnectionLimit`.
    pub async fn connect(
        params: SshConnectParams,
        verifier: Arc<dyn HostKeyVerifier>,
        agent: Option<Arc<dyn AgentConnector>>,
        log: &SessionLog,
        cancel: CancellationToken,
    ) -> Result<Self, Error> {
        connect::connect(params, verifier, agent, log, cancel).await
    }

    /// Open a `session` channel and request the subsystem `name` (`sftp`, used by T22).
    ///
    /// # Errors
    /// `Connection` when the channel can't be opened or the server refuses the
    /// subsystem; `Timeout` without a reply.
    pub async fn open_subsystem(
        &self,
        name: &str,
    ) -> Result<russh::ChannelStream<client::Msg>, Error> {
        let opened = async {
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(|e| self.channel_error(&e))?;
            channel
                .request_subsystem(true, name)
                .await
                .map_err(|e| self.channel_error(&e))?;
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Success) => return Ok(channel.into_stream()),
                    Some(ChannelMsg::Failure) => {
                        return Err(Error::Connection(format!(
                            "The server refused the {name} subsystem"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        return Err(Error::Connection(format!(
                            "The channel closed before the {name} subsystem started"
                        )));
                    }
                }
            }
        };
        tokio::time::timeout(self.timeout, opened)
            .await
            .map_err(|_| Error::Timeout)?
    }

    fn channel_error(&self, err: &russh::Error) -> Error {
        match self.shared.end.borrow().as_ref() {
            Some(cause) => cause.to_error(self.keepalive_secs).into_core(),
            None => Error::Connection(format!("Could not open a channel: {err}")),
        }
    }

    /// What was negotiated.
    pub fn info(&self) -> &SshSessionInfo {
        &self.info
    }

    /// The host key the server presented.
    pub fn host_key(&self) -> Option<ServerKey> {
        handler::lock(&self.shared.host_key).clone()
    }

    /// The connected peer: the server, or the proxy when proxied (T07).
    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    /// False once the transport closed (keepalive timeout, server disconnect).
    pub fn is_open(&self) -> bool {
        !self.handle.is_closed() && !*self.shared.closed.borrow()
    }

    /// Why the transport closed, if it did (for the error message), e.g.
    /// "Connection lost (no response for 90 s)".
    pub fn end_cause(&self) -> Option<String> {
        if let Some(cause) = self.shared.end.borrow().as_ref() {
            return Some(cause.describe(self.keepalive_secs));
        }
        (!self.is_open()).then(|| "Server closed the connection".to_owned())
    }

    /// `SSH_MSG_DISCONNECT` (reason ByApplication), bounded by [`DISCONNECT_WAIT`].
    pub async fn disconnect(self) {
        let _ = tokio::time::timeout(
            DISCONNECT_WAIT,
            self.handle
                .disconnect(russh::Disconnect::ByApplication, "", "en"),
        )
        .await;
    }
}
