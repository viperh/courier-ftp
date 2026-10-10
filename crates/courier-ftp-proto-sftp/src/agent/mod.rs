//! The SSH agent client for the `Agent` logon type and "try agent first" (T20), copied
//! from sverb `agent_client.rs` (D13).
//!
//! Lists identities and signs through an agent reached over a Unix socket
//! (`SSH_AUTH_SOCK`) or, on Windows, `SSH_AUTH_SOCK` when it names a pipe, then the
//! OpenSSH pipe (`\\.\pipe\openssh-ssh-agent`), then Pageant (russh's Pageant client).
//!
//! [`AgentConnector`] opens a connection ([`Agent`]); the auth chain asks for a fresh one
//! per authentication. Failing to reach the agent is not an error for the user: the
//! chain logs `No SSH agent available` and goes on.

use std::fmt;

use async_trait::async_trait;
use russh::keys::{
    HashAlg,
    agent::{AgentIdentity, client::AgentClient},
};
use tracing::debug;

/// A connection to an agent.
pub type AgentStreamBox = Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>;

/// Why the agent could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ssh agent: {0}")]
pub struct AgentError(pub String);

impl From<russh::keys::Error> for AgentError {
    fn from(err: russh::keys::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<std::io::Error> for AgentError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

/// An open agent connection.
#[async_trait]
pub trait Agent: Send {
    /// The agent's identities (keys and certificates), in the agent's order.
    ///
    /// # Errors
    /// The agent failed or closed the connection.
    async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError>;

    /// Sign `data` with `identity` (RSA: with `hash`, `None` meaning SHA-1).
    ///
    /// # Errors
    /// The agent refused or failed.
    async fn sign(
        &mut self,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError>;
}

/// Opens agent connections.
#[async_trait]
pub trait AgentConnector: Send + Sync + fmt::Debug {
    /// A new connection.
    ///
    /// # Errors
    /// No agent is configured or it can't be reached.
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError>;
}

/// An agent over any byte stream (russh's client).
pub struct StreamAgent {
    client: AgentClient<AgentStreamBox>,
}

impl fmt::Debug for StreamAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamAgent").finish_non_exhaustive()
    }
}

impl StreamAgent {
    /// An agent speaking over `stream`.
    pub fn new(stream: AgentStreamBox) -> Self {
        Self {
            client: AgentClient::connect(stream),
        }
    }

    /// Add `key` to the agent (tests).
    ///
    /// # Errors
    /// The agent refused.
    pub async fn add(&mut self, key: &russh::keys::PrivateKey) -> Result<(), AgentError> {
        self.client.add_identity(key, &[]).await.map_err(Into::into)
    }
}

#[async_trait]
impl Agent for StreamAgent {
    async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        self.client.request_identities().await.map_err(Into::into)
    }

    async fn sign(
        &mut self,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        self.client
            .sign_request(identity, hash, data)
            .await
            .map_err(Into::into)
    }
}

/// The user's agent: `SSH_AUTH_SOCK` (Unix socket); on Windows `SSH_AUTH_SOCK` when it
/// names a pipe, then the OpenSSH pipe, then Pageant.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemAgent;

/// The OpenSSH for Windows agent pipe.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

#[async_trait]
impl AgentConnector for SystemAgent {
    #[cfg(unix)]
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        let Some(path) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) else {
            return Err(AgentError("SSH_AUTH_SOCK is not set".to_owned()));
        };
        let stream = tokio::net::UnixStream::connect(&path).await?;
        debug!("connected to the system agent");
        Ok(Box::new(StreamAgent::new(Box::new(stream))))
    }

    #[cfg(windows)]
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        let pipe = std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|p| p.starts_with(r"\\.\pipe\"))
            .unwrap_or_else(|| OPENSSH_PIPE.to_owned());
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe) {
            Ok(stream) => {
                debug!("connected to the OpenSSH agent pipe");
                return Ok(Box::new(StreamAgent::new(Box::new(stream))));
            }
            Err(err) => debug!(%err, "no OpenSSH agent pipe; trying Pageant"),
        }
        let client = AgentClient::connect_pageant().await?;
        debug!("connected to Pageant");
        Ok(Box::new(StreamAgent::new(client.into_inner())))
    }

    #[cfg(not(any(unix, windows)))]
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Err(AgentError("no system agent on this platform".to_owned()))
    }
}

/// An agent on a given Unix socket.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct SocketAgent {
    /// The socket.
    pub path: std::path::PathBuf,
}

#[cfg(unix)]
#[async_trait]
impl AgentConnector for SocketAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        let stream = tokio::net::UnixStream::connect(&self.path).await?;
        Ok(Box::new(StreamAgent::new(Box::new(stream))))
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testing;
