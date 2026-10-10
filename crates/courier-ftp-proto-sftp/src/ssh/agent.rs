//! SSH agent access (logon type "Agent").
//!
//! [`SystemAgent`] reaches the user's agent:
//!
//! - Unix: the socket named by `SSH_AUTH_SOCK`;
//! - Windows: `SSH_AUTH_SOCK` when it names a pipe, else the OpenSSH for
//!   Windows pipe [`OPENSSH_PIPE`], else **Pageant** (russh's Pageant client).
//!
//! russh's [`AgentClient`] lists the identities and signs the authentication
//! requests (it implements russh's `Signer`).

use std::fmt;

use async_trait::async_trait;
use russh::keys::agent::client::{AgentClient, AgentStream};

/// A connection to an agent over any byte stream.
pub type AgentStreamBox = Box<dyn AgentStream + Send + Unpin>;

/// An open agent connection.
pub type Agent = AgentClient<AgentStreamBox>;

/// The OpenSSH for Windows agent pipe.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Opens agent connections.
#[async_trait]
pub trait AgentConnector: Send + Sync + fmt::Debug {
    /// A new connection, or why there is none (shown to the user).
    async fn connect(&self) -> Result<Agent, String>;
}

/// The user's agent (see the module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemAgent;

#[async_trait]
impl AgentConnector for SystemAgent {
    #[cfg(unix)]
    async fn connect(&self) -> Result<Agent, String> {
        let Some(path) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) else {
            return Err("no SSH agent is running (SSH_AUTH_SOCK is not set)".to_owned());
        };
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .map_err(|e| format!("cannot reach the SSH agent: {e}"))?;
        Ok(AgentClient::connect(Box::new(stream) as AgentStreamBox))
    }

    #[cfg(windows)]
    async fn connect(&self) -> Result<Agent, String> {
        let pipe = std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|p| p.starts_with(r"\\.\pipe\"))
            .unwrap_or_else(|| OPENSSH_PIPE.to_owned());
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe) {
            Ok(stream) => return Ok(AgentClient::connect(Box::new(stream) as AgentStreamBox)),
            Err(err) => tracing::debug!(%err, "no OpenSSH agent pipe; trying Pageant"),
        }
        let client = AgentClient::connect_pageant()
            .await
            .map_err(|e| format!("no SSH agent or Pageant is running: {e}"))?;
        Ok(AgentClient::connect(client.into_inner()))
    }

    #[cfg(not(any(unix, windows)))]
    async fn connect(&self) -> Result<Agent, String> {
        Err("SSH agents are not supported on this platform".to_owned())
    }
}

/// **Tests only** (`test-util`): an in-process agent (russh's agent server
/// over in-memory pipes) holding the keys it was given. Never touches
/// `SSH_AUTH_SOCK`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone)]
pub struct InProcessAgent {
    tx: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
}

#[cfg(any(test, feature = "test-util"))]
impl fmt::Debug for InProcessAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessAgent").finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl InProcessAgent {
    /// Start an agent holding `keys` (inside a tokio runtime).
    ///
    /// # Errors
    /// Adding a key failed.
    pub async fn start(keys: &[russh::keys::PrivateKey]) -> Result<Self, String> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let listener = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|s| (Ok::<_, std::io::Error>(s), rx))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let agent = Self { tx };
        let mut conn = agent.open()?;
        for key in keys {
            conn.add_identity(key, &[])
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(agent)
    }

    fn open(&self) -> Result<Agent, String> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.tx
            .send(server)
            .map_err(|_| "the test agent stopped".to_owned())?;
        Ok(AgentClient::connect(Box::new(client) as AgentStreamBox))
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl AgentConnector for InProcessAgent {
    async fn connect(&self) -> Result<Agent, String> {
        self.open()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};

    use super::*;

    #[tokio::test]
    async fn in_process_agent_lists_its_keys() {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let agent = InProcessAgent::start(std::slice::from_ref(&key))
            .await
            .unwrap();
        let mut conn = agent.connect().await.unwrap();
        let ids = conn.request_identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].public_key().key_data(), key.public_key().key_data());
    }
}
