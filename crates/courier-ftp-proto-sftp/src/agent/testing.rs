//! **Tests only** (`test-util`): agents for the auth tests. They never touch
//! `SSH_AUTH_SOCK`.
//!
//! - [`InProcessAgent`]: russh's agent server over in-memory pipes;
//! - [`UnixSocketAgent`] (Unix): the same server listening on a socket in a directory
//!   the test owns (reached with [`super::SocketAgent`]);
//! - [`UnreachableAgent`]: an agent that can't be reached.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;

use super::{Agent, AgentConnector, AgentError, StreamAgent};

/// An in-process agent holding the keys it was given.
#[derive(Clone)]
pub struct InProcessAgent {
    tx: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
    connects: Arc<AtomicUsize>,
}

impl fmt::Debug for InProcessAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessAgent").finish_non_exhaustive()
    }
}

impl InProcessAgent {
    /// Start an agent holding `keys` (must run inside a tokio runtime).
    ///
    /// # Errors
    /// Adding a key failed.
    pub async fn start(keys: &[russh::keys::PrivateKey]) -> Result<Self, AgentError> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let listener = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|s| (Ok::<_, std::io::Error>(s), rx))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let agent = Self {
            tx,
            connects: Arc::default(),
        };
        let mut conn = agent.open()?;
        for key in keys {
            conn.add(key).await?;
        }
        agent.connects.store(0, Ordering::SeqCst);
        Ok(agent)
    }

    fn open(&self) -> Result<StreamAgent, AgentError> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.tx
            .send(server)
            .map_err(|_| AgentError("the test agent stopped".to_owned()))?;
        self.connects.fetch_add(1, Ordering::SeqCst);
        Ok(StreamAgent::new(Box::new(client)))
    }

    /// How many connections were opened since [`InProcessAgent::start`].
    pub fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl AgentConnector for InProcessAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Ok(Box::new(self.open()?))
    }
}

/// russh's agent server on a Unix socket (stopped when dropped).
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixSocketAgent {
    /// The socket.
    pub path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl UnixSocketAgent {
    /// Listen on `path` (in a directory the test owns) and add `keys`.
    ///
    /// # Errors
    /// Binding or adding a key failed.
    pub async fn start(
        path: std::path::PathBuf,
        keys: &[russh::keys::PrivateKey],
    ) -> Result<Self, AgentError> {
        let listener = tokio::net::UnixListener::bind(&path)?;
        let incoming = futures::stream::unfold(listener, |l| async move {
            let next = l.accept().await.map(|(s, _)| s);
            Some((next, l))
        });
        let task = tokio::spawn(async move {
            let _ = russh::keys::agent::server::serve(Box::pin(incoming), ()).await;
        });
        let agent = Self { path, task };
        let stream = tokio::net::UnixStream::connect(&agent.path).await?;
        let mut conn = StreamAgent::new(Box::new(stream));
        for key in keys {
            conn.add(key).await?;
        }
        Ok(agent)
    }

    /// A connector for this socket.
    pub fn connector(&self) -> super::SocketAgent {
        super::SocketAgent {
            path: self.path.clone(),
        }
    }
}

#[cfg(unix)]
impl Drop for UnixSocketAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An agent that can't be reached.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnreachableAgent;

#[async_trait]
impl AgentConnector for UnreachableAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Err(AgentError("connection refused".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};

    use super::*;

    #[tokio::test]
    async fn in_process_agent_lists_and_signs() {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let agent = InProcessAgent::start(std::slice::from_ref(&key))
            .await
            .unwrap();
        let mut conn = agent.connect().await.unwrap();
        let ids = conn.identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].public_key().key_data(), key.public_key().key_data());
        let sig = conn.sign(&ids[0], None, b"hello".to_vec()).await.unwrap();
        assert!(!sig.is_empty());
        assert_eq!(agent.connects(), 1);
    }

    #[tokio::test]
    async fn unreachable_agents_are_errors_not_panics() {
        assert!(UnreachableAgent.connect().await.is_err());
        #[cfg(unix)]
        {
            let missing = super::super::SocketAgent {
                path: std::path::PathBuf::from("/nonexistent/courier-agent.sock"),
            };
            assert!(missing.connect().await.is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_agent_lists_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]));
        let agent =
            UnixSocketAgent::start(dir.path().join("agent.sock"), std::slice::from_ref(&key))
                .await
                .unwrap();
        let mut conn = agent.connector().connect().await.unwrap();
        let ids = conn.identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].public_key().key_data(), key.public_key().key_data());
    }
}
