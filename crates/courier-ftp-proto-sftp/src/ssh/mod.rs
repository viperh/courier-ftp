//! SSH connection and authentication (T20).
//!
//! [`connect`] opens an authenticated SSH session:
//!
//! 1. TCP through [`courier_ftp_core::net::connect_tcp`] (DNS, IPv6, Happy
//!    Eyeballs, the generic proxy), then russh's handshake over that stream;
//! 2. the server's host key goes to the [`HostKeyVerifier`] (T21 provides the
//!    real one); the connection proceeds only when it accepts;
//! 3. authentication for the site's [`LogonType`] (see [`auth`](self) below);
//! 4. the result is an [`SshSession`]; the SFTP subsystem (T22) is opened on it
//!    with [`SshSession::open_subsystem`].
//!
//! # Authentication
//!
//! After `none` (which learns the methods the server accepts):
//!
//! - **Normal**: `password` with the stored password. When the server takes
//!   only `keyboard-interactive`, a single hidden prompt that mentions
//!   "password" is answered with the stored password (once); other prompts are
//!   asked. With [`SshOptions::try_agent_first`] the agent's keys are offered
//!   first (off by default: offering many keys trips `MaxAuthTries`).
//! - **Ask for password**: `Prompt(Password)` (or the password remembered in
//!   the [`CredentialCache`]), then as Normal; a rejected password is asked
//!   again, up to [`PASSWORD_TRIES`] times.
//! - **Interactive**: `keyboard-interactive`, every challenge is a
//!   `Prompt(KeyboardInteractive)` (2FA/OTP; the echo flag is passed on); a
//!   server without it gets a password prompt.
//! - **Key file**: OpenSSH, PEM, PKCS#8 or PuTTY `.ppk` ([`keys`]); an
//!   encrypted key asks `Prompt(KeyPassphrase)` up to [`PASSPHRASE_TRIES`]
//!   times. RSA keys sign with `rsa-sha2-512/256` when the server lists them in
//!   `server-sig-algs`.
//! - **Agent**: each identity of the [`AgentConnector`] in turn.
//! - **Anonymous / Account** are FTP-only: [`Error::InvalidInput`].
//!
//! A partial success (`AuthenticationMethods publickey,keyboard-interactive`)
//! continues with `keyboard-interactive` or `password` as the server asks. On
//! failure the error says what was rejected and which methods the server
//! accepts. Every method tried is logged; secrets never are (passwords,
//! answers and passphrases are [`SecretString`]s, copied into russh's plain
//! `String`s only for the request that sends them).

mod auth;
mod handler;

pub mod agent;
pub mod hostkey;
pub mod keys;
pub mod text;
pub mod trust;

#[cfg(test)]
mod test_server;
#[cfg(test)]
mod tests;

use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use courier_ftp_core::{
    Error, Result,
    backend::{ConnectInfo, KeySource, ProxyChoice, SecurityInfo},
    events::{EventSender, LogKind, SessionId},
    model::{LocalPath, LogonType},
    net::{HostPort, NetOpts, connect_tcp},
    settings::Settings,
};
use russh::{Disconnect, SshId, client};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use self::handler::{Shared, lock};
pub use self::{
    agent::{AgentConnector, SystemAgent},
    handler::ClientHandler,
    hostkey::{AcceptAnyHostKey, HostKeyContext, HostKeyVerifier},
    keys::{KeyError, KeyFile, KeyFormat},
    trust::TrustStoreVerifier,
};

/// Password prompts per connection for "ask for password" and "interactive".
pub const PASSWORD_TRIES: usize = 3;
/// Passphrase prompts for an encrypted key before giving up.
pub const PASSPHRASE_TRIES: usize = 3;
/// Keep-alives without a reply before the connection is considered dead.
pub const KEEPALIVE_MAX: usize = 3;

/// The russh client handle of an authenticated session.
pub type SshHandle = client::Handle<ClientHandler>;

/// A private key given explicitly instead of the logon type's key file.
#[derive(Clone)]
pub enum KeyInput {
    /// A key file on disk.
    File(LocalPath),
    /// Key text (e.g. an SSH key from the vault, T30). `label` names it in
    /// messages and in the passphrase prompt.
    Text {
        /// Shown to the user.
        label: String,
        /// The private key, any supported format.
        text: SecretString,
    },
}

impl fmt::Debug for KeyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyInput::File(path) => f.debug_tuple("File").field(path).finish(),
            KeyInput::Text { label, .. } => f
                .debug_struct("Text")
                .field("label", label)
                .finish_non_exhaustive(),
        }
    }
}

/// What to connect to and how to log in.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SshOptions {
    /// The server.
    pub host: HostPort,
    /// How to log in.
    pub logon: LogonType,
    /// A key that overrides [`LogonType::KeyFile`]'s path (and makes a key
    /// login of other logon types' user).
    pub key: Option<KeyInput>,
    /// TCP options: timeout, IPv6 preference, proxy.
    pub net: NetOpts,
    /// Bound on the SSH handshake and on every authentication request
    /// (setting `connection.timeout_secs`). Prompts are not bounded.
    pub timeout: Duration,
    /// SSH keep-alive interval (`connection.keepalive_interval_secs`), `None`
    /// for no keep-alives.
    pub keepalive: Option<Duration>,
    /// Offer the agent's keys before the password for logon type Normal
    /// (per-site toggle, default off).
    pub try_agent_first: bool,
}

impl SshOptions {
    /// Options for `host` and `logon` with the timeouts, keep-alive and proxy
    /// from `settings`.
    pub fn new(host: HostPort, logon: LogonType, settings: &Settings) -> Self {
        let c = &settings.connection;
        Self {
            host,
            logon,
            key: None,
            net: NetOpts::from_settings(settings),
            timeout: Duration::from_secs(c.timeout_secs.max(1)),
            keepalive: c
                .keepalive
                .then(|| Duration::from_secs(c.keepalive_interval_secs.max(1))),
            try_agent_first: false,
        }
    }

    /// Options for a [`ConnectInfo`]: its address, logon, proxy choice and a
    /// key file from [`ConnectInfo::key`]. A [`KeySource::Vault`] key must be
    /// resolved by the caller into [`SshOptions::key`].
    pub fn from_connect_info(info: &ConnectInfo, settings: &Settings) -> Self {
        let mut opts = Self::new(HostPort::from(&info.address), info.logon.clone(), settings);
        opts.net = opts.net.bypass_proxy(info.proxy == ProxyChoice::Bypass);
        if let Some(KeySource::File(path)) = &info.key {
            opts.key = Some(KeyInput::File(path.clone()));
        }
        opts
    }

    /// The russh client configuration.
    fn client_config(&self) -> client::Config {
        // russh drops a connection that received nothing for
        // `inactivity_timeout`. With keep-alives the server answers them, so
        // the bound only has to cover the keep-alive window; without
        // keep-alives an idle session must not be torn down by us.
        let inactivity = self.keepalive.map(|interval| {
            let window = interval.saturating_mul(u32::try_from(KEEPALIVE_MAX + 1).unwrap_or(4));
            window.max(self.timeout)
        });
        client::Config {
            client_id: SshId::Standard(Cow::Owned(format!(
                "SSH-2.0-courier-ftp_{}",
                env!("CARGO_PKG_VERSION")
            ))),
            inactivity_timeout: inactivity,
            keepalive_interval: self.keepalive,
            keepalive_max: KEEPALIVE_MAX,
            nodelay: true,
            ..client::Config::default()
        }
    }
}

/// Passwords and key passphrases typed during this program run, kept in
/// memory only ("remember for this session"). Clones share the cache.
///
/// An entry is stored only after it authenticated successfully, and dropped
/// when the server rejects it. Values are [`SecretString`]s (zeroized when
/// dropped).
#[derive(Clone, Default)]
pub struct CredentialCache {
    inner: Arc<Mutex<HashMap<String, SecretString>>>,
}

impl fmt::Debug for CredentialCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialCache")
            .field("entries", &self.map().len())
            .finish()
    }
}

impl CredentialCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, SecretString>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn password_key(host: &HostPort, user: &str) -> String {
        format!("password:{user}@{host}")
    }

    fn passphrase_key(label: &str) -> String {
        format!("passphrase:{label}")
    }

    fn get(&self, key: &str) -> Option<SecretString> {
        self.map().get(key).cloned()
    }

    fn put(&self, key: String, value: SecretString) {
        self.map().insert(key, value);
    }

    fn forget(&self, key: &str) {
        self.map().remove(key);
    }

    /// Forget everything (e.g. when the vault is locked).
    pub fn clear(&self) {
        self.map().clear();
    }
}

/// Who connects and with which helpers.
#[derive(Debug, Clone)]
pub struct SshContext {
    /// The connection, for log lines and prompts.
    pub session: SessionId,
    /// The event bus.
    pub events: EventSender,
    /// Decides about the server's host key (T21).
    pub verifier: Arc<dyn HostKeyVerifier>,
    /// The SSH agent for logon type Agent (and `try_agent_first`).
    pub agent: Arc<dyn AgentConnector>,
    /// Remembered passwords and passphrases, or `None` to never remember a
    /// typed one.
    pub credentials: Option<CredentialCache>,
}

impl SshContext {
    /// A context using the system agent and no credential cache.
    pub fn new(
        session: SessionId,
        events: EventSender,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Self {
        Self {
            session,
            events,
            verifier,
            agent: Arc::new(SystemAgent),
            credentials: None,
        }
    }
}

/// An authenticated SSH session.
pub struct SshSession {
    handle: SshHandle,
    shared: Arc<Mutex<Shared>>,
    host: HostPort,
    user: String,
}

impl fmt::Debug for SshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshSession")
            .field("host", &self.host)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl SshSession {
    /// The russh handle, for opening channels.
    pub fn handle(&self) -> &SshHandle {
        &self.handle
    }

    /// The server.
    pub fn host(&self) -> &HostPort {
        &self.host
    }

    /// The user logged in as.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The server's identification string (e.g. `SSH-2.0-OpenSSH_9.6`).
    pub fn server_version(&self) -> String {
        lock(&self.shared).server_version.clone()
    }

    /// The negotiated algorithms and the host key, for the status bar and
    /// the server info dialog.
    pub fn security_info(&self) -> SecurityInfo {
        let s = lock(&self.shared);
        let aead = s.cipher.contains("gcm") || s.cipher.contains("poly1305");
        SecurityInfo::Ssh {
            kex: s.kex.clone(),
            cipher: s.cipher.clone(),
            mac: if aead { String::new() } else { s.mac.clone() },
            host_key: s.host_key.clone(),
        }
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Why the connection ended, when the server or a timeout ended it.
    pub fn end_reason(&self) -> Option<String> {
        lock(&self.shared).end.clone()
    }

    /// Open a session channel and request the subsystem `name` (`sftp`). The
    /// server's reply to the request arrives on the channel.
    ///
    /// # Errors
    /// [`Error::Connection`] when the channel can't be opened or the request
    /// can't be sent.
    pub async fn open_subsystem(&self, name: &str) -> Result<russh::Channel<client::Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| self.connection_error(&e))?;
        channel
            .request_subsystem(true, name)
            .await
            .map_err(|e| self.connection_error(&e))?;
        Ok(channel)
    }

    /// Close the connection (`SSH_MSG_DISCONNECT`, "by application").
    ///
    /// # Errors
    /// None in practice: a connection that is already gone counts as closed.
    pub async fn disconnect(&self) -> Result<()> {
        if let Err(err) = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
        {
            tracing::debug!(%err, "disconnect: connection already gone");
        }
        Ok(())
    }

    fn connection_error(&self, err: &russh::Error) -> Error {
        connection_error(&self.shared, err)
    }
}

/// Map a russh error to a core error, preferring what the handler saw.
fn connection_error(shared: &Mutex<Shared>, err: &russh::Error) -> Error {
    let mut s = lock(shared);
    if let Some(host_key) = s.host_key_error.take() {
        return host_key;
    }
    match err {
        russh::Error::UnknownKey => Error::HostKey("the host key was rejected".to_owned()),
        russh::Error::KeepaliveTimeout | russh::Error::InactivityTimeout => Error::Timeout,
        russh::Error::IO(io) => Error::Connection(io.to_string()),
        other => Error::Connection(match &s.end {
            Some(end) => end.clone(),
            None => other.to_string(),
        }),
    }
}

/// Run `fut` bounded by `timeout` and `cancel`.
async fn bounded<T>(
    timeout: Duration,
    cancel: &CancellationToken,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = tokio::time::timeout(timeout, fut) => r.unwrap_or(Err(Error::Timeout)),
    }
}

/// Connect, verify the host key and authenticate (see the module docs).
///
/// # Errors
/// - [`Error::InvalidInput`] for the FTP-only logon types;
/// - [`Error::Cancelled`] when `cancel` fires or a prompt is dismissed;
/// - [`Error::Timeout`] when the handshake or an authentication request takes
///   longer than [`SshOptions::timeout`];
/// - [`Error::HostKey`] (or the verifier's error) when the host key is not
///   accepted;
/// - [`Error::Auth`] when every method failed, with the methods the server
///   accepts;
/// - [`Error::Connection`] for network and protocol failures.
pub async fn connect(
    opts: &SshOptions,
    ctx: &SshContext,
    cancel: &CancellationToken,
) -> Result<SshSession> {
    if matches!(opts.logon, LogonType::Anonymous | LogonType::Account { .. }) {
        return Err(Error::InvalidInput(
            "anonymous and account logons are not available for SFTP".to_owned(),
        ));
    }
    let result = connect_inner(opts, ctx, cancel).await;
    if let Err(err) = &result {
        ctx.events.log(ctx.session, LogKind::Error, err.to_string());
    }
    result
}

async fn connect_inner(
    opts: &SshOptions,
    ctx: &SshContext,
    cancel: &CancellationToken,
) -> Result<SshSession> {
    let stream = connect_tcp(&opts.host, &opts.net, cancel, &ctx.events, ctx.session).await?;
    let user = opts.logon.user().to_owned();
    ctx.events.log(
        ctx.session,
        LogKind::Status,
        format!("Using username \"{user}\"."),
    );
    let shared = Arc::new(Mutex::new(Shared::default()));
    let handler = ClientHandler {
        verifier: Arc::clone(&ctx.verifier),
        host: opts.host.clone(),
        session: ctx.session,
        events: ctx.events.clone(),
        cancel: cancel.clone(),
        shared: Arc::clone(&shared),
    };
    let config = Arc::new(opts.client_config());
    let handle = handshake(opts.timeout, cancel, &shared, async {
        client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| connection_error(&shared, &e))
    })
    .await?;
    let mut session = SshSession {
        handle,
        shared,
        host: opts.host.clone(),
        user,
    };
    if let Err(err) = auth::authenticate(&mut session, opts, ctx, cancel).await {
        session.disconnect().await.ok();
        return Err(err);
    }
    ctx.events.log(
        ctx.session,
        LogKind::Status,
        format!("Connected to {}", opts.host),
    );
    Ok(session)
}

/// Run the handshake `fut`: it fails after `timeout` without progress, except
/// while the host-key verifier runs (it may be waiting on the user, T21);
/// cancelling aborts at once.
async fn handshake<T>(
    timeout: Duration,
    cancel: &CancellationToken,
    shared: &Mutex<Shared>,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    let mut fut = std::pin::pin!(fut);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Error::Cancelled),
            r = &mut fut => return r,
            () = tokio::time::sleep(timeout) => {
                if !lock(shared).verifying {
                    return Err(Error::Timeout);
                }
            }
        }
    }
}
