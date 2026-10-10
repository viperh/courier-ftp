//! **Tests only** (`test-util`): an in-process russh server on `127.0.0.1:0` for the
//! loopback tests (T20, later T22/T76), adapted from sverb `ssh/{testing,
//! auth_testing}.rs` (D13).
//!
//! It advertises a configurable method list, accepts a password, authorized public
//! keys and a scripted keyboard-interactive conversation, can require several methods
//! (`AuthenticationMethods publickey,password`: partial success), can show a banner,
//! can disconnect (with any reason code) after the client's `none` request, and has a
//! silent mode that accepts TCP but never sends its version string. It records the
//! authentication requests it saw. Session channels are accepted and the `sftp`
//! subsystem request is answered with success; with [`TestServerConfig::sftp`] set, the
//! channel is handed to that hook (T22's `testing::SftpTestServer` runs its SFTP server
//! there).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    Channel, ChannelId, MethodKind, MethodSet, Preferred,
    keys::{Algorithm, PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, ChannelOpenHandle, Msg, Response, Session},
};
use tokio::{net::TcpListener, task::JoinHandle};

use super::handler::lock;

/// One keyboard-interactive info request and the answers it expects.
#[derive(Debug, Clone)]
pub struct KbdRound {
    pub name: String,
    pub instructions: String,
    /// `(prompt, echo)`.
    pub prompts: Vec<(String, bool)>,
    pub expect: Vec<String>,
}

impl KbdRound {
    /// One non-echo prompt expecting `answer`.
    pub fn single(prompt: &str, answer: &str) -> Self {
        Self {
            name: String::new(),
            instructions: String::new(),
            prompts: vec![(prompt.to_owned(), false)],
            expect: vec![answer.to_owned()],
        }
    }
}

/// Receives the channel of every accepted `sftp` subsystem request.
#[derive(Clone)]
pub struct SubsystemHook(pub Arc<dyn Fn(russh::ChannelStream<Msg>) + Send + Sync>);

impl std::fmt::Debug for SubsystemHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubsystemHook")
    }
}

/// How the server behaves.
#[derive(Debug, Clone)]
pub struct TestServerConfig {
    /// Advertised methods (`publickey`, `password`, `keyboard-interactive`), returned
    /// with every rejection.
    pub methods: Vec<&'static str>,
    /// The accepted password.
    pub password: Option<String>,
    /// Accepted public keys.
    pub authorized: Vec<PublicKey>,
    /// The keyboard-interactive conversation (every round must be answered right).
    pub kbd: Vec<KbdRound>,
    /// Methods that must all succeed, in order (empty: any one is enough).
    pub required: Vec<&'static str>,
    /// `MaxAuthTries` (russh counts every rejection, `none` included). 0: unlimited.
    pub max_auth_attempts: usize,
    /// Sent as `SSH_MSG_USERAUTH_BANNER`.
    pub banner: Option<String>,
    /// Accept TCP but never send the version string.
    pub silent: bool,
    /// After the client's `none` request, wait this long and disconnect with this
    /// reason code (RFC 4253 §11.1) and description.
    pub disconnect_after_none: Option<(Duration, u32, String)>,
    /// Server algorithm preferences (also `server-sig-algs`).
    pub preferred: Option<Preferred>,
    /// Each `password` request is answered after this delay.
    pub auth_delay: Duration,
    /// The host keys (T21: several types, or another key for a "changed key").
    /// Empty: the fixed Ed25519 [`host_key`].
    pub host_keys: Vec<PrivateKey>,
    /// Serves the `sftp` subsystem (None: the request succeeds, nothing answers).
    pub sftp: Option<SubsystemHook>,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            methods: vec!["publickey", "password", "keyboard-interactive"],
            password: None,
            authorized: Vec::new(),
            kbd: Vec::new(),
            required: Vec::new(),
            max_auth_attempts: 0,
            banner: None,
            silent: false,
            disconnect_after_none: None,
            preferred: None,
            auth_delay: Duration::ZERO,
            host_keys: Vec::new(),
            sftp: None,
        }
    }
}

/// What the server saw, in order: `none`, `password`, `publickey:<key type>`
/// (offered or signed), `kbd`, `kbd-answer`, `subsystem:<name>`.
#[derive(Debug, Default)]
pub struct Seen {
    pub requests: Vec<String>,
    pub users: Vec<String>,
}

fn method_kind(name: &str) -> Option<MethodKind> {
    match name {
        "publickey" => Some(MethodKind::PublicKey),
        "password" => Some(MethodKind::Password),
        "keyboard-interactive" => Some(MethodKind::KeyboardInteractive),
        "none" => Some(MethodKind::None),
        _ => None,
    }
}

fn method_set(names: &[&str]) -> MethodSet {
    let kinds: Vec<MethodKind> = names.iter().filter_map(|n| method_kind(n)).collect();
    MethodSet::from(&kinds[..])
}

/// The server handler (one per connection).
struct Handler {
    config: Arc<TestServerConfig>,
    seen: Arc<Mutex<Seen>>,
    round: usize,
    /// Required methods already passed.
    passed: Vec<&'static str>,
    none_seen: Option<tokio::sync::oneshot::Sender<()>>,
    channels: Vec<Channel<Msg>>,
}

impl Handler {
    fn note(&self, what: String) {
        lock(&self.seen).requests.push(what);
    }

    fn methods_left(&self) -> Vec<&'static str> {
        if self.config.required.is_empty() {
            self.config.methods.clone()
        } else {
            self.config
                .required
                .iter()
                .filter(|m| !self.passed.contains(m))
                .copied()
                .collect()
        }
    }

    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(method_set(&self.methods_left())),
            partial_success: false,
        }
    }

    /// `method` succeeded: accept, or partial success while more are required.
    fn passed(&mut self, method: &'static str) -> Auth {
        if self.config.required.is_empty() {
            return Auth::Accept;
        }
        if !self.config.required.contains(&method) {
            return self.reject();
        }
        if !self.passed.contains(&method) {
            self.passed.push(method);
        }
        let left = self.methods_left();
        if left.is_empty() {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: Some(method_set(&left)),
                partial_success: true,
            }
        }
    }

    fn allowed(&self, method: &str) -> bool {
        self.methods_left().contains(&method)
    }

    fn kbd_round(&self) -> Auth {
        let r = &self.config.kbd[self.round];
        Auth::Partial {
            name: Cow::Owned(r.name.clone()),
            instructions: Cow::Owned(r.instructions.clone()),
            prompts: Cow::Owned(
                r.prompts
                    .iter()
                    .map(|(p, e)| (Cow::Owned(p.clone()), *e))
                    .collect(),
            ),
        }
    }

    fn known(&self, key: &PublicKey) -> bool {
        self.config
            .authorized
            .iter()
            .any(|k| k.key_data() == key.key_data())
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.note("none".into());
        lock(&self.seen).users.push(user.to_owned());
        if let Some(tx) = self.none_seen.take() {
            let _ = tx.send(());
        }
        Ok(self.reject())
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.note("password".into());
        if !self.config.auth_delay.is_zero() {
            tokio::time::sleep(self.config.auth_delay).await;
        }
        if self.allowed("password") && self.config.password.as_deref() == Some(password) {
            Ok(self.passed("password"))
        } else {
            Ok(self.reject())
        }
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.note(format!("publickey:{}", key.algorithm().as_str()));
        Ok(if self.allowed("publickey") && self.known(key) {
            Auth::Accept
        } else {
            self.reject()
        })
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.allowed("publickey") && self.known(key) {
            self.passed("publickey")
        } else {
            self.reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let Some(response) = response else {
            self.note("kbd".into());
            self.round = 0;
            if self.config.kbd.is_empty() || !self.allowed("keyboard-interactive") {
                return Ok(self.reject());
            }
            return Ok(self.kbd_round());
        };
        self.note("kbd-answer".into());
        let answers: Vec<String> = response
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect();
        let Some(round) = self.config.kbd.get(self.round) else {
            return Ok(self.reject());
        };
        if answers != round.expect {
            return Ok(self.reject());
        }
        self.round += 1;
        if self.round == self.config.kbd.len() {
            Ok(self.passed("keyboard-interactive"))
        } else {
            Ok(self.kbd_round())
        }
    }

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.config.banner.clone())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.note(format!("subsystem:{name}"));
        if name == "sftp" {
            if let Some(hook) = &self.config.sftp
                && let Some(i) = self.channels.iter().position(|c| c.id() == channel)
            {
                let ch = self.channels.swap_remove(i);
                (hook.0)(ch.into_stream());
            }
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }
}

/// A running in-process server (stopped when dropped).
#[derive(Debug)]
pub struct TestServer {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
    task: JoinHandle<()>,
    connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    handles: Arc<Mutex<Vec<server::Handle>>>,
    host_keys: Vec<PublicKey>,
}

impl Drop for TestServer {
    /// Stops accepting and closes every connection.
    fn drop(&mut self) {
        self.task.abort();
        for c in lock(&self.connections).drain(..) {
            c.abort();
        }
    }
}

/// The server's fixed Ed25519 host key.
pub fn host_key() -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]))
}

impl TestServer {
    /// Start a server on `127.0.0.1:0`.
    pub async fn start(config: TestServerConfig) -> Self {
        Self::spawn(config)
    }

    /// As [`start`](Self::start), from synchronous code inside a tokio runtime (the
    /// conformance environments are built synchronously).
    pub fn spawn(config: TestServerConfig) -> Self {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let keys = if config.host_keys.is_empty() {
            vec![host_key()]
        } else {
            config.host_keys.clone()
        };
        let host_keys: Vec<PublicKey> = keys.iter().map(|k| k.public_key().clone()).collect();
        let server_config = Arc::new(server::Config {
            keys,
            preferred: config.preferred.clone().unwrap_or_default(),
            methods: method_set(&config.methods),
            max_auth_attempts: config.max_auth_attempts,
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(600)),
            ..server::Config::default()
        });
        let config = Arc::new(config);
        let seen2 = Arc::clone(&seen);
        let connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let conns = Arc::clone(&connections);
        let handles: Arc<Mutex<Vec<server::Handle>>> = Arc::default();
        let handles2 = Arc::clone(&handles);
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                if config.silent {
                    // Never send the version string; keep the socket open.
                    held.push(stream);
                    continue;
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                let handler = Handler {
                    config: Arc::clone(&config),
                    seen: Arc::clone(&seen2),
                    round: 0,
                    passed: Vec::new(),
                    none_seen: Some(tx),
                    channels: Vec::new(),
                };
                let server_config = Arc::clone(&server_config);
                let disconnect = config.disconnect_after_none.clone();
                let handles = Arc::clone(&handles2);
                let conn = tokio::spawn(async move {
                    let Ok(running) = server::run_stream(server_config, stream, handler).await
                    else {
                        return;
                    };
                    lock(&handles).push(running.handle());
                    if let Some((delay, code, text)) = disconnect {
                        let handle = running.handle();
                        let reason = russh::Disconnect::try_from(code)
                            .unwrap_or(russh::Disconnect::ByApplication);
                        tokio::spawn(async move {
                            if rx.await.is_ok() {
                                tokio::time::sleep(delay).await;
                                let _ = handle.disconnect(reason, text, "en".into()).await;
                            }
                        });
                    }
                    let _ = running.await;
                });
                lock(&conns).push(conn.abort_handle());
            }
        });
        Self {
            addr,
            seen,
            task,
            connections,
            handles,
            host_keys,
        }
    }

    /// Disconnect every connection (`ByApplication`, "server shutting down").
    pub async fn shutdown(&self) {
        let handles: Vec<server::Handle> = lock(&self.handles).drain(..).collect();
        for h in handles {
            let _ = h
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "server shutting down".into(),
                    "en".into(),
                )
                .await;
        }
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The server's (first) host key.
    pub fn host_key(&self) -> &PublicKey {
        &self.host_keys[0]
    }

    /// Every host key the server holds.
    pub fn host_keys(&self) -> &[PublicKey] {
        &self.host_keys
    }

    /// The authentication requests seen so far.
    pub fn requests(&self) -> Vec<String> {
        lock(&self.seen).requests.clone()
    }

    /// How many `publickey` requests were seen.
    pub fn publickey_requests(&self) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.starts_with("publickey"))
            .count()
    }

    /// The users seen in `none` requests.
    pub fn users(&self) -> Vec<String> {
        lock(&self.seen).users.clone()
    }
}

/// Server preferences offering only `diffie-hellman-group14-sha1` and `aes128-cbc`
/// (no common cipher with the client).
pub fn legacy_preferences() -> Preferred {
    Preferred {
        kex: Cow::Owned(vec![russh::kex::DH_G14_SHA1]),
        cipher: Cow::Owned(vec![russh::cipher::AES_128_CBC]),
        ..Preferred::default()
    }
}

/// Server preferences whose `server-sig-algs` lists the given key algorithms.
pub fn sig_algs(algs: Vec<Algorithm>) -> Preferred {
    Preferred {
        key: Cow::Owned(algs),
        ..Preferred::default()
    }
}
