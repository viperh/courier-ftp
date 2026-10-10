//! An in-process russh server on 127.0.0.1 for the authentication tests
//! (adapted from sverb's `auth_testing`): `password`, `publickey`, a scripted
//! `keyboard-interactive` conversation, an optional auth banner and an
//! optional two-factor mode (the first factor is only a partial success).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    MethodKind, MethodSet,
    keys::{PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, Response},
};
use tokio::net::TcpListener;

/// One keyboard-interactive info request and the answers it expects.
#[derive(Debug, Clone)]
pub(crate) struct KbdRound {
    pub(crate) instructions: &'static str,
    /// `(prompt, echo)`.
    pub(crate) prompts: Vec<(&'static str, bool)>,
    pub(crate) expect: Vec<&'static str>,
}

/// How the server authenticates.
#[derive(Debug, Clone)]
pub(crate) struct Policy {
    /// Advertised methods.
    pub(crate) methods: Vec<MethodKind>,
    pub(crate) password: Option<&'static str>,
    pub(crate) authorized: Vec<PublicKey>,
    /// The keyboard-interactive conversation (every round answered right).
    pub(crate) kbd: Vec<KbdRound>,
    /// A right password or key is only a partial success; then
    /// `keyboard-interactive` (the `kbd` rounds) must follow.
    pub(crate) two_factor: bool,
    pub(crate) banner: Option<&'static str>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            methods: vec![
                MethodKind::PublicKey,
                MethodKind::Password,
                MethodKind::KeyboardInteractive,
            ],
            password: None,
            authorized: Vec::new(),
            kbd: Vec::new(),
            two_factor: false,
            banner: None,
        }
    }
}

/// What the server saw, in order: `none`, `password`, `publickey:<alg>`,
/// `kbd`, `kbd-answer`.
pub(crate) type Seen = Arc<Mutex<Vec<String>>>;

#[derive(Clone)]
struct AuthServer {
    policy: Arc<Policy>,
    seen: Seen,
    round: usize,
    first_factor_done: bool,
}

impl AuthServer {
    fn methods(&self) -> MethodSet {
        if self.first_factor_done {
            MethodSet::from(&[MethodKind::KeyboardInteractive][..])
        } else {
            MethodSet::from(&self.policy.methods[..])
        }
    }

    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(self.methods()),
            partial_success: false,
        }
    }

    /// A right first factor.
    fn accept(&mut self) -> Auth {
        if self.policy.two_factor && !self.first_factor_done {
            self.first_factor_done = true;
            Auth::Reject {
                proceed_with_methods: Some(self.methods()),
                partial_success: true,
            }
        } else {
            Auth::Accept
        }
    }

    fn note(&self, what: impl Into<String>) {
        self.seen.lock().unwrap().push(what.into());
    }

    fn kbd_round(&self) -> Auth {
        let r = &self.policy.kbd[self.round];
        Auth::Partial {
            name: Cow::Borrowed("test"),
            instructions: Cow::Borrowed(r.instructions),
            prompts: Cow::Owned(
                r.prompts
                    .iter()
                    .map(|(p, e)| (Cow::Borrowed(*p), *e))
                    .collect(),
            ),
        }
    }
}

impl server::Handler for AuthServer {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.policy.banner.map(str::to_owned))
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.note("none");
        Ok(self.reject())
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.note("password");
        Ok(
            if !self.first_factor_done && self.policy.password == Some(password) {
                self.accept()
            } else {
                self.reject()
            },
        )
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.note(format!("publickey:{}", key.algorithm().as_str()));
        let known = self
            .policy
            .authorized
            .iter()
            .any(|k| k.key_data() == key.key_data());
        Ok(if known && !self.first_factor_done {
            Auth::Accept
        } else {
            self.reject()
        })
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let known = self
            .policy
            .authorized
            .iter()
            .any(|k| k.key_data() == key.key_data());
        Ok(if known && !self.first_factor_done {
            self.accept()
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
            self.note("kbd");
            self.round = 0;
            if self.policy.kbd.is_empty() {
                return Ok(self.reject());
            }
            return Ok(self.kbd_round());
        };
        self.note("kbd-answer");
        let answers: Vec<String> = response
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect();
        let want = &self.policy.kbd[self.round].expect;
        if answers.len() != want.len() || answers.iter().zip(want).any(|(a, w)| a != w) {
            return Ok(self.reject());
        }
        self.round += 1;
        if self.round == self.policy.kbd.len() {
            Ok(Auth::Accept)
        } else {
            Ok(self.kbd_round())
        }
    }
}

/// A server authenticating per `policy`: its address and what it saw.
pub(crate) async fn start(policy: Policy) -> (SocketAddr, Seen) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let config = Arc::new(server::Config {
        keys: vec![key],
        methods: MethodSet::from(&policy.methods[..]),
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Seen::default();
    let handler = AuthServer {
        policy: Arc::new(policy),
        seen: Arc::clone(&seen),
        round: 0,
        first_factor_done: false,
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let config = Arc::clone(&config);
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    (addr, seen)
}

/// The test server's host key.
pub(crate) fn host_key() -> PublicKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]))
        .public_key()
        .clone()
}
