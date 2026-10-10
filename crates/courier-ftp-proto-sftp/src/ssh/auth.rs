//! The authentication chain (T20; adapted from sverb `ssh/auth.rs`, D13).
//!
//! After `none` (which learns the server's method list; a server that accepts `none`
//! ends the chain), the steps of the logon type run in order, skipping any step whose
//! method the latest `USERAUTH_FAILURE` does not list:
//!
//! | Logon type | Steps |
//! |---|---|
//! | `Normal` | \[A\] if `try_agent_first` → \[P1\] stored password → \[K\] keyboard-interactive (the stored password answers once) → \[P2\] password prompts |
//! | `AskForPassword` | \[A\] → \[P2\] → \[K\] (the typed password answers once) |
//! | `Interactive` | \[A\] → \[K\] (every info request is shown) → \[P2\] only if the server lists `password` but not `keyboard-interactive` |
//! | `KeyFile` | \[F\] key file only |
//! | `Agent` | \[A\] agent identities only |
//!
//! Every request after `none` counts against [`MAX_AUTH_ATTEMPTS`] (each key and each
//! agent identity is one, each keyboard-interactive conversation is one). A cancelled
//! prompt aborts the whole connect ([`SshError::Cancelled`]).
//!
//! The chain is written against two seams so unit tests can script both sides:
//! [`AuthBackend`] (the server: russh's auth calls, `RusshBackend`) and [`AuthIo`]
//! (the user: log lines and prompts, [`PromptIo`] over the T04 event bus). Answers
//! used in a successful (or partially successful) request are reported with
//! [`AuthIo::accepted`] once the whole authentication succeeded, so the UI caches or
//! saves a typed password or passphrase only when it is known to be right.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use courier_ftp_core::{
    events::{
        KbdField, KbdInteractivePrompt, LogKind, PassphrasePrompt, PasswordPrompt, PasswordPurpose,
        PromptId, PromptKind, PromptResponse, SecretCacheKey, SessionLog,
    },
    model::Protocol,
    secret::SecretString,
    text::sanitize_server_text,
};
use russh::{
    client::{AuthResult, Handle, KeyboardInteractiveAuthResponse},
    keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, agent::AgentIdentity},
};
use tokio_util::sync::CancellationToken;
use tracing::debug;
use zeroize::Zeroizing;

use super::{
    SshLogon,
    errors::{EndCause, SshError, from_russh},
    handler::{ClientHandler, Shared},
};
use crate::{
    agent::{Agent, AgentConnector},
    keys::{self, KeyError},
};

/// Requests after `none` (OpenSSH `MaxAuthTries` default).
pub const MAX_AUTH_ATTEMPTS: u32 = 6;
/// Password prompts after a rejected or absent password.
pub const PASSWORD_PROMPTS: u8 = 3;
/// Passphrase prompts per key.
pub const PASSPHRASE_TRIES: u8 = 3;
/// Keyboard-interactive conversations per connection.
pub const KBD_ROUNDS: u8 = 3;
/// Prompts in one info request (more → the method fails).
pub const MAX_KBD_PROMPTS: usize = 10;
/// Characters per server prompt / name / instruction.
pub const MAX_PROMPT_TEXT: usize = 512;

/// `publickey`.
pub const PUBLICKEY: &str = "publickey";
/// `password`.
pub const PASSWORD: &str = "password";
/// `keyboard-interactive`.
pub const KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";

// ---------------------------------------------------------------- pure helpers

/// What the server said about RSA signatures (`server-sig-algs`, RFC 8308).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSigSupport {
    /// `rsa-sha2-512` is offered.
    Sha512,
    /// `rsa-sha2-256` is offered (and not 512).
    Sha256,
    /// `server-sig-algs` is sent but lists no `rsa-sha2-*` algorithm.
    NoSha2,
    /// No `server-sig-algs` (OpenSSH < 7.2).
    Unknown,
}

/// The hash for an RSA signature: `Some(Some(h))` → `rsa-sha2-*`, `Some(None)` →
/// `ssh-rsa` (SHA-1, servers without `server-sig-algs`), `None` → skip the key.
pub fn rsa_hash(support: RsaSigSupport) -> Option<Option<HashAlg>> {
    match support {
        RsaSigSupport::Sha512 => Some(Some(HashAlg::Sha512)),
        RsaSigSupport::Sha256 => Some(Some(HashAlg::Sha256)),
        RsaSigSupport::Unknown => Some(None),
        RsaSigSupport::NoSha2 => None,
    }
}

/// The signature algorithm name for a key type and hash (`rsa-sha2-512`, `ssh-ed25519`).
fn signature_name(key_type: &str, is_rsa: bool, hash: Option<HashAlg>) -> String {
    match (is_rsa, hash) {
        (true, Some(HashAlg::Sha512)) => "rsa-sha2-512".to_owned(),
        (true, Some(HashAlg::Sha256)) => "rsa-sha2-256".to_owned(),
        (true, _) => "ssh-rsa".to_owned(),
        (false, _) => key_type.to_owned(),
    }
}

/// Whether a keyboard-interactive request may be answered with the password: exactly
/// one non-echo prompt mentioning "password" (any case).
pub fn is_password_request(prompts: &[KbdField]) -> bool {
    matches!(prompts, [p] if !p.echo && p.text.to_lowercase().contains("password"))
}

// ---------------------------------------------------------------- seams

/// The outcome of one authentication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authenticated.
    Success,
    /// Rejected. `remaining` is the server's list of methods that can continue;
    /// `partial` means this method succeeded but more are required.
    Failure {
        /// Methods that can continue.
        remaining: Vec<String>,
        /// Partial success.
        partial: bool,
    },
}

/// A keyboard-interactive reply from the server.
#[derive(Debug, Clone, PartialEq)]
pub enum KbdReply {
    /// Authenticated.
    Success,
    /// Rejected (see [`AuthOutcome::Failure`]).
    Failure {
        /// Methods that can continue.
        remaining: Vec<String>,
        /// Partial success.
        partial: bool,
    },
    /// An info request (raw server text; the chain sanitizes it).
    Info {
        /// Name.
        name: String,
        /// Instruction.
        instruction: String,
        /// Prompts.
        prompts: Vec<KbdField>,
    },
}

/// The server side of the chain (russh's auth calls; scripted in unit tests).
#[async_trait]
pub trait AuthBackend: Send {
    /// `none`.
    async fn none(&mut self, user: &str) -> Result<AuthOutcome, SshError>;
    /// `password`.
    async fn password(
        &mut self,
        user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, SshError>;
    /// `publickey` with a private key (`hash`: RSA signature hash, `None` = SHA-1).
    async fn publickey(
        &mut self,
        user: &str,
        key: Arc<PrivateKey>,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError>;
    /// `publickey` with an agent identity, signed by `agent`.
    async fn agent_identity(
        &mut self,
        user: &str,
        agent: &mut dyn Agent,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError>;
    /// Start `keyboard-interactive`.
    async fn kbd_start(&mut self, user: &str) -> Result<KbdReply, SshError>;
    /// Answer an info request.
    async fn kbd_respond(&mut self, answers: &[SecretString]) -> Result<KbdReply, SshError>;
    /// What `server-sig-algs` says about RSA (asked only when an RSA key is used).
    async fn rsa_support(&mut self) -> RsaSigSupport;
}

/// Identifies one answered prompt (the IO maps it to the T04 [`PromptId`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PromptToken(pub u64);

/// What the chain asks the user.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthPrompt {
    /// The login password.
    Password {
        /// A previous password for this connection was rejected.
        retry: bool,
        /// 1-based.
        attempt: u8,
    },
    /// The key file's passphrase.
    Passphrase {
        /// The previous passphrase was wrong.
        retry: bool,
        /// 1-based.
        attempt: u8,
    },
    /// A keyboard-interactive info request (texts already sanitized).
    KeyboardInteractive {
        /// Name.
        name: String,
        /// Instructions.
        instructions: String,
        /// The fields.
        prompts: Vec<KbdField>,
    },
}

#[cfg(test)]
thread_local! {
    /// Answer buffers dropped on this thread (`answer_buffers_dropped_after_request`).
    pub(crate) static ANSWERS_DROPPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The user's answer: one value for a password or passphrase, one per field for
/// keyboard-interactive. Each is a [`SecretString`] (zeroized on drop); the chain drops
/// the answer as soon as the request using it returns.
#[derive(Debug)]
pub struct AuthAnswer {
    /// Reported back with [`AuthIo::accepted`].
    pub token: PromptToken,
    /// The values.
    pub values: Vec<SecretString>,
}

impl Drop for AuthAnswer {
    fn drop(&mut self) {
        #[cfg(test)]
        ANSWERS_DROPPED.with(|c| c.set(c.get() + 1));
    }
}

/// The user side of the chain.
#[async_trait]
pub trait AuthIo: Send {
    /// A session-log line.
    fn log(&mut self, kind: LogKind, text: String);
    /// Ask the user; `Ok(None)` = cancelled.
    ///
    /// # Errors
    /// The connection closed while asking.
    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<AuthAnswer>, SshError>;
    /// The answer `token` was part of the successful authentication.
    fn accepted(&mut self, token: PromptToken);
}

// ---------------------------------------------------------------- the chain

/// The private key of a `KeyFile` logon.
pub struct KeyMaterial {
    /// The key text (OpenSSH, PEM, PKCS#8 or PuTTY), zeroized on drop.
    pub text: Zeroizing<String>,
    /// The path, or "vault key of &lt;site&gt;" (prompts and log).
    pub label: String,
    /// The stored passphrase, tried silently before prompting.
    pub passphrase: Option<SecretString>,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// What the chain needs from the connection parameters.
#[derive(Debug)]
pub struct ChainTarget<'a> {
    /// Login user.
    pub user: &'a str,
    /// The logon type (decides the steps).
    pub logon: SshLogon,
    /// The stored password (`Normal`).
    pub password: Option<&'a SecretString>,
    /// The key (`KeyFile`).
    pub key: Option<&'a KeyMaterial>,
    /// Offer the agent's identities first.
    pub try_agent_first: bool,
}

/// One step of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// \[A\] agent identities.
    Agent,
    /// \[P1\] the stored password.
    StoredPassword,
    /// \[P2\] password prompts.
    PasswordPrompts,
    /// \[P2\] only if the server lists `password` but not `keyboard-interactive`.
    PasswordPromptsIfNoKbd,
    /// \[K\] keyboard-interactive; `auto`: the stored/typed password answers once.
    Kbd { auto: bool },
    /// \[F\] the key file.
    KeyFile,
}

fn steps(logon: SshLogon, try_agent_first: bool) -> Vec<Step> {
    let mut steps = Vec::new();
    if try_agent_first && !matches!(logon, SshLogon::Agent | SshLogon::KeyFile) {
        steps.push(Step::Agent);
    }
    match logon {
        SshLogon::Normal => steps.extend([
            Step::StoredPassword,
            Step::Kbd { auto: true },
            Step::PasswordPrompts,
        ]),
        SshLogon::AskForPassword => {
            steps.extend([Step::PasswordPrompts, Step::Kbd { auto: true }]);
        }
        SshLogon::Interactive => {
            steps.extend([Step::Kbd { auto: false }, Step::PasswordPromptsIfNoKbd]);
        }
        SshLogon::KeyFile => steps.push(Step::KeyFile),
        SshLogon::Agent => steps.push(Step::Agent),
    }
    steps
}

/// How a step ended.
enum Flow {
    /// Authenticated.
    Done,
    /// Go on with the next step.
    Next,
    /// Stop: the attempt cap is reached, or the server takes nothing more.
    Stop,
}

struct Chain<'t, 'x> {
    t: &'t ChainTarget<'t>,
    backend: &'x mut (dyn AuthBackend + 'x),
    io: &'x mut (dyn AuthIo + 'x),
    agent: Option<Arc<dyn AgentConnector>>,
    allowed: Vec<String>,
    attempts: u32,
    tried: Vec<&'static str>,
    accepted: Vec<PromptToken>,
    method: &'static str,
    rsa: Option<RsaSigSupport>,
    /// A password for this connection was rejected (the next prompt says "try again").
    password_rejected: bool,
    /// The password typed in \[P2\], for the keyboard-interactive auto-answer.
    typed_password: Option<(SecretString, PromptToken)>,
    kbd_auto_used: bool,
}

impl Chain<'_, '_> {
    fn allows(&self, method: &str) -> bool {
        self.allowed.iter().any(|m| m == method)
    }

    fn exhausted(&self) -> bool {
        self.attempts >= MAX_AUTH_ATTEMPTS || self.allowed.is_empty()
    }

    fn status(&mut self, text: impl Into<String>) {
        self.io.log(LogKind::Status, text.into());
    }

    /// Count one request for `method`. `false`: the cap is reached (nothing sent).
    fn attempt(&mut self, method: &'static str) -> bool {
        if self.attempts >= MAX_AUTH_ATTEMPTS {
            debug!(
                max = MAX_AUTH_ATTEMPTS,
                "authentication attempt cap reached"
            );
            return false;
        }
        self.attempts += 1;
        if !self.tried.contains(&method) {
            self.tried.push(method);
        }
        true
    }

    /// Apply an outcome of a `method` request whose answers were `tokens`: `Some(flow)`
    /// leaves the step (success, or nothing more to try); `None` goes on. Partial
    /// success means the request counted; the new method list decides what follows.
    fn after(
        &mut self,
        method: &'static str,
        out: AuthOutcome,
        tokens: &[PromptToken],
    ) -> Option<Flow> {
        let (done, partial) = match out {
            AuthOutcome::Success => (true, true),
            AuthOutcome::Failure { remaining, partial } => {
                debug!(methods = ?remaining, partial, "authentication continues");
                self.allowed = remaining;
                (false, partial)
            }
        };
        if done || partial {
            for t in tokens {
                if !self.accepted.contains(t) {
                    self.accepted.push(*t);
                }
            }
        }
        if done {
            self.method = method;
            return Some(Flow::Done);
        }
        self.exhausted().then_some(Flow::Stop)
    }

    async fn rsa_support(&mut self) -> RsaSigSupport {
        if let Some(s) = self.rsa {
            return s;
        }
        let s = self.backend.rsa_support().await;
        debug!(?s, "server-sig-algs (RSA)");
        self.rsa = Some(s);
        s
    }

    /// The hash for a key (`Some(None)` for non-RSA keys), or `None` to skip it.
    async fn hash_for(&mut self, is_rsa: bool) -> Option<Option<HashAlg>> {
        if !is_rsa {
            return Some(None);
        }
        let support = self.rsa_support().await;
        let hash = rsa_hash(support);
        match support {
            RsaSigSupport::Unknown => {
                self.status("Server does not support SHA-2 RSA signatures; using ssh-rsa (SHA-1)")
            }
            RsaSigSupport::NoSha2 => {
                self.status("Skipping RSA key: the server accepts no RSA SHA-2 signature algorithm")
            }
            RsaSigSupport::Sha512 | RsaSigSupport::Sha256 => {}
        }
        hash
    }

    async fn run(&mut self) -> Result<&'static str, SshError> {
        self.status(format!("Using username \"{}\".", self.t.user));
        match self.backend.none(self.t.user).await? {
            AuthOutcome::Success => return Ok("none"),
            AuthOutcome::Failure { remaining, .. } => {
                debug!(methods = ?remaining, "server auth methods");
                self.allowed = remaining;
            }
        }
        for step in steps(self.t.logon, self.t.try_agent_first) {
            if self.exhausted() {
                break;
            }
            let flow = match step {
                Step::Agent => self.agent_step().await,
                Step::StoredPassword => self.stored_password_step().await,
                Step::PasswordPrompts => self.password_prompts().await,
                Step::PasswordPromptsIfNoKbd => {
                    if self.allows(KEYBOARD_INTERACTIVE) {
                        Ok(Flow::Next)
                    } else {
                        self.password_prompts().await
                    }
                }
                Step::Kbd { auto } => self.kbd_step(auto).await,
                Step::KeyFile => self.key_step().await,
            }
            .map_err(|e| self.auth_disconnect(e))?;
            match flow {
                Flow::Done => {
                    for token in std::mem::take(&mut self.accepted) {
                        self.io.accepted(token);
                    }
                    return Ok(self.method);
                }
                Flow::Next => {}
                Flow::Stop => break,
            }
        }
        Err(SshError::Auth {
            tried: self.tried.clone(),
            accepts: self.allowed.clone(),
        })
    }

    /// A server that disconnects because of too many failed attempts (OpenSSH
    /// `MaxAuthTries`: "Too many authentication failures") is a permission problem.
    fn auth_disconnect(&self, err: SshError) -> SshError {
        match err {
            SshError::RemoteDisconnect(msg)
                if msg.to_ascii_lowercase().contains("authentication failures") =>
            {
                SshError::Auth {
                    tried: self.tried.clone(),
                    accepts: self.allowed.clone(),
                }
            }
            other => other,
        }
    }

    // ------------------------------------------------------------ \[A\] agent

    async fn agent_step(&mut self) -> Result<Flow, SshError> {
        if !self.allows(PUBLICKEY) {
            return Ok(Flow::Next);
        }
        let Some(connector) = self.agent.clone() else {
            self.status("No SSH agent available");
            return Ok(Flow::Next);
        };
        let mut agent = match connector.connect().await {
            Ok(agent) => agent,
            Err(err) => {
                debug!(%err, "agent unavailable");
                self.status("No SSH agent available");
                return Ok(Flow::Next);
            }
        };
        let identities = match agent.identities().await {
            Ok(ids) => ids,
            Err(err) => {
                debug!(%err, "agent: listing identities failed");
                Vec::new()
            }
        };
        if identities.is_empty() {
            self.status("SSH agent has no keys");
            return Ok(Flow::Next);
        }
        for identity in &identities {
            if !self.allows(PUBLICKEY) {
                return Ok(Flow::Next);
            }
            let public = identity.public_key();
            let is_rsa = public.algorithm().is_rsa();
            let Some(hash) = self.hash_for(is_rsa).await else {
                continue;
            };
            if !self.attempt(PUBLICKEY) {
                return Ok(Flow::Stop);
            }
            let fp = public.fingerprint(HashAlg::Sha256);
            let sig = signature_name(public.algorithm().as_str(), is_rsa, hash);
            self.status(format!(
                "Trying agent key \"{}\" ({sig} {fp})",
                sanitize_server_text(identity.comment(), MAX_PROMPT_TEXT)
            ));
            let out = self
                .backend
                .agent_identity(self.t.user, agent.as_mut(), identity, hash)
                .await?;
            if let Some(flow) = self.after(PUBLICKEY, out, &[]) {
                return Ok(flow);
            }
        }
        Ok(Flow::Next)
    }

    // ------------------------------------------------------------ \[P1\], \[P2\] password

    async fn stored_password_step(&mut self) -> Result<Flow, SshError> {
        let Some(stored) = self.t.password else {
            return Ok(Flow::Next);
        };
        if !self.allows(PASSWORD) {
            return Ok(Flow::Next);
        }
        if !self.attempt(PASSWORD) {
            return Ok(Flow::Stop);
        }
        self.status("Trying password authentication.");
        let out = self.backend.password(self.t.user, stored).await?;
        if let Some(flow) = self.after(PASSWORD, out, &[]) {
            return Ok(flow);
        }
        self.password_rejected = true;
        Ok(Flow::Next)
    }

    async fn password_prompts(&mut self) -> Result<Flow, SshError> {
        for attempt in 1..=PASSWORD_PROMPTS {
            if !self.allows(PASSWORD) {
                return Ok(Flow::Next);
            }
            if self.attempts >= MAX_AUTH_ATTEMPTS {
                return Ok(Flow::Stop);
            }
            let prompt = AuthPrompt::Password {
                retry: self.password_rejected,
                attempt,
            };
            let Some(answer) = self.io.ask(prompt).await? else {
                return Err(SshError::Cancelled);
            };
            if !self.attempt(PASSWORD) {
                return Ok(Flow::Stop);
            }
            self.status("Trying password authentication.");
            let empty = SecretString::from("");
            let password = answer.values.first().unwrap_or(&empty);
            let out = self.backend.password(self.t.user, password).await?;
            self.typed_password = Some((SecretString::from(password.expose()), answer.token));
            let token = answer.token;
            drop(answer);
            if let Some(flow) = self.after(PASSWORD, out, &[token]) {
                return Ok(flow);
            }
            self.password_rejected = true;
        }
        Ok(Flow::Next)
    }

    // ------------------------------------------------------------ \[K\] keyboard-interactive

    async fn kbd_step(&mut self, auto: bool) -> Result<Flow, SshError> {
        for _ in 0..KBD_ROUNDS {
            if !self.allows(KEYBOARD_INTERACTIVE) {
                return Ok(Flow::Next);
            }
            if !self.attempt(KEYBOARD_INTERACTIVE) {
                return Ok(Flow::Stop);
            }
            self.status("Trying keyboard-interactive authentication.");
            // The answers given in this conversation (accepted only if it succeeds).
            let mut tokens: Vec<PromptToken> = Vec::new();
            let mut reply = self.backend.kbd_start(self.t.user).await?;
            loop {
                match reply {
                    KbdReply::Success => {
                        return Ok(self
                            .after(KEYBOARD_INTERACTIVE, AuthOutcome::Success, &tokens)
                            .unwrap_or(Flow::Done));
                    }
                    KbdReply::Failure { remaining, partial } => {
                        let out = AuthOutcome::Failure { remaining, partial };
                        if let Some(flow) = self.after(KEYBOARD_INTERACTIVE, out, &tokens) {
                            return Ok(flow);
                        }
                        break;
                    }
                    KbdReply::Info {
                        name,
                        instruction,
                        prompts,
                    } => {
                        if prompts.len() > MAX_KBD_PROMPTS {
                            self.io.log(
                                LogKind::Error,
                                format!(
                                    "Keyboard-interactive request with {} prompts refused (at most {MAX_KBD_PROMPTS})",
                                    prompts.len()
                                ),
                            );
                            return Ok(Flow::Next);
                        }
                        let answers = self
                            .kbd_answers(auto, &name, &instruction, prompts, &mut tokens)
                            .await?;
                        reply = self.backend.kbd_respond(&answers.values).await?;
                        drop(answers);
                    }
                }
            }
        }
        Ok(Flow::Next)
    }

    /// Answers for one info request: none needed, the password once, or a prompt.
    async fn kbd_answers(
        &mut self,
        auto: bool,
        name: &str,
        instruction: &str,
        prompts: Vec<KbdField>,
        tokens: &mut Vec<PromptToken>,
    ) -> Result<AuthAnswer, SshError> {
        if prompts.is_empty() {
            return Ok(AuthAnswer {
                token: PromptToken(0),
                values: Vec::new(),
            });
        }
        if auto && !self.kbd_auto_used && is_password_request(&prompts) {
            let candidate = match (self.t.password, &self.typed_password) {
                (Some(stored), _) => Some((SecretString::from(stored.expose()), None)),
                (None, Some((typed, token))) => {
                    Some((SecretString::from(typed.expose()), Some(*token)))
                }
                (None, None) => None,
            };
            if let Some((password, token)) = candidate {
                debug!("keyboard-interactive: answered with the password (once)");
                self.kbd_auto_used = true;
                if let Some(t) = token {
                    tokens.push(t);
                }
                return Ok(AuthAnswer {
                    token: PromptToken(0),
                    values: vec![password],
                });
            }
        }
        let n = prompts.len();
        let prompt = AuthPrompt::KeyboardInteractive {
            name: sanitize_server_text(name, MAX_PROMPT_TEXT),
            instructions: sanitize_server_text(instruction, MAX_PROMPT_TEXT),
            prompts: prompts
                .into_iter()
                .map(|p| KbdField {
                    text: sanitize_server_text(&p.text, MAX_PROMPT_TEXT),
                    echo: p.echo,
                })
                .collect(),
        };
        let Some(mut answer) = self.io.ask(prompt).await? else {
            return Err(SshError::Cancelled);
        };
        answer.values.resize_with(n, || SecretString::from(""));
        tokens.push(answer.token);
        Ok(answer)
    }

    // ------------------------------------------------------------ \[F\] key file

    async fn key_step(&mut self) -> Result<Flow, SshError> {
        let Some(km) = self.t.key else {
            return Err(SshError::InvalidInput(
                "No key file is configured for this site".to_owned(),
            ));
        };
        if !self.allows(PUBLICKEY) {
            return Ok(Flow::Next);
        }
        let (key, token) = self.load_key(km).await?;
        let is_rsa = key.algorithm().is_rsa();
        let Some(hash) = self.hash_for(is_rsa).await else {
            return Ok(Flow::Next);
        };
        if !self.attempt(PUBLICKEY) {
            return Ok(Flow::Stop);
        }
        let public = key.public_key();
        let sig = signature_name(public.algorithm().as_str(), is_rsa, hash);
        let fp = public.fingerprint(HashAlg::Sha256);
        self.status(format!("Trying public key {} ({sig} {fp})", km.label));
        let out = self.backend.publickey(self.t.user, key, hash).await?;
        let tokens: Vec<PromptToken> = token.into_iter().collect();
        Ok(self.after(PUBLICKEY, out, &tokens).unwrap_or(Flow::Next))
    }

    /// Decode the key (the stored passphrase silently, then up to
    /// [`PASSPHRASE_TRIES`] prompts). The token is the prompt whose passphrase worked.
    async fn load_key(
        &mut self,
        km: &KeyMaterial,
    ) -> Result<(Arc<PrivateKey>, Option<PromptToken>), SshError> {
        let bad = |e: KeyError| key_error(&km.label, &e);
        match decode_blocking(&km.text, None).await {
            Ok(key) => return Ok((Arc::new(key), None)),
            Err(KeyError::NeedsPassphrase) => {}
            Err(e) => return Err(bad(e)),
        }
        let mut retry = false;
        if let Some(stored) = &km.passphrase {
            match decode_blocking(&km.text, Some(stored.expose())).await {
                Ok(key) => return Ok((Arc::new(key), None)),
                Err(KeyError::WrongPassphrase | KeyError::NeedsPassphrase) => {
                    debug!("the stored passphrase does not decrypt the key");
                    retry = true;
                }
                Err(e) => return Err(bad(e)),
            }
        }
        for attempt in 1..=PASSPHRASE_TRIES {
            let Some(answer) = self
                .io
                .ask(AuthPrompt::Passphrase { retry, attempt })
                .await?
            else {
                return Err(SshError::Cancelled);
            };
            let pass = answer.values.first().map_or("", |a| a.expose());
            match decode_blocking(&km.text, Some(pass)).await {
                Ok(key) => return Ok((Arc::new(key), Some(answer.token))),
                Err(KeyError::WrongPassphrase | KeyError::NeedsPassphrase) => {
                    debug!(attempt, "wrong passphrase");
                    retry = true;
                }
                Err(e) => return Err(bad(e)),
            }
        }
        Err(SshError::WrongPassphrase {
            label: km.label.clone(),
            attempts: PASSPHRASE_TRIES,
        })
    }
}

/// Decode on the blocking pool (Argon2 and RSA checks can take a while).
async fn decode_blocking(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyError> {
    let text = Zeroizing::new(text.to_owned());
    let pass = passphrase.map(|p| Zeroizing::new(p.to_owned()));
    tokio::task::spawn_blocking(move || keys::decode(&text, pass.as_deref().map(String::as_str)))
        .await
        .map_err(|e| KeyError::Read(e.to_string()))?
}

/// The user-facing error for a key that can't be used.
pub fn key_error(label: &str, err: &KeyError) -> SshError {
    SshError::InvalidInput(match err {
        KeyError::TooLarge => format!("{label} is not a private key (larger than 64 KiB)"),
        KeyError::Format | KeyError::PublicKey => err.to_string(),
        other => format!("Could not read key file {label}: {other}"),
    })
}

/// Run the chain for `target` against `backend`, asking through `io`; `agent` is the
/// SSH agent (`None`: the agent step logs "No SSH agent available"). Returns the
/// method that succeeded (`password`, `publickey`, …).
///
/// # Errors
/// [`SshError::Auth`] with the methods tried when nothing worked;
/// [`SshError::WrongPassphrase`]; [`SshError::Cancelled`]; connection errors.
pub async fn run_chain(
    target: &ChainTarget<'_>,
    backend: &mut (dyn AuthBackend + '_),
    io: &mut (dyn AuthIo + '_),
    agent: Option<Arc<dyn AgentConnector>>,
) -> Result<&'static str, SshError> {
    let mut chain = Chain {
        t: target,
        backend,
        io,
        agent,
        allowed: Vec::new(),
        attempts: 0,
        tried: Vec::new(),
        accepted: Vec::new(),
        method: "none",
        rsa: None,
        password_rejected: false,
        typed_password: None,
        kbd_auto_used: false,
    };
    chain.run().await
}

// ---------------------------------------------------------------- russh backend

/// [`AuthBackend`] over the russh connection. Every request is bounded by the
/// connection timeout and the cancel token.
pub(crate) struct RusshBackend<'h> {
    pub(crate) handle: &'h mut Handle<ClientHandler>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) timeout: Duration,
    pub(crate) keepalive_secs: u64,
    pub(crate) cancel: CancellationToken,
}

impl std::fmt::Debug for RusshBackend<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusshBackend").finish_non_exhaustive()
    }
}

/// How long to wait for the handler to record why the transport ended.
const END_CAUSE_WAIT: Duration = Duration::from_millis(500);

/// Map a failed request: the server's disconnect (if any) wins over russh's error.
pub(crate) async fn request_error(
    shared: &Shared,
    err: &russh::Error,
    keepalive_secs: u64,
) -> SshError {
    match shared.end_cause(END_CAUSE_WAIT).await {
        Some(cause @ (EndCause::Remote { .. } | EndCause::KeepaliveTimeout)) => {
            cause.to_error(keepalive_secs)
        }
        _ => from_russh(err, keepalive_secs),
    }
}

fn methods(list: &russh::MethodSet) -> Vec<String> {
    list.iter()
        .map(|m| <&'static str>::from(m).to_owned())
        .collect()
}

fn outcome(result: AuthResult) -> AuthOutcome {
    match result {
        AuthResult::Success => AuthOutcome::Success,
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => AuthOutcome::Failure {
            remaining: methods(&remaining_methods),
            partial: partial_success,
        },
    }
}

fn kbd(reply: KeyboardInteractiveAuthResponse) -> KbdReply {
    match reply {
        KeyboardInteractiveAuthResponse::Success => KbdReply::Success,
        KeyboardInteractiveAuthResponse::Failure {
            remaining_methods,
            partial_success,
        } => KbdReply::Failure {
            remaining: methods(&remaining_methods),
            partial: partial_success,
        },
        KeyboardInteractiveAuthResponse::InfoRequest {
            name,
            instructions,
            prompts,
        } => KbdReply::Info {
            name,
            instruction: instructions,
            prompts: prompts
                .into_iter()
                .map(|p| KbdField {
                    text: p.prompt,
                    echo: p.echo,
                })
                .collect(),
        },
    }
}

/// Signs auth requests through an [`Agent`] for russh.
struct AgentSigner<'a> {
    agent: &'a mut dyn Agent,
}

/// An agent signing failure, for russh.
#[derive(Debug)]
struct SignError(String);

impl From<russh::SendError> for SignError {
    fn from(err: russh::SendError) -> Self {
        Self(err.to_string())
    }
}

impl russh::Signer for AgentSigner<'_> {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.agent
            .sign(key, hash_alg, to_sign)
            .await
            .map_err(|e| SignError(e.0))
    }
}

/// Bounded by `timeout` and `cancel`.
macro_rules! guarded {
    ($self:ident, $fut:expr) => {{
        let res = tokio::select! {
            biased;
            () = $self.cancel.cancelled() => return Err(SshError::Cancelled),
            r = tokio::time::timeout($self.timeout, $fut) => r,
        };
        match res {
            Err(_) => return Err(SshError::AuthTimeout),
            Ok(r) => r,
        }
    }};
}

#[async_trait]
impl AuthBackend for RusshBackend<'_> {
    async fn none(&mut self, user: &str) -> Result<AuthOutcome, SshError> {
        match guarded!(self, self.handle.authenticate_none(user)) {
            Ok(r) => Ok(outcome(r)),
            Err(e) => Err(request_error(&self.shared, &e, self.keepalive_secs).await),
        }
    }

    async fn password(
        &mut self,
        user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, SshError> {
        // russh takes an owned `String`; it lives only for the request.
        let r = guarded!(
            self,
            self.handle.authenticate_password(user, password.expose())
        );
        match r {
            Ok(r) => Ok(outcome(r)),
            Err(e) => Err(request_error(&self.shared, &e, self.keepalive_secs).await),
        }
    }

    async fn publickey(
        &mut self,
        user: &str,
        key: Arc<PrivateKey>,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        let key = PrivateKeyWithHashAlg::new(key, hash);
        match guarded!(self, self.handle.authenticate_publickey(user, key)) {
            Ok(r) => Ok(outcome(r)),
            Err(e) => Err(request_error(&self.shared, &e, self.keepalive_secs).await),
        }
    }

    async fn agent_identity(
        &mut self,
        user: &str,
        agent: &mut dyn Agent,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        let mut signer = AgentSigner { agent };
        let r = match identity {
            AgentIdentity::PublicKey { key, .. } => guarded!(
                self,
                self.handle
                    .authenticate_publickey_with(user, key.clone(), hash, &mut signer)
            ),
            AgentIdentity::Certificate { certificate, .. } => guarded!(
                self,
                self.handle.authenticate_certificate_with(
                    user,
                    certificate.clone(),
                    hash,
                    &mut signer
                )
            ),
        };
        r.map(outcome)
            .map_err(|e| SshError::Protocol(format!("the SSH agent could not sign: {}", e.0)))
    }

    async fn kbd_start(&mut self, user: &str) -> Result<KbdReply, SshError> {
        let r = guarded!(
            self,
            self.handle
                .authenticate_keyboard_interactive_start(user, None::<String>)
        );
        match r {
            Ok(r) => Ok(kbd(r)),
            Err(e) => Err(request_error(&self.shared, &e, self.keepalive_secs).await),
        }
    }

    async fn kbd_respond(&mut self, answers: &[SecretString]) -> Result<KbdReply, SshError> {
        // russh takes owned `String`s; they live only for the request.
        let responses: Vec<String> = answers.iter().map(|a| a.expose().to_owned()).collect();
        let r = guarded!(
            self,
            self.handle
                .authenticate_keyboard_interactive_respond(responses)
        );
        match r {
            Ok(r) => Ok(kbd(r)),
            Err(e) => Err(request_error(&self.shared, &e, self.keepalive_secs).await),
        }
    }

    async fn rsa_support(&mut self) -> RsaSigSupport {
        let r = tokio::time::timeout(self.timeout, self.handle.best_supported_rsa_hash()).await;
        match r {
            Ok(Ok(Some(Some(HashAlg::Sha512)))) => RsaSigSupport::Sha512,
            Ok(Ok(Some(Some(HashAlg::Sha256)))) => RsaSigSupport::Sha256,
            Ok(Ok(Some(_))) => RsaSigSupport::NoSha2,
            _ => RsaSigSupport::Unknown,
        }
    }
}

// ---------------------------------------------------------------- prompts over T04

/// [`AuthIo`] over the T04 event bus: log lines to the session log, prompts with
/// `EventSender::prompt_tracked` (no timeout; `cancel` aborts), and
/// `CredentialAccepted` for accepted answers.
pub struct PromptIo<'a> {
    pub(crate) log: &'a SessionLog,
    pub(crate) cancel: &'a CancellationToken,
    pub(crate) shared: Arc<Shared>,
    /// `"alice@web01.example.com:22"`.
    pub(crate) target: String,
    /// `"web01.example.com:22"`.
    pub(crate) host_port: String,
    pub(crate) password_cache: SecretCacheKey,
    pub(crate) key_label: String,
    pub(crate) can_save: bool,
    pub(crate) ids: HashMap<PromptToken, PromptId>,
}

impl std::fmt::Debug for PromptIo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptIo").finish_non_exhaustive()
    }
}

impl<'a> PromptIo<'a> {
    /// Prompts for `user@host:port`.
    pub(crate) fn new(
        log: &'a SessionLog,
        cancel: &'a CancellationToken,
        shared: Arc<Shared>,
        params: &super::SshConnectParams,
    ) -> Self {
        let host_port = if params.host.contains(':') {
            format!("[{}]:{}", params.host, params.port)
        } else {
            format!("{}:{}", params.host, params.port)
        };
        Self {
            log,
            cancel,
            shared,
            target: format!("{}@{host_port}", params.user),
            host_port,
            password_cache: SecretCacheKey::Password {
                protocol: Protocol::Sftp,
                host: params.host.to_ascii_lowercase(),
                port: params.port,
                user: params.user.clone(),
            },
            key_label: params.key_label.clone(),
            can_save: params.can_save,
            ids: HashMap::new(),
        }
    }

    fn kind(&self, prompt: AuthPrompt) -> PromptKind {
        match prompt {
            AuthPrompt::Password { retry, attempt } => PromptKind::Password(PasswordPrompt {
                purpose: PasswordPurpose::Login,
                target: self.target.clone(),
                retry,
                attempt,
                max_attempts: PASSWORD_PROMPTS,
                cache_key: self.password_cache.clone(),
                can_save: self.can_save,
            }),
            AuthPrompt::Passphrase { retry, attempt } => {
                PromptKind::KeyPassphrase(PassphrasePrompt {
                    key_label: self.key_label.clone(),
                    retry,
                    attempt,
                    max_attempts: PASSPHRASE_TRIES,
                    cache_key: SecretCacheKey::Passphrase {
                        key: self.key_label.clone(),
                    },
                    can_save: self.can_save,
                })
            }
            AuthPrompt::KeyboardInteractive {
                name,
                instructions,
                prompts,
            } => PromptKind::KeyboardInteractive(KbdInteractivePrompt {
                host: self.host_port.clone(),
                name,
                instructions,
                prompts,
            }),
        }
    }
}

#[async_trait]
impl AuthIo for PromptIo<'_> {
    fn log(&mut self, kind: LogKind, text: String) {
        self.log.events.log(self.log.session, kind, text);
    }

    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<AuthAnswer>, SshError> {
        let kind = self.kind(prompt);
        let mut closed = self.shared.closed.subscribe();
        let asked = self
            .log
            .events
            .prompt_tracked(self.log.session, kind, Some(self.cancel));
        let answer = tokio::select! {
            r = asked => Some(r),
            r = closed.wait_for(|c| *c) => {
                drop(r);
                None
            }
        };
        let Some(answer) = answer else {
            // A "too many connections" disconnect keeps its meaning (T41).
            return Err(match self.shared.end_cause(END_CAUSE_WAIT).await {
                Some(cause @ EndCause::Remote { code, .. })
                    if code == super::errors::DISCONNECT_TOO_MANY_CONNECTIONS =>
                {
                    cause.to_error(0)
                }
                _ => SshError::ClosedWhilePrompting,
            });
        };
        let (id, response) = match answer {
            Ok(a) => a,
            Err(courier_ftp_core::Error::Cancelled) => return Ok(None),
            Err(e) => return Err(SshError::Protocol(e.to_string())),
        };
        let token = PromptToken(id.get());
        self.ids.insert(token, id);
        let values = match response {
            PromptResponse::Secret { value, .. } => vec![value],
            PromptResponse::Answers(values) => values,
            _ => return Ok(None),
        };
        Ok(Some(AuthAnswer { token, values }))
    }

    fn accepted(&mut self, token: PromptToken) {
        if let Some(id) = self.ids.get(&token) {
            self.log.events.credential_accepted(self.log.session, *id);
        }
    }
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
