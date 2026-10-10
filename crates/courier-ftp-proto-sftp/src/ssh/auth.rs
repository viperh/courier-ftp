//! The authentication chain (see the module docs of [`super`]).

use std::sync::Arc;

use courier_ftp_core::{
    Error, Result,
    events::{LogKind, PromptKind, PromptResponse},
    model::{LocalPath, LogonType},
};
use russh::{
    MethodKind,
    client::{AuthResult, KeyboardInteractiveAuthResponse},
    keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, agent::AgentIdentity},
};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use super::{
    CredentialCache, KeyInput, PASSPHRASE_TRIES, PASSWORD_TRIES, SshContext, SshOptions,
    SshSession, bounded, connection_error,
    hostkey::describe_key,
    keys::{KeyError, KeyFile},
    text::sanitize_server_text,
};

/// Info requests answered in one keyboard-interactive conversation.
const KBD_MAX_REQUESTS: usize = 16;
/// Keyboard-interactive conversations per connection (2FA servers restart it
/// after a partial success).
const KBD_MAX_ROUNDS: usize = 3;
/// Steps after a partial success.
const MAX_CONTINUATIONS: usize = 4;

/// One request to the server, bounded by the timeout and cancellation.
async fn request<T>(
    timeout: std::time::Duration,
    cancel: &CancellationToken,
    shared: &std::sync::Mutex<super::handler::Shared>,
    fut: impl Future<Output = std::result::Result<T, russh::Error>>,
) -> Result<T> {
    bounded(timeout, cancel, async {
        fut.await.map_err(|e| connection_error(shared, &e))
    })
    .await
}

/// [`request`] with the chain's timeout, token and shared state (field paths
/// stay disjoint from the `handle` the future borrows).
macro_rules! req {
    ($chain:ident, $fut:expr) => {
        request(
            $chain.opts.timeout,
            $chain.cancel,
            &$chain.session.shared,
            $fut,
        )
    };
}

/// How a step ended.
#[derive(Debug)]
enum Step {
    /// Authenticated.
    Done,
    /// Accepted, but the server wants another method.
    Partial,
    /// Rejected or not possible; the reason for the final error.
    Failed(String),
}

/// Run the chain on `session`.
pub(super) async fn authenticate(
    session: &mut SshSession,
    opts: &SshOptions,
    ctx: &SshContext,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut chain = Chain {
        session,
        opts,
        ctx,
        cancel,
        user: opts.logon.user().to_owned(),
        allowed: None,
        password: opts.logon.password().cloned(),
        password_typed: false,
        kbd_auto_used: false,
        rsa_hash: None,
    };
    chain.run().await
}

struct Chain<'a> {
    session: &'a mut SshSession,
    opts: &'a SshOptions,
    ctx: &'a SshContext,
    cancel: &'a CancellationToken,
    user: String,
    /// The methods the server accepts (from its latest failure reply).
    allowed: Option<Vec<MethodKind>>,
    /// The password: stored, remembered or typed.
    password: Option<SecretString>,
    /// `password` was typed (or remembered) for this connection.
    password_typed: bool,
    /// The stored password answered a keyboard-interactive prompt already.
    kbd_auto_used: bool,
    /// The RSA signature hash, once asked (`Some(None)`: `ssh-rsa`).
    rsa_hash: Option<Option<HashAlg>>,
}

impl Chain<'_> {
    fn status(&self, text: impl Into<String>) {
        self.ctx.events.log(self.ctx.session, LogKind::Status, text);
    }

    fn allows(&self, method: MethodKind) -> bool {
        self.allowed.as_ref().is_none_or(|m| m.contains(&method))
    }

    fn accepted_methods(&self) -> String {
        match &self.allowed {
            Some(m) if !m.is_empty() => m
                .iter()
                .map(<&'static str>::from)
                .collect::<Vec<_>>()
                .join(", "),
            Some(_) => "none".to_owned(),
            None => "unknown".to_owned(),
        }
    }

    fn failure(&self, reason: &str) -> Error {
        Error::Auth(format!(
            "{reason} (the server accepts: {})",
            self.accepted_methods()
        ))
    }

    fn cache(&self) -> Option<&CredentialCache> {
        self.ctx.credentials.as_ref()
    }

    fn outcome(&mut self, result: AuthResult, rejected: &str) -> Step {
        match result {
            AuthResult::Success => Step::Done,
            AuthResult::Failure {
                remaining_methods,
                partial_success,
            } => {
                self.allowed = Some(remaining_methods.to_vec());
                if partial_success {
                    self.status("Partial success; the server asks for another method");
                    Step::Partial
                } else {
                    Step::Failed(rejected.to_owned())
                }
            }
        }
    }

    async fn run(&mut self) -> Result<()> {
        let user = self.user.clone();
        let first = req!(self, self.session.handle.authenticate_none(user)).await?;
        match first {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure {
                remaining_methods, ..
            } => {
                let methods = remaining_methods.to_vec();
                tracing::debug!(?methods, "server auth methods");
                self.allowed = Some(methods);
            }
        }

        let mut step = self.main_step().await?;
        for _ in 0..MAX_CONTINUATIONS {
            if !matches!(step, Step::Partial) {
                break;
            }
            step = self.continuation().await?;
        }
        match step {
            Step::Done => {
                self.remember_password();
                Ok(())
            }
            Step::Partial => Err(self.failure("authentication did not complete")),
            Step::Failed(reason) => {
                // A remembered password that no longer works is dropped.
                self.forget_password();
                Err(self.failure(&reason))
            }
        }
    }

    async fn main_step(&mut self) -> Result<Step> {
        if let Some(key) = self.opts.key.clone() {
            return self.key_step(key).await;
        }
        match &self.opts.logon {
            LogonType::Normal { .. } => {
                if self.opts.try_agent_first && self.allows(MethodKind::PublicKey) {
                    match self.agent_step().await? {
                        Step::Failed(reason) => {
                            tracing::debug!(%reason, "agent first: no luck");
                        }
                        other => return Ok(other),
                    }
                }
                self.password_or_kbd(false).await
            }
            LogonType::AskForPassword { .. } => self.password_or_kbd(true).await,
            LogonType::Interactive { .. } => {
                if self.allows(MethodKind::KeyboardInteractive) {
                    self.kbd_step().await
                } else {
                    self.password_or_kbd(true).await
                }
            }
            LogonType::KeyFile { path, .. } => self.key_step(KeyInput::File(path.clone())).await,
            LogonType::Agent { .. } => self.agent_step().await,
            LogonType::Anonymous | LogonType::Account { .. } => Err(Error::InvalidInput(
                "anonymous and account logons are not available for SFTP".to_owned(),
            )),
        }
    }

    /// After a partial success: the next method the server asks for.
    async fn continuation(&mut self) -> Result<Step> {
        if self.allows(MethodKind::KeyboardInteractive) {
            self.kbd_step().await
        } else if self.allows(MethodKind::Password) {
            self.password_or_kbd(true).await
        } else if self.allows(MethodKind::PublicKey)
            && matches!(self.opts.logon, LogonType::Agent { .. })
        {
            self.agent_step().await
        } else {
            Ok(Step::Failed(
                "the server asks for a method this logon type can't provide".to_owned(),
            ))
        }
    }

    // ------------------------------------------------------------ password

    /// `password`, or `keyboard-interactive` with the password answering a
    /// password prompt. `may_ask`: a missing or rejected password is asked
    /// for (up to [`PASSWORD_TRIES`] times).
    async fn password_or_kbd(&mut self, may_ask: bool) -> Result<Step> {
        if !self.allows(MethodKind::Password) {
            if self.allows(MethodKind::KeyboardInteractive) {
                if self.password.is_none() && may_ask {
                    self.ask_password(false).await?;
                }
                return self.kbd_step().await;
            }
            return Ok(Step::Failed(
                "the server does not accept password authentication".to_owned(),
            ));
        }
        let tries = if may_ask { PASSWORD_TRIES } else { 1 };
        let mut retry = false;
        for _ in 0..tries {
            if self.password.is_none() || retry {
                if !may_ask {
                    break;
                }
                self.ask_password(retry).await?;
            }
            let Some(password) = self.password.clone() else {
                break;
            };
            self.status("Authenticating with password");
            let user = self.user.clone();
            let request = self
                .session
                .handle
                .authenticate_password(user, password.expose_secret().to_owned());
            let result = req!(self, request).await?;
            drop(password);
            match self.outcome(result, "server rejected password") {
                Step::Failed(reason) => {
                    self.status("Password rejected");
                    self.forget_password();
                    if !self.allows(MethodKind::Password) {
                        return Ok(Step::Failed(reason));
                    }
                    retry = true;
                }
                other => return Ok(other),
            }
        }
        Ok(Step::Failed("server rejected password".to_owned()))
    }

    /// Ask for the password (or take the remembered one when not a retry).
    async fn ask_password(&mut self, retry: bool) -> Result<()> {
        let key = CredentialCache::password_key(&self.opts.host, &self.user);
        if !retry && let Some(remembered) = self.cache().and_then(|c| c.get(&key)) {
            self.password = Some(remembered);
            self.password_typed = true;
            return Ok(());
        }
        let for_ = format!("{}@{}", self.user, self.opts.host);
        let answer = self
            .ctx
            .events
            .ask(
                Some(self.ctx.session),
                PromptKind::Password { for_ },
                self.cancel,
            )
            .await?;
        match answer {
            PromptResponse::Secret(password) => {
                self.password = Some(password);
                self.password_typed = true;
                Ok(())
            }
            _ => Err(Error::Cancelled),
        }
    }

    fn forget_password(&mut self) {
        if self.password_typed {
            self.password = None;
            let key = CredentialCache::password_key(&self.opts.host, &self.user);
            if let Some(cache) = self.cache() {
                cache.forget(&key);
            }
        } else {
            // A stored password is not asked again (logon type Normal).
            self.password = None;
        }
    }

    fn remember_password(&self) {
        if self.password_typed
            && let (Some(cache), Some(password)) = (self.cache(), &self.password)
        {
            let key = CredentialCache::password_key(&self.opts.host, &self.user);
            cache.put(key, password.clone());
        }
    }

    // ------------------------------------------------------------ keyboard-interactive

    async fn kbd_step(&mut self) -> Result<Step> {
        if !self.allows(MethodKind::KeyboardInteractive) {
            return Ok(Step::Failed(
                "the server does not accept keyboard-interactive authentication".to_owned(),
            ));
        }
        for _ in 0..KBD_MAX_ROUNDS {
            self.status("Authenticating with keyboard-interactive");
            let user = self.user.clone();
            let start = self
                .session
                .handle
                .authenticate_keyboard_interactive_start(user, None::<String>);
            let mut reply = req!(self, start).await?;
            let mut requests = 0;
            let step = loop {
                match reply {
                    KeyboardInteractiveAuthResponse::Success => break Step::Done,
                    KeyboardInteractiveAuthResponse::Failure {
                        remaining_methods,
                        partial_success,
                    } => {
                        break self.outcome(
                            AuthResult::Failure {
                                remaining_methods,
                                partial_success,
                            },
                            "server rejected the keyboard-interactive answers",
                        );
                    }
                    KeyboardInteractiveAuthResponse::InfoRequest {
                        name,
                        instructions,
                        prompts,
                    } => {
                        requests += 1;
                        if requests > KBD_MAX_REQUESTS {
                            break Step::Failed(
                                "too many keyboard-interactive requests".to_owned(),
                            );
                        }
                        let answers = self.kbd_answers(&name, &instructions, &prompts).await?;
                        // russh takes owned `String`s; they live for this request only.
                        let responses = answers
                            .iter()
                            .map(|a| a.expose_secret().to_owned())
                            .collect();
                        drop(answers);
                        let respond = self
                            .session
                            .handle
                            .authenticate_keyboard_interactive_respond(responses);
                        reply = req!(self, respond).await?;
                    }
                }
            };
            match step {
                // 2FA: another conversation after a partial success.
                Step::Partial if self.allows(MethodKind::KeyboardInteractive) => {}
                other => return Ok(other),
            }
        }
        Ok(Step::Partial)
    }

    /// Answers for one info request.
    async fn kbd_answers(
        &mut self,
        name: &str,
        instructions: &str,
        prompts: &[russh::client::Prompt],
    ) -> Result<Vec<SecretString>> {
        if prompts.is_empty() {
            return Ok(Vec::new());
        }
        if let [only] = prompts
            && !only.echo
            && only.prompt.to_lowercase().contains("password")
            && !self.kbd_auto_used
            && let Some(password) = &self.password
        {
            tracing::debug!("keyboard-interactive: answered with the password");
            self.kbd_auto_used = true;
            return Ok(vec![password.clone()]);
        }
        let kind = PromptKind::KeyboardInteractive {
            name: sanitize_server_text(name),
            instructions: sanitize_server_text(instructions),
            prompts: prompts
                .iter()
                .map(|p| (sanitize_server_text(&p.prompt), p.echo))
                .collect(),
        };
        let answer = self
            .ctx
            .events
            .ask(Some(self.ctx.session), kind, self.cancel)
            .await?;
        match answer {
            PromptResponse::Answers(mut answers) => {
                answers.resize_with(prompts.len(), || SecretString::from(String::new()));
                Ok(answers)
            }
            // A single prompt answered like a password dialog.
            PromptResponse::Secret(secret) if prompts.len() == 1 => Ok(vec![secret]),
            _ => Err(Error::Cancelled),
        }
    }

    // ------------------------------------------------------------ public key

    /// The hash for an RSA signature: `rsa-sha2-512/256` when the server
    /// lists them in `server-sig-algs`, else `ssh-rsa` (SHA-1).
    async fn rsa_hash(&mut self) -> Result<Option<HashAlg>> {
        if let Some(hash) = self.rsa_hash {
            return Ok(hash);
        }
        let ask = self.session.handle.best_supported_rsa_hash();
        let hash = req!(self, ask).await?.flatten();
        tracing::debug!(?hash, "RSA signature hash");
        self.rsa_hash = Some(hash);
        Ok(hash)
    }

    async fn key_step(&mut self, input: KeyInput) -> Result<Step> {
        if !self.allows(MethodKind::PublicKey) {
            return Ok(Step::Failed(
                "the server does not accept public key authentication".to_owned(),
            ));
        }
        let file = match &input {
            KeyInput::File(path) => KeyFile::read(path).await,
            KeyInput::Text { label, text } => KeyFile::from_text(label.clone(), text.clone()),
        }
        .map_err(|e| Error::Auth(e.to_string()))?;
        let path = match &input {
            KeyInput::File(path) => path.clone(),
            KeyInput::Text { label, .. } => LocalPath::new(label),
        };
        let key = self.decode_key(&file, &path).await?;
        self.status(format!(
            "Authenticating with public key \"{}\" ({})",
            file.label(),
            describe_key(key.public_key())
        ));
        let hash = if key.algorithm().is_rsa() {
            self.rsa_hash().await?
        } else {
            None
        };
        let user = self.user.clone();
        let request = self
            .session
            .handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash));
        let result = req!(self, request).await?;
        Ok(self.outcome(result, "server rejected the key"))
    }

    /// Decode the key, asking for the passphrase when it is encrypted.
    async fn decode_key(&mut self, file: &KeyFile, path: &LocalPath) -> Result<PrivateKey> {
        if !file.is_encrypted() {
            return file
                .decode(None)
                .await
                .map_err(|e| Error::Auth(e.to_string()));
        }
        if let Some(saved) = self.opts.passphrase.clone() {
            match file.decode(Some(&saved)).await {
                Ok(key) => return Ok(key),
                Err(KeyError::WrongPassphrase) => {
                    tracing::debug!("the saved key passphrase does not open the key");
                }
                Err(other) => return Err(Error::Auth(other.to_string())),
            }
        }
        let cache_key = CredentialCache::passphrase_key(file.label());
        if let Some(remembered) = self.cache().and_then(|c| c.get(&cache_key)) {
            match file.decode(Some(&remembered)).await {
                Ok(key) => return Ok(key),
                Err(_) => {
                    if let Some(cache) = self.cache() {
                        cache.forget(&cache_key);
                    }
                }
            }
        }
        for attempt in 0..PASSPHRASE_TRIES {
            if attempt > 0 {
                self.ctx.events.log(
                    self.ctx.session,
                    LogKind::Error,
                    format!("Wrong passphrase for key \"{}\"", file.label()),
                );
            }
            let answer = self
                .ctx
                .events
                .ask(
                    Some(self.ctx.session),
                    PromptKind::KeyPassphrase { path: path.clone() },
                    self.cancel,
                )
                .await?;
            let PromptResponse::Secret(passphrase) = answer else {
                return Err(Error::Cancelled);
            };
            match file.decode(Some(&passphrase)).await {
                Ok(key) => {
                    if let Some(cache) = self.cache() {
                        cache.put(cache_key, passphrase);
                    }
                    return Ok(key);
                }
                Err(KeyError::WrongPassphrase) => {}
                Err(other) => return Err(Error::Auth(other.to_string())),
            }
        }
        Err(Error::Auth(format!(
            "wrong passphrase for key \"{}\" ({PASSPHRASE_TRIES} attempts)",
            file.label()
        )))
    }

    // ------------------------------------------------------------ agent

    async fn agent_step(&mut self) -> Result<Step> {
        if !self.allows(MethodKind::PublicKey) {
            return Ok(Step::Failed(
                "the server does not accept public key authentication".to_owned(),
            ));
        }
        let mut agent = match self.ctx.agent.connect().await {
            Ok(agent) => agent,
            Err(reason) => {
                self.ctx
                    .events
                    .log(self.ctx.session, LogKind::Error, reason.clone());
                return Ok(Step::Failed(reason));
            }
        };
        let identities = bounded(self.opts.timeout, self.cancel, async {
            agent
                .request_identities()
                .await
                .map_err(|e| Error::Auth(format!("the SSH agent failed: {e}")))
        })
        .await?;
        if identities.is_empty() {
            return Ok(Step::Failed("the SSH agent holds no keys".to_owned()));
        }
        for identity in identities {
            if !self.allows(MethodKind::PublicKey) {
                break;
            }
            let public = identity.public_key().into_owned();
            self.status(format!(
                "Authenticating with agent key {}",
                describe_key(&public)
            ));
            let hash = if public.algorithm().is_rsa() {
                self.rsa_hash().await?
            } else {
                None
            };
            let user = self.user.clone();
            let handle = &mut self.session.handle;
            let signed = bounded(self.opts.timeout, self.cancel, async {
                let result = match &identity {
                    AgentIdentity::PublicKey { key, .. } => {
                        handle
                            .authenticate_publickey_with(user, key.clone(), hash, &mut agent)
                            .await
                    }
                    AgentIdentity::Certificate { certificate, .. } => {
                        handle
                            .authenticate_certificate_with(
                                user,
                                certificate.clone(),
                                hash,
                                &mut agent,
                            )
                            .await
                    }
                };
                result.map_err(|e| Error::Auth(format!("the SSH agent could not sign: {e}")))
            })
            .await;
            let result = match signed {
                Ok(result) => result,
                Err(Error::Auth(reason)) => {
                    self.ctx
                        .events
                        .log(self.ctx.session, LogKind::Error, reason);
                    continue;
                }
                Err(other) => return Err(other),
            };
            match self.outcome(result, "server rejected every agent key") {
                Step::Failed(_) => {}
                other => return Ok(other),
            }
        }
        Ok(Step::Failed("server rejected every agent key".to_owned()))
    }
}
