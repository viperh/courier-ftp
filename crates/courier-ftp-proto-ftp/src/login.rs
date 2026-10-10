//! Login scripts and the login state machine (RFC 959 §6 USER/PASS/ACCT, generalised
//! for T15's proxy scripts; T10 §6).
//!
//! | Step | Reply | Next |
//! |---|---|---|
//! | `USER` | 230, 232 | logged in for this target: the following `PASS`/`ACCT` of that target are skipped |
//! | | 331 | a `PASS` step must follow (missing → password prompt) |
//! | | 332 | an `ACCT` step must follow (missing → account prompt) |
//! | `PASS` | 230, 202, 232 | logged in for this target |
//! | | 332 | `ACCT` |
//! | `ACCT` | 230, 202 | logged in |
//! | any | 421 / 530 "too many connections" | `ConnectionLimit` |
//! | any | other 421 | `Connection` |
//! | any | 530, 430, other 5xx | `Auth` (`Proxy` for proxy steps) |
//! | any | other 4xx | `Protocol` (transient) |
//! | `Other` | 4xx/5xx | `Proxy("FTP proxy could not connect to the server: …")` |
//!
//! Secrets are resolved lazily: a password prompt appears only when `331` arrives.
//! After a successful login every prompt answered during it is confirmed with
//! [`EventSender::credential_accepted`](courier_ftp_core::events::EventSender::credential_accepted)
//! (T69 then caches/saves the value).

use std::{collections::VecDeque, fmt};

use courier_ftp_core::{
    Error, Result,
    events::{
        PasswordPrompt, PasswordPurpose, PromptId, PromptKind, PromptResponse, SecretCacheKey,
    },
    model::LogonType,
    net::CancellationToken,
    secret::SecretString,
};

use crate::{
    command::Command,
    control::{ControlConnection, Phase, is_too_many},
    reply::Reply,
};

/// The password sent for anonymous logins.
pub const ANONYMOUS_PASSWORD: &str = "anonymous@example.com";

/// An ordered login sequence. The default is built from `ServerAddress.user` +
/// `LogonType` ([`LoginScript::for_logon`]); T15 builds proxy scripts.
#[derive(Debug)]
pub struct LoginScript {
    /// The steps, in order.
    pub steps: Vec<LoginStep>,
    /// Prompt metadata for `AskPassword`/`AskAccount` steps (and for the prompts the
    /// state machine adds when the server asks for a missing password/account).
    pub prompt: Option<LoginPromptInfo>,
}

/// One step of a [`LoginScript`].
#[derive(Debug)]
pub struct LoginStep {
    /// What the step sends.
    pub kind: StepKind,
    /// The argument.
    pub value: StepValue,
    /// Log text with secrets already replaced by `****` (T15 custom lines).
    pub log_text: String,
    /// Which login this step belongs to (proxy or target), for error messages.
    pub target: LoginTarget,
}

/// The command of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// `USER`.
    User,
    /// `PASS`.
    Pass,
    /// `ACCT`.
    Acct,
    /// Another verb (T15 `SITE`, `OPEN`).
    Other(&'static str),
}

impl StepKind {
    fn verb(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Pass => "PASS",
            Self::Acct => "ACCT",
            Self::Other(v) => v,
        }
    }
}

/// The argument of a step.
pub enum StepValue {
    /// Logged as is.
    Plain(String),
    /// Logged as `****`.
    Secret(SecretString),
    /// Ask the user for the login password (only when the server asks for it).
    AskPassword,
    /// Ask the user for the account (`ACCT`).
    AskAccount,
    /// A whole command line sent verbatim (the verb is ignored), logged as `log_text`.
    Line(SecretString),
}

impl fmt::Debug for StepValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(s) => f.debug_tuple("Plain").field(s).finish(),
            Self::Secret(_) => f.write_str("Secret(****)"),
            Self::AskPassword => f.write_str("AskPassword"),
            Self::AskAccount => f.write_str("AskAccount"),
            Self::Line(_) => f.write_str("Line(****)"),
        }
    }
}

/// Which login a step belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginTarget {
    /// The FTP proxy (T15).
    Proxy,
    /// The server.
    Server,
}

/// Prompt metadata for `AskPassword`/`AskAccount` steps (filled by T14 from
/// `ConnectInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPromptInfo {
    /// `PasswordPrompt.target`, `"user@host:port"`.
    pub target: String,
    /// T04 `Password { protocol: Ftp, host, port, user }`; the account prompt uses the
    /// matching `SecretCacheKey::Account`.
    pub cache_key: SecretCacheKey,
    /// T04 `can_save`: saved site and `vault.store_passwords`.
    pub can_save: bool,
}

impl LoginStep {
    /// A step whose log text is generated (`VERB value`, secrets and prompts `****`).
    pub fn new(kind: StepKind, value: StepValue, target: LoginTarget) -> Self {
        let log_text = match &value {
            StepValue::Plain(s) => format!("{} {s}", kind.verb()),
            _ => format!("{} ****", kind.verb()),
        };
        Self {
            kind,
            value,
            log_text,
            target,
        }
    }
}

impl LoginScript {
    /// USER/PASS[/ACCT] for `ServerAddress.user` + `LogonType` (T02).
    ///
    /// - `Anonymous` → `USER anonymous`, `PASS anonymous@example.com`.
    /// - `Normal`/`Account` with a stored password → `USER`, `PASS`, then `ACCT` only if
    ///   the server answers `332` (no stored account → prompt).
    /// - `Normal` without a password, `AskForPassword`, `Interactive`, `Account` without
    ///   a password → the password is asked when `331` arrives.
    ///
    /// # Errors
    ///
    /// `InvalidInput("user name required")` for a missing user with a non-anonymous
    /// logon; `InvalidInput("key-based logon is SFTP only")` for `KeyFile`/`Agent`.
    pub fn for_logon(
        user: Option<&str>,
        logon: &LogonType,
        prompt: LoginPromptInfo,
    ) -> Result<Self> {
        use LoginTarget::Server;
        let dup = |s: &SecretString| SecretString::from(s.expose());
        let pass_value = |p: &Option<SecretString>| match p {
            Some(p) => StepValue::Secret(dup(p)),
            None => StepValue::AskPassword,
        };
        let user_step = || -> Result<LoginStep> {
            let user = user
                .filter(|u| !u.is_empty())
                .ok_or_else(|| Error::InvalidInput("user name required".into()))?;
            Ok(LoginStep::new(
                StepKind::User,
                StepValue::Plain(user.to_owned()),
                Server,
            ))
        };
        let steps = match logon {
            LogonType::Anonymous => vec![
                LoginStep::new(StepKind::User, StepValue::Plain("anonymous".into()), Server),
                LoginStep::new(
                    StepKind::Pass,
                    StepValue::Plain(ANONYMOUS_PASSWORD.into()),
                    Server,
                ),
            ],
            LogonType::KeyFile { .. } | LogonType::Agent => {
                return Err(Error::InvalidInput("key-based logon is SFTP only".into()));
            }
            LogonType::Normal { password } => vec![
                user_step()?,
                LoginStep::new(StepKind::Pass, pass_value(password), Server),
            ],
            LogonType::AskForPassword | LogonType::Interactive => vec![
                user_step()?,
                LoginStep::new(StepKind::Pass, StepValue::AskPassword, Server),
            ],
            LogonType::Account { password, account } => vec![
                user_step()?,
                LoginStep::new(StepKind::Pass, pass_value(password), Server),
                LoginStep::new(
                    StepKind::Acct,
                    match account {
                        Some(a) => StepValue::Secret(dup(a)),
                        None => StepValue::AskAccount,
                    },
                    Server,
                ),
            ],
        };
        Ok(Self {
            steps,
            prompt: Some(prompt),
        })
    }
}

/// Moves the first remaining `kind` step of `target` to the front, or adds a prompt step.
fn ensure_next(steps: &mut VecDeque<LoginStep>, kind: StepKind, target: LoginTarget) {
    if let Some(pos) = steps
        .iter()
        .position(|s| s.kind == kind && s.target == target)
    {
        if pos > 0
            && let Some(step) = steps.remove(pos)
        {
            steps.push_front(step);
        }
        return;
    }
    let value = if kind == StepKind::Acct {
        StepValue::AskAccount
    } else {
        StepValue::AskPassword
    };
    steps.push_front(LoginStep::new(kind, value, target));
}

/// The error for a failed login step, `None` when the reply lets the login continue.
fn step_error(kind: StepKind, target: LoginTarget, reply: &Reply) -> Option<Error> {
    if reply.is_ok() || reply.is_intermediate() {
        return None;
    }
    let code = reply.code();
    let text = reply.text();
    if code == 421 {
        return Some(if is_too_many(&text) {
            Error::ConnectionLimit(text)
        } else {
            Error::Connection(text)
        });
    }
    if code == 530 && is_too_many(&text) {
        return Some(Error::ConnectionLimit(text));
    }
    if let StepKind::Other(_) = kind {
        return Some(Error::Proxy(format!(
            "FTP proxy could not connect to the server: {text}"
        )));
    }
    if target == LoginTarget::Proxy && (code == 530 || code == 430 || reply.is_permanent_err()) {
        return Some(Error::Proxy(format!("FTP proxy login failed: {text}")));
    }
    Some(match code {
        530 | 430 => Error::Auth(text),
        400..=499 => Error::Protocol {
            code: Some(code),
            message: text,
        },
        _ => Error::Auth(text),
    })
}

impl ControlConnection {
    /// Runs a login script (default or T15 proxy script). On success the state is
    /// `Ready`, `Logged in` is logged and `credential_accepted` is sent for every prompt
    /// answered during this login.
    ///
    /// # Errors
    ///
    /// See the module table; `Cancelled` when a prompt is cancelled or the token fires;
    /// `Auth("login incomplete: …")` when the last reply is not 2xx; `Timeout`.
    pub async fn login(&mut self, script: LoginScript, cancel: &CancellationToken) -> Result<()> {
        self.phase = Phase::LoggingIn;
        let mut answered = Vec::new();
        self.run_login(script, cancel, &mut answered).await?;
        self.phase = Phase::Ready;
        for id in answered {
            self.log.events.credential_accepted(self.log.session, id);
        }
        self.log.status("Logged in");
        tracing::info!(session = self.log.session.get(), "ftp session logged in");
        Ok(())
    }

    async fn run_login(
        &mut self,
        script: LoginScript,
        cancel: &CancellationToken,
        answered: &mut Vec<PromptId>,
    ) -> Result<()> {
        let prompt = script.prompt;
        let mut steps: VecDeque<LoginStep> = script.steps.into();
        let mut logged_in: Vec<LoginTarget> = Vec::new();
        let mut last: Option<Reply> = None;
        while let Some(step) = steps.pop_front() {
            if matches!(step.kind, StepKind::Pass | StepKind::Acct)
                && logged_in.contains(&step.target)
            {
                continue;
            }
            let (kind, target) = (step.kind, step.target);
            let cmd = self
                .step_command(step, prompt.as_ref(), cancel, answered)
                .await?;
            let reply = self.send_raw(cmd, cancel).await?;
            if let Some(err) = step_error(kind, target, &reply) {
                return Err(err);
            }
            match (kind, reply.code()) {
                (StepKind::Other(_), _) => {}
                (_, 230 | 232 | 202) => logged_in.push(target),
                (StepKind::User, 331) => ensure_next(&mut steps, StepKind::Pass, target),
                (_, 332) => ensure_next(&mut steps, StepKind::Acct, target),
                _ => {}
            }
            last = Some(reply);
        }
        match last {
            Some(r) if r.is_ok() => Ok(()),
            Some(r) => Err(Error::Auth(format!("login incomplete: {}", r.text()))),
            None => Err(Error::Auth("login incomplete: empty login script".into())),
        }
    }

    async fn step_command(
        &mut self,
        step: LoginStep,
        prompt: Option<&LoginPromptInfo>,
        cancel: &CancellationToken,
        answered: &mut Vec<PromptId>,
    ) -> Result<Command> {
        let verb = step.kind.verb();
        let cmd = match step.value {
            StepValue::Plain(s) => Command::new(verb).arg(s)?,
            StepValue::Secret(s) => Command::new(verb).secret(s)?,
            StepValue::AskPassword => {
                let (id, value) = self.ask(PasswordPurpose::Login, prompt, cancel).await?;
                answered.push(id);
                self.prompted_password = Some(SecretString::from(value.expose()));
                Command::new(verb).secret(value)?
            }
            StepValue::AskAccount => {
                let (id, value) = self.ask(PasswordPurpose::Account, prompt, cancel).await?;
                answered.push(id);
                self.prompted_account = Some(SecretString::from(value.expose()));
                Command::new(verb).secret(value)?
            }
            StepValue::Line(line) => return Command::secret_line(line, step.log_text),
        };
        Ok(cmd.with_log_text(step.log_text))
    }

    /// One password/account prompt (T04 `prompt_tracked`). No reply is awaited while
    /// the user types, so the inactivity timer does not run.
    async fn ask(
        &mut self,
        purpose: PasswordPurpose,
        prompt: Option<&LoginPromptInfo>,
        cancel: &CancellationToken,
    ) -> Result<(PromptId, SecretString)> {
        let info = prompt.ok_or_else(|| {
            Error::Internal("login script asks for a secret without prompt information".into())
        })?;
        let cache_key = match (purpose, &info.cache_key) {
            (
                PasswordPurpose::Account,
                SecretCacheKey::Password {
                    host, port, user, ..
                },
            ) => SecretCacheKey::Account {
                host: host.clone(),
                port: *port,
                user: user.clone(),
            },
            (_, key) => key.clone(),
        };
        let kind = PromptKind::Password(PasswordPrompt {
            purpose,
            target: info.target.clone(),
            retry: false,
            attempt: 1,
            max_attempts: 1,
            cache_key,
            can_save: info.can_save,
        });
        let (id, response) = self
            .log
            .events
            .prompt_tracked(self.log.session, kind, Some(cancel))
            .await?;
        match response {
            PromptResponse::Secret { value, .. } => Ok((id, value)),
            _ => Err(Error::Cancelled),
        }
    }
}
