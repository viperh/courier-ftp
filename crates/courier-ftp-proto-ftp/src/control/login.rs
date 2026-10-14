//! The login sequence as a [`LoginScript`]: the normal `USER`/`PASS`/`ACCT`
//! login is the default script; the FTP proxy types (T15) build their own
//! (`USER %s` · `PASS %w` · `SITE %h` · `USER %u` · `PASS %p` …).

use std::fmt;

use courier_ftp_core::{Error, Result, model::LogonType};
use secrecy::SecretString;

/// The password sent for anonymous logins (FileZilla's choice).
pub const ANONYMOUS_PASSWORD: &str = "anonymous@example.com";

/// One command of a login script.
///
/// How the reply decides what happens next:
///
/// - [`User`](LoginStep::User): `230` logs in at once (the following `Pass` and
///   `Acct` steps are skipped up to the next `User` or `Command`); `331`
///   continues with the password, `332` with the account.
/// - [`Pass`](LoginStep::Pass): `230`/`202` logs in (following `Acct` steps are
///   skipped); `332` continues with `Acct`.
/// - [`Acct`](LoginStep::Acct): `230`/`202` logs in.
/// - [`Command`](LoginStep::Command) / [`SecretCommand`](LoginStep::SecretCommand):
///   any `2xx` or `3xx` continues (`SITE host`, `OPEN host` of FTP proxies).
///
/// Every other reply ends the login: `530`/`532` as [`Error::Auth`], `421` as
/// [`Error::Connection`], anything else as [`Error::Protocol`].
#[derive(Clone)]
pub enum LoginStep {
    /// `USER <name>`.
    User(String),
    /// `PASS <password>`, logged as `PASS ****`.
    Pass(SecretString),
    /// `ACCT <account>`, logged as `ACCT ****`.
    Acct(SecretString),
    /// Another command, logged as it is.
    Command(String),
    /// A command containing secrets (a custom proxy script line with `%p` or
    /// `%w`, T15). Every value in `secrets` is replaced by `****` in the log.
    SecretCommand {
        /// The command with the secrets substituted.
        line: SecretString,
        /// The substituted secrets to mask.
        secrets: Vec<SecretString>,
    },
}

impl fmt::Debug for LoginStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginStep::User(user) => f.debug_tuple("User").field(user).finish(),
            LoginStep::Pass(_) => f.write_str("Pass(****)"),
            LoginStep::Acct(_) => f.write_str("Acct(****)"),
            LoginStep::Command(cmd) => f.debug_tuple("Command").field(cmd).finish(),
            LoginStep::SecretCommand { .. } => f.write_str("SecretCommand(****)"),
        }
    }
}

/// The commands that log in, run by
/// [`ControlConnection::login`](super::ControlConnection::login).
#[derive(Debug, Clone)]
pub struct LoginScript {
    steps: Vec<LoginStep>,
}

impl LoginScript {
    /// A script of these steps (FTP proxies, T15).
    pub fn new(steps: Vec<LoginStep>) -> Self {
        Self { steps }
    }

    /// The steps in order.
    pub fn steps(&self) -> &[LoginStep] {
        &self.steps
    }

    /// The normal login for `logon`:
    ///
    /// - Anonymous: `USER anonymous`, `PASS anonymous@example.com`;
    /// - Normal: `USER`, `PASS`;
    /// - Account: `USER`, `PASS`, `ACCT` (sent only if the server asks with
    ///   `332`);
    /// - Ask for password / Interactive: `USER`, `PASS` with `password` (the
    ///   answer to the password prompt, asked before connecting).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for SSH-only logon types (key file, agent) and
    /// when an asked-for password is missing.
    pub fn for_logon(logon: &LogonType, password: Option<SecretString>) -> Result<Self> {
        let steps = match logon {
            LogonType::Anonymous => vec![
                LoginStep::User("anonymous".into()),
                LoginStep::Pass(SecretString::from(ANONYMOUS_PASSWORD)),
            ],
            LogonType::Normal { user, password } => vec![
                LoginStep::User(user.clone()),
                LoginStep::Pass(password.clone()),
            ],
            LogonType::Account {
                user,
                password,
                account,
            } => vec![
                LoginStep::User(user.clone()),
                LoginStep::Pass(password.clone()),
                LoginStep::Acct(SecretString::from(account.as_str())),
            ],
            LogonType::AskForPassword { user } | LogonType::Interactive { user } => {
                let password = password
                    .ok_or_else(|| Error::InvalidInput("a password is needed to log in".into()))?;
                vec![LoginStep::User(user.clone()), LoginStep::Pass(password)]
            }
            LogonType::KeyFile { .. } | LogonType::Agent { .. } => {
                return Err(Error::InvalidInput(
                    "key file and agent logins are for SFTP only, not FTP".into(),
                ));
            }
        };
        Ok(Self { steps })
    }
}
