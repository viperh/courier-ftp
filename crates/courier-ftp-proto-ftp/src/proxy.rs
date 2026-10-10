//! FTP proxies (T15): FileZilla's "FTP Proxy" types, where the client opens
//! the control connection to a proxy FTP server and tells it with FTP
//! commands which real server to reach.
//!
//! The proxy only changes two things of the start sequence in
//! [`connect`](crate::control::connect): the TCP connection goes to the proxy
//! ([`FtpProxyConfig::server`]) instead of the server, and the login is the
//! proxy's [`LoginScript`] ([`FtpProxyConfig::login_script`]) instead of the
//! normal one.
//!
//! # Login sequences
//!
//! Placeholders: `%h` host (with `:port` when the port is not 21), `%u` user,
//! `%p` password, `%a` account, `%s` proxy user, `%w` proxy password, `%%` a
//! literal `%`. Any other `%x` is sent as it is.
//!
//! | Type | Sequence |
//! |---|---|
//! | [`UserAtHost`](FtpProxyType::UserAtHost) | `USER %s` · `PASS %w` · `USER %u@%h` · `PASS %p` · `ACCT %a` |
//! | [`Site`](FtpProxyType::Site) | `USER %s` · `PASS %w` · `SITE %h` · `USER %u` · `PASS %p` · `ACCT %a` |
//! | [`Open`](FtpProxyType::Open) | `USER %s` · `PASS %w` · `OPEN %h` · `USER %u` · `PASS %p` · `ACCT %a` |
//! | [`Custom`](FtpProxyType::Custom) | the user's lines |
//!
//! A line whose placeholder has an empty (or no) value is skipped, in the
//! built-in sequences too: without a proxy user, `USER %s` and `PASS %w` are
//! not sent; without an account, `ACCT %a` is not (and `ACCT` is only ever
//! sent when the server asks for it with `332`). Blank script lines are
//! ignored.
//!
//! Lines starting with `USER`, `PASS` or `ACCT` become the matching
//! [`LoginStep`] (so `230` straight after `USER` skips the password, as in a
//! normal login); every other line is a [`LoginStep::Command`], which any
//! `2xx`/`3xx` reply accepts.
//!
//! # Secrets in the log
//!
//! `PASS` and `ACCT` lines are logged as `PASS ****` / `ACCT ****`. Any other
//! line that contains `%p`, `%w` or `%a` is a [`LoginStep::SecretCommand`]
//! with every substituted secret replaced by `****` in the log.
//!
//! # Explicit TLS
//!
//! With explicit FTPS, `AUTH TLS` is sent right after the greeting, so to the
//! proxy, before the login script. Whether the connection to the real server
//! is encrypted too depends on the proxy: courier-ftp only sees the TLS
//! session with the proxy.
//!
//! # Generic proxies
//!
//! An FTP proxy and a generic (HTTP/SOCKS) proxy can't both apply to one
//! connection: settings validation turns the FTP proxy off when both are set,
//! and [`FtpOptions`](crate::control::FtpOptions) connects to the FTP proxy
//! directly. The site's "bypass proxy" option turns off both.

use std::fmt;

use courier_ftp_core::{
    Error, Result,
    model::LogonType,
    net::HostPort,
    settings::{FtpProxy, ProxyServer},
};
use secrecy::{ExposeSecret, SecretString};

use crate::control::{ANONYMOUS_PASSWORD, LoginScript, LoginStep};

/// The default FTP port: `%h` has no `:port` suffix for it.
pub const DEFAULT_FTP_PORT: u16 = 21;

/// The `USER@HOST` login sequence.
pub const USER_AT_HOST_SCRIPT: &str = "USER %s\nPASS %w\nUSER %u@%h\nPASS %p\nACCT %a";
/// The `SITE` login sequence.
pub const SITE_SCRIPT: &str = "USER %s\nPASS %w\nSITE %h\nUSER %u\nPASS %p\nACCT %a";
/// The `OPEN` login sequence.
pub const OPEN_SCRIPT: &str = "USER %s\nPASS %w\nOPEN %h\nUSER %u\nPASS %p\nACCT %a";

/// How the proxy is told which server to reach.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FtpProxyType {
    /// `USER user@host`.
    UserAtHost,
    /// `SITE host`.
    Site,
    /// `OPEN host`.
    Open,
    /// A user-supplied script, one command per line.
    Custom(String),
}

impl FtpProxyType {
    /// The login script template of this type.
    pub fn script(&self) -> &str {
        match self {
            Self::UserAtHost => USER_AT_HOST_SCRIPT,
            Self::Site => SITE_SCRIPT,
            Self::Open => OPEN_SCRIPT,
            Self::Custom(script) => script,
        }
    }
}

impl fmt::Display for FtpProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UserAtHost => "USER@HOST",
            Self::Site => "SITE",
            Self::Open => "OPEN",
            Self::Custom(_) => "custom",
        })
    }
}

/// An FTP proxy with its resolved credentials. `Debug` never shows the
/// password.
#[derive(Clone)]
pub struct FtpProxyConfig {
    /// How the target server is named to the proxy.
    pub kind: FtpProxyType,
    /// The proxy's address (where the control connection goes).
    pub server: HostPort,
    /// The proxy user (`%s`), if any.
    pub user: Option<String>,
    /// The proxy password (`%w`), once read from the vault. Only used with a
    /// proxy user.
    pub password: Option<SecretString>,
    /// Id of the vault item holding the proxy password (from the settings).
    pub password_ref: Option<String>,
}

impl fmt::Debug for FtpProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtpProxyConfig")
            .field("kind", &self.kind)
            .field("server", &self.server)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "****"))
            .field("password_ref", &self.password_ref)
            .finish()
    }
}

impl FtpProxyConfig {
    /// The FTP proxy from the settings, without its password (the settings
    /// only hold [`password_ref`](Self::password_ref); set
    /// [`password`](Self::password) once the vault is unlocked). `None` for
    /// [`FtpProxy::None`].
    pub fn from_settings(proxy: &FtpProxy) -> Option<Self> {
        let (kind, server) = match proxy {
            FtpProxy::None => return None,
            FtpProxy::UserAtHost(s) => (FtpProxyType::UserAtHost, s),
            FtpProxy::Site(s) => (FtpProxyType::Site, s),
            FtpProxy::Open(s) => (FtpProxyType::Open, s),
            FtpProxy::Custom { server, script } => (FtpProxyType::Custom(script.clone()), server),
        };
        let ProxyServer {
            host,
            port,
            user,
            password_ref,
        } = server;
        Some(Self {
            kind,
            server: HostPort::new(host.clone(), *port),
            user: user.clone().filter(|u| !u.is_empty()),
            password: None,
            password_ref: password_ref.clone().filter(|r| !r.is_empty()),
        })
    }

    /// The login script that reaches `target` through this proxy and logs in
    /// with `logon`. `password` is the answer to the password prompt for
    /// logon types that ask for one.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for SSH-only logon types (key file, agent),
    /// when an asked-for password is missing, or when the script sends
    /// nothing.
    pub fn login_script(
        &self,
        target: &HostPort,
        logon: &LogonType,
        password: Option<SecretString>,
    ) -> Result<LoginScript> {
        // Proxy authentication needs a proxy user: without one, `%w` is
        // empty too (no `PASS %w` without `USER %s`).
        let proxy_password = self
            .user
            .as_ref()
            .and(self.password.as_ref())
            .map(|p| p.expose_secret());
        let values = ScriptValues::new(target, logon, password)?
            .with_proxy(self.user.as_deref(), proxy_password);
        expand_script(self.kind.script(), &values)
    }
}

/// The values the placeholders stand for.
#[derive(Default)]
pub struct ScriptValues {
    /// `%h`.
    pub host: String,
    /// `%u`.
    pub user: String,
    /// `%p`.
    pub password: Option<SecretString>,
    /// `%a`.
    pub account: Option<SecretString>,
    /// `%s`.
    pub proxy_user: Option<String>,
    /// `%w`.
    pub proxy_password: Option<SecretString>,
}

impl fmt::Debug for ScriptValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mask = |s: &Option<SecretString>| s.as_ref().map(|_| "****");
        f.debug_struct("ScriptValues")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("password", &mask(&self.password))
            .field("account", &mask(&self.account))
            .field("proxy_user", &self.proxy_user)
            .field("proxy_password", &mask(&self.proxy_password))
            .finish()
    }
}

impl ScriptValues {
    /// `%h`, `%u`, `%p` and `%a` for `target` and `logon` (anonymous logins
    /// use `anonymous` / [`ANONYMOUS_PASSWORD`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for SSH-only logon types and when an
    /// asked-for password is missing.
    pub fn new(
        target: &HostPort,
        logon: &LogonType,
        password: Option<SecretString>,
    ) -> Result<Self> {
        let (user, password, account) = match logon {
            LogonType::Anonymous => (
                "anonymous".to_owned(),
                SecretString::from(ANONYMOUS_PASSWORD),
                None,
            ),
            LogonType::Normal { user, password } => (user.clone(), password.clone(), None),
            LogonType::Account {
                user,
                password,
                account,
            } => (
                user.clone(),
                password.clone(),
                Some(SecretString::from(account.as_str())),
            ),
            LogonType::AskForPassword { user } | LogonType::Interactive { user } => {
                let password = password
                    .ok_or_else(|| Error::InvalidInput("a password is needed to log in".into()))?;
                (user.clone(), password, None)
            }
            LogonType::KeyFile { .. } | LogonType::Agent { .. } => {
                return Err(Error::InvalidInput(
                    "key file and agent logins are for SFTP only, not FTP".into(),
                ));
            }
        };
        Ok(Self {
            host: host_placeholder(target),
            user,
            password: Some(password),
            account,
            proxy_user: None,
            proxy_password: None,
        })
    }

    /// Set `%s` and `%w`.
    #[must_use]
    pub fn with_proxy(mut self, user: Option<&str>, password: Option<&str>) -> Self {
        self.proxy_user = user.map(str::to_owned);
        self.proxy_password = password.map(SecretString::from);
        self
    }

    /// The value of placeholder `c`, and whether it is a secret. `None` for
    /// characters that are not placeholders.
    fn get(&self, c: char) -> Option<(Option<&str>, bool)> {
        fn secret(s: &Option<SecretString>) -> Option<&str> {
            s.as_ref().map(|s| s.expose_secret())
        }
        Some(match c {
            'h' => (Some(self.host.as_str()), false),
            'u' => (Some(self.user.as_str()), false),
            'p' => (secret(&self.password), true),
            'a' => (secret(&self.account), true),
            's' => (self.proxy_user.as_deref(), false),
            'w' => (secret(&self.proxy_password), true),
            _ => return None,
        })
    }
}

/// `%h` for `target`: the host, plus `:port` when the port is not 21
/// (`[v6]:port` for IPv6 literals).
pub fn host_placeholder(target: &HostPort) -> String {
    if target.port == DEFAULT_FTP_PORT {
        target.host.clone()
    } else {
        target.to_string()
    }
}

/// One expanded script line.
struct Expanded {
    /// The line with every placeholder substituted.
    line: SecretString,
    /// The substituted secret values.
    secrets: Vec<SecretString>,
}

/// Substitute the placeholders of one line. `None` when a placeholder has an
/// empty value (the line is skipped).
fn expand_line(template: &str, values: &ScriptValues) -> Option<Expanded> {
    let mut line = String::with_capacity(template.len());
    let mut secrets = Vec::new();
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            line.push(c);
            continue;
        }
        match chars.next() {
            None => line.push('%'),
            Some('%') => line.push('%'),
            Some(p) => match values.get(p) {
                None => {
                    line.push('%');
                    line.push(p);
                }
                Some((value, secret)) => {
                    let value = value.filter(|v| !v.is_empty())?;
                    line.push_str(value);
                    if secret {
                        secrets.push(SecretString::from(value));
                    }
                }
            },
        }
    }
    Some(Expanded {
        line: SecretString::from(line),
        secrets,
    })
}

/// Expand a login script template with `values`: one [`LoginStep`] per
/// non-blank line, skipping lines with an empty placeholder (see the
/// [module docs](self)). Never panics, whatever the template.
///
/// # Errors
///
/// [`Error::InvalidInput`] when no line is left to send.
pub fn expand_script(script: &str, values: &ScriptValues) -> Result<LoginScript> {
    let mut steps = Vec::new();
    for template in script.lines() {
        let template = template.trim();
        if template.is_empty() {
            continue;
        }
        let Some(Expanded { line, secrets }) = expand_line(template, values) else {
            continue;
        };
        let text = line.expose_secret();
        let (verb, rest) = match text.split_once(' ') {
            Some((verb, rest)) => (verb, rest),
            None => (text, ""),
        };
        let step = if verb.eq_ignore_ascii_case("PASS") {
            LoginStep::Pass(SecretString::from(rest))
        } else if verb.eq_ignore_ascii_case("ACCT") {
            LoginStep::Acct(SecretString::from(rest))
        } else if !secrets.is_empty() {
            LoginStep::SecretCommand { line, secrets }
        } else if verb.eq_ignore_ascii_case("USER") {
            LoginStep::User(rest.to_owned())
        } else {
            LoginStep::Command(text.to_owned())
        };
        steps.push(step);
    }
    if steps.is_empty() {
        return Err(Error::InvalidInput(
            "the FTP proxy login script sends no command".into(),
        ));
    }
    Ok(LoginScript::new(steps))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use courier_ftp_core::events::{mask_command, mask_secrets};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    use super::*;

    /// Proxy user and password of a table row.
    type Auth = Option<(&'static str, &'static str)>;
    /// Expected lines of a table row.
    type Lines = &'static [&'static str];

    /// What a step sends and what the log shows.
    fn render(step: &LoginStep) -> (String, String) {
        match step {
            LoginStep::User(u) => (format!("USER {u}"), format!("USER {u}")),
            LoginStep::Pass(p) => (format!("PASS {}", p.expose_secret()), "PASS ****".into()),
            LoginStep::Acct(a) => (format!("ACCT {}", a.expose_secret()), "ACCT ****".into()),
            LoginStep::Command(c) => (c.clone(), mask_command(c).into_owned()),
            LoginStep::SecretCommand { line, secrets } => {
                let secrets: Vec<&str> = secrets.iter().map(|s| s.expose_secret()).collect();
                let masked = mask_secrets(line.expose_secret(), &secrets);
                (
                    line.expose_secret().to_owned(),
                    mask_command(&masked).into_owned(),
                )
            }
        }
    }

    fn sent_and_logged(script: &LoginScript) -> (Vec<String>, Vec<String>) {
        script.steps().iter().map(render).unzip()
    }

    fn values(port: u16, account: Option<&str>, proxy: Option<(&str, &str)>) -> ScriptValues {
        let logon = match account {
            Some(account) => LogonType::Account {
                user: "bob".into(),
                password: SecretString::from("pw1"),
                account: account.into(),
            },
            None => LogonType::Normal {
                user: "bob".into(),
                password: SecretString::from("pw1"),
            },
        };
        let v = ScriptValues::new(&HostPort::new("ftp.example.com", port), &logon, None).unwrap();
        match proxy {
            Some((u, p)) => v.with_proxy(Some(u), Some(p)),
            None => v,
        }
    }

    #[test]
    fn built_in_scripts() {
        let auth = Some(("puser", "ppw"));
        let cases: &[(FtpProxyType, u16, Auth, Lines, Lines)] = &[
            (
                FtpProxyType::UserAtHost,
                21,
                None,
                &["USER bob@ftp.example.com", "PASS pw1"],
                &["USER bob@ftp.example.com", "PASS ****"],
            ),
            (
                FtpProxyType::UserAtHost,
                2121,
                auth,
                &[
                    "USER puser",
                    "PASS ppw",
                    "USER bob@ftp.example.com:2121",
                    "PASS pw1",
                ],
                &[
                    "USER puser",
                    "PASS ****",
                    "USER bob@ftp.example.com:2121",
                    "PASS ****",
                ],
            ),
            (
                FtpProxyType::Site,
                21,
                auth,
                &[
                    "USER puser",
                    "PASS ppw",
                    "SITE ftp.example.com",
                    "USER bob",
                    "PASS pw1",
                ],
                &[
                    "USER puser",
                    "PASS ****",
                    "SITE ftp.example.com",
                    "USER bob",
                    "PASS ****",
                ],
            ),
            (
                FtpProxyType::Open,
                990,
                auth,
                &[
                    "USER puser",
                    "PASS ppw",
                    "OPEN ftp.example.com:990",
                    "USER bob",
                    "PASS pw1",
                ],
                &[
                    "USER puser",
                    "PASS ****",
                    "OPEN ftp.example.com:990",
                    "USER bob",
                    "PASS ****",
                ],
            ),
            (
                FtpProxyType::Site,
                21,
                None,
                &["SITE ftp.example.com", "USER bob", "PASS pw1"],
                &["SITE ftp.example.com", "USER bob", "PASS ****"],
            ),
        ];
        for (kind, port, proxy, sent, logged) in cases {
            let script = expand_script(kind.script(), &values(*port, None, *proxy)).unwrap();
            let (s, l) = sent_and_logged(&script);
            assert_eq!(s, *sent, "{kind}");
            assert_eq!(l, *logged, "{kind}");
        }
    }

    #[test]
    fn account_adds_acct_step() {
        let script = expand_script(SITE_SCRIPT, &values(21, Some("acc"), None)).unwrap();
        let (sent, logged) = sent_and_logged(&script);
        assert_eq!(
            sent,
            ["SITE ftp.example.com", "USER bob", "PASS pw1", "ACCT acc"]
        );
        assert_eq!(
            logged,
            ["SITE ftp.example.com", "USER bob", "PASS ****", "ACCT ****"]
        );
    }

    #[test]
    fn custom_script_substitution_skipping_and_masking() {
        let auth = Some(("puser", "ppw"));
        let cases: &[(&str, Auth, Lines, Lines)] = &[
            // Every placeholder, %% and an unknown one.
            (
                "USER %u@%h %s\nQUOTE %% %x 100%",
                auth,
                &["USER bob@ftp.example.com:2121 puser", "QUOTE % %x 100%"],
                &["USER bob@ftp.example.com:2121 puser", "QUOTE % %x 100%"],
            ),
            // Secrets in other commands are masked; case-insensitive verbs.
            (
                "LOGIN %s %w\nsite login %u %p\npass %p",
                auth,
                &["LOGIN puser ppw", "site login bob pw1", "PASS pw1"],
                &["LOGIN puser ****", "site login bob ****", "PASS ****"],
            ),
            // Lines with an empty placeholder are skipped; blank lines ignored.
            (
                "\n  USER %s  \nPASS %w\n\nUSER %u@%h\r\nPASS %p\nACCT %a\n",
                None,
                &["USER bob@ftp.example.com:2121", "PASS pw1"],
                &["USER bob@ftp.example.com:2121", "PASS ****"],
            ),
            // USER with a secret is masked too.
            (
                "USER %s:%w@%h",
                auth,
                &["USER puser:ppw@ftp.example.com:2121"],
                &["USER puser:****@ftp.example.com:2121"],
            ),
        ];
        for (template, proxy, sent, logged) in cases {
            let script = expand_script(template, &values(2121, None, *proxy)).unwrap();
            let (s, l) = sent_and_logged(&script);
            assert_eq!(s, *sent, "{template:?}");
            assert_eq!(l, *logged, "{template:?}");
        }
    }

    #[test]
    fn user_step_kinds() {
        let script = expand_script(
            "USER %u\nUSER %w\nPASS %p\nACCT %a\nSITE %h",
            &values(21, Some("a"), Some(("s", "w"))),
        )
        .unwrap();
        let kinds: Vec<&str> = script
            .steps()
            .iter()
            .map(|s| match s {
                LoginStep::User(_) => "user",
                LoginStep::Pass(_) => "pass",
                LoginStep::Acct(_) => "acct",
                LoginStep::Command(_) => "command",
                LoginStep::SecretCommand { .. } => "secret",
            })
            .collect();
        assert_eq!(kinds, ["user", "secret", "pass", "acct", "command"]);
    }

    #[test]
    fn empty_script_is_an_error() {
        for template in ["", "\n \n", "USER %s\nPASS %w"] {
            assert!(matches!(
                expand_script(template, &values(21, None, None)),
                Err(Error::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn host_placeholder_ports() {
        assert_eq!(host_placeholder(&HostPort::new("h", 21)), "h");
        assert_eq!(host_placeholder(&HostPort::new("h", 2121)), "h:2121");
        assert_eq!(host_placeholder(&HostPort::new("::1", 21)), "::1");
        assert_eq!(
            host_placeholder(&HostPort::new("[::1]", 2121)),
            "[::1]:2121"
        );
    }

    #[test]
    fn logon_values() {
        let target = HostPort::new("h", 21);
        let v = ScriptValues::new(&target, &LogonType::Anonymous, None).unwrap();
        assert_eq!(v.user, "anonymous");
        assert_eq!(
            v.password.as_ref().unwrap().expose_secret(),
            ANONYMOUS_PASSWORD
        );
        let ask = LogonType::AskForPassword { user: "u".into() };
        assert!(ScriptValues::new(&target, &ask, None).is_err());
        let v = ScriptValues::new(&target, &ask, Some(SecretString::from("x"))).unwrap();
        assert_eq!(v.password.as_ref().unwrap().expose_secret(), "x");
        let agent = LogonType::Agent { user: "u".into() };
        assert!(matches!(
            ScriptValues::new(&target, &agent, None),
            Err(Error::InvalidInput(_))
        ));
        assert!(format!("{v:?}").contains("password: Some(\"****\")"));
    }

    #[test]
    fn config_from_settings() {
        assert!(FtpProxyConfig::from_settings(&FtpProxy::None).is_none());
        let server = ProxyServer {
            host: "[::1]".into(),
            port: 2100,
            user: Some(String::new()),
            password_ref: Some("vault-1".into()),
        };
        let cfg = FtpProxyConfig::from_settings(&FtpProxy::Custom {
            server: server.clone(),
            script: "USER %u@%h".into(),
        })
        .unwrap();
        assert_eq!(cfg.kind, FtpProxyType::Custom("USER %u@%h".into()));
        assert_eq!(cfg.server, HostPort::new("::1", 2100));
        assert_eq!(cfg.user, None);
        assert_eq!(cfg.password_ref.as_deref(), Some("vault-1"));
        for (proxy, kind) in [
            (
                FtpProxy::UserAtHost(server.clone()),
                FtpProxyType::UserAtHost,
            ),
            (FtpProxy::Site(server.clone()), FtpProxyType::Site),
            (FtpProxy::Open(server.clone()), FtpProxyType::Open),
        ] {
            assert_eq!(FtpProxyConfig::from_settings(&proxy).unwrap().kind, kind);
        }
    }

    #[test]
    fn config_debug_hides_the_password() {
        let mut cfg = FtpProxyConfig::from_settings(&FtpProxy::Site(ProxyServer {
            host: "p".into(),
            port: 21,
            user: Some("puser".into()),
            password_ref: None,
        }))
        .unwrap();
        cfg.password = Some(SecretString::from("canary-proxy-pw"));
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("canary-proxy-pw"), "{debug}");
        let script = cfg
            .login_script(
                &HostPort::new("t", 21),
                &LogonType::Normal {
                    user: "bob".into(),
                    password: SecretString::from("canary-user-pw"),
                },
                None,
            )
            .unwrap();
        let debug = format!("{script:?}");
        assert!(!debug.contains("canary"), "{debug}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// The custom script parser never panics, and every secret is masked
        /// in the logged form of the lines that carry it.
        #[test]
        fn custom_script_never_panics(
            script in prop::collection::vec(
                prop::sample::select(vec![
                    "%", "%%", "%h", "%u", "%p", "%a", "%s", "%w", "%x", "%\u{e9}", "\u{e9}",
                    "USER ", "PASS ", "ACCT ", "SITE ", " ", "\n", "\r\n", "\r", "\0", "@", ":",
                ]),
                0..40,
            ).prop_map(|v| v.concat()),
            arbitrary in ".{0,64}",
            proxy in any::<bool>(),
        ) {
            for template in [&script, &arbitrary] {
                let v = values(2121, Some("acct-canary"), proxy.then_some(("s", "proxy-canary")));
                if let Ok(s) = expand_script(template, &v) {
                    let (_, logged) = sent_and_logged(&s);
                    for line in logged {
                        prop_assert!(!line.contains("canary"), "{line:?}");
                        prop_assert!(!line.contains("pw1"), "{line:?}");
                    }
                }
            }
        }
    }
}
