//! Server configuration (T84; T86 adds the config file lookup and the remaining
//! variables).
//!
//! Sources, lowest to highest precedence: built-in defaults, an optional TOML text
//! (same keys as the variables, lower case), environment variables. An empty
//! environment variable counts as unset. Loading fails (the server refuses to
//! start, exit code 2) when `COURIER_SERVER_SECRET` is missing, shorter than 32
//! bytes or neither hex nor base64, or when `COURIER_PUBLIC_URL` is missing.
//!
//! | Environment | TOML key | Default |
//! |---|---|---|
//! | `DATABASE_URL` | `database_url` | — (required by `serve`, `migrate`) |
//! | `COURIER_BIND` | `bind` | `0.0.0.0:8080` |
//! | `COURIER_PUBLIC_URL` | `public_url` | required, `https://…` without trailing `/` |
//! | `COURIER_SERVER_SECRET` | `server_secret` | required, ≥ 32 bytes, hex or base64 |
//! | `COURIER_TLS_CERT`, `COURIER_TLS_KEY` | `tls_cert`, `tls_key` | off (both or neither) |
//! | `COURIER_TRUSTED_PROXIES` | `trusted_proxies` | none (comma list of IP/CIDR) |
//! | `COURIER_CORS_ORIGINS` | `cors_allowed_origins` | none (deny) |
//! | `COURIER_REQUEST_TIMEOUT_S` | `request_timeout_s` | 30 (1..=300) |
//! | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | `[smtp]` | off; 587; —; —; required with host; true |

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use ipnet::IpNet;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Default listen address.
pub const DEFAULT_BIND: &str = "0.0.0.0:8080";
/// Minimum decoded length of `COURIER_SERVER_SECRET`.
pub const SECRET_MIN_LEN: usize = 32;
/// Default per-request timeout in seconds.
pub const DEFAULT_REQUEST_TIMEOUT_S: u64 = 30;
/// Largest accepted `COURIER_REQUEST_TIMEOUT_S`.
pub const MAX_REQUEST_TIMEOUT_S: u64 = 300;
/// Default SMTP port (submission with STARTTLS).
pub const DEFAULT_SMTP_PORT: u16 = 587;

/// Configuration errors. Each message names the variable to fix.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `COURIER_SERVER_SECRET` is not set.
    #[error(
        "COURIER_SERVER_SECRET is required (at least {SECRET_MIN_LEN} random bytes, hex or base64); \
         generate one with `openssl rand -base64 48` and back it up together with the database"
    )]
    MissingSecret,
    /// `COURIER_SERVER_SECRET` decodes to fewer than 32 bytes.
    #[error(
        "COURIER_SERVER_SECRET is too short: {len} bytes after decoding, at least {SECRET_MIN_LEN} required"
    )]
    SecretTooShort {
        /// Decoded length.
        len: usize,
    },
    /// `COURIER_SERVER_SECRET` is neither hex nor base64.
    #[error("COURIER_SERVER_SECRET must be hex or base64 encoded")]
    SecretEncoding,
    /// A required setting is missing.
    #[error("{0} is required")]
    Missing(&'static str),
    /// A setting has an invalid value.
    #[error("invalid {name}: {reason}")]
    Invalid {
        /// The variable.
        name: &'static str,
        /// What is wrong with it (never the value of a secret).
        reason: String,
    },
    /// The TOML text is malformed or has unknown keys.
    #[error("invalid config file: {0}")]
    Parse(#[from] Box<toml::de::Error>),
}

/// A value that must never show up in logs or `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct Sensitive<T>(pub T);

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// The decoded `COURIER_SERVER_SECRET` (zeroized on drop, redacted in `Debug`).
#[derive(Clone)]
pub struct ServerSecret(Zeroizing<Vec<u8>>);

impl fmt::Debug for ServerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerSecret([REDACTED])")
    }
}

impl ServerSecret {
    /// Parses a hex or base64 (standard or URL-safe, padded or not) secret. A
    /// string made only of an even number of hex digits is read as hex.
    ///
    /// # Errors
    /// [`ConfigError::MissingSecret`], [`ConfigError::SecretEncoding`] or
    /// [`ConfigError::SecretTooShort`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        use base64::engine::general_purpose::{
            STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
        };
        let s = raw.trim();
        if s.is_empty() {
            return Err(ConfigError::MissingSecret);
        }
        let bytes = if s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(s).map_err(|_| ConfigError::SecretEncoding)?
        } else {
            [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|engine| engine.decode(s).ok())
                .ok_or(ConfigError::SecretEncoding)?
        };
        let bytes = Zeroizing::new(bytes);
        if bytes.len() < SECRET_MIN_LEN {
            return Err(ConfigError::SecretTooShort { len: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// The raw secret bytes. Only key derivation should look at them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Built-in TLS (rustls) certificate and key paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert: PathBuf,
    /// PEM private key.
    pub key: PathBuf,
}

/// SMTP settings (recovery codes, T89 invites). Optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    /// Relay host name.
    pub host: String,
    /// Relay port.
    pub port: u16,
    /// Login user, if the relay needs authentication.
    pub user: Option<String>,
    /// Login password.
    pub password: Option<Sensitive<String>>,
    /// `From:` address.
    pub from: String,
    /// `true`: STARTTLS on a plain connection; `false`: implicit TLS.
    pub starttls: bool,
}

/// The validated server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL connection string (contains a password, hence redacted).
    pub database_url: Option<Sensitive<String>>,
    /// Listen address.
    pub bind: SocketAddr,
    /// Public base URL, without a trailing slash (invite links, mail texts).
    pub public_url: String,
    /// The at-rest encryption secret.
    pub server_secret: ServerSecret,
    /// Built-in TLS, if configured.
    pub tls: Option<TlsConfig>,
    /// SMTP, if configured.
    pub smtp: Option<SmtpConfig>,
    /// Reverse proxies whose `X-Forwarded-For` is trusted.
    pub trusted_proxies: Vec<IpNet>,
    /// Origins allowed by CORS (empty: deny all cross-origin requests).
    pub cors_allowed_origins: Vec<String>,
    /// Per-request timeout.
    pub request_timeout: Duration,
}

/// The TOML shape (every key optional; unknown keys are rejected).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    database_url: Option<String>,
    bind: Option<String>,
    public_url: Option<String>,
    server_secret: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    trusted_proxies: Option<Vec<String>>,
    cors_allowed_origins: Option<Vec<String>>,
    request_timeout_s: Option<u64>,
    smtp: Option<FileSmtp>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSmtp {
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    from: Option<String>,
    starttls: Option<bool>,
}

impl Config {
    /// Loads the configuration from the process environment.
    ///
    /// # Errors
    /// Any [`ConfigError`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_sources(None, |name| std::env::var(name).ok())
    }

    /// Builds the configuration from an optional TOML text and an environment
    /// lookup. Pure; used directly by tests.
    ///
    /// # Errors
    /// Any [`ConfigError`].
    pub fn from_sources(
        toml_text: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let file: FileConfig = match toml_text {
            Some(text) => toml::from_str(text).map_err(Box::new)?,
            None => FileConfig::default(),
        };
        let env = |name: &str| env(name).filter(|v| !v.trim().is_empty());

        let secret_raw = env("COURIER_SERVER_SECRET")
            .or(file.server_secret)
            .ok_or(ConfigError::MissingSecret)?;
        let server_secret = ServerSecret::parse(&secret_raw)?;

        let public_url = env("COURIER_PUBLIC_URL")
            .or(file.public_url)
            .ok_or(ConfigError::Missing("COURIER_PUBLIC_URL"))?;
        let public_url = parse_public_url(&public_url)?;

        let bind = parse_addr(
            "COURIER_BIND",
            &env("COURIER_BIND")
                .or(file.bind)
                .unwrap_or_else(|| DEFAULT_BIND.to_owned()),
        )?;

        let tls_cert = env("COURIER_TLS_CERT").map(PathBuf::from).or(file.tls_cert);
        let tls_key = env("COURIER_TLS_KEY").map(PathBuf::from).or(file.tls_key);
        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsConfig { cert, key }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid {
                    name: "COURIER_TLS_CERT/COURIER_TLS_KEY",
                    reason: "set both or neither".into(),
                });
            }
        };

        let fsmtp = file.smtp.unwrap_or_default();
        let smtp = match env("SMTP_HOST").or(fsmtp.host) {
            None => None,
            Some(host) => {
                let port = match env("SMTP_PORT") {
                    Some(p) => parse_num("SMTP_PORT", &p)?,
                    None => fsmtp.port.unwrap_or(DEFAULT_SMTP_PORT),
                };
                let starttls = match env("SMTP_STARTTLS") {
                    Some(v) => parse_bool("SMTP_STARTTLS", &v)?,
                    None => fsmtp.starttls.unwrap_or(true),
                };
                Some(SmtpConfig {
                    host: host.trim().to_owned(),
                    port,
                    user: env("SMTP_USER").or(fsmtp.user),
                    password: env("SMTP_PASSWORD").or(fsmtp.password).map(Sensitive),
                    from: env("SMTP_FROM").or(fsmtp.from).ok_or(ConfigError::Missing(
                        "SMTP_FROM (needed when SMTP_HOST is set)",
                    ))?,
                    starttls,
                })
            }
        };

        let trusted_proxies = match env("COURIER_TRUSTED_PROXIES") {
            Some(v) => split_list(&v),
            None => file.trusted_proxies.unwrap_or_default(),
        }
        .iter()
        .map(|s| parse_net(s))
        .collect::<Result<Vec<_>, _>>()?;

        let cors_allowed_origins = match env("COURIER_CORS_ORIGINS") {
            Some(v) => split_list(&v),
            None => file.cors_allowed_origins.unwrap_or_default(),
        };

        let timeout_s = match env("COURIER_REQUEST_TIMEOUT_S") {
            Some(v) => parse_num("COURIER_REQUEST_TIMEOUT_S", &v)?,
            None => file.request_timeout_s.unwrap_or(DEFAULT_REQUEST_TIMEOUT_S),
        };
        if !(1..=MAX_REQUEST_TIMEOUT_S).contains(&timeout_s) {
            return Err(ConfigError::Invalid {
                name: "COURIER_REQUEST_TIMEOUT_S",
                reason: format!("must be 1..={MAX_REQUEST_TIMEOUT_S}"),
            });
        }

        Ok(Self {
            database_url: env("DATABASE_URL").or(file.database_url).map(Sensitive),
            bind,
            public_url,
            server_secret,
            tls,
            smtp,
            trusted_proxies,
            cors_allowed_origins,
            request_timeout: Duration::from_secs(timeout_s),
        })
    }

    /// The database URL, or an error naming `DATABASE_URL`.
    ///
    /// # Errors
    /// [`ConfigError::Missing`] when unset.
    pub fn require_database_url(&self) -> Result<&str, ConfigError> {
        self.database_url
            .as_ref()
            .map(|s| s.0.as_str())
            .ok_or(ConfigError::Missing("DATABASE_URL"))
    }
}

/// `https://host[:port][/path]` without a trailing slash. Plain `http://` is
/// accepted only for loopback hosts (local development).
fn parse_public_url(raw: &str) -> Result<String, ConfigError> {
    let url = raw.trim().trim_end_matches('/').to_owned();
    let invalid = |reason: &str| ConfigError::Invalid {
        name: "COURIER_PUBLIC_URL",
        reason: reason.to_owned(),
    };
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit_once(':').map_or(host, |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                host
            }
        });
        if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return Err(invalid("must be an https:// URL"));
        }
        rest
    } else {
        return Err(invalid("must be an https:// URL"));
    };
    if rest.is_empty() || rest.contains(['?', '#']) || rest.chars().any(char::is_whitespace) {
        return Err(invalid("must be a plain URL with a host"));
    }
    Ok(url)
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_addr(name: &'static str, v: &str) -> Result<SocketAddr, ConfigError> {
    v.trim().parse().map_err(|e| ConfigError::Invalid {
        name,
        reason: format!("`{v}`: {e}"),
    })
}

fn parse_num<T: std::str::FromStr>(name: &'static str, v: &str) -> Result<T, ConfigError>
where
    T::Err: fmt::Display,
{
    v.trim().parse().map_err(|e| ConfigError::Invalid {
        name,
        reason: format!("`{v}`: {e}"),
    })
}

fn parse_bool(name: &'static str, v: &str) -> Result<bool, ConfigError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid {
            name,
            reason: format!("`{v}` is not a boolean"),
        }),
    }
}

fn parse_net(s: &str) -> Result<IpNet, ConfigError> {
    let s = s.trim();
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| ConfigError::Invalid {
            name: "COURIER_TRUSTED_PROXIES",
            reason: format!("`{s}` is not an IP address or CIDR"),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_hex_and_base64_min_len() {
        // 31 bytes rejected, 32 accepted (hex).
        assert!(matches!(
            ServerSecret::parse(&"ab".repeat(31)),
            Err(ConfigError::SecretTooShort { len: 31 })
        ));
        assert_eq!(
            ServerSecret::parse(&"ab".repeat(32))
                .unwrap()
                .expose()
                .len(),
            32
        );
        // The same boundary in base64 (standard and URL-safe, padded or not).
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        assert!(matches!(
            ServerSecret::parse(&STANDARD.encode([7u8; 31])),
            Err(ConfigError::SecretTooShort { len: 31 })
        ));
        assert_eq!(
            ServerSecret::parse(&STANDARD.encode([7u8; 32]))
                .unwrap()
                .expose(),
            &[7u8; 32]
        );
        assert_eq!(
            ServerSecret::parse(&URL_SAFE_NO_PAD.encode([0xfb; 33]))
                .unwrap()
                .expose()
                .len(),
            33
        );
        assert!(matches!(
            ServerSecret::parse("not base64 at all!"),
            Err(ConfigError::SecretEncoding)
        ));
        assert!(matches!(
            ServerSecret::parse("   "),
            Err(ConfigError::MissingSecret)
        ));
        let s = ServerSecret::parse(&"cd".repeat(32)).unwrap();
        assert_eq!(format!("{s:?}"), "ServerSecret([REDACTED])");
    }

    #[test]
    fn public_url_rules() {
        assert_eq!(
            parse_public_url("https://sync.example.test/").unwrap(),
            "https://sync.example.test"
        );
        assert!(parse_public_url("http://localhost:8080").is_ok());
        assert!(parse_public_url("http://127.0.0.1").is_ok());
        assert!(parse_public_url("http://sync.example.test").is_err());
        assert!(parse_public_url("sync.example.test").is_err());
        assert!(parse_public_url("https://").is_err());
        assert!(parse_public_url("https://x.test/?a=b").is_err());
    }

    #[test]
    fn trusted_proxy_parsing() {
        assert_eq!(parse_net("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(parse_net("127.0.0.1").unwrap().to_string(), "127.0.0.1/32");
        assert!(parse_net("nope").is_err());
    }
}
