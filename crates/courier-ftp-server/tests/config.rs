//! Configuration from environment variables (and TOML text, completed in T86).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::time::Duration;

use courier_ftp_server::config::{Config, ConfigError};

fn load(toml: Option<&str>, env: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect();
    Config::from_sources(toml, |k| env.get(k).cloned())
}

const URL: (&str, &str) = ("COURIER_PUBLIC_URL", "https://sync.example.test/");
const SECRET: (&str, &str) = (
    "COURIER_SERVER_SECRET",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);

#[test]
fn missing_or_short_secret_is_a_startup_error() {
    let err = load(None, &[URL]).unwrap_err();
    assert!(matches!(err, ConfigError::MissingSecret), "{err:?}");
    assert!(err.to_string().contains("COURIER_SERVER_SECRET is required"));
    // Empty counts as unset.
    let err = load(None, &[URL, ("COURIER_SERVER_SECRET", "  ")]).unwrap_err();
    assert!(matches!(err, ConfigError::MissingSecret), "{err:?}");
    let short = "ab".repeat(31);
    let err = load(None, &[URL, ("COURIER_SERVER_SECRET", &short)]).unwrap_err();
    assert!(
        matches!(err, ConfigError::SecretTooShort { len: 31 }),
        "{err:?}"
    );
    let err = load(None, &[URL, ("COURIER_SERVER_SECRET", "!!not-an-encoding!!")]).unwrap_err();
    assert!(matches!(err, ConfigError::SecretEncoding), "{err:?}");
    // 32 bytes as base64 are fine.
    let b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    assert_eq!(
        load(None, &[URL, ("COURIER_SERVER_SECRET", b64)])
            .unwrap()
            .server_secret
            .expose()
            .len(),
        32
    );
}

#[test]
fn defaults_and_redaction() {
    let cfg = load(
        None,
        &[
            URL,
            SECRET,
            ("DATABASE_URL", "postgres://courier:db-password@db/courier"),
        ],
    )
    .unwrap();
    assert_eq!(cfg.public_url, "https://sync.example.test");
    assert_eq!(cfg.bind.to_string(), "0.0.0.0:8080");
    assert_eq!(cfg.request_timeout, Duration::from_secs(30));
    assert!(cfg.tls.is_none() && cfg.smtp.is_none());
    assert!(cfg.trusted_proxies.is_empty() && cfg.cors_allowed_origins.is_empty());
    assert_eq!(
        cfg.require_database_url().unwrap(),
        "postgres://courier:db-password@db/courier"
    );
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("0123456789abcdef"), "{dbg}");
    assert!(!dbg.contains("db-password"), "{dbg}");
    let no_db = load(None, &[URL, SECRET]).unwrap();
    assert!(matches!(
        no_db.require_database_url(),
        Err(ConfigError::Missing("DATABASE_URL"))
    ));
}

#[test]
fn public_url_is_required_and_https() {
    assert!(matches!(
        load(None, &[SECRET]).unwrap_err(),
        ConfigError::Missing("COURIER_PUBLIC_URL")
    ));
    for bad in ["http://sync.example.test", "ftp://x", "https://", "https://a b"] {
        let err = load(None, &[SECRET, ("COURIER_PUBLIC_URL", bad)]).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{bad}: {err:?}");
    }
    let local = load(None, &[SECRET, ("COURIER_PUBLIC_URL", "http://localhost:8080")]).unwrap();
    assert_eq!(local.public_url, "http://localhost:8080");
}

#[test]
fn tls_both_or_neither() {
    let err = load(None, &[URL, SECRET, ("COURIER_TLS_CERT", "/c.pem")]).unwrap_err();
    assert!(err.to_string().contains("set both or neither"), "{err}");
    let cfg = load(
        None,
        &[
            URL,
            SECRET,
            ("COURIER_TLS_CERT", "/c.pem"),
            ("COURIER_TLS_KEY", "/k.pem"),
        ],
    )
    .unwrap();
    assert!(cfg.tls.is_some());
}

#[test]
fn smtp_settings() {
    let err = load(None, &[URL, SECRET, ("SMTP_HOST", "mail.example.test")]).unwrap_err();
    assert!(err.to_string().contains("SMTP_FROM"), "{err}");
    let cfg = load(
        None,
        &[
            URL,
            SECRET,
            ("SMTP_HOST", "mail.example.test"),
            ("SMTP_FROM", "courier@example.test"),
            ("SMTP_PASSWORD", "smtp-secret"),
        ],
    )
    .unwrap();
    let smtp = cfg.smtp.as_ref().unwrap();
    assert_eq!(smtp.port, 587);
    assert!(smtp.starttls);
    assert!(!format!("{cfg:?}").contains("smtp-secret"));
    let cfg = load(
        None,
        &[
            URL,
            SECRET,
            ("SMTP_HOST", "mail.example.test"),
            ("SMTP_FROM", "courier@example.test"),
            ("SMTP_PORT", "465"),
            ("SMTP_STARTTLS", "false"),
        ],
    )
    .unwrap();
    let smtp = cfg.smtp.unwrap();
    assert_eq!((smtp.port, smtp.starttls), (465, false));
    assert!(load(None, &[URL, SECRET, ("SMTP_HOST", "h"), ("SMTP_FROM", "f"), ("SMTP_PORT", "x")]).is_err());
}

#[test]
fn proxies_bind_and_timeout() {
    let cfg = load(
        None,
        &[
            URL,
            SECRET,
            ("COURIER_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1 ,::1"),
            ("COURIER_BIND", "127.0.0.1:9000"),
            ("COURIER_REQUEST_TIMEOUT_S", "300"),
        ],
    )
    .unwrap();
    assert_eq!(cfg.trusted_proxies.len(), 3);
    assert_eq!(cfg.bind.to_string(), "127.0.0.1:9000");
    assert_eq!(cfg.request_timeout, Duration::from_secs(300));
    for (k, v) in [
        ("COURIER_TRUSTED_PROXIES", "not-an-ip"),
        ("COURIER_BIND", "nowhere"),
        ("COURIER_REQUEST_TIMEOUT_S", "0"),
        ("COURIER_REQUEST_TIMEOUT_S", "301"),
    ] {
        assert!(load(None, &[URL, SECRET, (k, v)]).is_err(), "{k}={v}");
    }
}

#[test]
fn environment_wins_over_toml() {
    let toml = r#"
        public_url = "https://from-file.example.test"
        bind = "127.0.0.1:7000"
    "#;
    let cfg = load(Some(toml), &[SECRET]).unwrap();
    assert_eq!(cfg.public_url, "https://from-file.example.test");
    assert_eq!(cfg.bind.to_string(), "127.0.0.1:7000");
    let cfg = load(Some(toml), &[SECRET, URL, ("COURIER_BIND", "")]).unwrap();
    assert_eq!(cfg.public_url, "https://sync.example.test");
    assert_eq!(cfg.bind.to_string(), "127.0.0.1:7000", "empty = unset");
    assert!(matches!(
        load(Some("unknown_key = 1"), &[SECRET, URL]).unwrap_err(),
        ConfigError::Parse(_)
    ));
}
