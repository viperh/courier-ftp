//! FTP proxy logins (T15): the fake server plays the proxy and asserts the
//! exact command sequence of each type.

use courier_ftp_core::{
    backend::{ConnectInfo, ProxyChoice},
    model::{Protocol, ServerAddress},
    settings::{FtpProxy, GenericProxy, ProxyServer},
};
use pretty_assertions::assert_eq;

use super::*;

/// Settings with `proxy` as the FTP proxy.
fn proxy_settings(proxy: FtpProxy) -> Settings {
    let mut settings = Settings::default();
    settings.proxy.ftp_proxy = proxy;
    settings
}

fn proxy_server(server: &FakeServer, user: Option<&str>) -> ProxyServer {
    ProxyServer {
        host: server.host.host.clone(),
        port: server.host.port,
        user: user.map(str::to_owned),
        password_ref: Some("vault-proxy".into()),
    }
}

/// Connect through the fake server as an FTP proxy to `target`, logging in
/// as bob/pw (proxy password `proxypw` from the "vault"), and return the
/// command log. Fails if a password shows up in any log line.
async fn connect_through_proxy(
    script: Vec<Step>,
    make: impl FnOnce(&FakeServer) -> FtpProxy,
    target: HostPort,
) -> Vec<String> {
    let mut steps = vec![send("220 proxy\r\n")];
    steps.extend(script);
    steps.extend(after_login(&["500 FEAT not understood"], vec![], "\"/\""));
    let server = FakeServer::start(steps).await;
    let settings = proxy_settings(make(&server));
    let mut opts = FtpOptions::new(target, normal("bob", "pw"), &settings);
    opts.timeout = Duration::from_secs(5);
    assert_eq!(opts.control_target(), &server.host);
    assert_eq!(
        opts.ftp_proxy.as_ref().unwrap().password_ref.as_deref(),
        Some("vault-proxy")
    );
    opts.set_ftp_proxy_password(SecretString::from("proxypw"));
    let (ctx, mut rx) = context();
    let conn = connect(&opts, ctx).await.unwrap();
    let logs = all_logs(&mut rx);
    drop(conn);
    server.finish().await;
    for (_, text) in &logs {
        assert!(!text.contains("proxypw"), "{text}");
        assert!(!text.contains(" pw"), "{text}");
    }
    assert!(
        logs.iter().any(
            |(k, t)| *k == LogKind::Status && t.starts_with("Logging in through the FTP proxy")
        ),
        "{logs:?}"
    );
    logs.into_iter()
        .filter(|(k, _)| *k == LogKind::Command)
        .map(|(_, t)| t)
        .collect()
}

/// The login part of the command log (before `SYST`).
fn login_part(commands: &[String]) -> Vec<&str> {
    commands
        .iter()
        .map(String::as_str)
        .take_while(|c| *c != "SYST")
        .collect()
}

#[tokio::test]
async fn user_at_host_without_proxy_auth() {
    let mut script = Vec::new();
    script.extend(exchange("USER bob@real.example.com", &["331 Password"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    let commands = connect_through_proxy(
        script,
        |s| FtpProxy::UserAtHost(proxy_server(s, None)),
        HostPort::new("real.example.com", 21),
    )
    .await;
    assert_eq!(
        login_part(&commands),
        ["USER bob@real.example.com", "PASS ****"]
    );
}

#[tokio::test]
async fn user_at_host_with_proxy_auth() {
    let mut script = Vec::new();
    script.extend(exchange("USER puser", &["331 Password"]));
    script.extend(exchange("PASS proxypw", &["230 Proxy login ok"]));
    script.extend(exchange(
        "USER bob@real.example.com:2121",
        &["331 Password"],
    ));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    let commands = connect_through_proxy(
        script,
        |s| FtpProxy::UserAtHost(proxy_server(s, Some("puser"))),
        HostPort::new("real.example.com", 2121),
    )
    .await;
    assert_eq!(
        login_part(&commands),
        [
            "USER puser",
            "PASS ****",
            "USER bob@real.example.com:2121",
            "PASS ****"
        ]
    );
}

#[tokio::test]
async fn site() {
    let mut script = Vec::new();
    script.extend(exchange("USER puser", &["331 Password"]));
    script.extend(exchange("PASS proxypw", &["230 Proxy login ok"]));
    script.extend(exchange("SITE real.example.com", &["220 Connected"]));
    script.extend(exchange("USER bob", &["331 Password"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    let commands = connect_through_proxy(
        script,
        |s| FtpProxy::Site(proxy_server(s, Some("puser"))),
        HostPort::new("real.example.com", 21),
    )
    .await;
    assert_eq!(
        login_part(&commands),
        [
            "USER puser",
            "PASS ****",
            "SITE real.example.com",
            "USER bob",
            "PASS ****"
        ]
    );
}

#[tokio::test]
async fn open() {
    let mut script = Vec::new();
    script.extend(exchange("USER puser", &["331 Password"]));
    script.extend(exchange("PASS proxypw", &["230 Proxy login ok"]));
    script.extend(exchange("OPEN [2001:db8::1]:990", &["200 Connected"]));
    script.extend(exchange("USER bob", &["331 Password"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    let commands = connect_through_proxy(
        script,
        |s| FtpProxy::Open(proxy_server(s, Some("puser"))),
        HostPort::new("2001:db8::1", 990),
    )
    .await;
    assert_eq!(
        login_part(&commands),
        [
            "USER puser",
            "PASS ****",
            "OPEN [2001:db8::1]:990",
            "USER bob",
            "PASS ****"
        ]
    );
}

#[tokio::test]
async fn custom_script() {
    let mut script = Vec::new();
    script.extend(exchange("LOGIN puser proxypw", &["230 Proxy login ok"]));
    script.extend(exchange("CONNECT real.example.com", &["220 Connected"]));
    script.extend(exchange("USER bob", &["331 Password"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    let commands = connect_through_proxy(
        script,
        |s| FtpProxy::Custom {
            server: proxy_server(s, Some("puser")),
            // `ACCT %a` is skipped: no account.
            script: "LOGIN %s %w\nCONNECT %h\n\nUSER %u\nPASS %p\nACCT %a".into(),
        },
        HostPort::new("real.example.com", 21),
    )
    .await;
    assert_eq!(
        login_part(&commands),
        [
            "LOGIN puser ****",
            "CONNECT real.example.com",
            "USER bob",
            "PASS ****"
        ]
    );
}

#[tokio::test]
async fn proxy_refusing_the_target_is_an_error() {
    let mut script = vec![send("220 proxy\r\n")];
    script.extend(exchange("SITE real.example.com", &["530 Not allowed"]));
    let server = FakeServer::start(script).await;
    let settings = proxy_settings(FtpProxy::Site(proxy_server(&server, None)));
    let mut opts = FtpOptions::new(
        HostPort::new("real.example.com", 21),
        normal("bob", "pw"),
        &settings,
    );
    opts.timeout = Duration::from_secs(5);
    let (ctx, _rx) = context();
    assert!(matches!(connect(&opts, ctx).await, Err(Error::Auth(_))));
    server.finish().await;
}

#[test]
fn options_bypass_and_generic_proxy() {
    let server = ProxyServer {
        host: "proxy".into(),
        port: 2100,
        user: None,
        password_ref: None,
    };
    let settings = proxy_settings(FtpProxy::Site(server.clone()));
    let mut info = ConnectInfo::new(
        ServerAddress::new(Protocol::Ftp, "real.example.com"),
        LogonType::Anonymous,
    );
    let opts = FtpOptions::from_connect_info(&info, &settings);
    assert_eq!(opts.control_target(), &HostPort::new("proxy", 2100));
    let steps: Vec<String> = opts
        .login_script(None)
        .unwrap()
        .steps()
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
    assert_eq!(
        steps,
        [
            "Command(\"SITE real.example.com\")",
            "User(\"anonymous\")",
            "Pass(****)"
        ]
    );

    // The site's "bypass proxy" turns the FTP proxy off.
    info.proxy = ProxyChoice::Bypass;
    let opts = FtpOptions::from_connect_info(&info, &settings);
    assert!(opts.ftp_proxy.is_none());
    assert_eq!(
        opts.control_target(),
        &HostPort::new("real.example.com", 21)
    );

    // A generic proxy alone is kept; next to an FTP proxy it is dropped (the
    // FTP proxy is reached directly).
    let mut settings = Settings::default();
    settings.proxy.generic = GenericProxy::Socks5(server);
    let opts = FtpOptions::new(HostPort::new("h", 21), LogonType::Anonymous, &settings);
    assert!(opts.net.proxy.is_some() && opts.ftp_proxy.is_none());
    settings.proxy.ftp_proxy = FtpProxy::Open(ProxyServer {
        host: "p".into(),
        port: 21,
        user: None,
        password_ref: None,
    });
    let opts = FtpOptions::new(HostPort::new("h", 21), LogonType::Anonymous, &settings);
    assert!(opts.net.proxy.is_none() && opts.ftp_proxy.is_some());
}
