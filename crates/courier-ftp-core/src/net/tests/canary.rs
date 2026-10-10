//! AC8: a canary proxy password never reaches the session log, `tracing` output or
//! `Debug` output.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use base64::Engine as _;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::sync::CancellationToken;

use super::{echo, fake_proxy, opts, read_n, read_until, session_log, ui};
use crate::{
    net::{HostPort, ProxyConfig, ProxyCredentials, connect_tcp},
    secret::SecretString,
};

const CANARY: &str = "CANARY-PW-net-7f3a";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut v) = self.0.lock() {
            v.extend_from_slice(data);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn creds(pw: Option<&str>) -> Option<ProxyCredentials> {
    Some(ProxyCredentials {
        user: "alice".into(),
        password: pw.map(SecretString::from),
    })
}

#[tokio::test]
async fn proxy_password_canary_not_logged() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Callsite interest is cached process-wide; tests running in parallel can
    // leave it stale, so recompute it now that this subscriber is the default.
    tracing::callsite::rebuild_interest_cache();

    let token = base64::engine::general_purpose::STANDARD.encode(format!("alice:{CANARY}"));
    let expected = format!("Proxy-Authorization: Basic {token}\r\n");
    // HTTP: 407 without the header, 200 with the right one, 403 otherwise.
    let (http_proxy, _) = fake_proxy(move |mut s: TcpStream, _i, _rec| {
        let expected = expected.clone();
        async move {
            let head = String::from_utf8_lossy(&read_until(&mut s, b"\r\n\r\n").await).into_owned();
            let answer: &[u8] = if head.contains(&expected) {
                b"HTTP/1.1 200 OK\r\n\r\n"
            } else if head.contains("Proxy-Authorization") {
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
            } else {
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
            };
            let _ = s.write_all(answer).await;
            if answer.starts_with(b"HTTP/1.1 200") {
                echo(s).await;
            }
        }
    })
    .await;
    // SOCKS5 with user/password; fails the authentication so the error path runs too.
    let (socks_proxy, _) = fake_proxy(|mut s: TcpStream, _i, _rec| async move {
        let _ = read_n(&mut s, 4).await;
        let _ = s.write_all(&[5, 2]).await;
        let _ = read_n(&mut s, 2 + 5 + 1 + CANARY.len()).await;
        let _ = s.write_all(&[1, 1]).await;
    })
    .await;

    let (log, rx) = session_log();
    let ui = ui(rx, Some(CANARY));
    let target = HostPort::new("ftp.example.com", 21);
    let http = |pw: Option<&str>| ProxyConfig::Http {
        proxy: HostPort::new("127.0.0.1", http_proxy.port()),
        auth: creds(pw),
    };
    let socks = ProxyConfig::Socks5 {
        proxy: HostPort::new("127.0.0.1", socks_proxy.port()),
        auth: creds(Some(CANARY)),
    };
    let mut debug_out = String::new();
    for cfg in [http(Some(CANARY)), http(None), http(Some("wrong")), socks] {
        let o = opts(cfg);
        debug_out.push_str(&format!("{o:?}\n"));
        let result = connect_tcp(&target, &o, CancellationToken::new(), &log).await;
        tracing::debug!(?result, "dial result");
        debug_out.push_str(&format!("{result:?}\n"));
        if let Err(err) = &result {
            debug_out.push_str(&format!("{err}\n"));
        }
    }
    drop(log);
    let seen = ui.await.unwrap();
    assert_eq!(seen.prompts, 1, "the 407 without a password prompted once");
    assert_eq!(seen.accepted, 1);

    let traced = buf
        .0
        .lock()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default();
    let logged = seen.all_text();
    assert!(!traced.is_empty() && !logged.is_empty());
    for (what, text) in [
        ("tracing", &traced),
        ("log", &logged),
        ("debug", &debug_out),
    ] {
        assert!(!text.contains(CANARY), "{what}: {text}");
        assert!(!text.contains(&token), "{what}: {text}");
    }
}
