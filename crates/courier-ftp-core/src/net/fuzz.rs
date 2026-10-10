//! Fuzz bodies for the proxy handshakes (T07, T91 §7): a hostile proxy's
//! replies to HTTP `CONNECT`, SOCKS4/4a and SOCKS5 (with and without RFC 1929
//! authentication), delivered in reads of 1..=32 bytes. Used by the cargo-fuzz
//! target `proxy_reply` and by the property tests in `net::tests`.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::{HostPort, ProxyAuth, http, socks};

/// A proxy that answers with a fixed script, `chunk` bytes per read, and
/// swallows everything written to it.
struct ScriptedProxy {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl AsyncRead for ScriptedProxy {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        let n = rest.len().min(self.chunk).min(buf.remaining());
        buf.put_slice(rest.get(..n).unwrap_or_default());
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedProxy {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Where the HTTP reply head ends (after the first `\r\n\r\n` or `\n\n`).
fn http_head_end(data: &[u8]) -> Option<usize> {
    let crlf = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4);
    let lf = data.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The first byte picks the handshake (low two bits: HTTP, SOCKS4, SOCKS5,
/// SOCKS5 with a login) and the read size (bits 2..=6, 1..=32 bytes); the rest
/// is the proxy's answer. Must never panic, and after a successful HTTP
/// `CONNECT` the bytes after the reply head must come next, unchanged.
#[doc(hidden)]
pub fn fuzz_proxy_reply(data: &[u8]) {
    let Some((&first, reply)) = data.split_first() else {
        return;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let mut proxy = ScriptedProxy {
        data: reply.to_vec(),
        pos: 0,
        chunk: usize::from((first >> 2) & 0x1f) + 1,
    };
    let target = HostPort::new("host.example", 22);
    let login = ProxyAuth {
        user: "user".into(),
        password: Some("pw".to_owned().into()),
    };
    runtime.block_on(async {
        match first & 0b11 {
            0 => {
                let auth = (first & 0x80 != 0).then_some(&login);
                if http::connect(&mut proxy, &target, auth).await.is_ok() {
                    let mut rest = Vec::new();
                    let _ = proxy.read_to_end(&mut rest).await;
                    let end = http_head_end(reply).unwrap_or(reply.len());
                    assert_eq!(
                        rest,
                        reply.get(end..).unwrap_or_default(),
                        "bytes after the CONNECT reply were changed"
                    );
                }
            }
            1 => {
                let _ = socks::connect_v4(&mut proxy, &target, Some(&login)).await;
            }
            2 => {
                let _ = socks::connect_v5(&mut proxy, &target, None).await;
            }
            _ => {
                let _ = socks::connect_v5(&mut proxy, &target, Some(&login)).await;
            }
        }
    });
}
