//! [`NetStream`]: a connected TCP stream, possibly through a proxy, that first replays
//! the bytes a proxy sent after its handshake (sverb `PrefixedStream`).

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

/// A stream that yields `prefix` before reading from `inner` (writes go straight to
/// `inner`).
pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// `prefix` first, then `inner`.
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// The early bytes not read yet.
    pub(crate) fn pending(&self) -> usize {
        self.prefix.len() - self.pos
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// A connected byte stream (possibly through a proxy). Bytes the proxy sent after its
/// handshake response are replayed first.
pub struct NetStream {
    inner: PrefixedStream<TcpStream>,
    local: SocketAddr,
    peer: SocketAddr,
    target_ip: Option<IpAddr>,
    proxied: bool,
}

impl fmt::Debug for NetStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetStream")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .field("proxied", &self.proxied)
            .field("pending_early_bytes", &self.inner.pending())
            .finish()
    }
}

impl NetStream {
    /// Wraps a connected socket. `target_ip` is `Some` only for direct connections.
    pub(crate) fn new(
        tcp: TcpStream,
        early: Vec<u8>,
        target_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let peer = tcp.peer_addr()?;
        Ok(Self {
            inner: PrefixedStream::new(early, tcp),
            local,
            peer,
            proxied: target_ip.is_none(),
            target_ip,
        })
    }

    /// Our end of the TCP connection (T11 active mode binds on this IP).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The TCP peer: the server, or the proxy when proxied.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The server's IP when connected directly; `None` through a proxy (DNS at the
    /// proxy).
    pub fn target_ip(&self) -> Option<IpAddr> {
        self.target_ip
    }

    /// Connected through an HTTP or SOCKS proxy.
    pub fn is_proxied(&self) -> bool {
        self.proxied
    }

    /// Change the `SO_RCVBUF`/`SO_SNDBUF` sizes (T41b). Errors are logged at debug
    /// level and ignored.
    pub fn set_socket_buffer(&self, bytes: usize) {
        set_buffers(self.inner.get_ref(), bytes);
    }
}

/// Sets both buffer sizes; failures are only traced (the OS may clamp or refuse).
pub(crate) fn set_buffers(tcp: &TcpStream, bytes: usize) {
    let sock = SockRef::from(tcp);
    if let Err(err) = sock.set_recv_buffer_size(bytes) {
        tracing::debug!(%err, bytes, "set SO_RCVBUF failed");
    }
    if let Err(err) = sock.set_send_buffer_size(bytes) {
        tracing::debug!(%err, bytes, "set SO_SNDBUF failed");
    }
}

impl AsyncRead for NetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
