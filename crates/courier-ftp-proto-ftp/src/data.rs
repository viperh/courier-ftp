//! FTP data connections (T11): the per-session policy ([`DataConfig`]) and learned
//! state ([`DataState`]), the raw and TLS-wrapped data sockets ([`RawData`],
//! [`DataIo`], [`DataTlsHook`] for T12), the transfer commands and the open transfer
//! ([`DataStream`]). The session-level operations live in [`crate::transfer::FtpData`].

use std::{
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{Result, net::NetOpts, net::NetStream, settings::ActiveExternalIp};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::Sleep,
};

use crate::ascii::{AsciiDecode, AsciiEncode};

/// Passive (`EPSV`/`PASV`) or active (`EPRT`/`PORT`) data connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataMode {
    /// The client connects to the server (default).
    Passive,
    /// The server connects to the client.
    Active,
}

/// Default data socket buffer (T41b raises it to 4 MiB).
pub const DEFAULT_SOCKET_BUFFER: usize = 256 * 1024;

/// Per-session data-connection policy, built from `Settings` + `ConnectInfo` (T14).
#[derive(Debug)]
pub struct DataConfig {
    /// `ftp.transfer_mode` / the site override.
    pub mode: DataMode,
    /// `ftp.fallback_to_active` (true).
    pub fallback_to_active: bool,
    /// `ftp.passive_ignore_unroutable_ip` (true).
    pub ignore_unroutable_pasv_ip: bool,
    /// `ftp.active_external_ip` (`Auto`).
    pub external_ip: ActiveExternalIp,
    /// `ftp.active_no_external_ip_on_local` (true): local server → advertise the local
    /// IP.
    pub no_external_ip_on_local: bool,
    /// `ftp.active_port_range` (`None`).
    pub port_range: Option<(u16, u16)>,
    /// `!net.proxy.allows_inbound()` (T07): active mode impossible.
    pub through_generic_proxy: bool,
    /// T07 options for data dials (`Purpose::Data`).
    pub net: NetOpts,
    /// Host name dialled for the control connection (used with proxies).
    pub control_host: String,
    /// `connection.timeout_secs`.
    pub timeout: Duration,
    /// `SO_RCVBUF`/`SO_SNDBUF` of data sockets ([`DEFAULT_SOCKET_BUFFER`]).
    pub socket_buffer: usize,
}

/// Per-session learned state ("remember the choice for the session").
#[derive(Debug, Default, Clone)]
pub struct DataState {
    /// `EPSV` was refused (500/501/502/504).
    pub epsv_failed: bool,
    /// `PASV` was refused.
    pub pasv_failed: bool,
    /// `EPRT` was refused after `PORT`.
    pub eprt_failed: bool,
    /// Set after a successful passive → active fallback.
    pub use_active: bool,
    /// `None` = unknown (no `REST STREAM` in FEAT); learned from `350`/5xx.
    pub rest_supported: Option<bool>,
    /// The address fetched from `ftp.active_external_ip = FromUrl`.
    pub external_ip_cache: Option<IpAddr>,
}

/// A connected data socket before TLS: dialled through T07 (passive; may be proxied) or
/// accepted from our listener (active).
#[derive(Debug)]
pub enum RawData {
    /// Passive mode: dialled with `net::connect_tcp`.
    Dialed(NetStream),
    /// Active mode: accepted from the listener.
    Accepted(TcpStream),
}

/// Wraps a freshly connected data socket (TLS, T12). Plain FTP passes `None`.
#[async_trait]
pub trait DataTlsHook: Send + Sync {
    /// Runs the handshake (after the `1xx` reply).
    async fn wrap(&self, raw: RawData) -> Result<DataIo>;
}

/// A data socket, plain or TLS-wrapped.
pub enum DataIo {
    /// Plain FTP.
    Plain(RawData),
    /// FTPS (T12).
    Tls(Box<tokio_rustls::client::TlsStream<RawData>>),
}

impl fmt::Debug for DataIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(raw) => f.debug_tuple("Plain").field(raw).finish(),
            Self::Tls(tls) => f.debug_tuple("Tls").field(tls.get_ref().0).finish(),
        }
    }
}

/// What the transfer command is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferCommand {
    /// `LIST [args]` (T13/T14).
    List {
        /// e.g. `-a`.
        args: Option<String>,
    },
    /// `MLSD` (T13/T14).
    Mlsd,
    /// `[REST offset] RETR path`.
    Retr {
        /// Server path as sent.
        path: String,
        /// Resume offset (`REST`).
        offset: u64,
        /// `TransferOpts.range_len` (T03): stop after this many bytes.
        range_len: Option<u64>,
    },
    /// `[REST offset] STOR path` (offset > 0 → upload resume).
    Stor {
        /// Server path as sent.
        path: String,
        /// Resume offset (`REST`).
        offset: u64,
    },
    /// `APPE path`.
    Appe {
        /// Server path as sent.
        path: String,
    },
}

impl TransferCommand {
    /// The `REST` offset (0 = none).
    pub fn offset(&self) -> u64 {
        match self {
            Self::Retr { offset, .. } | Self::Stor { offset, .. } => *offset,
            _ => 0,
        }
    }

    /// Uploads write to the stream; everything else reads.
    pub fn is_upload(&self) -> bool {
        matches!(self, Self::Stor { .. } | Self::Appe { .. })
    }

    /// File transfers (as opposed to listings).
    pub fn is_file(&self) -> bool {
        !matches!(self, Self::List { .. } | Self::Mlsd)
    }
}

/// Direction of a [`DataStream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Download,
    Upload,
}

/// The socket plus the ASCII adapter of the transfer.
#[derive(Debug)]
pub(crate) enum StreamIo {
    Plain(DataIo),
    Decode(AsciiDecode<DataIo>),
    Encode(AsciiEncode<DataIo>),
}

/// An open transfer. Exactly one may exist per control connection. Downloads and
/// listings read ([`AsyncRead`]) until EOF; uploads write ([`AsyncWrite`]) and are
/// shut down by [`FtpData::finish`](crate::transfer::FtpData::finish) (or by the
/// caller). Dropping it closes the data socket; `finish(None)` then aborts.
///
/// A read or write that makes no progress for the inactivity timeout fails with
/// `io::ErrorKind::TimedOut` ("Data connection timed out"); the timer runs only while a
/// poll is pending (time the caller spends elsewhere is not counted).
pub struct DataStream {
    pub(crate) io: Option<StreamIo>,
    pub(crate) direction: Direction,
    pub(crate) bytes: u64,
    /// Bytes still allowed by `range_len`.
    pub(crate) range_left: Option<u64>,
    /// The range limit was reached (the data may continue).
    pub(crate) range_hit: bool,
    pub(crate) eof: bool,
    pub(crate) shut_down: bool,
    pub(crate) timed_out: bool,
    pub(crate) failed: Option<String>,
    /// `226`/`250` arrived without a `1xx`: an empty transfer, nothing to finish.
    pub(crate) completed: bool,
    timeout: Duration,
    timer: Option<Pin<Box<Sleep>>>,
}

impl fmt::Debug for DataStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataStream")
            .field("direction", &self.direction)
            .field("bytes", &self.bytes)
            .field("range_left", &self.range_left)
            .field("eof", &self.eof)
            .field("shut_down", &self.shut_down)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl DataStream {
    pub(crate) fn new(
        io: StreamIo,
        direction: Direction,
        range_len: Option<u64>,
        timeout: Duration,
    ) -> Self {
        Self {
            io: Some(io),
            direction,
            bytes: 0,
            range_left: range_len,
            range_hit: false,
            eof: false,
            shut_down: false,
            timed_out: false,
            failed: None,
            completed: false,
            timeout,
            timer: None,
        }
    }

    /// An empty transfer (`226` without `1xx`).
    pub(crate) fn empty(direction: Direction) -> Self {
        Self {
            io: None,
            direction,
            bytes: 0,
            range_left: None,
            range_hit: false,
            eof: true,
            shut_down: true,
            timed_out: false,
            failed: None,
            completed: true,
            timeout: Duration::ZERO,
            timer: None,
        }
    }

    /// Bytes read or written by the caller so far (after ASCII conversion).
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes
    }

    /// The download reached EOF (or its `range_len`), or the upload was shut down.
    pub fn is_complete(&self) -> bool {
        match self.direction {
            Direction::Download => self.eof || self.range_hit,
            Direction::Upload => self.shut_down,
        }
    }

    /// After a ranged read hit its limit: does the server's data end here? Waits up to
    /// `wait` for EOF; data or silence mean "no".
    pub(crate) async fn data_ends_within(&mut self, wait: Duration) -> bool {
        let Some(io) = self.io.as_mut() else {
            return true;
        };
        let mut one = [0u8; 1];
        matches!(
            tokio::time::timeout(wait, io.read(&mut one)).await,
            Ok(Ok(0))
        )
    }

    /// Arms the inactivity timer when a poll is pending; `Err` when it fired.
    fn poll_idle(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let timeout = self.timeout;
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.timer = None;
                self.timed_out = true;
                Poll::Ready(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Data connection timed out",
                ))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn note_error(&mut self, e: &io::Error) {
        if self.failed.is_none() && !self.timed_out {
            self.failed = Some(e.to_string());
        }
    }

    fn wrong_direction() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "wrong direction for this data stream",
        )
    }
}

impl AsyncRead for DataStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.direction != Direction::Download {
            return Poll::Ready(Err(DataStream::wrong_direction()));
        }
        if this.eof || this.range_hit || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let Some(io) = this.io.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let max = match this.range_left {
            Some(left) => usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(buf.remaining()),
            None => buf.remaining(),
        };
        let mut sub = ReadBuf::new(buf.initialize_unfilled_to(max));
        match Pin::new(io).poll_read(cx, &mut sub) {
            Poll::Ready(Ok(())) => {
                let n = sub.filled().len();
                buf.advance(n);
                this.timer = None;
                if n == 0 {
                    this.eof = true;
                } else {
                    this.bytes += n as u64;
                    if let Some(left) = this.range_left.as_mut() {
                        *left -= n as u64;
                        if *left == 0 {
                            this.range_hit = true;
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.timer = None;
                this.note_error(&e);
                Poll::Ready(Err(e))
            }
            Poll::Pending => this.poll_idle(cx).map(Err),
        }
    }
}

impl AsyncWrite for DataStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.direction != Direction::Upload {
            return Poll::Ready(Err(DataStream::wrong_direction()));
        }
        let Some(io) = this.io.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        match Pin::new(io).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.timer = None;
                this.bytes += n as u64;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                this.timer = None;
                this.note_error(&e);
                Poll::Ready(Err(e))
            }
            Poll::Pending => this.poll_idle(cx).map(Err),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(io) = this.io.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(io).poll_flush(cx) {
            Poll::Ready(r) => {
                this.timer = None;
                if let Err(e) = &r {
                    this.note_error(e);
                }
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_idle(cx).map(Err),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shut_down {
            return Poll::Ready(Ok(()));
        }
        let Some(io) = this.io.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(io).poll_shutdown(cx) {
            Poll::Ready(r) => {
                this.timer = None;
                match &r {
                    Ok(()) => this.shut_down = this.direction == Direction::Upload,
                    Err(e) => this.note_error(e),
                }
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_idle(cx).map(Err),
        }
    }
}

// ---- delegation -------------------------------------------------------------------------

macro_rules! delegate_io {
    ($ty:ty, $($variant:ident),+) => {
        impl AsyncRead for $ty {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $(Self::$variant(s) => Pin::new(s).poll_read(cx, buf),)+
                }
            }
        }

        impl AsyncWrite for $ty {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                match self.get_mut() {
                    $(Self::$variant(s) => Pin::new(s).poll_write(cx, buf),)+
                }
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $(Self::$variant(s) => Pin::new(s).poll_flush(cx),)+
                }
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $(Self::$variant(s) => Pin::new(s).poll_shutdown(cx),)+
                }
            }
        }
    };
}

delegate_io!(RawData, Dialed, Accepted);
delegate_io!(DataIo, Plain, Tls);
delegate_io!(StreamIo, Plain, Decode, Encode);
