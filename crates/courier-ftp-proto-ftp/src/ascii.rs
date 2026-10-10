//! ASCII transfer type (T11 §5): streaming conversion between network ASCII (CRLF line
//! ends, RFC 959 `TYPE A N`) and local text. On Unix and macOS downloads turn `CR LF`
//! into `LF` and uploads turn a bare `LF` into `CR LF`; on Windows both are the
//! identity (local text already uses CRLF). The state survives chunk boundaries, so the
//! output never depends on how the bytes were split.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Whether this platform converts line ends at all.
const CONVERT: bool = !cfg!(windows);
/// Read/convert granularity.
const CHUNK: usize = 16 * 1024;

/// Download direction state: `CR LF` → `LF`, a lone `CR` passes through; a `CR` that
/// ends a chunk is held until the next byte (or the end of the data).
#[derive(Debug, Default, Clone)]
pub(crate) struct DecodeState {
    pending_cr: bool,
}

impl DecodeState {
    pub(crate) fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        out.reserve(input.len() + 1);
        for &b in input {
            if self.pending_cr {
                self.pending_cr = false;
                if b == b'\n' {
                    out.push(b'\n');
                    continue;
                }
                out.push(b'\r');
            }
            if b == b'\r' {
                self.pending_cr = true;
            } else {
                out.push(b);
            }
        }
    }

    /// End of data: emits a held `CR`.
    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) {
        if std::mem::take(&mut self.pending_cr) {
            out.push(b'\r');
        }
    }
}

/// Upload direction state: an `LF` not preceded by `CR` becomes `CR LF`.
#[derive(Debug, Default, Clone)]
pub(crate) struct EncodeState {
    last_was_cr: bool,
}

impl EncodeState {
    pub(crate) fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        out.reserve(input.len() + input.len() / 16 + 1);
        for &b in input {
            if b == b'\n' && !self.last_was_cr {
                out.push(b'\r');
            }
            out.push(b);
            self.last_was_cr = b == b'\r';
        }
    }
}

/// Streaming network-ASCII → local text (download). See the module docs.
#[derive(Debug)]
pub struct AsciiDecode<R> {
    inner: R,
    convert: bool,
    state: DecodeState,
    inbuf: Box<[u8]>,
    out: Vec<u8>,
    out_pos: usize,
    eof: bool,
}

impl<R> AsciiDecode<R> {
    /// Wraps `inner` with this platform's conversion.
    pub fn new(inner: R) -> Self {
        Self::with_conversion(inner, CONVERT)
    }

    /// Wraps `inner`; `convert = false` is the identity (Windows).
    pub(crate) fn with_conversion(inner: R, convert: bool) -> Self {
        Self {
            inner,
            convert,
            state: DecodeState::default(),
            inbuf: if convert {
                vec![0; CHUNK].into_boxed_slice()
            } else {
                Box::default()
            },
            out: Vec::new(),
            out_pos: 0,
            eof: false,
        }
    }

    /// The wrapped stream.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// The wrapped stream.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AsciiDecode<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.convert {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.out_pos < this.out.len() {
                let n = (this.out.len() - this.out_pos).min(buf.remaining());
                buf.put_slice(&this.out[this.out_pos..this.out_pos + n]);
                this.out_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut rb = ReadBuf::new(&mut this.inbuf);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            this.out.clear();
            this.out_pos = 0;
            let filled = rb.filled();
            if filled.is_empty() {
                this.eof = true;
                this.state.finish(&mut this.out);
            } else {
                this.state.decode(filled, &mut this.out);
            }
        }
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for AsciiDecode<R> {
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
}

/// Local text → network ASCII (upload). See the module docs. Like a `BufWriter`, a
/// write is accepted once converted; `flush`/`shutdown` drain the converted bytes.
#[derive(Debug)]
pub struct AsciiEncode<W> {
    inner: W,
    convert: bool,
    state: EncodeState,
    out: Vec<u8>,
    out_pos: usize,
}

impl<W> AsciiEncode<W> {
    /// Wraps `inner` with this platform's conversion.
    pub fn new(inner: W) -> Self {
        Self::with_conversion(inner, CONVERT)
    }

    /// Wraps `inner`; `convert = false` is the identity (Windows).
    pub(crate) fn with_conversion(inner: W, convert: bool) -> Self {
        Self {
            inner,
            convert,
            state: EncodeState::default(),
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// The wrapped stream.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// The wrapped stream.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsciiEncode<W> {
    /// Writes out every converted byte not written yet.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsciiEncode<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.convert {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        ready!(this.poll_drain(cx))?;
        let take = buf.len().min(CHUNK);
        this.state.encode(&buf[..take], &mut this.out);
        // Opportunistic: errors and back-pressure surface on the next call.
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<W: AsyncRead + Unpin> AsyncRead for AsciiEncode<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests;
