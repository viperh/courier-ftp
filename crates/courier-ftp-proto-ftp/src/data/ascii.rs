//! ASCII transfer type (`TYPE A`) line ending conversion, streaming.
//!
//! - [`AsciiReader`] (downloads): the network form CRLF becomes the local
//!   newline: LF on Unix and macOS; on Windows CRLF is the local newline and
//!   the bytes pass through unchanged. A lone CR is kept.
//! - [`AsciiWriter`] (uploads): every LF not already preceded by CR becomes
//!   CRLF, so files with Unix and with Windows line endings both arrive with
//!   CRLF.
//!
//! Both keep the state needed across chunk boundaries (a CR as the last
//! byte of one read, an LF as the first of the next).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Whether downloads convert CRLF to LF on this platform.
pub const CONVERT_DOWNLOADS: bool = !cfg!(windows);

/// Converts CRLF to LF while reading (see the [module docs](self)).
#[derive(Debug)]
pub struct AsciiReader<R> {
    inner: R,
    /// Converted bytes not yet handed out.
    out: Vec<u8>,
    out_pos: usize,
    /// A CR was the last byte of the previous chunk and hasn't been emitted.
    pending_cr: bool,
    /// The inner reader reached EOF.
    eof: bool,
    convert: bool,
}

impl<R> AsciiReader<R> {
    /// Wrap `inner`, converting on platforms where the local newline is LF.
    pub fn new(inner: R) -> Self {
        Self::with_conversion(inner, CONVERT_DOWNLOADS)
    }

    /// Wrap `inner`; `convert = false` passes the bytes through (Windows).
    pub fn with_conversion(inner: R, convert: bool) -> Self {
        Self {
            inner,
            out: Vec::new(),
            out_pos: 0,
            pending_cr: false,
            eof: false,
            convert,
        }
    }

    /// The wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// The wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Convert one chunk of input into `out`.
    fn convert_chunk(&mut self, input: &[u8]) {
        self.out.clear();
        self.out_pos = 0;
        let mut iter = input.iter().peekable();
        if self.pending_cr {
            self.pending_cr = false;
            if input.first() != Some(&b'\n') {
                self.out.push(b'\r');
            }
        }
        while let Some(&b) = iter.next() {
            if b == b'\r' {
                match iter.peek() {
                    Some(b'\n') => {}
                    Some(_) => self.out.push(b'\r'),
                    None => self.pending_cr = true,
                }
            } else {
                self.out.push(b);
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AsciiReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.convert {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        loop {
            if this.out_pos < this.out.len() {
                let rest = this.out.get(this.out_pos..).unwrap_or_default();
                let n = rest.len().min(buf.remaining());
                buf.put_slice(rest.get(..n).unwrap_or_default());
                this.out_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                if this.pending_cr {
                    this.pending_cr = false;
                    this.out.clear();
                    this.out.push(b'\r');
                    this.out_pos = 0;
                    continue;
                }
                return Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                this.eof = true;
                continue;
            }
            this.convert_chunk(scratch.get(..filled).unwrap_or_default());
        }
    }
}

/// Converts LF to CRLF while writing (see the [module docs](self)).
#[derive(Debug)]
pub struct AsciiWriter<W> {
    inner: W,
    /// Converted bytes not yet written to `inner`.
    pending: Vec<u8>,
    written: usize,
    /// The last input byte was CR (so a following LF is already CRLF).
    last_cr: bool,
}

impl<W> AsciiWriter<W> {
    /// Wrap `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            written: 0,
            last_cr: false,
        }
    }

    /// The wrapped writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsciiWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let rest = self.pending.get(self.written..).unwrap_or_default();
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, rest))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsciiWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = data.len().min(64 * 1024);
        let input = data.get(..take).unwrap_or_default();
        this.pending.reserve(input.len() + input.len() / 16 + 1);
        for &b in input {
            if b == b'\n' && !this.last_cr {
                this.pending.push(b'\r');
            }
            this.pending.push(b);
            this.last_cr = b == b'\r';
        }
        // The input is accepted; a write error from draining shows up on
        // the next write, flush or shutdown.
        match this.poll_drain(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A reader that returns `data` in the given chunk sizes.
    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        sizes: Vec<usize>,
        next: usize,
    }

    impl AsyncRead for Chunked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let size = self.sizes.get(self.next).copied().unwrap_or(7).max(1);
            self.next += 1;
            let end = (self.pos + size)
                .min(self.data.len())
                .min(self.pos + buf.remaining());
            let chunk = self.data[self.pos..end].to_vec();
            buf.put_slice(&chunk);
            self.pos = end;
            Poll::Ready(Ok(()))
        }
    }

    /// A writer that accepts at most `size` bytes per call.
    struct Trickle {
        out: Vec<u8>,
        size: usize,
    }

    impl AsyncWrite for Trickle {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = data.len().min(self.size);
            self.out.extend_from_slice(&data[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn crlf_to_lf(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
                i += 1;
                continue;
            }
            out.push(data[i]);
            i += 1;
        }
        out
    }

    fn lf_to_crlf(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut last_cr = false;
        for &b in data {
            if b == b'\n' && !last_cr {
                out.push(b'\r');
            }
            out.push(b);
            last_cr = b == b'\r';
        }
        out
    }

    async fn read_all(data: &[u8], sizes: Vec<usize>, buf_size: usize) -> Vec<u8> {
        let mut r = AsciiReader::with_conversion(
            Chunked {
                data: data.to_vec(),
                pos: 0,
                sizes,
                next: 0,
            },
            true,
        );
        let mut out = Vec::new();
        let mut buf = vec![0u8; buf_size];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    async fn write_all(chunks: &[&[u8]], size: usize) -> Vec<u8> {
        let mut w = AsciiWriter::new(Trickle {
            out: Vec::new(),
            size,
        });
        for c in chunks {
            w.write_all(c).await.unwrap();
        }
        w.shutdown().await.unwrap();
        w.into_inner().out
    }

    #[tokio::test]
    async fn cr_at_the_end_of_a_chunk() {
        // "a\r" | "\nb" must become "a\nb".
        assert_eq!(read_all(b"a\r\nb", vec![2, 2], 64).await, b"a\nb");
        // A lone CR at a chunk end is kept.
        assert_eq!(read_all(b"a\rb", vec![2, 1], 64).await, b"a\rb");
        // A CR as the very last byte is kept.
        assert_eq!(read_all(b"a\r", vec![2], 64).await, b"a\r");
        assert_eq!(read_all(b"\r\r\n", vec![1, 1, 1], 64).await, b"\r\n");
        assert_eq!(read_all(b"x\r\n", vec![1, 1, 1], 1).await, b"x\n");
    }

    #[tokio::test]
    async fn lf_split_from_its_cr_on_upload() {
        assert_eq!(write_all(&[b"a\r", b"\nb\n"], 3).await, b"a\r\nb\r\n");
        assert_eq!(write_all(&[b"a\n", b"\n"], 1).await, b"a\r\n\r\n");
    }

    #[tokio::test]
    async fn passthrough_on_windows_style() {
        let mut r = AsciiReader::with_conversion(&b"a\r\nb"[..], false);
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"a\r\nb");
    }

    proptest! {
        #[test]
        fn reader_matches_the_reference(
            data in proptest::collection::vec(prop_oneof![Just(b'\r'), Just(b'\n'), Just(b'a')], 0..200),
            sizes in proptest::collection::vec(1usize..9, 0..60),
            buf_size in 1usize..16,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let got = rt.block_on(read_all(&data, sizes, buf_size));
            prop_assert_eq!(got, crlf_to_lf(&data));
        }

        #[test]
        fn writer_matches_the_reference(
            data in proptest::collection::vec(prop_oneof![Just(b'\r'), Just(b'\n'), Just(b'a')], 0..200),
            split in 0usize..200,
            size in 1usize..9,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let split = split.min(data.len());
            let (a, b) = data.split_at(split);
            let got = rt.block_on(write_all(&[a, b], size));
            prop_assert_eq!(got, lf_to_crlf(&data));
        }
    }
}
