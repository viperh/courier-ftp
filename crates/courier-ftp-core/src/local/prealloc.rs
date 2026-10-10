//! Preallocated downloads (T42, `transfers.preallocate`): the file is
//! extended to its final size before writing, and trimmed back to what was
//! actually written when the stream ends early, so its length stays a valid
//! resume offset.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::AsyncWrite;

/// A file reserved to `reserved` bytes, written from `pos`.
pub(super) struct Preallocated {
    file: tokio::fs::File,
    /// A handle for the synchronous trim in `Drop`.
    trim: std::fs::File,
    pos: u64,
    reserved: u64,
    trimmed: bool,
}

impl Preallocated {
    /// Extends `file` (positioned at `pos`) to `size` bytes. Gives the file
    /// back when that isn't possible (the filesystem doesn't support it);
    /// the caller then writes without preallocating.
    pub(super) async fn reserve(
        file: tokio::fs::File,
        pos: u64,
        size: u64,
    ) -> Result<Self, tokio::fs::File> {
        if size <= pos {
            return Err(file);
        }
        let trim = match file.try_clone().await {
            Ok(f) => f.into_std().await,
            Err(_) => return Err(file),
        };
        if let Err(e) = file.set_len(size).await {
            tracing::debug!("preallocation failed, writing without: {e}");
            return Err(file);
        }
        Ok(Self {
            file,
            trim,
            pos,
            reserved: size,
            trimmed: false,
        })
    }

    /// Cuts the unwritten reserved tail.
    fn trim(&mut self) {
        if !self.trimmed
            && self.pos < self.reserved
            && let Err(e) = self.trim.set_len(self.pos)
        {
            tracing::debug!("could not trim a preallocated file: {e}");
        }
        self.trimmed = true;
    }
}

impl AsyncWrite for Preallocated {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let r = Pin::new(&mut this.file).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            this.pos += n as u64;
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.file).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.trim();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl Drop for Preallocated {
    fn drop(&mut self) {
        // Writes still in flight all lie below `pos`, so trimming first is
        // safe.
        self.trim();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;

    use crate::{
        backend::{Backend, TransferOpts, TransferType, WriteMode},
        local::{LocalBackend, local_to_remote},
    };

    fn opts(hint: Option<u64>) -> TransferOpts {
        TransferOpts {
            transfer_type: TransferType::Binary,
            preallocate_hint: hint,
        }
    }

    #[tokio::test]
    async fn reserves_then_trims_to_what_was_written() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        let path = local_to_remote(&file).unwrap();
        let mut b = LocalBackend::new();
        b.connect(CancellationToken::new()).await.unwrap();
        let len = || std::fs::metadata(&file).unwrap().len();

        // Complete: the full size.
        let mut w = b
            .open_write(&path, WriteMode::Truncate, &opts(Some(1000)))
            .await
            .unwrap();
        assert_eq!(len(), 1000, "reserved up front");
        w.write_all(&[7u8; 1000]).await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        assert_eq!(std::fs::read(&file).unwrap(), vec![7u8; 1000]);

        // Interrupted: trimmed to the written length (a valid resume offset).
        let mut w = b
            .open_write(&path, WriteMode::Truncate, &opts(Some(1000)))
            .await
            .unwrap();
        w.write_all(&[1u8; 300]).await.unwrap();
        w.flush().await.unwrap();
        drop(w);
        assert_eq!(len(), 300);

        // Resume truncates back to the offset first, then reserves again.
        let mut w = b
            .open_write(&path, WriteMode::ResumeAt(200), &opts(Some(1000)))
            .await
            .unwrap();
        assert_eq!(len(), 1000);
        w.write_all(&[2u8; 100]).await.unwrap();
        w.flush().await.unwrap();
        drop(w);
        let data = std::fs::read(&file).unwrap();
        assert_eq!(data.len(), 300);
        assert!(data[..200].iter().all(|b| *b == 1));
        assert!(data[200..].iter().all(|b| *b == 2));

        // Without a hint nothing is reserved.
        let w = b
            .open_write(&path, WriteMode::Truncate, &opts(None))
            .await
            .unwrap();
        drop(w);
        assert_eq!(len(), 0);
    }
}
