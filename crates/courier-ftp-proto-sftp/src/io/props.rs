#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_core::{backend::WriteMode, model::RemotePath};
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{IoParams, SftpReader, SftpWriter};
use crate::testing::{SftpTestKnobs, duplex_sftp_pair};

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

const PARAMS: IoParams = IoParams {
    chunk: 32_768,
    outstanding: 8,
    max_inflight_bytes: 8 << 20,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Random per-request caps (short reads), file sizes (EOF positions), start offsets
    /// and ranges: the output always equals the file's bytes.
    #[test]
    fn reader_reassembles_any_short_read_pattern(
        len in 0usize..300_000,
        caps in proptest::collection::vec(1u32..70_000, 0..6),
        offset_frac in 0.0f64..1.2,
        range in proptest::option::of(0u64..200_000),
        seed in any::<u8>(),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let content = data(len, seed);
        std::fs::write(dir.path().join("f"), &content).unwrap();
        let knobs = SftpTestKnobs { read_caps: caps, ..SftpTestKnobs::default() };
        let offset = (len as f64 * offset_frac) as u64;
        let out = rt().block_on(async {
            let (raw, _stats) = duplex_sftp_pair(knobs, dir.path());
            raw.init().await.unwrap();
            let path = RemotePath::parse("/f").unwrap();
            let mut r = SftpReader::open(Arc::new(raw), &path, offset, range, PARAMS)
                .await
                .unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).await.unwrap();
            out
        });
        let start = (offset as usize).min(len);
        let end = match range {
            Some(n) => (start + n as usize).min(len),
            None => len,
        };
        prop_assert_eq!(out.len(), end - start);
        prop_assert!(out == content[start..end]);
    }

    /// Random `poll_write` sizes: the remote file is byte-identical.
    #[test]
    fn writer_any_write_sizes_byte_identical(
        sizes in proptest::collection::vec(0usize..100_000, 0..12),
        chunk in prop_oneof![Just(4096u32), Just(32_768), Just(100_000)],
        outstanding in 1u32..16,
        seed in any::<u8>(),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let total: usize = sizes.iter().sum();
        let content = data(total, seed);
        let params = IoParams { chunk, outstanding, max_inflight_bytes: 8 << 20 };
        rt().block_on(async {
            let (raw, _stats) = duplex_sftp_pair(SftpTestKnobs::default(), dir.path());
            raw.init().await.unwrap();
            let path = RemotePath::parse("/out").unwrap();
            let mut w = SftpWriter::open(Arc::new(raw), &path, WriteMode::Truncate, params)
                .await
                .unwrap();
            let mut at = 0;
            for n in &sizes {
                let mut piece = &content[at..at + n];
                while !piece.is_empty() {
                    let k = w.write(piece).await.unwrap();
                    assert!(k > 0 && k <= chunk as usize);
                    piece = &piece[k..];
                }
                at += n;
            }
            w.shutdown().await.unwrap();
        });
        let back = std::fs::read(dir.path().join("out")).unwrap();
        prop_assert_eq!(back.len(), total);
        prop_assert!(back == content);
    }
}
