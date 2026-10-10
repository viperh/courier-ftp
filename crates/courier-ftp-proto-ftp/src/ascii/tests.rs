//! ASCII conversion: chunk boundaries, lone CRs, round trips.

#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;

use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// Yields the given chunks one per read.
struct ChunkReader(VecDeque<Vec<u8>>);

impl AsyncRead for ChunkReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(mut chunk) = this.0.pop_front() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                this.0.push_front(chunk.split_off(n));
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn split(data: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = data;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes
            .get(i % sizes.len().max(1))
            .copied()
            .unwrap_or(1)
            .clamp(1, rest.len());
        out.push(rest[..n].to_vec());
        rest = &rest[n..];
        i += 1;
    }
    out
}

fn decode_chunks(chunks: Vec<Vec<u8>>, convert: bool) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async move {
        let mut d = AsciiDecode::with_conversion(ChunkReader(chunks.into()), convert);
        let mut out = Vec::new();
        d.read_to_end(&mut out).await.unwrap();
        out
    })
}

fn encode_chunks(chunks: Vec<Vec<u8>>, convert: bool) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async move {
        let mut e = AsciiEncode::with_conversion(Vec::new(), convert);
        for c in chunks {
            e.write_all(&c).await.unwrap();
        }
        e.shutdown().await.unwrap();
        e.inner
    })
}

#[test]
fn ascii_decode_cr_at_chunk_end() {
    let chunks = vec![b"line1\r".to_vec(), b"\nline2\r".to_vec(), b"\n".to_vec()];
    assert_eq!(decode_chunks(chunks, true), b"line1\nline2\n");
    // A CR held at the very end is emitted at EOF.
    assert_eq!(decode_chunks(vec![b"a\r".to_vec()], true), b"a\r");
    // A held CR followed by another CR.
    assert_eq!(
        decode_chunks(vec![b"a\r".to_vec(), b"\r\n".to_vec()], true),
        b"a\r\n"
    );
}

#[test]
fn ascii_decode_lone_cr_kept() {
    assert_eq!(decode_chunks(vec![b"a\rb\r\nc".to_vec()], true), b"a\rb\nc");
    assert_eq!(decode_chunks(vec![b"\r\r\r".to_vec()], true), b"\r\r\r");
}

#[test]
fn ascii_encode_existing_crlf_kept() {
    assert_eq!(
        encode_chunks(vec![b"a\nb\r\nc\n".to_vec()], true),
        b"a\r\nb\r\nc\r\n"
    );
    // CR at the end of one write, LF at the start of the next: unchanged.
    assert_eq!(
        encode_chunks(vec![b"a\r".to_vec(), b"\nb".to_vec()], true),
        b"a\r\nb"
    );
    assert_eq!(encode_chunks(vec![b"\n\n".to_vec()], true), b"\r\n\r\n");
}

#[test]
fn ascii_identity_when_not_converting() {
    let data = b"a\r\nb\nc\r".to_vec();
    assert_eq!(decode_chunks(vec![data.clone()], false), data);
    assert_eq!(encode_chunks(vec![data.clone()], false), data);
}

#[cfg(windows)]
#[test]
fn ascii_windows_is_identity() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let data = b"a\r\nb\nc\r".to_vec();
        let mut d = AsciiDecode::new(ChunkReader(vec![data.clone()].into()));
        let mut out = Vec::new();
        d.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
        let mut e = AsciiEncode::new(Vec::new());
        e.write_all(&data).await.unwrap();
        e.shutdown().await.unwrap();
        assert_eq!(e.inner, data);
    });
}

#[test]
fn large_writes_are_split_and_complete() {
    let data: Vec<u8> = (0..100_000u32)
        .map(|i| if i % 7 == 0 { b'\n' } else { b'x' })
        .collect();
    let encoded = encode_chunks(vec![data.clone()], true);
    assert_eq!(decode_chunks(vec![encoded], true), data);
}

fn text_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![Just(b'\r'), Just(b'\n'), Just(b'a'), any::<u8>()],
        0..512,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_ascii_chunking_invariant(
        data in text_bytes(),
        sizes in proptest::collection::vec(1usize..=64, 1..16),
    ) {
        let whole_dec = decode_chunks(vec![data.clone()], true);
        prop_assert_eq!(decode_chunks(split(&data, &sizes), true), whole_dec);
        let whole_enc = encode_chunks(vec![data.clone()], true);
        prop_assert_eq!(encode_chunks(split(&data, &sizes), true), whole_enc);
    }

    #[test]
    fn prop_ascii_roundtrip_lf_text(
        data in proptest::collection::vec(
            prop_oneof![Just(b'\n'), Just(b'a'), Just(b' '), 0x20u8..0x7f], 0..512),
        sizes in proptest::collection::vec(1usize..=64, 1..16),
    ) {
        let encoded = encode_chunks(split(&data, &sizes), true);
        prop_assert_eq!(decode_chunks(split(&encoded, &sizes), true), data);
    }
}
