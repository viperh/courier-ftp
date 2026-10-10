//! The deterministic fixture tree baked into the sshd and ftpd images under
//! `/home/<user>/fixtures/` (generated at image build by `bin/make-fixture-tree`, which
//! uses the same algorithm as [`fixture_bytes`]).

use std::{io::Read, path::Path};

use sha2::{Digest, Sha256};

/// Every regular file of the fixture tree: `(relative path, size)`.
pub const FIXTURE_TREE: &[(&str, u64)] = &[
    ("small.bin", 1024),
    ("1MiB.bin", 1_048_576),
    ("empty.txt", 0),
    ("names/with space.txt", 100),
    ("names/ leading-space.txt", 100),
    ("names/trailing-space.txt ", 100),
    ("names/Zürich – ü.txt", 100),
    ("names/日本語.txt", 100),
    ("names/-dash.txt", 100),
    ("names/semi;colon.txt", 100),
    ("sub/dir/deep.txt", 100),
];

/// The symlinks of the fixture tree: `(link, target)`.
pub const FIXTURE_SYMLINKS: &[(&str, &str)] = &[("link-to-small", "small.bin")];

/// Where the tree lives in the images, for `user`.
pub fn remote_fixture_dir(user: &str) -> String {
    format!("/home/{user}/fixtures")
}

/// The content of fixture file `rel_path` of `len` bytes: block *i* (32 bytes) is
/// `SHA-256(rel_path || u64_be(i))`, the whole truncated to `len`.
pub fn fixture_bytes(rel_path: &str, len: u64) -> impl Read + use<> {
    FixtureReader {
        key: rel_path.as_bytes().to_vec(),
        remaining: len,
        block: 0,
        buf: [0; 32],
        pos: 32,
    }
}

struct FixtureReader {
    key: Vec<u8>,
    remaining: u64,
    block: u64,
    buf: [u8; 32],
    pos: usize,
}

impl Read for FixtureReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < out.len() && self.remaining > 0 {
            if self.pos == self.buf.len() {
                let mut h = Sha256::new();
                h.update(&self.key);
                h.update(self.block.to_be_bytes());
                self.buf.copy_from_slice(&h.finalize());
                self.block += 1;
                self.pos = 0;
            }
            let avail = self.buf.len() - self.pos;
            let n = avail
                .min(out.len() - written)
                .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
            out[written..written + n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            written += n;
            self.remaining -= n as u64;
        }
        Ok(written)
    }
}

/// SHA-256 of everything `reader` yields, as lowercase hex.
///
/// # Errors
/// The reader failed.
pub fn sha256_reader(mut reader: impl Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// SHA-256 of a local file, as lowercase hex.
///
/// # Errors
/// The file could not be read.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    sha256_reader(std::fs::File::open(path)?)
}

/// SHA-256 of fixture file `rel_path` (from [`FIXTURE_TREE`]), as lowercase hex.
pub fn fixture_sha256(rel_path: &str) -> Option<String> {
    let (_, len) = FIXTURE_TREE.iter().find(|(p, _)| *p == rel_path)?;
    sha256_reader(fixture_bytes(rel_path, *len)).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Hashes of `bin/make-fixture-tree` output (Python), committed.
    #[test]
    fn fixture_bytes_matches_make_fixture_tree() {
        for (rel, want) in [
            (
                "small.bin",
                "81c9255503f380584398bf6dfff4fc83da6679c6ae00ffa6c7d85165b6972b18",
            ),
            (
                "names/Zürich – ü.txt",
                "9ddcbe3316bd6e47e74dc26cd7ddcb180ab573ade27dd65e76b9041a2cb2b77c",
            ),
            (
                "sub/dir/deep.txt",
                "ca7f187ca4a9b089d6cd2e3034a2aa8d00a2759c88668eaafd010504aeb6fa54",
            ),
        ] {
            assert_eq!(fixture_sha256(rel).unwrap(), want, "{rel}");
        }
    }

    #[test]
    fn fixture_bytes_has_exact_length_with_odd_reads() {
        let mut r = fixture_bytes("x", 100);
        let mut all = Vec::new();
        let mut buf = [0_u8; 7];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all.len(), 100);
        let mut again = Vec::new();
        fixture_bytes("x", 100).read_to_end(&mut again).unwrap();
        assert_eq!(all, again);
        assert_eq!(sha256_reader(fixture_bytes("e", 0)).unwrap().len(), 64);
    }
}
