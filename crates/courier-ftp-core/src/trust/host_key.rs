//! [`HostKey`]: an SSH public key in its wire encoding, without depending on
//! an SSH library.

use std::fmt;

use base64ct::{Base64, Base64Unpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::{Error, Result, model::HostKeyFingerprint};

/// An SSH public host key: its algorithm name and the SSH wire encoding of
/// the key (the "blob" that `known_hosts` and `authorized_keys` carry in
/// base64). Two keys are the same key when their blobs are equal.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HostKey {
    algorithm: String,
    blob: Vec<u8>,
}

impl HostKey {
    /// A key from its wire encoding. The algorithm is read from the blob's
    /// first field.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] when the blob doesn't start with an algorithm
    /// name.
    pub fn from_blob(blob: Vec<u8>) -> Result<Self> {
        let mut reader = Reader(&blob);
        let algorithm = reader
            .string()
            .and_then(|name| std::str::from_utf8(name).ok())
            .filter(|name| !name.is_empty() && name.is_ascii())
            .ok_or_else(|| Error::InvalidInput("not an SSH public key".to_owned()))?
            .to_owned();
        Ok(Self { algorithm, blob })
    }

    /// A key as OpenSSH writes it: `key_type` (`ssh-ed25519`) and the
    /// base64 blob.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] when the base64 is invalid or the blob is of
    /// another type than `key_type`.
    pub fn from_openssh(key_type: &str, base64: &str) -> Result<Self> {
        let blob = Base64::decode_vec(base64)
            .map_err(|_| Error::InvalidInput("invalid base64 in SSH public key".to_owned()))?;
        let key = Self::from_blob(blob)?;
        if key.algorithm != key_type {
            return Err(Error::InvalidInput(format!(
                "SSH public key says {key_type} but contains {}",
                key.algorithm
            )));
        }
        Ok(key)
    }

    /// The algorithm, e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The wire encoding.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The blob in base64, as in `known_hosts`.
    pub fn to_base64(&self) -> String {
        Base64::encode_string(&self.blob)
    }

    /// `SHA256:` and unpadded base64, as `ssh-keygen -l` prints it.
    pub fn sha256(&self) -> String {
        format!(
            "SHA256:{}",
            Base64Unpadded::encode_string(&Sha256::digest(&self.blob))
        )
    }

    /// The legacy `MD5:aa:bb:…` fingerprint.
    pub fn md5(&self) -> String {
        let digest = md5::compute(&self.blob);
        let hex: Vec<String> = digest.0.iter().map(|b| format!("{b:02x}")).collect();
        format!("MD5:{}", hex.join(":"))
    }

    /// The key size in bits, when the algorithm is known: 256 for Ed25519,
    /// the curve size for ECDSA, the modulus size for RSA, `p`'s size for DSA.
    pub fn bits(&self) -> Option<u32> {
        let alg = self.algorithm.as_str();
        match alg {
            "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => Some(256),
            "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => Some(256),
            "ecdsa-sha2-nistp384" => Some(384),
            "ecdsa-sha2-nistp521" => Some(521),
            "ssh-rsa" => {
                // string alg, mpint e, mpint n
                let mut r = Reader(&self.blob);
                r.string()?;
                r.string()?;
                mpint_bits(r.string()?)
            }
            "ssh-dss" => {
                // string alg, mpint p, …
                let mut r = Reader(&self.blob);
                r.string()?;
                mpint_bits(r.string()?)
            }
            _ => None,
        }
    }

    /// What the trust prompt shows.
    pub fn fingerprint(&self) -> HostKeyFingerprint {
        HostKeyFingerprint {
            algorithm: self.algorithm.clone(),
            bits: self.bits(),
            sha256: self.sha256(),
            md5: Some(self.md5()),
        }
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostKey({} {})", self.algorithm, self.sha256())
    }
}

impl fmt::Display for HostKey {
    /// `ssh-ed25519 SHA256:…`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.algorithm, self.sha256())
    }
}

/// Size in bits of an SSH `mpint` (big-endian, possibly a leading zero).
fn mpint_bits(bytes: &[u8]) -> Option<u32> {
    let first = bytes.iter().position(|&b| b != 0)?;
    let len = u32::try_from(bytes.len() - first).ok()?;
    Some(len * 8 - bytes[first].leading_zeros())
}

/// Reads SSH wire `string`s.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if rest.len() < len {
            return None;
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Some(value)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    /// Wire encoding of `fields` as SSH strings.
    pub(crate) fn blob(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in fields {
            out.extend_from_slice(&u32::try_from(f.len()).unwrap().to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// A fake Ed25519 key whose 32 key bytes are all `seed`.
    pub(crate) fn ed25519(seed: u8) -> HostKey {
        HostKey::from_blob(blob(&[b"ssh-ed25519", &[seed; 32]])).unwrap()
    }

    // `ed25519(7)` in base64, and its SHA-256, computed independently with
    // Python's `base64`/`hashlib`.
    const OPENSSH: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";
    const OPENSSH_SHA256: &str = "SHA256:gNSIRW+2Iyiuvsdp/bgjy38bvWHw6wQm3tuoXrl3WjQ";

    #[test]
    fn openssh_text_round_trips() {
        let key = HostKey::from_openssh("ssh-ed25519", OPENSSH).unwrap();
        assert_eq!(key, ed25519(7));
        assert_eq!(key.algorithm(), "ssh-ed25519");
        assert_eq!(key.to_base64(), OPENSSH);
        assert_eq!(key.bits(), Some(256));
        assert_eq!(key.sha256(), OPENSSH_SHA256);
        assert_eq!(key.to_string(), format!("ssh-ed25519 {OPENSSH_SHA256}"));
        assert_eq!(key.md5().len(), "MD5:".len() + 16 * 3 - 1);
    }

    #[test]
    fn mismatched_type_and_garbage_are_rejected() {
        assert!(HostKey::from_openssh("ssh-rsa", OPENSSH).is_err());
        assert!(HostKey::from_openssh("ssh-ed25519", "!!!").is_err());
        assert!(HostKey::from_blob(vec![0, 0, 0, 9, b'a']).is_err());
        assert!(HostKey::from_blob(Vec::new()).is_err());
    }

    #[test]
    fn fingerprints_match_known_values() {
        // sha256/md5 of the bytes, independently computed with coreutils:
        // printf 'abc' | sha256sum / md5sum
        let key = HostKey {
            algorithm: "x".into(),
            blob: b"abc".to_vec(),
        };
        assert_eq!(
            key.sha256(),
            "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
        );
        assert_eq!(
            key.md5(),
            "MD5:90:01:50:98:3c:d2:4f:b0:d6:96:3f:7d:28:e1:7f:72"
        );
    }

    #[test]
    fn rsa_bits_come_from_the_modulus() {
        let mut n = vec![0x00, 0xc3];
        n.extend(std::iter::repeat_n(0xff, 383)); // 384 bytes = 3072 bits
        let key = HostKey::from_blob(blob(&[b"ssh-rsa", &[1, 0, 1], &n])).unwrap();
        assert_eq!(key.bits(), Some(3072));
        let key = HostKey::from_blob(blob(&[b"ssh-rsa", &[1, 0, 1], &[0x01, 0]])).unwrap();
        assert_eq!(key.bits(), Some(9));
        let ecdsa = HostKey::from_blob(blob(&[b"ecdsa-sha2-nistp521", b"nistp521", b"q"])).unwrap();
        assert_eq!(ecdsa.bits(), Some(521));
        let other = HostKey::from_blob(blob(&[b"ssh-unknown"])).unwrap();
        assert_eq!(other.bits(), None);
    }

    #[test]
    fn fingerprint_fills_every_field() {
        let fp = ed25519(1).fingerprint();
        assert_eq!(fp.algorithm, "ssh-ed25519");
        assert_eq!(fp.bits, Some(256));
        assert_eq!(fp.sha256, ed25519(1).sha256());
        assert_eq!(fp.md5, Some(ed25519(1).md5()));
    }
}
