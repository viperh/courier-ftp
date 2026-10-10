//! Fingerprints as `ssh-keygen -l` prints them (copied from sverb
//! `known_hosts/fingerprint.rs`, D13, plus MD5): SHA-256 of the key blob in base64
//! without padding, or MD5 as 16 lowercase hex pairs (`ssh-keygen -l -E md5`).

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use md5::Md5;
use sha2::{Digest as _, Sha256};

/// The key blob of a base64 public-key field (`None`: not base64).
pub fn key_blob(base64: &str) -> Option<Vec<u8>> {
    STANDARD.decode(base64.trim()).ok()
}

/// `SHA256:<base64, no padding>` of a key blob.
pub fn fingerprint_sha256(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// `MD5:aa:bb:…` (16 lowercase hex pairs) of a key blob.
pub fn fingerprint_md5(blob: &[u8]) -> String {
    use md5::Digest as _;
    let digest = Md5::digest(blob);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("MD5:{}", hex.join(":"))
}
