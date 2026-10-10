//! Read-only support for OpenSSH `known_hosts` files (T21; copied from sverb
//! `sverb-core/src/known_hosts`, D13, without randomart and certificate checking).
//!
//! - [`parse`](mod@parse): the text format (`parse_known_hosts`);
//! - [`hashed`]: `|1|base64(salt)|base64(HMAC-SHA1(salt, lookup_key))` host fields;
//! - [`lookup`](mod@lookup): the lookup key (`host` / `[host]:port`), OpenSSH pattern
//!   lists and the entries that apply to a host;
//! - [`fingerprint`]: `SHA256:` and `MD5:` fingerprints as `ssh-keygen -l` prints them;
//! - [`openssh`]: [`OpenSshKnownHosts`], the cached reader of the user's and the
//!   system's files.
//!
//! courier-ftp never writes these files; trusted keys it learns go to the
//! `HostKeyStore` (`courier_ftp_core::trust`).

use std::path::PathBuf;

pub mod fingerprint;
pub mod hashed;
pub mod lookup;
pub mod openssh;
pub mod parse;

pub use fingerprint::{fingerprint_md5, fingerprint_sha256, key_blob};
pub use lookup::{OpenSshMatches, host_field_matches, lookup, lookup_key, pattern_list_matches};
pub use openssh::OpenSshKnownHosts;
pub use parse::{ParseWarning, parse_known_hosts};

/// The marker of a `known_hosts` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Marker {
    /// A plain host key.
    #[default]
    None,
    /// `@revoked`: this key must never be accepted.
    Revoked,
    /// `@cert-authority`: a CA for host certificates (ignored by courier-ftp).
    CertAuthority,
}

/// One entry of an OpenSSH `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSshEntry {
    /// The host field: a comma-separated pattern list or a hashed `|1|…` field.
    pub host_pattern: String,
    /// `"ssh-ed25519"`, `"ssh-rsa"`, …
    pub key_type: String,
    /// The base64 key blob.
    pub public_key: String,
    /// `@revoked` / `@cert-authority` / none.
    pub marker: Marker,
    /// The file the line is from.
    pub source: PathBuf,
    /// 1-based line number.
    pub line: usize,
}

/// Whether two key type names denote the same key type: `ssh-rsa`, `rsa-sha2-256` and
/// `rsa-sha2-512` are one RSA key type.
pub fn same_key_type(a: &str, b: &str) -> bool {
    let rsa = |n: &str| n == "ssh-rsa" || n.starts_with("rsa-sha2-");
    a == b || (rsa(a) && rsa(b))
}

/// The body of the `known_hosts_parse` fuzz target (T91) and its property-test twin:
/// parse arbitrary bytes, look a host up and fingerprint every key. Must never panic.
#[doc(hidden)]
pub fn fuzz_known_hosts_parse(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let (entries, _) = parse_known_hosts(&text, std::path::Path::new("fuzz"));
    for (host, port) in [("host.example", 22), ("host.example", 2222), ("::1", 22)] {
        let _ = lookup(&entries, host, port);
    }
    for e in &entries {
        let _ = host_field_matches(&e.host_pattern, "[a.b]:1");
        if let Some(blob) = key_blob(&e.public_key) {
            let _ = fingerprint_sha256(&blob);
            let _ = fingerprint_md5(&blob);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod props;
