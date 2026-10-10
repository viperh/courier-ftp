//! Algorithm preferences (T20; adapted from sverb `ssh/algorithms.rs`, D13).
//!
//! The preference lists work on names; [`to_russh`] converts them to
//! `russh::Preferred`, dropping anything the pinned russh doesn't implement. Faster AEAD
//! ciphers come first (T41b §3). The `COMPAT_*` entries are appended last, so they are
//! only chosen when the server offers nothing better; everything else (CBC, 3DES,
//! `diffie-hellman-group1-sha1`, `ssh-dss`) is not offered at all. Host-key types the
//! verifier already trusts for the host move to the front (T21).

use std::borrow::Cow;

use russh::{Preferred, cipher, compression, kex, keys::Algorithm, mac};

/// Key exchange, most preferred first.
pub const KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
];
/// Key exchange offered last, for old servers.
pub const COMPAT_KEX: &[&str] = &["diffie-hellman-group14-sha1"];

/// Host-key algorithms, most preferred first.
pub const HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];
/// Host-key algorithms offered last (RSA with SHA-1 signatures).
pub const COMPAT_HOST_KEYS: &[&str] = &["ssh-rsa"];

/// Ciphers, most preferred first (fast AEAD first).
pub const CIPHERS: &[&str] = &[
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
];

/// MACs (used with the non-AEAD ciphers only).
pub const MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
];
/// MACs offered last.
pub const COMPAT_MACS: &[&str] = &["hmac-sha1"];

/// Compression.
pub const COMPRESSION: &[&str] = &["none"];

/// An algorithm category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgoKind {
    /// Key exchange.
    Kex,
    /// Host key.
    HostKey,
    /// Cipher.
    Cipher,
    /// MAC.
    Mac,
    /// Compression.
    Compression,
}

impl AlgoKind {
    /// Every category.
    pub const ALL: [Self; 5] = [
        Self::Kex,
        Self::HostKey,
        Self::Cipher,
        Self::Mac,
        Self::Compression,
    ];

    /// The words used in messages ("No common key exchange: …").
    pub fn noun(self) -> &'static str {
        match self {
            Self::Kex => "key exchange",
            Self::HostKey => "host key algorithm",
            Self::Cipher => "cipher",
            Self::Mac => "MAC",
            Self::Compression => "compression",
        }
    }

    /// The preferred list.
    pub fn preferred(self) -> &'static [&'static str] {
        match self {
            Self::Kex => KEX,
            Self::HostKey => HOST_KEYS,
            Self::Cipher => CIPHERS,
            Self::Mac => MACS,
            Self::Compression => COMPRESSION,
        }
    }

    /// The compatibility entries appended last.
    pub fn compat(self) -> &'static [&'static str] {
        match self {
            Self::Kex => COMPAT_KEX,
            Self::HostKey => COMPAT_HOST_KEYS,
            Self::Mac => COMPAT_MACS,
            Self::Cipher | Self::Compression => &[],
        }
    }

    /// Whether the pinned russh implements `name` in this category.
    pub fn is_supported(self, name: &str) -> bool {
        match self {
            Self::Kex => kex::Name::try_from(name).is_ok() && name != "none",
            Self::HostKey => host_key_algorithm(name).is_some(),
            Self::Cipher => {
                cipher::Name::try_from(name).is_ok() && !matches!(name, "none" | "clear")
            }
            Self::Mac => mac::Name::try_from(name).is_ok() && name != "none",
            Self::Compression => compression::Name::try_from(name).is_ok(),
        }
    }
}

/// The host-key algorithms russh can verify (no DSA, no FIDO `sk-*` host keys).
fn host_key_algorithm(name: &str) -> Option<Algorithm> {
    match Algorithm::new(name).ok()? {
        a @ (Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }) => Some(a),
        _ => None,
    }
}

/// The preference lists for one connection, by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlgoTable {
    /// Key exchange.
    pub kex: Vec<String>,
    /// Host key algorithms.
    pub host_key: Vec<String>,
    /// Ciphers.
    pub cipher: Vec<String>,
    /// MACs.
    pub mac: Vec<String>,
    /// Compression.
    pub compression: Vec<String>,
}

impl AlgoTable {
    /// The list for `kind`.
    pub fn list(&self, kind: AlgoKind) -> &[String] {
        match kind {
            AlgoKind::Kex => &self.kex,
            AlgoKind::HostKey => &self.host_key,
            AlgoKind::Cipher => &self.cipher,
            AlgoKind::Mac => &self.mac,
            AlgoKind::Compression => &self.compression,
        }
    }

    fn list_mut(&mut self, kind: AlgoKind) -> &mut Vec<String> {
        match kind {
            AlgoKind::Kex => &mut self.kex,
            AlgoKind::HostKey => &mut self.host_key,
            AlgoKind::Cipher => &mut self.cipher,
            AlgoKind::Mac => &mut self.mac,
            AlgoKind::Compression => &mut self.compression,
        }
    }
}

/// The preferences for a connection: the preferred lists (host-key types in
/// `known_key_types` moved to the front), then the compatibility entries. Only names the
/// pinned russh implements are kept.
pub fn preferences(known_key_types: &[String]) -> AlgoTable {
    let mut table = AlgoTable::default();
    for kind in AlgoKind::ALL {
        let mut preferred: Vec<String> = kind
            .preferred()
            .iter()
            .filter(|n| kind.is_supported(n))
            .map(|n| (*n).to_owned())
            .collect();
        if kind == AlgoKind::HostKey {
            preferred = reorder_host_keys(&preferred, known_key_types);
        }
        let list = table.list_mut(kind);
        list.extend(preferred);
        list.extend(
            kind.compat()
                .iter()
                .filter(|n| kind.is_supported(n))
                .map(|n| (*n).to_owned()),
        );
    }
    table
}

/// Whether two host-key names are the same key type (all RSA signature variants share
/// one `ssh-rsa` key).
fn same_key_type(known: &str, algorithm: &str) -> bool {
    let rsa = |n: &str| n == "ssh-rsa" || n.starts_with("rsa-sha2-");
    known == algorithm || (rsa(known) && rsa(algorithm))
}

/// Move the algorithms whose key type is in `known` to the front, keeping the
/// preference order within both groups.
pub fn reorder_host_keys(list: &[String], known: &[String]) -> Vec<String> {
    let is_known = |a: &String| known.iter().any(|k| same_key_type(k, a));
    let (mut front, back): (Vec<String>, Vec<String>) = list.iter().cloned().partition(is_known);
    front.extend(back);
    front
}

/// Extension pseudo-algorithms appended to the key exchange list: RFC 8308 ext-info
/// (`server-sig-algs`) and OpenSSH strict KEX (the Terrapin mitigation).
const KEX_EXTENSIONS: [kex::Name; 2] = [
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// Whether `name` is an extension pseudo-algorithm rather than a key exchange.
pub fn is_kex_extension(name: &str) -> bool {
    name.starts_with("ext-info-") || name.starts_with("kex-strict-")
}

/// Convert `table` to russh's preferences. Names russh doesn't know are dropped. No
/// host certificates are offered (host keys are verified as plain keys, T21).
pub fn to_russh(table: &AlgoTable) -> Preferred {
    let mut kex: Vec<kex::Name> = table
        .kex
        .iter()
        .filter_map(|n| kex::Name::try_from(n.as_str()).ok())
        .collect();
    kex.extend(KEX_EXTENSIONS);
    Preferred {
        kex: Cow::Owned(kex),
        key: Cow::Owned(
            table
                .host_key
                .iter()
                .filter_map(|n| host_key_algorithm(n))
                .collect(),
        ),
        host_key_certificates: Cow::Owned(Vec::new()),
        cipher: Cow::Owned(
            table
                .cipher
                .iter()
                .filter(|n| AlgoKind::Cipher.is_supported(n))
                .filter_map(|n| cipher::Name::try_from(n.as_str()).ok())
                .collect(),
        ),
        mac: Cow::Owned(
            table
                .mac
                .iter()
                .filter(|n| AlgoKind::Mac.is_supported(n))
                .filter_map(|n| mac::Name::try_from(n.as_str()).ok())
                .collect(),
        ),
        compression: Cow::Owned(
            table
                .compression
                .iter()
                .filter_map(|n| compression::Name::try_from(n.as_str()).ok())
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn s(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn default_table_follows_the_spec() {
        let table = preferences(&[]);
        assert_eq!(
            &table.kex[..3],
            &s(&[
                "mlkem768x25519-sha256",
                "curve25519-sha256",
                "curve25519-sha256@libssh.org"
            ])
        );
        assert_eq!(table.cipher[0], "aes128-gcm@openssh.com");
        assert_eq!(table.host_key[0], "ssh-ed25519");
        assert_eq!(table.compression, s(&["none"]));
        for kind in AlgoKind::ALL {
            for name in table.list(kind) {
                assert!(kind.is_supported(name), "{name}");
                assert!(!name.contains("cbc") && name != "ssh-dss", "{name}");
            }
        }
        assert!(!table.kex.iter().any(|n| n == "diffie-hellman-group1-sha1"));
    }

    #[test]
    fn known_key_types_move_to_front() {
        let table = preferences(&s(&["rsa-sha2-512"]));
        assert_eq!(table.host_key[0], "rsa-sha2-512");
        assert_eq!(table.host_key[1], "rsa-sha2-256", "same key type");
        assert_eq!(table.host_key[2], "ssh-ed25519");
        // known_hosts stores RSA keys as `ssh-rsa`: the SHA-2 variants move up, but
        // `ssh-rsa` (SHA-1) itself stays last.
        let table = preferences(&s(&["ssh-rsa", "ecdsa-sha2-nistp384"]));
        assert_eq!(
            &table.host_key[..3],
            &s(&["ecdsa-sha2-nistp384", "rsa-sha2-512", "rsa-sha2-256"])
        );
        assert_eq!(table.host_key.last().map(String::as_str), Some("ssh-rsa"));
    }

    #[test]
    fn compat_entries_are_last() {
        let table = preferences(&s(&["ssh-rsa"]));
        for kind in AlgoKind::ALL {
            let list = table.list(kind);
            let compat = kind.compat();
            if compat.is_empty() {
                continue;
            }
            let tail = &list[list.len() - compat.len()..];
            assert_eq!(tail, &s(compat)[..], "{kind:?}");
            for name in &list[..list.len() - compat.len()] {
                assert!(!compat.contains(&name.as_str()), "{kind:?} {name}");
            }
        }
    }

    #[test]
    fn unsupported_names_dropped() {
        let table = AlgoTable {
            kex: s(&["made-up-kex", "curve25519-sha256"]),
            host_key: s(&["ssh-dss", "ssh-ed25519", "nope"]),
            cipher: s(&["none", "3des-cbc", "aes128-ctr"]),
            mac: s(&["hmac-md5", "hmac-sha2-256"]),
            compression: s(&["none"]),
        };
        let p = to_russh(&table);
        assert_eq!(p.kex.len(), 1 + 2, "plus ext-info-c and strict kex");
        assert_eq!(p.key.len(), 1);
        assert_eq!(p.cipher.len(), 1);
        assert_eq!(p.mac.len(), 1);
        assert!(p.host_key_certificates.is_empty());
        let full = to_russh(&preferences(&[]));
        assert_eq!(full.key.len(), preferences(&[]).host_key.len());
        assert!(is_kex_extension("ext-info-c"));
        assert!(!is_kex_extension("curve25519-sha256"));
    }
}
