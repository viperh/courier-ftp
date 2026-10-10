//! Trust in SSH host keys (T21) and TLS certificates (T12).
//!
//! - [`HostKey`]: a public key as SSH encodes it, with its fingerprints;
//! - [`HostKeyStore`]: keys the user chose to "Always trust"
//!   ([`MemoryHostKeyStore`] here; the vault-backed store is T30);
//! - [`known_hosts`]: read-only import of OpenSSH's `known_hosts` files;
//! - [`decide`]: the pure decision between accepting, refusing and asking;
//! - [`cert`]: trusted TLS certificates ([`CertTrustStore`]) and
//!   [`decide_certificate`] for FTPS (T12).
//!
//! The SSH verifier that puts these together lives in
//! `courier-ftp-proto-sftp` (`ssh::trust`), at the edge where russh's key
//! type is converted into a [`HostKey`].

pub mod cert;
mod host_key;
pub mod known_hosts;
mod store;

pub use self::{
    cert::{
        CertDecision, CertTrustInputs, CertTrustSource, CertTrustStore, CertTrustStoreSlot,
        MemoryCertTrustStore, TrustedCertificate, cert_sha256, colon_hex, decide_certificate,
        sha1_fingerprint, sha256_fingerprint,
    },
    host_key::HostKey,
    known_hosts::{KnownHosts, KnownHostsMatch},
    store::{HostKeyStore, HostKeyStoreSlot, KnownHost, MemoryHostKeyStore},
};

/// A host name as trust entries are keyed: ASCII lower case, brackets
/// around an IPv6 literal removed.
pub fn normalize_host(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

/// Where an accepted key was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSource {
    /// The [`HostKeyStore`] ("Always trust").
    Store,
    /// OpenSSH `known_hosts`.
    KnownHosts,
    /// "Trust once" earlier in this program run.
    Session,
}

/// What [`decide`] knows about the host.
#[derive(Debug, Clone, Copy)]
pub struct TrustInputs<'a> {
    /// Keys in the [`HostKeyStore`] for the host.
    pub stored: &'a [HostKey],
    /// What `known_hosts` says.
    pub known_hosts: &'a KnownHostsMatch,
    /// Keys trusted once during this run.
    pub session: &'a [HostKey],
    /// Whether "Always trust" can be stored (vault unlocked).
    pub can_remember: bool,
}

/// What to do with the key the server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Trusted: connect without asking.
    Accept(TrustSource),
    /// `@revoked` in `known_hosts`: refuse without asking.
    Revoked,
    /// Ask the user (`PromptKind::TrustHostKey`).
    Ask {
        /// The trusted key of the same type the server no longer presents
        /// (a possible man-in-the-middle attack), or `None` for a host seen
        /// for the first time.
        known: Option<HostKey>,
        /// Whether "Always trust" may be offered.
        can_remember: bool,
    },
}

/// Decide about `key` (pure; see the module docs of T21):
///
/// 1. revoked in `known_hosts` → [`Decision::Revoked`], even when trusted
///    elsewhere;
/// 2. equal to a stored, once-trusted or `known_hosts` key → accept;
/// 3. a trusted key of the same algorithm exists (store first, then this
///    session, then `known_hosts`) → ask with `known: Some(old)`;
/// 4. otherwise → ask with `known: None`.
pub fn decide(key: &HostKey, inputs: &TrustInputs<'_>) -> Decision {
    if inputs.known_hosts.revoked.contains(key) {
        return Decision::Revoked;
    }
    let sources = [
        (TrustSource::Store, inputs.stored),
        (TrustSource::Session, inputs.session),
        (
            TrustSource::KnownHosts,
            inputs.known_hosts.trusted.as_slice(),
        ),
    ];
    if let Some((source, _)) = sources.iter().find(|(_, keys)| keys.contains(key)) {
        return Decision::Accept(*source);
    }
    let known = sources
        .iter()
        .flat_map(|(_, keys)| keys.iter())
        .find(|k| k.algorithm() == key.algorithm())
        .cloned();
    Decision::Ask {
        known,
        can_remember: inputs.can_remember,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::{host_key::tests::blob, *};

    fn ed(seed: u8) -> HostKey {
        host_key::tests::ed25519(seed)
    }

    fn ecdsa() -> HostKey {
        HostKey::from_blob(blob(&[b"ecdsa-sha2-nistp256", b"nistp256", b"q"])).unwrap()
    }

    #[test]
    fn normalize_host_lowercases_and_strips_brackets() {
        assert_eq!(normalize_host("Example.COM"), "example.com");
        assert_eq!(normalize_host("[FE80::1]"), "fe80::1");
        assert_eq!(normalize_host("::1"), "::1");
    }

    #[test]
    fn decision_table() {
        struct Case {
            name: &'static str,
            stored: Vec<HostKey>,
            known_trusted: Vec<HostKey>,
            known_revoked: Vec<HostKey>,
            session: Vec<HostKey>,
            can_remember: bool,
            want: Decision,
        }
        let key = ed(1);
        let ask_new = |can_remember| Decision::Ask {
            known: None,
            can_remember,
        };
        let cases = vec![
            Case {
                name: "unknown host",
                stored: vec![],
                known_trusted: vec![],
                known_revoked: vec![],
                session: vec![],
                can_remember: true,
                want: ask_new(true),
            },
            Case {
                name: "unknown host, vault locked",
                stored: vec![],
                known_trusted: vec![],
                known_revoked: vec![],
                session: vec![],
                can_remember: false,
                want: ask_new(false),
            },
            Case {
                name: "only another algorithm is known",
                stored: vec![ecdsa()],
                known_trusted: vec![],
                known_revoked: vec![],
                session: vec![],
                can_remember: true,
                want: ask_new(true),
            },
            Case {
                name: "matches the store",
                stored: vec![ecdsa(), key.clone()],
                known_trusted: vec![],
                known_revoked: vec![],
                session: vec![],
                can_remember: true,
                want: Decision::Accept(TrustSource::Store),
            },
            Case {
                name: "matches known_hosts",
                stored: vec![],
                known_trusted: vec![key.clone()],
                known_revoked: vec![],
                session: vec![],
                can_remember: true,
                want: Decision::Accept(TrustSource::KnownHosts),
            },
            Case {
                name: "matches known_hosts, vault locked",
                stored: vec![],
                known_trusted: vec![key.clone()],
                known_revoked: vec![],
                session: vec![],
                can_remember: false,
                want: Decision::Accept(TrustSource::KnownHosts),
            },
            Case {
                name: "trusted once this session",
                stored: vec![],
                known_trusted: vec![],
                known_revoked: vec![],
                session: vec![key.clone()],
                can_remember: true,
                want: Decision::Accept(TrustSource::Session),
            },
            Case {
                name: "known_hosts matches although the store has an old key",
                stored: vec![ed(2)],
                known_trusted: vec![key.clone()],
                known_revoked: vec![],
                session: vec![],
                can_remember: true,
                want: Decision::Accept(TrustSource::KnownHosts),
            },
            Case {
                name: "mismatch with the store",
                stored: vec![ed(2)],
                known_trusted: vec![ed(3)],
                known_revoked: vec![],
                session: vec![],
                can_remember: true,
                want: Decision::Ask {
                    known: Some(ed(2)),
                    can_remember: true,
                },
            },
            Case {
                name: "mismatch with known_hosts, vault locked",
                stored: vec![],
                known_trusted: vec![ecdsa(), ed(3)],
                known_revoked: vec![],
                session: vec![],
                can_remember: false,
                want: Decision::Ask {
                    known: Some(ed(3)),
                    can_remember: false,
                },
            },
            Case {
                name: "mismatch with a once-trusted key",
                stored: vec![],
                known_trusted: vec![],
                known_revoked: vec![],
                session: vec![ed(4)],
                can_remember: true,
                want: Decision::Ask {
                    known: Some(ed(4)),
                    can_remember: true,
                },
            },
            Case {
                name: "revoked",
                stored: vec![],
                known_trusted: vec![],
                known_revoked: vec![key.clone()],
                session: vec![],
                can_remember: true,
                want: Decision::Revoked,
            },
            Case {
                name: "revoked wins over every trust",
                stored: vec![key.clone()],
                known_trusted: vec![key.clone()],
                known_revoked: vec![key.clone()],
                session: vec![key.clone()],
                can_remember: true,
                want: Decision::Revoked,
            },
            Case {
                name: "another key revoked",
                stored: vec![key.clone()],
                known_trusted: vec![],
                known_revoked: vec![ed(9)],
                session: vec![],
                can_remember: true,
                want: Decision::Accept(TrustSource::Store),
            },
        ];
        for case in cases {
            let known_hosts = KnownHostsMatch {
                trusted: case.known_trusted,
                revoked: case.known_revoked,
            };
            let inputs = TrustInputs {
                stored: &case.stored,
                known_hosts: &known_hosts,
                session: &case.session,
                can_remember: case.can_remember,
            };
            assert_eq!(decide(&key, &inputs), case.want, "{}", case.name);
        }
    }
}
