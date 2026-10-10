//! Trust stores for TLS certificates and SSH host keys: `CertTrustStore` (T12)
//! and `HostKeyStore` (T21).
//!
//! Host keys (T21): [`KnownHost`] entries live in a [`HostKeyStore`] — memory while the
//! vault is locked ([`MemoryHostKeyStore`]), the vault after unlock (T30) — behind a
//! [`SwitchableHostKeyStore`]. [`SessionTrust`] remembers every accepted key for the
//! life of the process so the extra transfer connections do not ask again. The
//! verifier itself (`TrustVerifier`) lives in `courier-ftp-proto-sftp`.

mod host_keys;

pub use crate::events::{OldKey, OldKeySource};
pub use host_keys::{
    HostKeyStore, KnownHost, KnownHostId, MemoryHostKeyStore, SessionTrust, SwitchableHostKeyStore,
    normalize_host,
};

#[cfg(test)]
mod tests;
