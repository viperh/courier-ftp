//! Typed views implemented in T81. `Site`, `SiteFolder` and `CredentialOverride` (T31)
//! and `Bookmark`, `HistoryEntry` (T33) live with their features.

pub(crate) mod known_host;
pub(crate) mod proxy_credential;
pub(crate) mod ssh_key;
pub(crate) mod trusted_cert;
