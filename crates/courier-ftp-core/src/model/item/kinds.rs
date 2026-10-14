//! Item kinds (T81).

use std::fmt;

use serde::{Deserialize, Serialize};

/// What an [`ItemBody`](super::ItemBody) describes. Encoded as a stable kebab-case string.
///
/// `#[non_exhaustive]`: newer builds may add kinds; an unknown kind fails to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ItemKind {
    /// One Site Manager entry (T31), passwords included.
    Site,
    /// A Site Manager folder; the tree is built from each item's `parent` id.
    SiteFolder,
    /// A global or site bookmark (T33).
    Bookmark,
    /// A trusted SSH host key (T21).
    KnownHost,
    /// A trusted TLS certificate (T12).
    TrustedCert,
    /// A private SSH key stored in the vault, referenced by sites by id.
    SshKey,
    /// Proxy user and password, referenced from settings by id.
    ProxyCredential,
    /// A member's own credentials for a site in a team vault, stored in their
    /// personal vault (T89).
    CredentialOverride,
    /// A quickconnect history entry; synced only when `sync.history` is on.
    HistoryEntry,
}

impl ItemKind {
    /// Every kind this build knows.
    pub const ALL: [ItemKind; 9] = [
        ItemKind::Site,
        ItemKind::SiteFolder,
        ItemKind::Bookmark,
        ItemKind::KnownHost,
        ItemKind::TrustedCert,
        ItemKind::SshKey,
        ItemKind::ProxyCredential,
        ItemKind::CredentialOverride,
        ItemKind::HistoryEntry,
    ];

    /// The stable wire string (`"site"`, `"known-host"`, …).
    pub const fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Site => "site",
            ItemKind::SiteFolder => "site-folder",
            ItemKind::Bookmark => "bookmark",
            ItemKind::KnownHost => "known-host",
            ItemKind::TrustedCert => "trusted-cert",
            ItemKind::SshKey => "ssh-key",
            ItemKind::ProxyCredential => "proxy-credential",
            ItemKind::CredentialOverride => "credential-override",
            ItemKind::HistoryEntry => "history-entry",
        }
    }

    /// Parses [`ItemKind::as_str`].
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_match_serde() -> Result<(), Box<dyn std::error::Error>> {
        for kind in ItemKind::ALL {
            let mut buf = Vec::new();
            ciborium::into_writer(&kind, &mut buf)?;
            let v: ciborium::Value = ciborium::from_reader(buf.as_slice())?;
            assert_eq!(v.as_text(), Some(kind.as_str()));
            assert_eq!(ItemKind::from_wire(kind.as_str()), Some(kind));
            assert_eq!(serde_json::to_string(&kind)?, format!("\"{kind}\""));
        }
        assert_eq!(ItemKind::from_wire("host"), None);
        Ok(())
    }
}
