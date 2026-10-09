//! Item kinds (T81; sverb `model/kinds.rs`, D13).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::BodyCodecError;

/// What an [`ItemBody`](super::ItemBody) describes. Encoded as a stable kebab-case string.
///
/// An unknown string decodes to [`BodyCodecError::UnknownKind`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ItemKind {
    /// A Site Manager entry (view `Site`, T31).
    Site,
    /// A Site Manager folder (view `SiteFolder`, T31).
    SiteFolder,
    /// A global or per-site bookmark (view `Bookmark`, T33).
    Bookmark,
    /// A trusted SSH host key ([`KnownHostItem`](super::KnownHostItem)).
    KnownHost,
    /// A trusted TLS certificate ([`TrustedCertItem`](super::TrustedCertItem)).
    TrustedCert,
    /// An SSH private key ([`SshKeyItem`](super::SshKeyItem)).
    SshKey,
    /// A proxy password ([`ProxyCredentialItem`](super::ProxyCredentialItem)).
    ProxyCredential,
    /// A user's own credentials for a team site (view `CredentialOverride`, T31, T89).
    CredentialOverride,
    /// A quickconnect history entry (view `HistoryEntry`, T33).
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

    /// The stable wire string (`"site"`, `"site-folder"`, …).
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

    /// Parses a wire string; `None` for a kind this build does not know.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ItemKind {
    type Err = BodyCodecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_wire(s).ok_or_else(|| BodyCodecError::UnknownKind(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::super::ItemBody;
    use super::*;

    #[test]
    fn wire_strings_match_serde() -> Result<(), Box<dyn std::error::Error>> {
        for kind in ItemKind::ALL {
            let mut buf = Vec::new();
            ciborium::into_writer(&kind, &mut buf)?;
            let v: Value = ciborium::from_reader(buf.as_slice())?;
            assert_eq!(v.as_text(), Some(kind.as_str()));
            assert_eq!(kind.as_str().parse::<ItemKind>()?, kind);
            assert_eq!(kind.to_string(), kind.as_str());
        }
        Ok(())
    }

    #[test]
    fn unknown_kind_is_error() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = ItemBody::new(ItemKind::Site, 1).to_cbor()?;
        // Re-encode with an unknown kind string.
        let mut v: Value = ciborium::from_reader(bytes.as_slice())?;
        if let Value::Map(entries) = &mut v {
            for (k, val) in entries.iter_mut() {
                if k.as_text() == Some("kind") {
                    *val = Value::Text("teleporter".into());
                }
            }
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&v, &mut bytes)?;
        let err = ItemBody::from_cbor(&bytes).err();
        assert!(
            matches!(&err, Some(BodyCodecError::UnknownKind(s)) if s == "teleporter"),
            "{err:?}"
        );
        assert!(matches!(
            "teleporter".parse::<ItemKind>(),
            Err(BodyCodecError::UnknownKind(_))
        ));
        Ok(())
    }
}
