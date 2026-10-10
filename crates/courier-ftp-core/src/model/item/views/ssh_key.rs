//! The `ssh-key` view: an SSH private key stored in the vault (T20, T31).

use crate::model::ids::UnixMillis;
use crate::model::item::view::wire_enum;
use crate::model::item::{
    FieldReader, FieldWriter, ItemBody, ItemKind, ItemView, SecretField, ViewError,
};

/// Largest accepted private key file.
pub const MAX_PRIVATE_KEY: usize = 64 * 1024;

wire_enum!(
    /// The key algorithm.
    SshKeyAlgorithm {
        /// Ed25519.
        Ed25519 => "ed25519",
        /// ECDSA on NIST P-256.
        EcdsaP256 => "ecdsa-p256",
        /// ECDSA on NIST P-384.
        EcdsaP384 => "ecdsa-p384",
        /// ECDSA on NIST P-521.
        EcdsaP521 => "ecdsa-p521",
        /// RSA.
        Rsa => "rsa",
        /// DSA (legacy).
        Dsa => "dsa",
    }
);

wire_enum!(
    /// The file format the key was imported in.
    SshKeyFormat {
        /// OpenSSH private key format.
        Openssh => "openssh",
        /// Traditional PEM (PKCS#1 / SEC1).
        Pem => "pem",
        /// PKCS#8.
        Pkcs8 => "pkcs8",
        /// PuTTY PPK version 2.
        Ppk2 => "ppk2",
        /// PuTTY PPK version 3.
        Ppk3 => "ppk3",
    }
);

/// An SSH private key. `Debug` never shows the key or passphrase.
#[derive(Debug, PartialEq, Eq)]
pub struct SshKeyItem {
    /// Display name.
    pub label: String,
    /// Key algorithm.
    pub algorithm: SshKeyAlgorithm,
    /// The key file content as imported (at most [`MAX_PRIVATE_KEY`] bytes).
    pub private_key: SecretField,
    /// The format of `private_key`.
    pub format: SshKeyFormat,
    /// OpenSSH one-line public key, when it could be derived.
    pub public_key: Option<String>,
    /// The key's passphrase, if stored.
    pub passphrase: SecretField,
    /// Optional comment.
    pub comment: Option<String>,
    /// When the key was imported.
    pub added_at: UnixMillis,
}

impl SshKeyItem {
    /// Deep copy (re-wraps the secrets).
    pub fn duplicate(&self) -> Self {
        Self {
            label: self.label.clone(),
            algorithm: self.algorithm,
            private_key: self.private_key.duplicate(),
            format: self.format,
            public_key: self.public_key.clone(),
            passphrase: self.passphrase.duplicate(),
            comment: self.comment.clone(),
            added_at: self.added_at,
        }
    }
}

impl ItemView for SshKeyItem {
    const KIND: ItemKind = ItemKind::SshKey;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        let private_key = r.secret("private_key")?;
        if private_key
            .value()
            .is_some_and(|k| k.expose().len() > MAX_PRIVATE_KEY)
        {
            return Err(ViewError::FieldType {
                field: "private_key".into(),
                expected: "at most 64 KiB",
            });
        }
        Ok(Self {
            label: r.text("label", "")?,
            algorithm: r.req_enum("algorithm")?,
            private_key,
            format: r.req_enum("format")?,
            public_key: r.opt_text("public_key")?,
            passphrase: r.secret("passphrase")?,
            comment: r.opt_text("comment")?,
            added_at: r.millis("added_at")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.text(body, "label", &self.label, "");
        w.opt_enum(body, "algorithm", Some(&self.algorithm));
        w.secret(body, "private_key", &self.private_key);
        w.opt_enum(body, "format", Some(&self.format));
        w.opt_text(body, "public_key", self.public_key.as_deref());
        w.secret(body, "passphrase", &self.passphrase);
        w.opt_text(body, "comment", self.comment.as_deref());
        w.millis(body, "added_at", self.added_at);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::ids::DeviceId;
    use crate::model::item::{HlcClock, ManualClock, WireEnum};

    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-key-7c1d\n";
    const PASS: &str = "CANARY-pass-2e9a";

    #[test]
    fn roundtrip_redacts() -> Result<(), ViewError> {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let mut w = FieldWriter::new(&mut clock, DeviceId::from_bytes([1; 16]));
        let view = SshKeyItem {
            label: "deploy".into(),
            algorithm: SshKeyAlgorithm::Ed25519,
            private_key: SecretField::Value(KEY.into()),
            format: SshKeyFormat::Openssh,
            public_key: Some("ssh-ed25519 AAAA deploy@host".into()),
            passphrase: SecretField::Value(PASS.into()),
            comment: None,
            added_at: UnixMillis(1_700_000_000_000),
        };
        let mut body = view.to_new_body(&mut w);
        let back = SshKeyItem::from_body(&body)?;
        assert_eq!(back, view);
        assert_eq!(back.duplicate(), view);
        let before = body.clone();
        view.apply_to(&mut body, &mut w);
        assert_eq!(body, before, "unchanged view created stamps");

        // Saving a view read without secrets keeps them.
        let mut listed = view.duplicate();
        listed.private_key = listed.private_key.without_value();
        listed.passphrase = listed.passphrase.without_value();
        listed.apply_to(&mut body, &mut w);
        assert_eq!(body, before);

        for s in [format!("{view:?}"), format!("{body:?}")] {
            assert!(!s.contains("CANARY"), "{s}");
        }

        // Wire strings round-trip; unknown strings are a type error.
        for a in SshKeyAlgorithm::ALL {
            assert_eq!(SshKeyAlgorithm::from_wire(a.as_wire()), Some(*a));
        }
        for f in SshKeyFormat::ALL {
            assert_eq!(SshKeyFormat::from_wire(f.as_wire()), Some(*f));
        }
        body.set("format", "ppk9", &mut clock, DeviceId::from_bytes([1; 16]));
        assert!(matches!(
            SshKeyItem::from_body(&body),
            Err(ViewError::FieldType { .. })
        ));
        Ok(())
    }
}
