//! The `proxy-credential` view: a proxy password, referenced by the settings
//! `proxy.generic.credential_id` / `proxy.ftp_proxy.credential_id` (T05, used by T07 and
//! T15). The proxy user name stays in settings.

use crate::model::item::view::wire_enum;
use crate::model::item::{
    FieldReader, FieldWriter, ItemBody, ItemKind, ItemView, SecretField, ViewError,
};

wire_enum!(
    /// Which proxy setting the credential belongs to.
    ProxyScope {
        /// The generic (SOCKS/HTTP) proxy.
        Generic => "generic",
        /// The FTP proxy.
        FtpProxy => "ftp-proxy",
    }
);

/// A proxy password. `Debug` never shows the password.
#[derive(Debug, PartialEq, Eq)]
pub struct ProxyCredentialItem {
    /// Display name.
    pub label: String,
    /// Which proxy setting it is for.
    pub scope: ProxyScope,
    /// The password.
    pub password: SecretField,
}

impl ProxyCredentialItem {
    /// Deep copy (re-wraps the secret).
    pub fn duplicate(&self) -> Self {
        Self {
            label: self.label.clone(),
            scope: self.scope,
            password: self.password.duplicate(),
        }
    }
}

impl ItemView for ProxyCredentialItem {
    const KIND: ItemKind = ItemKind::ProxyCredential;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        Ok(Self {
            label: r.text("label", "")?,
            scope: r.req_enum("scope")?,
            password: r.secret("password")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.text(body, "label", &self.label, "");
        w.opt_enum(body, "scope", Some(&self.scope));
        w.secret(body, "password", &self.password);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::ids::DeviceId;
    use crate::model::item::{HlcClock, ManualClock};

    #[test]
    fn roundtrip() -> Result<(), ViewError> {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let mut w = FieldWriter::new(&mut clock, DeviceId::from_bytes([1; 16]));
        let mut view = ProxyCredentialItem {
            label: "office proxy".into(),
            scope: ProxyScope::FtpProxy,
            password: SecretField::Value("CANARY-proxy-31f0".into()),
        };
        let mut body = view.to_new_body(&mut w);
        assert_eq!(ProxyCredentialItem::from_body(&body)?, view);
        let before = body.clone();
        view.apply_to(&mut body, &mut w);
        assert_eq!(body, before, "unchanged view created stamps");
        assert!(!format!("{view:?}").contains("CANARY"));

        // Clearing the password writes null.
        view.password = SecretField::Absent;
        view.apply_to(&mut body, &mut w);
        assert_eq!(ProxyCredentialItem::from_body(&body)?, view);
        assert!(body.contains("password"));
        Ok(())
    }
}
