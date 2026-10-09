//! The `trusted-cert` view: an FTPS certificate the user chose to trust (T12).

use crate::model::ids::UnixMillis;
use crate::model::item::{FieldReader, FieldWriter, ItemBody, ItemKind, ItemView, ViewError};

/// Largest accepted leaf certificate.
pub const MAX_CERT_DER: usize = 16 * 1024;

/// A trusted TLS leaf certificate. One item per `(host, port)`: "Always trust" of a
/// changed certificate replaces the fingerprint in the existing item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCertItem {
    /// Host name, lowercase.
    pub host: String,
    /// Port.
    pub port: u16,
    /// SHA-256 of the leaf certificate DER.
    pub sha256: [u8; 32],
    /// The leaf certificate (at most [`MAX_CERT_DER`] bytes).
    pub cert_der: Vec<u8>,
    /// Subject, for display.
    pub subject: String,
    /// Issuer, for display.
    pub issuer: String,
    /// End of validity.
    pub not_after: UnixMillis,
    /// When the certificate was trusted.
    pub added_at: UnixMillis,
}

impl TrustedCertItem {
    /// Whether this entry is for `(host, port)` (host compared case-insensitively).
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.port == port && self.host.eq_ignore_ascii_case(host)
    }
}

impl ItemView for TrustedCertItem {
    const KIND: ItemKind = ItemKind::TrustedCert;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        let sha256 = r.req_bytes("sha256")?;
        let sha256: [u8; 32] = sha256.try_into().map_err(|_| ViewError::FieldType {
            field: "sha256".into(),
            expected: "32 bytes",
        })?;
        let cert_der = r.req_bytes("cert_der")?;
        if cert_der.len() > MAX_CERT_DER {
            return Err(ViewError::FieldType {
                field: "cert_der".into(),
                expected: "at most 16 KiB",
            });
        }
        Ok(Self {
            host: r.req_text("host")?,
            port: r.req_int("port")?,
            sha256,
            cert_der,
            subject: r.text("subject", "")?,
            issuer: r.text("issuer", "")?,
            not_after: r.millis("not_after")?,
            added_at: r.millis("added_at")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.req_text(body, "host", &self.host);
        w.opt_uint(body, "port", Some(u64::from(self.port)));
        w.bytes(body, "sha256", &self.sha256);
        w.bytes(body, "cert_der", &self.cert_der);
        w.text(body, "subject", &self.subject, "");
        w.text(body, "issuer", &self.issuer, "");
        w.millis(body, "not_after", self.not_after);
        w.millis(body, "added_at", self.added_at);
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
        let mut view = TrustedCertItem {
            host: "ftp.example.com".into(),
            port: 990,
            sha256: [0x5a; 32],
            cert_der: vec![0x30, 0x82, 0x01, 0x00],
            subject: "CN=ftp.example.com".into(),
            issuer: "CN=Example CA".into(),
            not_after: UnixMillis(1_900_000_000_000),
            added_at: UnixMillis(1_700_000_000_000),
        };
        let mut body = view.to_new_body(&mut w);
        assert_eq!(TrustedCertItem::from_body(&body)?, view);
        let before = body.clone();
        view.apply_to(&mut body, &mut w);
        assert_eq!(body, before, "unchanged view created stamps");
        assert!(view.matches("FTP.example.com", 990));

        // "Always trust" of a changed certificate replaces the fingerprint in place.
        view.sha256 = [0x6b; 32];
        view.apply_to(&mut body, &mut w);
        assert_eq!(TrustedCertItem::from_body(&body)?.sha256, [0x6b; 32]);

        // Wrong fingerprint length and oversized certificates are rejected.
        let mut bad = body.clone();
        w.bytes(&mut bad, "sha256", &[1; 31]);
        assert!(matches!(
            TrustedCertItem::from_body(&bad),
            Err(ViewError::FieldType { .. })
        ));
        let mut big = body;
        w.bytes(&mut big, "cert_der", &vec![0; MAX_CERT_DER + 1]);
        assert!(TrustedCertItem::from_body(&big).is_err());
        Ok(())
    }
}
