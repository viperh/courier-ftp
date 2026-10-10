//! The `known-host` view: a trusted SSH host key (T21 converts it to and from
//! `trust::KnownHost` through T30).

use crate::model::ids::UnixMillis;
use crate::model::item::{FieldReader, FieldWriter, ItemBody, ItemKind, ItemView, ViewError};

/// Default SSH port.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// A trusted SSH host key. One item per `(host, port, key_type)`; lookups compare the
/// host case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostItem {
    /// Host name or address, lowercase, without brackets.
    pub host: String,
    /// Port (default 22).
    pub port: u16,
    /// Key algorithm name (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, …).
    pub key_type: String,
    /// OpenSSH base64 key blob, without type or comment.
    pub public_key: String,
    /// When the key was trusted.
    pub added_at: UnixMillis,
    /// Optional comment.
    pub comment: Option<String>,
}

impl KnownHostItem {
    /// A new entry; the host is normalized ([`KnownHostItem::normalize_host`]).
    pub fn new(
        host: &str,
        port: u16,
        key_type: &str,
        public_key: &str,
        added_at: UnixMillis,
    ) -> Self {
        Self {
            host: Self::normalize_host(host),
            port,
            key_type: key_type.to_owned(),
            public_key: public_key.to_owned(),
            added_at,
            comment: None,
        }
    }

    /// Lowercase, without the `[` `]` of an IPv6 literal.
    pub fn normalize_host(host: &str) -> String {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase()
    }

    /// Whether this entry is for `(host, port, key_type)` (host compared
    /// case-insensitively).
    pub fn matches(&self, host: &str, port: u16, key_type: &str) -> bool {
        self.port == port
            && self.key_type == key_type
            && self.host.eq_ignore_ascii_case(&Self::normalize_host(host))
    }
}

impl ItemView for KnownHostItem {
    const KIND: ItemKind = ItemKind::KnownHost;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        Ok(Self {
            host: r.req_text("host")?,
            port: r.int("port", DEFAULT_SSH_PORT)?,
            key_type: r.req_text("key_type")?,
            public_key: r.req_text("public_key")?,
            added_at: r.millis("added_at")?,
            comment: r.opt_text("comment")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.req_text(body, "host", &self.host);
        w.uint(
            body,
            "port",
            u64::from(self.port),
            u64::from(DEFAULT_SSH_PORT),
        );
        w.req_text(body, "key_type", &self.key_type);
        w.req_text(body, "public_key", &self.public_key);
        w.millis(body, "added_at", self.added_at);
        w.opt_text(body, "comment", self.comment.as_deref());
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
        let mut view = KnownHostItem::new(
            "[FE80::1]",
            2222,
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIA",
            UnixMillis(1_700_000_000_000),
        );
        view.comment = Some("build box".into());
        assert_eq!(view.host, "fe80::1");
        assert!(view.matches("[fe80::1]", 2222, "ssh-ed25519"));
        assert!(!view.matches("fe80::1", 22, "ssh-ed25519"));

        let mut body = view.to_new_body(&mut w);
        assert_eq!(KnownHostItem::from_body(&body)?, view);
        let before = body.clone();
        view.apply_to(&mut body, &mut w);
        assert_eq!(body, before, "unchanged view created stamps");

        // Default port is not written; a missing key reads as 22.
        let plain = KnownHostItem::new("h", 22, "ssh-rsa", "AAAA", UnixMillis(1));
        let body = plain.to_new_body(&mut w);
        assert!(!body.contains("port"));
        assert!(!body.contains("comment"));
        assert_eq!(KnownHostItem::from_body(&body)?, plain);

        assert_eq!(
            KnownHostItem::from_body(&ItemBody::new(ItemKind::KnownHost, 1)),
            Err(ViewError::Missing("host"))
        );
        Ok(())
    }
}
