//! Shape checks shared by client and server.
//!
//! The server maps every [`ProtoError::Invalid`] to `400 invalid` with the error's
//! text; error reasons never echo the rejected value.

use std::collections::HashSet;

use uuid::Uuid;

use crate::error::ProtoError;
use crate::limits::{
    MAX_BATCH_BYTES, MAX_BATCH_ITEMS, MAX_DEVICE_FIELD, MAX_EMAIL_LEN, MAX_ORG_NAME_CHARS,
    MAX_ROTATION_CHUNK,
};
use crate::rotation::RotateRequest;
use crate::sync::PushRequest;

/// Shortest acceptable email (`a@b`).
const MIN_EMAIL_LEN: usize = 3;

/// Device name or platform used when the client sends none.
pub const UNKNOWN_DEVICE_FIELD: &str = "unknown";

/// Trims and lower-cases an email, then checks it: 3..=254 chars, exactly one `@`,
/// non-empty local and domain parts, no whitespace or control characters. Returns
/// the normalized email (also the OPAQUE credential identifier input, T80).
///
/// # Errors
/// [`ProtoError::Invalid`] (`field` = `"email"`).
pub fn normalize_email(raw: &str) -> Result<String, ProtoError> {
    let email = raw.trim().to_lowercase();
    let len = email.chars().count();
    if len < MIN_EMAIL_LEN {
        return Err(ProtoError::invalid("email", "too short"));
    }
    if len > MAX_EMAIL_LEN {
        return Err(ProtoError::invalid(
            "email",
            format!("longer than {MAX_EMAIL_LEN} characters"),
        ));
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ProtoError::invalid(
            "email",
            "contains whitespace or control characters",
        ));
    }
    let mut parts = email.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty() => Ok(email),
        _ => Err(ProtoError::invalid(
            "email",
            "must be one non-empty local part, '@' and a non-empty domain",
        )),
    }
}

/// Normalizes a device name or platform: trimmed, at most
/// [`MAX_DEVICE_FIELD`] chars, no control characters; absent or empty becomes
/// [`UNKNOWN_DEVICE_FIELD`].
///
/// # Errors
/// [`ProtoError::Invalid`] (`field` = `"device"`).
pub fn device_field(raw: Option<&str>) -> Result<String, ProtoError> {
    let value = raw.map_or("", str::trim);
    if value.is_empty() {
        return Ok(UNKNOWN_DEVICE_FIELD.to_owned());
    }
    if value.chars().count() > MAX_DEVICE_FIELD {
        return Err(ProtoError::invalid(
            "device",
            format!("longer than {MAX_DEVICE_FIELD} characters"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(ProtoError::invalid("device", "contains control characters"));
    }
    Ok(value.to_owned())
}

/// Normalizes an org display name: trimmed, 1..=[`MAX_ORG_NAME_CHARS`] chars, no
/// control characters.
///
/// # Errors
/// [`ProtoError::Invalid`] (`field` = `"name"`).
pub fn validate_org_name(raw: &str) -> Result<String, ProtoError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ProtoError::invalid("name", "empty"));
    }
    if name.chars().count() > MAX_ORG_NAME_CHARS {
        return Err(ProtoError::invalid(
            "name",
            format!("longer than {MAX_ORG_NAME_CHARS} characters"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(ProtoError::invalid("name", "contains control characters"));
    }
    Ok(name.to_owned())
}

/// Checks a list of ids: none nil, none repeated.
fn unique_ids(field: &'static str, ids: impl Iterator<Item = Uuid>) -> Result<(), ProtoError> {
    let mut seen = HashSet::new();
    for id in ids {
        if id.is_nil() {
            return Err(ProtoError::invalid(field, "nil id"));
        }
        if !seen.insert(id) {
            return Err(ProtoError::invalid(field, format!("duplicate id {id}")));
        }
    }
    Ok(())
}

/// Checks a chunk of envelopes: at most `max_items`, at most [`MAX_BATCH_BYTES`] in total.
fn batch_size<'a>(
    field: &'static str,
    max_items: usize,
    envelopes: impl ExactSizeIterator<Item = &'a [u8]>,
) -> Result<(), ProtoError> {
    if envelopes.len() > max_items {
        return Err(ProtoError::invalid(
            field,
            format!("more than {max_items} entries"),
        ));
    }
    let total = envelopes.fold(0usize, |acc, e| acc.saturating_add(e.len()));
    if total > MAX_BATCH_BYTES {
        return Err(ProtoError::invalid(
            field,
            format!("envelopes exceed {MAX_BATCH_BYTES} bytes in total"),
        ));
    }
    Ok(())
}

impl PushRequest {
    /// At most [`MAX_BATCH_ITEMS`] changes, Σ envelope ≤ [`MAX_BATCH_BYTES`], no
    /// duplicate ids, no nil ids. Per-envelope size is **not** checked here: it is a
    /// per-item `too_large` result, not a request error.
    ///
    /// # Errors
    /// [`ProtoError::Invalid`] (`field` = `"changes"`).
    pub fn validate(&self) -> Result<(), ProtoError> {
        batch_size(
            "changes",
            MAX_BATCH_ITEMS,
            self.changes.iter().map(|c| c.envelope.as_slice()),
        )?;
        unique_ids("changes", self.changes.iter().map(|c| c.id))
    }
}

impl RotateRequest {
    /// `begin`: `new_key_version` ≥ 1. `upload`: at most [`MAX_ROTATION_CHUNK`]
    /// items, Σ envelope ≤ [`MAX_BATCH_BYTES`], no duplicate or nil ids. `commit`: no
    /// duplicate or nil users.
    ///
    /// # Errors
    /// [`ProtoError::Invalid`].
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Begin { new_key_version } => {
                if *new_key_version == 0 {
                    return Err(ProtoError::invalid("new_key_version", "must be at least 1"));
                }
                Ok(())
            }
            Self::Upload { items } => {
                batch_size(
                    "items",
                    MAX_ROTATION_CHUNK,
                    items.iter().map(|i| i.envelope.as_slice()),
                )?;
                unique_ids("items", items.iter().map(|i| i.id))
            }
            Self::Commit { wrapped_keys } => {
                unique_ids("wrapped_keys", wrapped_keys.iter().map(|g| g.user))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::rotation::{RotatedItem, RotationGrant};
    use crate::sync::{Permission, PushChange};

    fn change(n: u128, len: usize) -> PushChange {
        PushChange {
            id: Uuid::from_u128(n),
            base_revision: 0,
            key_version: 1,
            envelope: vec![0; len],
            deleted: false,
        }
    }

    fn push(changes: Vec<PushChange>) -> PushRequest {
        PushRequest { changes }
    }

    #[test]
    fn push_limits() {
        // 500 changes ok, 501 rejected.
        let ok = push((1..=500).map(|n| change(n, 1)).collect());
        assert!(ok.validate().is_ok());
        let too_many = push((1..=501).map(|n| change(n, 1)).collect());
        assert!(too_many.validate().is_err());

        // Exactly 8 MiB ok, one byte more rejected.
        let half = MAX_BATCH_BYTES / 2;
        let exact = push(vec![change(1, half), change(2, half)]);
        assert!(exact.validate().is_ok());
        let over = push(vec![change(1, half), change(2, half + 1)]);
        assert!(over.validate().is_err());

        // A single envelope over 1 MiB is not a request error.
        assert!(push(vec![change(1, 2 * 1024 * 1024)]).validate().is_ok());

        // Duplicate and nil ids.
        assert!(push(vec![change(1, 1), change(1, 1)]).validate().is_err());
        assert!(push(vec![change(0, 1)]).validate().is_err());
        assert!(push(vec![]).validate().is_ok());
    }

    #[test]
    fn rotate_limits() {
        let item = |n: u128, len: usize| RotatedItem {
            id: Uuid::from_u128(n),
            envelope: vec![0; len],
        };
        let ok = RotateRequest::Upload {
            items: (1..=500).map(|n| item(n, 1)).collect(),
        };
        assert!(ok.validate().is_ok());
        let too_many = RotateRequest::Upload {
            items: (1..=501).map(|n| item(n, 1)).collect(),
        };
        assert!(too_many.validate().is_err());
        let too_big = RotateRequest::Upload {
            items: vec![item(1, MAX_BATCH_BYTES), item(2, 1)],
        };
        assert!(too_big.validate().is_err());
        let dup = RotateRequest::Upload {
            items: vec![item(1, 1), item(1, 1)],
        };
        assert!(dup.validate().is_err());
        assert!(
            RotateRequest::Begin { new_key_version: 0 }
                .validate()
                .is_err()
        );
        assert!(
            RotateRequest::Begin { new_key_version: 2 }
                .validate()
                .is_ok()
        );
        let grant = |n: u128| RotationGrant {
            user: Uuid::from_u128(n),
            wrapped: vec![1],
            signature: vec![2],
            permission: Permission::Read,
        };
        let dup_users = RotateRequest::Commit {
            wrapped_keys: vec![grant(1), grant(1)],
        };
        assert!(dup_users.validate().is_err());
        let ok = RotateRequest::Commit {
            wrapped_keys: vec![grant(1), grant(2)],
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn normalize_email_cases() {
        assert_eq!(
            normalize_email("  Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
        assert_eq!(normalize_email("a@b").unwrap(), "a@b");
        let long = format!("{}@b.c", "a".repeat(251));
        assert_eq!(long.len(), 255);
        for bad in [
            "",
            "a",
            "a@",
            "@b",
            "a@b@c",
            "a b@c",
            "a\u{7}@b",
            long.as_str(),
        ] {
            assert!(normalize_email(bad).is_err(), "accepted {bad:?}");
        }
        let max = format!("{}@b.c", "a".repeat(250));
        assert!(normalize_email(&max).is_ok());
    }

    #[test]
    fn device_field_rules() {
        assert_eq!(device_field(None).unwrap(), "unknown");
        assert_eq!(device_field(Some("")).unwrap(), "unknown");
        assert_eq!(device_field(Some("   ")).unwrap(), "unknown");
        assert_eq!(device_field(Some(" laptop ")).unwrap(), "laptop");
        assert!(device_field(Some(&"x".repeat(128))).is_ok());
        assert!(device_field(Some(&"x".repeat(129))).is_err());
        assert!(device_field(Some("lap\u{0}top")).is_err());
        assert!(device_field(Some("lap\ttop")).is_err());
    }

    #[test]
    fn org_name_rules() {
        assert_eq!(validate_org_name("  Acme ").unwrap(), "Acme");
        assert!(validate_org_name("   ").is_err());
        assert!(validate_org_name(&"é".repeat(100)).is_ok());
        assert!(validate_org_name(&"é".repeat(101)).is_err());
        assert!(validate_org_name("a\nb").is_err());
    }

    #[test]
    fn errors_do_not_echo_values() {
        let err = normalize_email("SECRET-VALUE@@x").unwrap_err().to_string();
        assert!(!err.to_lowercase().contains("secret-value"), "{err}");
    }
}
