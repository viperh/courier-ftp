//! The item plaintext (T81; sverb `model/body.rs`, D13): [`ItemBody`] with
//! HLC-[`Stamped`] fields.
//!
//! [`ItemBody::to_cbor`] gives the bytes `courier_ftp_crypto::envelope::seal_item`
//! encrypts. Encoding is deterministic: the body is a CBOR map with the keys `kind`,
//! `schema_version`, `fields`, `deleted` in this order, the fields map is a `BTreeMap`
//! (sorted keys), and `ciborium::Value` maps inside values keep their insertion order,
//! which decoding preserves.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use ciborium::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hlc::{Hlc, HlcClock};
use super::kinds::ItemKind;
use crate::model::ids::DeviceId;

/// Field names (last dotted segment) whose values are secrets. They are plain CBOR text
/// inside the encrypted body, exposed only as `SecretString` by typed views, and
/// redacted by `ItemBody`'s `Debug`.
pub const SECRET_FIELDS: [&str; 5] = [
    "password",
    "private_key",
    "passphrase",
    "key_passphrase",
    "account",
];

/// Whether `field` (a possibly dotted key) holds a secret.
pub fn is_secret_field(field: &str) -> bool {
    let last = field.rsplit('.').next().unwrap_or(field);
    SECRET_FIELDS.contains(&last)
}

/// A value with the HLC stamp and device of its last write.
///
/// Merge order is `(hlc, device)` ([`Stamped::cmp_stamp`]). Encoded in CBOR as the
/// array `[value, hlc, device]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Stamped<T> {
    /// The value.
    pub value: T,
    /// When it was written.
    pub hlc: Hlc,
    /// Which device wrote it; breaks ties between equal stamps.
    pub device: DeviceId,
}

impl<T> Stamped<T> {
    /// Bundles a value with its stamp.
    pub fn new(value: T, hlc: Hlc, device: DeviceId) -> Self {
        Self { value, hlc, device }
    }

    /// The merge key `(hlc, device)`.
    pub fn stamp(&self) -> (Hlc, DeviceId) {
        (self.hlc, self.device)
    }

    /// Compares by `(hlc, device)`, ignoring the value.
    pub fn cmp_stamp<U>(&self, other: &Stamped<U>) -> Ordering {
        self.stamp().cmp(&other.stamp())
    }

    /// Whether this write wins over `other` under last-writer-wins.
    pub fn is_newer_than<U>(&self, other: &Stamped<U>) -> bool {
        self.cmp_stamp(other) == Ordering::Greater
    }
}

impl<T: Serialize> Serialize for Stamped<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&self.value, &self.hlc, &self.device).serialize(s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Stamped<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (value, hlc, device) = <(T, Hlc, DeviceId)>::deserialize(d)?;
        Ok(Self { value, hlc, device })
    }
}

/// Errors encoding or decoding an [`ItemBody`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyCodecError {
    /// The bytes are not a valid CBOR item body.
    #[error("invalid item body: {0}")]
    Decode(String),
    /// The body could not be encoded (should not happen).
    #[error("could not encode item body: {0}")]
    Encode(String),
    /// The body is valid but of a kind this build does not know (written by a newer
    /// build). It is kept untouched (T30) and stored as received (T88).
    #[error("unknown item kind")]
    UnknownKind(String),
}

/// The plaintext of a vault item.
#[derive(Clone, PartialEq, Serialize)]
pub struct ItemBody {
    /// What the item is.
    pub kind: ItemKind,
    /// Bumped only for breaking changes (see [`migrate`](fn@super::migrate)).
    pub schema_version: u16,
    /// Field-level LWW registers. Nested settings use dotted keys (`proxy.host`).
    /// Unknown keys are kept as they are.
    pub fields: BTreeMap<String, Stamped<Value>>,
    /// The tombstone; see [`ItemBody::is_deleted`].
    pub deleted: Option<Stamped<bool>>,
}

/// The wire form, with `kind` as a plain string so an unknown kind is reported as
/// [`BodyCodecError::UnknownKind`] rather than a generic decode error.
#[derive(Deserialize)]
struct RawBody {
    kind: String,
    schema_version: u16,
    #[serde(default)]
    fields: BTreeMap<String, Stamped<Value>>,
    #[serde(default)]
    deleted: Option<Stamped<bool>>,
}

impl fmt::Debug for ItemBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Fields<'a>(&'a BTreeMap<String, Stamped<Value>>);
        impl fmt::Debug for Fields<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut m = f.debug_map();
                for (k, v) in self.0 {
                    if is_secret_field(k) && !v.value.is_null() {
                        m.entry(k, &format_args!("[REDACTED] @ {:?}/{:?}", v.hlc, v.device));
                    } else {
                        m.entry(k, v);
                    }
                }
                m.finish()
            }
        }
        f.debug_struct("ItemBody")
            .field("kind", &self.kind)
            .field("schema_version", &self.schema_version)
            .field("fields", &Fields(&self.fields))
            .field("deleted", &self.deleted)
            .finish()
    }
}

/// A stamp for a write that replaces `current`: the clock's next stamp, raised past
/// `current` if needed. (After a clamped skewed observation the clock can lag behind a
/// stored stamp; a local overwrite must still win over what it replaced.)
pub(crate) fn next_stamp_after(clock: &mut HlcClock, current: Option<Hlc>) -> Hlc {
    let now = clock.now();
    match current {
        Some(cur) if cur >= now => Hlc::from_u64(cur.as_u64().saturating_add(1)),
        _ => now,
    }
}

impl ItemBody {
    /// An empty body.
    pub fn new(kind: ItemKind, schema_version: u16) -> Self {
        Self {
            kind,
            schema_version,
            fields: BTreeMap::new(),
            deleted: None,
        }
    }

    /// Writes `value` to `field` with a fresh stamp. Returns whether anything changed.
    ///
    /// Writing the value a field already holds is a no-op (no new stamp), so the outbox
    /// sees no spurious changes. A missing field and an explicit `Null` are different.
    pub fn set(
        &mut self,
        field: &str,
        value: impl Into<Value>,
        clock: &mut HlcClock,
        device: DeviceId,
    ) -> bool {
        let value = value.into();
        let current = self.fields.get(field);
        if current.is_some_and(|c| c.value == value) {
            return false;
        }
        let hlc = next_stamp_after(clock, current.map(|c| c.hlc));
        self.fields
            .insert(field.to_owned(), Stamped::new(value, hlc, device));
        true
    }

    /// Writes an explicit `Null` ("None"), which wins merges against older values. The
    /// key stays in the map. Returns whether anything changed.
    pub fn unset(&mut self, field: &str, clock: &mut HlcClock, device: DeviceId) -> bool {
        self.set(field, Value::Null, clock, device)
    }

    /// The current value of `field`; `Null` and missing are both `None`.
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.fields
            .get(field)
            .map(|s| &s.value)
            .filter(|v| !v.is_null())
    }

    /// The stamped register for `field`, including explicit `Null`s.
    pub fn get_stamped(&self, field: &str) -> Option<&Stamped<Value>> {
        self.fields.get(field)
    }

    /// Whether the key is present (even as `Null`).
    pub fn contains(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Sets the tombstone, stamped after every field so the item is deleted.
    pub fn delete(&mut self, clock: &mut HlcClock, device: DeviceId) {
        let hlc = next_stamp_after(clock, self.max_hlc());
        self.deleted = Some(Stamped::new(true, hlc, device));
    }

    /// Clears the tombstone (undo of a delete). No-op if the item is not deleted.
    pub fn restore(&mut self, clock: &mut HlcClock, device: DeviceId) {
        if self.deleted.as_ref().is_some_and(|d| d.value) {
            let hlc = next_stamp_after(clock, self.max_hlc());
            self.deleted = Some(Stamped::new(false, hlc, device));
        }
    }

    /// Deleted iff the tombstone is `true` and newer than every field. An edit newer
    /// than the delete resurrects the item.
    pub fn is_deleted(&self) -> bool {
        match &self.deleted {
            Some(d) if d.value => self.max_field_hlc().is_none_or(|max| d.hlc > max),
            _ => false,
        }
    }

    /// The highest field stamp (`None` for a body without fields).
    pub fn max_field_hlc(&self) -> Option<Hlc> {
        self.fields.values().map(|s| s.hlc).max()
    }

    /// The highest stamp in the body, tombstone included.
    pub fn max_hlc(&self) -> Option<Hlc> {
        let d = self.deleted.as_ref().map(|d| d.hlc);
        self.max_field_hlc().max(d)
    }

    /// Deterministic CBOR encoding (the input of `envelope::seal_item`).
    pub fn to_cbor(&self) -> Result<Vec<u8>, BodyCodecError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| BodyCodecError::Encode(e.to_string()))?;
        Ok(out)
    }

    /// Decodes [`ItemBody::to_cbor`] output. Never panics on untrusted input; nesting
    /// depth is bounded by `ciborium`'s recursion limit, the size by the caller (T80's
    /// plaintext cap, T30's item limit).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, BodyCodecError> {
        let raw: RawBody =
            ciborium::from_reader(bytes).map_err(|e| BodyCodecError::Decode(e.to_string()))?;
        let kind = ItemKind::from_wire(&raw.kind).ok_or(BodyCodecError::UnknownKind(raw.kind))?;
        Ok(Self {
            kind,
            schema_version: raw.schema_version,
            fields: raw.fields,
            deleted: raw.deleted,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::item::hlc::ManualClock;

    const T0: Duration = Duration::from_secs(1_800_000_000);

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn clock() -> HlcClock {
        HlcClock::new(ManualClock::new(T0))
    }

    #[test]
    fn set_same_value_is_noop() {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        assert!(b.set("host", "example.com", &mut clock, dev(1)));
        let before = b.clone();
        let last = clock.last();
        assert!(!b.set("host", "example.com", &mut clock, dev(2)));
        assert_eq!(b, before);
        assert_eq!(clock.last(), last);
        assert!(b.set("host", "other.example", &mut clock, dev(1)));
    }

    #[test]
    fn unset_writes_null() {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        b.set("user", "alice", &mut clock, dev(1));
        assert!(b.unset("user", &mut clock, dev(1)));
        assert!(b.contains("user"));
        assert_eq!(b.get("user"), None);
        assert_eq!(b.get_stamped("user").map(|s| &s.value), Some(&Value::Null));
        assert!(!b.unset("user", &mut clock, dev(1)));
        // Unsetting a missing key writes an explicit null too (it wins merges).
        assert!(b.unset("port", &mut clock, dev(1)));
        assert_eq!(b.get("missing"), None);
    }

    #[test]
    fn tombstone_only_body_is_deleted() {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        assert!(!b.is_deleted());
        b.delete(&mut clock, dev(1));
        assert!(b.is_deleted());
        b.restore(&mut clock, dev(1));
        assert!(!b.is_deleted());
        // A delete is stamped after every field.
        b.set("name", "x", &mut clock, dev(1));
        b.delete(&mut clock, dev(1));
        assert!(b.is_deleted());
        assert_eq!(b.max_hlc(), b.deleted.as_ref().map(|d| d.hlc));
        assert!(b.max_field_hlc() < b.max_hlc());
    }

    #[test]
    fn local_write_beats_skewed_stamp() {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        let future = Hlc::from_duration(T0 + Duration::from_secs(100_000));
        b.fields
            .insert("port".into(), Stamped::new(Value::from(21), future, dev(2)));
        assert!(b.set("port", 2121, &mut clock, dev(1)));
        let s = b.get_stamped("port").map(|s| s.hlc);
        assert_eq!(s, Some(Hlc::from_u64(future.as_u64() + 1)));
        // A delete also lands after the skewed stamp.
        b.delete(&mut clock, dev(1));
        assert!(b.is_deleted());
    }

    #[test]
    fn debug_redacts_secret_fields() {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        let canaries = [
            ("password", "CANARY-pw-1"),
            ("key_passphrase", "CANARY-kp-2"),
            ("passphrase", "CANARY-pp-3"),
            ("private_key", "CANARY-pk-4"),
            ("proxy.password", "CANARY-proxy-5"),
            ("account", "CANARY-acct-6"),
        ];
        for (k, v) in canaries {
            b.set(k, v, &mut clock, dev(1));
        }
        b.set("host", "example.com", &mut clock, dev(1));
        b.unset("x.password", &mut clock, dev(1));
        let s = format!("{b:?}");
        for (_, v) in canaries {
            assert!(!s.contains(v), "{s}");
        }
        assert!(!s.contains("CANARY"), "{s}");
        assert!(s.contains("[REDACTED] @ Hlc("), "{s}");
        assert!(s.contains("example.com"));
        assert!(is_secret_field("proxy.generic.password"));
        assert!(!is_secret_field("password_hint"));
    }

    #[test]
    fn cbor_is_deterministic() -> Result<(), BodyCodecError> {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        b.set("name", "web", &mut clock, dev(1));
        b.set("port", 2121, &mut clock, dev(2));
        b.set(
            "x.nested",
            Value::Map(vec![
                (Value::from("z"), Value::from(1)),
                (Value::from("a"), Value::Array(vec![Value::from(true)])),
            ]),
            &mut clock,
            dev(1),
        );
        b.set("id", Value::Bytes(vec![7; 16]), &mut clock, dev(1));
        b.delete(&mut clock, dev(3));
        let first = b.to_cbor()?;
        for _ in 0..100 {
            assert_eq!(b.to_cbor()?, first);
        }
        let decoded = ItemBody::from_cbor(&first)?;
        assert_eq!(decoded, b);
        assert_eq!(decoded.to_cbor()?, first);

        // Top-level layout: map of kind, schema_version, fields, deleted (in order).
        let v: Value = ciborium::from_reader(first.as_slice())
            .map_err(|e| BodyCodecError::Decode(e.to_string()))?;
        let keys: Vec<_> = v
            .as_map()
            .map(|m| m.iter().filter_map(|(k, _)| k.as_text()).collect())
            .unwrap_or_default();
        assert_eq!(keys, ["kind", "schema_version", "fields", "deleted"]);
        Ok(())
    }

    #[test]
    fn garbage_is_a_decode_error() {
        assert!(matches!(
            ItemBody::from_cbor(&[0xff, 0x00]),
            Err(BodyCodecError::Decode(_))
        ));
        assert!(matches!(
            ItemBody::from_cbor(&[]),
            Err(BodyCodecError::Decode(_))
        ));
    }
}
