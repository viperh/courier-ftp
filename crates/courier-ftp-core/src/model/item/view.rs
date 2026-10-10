//! Typed views over an [`ItemBody`] (T81; sverb `model/fields.rs`, D13).
//!
//! A view is built with [`ItemView::from_body`] (through a [`FieldReader`]) and written
//! back with [`ItemView::apply_to`] (through a [`FieldWriter`]). Writing:
//!
//! - only touches fields whose value changed ([`ItemBody::set`] skips equal values), so
//!   applying an unchanged view creates no stamp;
//! - never writes a default into a missing key (a missing key already reads as the
//!   default);
//! - never touches keys the view does not know, so an older build keeps what a newer one
//!   wrote.
//!
//! Field names, CBOR shapes and enum strings are listed in `docs/data-model.md`.

use std::fmt;

use ciborium::Value;

use super::body::ItemBody;
use super::hlc::HlcClock;
use super::kinds::ItemKind;
use super::migrate::current_schema;
use crate::model::ids::{DeviceId, ItemId, UnixMillis};
use crate::secret::SecretString;

/// Errors converting an [`ItemBody`] into a typed view. T30 reports the item as
/// unreadable for that view and keeps the raw body untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// The body is a different kind of item.
    #[error("expected a {expected} item, found {found}")]
    WrongKind {
        /// The kind the view needs.
        expected: ItemKind,
        /// The kind of the body.
        found: ItemKind,
    },
    /// A required field is missing (or `null`).
    #[error("required field `{0}` is missing")]
    Missing(&'static str),
    /// A field holds a CBOR value of the wrong type, out of range, or an unknown enum
    /// string.
    #[error("field `{field}` is not {expected}")]
    FieldType {
        /// The (dotted) field name.
        field: String,
        /// What the field should hold.
        expected: &'static str,
    },
}

impl ViewError {
    fn field_type(field: &str, expected: &'static str) -> Self {
        Self::FieldType {
            field: field.to_owned(),
            expected,
        }
    }
}

/// A closed enum encoded as a stable string (see `docs/data-model.md`).
pub trait WireEnum: Sized {
    /// The wire string.
    fn as_wire(&self) -> &'static str;
    /// Parses the wire string; `None` for an unknown one.
    fn from_wire(s: &str) -> Option<Self>;
}

/// Defines a fieldless enum with stable wire strings.
macro_rules! wire_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant),+
        }

        impl $name {
            /// Every variant.
            pub const ALL: &'static [$name] = &[$(Self::$variant),+];
        }

        impl $crate::model::item::WireEnum for $name {
            fn as_wire(&self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
            fn from_wire(s: &str) -> Option<Self> {
                match s { $($wire => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}
pub(crate) use wire_enum;

/// A secret field as seen by a view. Views listed from the T30 cache never hold secret
/// values; `Kept` makes `apply_to` leave the stored value untouched, so saving a view
/// that was read without secrets can never erase them.
///
/// `Debug` never shows the value. There is no `Clone` (use [`SecretField::duplicate`]);
/// `PartialEq` compares values in constant time.
#[derive(Debug, Default)]
pub enum SecretField {
    /// No secret stored (or the user cleared it): `apply_to` writes `null` if one is
    /// stored.
    #[default]
    Absent,
    /// A secret is stored but was not loaded: `apply_to` writes nothing.
    Kept,
    /// Loaded or newly typed: `apply_to` writes it when it differs from the stored value.
    Value(SecretString),
}

impl SecretField {
    /// Whether a secret is (or stays) stored.
    pub fn is_set(&self) -> bool {
        !matches!(self, Self::Absent)
    }

    /// The loaded value, if any.
    pub fn value(&self) -> Option<&SecretString> {
        match self {
            Self::Value(s) => Some(s),
            Self::Absent | Self::Kept => None,
        }
    }

    /// `Value` for `Some`, `Absent` for `None`.
    pub fn from_option(value: Option<SecretString>) -> Self {
        value.map_or(Self::Absent, Self::Value)
    }

    /// The same field without secret content: `Value` becomes `Kept` (what the T30
    /// cache hands out).
    pub fn without_value(&self) -> Self {
        match self {
            Self::Absent => Self::Absent,
            Self::Kept | Self::Value(_) => Self::Kept,
        }
    }

    /// Deep copy (re-wraps the secret).
    pub fn duplicate(&self) -> Self {
        match self {
            Self::Absent => Self::Absent,
            Self::Kept => Self::Kept,
            Self::Value(s) => Self::Value(SecretString::from(s.expose())),
        }
    }
}

impl PartialEq for SecretField {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) | (Self::Kept, Self::Kept) => true,
            (Self::Value(a), Self::Value(b)) => a.ct_eq(b),
            _ => false,
        }
    }
}

impl Eq for SecretField {}

/// CBOR tag that replaces stored secret values in the vault cache's bodies (T30), so
/// views read from the cache see [`SecretField::Kept`]. Never written to disk: writes
/// always start from the decrypted stored body.
pub(crate) const KEPT_SECRET_TAG: u64 = 0x6b65_7074; // "kept"

/// A typed view of one item kind.
pub trait ItemView: Sized {
    /// The kind of item this view reads.
    const KIND: ItemKind;

    /// Reads the view. Fails on the wrong kind, a missing required field or a field of
    /// the wrong type; never panics on untrusted bodies.
    fn from_body(body: &ItemBody) -> Result<Self, ViewError>;

    /// Writes only changed fields; never writes a default into a missing key; never
    /// touches keys it does not know.
    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>);

    /// A new body of [`ItemView::KIND`] at the current schema holding this view.
    fn to_new_body(&self, w: &mut FieldWriter<'_>) -> ItemBody {
        let mut body = ItemBody::new(Self::KIND, current_schema(Self::KIND));
        self.apply_to(&mut body, w);
        body
    }
}

/// Typed reads of an [`ItemBody`]'s fields. Missing and `null` read as `None` (or the
/// stated default); a wrong CBOR type is a [`ViewError::FieldType`].
#[derive(Debug, Clone, Copy)]
pub struct FieldReader<'a> {
    body: &'a ItemBody,
}

impl<'a> FieldReader<'a> {
    /// A reader for `body` after checking that it is of kind `expected`.
    pub fn for_kind(body: &'a ItemBody, expected: ItemKind) -> Result<Self, ViewError> {
        if body.kind != expected {
            return Err(ViewError::WrongKind {
                expected,
                found: body.kind,
            });
        }
        Ok(Self { body })
    }

    /// A reader for `body` of any kind.
    pub fn new(body: &'a ItemBody) -> Self {
        Self { body }
    }

    /// The raw value (`None` for missing or `null`).
    pub fn value(&self, key: &str) -> Option<&'a Value> {
        self.body.get(key)
    }

    fn map<T>(
        &self,
        key: &str,
        expected: &'static str,
        f: impl FnOnce(&'a Value) -> Option<T>,
    ) -> Result<Option<T>, ViewError> {
        match self.value(key) {
            None => Ok(None),
            Some(v) => f(v)
                .map(Some)
                .ok_or_else(|| ViewError::field_type(key, expected)),
        }
    }

    /// Optional text.
    pub fn opt_text(&self, key: &str) -> Result<Option<String>, ViewError> {
        self.map(key, "text", |v| v.as_text().map(str::to_owned))
    }

    /// Text with a default.
    pub fn text(&self, key: &str, default: &str) -> Result<String, ViewError> {
        Ok(self.opt_text(key)?.unwrap_or_else(|| default.to_owned()))
    }

    /// Required text.
    pub fn req_text(&self, key: &'static str) -> Result<String, ViewError> {
        self.opt_text(key)?.ok_or(ViewError::Missing(key))
    }

    /// A secret text field: `Value` when stored, `Absent` otherwise, `Kept` in a body
    /// from the T30 cache (secret values replaced by a crate-private CBOR tag).
    pub fn secret(&self, key: &str) -> Result<SecretField, ViewError> {
        if matches!(self.value(key), Some(Value::Tag(tag, _)) if *tag == KEPT_SECRET_TAG) {
            return Ok(SecretField::Kept);
        }
        let s = self.map(key, "text", |v| v.as_text().map(SecretString::from))?;
        Ok(SecretField::from_option(s))
    }

    /// An optional integer converted (and range-checked) into `T`.
    pub fn opt_int<T: TryFrom<i128>>(&self, key: &str) -> Result<Option<T>, ViewError> {
        self.map(key, "an integer in range", |v| {
            v.as_integer().and_then(|i| T::try_from(i128::from(i)).ok())
        })
    }

    /// An integer with a default.
    pub fn int<T: TryFrom<i128>>(&self, key: &str, default: T) -> Result<T, ViewError> {
        Ok(self.opt_int(key)?.unwrap_or(default))
    }

    /// A required integer.
    pub fn req_int<T: TryFrom<i128>>(&self, key: &'static str) -> Result<T, ViewError> {
        self.opt_int(key)?.ok_or(ViewError::Missing(key))
    }

    /// A timestamp; missing reads as `UnixMillis(0)`.
    pub fn millis(&self, key: &str) -> Result<UnixMillis, ViewError> {
        Ok(UnixMillis(self.int(key, 0_i64)?))
    }

    /// An optional float (integers are accepted too).
    pub fn opt_float(&self, key: &str) -> Result<Option<f64>, ViewError> {
        self.map(key, "a number", |v| match v {
            Value::Float(f) => Some(*f),
            #[allow(clippy::cast_precision_loss)]
            Value::Integer(i) => Some(i128::from(*i) as f64),
            _ => None,
        })
    }

    /// A bool with a default.
    pub fn bool(&self, key: &str, default: bool) -> Result<bool, ViewError> {
        Ok(self.map(key, "a bool", Value::as_bool)?.unwrap_or(default))
    }

    /// An optional id (16-byte byte string).
    pub fn opt_id(&self, key: &str) -> Result<Option<ItemId>, ViewError> {
        self.map(key, "an id", ItemId::from_value)
    }

    /// A required id.
    pub fn req_id(&self, key: &'static str) -> Result<ItemId, ViewError> {
        self.opt_id(key)?.ok_or(ViewError::Missing(key))
    }

    /// A list of ids; missing reads as empty.
    pub fn ids(&self, key: &str) -> Result<Vec<ItemId>, ViewError> {
        let ids = self.map(key, "a list of ids", |v| {
            v.as_array()?
                .iter()
                .map(ItemId::from_value)
                .collect::<Option<Vec<_>>>()
        })?;
        Ok(ids.unwrap_or_default())
    }

    /// An optional enum (unknown strings are a [`ViewError::FieldType`]).
    pub fn opt_enum<E: WireEnum>(&self, key: &str) -> Result<Option<E>, ViewError> {
        self.map(key, "a known enum string", |v| {
            v.as_text().and_then(E::from_wire)
        })
    }

    /// An enum with a default.
    pub fn enum_<E: WireEnum>(&self, key: &str, default: E) -> Result<E, ViewError> {
        Ok(self.opt_enum(key)?.unwrap_or(default))
    }

    /// A required enum.
    pub fn req_enum<E: WireEnum>(&self, key: &'static str) -> Result<E, ViewError> {
        self.opt_enum(key)?.ok_or(ViewError::Missing(key))
    }

    /// An optional byte string.
    pub fn opt_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, ViewError> {
        self.map(key, "bytes", |v| v.as_bytes().cloned())
    }

    /// A required byte string.
    pub fn req_bytes(&self, key: &'static str) -> Result<Vec<u8>, ViewError> {
        self.opt_bytes(key)?.ok_or(ViewError::Missing(key))
    }
}

/// Change-only writes for [`ItemView::apply_to`]. Every write goes through
/// [`ItemBody::set`], which skips values equal to the current one; a default (or
/// `None`) is not written to a key that reads as unset, so applying an unchanged view
/// creates no stamps. Each method returns whether it wrote anything.
pub struct FieldWriter<'a> {
    clock: &'a mut HlcClock,
    device: DeviceId,
}

impl fmt::Debug for FieldWriter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldWriter")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl<'a> FieldWriter<'a> {
    /// A writer stamping with `clock` as `device`.
    pub fn new(clock: &'a mut HlcClock, device: DeviceId) -> Self {
        Self { clock, device }
    }

    /// The writing device.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// Writes `value`, unless it is a default and the key currently reads as unset.
    pub fn put(&mut self, b: &mut ItemBody, key: &str, value: Value, is_default: bool) -> bool {
        if is_default && b.get(key).is_none() {
            return false;
        }
        b.set(key, value, self.clock, self.device)
    }

    /// Writes `null` if the key currently holds a value.
    pub fn clear(&mut self, b: &mut ItemBody, key: &str) -> bool {
        self.put(b, key, Value::Null, true)
    }

    fn opt(&mut self, b: &mut ItemBody, key: &str, value: Option<Value>) -> bool {
        match value {
            Some(v) => self.put(b, key, v, false),
            None => self.clear(b, key),
        }
    }

    /// Text with a default.
    pub fn text(&mut self, b: &mut ItemBody, key: &str, v: &str, default: &str) -> bool {
        self.put(b, key, Value::Text(v.to_owned()), v == default)
    }

    /// Optional text (`None` is `null`).
    pub fn opt_text(&mut self, b: &mut ItemBody, key: &str, v: Option<&str>) -> bool {
        self.opt(b, key, v.map(|s| Value::Text(s.to_owned())))
    }

    /// A secret: `Absent` clears, `Kept` writes nothing, `Value` writes when changed.
    pub fn secret(&mut self, b: &mut ItemBody, key: &str, v: &SecretField) -> bool {
        match v {
            SecretField::Absent => self.clear(b, key),
            SecretField::Kept => false,
            SecretField::Value(s) => {
                let text = s.expose_for_envelope().to_owned();
                self.put(b, key, Value::Text(text), false)
            }
        }
    }

    /// An unsigned integer with a default.
    pub fn uint(&mut self, b: &mut ItemBody, key: &str, v: u64, default: u64) -> bool {
        self.put(b, key, Value::from(v), v == default)
    }

    /// An optional unsigned integer.
    pub fn opt_uint(&mut self, b: &mut ItemBody, key: &str, v: Option<u64>) -> bool {
        self.opt(b, key, v.map(Value::from))
    }

    /// A signed integer with a default.
    pub fn int(&mut self, b: &mut ItemBody, key: &str, v: i64, default: i64) -> bool {
        self.put(b, key, Value::from(v), v == default)
    }

    /// A float with a default.
    pub fn float(&mut self, b: &mut ItemBody, key: &str, v: f64, default: f64) -> bool {
        #[allow(clippy::float_cmp)]
        let is_default = v == default;
        self.put(b, key, Value::Float(v), is_default)
    }

    /// A timestamp (always written; it has no meaningful default).
    pub fn millis(&mut self, b: &mut ItemBody, key: &str, v: UnixMillis) -> bool {
        self.put(b, key, Value::from(v), false)
    }

    /// A bool with a default.
    pub fn bool(&mut self, b: &mut ItemBody, key: &str, v: bool, default: bool) -> bool {
        self.put(b, key, Value::Bool(v), v == default)
    }

    /// A required id.
    pub fn id(&mut self, b: &mut ItemBody, key: &str, v: ItemId) -> bool {
        self.put(b, key, Value::from(v), false)
    }

    /// An optional id.
    pub fn opt_id(&mut self, b: &mut ItemBody, key: &str, v: Option<ItemId>) -> bool {
        self.opt(b, key, v.map(Value::from))
    }

    /// A list of ids (empty is the default). Lists are whole-value registers.
    pub fn ids(&mut self, b: &mut ItemBody, key: &str, v: &[ItemId]) -> bool {
        let value = Value::Array(v.iter().map(|id| Value::from(*id)).collect());
        self.put(b, key, value, v.is_empty())
    }

    /// An enum with a default.
    pub fn enum_<E: WireEnum + PartialEq>(
        &mut self,
        b: &mut ItemBody,
        key: &str,
        v: &E,
        default: &E,
    ) -> bool {
        self.put(b, key, Value::from(v.as_wire()), v == default)
    }

    /// An optional enum.
    pub fn opt_enum<E: WireEnum>(&mut self, b: &mut ItemBody, key: &str, v: Option<&E>) -> bool {
        self.opt(b, key, v.map(|e| Value::from(e.as_wire())))
    }

    /// A required text (always written).
    pub fn req_text(&mut self, b: &mut ItemBody, key: &str, v: &str) -> bool {
        self.put(b, key, Value::Text(v.to_owned()), false)
    }

    /// A required byte string (always written).
    pub fn bytes(&mut self, b: &mut ItemBody, key: &str, v: &[u8]) -> bool {
        self.put(b, key, Value::Bytes(v.to_vec()), false)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::item::{KnownHostItem, ManualClock};

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn clock() -> HlcClock {
        HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)))
    }

    #[test]
    fn secret_kept_writes_nothing() {
        let mut clock = clock();
        let mut w = FieldWriter::new(&mut clock, dev(1));
        let mut b = ItemBody::new(ItemKind::ProxyCredential, 1);
        assert!(w.secret(&mut b, "password", &SecretField::Value("CANARY-x".into())));
        let before = b.clone();
        assert!(!w.secret(&mut b, "password", &SecretField::Kept));
        assert_eq!(b, before);
        // Kept on a missing key writes nothing either.
        assert!(!w.secret(&mut b, "x.password", &SecretField::Kept));
        assert!(!b.contains("x.password"));
    }

    #[test]
    fn secret_absent_clears() {
        let mut clock = clock();
        let mut w = FieldWriter::new(&mut clock, dev(1));
        let mut b = ItemBody::new(ItemKind::ProxyCredential, 1);
        // Absent on a missing key: nothing to clear, no stamp.
        assert!(!w.secret(&mut b, "password", &SecretField::Absent));
        assert!(!b.contains("password"));
        w.secret(&mut b, "password", &SecretField::Value("pw".into()));
        assert!(w.secret(&mut b, "password", &SecretField::Absent));
        assert!(b.contains("password"));
        assert_eq!(b.get("password"), None);
        assert_eq!(
            FieldReader::new(&b).secret("password"),
            Ok(SecretField::Absent)
        );
        assert!(!w.secret(&mut b, "password", &SecretField::Absent));
    }

    #[test]
    fn secret_value_unchanged_no_stamp() {
        let mut clock = clock();
        let mut w = FieldWriter::new(&mut clock, dev(1));
        let mut b = ItemBody::new(ItemKind::ProxyCredential, 1);
        assert!(w.secret(&mut b, "password", &SecretField::Value("pw".into())));
        let before = b.clone();
        assert!(!w.secret(&mut b, "password", &SecretField::Value("pw".into())));
        assert_eq!(b, before);
        assert!(w.secret(&mut b, "password", &SecretField::Value("pw2".into())));
        let read = FieldReader::new(&b).secret("password");
        assert_eq!(read, Ok(SecretField::Value("pw2".into())));
        assert!(SecretField::Kept.is_set());
        assert!(!SecretField::Absent.is_set());
        assert_eq!(
            SecretField::Value("a".into()).without_value(),
            SecretField::Kept
        );
    }

    #[test]
    fn defaults_are_not_written_to_missing_keys() {
        let mut clock = clock();
        let mut w = FieldWriter::new(&mut clock, dev(1));
        let mut b = ItemBody::new(ItemKind::Site, 1);
        assert!(!w.text(&mut b, "name", "", ""));
        assert!(!w.bool(&mut b, "flag", false, false));
        assert!(!w.uint(&mut b, "port", 22, 22));
        assert!(!w.opt_text(&mut b, "comment", None));
        assert!(!w.ids(&mut b, "list", &[]));
        assert!(b.fields.is_empty());
        // A stored non-default value is overwritten by the default.
        assert!(w.uint(&mut b, "port", 2222, 22));
        assert!(w.uint(&mut b, "port", 22, 22));
        assert_eq!(FieldReader::new(&b).int::<u16>("port", 0), Ok(22));
    }

    #[test]
    fn reader_rejects_wrong_types() {
        let mut clock = clock();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        b.set("port", "twenty-one", &mut clock, dev(1));
        b.set("big", 70_000, &mut clock, dev(1));
        b.set("neg", -1, &mut clock, dev(1));
        let r = FieldReader::new(&b);
        assert!(matches!(
            r.opt_int::<u16>("port"),
            Err(ViewError::FieldType { .. })
        ));
        assert!(r.opt_int::<u16>("big").is_err());
        assert!(r.opt_int::<u64>("neg").is_err());
        assert_eq!(r.opt_int::<i64>("neg"), Ok(Some(-1)));
        assert_eq!(r.req_text("missing"), Err(ViewError::Missing("missing")));
        assert!(r.opt_id("port").is_err());
        assert!(matches!(
            FieldReader::for_kind(&b, ItemKind::Bookmark),
            Err(ViewError::WrongKind { .. })
        ));
    }

    #[test]
    fn unknown_keys_survive() -> Result<(), Box<dyn std::error::Error>> {
        let mut clock = clock();
        let future = Value::Map(vec![
            (Value::from("z"), Value::from(1)),
            (Value::from("a"), Value::Bytes(vec![1, 2, 3])),
        ]);
        let mut b = ItemBody::new(ItemKind::KnownHost, 1);
        {
            let mut w = FieldWriter::new(&mut clock, dev(1));
            let view = KnownHostItem::new("Example.COM", 22, "ssh-ed25519", "AAAA", UnixMillis(5));
            view.apply_to(&mut b, &mut w);
        }
        b.set("x.future", future.clone(), &mut clock, dev(9));
        let stored = b.get_stamped("x.future").cloned();
        let encode = |s: &Option<crate::model::item::Stamped<Value>>| -> Vec<u8> {
            let mut out = Vec::new();
            let _ = ciborium::into_writer(s, &mut out);
            out
        };

        let mut view = KnownHostItem::from_body(&b)?;
        view.comment = Some("laptop".into());
        let mut w = FieldWriter::new(&mut clock, dev(1));
        view.apply_to(&mut b, &mut w);
        let back = ItemBody::from_cbor(&b.to_cbor()?)?;
        assert_eq!(back.get("comment"), Some(&Value::from("laptop")));
        assert_eq!(
            encode(&back.get_stamped("x.future").cloned()),
            encode(&stored)
        );
        assert_eq!(back.get("x.future"), Some(&future));
        Ok(())
    }
}
