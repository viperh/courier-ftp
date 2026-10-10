//! Typed reads and change-only writes of [`ItemBody`] fields, shared by the typed views.

use ciborium::Value;
use secrecy::{ExposeSecret, SecretString};

use super::body::ItemBody;
use super::hlc::HlcClock;
use super::ids::{DeviceId, ItemId};
use super::kinds::ItemKind;
use super::migrate::is_read_only;

/// Errors converting an [`ItemBody`] into a typed view.
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
    /// A field holds a CBOR value of the wrong type (or out of range).
    #[error("field `{field}` has the wrong type")]
    FieldTypeError {
        /// The (dotted) field name.
        field: String,
    },
    /// A required field is missing.
    #[error("required field `{field}` is missing")]
    MissingField {
        /// The (dotted) field name.
        field: String,
    },
}

/// A closed enum encoded as a stable lowercase string inside an item field.
pub trait WireEnum: Sized + Copy {
    /// The wire string.
    fn as_wire(&self) -> &'static str;
    /// Parses the wire string.
    fn from_wire(s: &str) -> Option<Self>;
}

/// Defines a fieldless enum with stable wire strings. The first variant is the default.
macro_rules! wire_enum {
    ($(#[$doc:meta])* $name:ident { $(#[$fdoc:meta])* $first:ident => $fwire:literal $(, $(#[$vdoc:meta])* $variant:ident => $wire:literal)* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub enum $name {
            $(#[$fdoc])*
            #[default]
            $first,
            $($(#[$vdoc])* $variant),*
        }

        impl $crate::model::item::fields::WireEnum for $name {
            fn as_wire(&self) -> &'static str {
                match self { Self::$first => $fwire, $(Self::$variant => $wire),* }
            }
            fn from_wire(s: &str) -> Option<Self> {
                match s { $fwire => Some(Self::$first), $($wire => Some(Self::$variant),)* _ => None }
            }
        }
    };
}
pub(crate) use wire_enum;

fn type_err(field: &str) -> ViewError {
    ViewError::FieldTypeError {
        field: field.to_owned(),
    }
}

fn missing(key: &str) -> ViewError {
    ViewError::MissingField {
        field: key.to_owned(),
    }
}

/// Checks the kind and returns the view's `read_only` flag.
pub(crate) fn check_kind(body: &ItemBody, expected: ItemKind) -> Result<bool, ViewError> {
    if body.kind != expected {
        return Err(ViewError::WrongKind {
            expected,
            found: body.kind,
        });
    }
    Ok(is_read_only(body))
}

/// Typed reads. Missing and `Null` mean `None`; a wrong CBOR type is a `FieldTypeError`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    body: &'a ItemBody,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(body: &'a ItemBody) -> Self {
        Self { body }
    }

    fn map<T>(
        &self,
        key: &str,
        f: impl FnOnce(&Value) -> Option<T>,
    ) -> Result<Option<T>, ViewError> {
        match self.body.get(key) {
            None => Ok(None),
            Some(v) => f(v).map(Some).ok_or_else(|| type_err(key)),
        }
    }

    pub(crate) fn opt_str(&self, key: &str) -> Result<Option<String>, ViewError> {
        self.map(key, |v| v.as_text().map(str::to_owned))
    }

    pub(crate) fn str(&self, key: &str) -> Result<String, ViewError> {
        Ok(self.opt_str(key)?.unwrap_or_default())
    }

    pub(crate) fn opt_secret(&self, key: &str) -> Result<Option<SecretString>, ViewError> {
        self.map(key, |v| {
            v.as_text().map(|s| SecretString::from(s.to_owned()))
        })
    }

    pub(crate) fn bytes(&self, key: &str) -> Result<Vec<u8>, ViewError> {
        Ok(self
            .map(key, |v| v.as_bytes().cloned())?
            .unwrap_or_default())
    }

    pub(crate) fn int<T: TryFrom<ciborium::value::Integer>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ViewError> {
        self.map(key, |v| v.as_integer().and_then(|i| T::try_from(i).ok()))
    }

    pub(crate) fn req_int<T: TryFrom<ciborium::value::Integer>>(
        &self,
        key: &str,
    ) -> Result<T, ViewError> {
        self.int(key)?.ok_or_else(|| missing(key))
    }

    pub(crate) fn bool(&self, key: &str) -> Result<bool, ViewError> {
        Ok(self.map(key, Value::as_bool)?.unwrap_or(false))
    }

    pub(crate) fn opt_id(&self, key: &str) -> Result<Option<ItemId>, ViewError> {
        self.map(key, ItemId::from_value)
    }

    pub(crate) fn req_id(&self, key: &str) -> Result<ItemId, ViewError> {
        self.opt_id(key)?.ok_or_else(|| missing(key))
    }

    pub(crate) fn opt_enum<E: WireEnum>(&self, key: &str) -> Result<Option<E>, ViewError> {
        self.map(key, |v| v.as_text().and_then(E::from_wire))
    }

    pub(crate) fn req_enum<E: WireEnum>(&self, key: &str) -> Result<E, ViewError> {
        self.opt_enum(key)?.ok_or_else(|| missing(key))
    }

    /// An enum whose absence means its `Default` variant.
    pub(crate) fn enum_or_default<E: WireEnum + Default>(&self, key: &str) -> Result<E, ViewError> {
        Ok(self.opt_enum(key)?.unwrap_or_default())
    }
}

/// Change-only writes: every write goes through [`ItemBody::set`], which skips values
/// equal to the current one. A `Null` (or a type's default) is not written to a key
/// that doesn't exist yet, so applying an unchanged view creates no stamps.
#[derive(Debug)]
pub(crate) struct Writer<'a> {
    body: &'a mut ItemBody,
    clock: &'a mut HlcClock,
    device: DeviceId,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(body: &'a mut ItemBody, clock: &'a mut HlcClock, device: DeviceId) -> Self {
        Self {
            body,
            clock,
            device,
        }
    }

    /// Writes `value`, unless it is a default (`is_default`) and the key is absent.
    pub(crate) fn value(&mut self, key: &str, value: impl Into<Value>, is_default: bool) {
        if is_default && !self.body.contains(key) {
            return;
        }
        self.body.set(key, value.into(), self.clock, self.device);
    }

    /// An optional value: `None` is `Null`.
    pub(crate) fn opt<T: Into<Value>>(&mut self, key: &str, value: Option<T>) {
        match value {
            Some(v) => self.value(key, v.into(), false),
            None => self.value(key, Value::Null, true),
        }
    }

    /// A required string: `""` is the default.
    pub(crate) fn text(&mut self, key: &str, value: &str) {
        self.value(key, Value::Text(value.to_owned()), value.is_empty());
    }

    /// A required value with no meaningful default (always written).
    pub(crate) fn always(&mut self, key: &str, value: impl Into<Value>) {
        self.value(key, value.into(), false);
    }

    /// A plain bool: `false` is the default.
    pub(crate) fn flag(&mut self, key: &str, value: bool) {
        self.value(key, Value::Bool(value), !value);
    }

    pub(crate) fn opt_secret(&mut self, key: &str, value: Option<&SecretString>) {
        self.opt(key, value.map(|s| s.expose_secret().to_owned()));
    }

    pub(crate) fn bytes(&mut self, key: &str, value: &[u8]) {
        self.value(key, Value::Bytes(value.to_vec()), value.is_empty());
    }

    pub(crate) fn opt_enum<E: WireEnum>(&mut self, key: &str, value: Option<E>) {
        self.opt(key, value.map(|e| e.as_wire()));
    }

    /// An enum whose `Default` variant is not written to an absent key.
    pub(crate) fn enum_or_default<E: WireEnum + Default + PartialEq>(
        &mut self,
        key: &str,
        value: E,
    ) {
        let is_default = value == E::default();
        self.value(key, value.as_wire(), is_default);
    }
}
