//! Identifiers of the vault item model (T81, copied from sverb `model/ids.rs`, D13):
//! UUIDv7 newtypes that sort by creation time, and [`UnixMillis`].
//!
//! In CBOR (and every other non-human-readable serde format) an id is 16 raw bytes. In
//! JSON, the UI and `Display` it is the canonical hyphenated string. Inside an
//! [`ItemBody`](super::item::ItemBody) field value an id is a CBOR byte string of
//! length 16.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Source of new UUIDs, so tests can generate ids deterministically.
pub trait IdGen {
    /// Returns a fresh UUID. Implementations used in production return UUIDv7.
    fn next_uuid(&mut self) -> Uuid;
}

/// The production generator: [`Uuid::now_v7`] (monotonic within the process).
#[derive(Debug, Default, Clone, Copy)]
pub struct V7Gen;

impl IdGen for V7Gen {
    fn next_uuid(&mut self) -> Uuid {
        Uuid::now_v7()
    }
}

/// Deterministic generator for tests: UUIDv7-shaped ids with a fixed timestamp and an
/// increasing counter, so they still sort in generation order.
#[derive(Debug, Clone)]
pub struct SeqGen {
    millis: u64,
    counter: u64,
}

impl SeqGen {
    /// Starts at counter 0 with the given Unix timestamp in milliseconds.
    pub fn new(millis: u64) -> Self {
        Self { millis, counter: 0 }
    }
}

impl IdGen for SeqGen {
    fn next_uuid(&mut self) -> Uuid {
        self.counter += 1;
        // Layout (RFC 9562): 48-bit Unix millis, version 7, then the counter in the
        // low 64 bits (big-endian, so ids sort by it) with the 10xx variant.
        let mut bytes = [0_u8; 16];
        bytes[0..6].copy_from_slice(&self.millis.to_be_bytes()[2..8]);
        bytes[6] = 0x70;
        bytes[8..16].copy_from_slice(&self.counter.to_be_bytes());
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }
}

/// Error parsing an id from a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid id")]
pub struct IdParseError;

macro_rules! define_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A new UUIDv7 id from the system clock.
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// A new id from an injectable generator.
            pub fn generate(id_gen: &mut impl IdGen) -> Self {
                Self(id_gen.next_uuid())
            }

            /// Wraps an existing UUID.
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Builds an id from its 16 raw bytes.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            /// The underlying UUID.
            pub const fn uuid(&self) -> Uuid {
                self.0
            }

            /// The 16 raw bytes (the form `courier-ftp-crypto` binds as AAD, `Id16`).
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// First 8 hex characters, for compact display and logs.
            pub fn short(&self) -> String {
                let mut s = self.0.simple().to_string();
                s.truncate(8);
                s
            }

            /// Reads an id stored inside an item field (16-byte CBOR byte string).
            pub fn from_value(value: &Value) -> Option<Self> {
                let bytes: [u8; 16] = value.as_bytes()?.as_slice().try_into().ok()?;
                Some(Self::from_bytes(bytes))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0.hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::try_parse(s).map(Self).map_err(|_| IdParseError)
            }
        }

        impl From<$name> for Value {
            fn from(id: $name) -> Self {
                Value::Bytes(id.as_bytes().to_vec())
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }
    };
}

define_id!(
    /// Identifies a vault item (site, folder, bookmark, …) across all devices.
    ItemId
);
define_id!(
    /// Identifies a vault (personal or team).
    VaultId
);
define_id!(
    /// Identifies a device. Breaks HLC ties in [`Stamped`](super::item::Stamped) ordering.
    DeviceId
);
define_id!(
    /// Identifies a user account.
    UserId
);
define_id!(
    /// Identifies an organization (team vaults, T89).
    OrgId
);

/// Unix time in milliseconds, UTC. A CBOR integer inside item fields.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct UnixMillis(pub i64);

impl UnixMillis {
    /// The current system time (0 if the clock is before 1970).
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Self(ms)
    }
}

impl From<UnixMillis> for Value {
    fn from(t: UnixMillis) -> Self {
        Value::from(t.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_is_16_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let id = DeviceId::from_bytes([1; 16]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&id, &mut cbor)?;
        // 0x50 = byte string of length 16.
        assert_eq!(cbor.len(), 17);
        assert_eq!(cbor[0], 0x50);
        let back: DeviceId = ciborium::from_reader(cbor.as_slice())?;
        assert_eq!(back, id);
        let item = ItemId::from_uuid(id.uuid());
        assert_eq!(ItemId::from_value(&Value::from(item)), Some(item));
        assert_eq!(ItemId::from_value(&Value::Bytes(vec![1; 15])), None);
        Ok(())
    }

    #[test]
    fn json_is_hyphenated() -> Result<(), Box<dyn std::error::Error>> {
        let id = ItemId::from_bytes([0xab; 16]);
        let json = serde_json::to_string(&id)?;
        assert_eq!(json, "\"abababab-abab-abab-abab-abababababab\"");
        assert_eq!(serde_json::from_str::<ItemId>(&json)?, id);
        assert_eq!(id.to_string(), "abababab-abab-abab-abab-abababababab");
        assert_eq!(id.short(), "abababab");
        assert_eq!(id.to_string().parse::<ItemId>(), Ok(id));
        assert!("nope".parse::<ItemId>().is_err());
        Ok(())
    }

    #[test]
    fn seqgen_sorts() {
        let mut g = SeqGen::new(1_700_000_000_000);
        let ids: Vec<ItemId> = (0..1000).map(|_| ItemId::generate(&mut g)).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert!(ids.iter().all(|id| id.uuid().get_version_num() == 7));

        let ids: Vec<ItemId> = (0..1000).map(|_| ItemId::generate(&mut V7Gen)).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn unix_millis_is_an_integer() -> Result<(), Box<dyn std::error::Error>> {
        let t = UnixMillis(1_700_000_000_123);
        let mut cbor = Vec::new();
        ciborium::into_writer(&t, &mut cbor)?;
        let v: Value = ciborium::from_reader(cbor.as_slice())?;
        assert_eq!(v, Value::from(t));
        assert!(UnixMillis::now().0 > 0);
        Ok(())
    }
}
