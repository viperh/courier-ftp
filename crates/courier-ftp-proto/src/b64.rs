//! Binary fields on the wire: base64url **without padding**.
//!
//! Use as `#[serde(with = "courier_ftp_proto::b64")]` on `Vec<u8>` fields and
//! `#[serde(with = "courier_ftp_proto::b64::option")]` (plus
//! `#[serde(default)]`) on `Option<Vec<u8>>`. Decoding is strict: padding,
//! the standard alphabet and non-canonical trailing bits are rejected. The
//! codec is `base64ct` (constant time), since some fields are key material.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Deserializer, Serializer};

/// A malformed base64url string.
pub use base64ct::Error as DecodeError;

/// Encodes bytes as base64url without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes base64url without padding.
///
/// # Errors
/// Invalid characters, padding, length or non-canonical trailing bits.
pub fn decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    Base64UrlUnpadded::decode_vec(s)
}

/// Serde `serialize_with`.
///
/// # Errors
/// Serializer errors.
pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(bytes))
}

/// Serde `deserialize_with`.
///
/// # Errors
/// Not a string, or not base64url without padding.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
    decode(&s).map_err(|_| serde::de::Error::custom("invalid base64url (unpadded expected)"))
}

/// The same for `Option<Vec<u8>>` (`null` or absent is `None`; combine with
/// `#[serde(default)]`).
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serde `serialize_with`.
    ///
    /// # Errors
    /// Serializer errors.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&super::encode(b)),
            None => s.serialize_none(),
        }
    }

    /// Serde `deserialize_with`.
    ///
    /// # Errors
    /// Not a string or null, or not base64url without padding.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<std::borrow::Cow<'de, str>>::deserialize(d)?
            .map(|s| {
                super::decode(&s)
                    .map_err(|_| serde::de::Error::custom("invalid base64url (unpadded expected)"))
            })
            .transpose()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn no_padding_url_alphabet() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert!(decode("-_8=").is_err());
        assert!(decode("+/8").is_err());
        // Non-canonical trailing bits ("-_9" decodes to the same bytes).
        assert!(decode("-_9").is_err());
    }

    #[test]
    fn round_trips_every_length() {
        for n in 0..70u8 {
            let bytes: Vec<u8> = (0..n).collect();
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
        }
    }
}
