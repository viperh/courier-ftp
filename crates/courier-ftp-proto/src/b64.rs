//! Binary fields on the wire: base64url **without padding** (RFC 4648 §5).
//!
//! Use as `#[serde(with = "crate::b64")]` on `Vec<u8>` fields and
//! `#[serde(with = "crate::b64::option")]` on `Option<Vec<u8>>`. Decoding is strict:
//! `=` padding, the standard alphabet (`+`, `/`) and non-zero trailing bits are
//! rejected.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serializer};

/// Encodes bytes as base64url without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding.
///
/// # Errors
/// Invalid characters (including `+`, `/`), padding, length or trailing bits.
pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
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
    decode(&s).map_err(serde::de::Error::custom)
}

/// The same for `Option<Vec<u8>>` (`null` or absent ↔ `None`; combine with
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`).
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serde `serialize_with`.
    ///
    /// # Errors
    /// Serializer errors.
    #[allow(clippy::ref_option)] // the signature serde's `with` requires
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
            .map(|s| super::decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn no_padding_url_alphabet() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(decode("-_8=").is_err());
        assert!(decode("+/8").is_err());
        // Non-canonical trailing bits.
        assert!(decode("-_9").is_err());
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[derive(Debug, PartialEq, Serialize, serde::Deserialize)]
    struct Opt {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "option")]
        v: Option<Vec<u8>>,
    }

    #[test]
    fn option_null_absent_and_value() {
        let some = Opt {
            v: Some(vec![0xfb, 0xff]),
        };
        assert_eq!(serde_json::to_string(&some).unwrap(), r#"{"v":"-_8"}"#);
        assert_eq!(serde_json::from_str::<Opt>(r#"{"v":"-_8"}"#).unwrap(), some);
        let none = Opt { v: None };
        assert_eq!(serde_json::to_string(&none).unwrap(), "{}");
        assert_eq!(serde_json::from_str::<Opt>("{}").unwrap(), none);
        assert_eq!(serde_json::from_str::<Opt>(r#"{"v":null}"#).unwrap(), none);
        assert!(serde_json::from_str::<Opt>(r#"{"v":"-_8="}"#).is_err());
    }
}
