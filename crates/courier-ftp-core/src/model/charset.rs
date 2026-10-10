//! Server [`Charset`].

use std::{borrow::Cow, fmt};

use encoding_rs::Encoding;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// The character set of file names on a server (Site Manager, Charset tab).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Charset {
    /// UTF-8 if the server announces it (`FEAT` lists `UTF8`), otherwise the
    /// server's raw bytes decoded leniently.
    #[default]
    Auto,
    /// Always UTF-8.
    Utf8,
    /// A fixed legacy encoding, e.g. `windows-1252` or `Shift_JIS`.
    Custom(&'static Encoding),
}

impl Charset {
    /// The serialised form: `auto`, `utf-8`, or the encoding's WHATWG name.
    pub fn label(&self) -> &'static str {
        match self {
            Charset::Auto => "auto",
            Charset::Utf8 => "utf-8",
            Charset::Custom(enc) => enc.name(),
        }
    }

    /// Parse a label: `auto`, `utf-8`/`utf8`, or any WHATWG encoding label
    /// (case-insensitive).
    pub fn from_label(label: &str) -> Result<Self> {
        let label = label.trim();
        if label.eq_ignore_ascii_case("auto") {
            return Ok(Charset::Auto);
        }
        if label.eq_ignore_ascii_case("utf8") {
            return Ok(Charset::Utf8);
        }
        match Encoding::for_label(label.as_bytes()) {
            Some(enc) if enc == encoding_rs::UTF_8 => Ok(Charset::Utf8),
            Some(enc) => Ok(Charset::Custom(enc)),
            None => Err(Error::InvalidInput(format!("unknown charset `{label}`"))),
        }
    }

    /// Decode bytes from the server (file names, listing lines). Never fails.
    ///
    /// - [`Auto`](Charset::Auto): UTF-8 when the bytes are valid UTF-8,
    ///   otherwise Windows-1252 (a superset of Latin-1, so every byte maps to a
    ///   character). Decode line by line so one Latin-1 name doesn't garble the
    ///   UTF-8 names around it.
    /// - [`Utf8`](Charset::Utf8): UTF-8, invalid sequences become U+FFFD.
    /// - [`Custom`](Charset::Custom): that encoding, malformed bytes become U+FFFD.
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Cow<'a, str> {
        match self {
            Charset::Auto => match std::str::from_utf8(bytes) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => {
                    encoding_rs::WINDOWS_1252
                        .decode_without_bom_handling(bytes)
                        .0
                }
            },
            Charset::Utf8 => String::from_utf8_lossy(bytes),
            Charset::Custom(enc) => enc.decode_without_bom_handling(bytes).0,
        }
    }
}

impl fmt::Display for Charset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl Serialize for Charset {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl<'de> Deserialize<'de> for Charset {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let label = String::deserialize(deserializer)?;
        Charset::from_label(&label).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn labels() {
        assert_eq!(Charset::from_label("auto").unwrap(), Charset::Auto);
        assert_eq!(Charset::from_label("UTF-8").unwrap(), Charset::Utf8);
        assert_eq!(Charset::from_label("utf8").unwrap(), Charset::Utf8);
        assert_eq!(
            Charset::from_label("latin1").unwrap(),
            Charset::Custom(encoding_rs::WINDOWS_1252)
        );
        assert_eq!(
            Charset::from_label("shift_jis").unwrap(),
            Charset::Custom(encoding_rs::SHIFT_JIS)
        );
        assert!(Charset::from_label("klingon").is_err());
    }

    #[test]
    fn decode_with_fallback() {
        assert_eq!(Charset::Auto.decode("grüße".as_bytes()), "grüße");
        // Latin-1 bytes are not UTF-8: Auto falls back to Windows-1252.
        assert_eq!(Charset::Auto.decode(b"gr\xfc\xdfe"), "grüße");
        assert_eq!(Charset::Utf8.decode(b"gr\xfc"), "gr\u{fffd}");
        let sjis = Charset::from_label("shift_jis").unwrap();
        assert_eq!(sjis.decode(b"\x83\x65\x83\x58\x83\x67"), "テスト");
        let cp1251 = Charset::from_label("windows-1251").unwrap();
        assert_eq!(cp1251.decode(b"\xf4\xe0\xe9\xeb"), "файл");
    }

    #[test]
    fn serde_by_label() {
        for cs in [
            Charset::Auto,
            Charset::Utf8,
            Charset::Custom(encoding_rs::WINDOWS_1251),
        ] {
            let json = serde_json::to_string(&cs).unwrap();
            assert_eq!(serde_json::from_str::<Charset>(&json).unwrap(), cs);
        }
        assert_eq!(
            serde_json::to_string(&Charset::Custom(encoding_rs::SHIFT_JIS)).unwrap(),
            "\"Shift_JIS\""
        );
    }
}
