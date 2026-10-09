//! Filename and command encoding per server ([`Charset`]).

use std::borrow::Cow;
use std::fmt;

use encoding_rs::Encoding;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// Filename/command encoding per server (§1, Site Manager Charset tab).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Charset {
    /// UTF-8 if valid, else Windows-1252 per line (T10 switches to Utf8 on FEAT UTF8).
    #[default]
    Auto,
    /// Always UTF-8.
    Utf8,
    /// Any ASCII-compatible encoding_rs encoding (not UTF-16, not "replacement").
    Custom(&'static Encoding),
}

impl Charset {
    /// Parses "auto", "utf-8" or any encoding_rs label ("windows-1252", "shift_jis", …),
    /// case-insensitively.
    ///
    /// Errors: `InvalidInput` for unknown labels or non-ASCII-compatible encodings.
    pub fn from_label(label: &str) -> Result<Self> {
        let trimmed = label.trim();
        if trimmed.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let Some(enc) = Encoding::for_label(trimmed.as_bytes()) else {
            return Err(Error::InvalidInput(format!(
                "unknown charset \"{}\"",
                label.escape_debug()
            )));
        };
        if enc == encoding_rs::UTF_8 {
            return Ok(Self::Utf8);
        }
        if !enc.is_ascii_compatible() || enc == encoding_rs::REPLACEMENT {
            return Err(Error::InvalidInput(format!(
                "charset \"{}\" is not ASCII-compatible",
                enc.name()
            )));
        }
        Ok(Self::Custom(enc))
    }

    /// The label: "auto", "utf-8", or the encoding_rs name ("windows-1252", "Shift_JIS").
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Utf8 => "utf-8",
            Self::Custom(e) => e.name(),
        }
    }

    /// Decodes server bytes (lossy: invalid sequences become U+FFFD). `Auto` uses UTF-8
    /// when the bytes are valid UTF-8, otherwise Windows-1252.
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Cow<'a, str> {
        match self {
            Self::Auto => match std::str::from_utf8(bytes) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => {
                    encoding_rs::WINDOWS_1252
                        .decode_without_bom_handling(bytes)
                        .0
                }
            },
            Self::Utf8 => String::from_utf8_lossy(bytes),
            Self::Custom(e) => e.decode_without_bom_handling(bytes).0,
        }
    }

    /// Encodes text for the server (`Auto` and `Utf8` = UTF-8).
    ///
    /// Errors: `InvalidInput` if `text` has characters the encoding cannot represent
    /// (never HTML entities).
    pub fn encode<'a>(&self, text: &'a str) -> Result<Cow<'a, [u8]>> {
        match self {
            Self::Auto | Self::Utf8 => Ok(Cow::Borrowed(text.as_bytes())),
            Self::Custom(e) => {
                let (bytes, _, had_errors) = e.encode(text);
                if had_errors {
                    return Err(Error::InvalidInput(format!(
                        "text contains characters that {} cannot represent",
                        e.name()
                    )));
                }
                Ok(bytes)
            }
        }
    }
}

impl fmt::Display for Charset {
    /// The label.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl Serialize for Charset {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.label())
    }
}

impl<'de> Deserialize<'de> for Charset {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let label = String::deserialize(d)?;
        Self::from_label(&label).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charset_auto_falls_back_to_windows_1252() {
        assert_eq!(Charset::Auto.decode("grüße".as_bytes()), "grüße");
        assert!(matches!(Charset::Auto.decode(b"abc"), Cow::Borrowed("abc")));
        // 0xFC = 'ü', 0x80 = '€' in Windows-1252.
        assert_eq!(Charset::Auto.decode(b"gr\xfc\x80e"), "grü€e");
        assert_eq!(Charset::Utf8.decode(b"a\xffb"), "a\u{fffd}b");
        assert_eq!(
            Charset::Auto.encode("ü").ok().as_deref(),
            Some("ü".as_bytes())
        );
    }

    #[test]
    fn charset_custom_encode_unmappable_fails() {
        let cs = Charset::from_label("windows-1252").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cs.encode("grü€").ok().as_deref(), Some(&b"gr\xfc\x80"[..]));
        assert!(matches!(cs.encode("日本"), Err(Error::InvalidInput(_))));
        assert_eq!(cs.decode(b"\xfc"), "ü");
        let sjis = Charset::from_label("Shift_JIS").unwrap_or_else(|e| panic!("{e}"));
        let bytes = sjis.encode("日本").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sjis.decode(&bytes), "日本");
    }

    #[test]
    fn charset_rejects_utf16_label() {
        for bad in [
            "utf-16",
            "UTF-16LE",
            "utf-16be",
            "replacement",
            "iso-2022-kr",
            "iso-2022-jp",
            "no-such",
            "",
        ] {
            assert!(
                matches!(Charset::from_label(bad), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
        assert_eq!(Charset::from_label("AUTO").ok(), Some(Charset::Auto));
        assert_eq!(Charset::from_label("utf8").ok(), Some(Charset::Utf8));
        assert_eq!(Charset::from_label("UTF-8").ok(), Some(Charset::Utf8));
        assert_eq!(
            Charset::from_label("iso-8859-1").ok(),
            Some(Charset::Custom(encoding_rs::WINDOWS_1252))
        );
    }

    #[test]
    fn charset_serde_label_roundtrip() {
        for cs in [
            Charset::Auto,
            Charset::Utf8,
            Charset::Custom(encoding_rs::WINDOWS_1252),
            Charset::Custom(encoding_rs::SHIFT_JIS),
            Charset::Custom(encoding_rs::KOI8_R),
        ] {
            let json = serde_json::to_string(&cs).unwrap_or_default();
            assert_eq!(json, format!("\"{}\"", cs.label()));
            assert_eq!(
                serde_json::from_str::<Charset>(&json).ok(),
                Some(cs),
                "{json}"
            );
        }
        assert_eq!(
            serde_json::to_string(&Charset::Auto).ok().as_deref(),
            Some("\"auto\"")
        );
        assert!(serde_json::from_str::<Charset>("\"utf-16\"").is_err());
        assert_eq!(Charset::default(), Charset::Auto);
        assert_eq!(Charset::Utf8.to_string(), "utf-8");
    }
}
