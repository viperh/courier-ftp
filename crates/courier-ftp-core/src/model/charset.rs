//! Server [`Charset`].

use std::fmt;

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
