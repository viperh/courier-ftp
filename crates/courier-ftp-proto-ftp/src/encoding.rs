//! The session's charset decision (RFC 2640 + the site [`Charset`], T10 §4).
//!
//! | Site charset | Server FEAT has `UTF8` | Session encoding |
//! |---|---|---|
//! | `Utf8` | any | UTF-8 (invalid bytes → U+FFFD, a `Debug(1)` warning) |
//! | `Custom(enc)` | any | `enc` both directions |
//! | `Auto` | yes | UTF-8 ([`SessionEncoding::confirm_utf8`]) |
//! | `Auto` | no | UTF-8 tentatively; the first line that is not valid UTF-8 switches the session to windows-1252 for both directions, for good |
//!
//! The reply parser ([`ReplyParser`](crate::reply::ReplyParser)) and the session share
//! the switch: a [`LineDecoder`] obtained from [`SessionEncoding::line_decoder`] flips the
//! same flag, so replies, listings (T13/T14) and commands always agree.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use courier_ftp_core::{Error, Result, listing::TextDecoder, model::Charset};
use encoding_rs::Encoding;

/// `Auto`: UTF-8 is assumed but not confirmed.
const TENTATIVE: u8 = 0;
/// `Auto`: the server advertised `UTF8` (FEAT).
const CONFIRMED_UTF8: u8 = 1;
/// `Auto`: a line was not valid UTF-8; windows-1252 from now on.
const SWITCHED: u8 = 2;

/// The fallback of the `Auto` charset (the WHATWG mapping for "ISO-8859-1").
pub const FALLBACK: &Encoding = encoding_rs::WINDOWS_1252;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Utf8,
    Auto,
    Fixed(&'static Encoding),
}

/// Something worth a log line that happened while decoding a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeNote {
    /// `Auto`: this line switched the session to windows-1252.
    SwitchedToFallback,
    /// UTF-8 session: the line had invalid bytes (replaced with U+FFFD).
    InvalidUtf8,
}

impl DecodeNote {
    /// The message-log text of this note.
    pub fn message(self) -> &'static str {
        match self {
            Self::SwitchedToFallback => "Server does not use UTF-8, switching to windows-1252",
            Self::InvalidUtf8 => {
                "Warning: invalid UTF-8 in server text, replaced with U+FFFD characters"
            }
        }
    }
}

/// Line decoding (bytes → text) with the session's charset rules; reuses T13's
/// [`TextDecoder`]. Clones share the `Auto` switch with the [`SessionEncoding`] they came
/// from.
#[derive(Debug, Clone)]
pub struct LineDecoder {
    mode: Mode,
    state: Arc<AtomicU8>,
}

impl LineDecoder {
    /// A decoder for `charset` with its own (unshared) state.
    pub fn new(charset: Charset) -> Self {
        let mode = match charset {
            Charset::Auto => Mode::Auto,
            Charset::Utf8 => Mode::Utf8,
            Charset::Custom(e) => Mode::Fixed(e),
        };
        Self {
            mode,
            state: Arc::new(AtomicU8::new(TENTATIVE)),
        }
    }

    /// Decodes one line (without its line terminator). May switch an `Auto` session to
    /// windows-1252 (then the note says so).
    pub fn decode(&self, bytes: &[u8]) -> (String, Option<DecodeNote>) {
        match self.mode {
            Mode::Fixed(e) => (TextDecoder::Fixed(e).decode(bytes).0, None),
            Mode::Utf8 => decode_utf8(bytes),
            Mode::Auto => match self.state.load(Ordering::Acquire) {
                CONFIRMED_UTF8 => decode_utf8(bytes),
                SWITCHED => (TextDecoder::Fixed(FALLBACK).decode(bytes).0, None),
                _ => match std::str::from_utf8(bytes) {
                    Ok(s) => (s.to_owned(), None),
                    Err(_) => {
                        let won = self
                            .state
                            .compare_exchange(
                                TENTATIVE,
                                SWITCHED,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok();
                        let text = TextDecoder::Fixed(FALLBACK).decode(bytes).0;
                        if won {
                            (text, Some(DecodeNote::SwitchedToFallback))
                        } else if self.state.load(Ordering::Acquire) == CONFIRMED_UTF8 {
                            decode_utf8(bytes)
                        } else {
                            (text, None)
                        }
                    }
                },
            },
        }
    }

    /// The T13 listing decoder matching the current state.
    pub fn text_decoder(&self) -> TextDecoder {
        match self.mode {
            Mode::Fixed(e) => TextDecoder::Fixed(e),
            Mode::Utf8 => TextDecoder::Utf8,
            Mode::Auto => match self.state.load(Ordering::Acquire) {
                CONFIRMED_UTF8 => TextDecoder::Utf8,
                SWITCHED => TextDecoder::Fixed(FALLBACK),
                _ => TextDecoder::Utf8OrFallback(FALLBACK),
            },
        }
    }

    /// The encoding currently used for both directions.
    fn encoding(&self) -> &'static Encoding {
        match self.mode {
            Mode::Fixed(e) => e,
            Mode::Utf8 => encoding_rs::UTF_8,
            Mode::Auto => {
                if self.state.load(Ordering::Acquire) == SWITCHED {
                    FALLBACK
                } else {
                    encoding_rs::UTF_8
                }
            }
        }
    }
}

fn decode_utf8(bytes: &[u8]) -> (String, Option<DecodeNote>) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_owned(), None),
        Err(_) => (
            String::from_utf8_lossy(bytes).into_owned(),
            Some(DecodeNote::InvalidUtf8),
        ),
    }
}

/// The session's charset decision (RFC 2640 + [`Charset`] from T02).
#[derive(Debug, Clone)]
pub struct SessionEncoding {
    charset: Charset,
    decoder: LineDecoder,
}

impl SessionEncoding {
    /// The starting point for a site charset (before FEAT).
    pub fn new(charset: Charset) -> Self {
        Self {
            charset,
            decoder: LineDecoder::new(charset),
        }
    }

    /// The site charset this session started from.
    pub fn charset(&self) -> Charset {
        self.charset
    }

    /// Decodes one line; may switch `Auto` → windows-1252 (see the module docs).
    pub fn decode_line(&mut self, bytes: &[u8]) -> String {
        self.decoder.decode(bytes).0
    }

    /// As [`decode_line`](Self::decode_line), also returning what happened.
    pub fn decode_line_noted(&mut self, bytes: &[u8]) -> (String, Option<DecodeNote>) {
        self.decoder.decode(bytes)
    }

    /// Encodes text for the server.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when the text has characters the session encoding cannot represent
    /// (never substituted: a `?` could address a different file).
    pub fn encode(&self, s: &str) -> Result<Vec<u8>> {
        let enc = self.decoder.encoding();
        if enc == encoding_rs::UTF_8 {
            return Ok(s.as_bytes().to_vec());
        }
        let (bytes, _, had_errors) = enc.encode(s);
        if had_errors {
            return Err(Error::InvalidInput(format!(
                "text contains characters that {} cannot represent",
                enc.name()
            )));
        }
        Ok(bytes.into_owned())
    }

    /// The name of the encoding currently used (`"UTF-8"`, `"windows-1252"`, …).
    pub fn name(&self) -> &'static str {
        self.decoder.encoding().name()
    }

    /// `Auto` session whose server advertised `UTF8`: UTF-8 for good (no fallback).
    /// No effect for other charsets or after a switch.
    pub fn confirm_utf8(&self) {
        if self.decoder.mode == Mode::Auto {
            let _ = self.decoder.state.compare_exchange(
                TENTATIVE,
                CONFIRMED_UTF8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    /// `Auto` session that switched to windows-1252.
    pub fn is_switched(&self) -> bool {
        self.decoder.mode == Mode::Auto && self.decoder.state.load(Ordering::Acquire) == SWITCHED
    }

    /// Whether `OPTS UTF8 ON` may be sent (`Auto` and `Utf8`, never a custom charset).
    pub fn wants_utf8(&self) -> bool {
        !matches!(self.charset, Charset::Custom(_))
    }

    /// A decoder sharing this session's `Auto` switch (for the reply parser).
    pub fn line_decoder(&self) -> LineDecoder {
        self.decoder.clone()
    }

    /// The T13 listing decoder for the current state (T14 configures listings with it).
    pub fn text_decoder(&self) -> TextDecoder {
        self.decoder.text_decoder()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_auto_switches_to_windows1252_on_invalid_utf8() {
        let mut enc = SessionEncoding::new(Charset::Auto);
        let parser_side = enc.line_decoder();
        assert_eq!(enc.decode_line("grüße".as_bytes()), "grüße");
        assert_eq!(enc.name(), "UTF-8");
        assert_eq!(
            parser_side.decode(b"gr\xfc\xdfe"),
            ("grüße".to_owned(), Some(DecodeNote::SwitchedToFallback))
        );
        // Shared: the session switched too, and never switches back.
        assert!(enc.is_switched());
        assert_eq!(enc.name(), "windows-1252");
        assert_eq!(enc.decode_line("ü".as_bytes()), "Ã¼");
        assert_eq!(parser_side.decode(b"\xfc"), ("ü".to_owned(), None));
        assert_eq!(enc.encode("ü").ok(), Some(vec![0xfc]));
        enc.confirm_utf8();
        assert!(enc.is_switched());
    }

    #[test]
    fn encoding_auto_confirmed_utf8_never_switches() {
        let enc = SessionEncoding::new(Charset::Auto);
        enc.confirm_utf8();
        let d = enc.line_decoder();
        assert_eq!(
            d.decode(b"a\xfcb"),
            ("a\u{fffd}b".to_owned(), Some(DecodeNote::InvalidUtf8))
        );
        assert!(!enc.is_switched());
        assert_eq!(enc.encode("ü").ok(), Some("ü".as_bytes().to_vec()));
    }

    #[test]
    fn encoding_custom_unmappable_is_invalid_input() {
        let enc = SessionEncoding::new(Charset::Custom(encoding_rs::WINDOWS_1252));
        assert!(!enc.wants_utf8());
        assert_eq!(enc.encode("ÿ").ok(), Some(vec![0xff]));
        assert!(matches!(enc.encode("日本"), Err(Error::InvalidInput(_))));
        let sjis = SessionEncoding::new(Charset::Custom(encoding_rs::SHIFT_JIS));
        assert!(sjis.encode("日本").is_ok());
        assert!(matches!(sjis.encode("€"), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn encoding_utf8_reports_invalid_bytes() {
        let mut enc = SessionEncoding::new(Charset::Utf8);
        assert_eq!(
            enc.decode_line_noted(b"\xff"),
            ("\u{fffd}".to_owned(), Some(DecodeNote::InvalidUtf8))
        );
        assert!(!enc.is_switched());
        assert!(matches!(enc.text_decoder(), TextDecoder::Utf8));
    }
}
