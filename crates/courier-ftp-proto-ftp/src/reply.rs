//! FTP replies (RFC 959 §4.2): [`ReplyCode`], [`Reply`] and the incremental, bounded
//! [`ReplyParser`] (T10 §1).
//!
//! ```text
//! reply        = single-line / multi-line
//! single-line  = code SP text CRLF  /  code CRLF
//! multi-line   = code "-" text CRLF *( line CRLF ) code SP text CRLF   ; same code
//! code         = %x31-35 2DIGIT
//! ```
//!
//! The parser is pure (no I/O): it strips Telnet commands (RFC 854), splits lines on LF
//! (a CR before it is dropped), decodes them with the session's [`LineDecoder`], replaces
//! control characters with U+FFFD and enforces the limits [`MAX_LINE_BYTES`],
//! [`MAX_REPLY_LINES`] and [`MAX_REPLY_BYTES`]. [`fuzz_reply_parser`] is its fuzz body.

use std::fmt;

use courier_ftp_core::{Error, Result, model::Charset};

use crate::encoding::{DecodeNote, LineDecoder};

/// Longest accepted reply line in bytes (without the terminator).
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Most lines in one reply.
pub const MAX_REPLY_LINES: usize = 10_000;
/// Largest reply in bytes (all lines).
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// A three-digit FTP reply code (RFC 959 §4.2). Always 100..=599 with first digit 1–5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplyCode(u16);

impl ReplyCode {
    /// `Some` for 100..=599.
    pub fn new(code: u16) -> Option<Self> {
        (100..=599).contains(&code).then_some(Self(code))
    }

    /// For constants inside the crate (the value must be valid).
    pub(crate) const fn from_const(code: u16) -> Self {
        Self(code)
    }

    /// The numeric code.
    pub fn get(self) -> u16 {
        self.0
    }

    /// The first digit's meaning.
    pub fn class(self) -> ReplyClass {
        match self.0 / 100 {
            1 => ReplyClass::Preliminary,
            2 => ReplyClass::Completion,
            3 => ReplyClass::Intermediate,
            4 => ReplyClass::TransientNegative,
            _ => ReplyClass::PermanentNegative,
        }
    }

    /// Parses the code at the start of `line` (three ASCII digits, first 1–5).
    fn parse_prefix(line: &str) -> Option<Self> {
        let b = line.as_bytes();
        if b.len() < 3 || !(b'1'..=b'5').contains(&b[0]) {
            return None;
        }
        if !b[1].is_ascii_digit() || !b[2].is_ascii_digit() {
            return None;
        }
        let code =
            u16::from(b[0] - b'0') * 100 + u16::from(b[1] - b'0') * 10 + u16::from(b[2] - b'0');
        Some(Self(code))
    }
}

impl fmt::Display for ReplyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// First digit of a reply code (RFC 959 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplyClass {
    /// 1yz: positive preliminary.
    Preliminary,
    /// 2yz: positive completion.
    Completion,
    /// 3yz: positive intermediate.
    Intermediate,
    /// 4yz: transient negative completion.
    TransientNegative,
    /// 5yz: permanent negative completion.
    PermanentNegative,
}

/// One complete (single- or multi-line) reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The reply code.
    pub code: ReplyCode,
    /// Every line exactly as received (decoded, CR/LF stripped, control chars replaced
    /// with U+FFFD), including the `NNN-`/`NNN ` prefixes. Used for the message log.
    pub lines: Vec<String>,
}

impl Reply {
    /// A reply from its code and raw lines (tests, fake servers).
    pub fn new(code: ReplyCode, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// The numeric code.
    pub fn code(&self) -> u16 {
        self.code.get()
    }

    /// The first digit's meaning.
    pub fn class(&self) -> ReplyClass {
        self.code.class()
    }

    /// 1xx.
    pub fn is_preliminary(&self) -> bool {
        self.class() == ReplyClass::Preliminary
    }

    /// 2xx.
    pub fn is_ok(&self) -> bool {
        self.class() == ReplyClass::Completion
    }

    /// 3xx.
    pub fn is_intermediate(&self) -> bool {
        self.class() == ReplyClass::Intermediate
    }

    /// 4xx.
    pub fn is_transient_err(&self) -> bool {
        self.class() == ReplyClass::TransientNegative
    }

    /// 5xx.
    pub fn is_permanent_err(&self) -> bool {
        self.class() == ReplyClass::PermanentNegative
    }

    /// Text without code prefixes; continuation lines joined with '\n'.
    ///
    /// The prefix (`NNN-`, `NNN ` or a bare `NNN`) is removed from the first and last
    /// line and from continuation lines that carry the reply's own code followed by `-`
    /// (ProFTPD style). Other continuation lines are kept as received.
    pub fn text(&self) -> String {
        let n = self.lines.len();
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(self.strip_prefix(line, i == 0 || i + 1 == n));
        }
        out
    }

    /// The text of the first line only (without the code prefix).
    pub fn first_line_text(&self) -> &str {
        self.lines
            .first()
            .map_or("", |l| self.strip_prefix(l, true))
    }

    fn strip_prefix<'a>(&self, line: &'a str, edge: bool) -> &'a str {
        if ReplyCode::parse_prefix(line) != Some(self.code) {
            return line;
        }
        match line.as_bytes().get(3) {
            None if edge => "",
            Some(b'-') => &line[4..],
            Some(b' ') if edge => &line[4..],
            _ => line,
        }
    }
}

impl fmt::Display for Reply {
    /// The lines joined with `'\n'`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines.join("\n"))
    }
}

/// Why the parser gave up. The connection is unusable afterwards (`Broken`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyError {
    /// One line exceeded [`MAX_LINE_BYTES`].
    LineTooLong,
    /// One reply exceeded [`MAX_REPLY_LINES`] or [`MAX_REPLY_BYTES`].
    ReplyTooLarge,
    /// The first line of a reply does not start with a reply code (sanitised excerpt).
    Malformed(String),
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong => write!(f, "reply line longer than {MAX_LINE_BYTES} bytes"),
            Self::ReplyTooLarge => write!(
                f,
                "reply larger than {MAX_REPLY_LINES} lines or {MAX_REPLY_BYTES} bytes"
            ),
            Self::Malformed(line) => write!(f, "malformed reply line: {line:?}"),
        }
    }
}

impl std::error::Error for ReplyError {}

impl From<ReplyError> for Error {
    /// `Protocol { code: None, .. }` ("Invalid reply from server").
    fn from(e: ReplyError) -> Self {
        Error::Protocol {
            code: None,
            message: format!("invalid reply from server: {e}"),
        }
    }
}

/// Telnet filter state (RFC 854).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Telnet {
    Data,
    /// After IAC.
    Iac,
    /// After IAC WILL/WONT/DO/DONT: one option byte to drop.
    Opt,
}

const IAC: u8 = 0xFF;

/// An unfinished multi-line reply.
#[derive(Debug)]
struct Pending {
    code: ReplyCode,
    lines: Vec<String>,
    bytes: usize,
}

/// Incremental, allocation-bounded reply parser. Feed it bytes in any chunking; it yields
/// complete replies. Pure (no I/O) so it is property-tested and fuzzed.
#[derive(Debug)]
pub struct ReplyParser {
    decoder: LineDecoder,
    telnet: Telnet,
    line: Vec<u8>,
    pending: Option<Pending>,
    notes: Vec<DecodeNote>,
}

impl ReplyParser {
    /// A parser decoding lines with `decoder`.
    pub fn new(decoder: LineDecoder) -> Self {
        Self {
            decoder,
            telnet: Telnet::Data,
            line: Vec::new(),
            pending: None,
            notes: Vec::new(),
        }
    }

    /// Append bytes; returns replies completed by this chunk (usually 0 or 1).
    ///
    /// # Errors
    ///
    /// A [`ReplyError`]; the parser is reset (buffered data dropped) and the stream
    /// must not be used any more.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Reply>, ReplyError> {
        let mut out = Vec::new();
        for &b in bytes {
            let data = match self.telnet {
                Telnet::Data if b == IAC => {
                    self.telnet = Telnet::Iac;
                    None
                }
                Telnet::Data => Some(b),
                Telnet::Iac => {
                    self.telnet = match b {
                        IAC => Telnet::Data,
                        // WILL, WONT, DO, DONT: an option byte follows.
                        251..=254 => Telnet::Opt,
                        _ => Telnet::Data,
                    };
                    (b == IAC).then_some(IAC)
                }
                Telnet::Opt => {
                    self.telnet = Telnet::Data;
                    None
                }
            };
            let Some(b) = data else { continue };
            if b == b'\n' {
                let mut line = std::mem::take(&mut self.line);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                match self.complete_line(&line) {
                    Ok(Some(reply)) => out.push(reply),
                    Ok(None) => {}
                    Err(e) => {
                        self.reset();
                        return Err(e);
                    }
                }
                // Reuse the allocation for the next line.
                line.clear();
                self.line = line;
            } else {
                // One extra byte is allowed for a CR before the LF.
                if self.line.len() > MAX_LINE_BYTES {
                    self.reset();
                    return Err(ReplyError::LineTooLong);
                }
                self.line.push(b);
            }
        }
        Ok(out)
    }

    /// True if a partial line or an unterminated multi-line reply is buffered.
    pub fn has_partial(&self) -> bool {
        !self.line.is_empty() || self.pending.is_some() || self.telnet != Telnet::Data
    }

    /// Decoder notes (charset switch, invalid UTF-8) since the last call.
    pub fn take_notes(&mut self) -> Vec<DecodeNote> {
        std::mem::take(&mut self.notes)
    }

    fn reset(&mut self) {
        self.telnet = Telnet::Data;
        self.line = Vec::new();
        self.pending = None;
    }

    fn complete_line(&mut self, raw: &[u8]) -> Result<Option<Reply>, ReplyError> {
        if raw.len() > MAX_LINE_BYTES {
            return Err(ReplyError::LineTooLong);
        }
        let (text, note) = self.decoder.decode(raw);
        if let Some(note) = note {
            self.notes.push(note);
        }
        let text = sanitise(&text);
        match self.pending.take() {
            None => {
                let Some(code) = ReplyCode::parse_prefix(&text) else {
                    return Err(ReplyError::Malformed(excerpt(&text)));
                };
                match text.as_bytes().get(3) {
                    None | Some(b' ') => Ok(Some(Reply::new(code, vec![text]))),
                    Some(b'-') => {
                        self.pending = Some(Pending {
                            code,
                            bytes: raw.len(),
                            lines: vec![text],
                        });
                        Ok(None)
                    }
                    Some(_) => Err(ReplyError::Malformed(excerpt(&text))),
                }
            }
            Some(mut p) => {
                p.bytes += raw.len();
                if p.lines.len() >= MAX_REPLY_LINES || p.bytes > MAX_REPLY_BYTES {
                    return Err(ReplyError::ReplyTooLarge);
                }
                let ends = ReplyCode::parse_prefix(&text) == Some(p.code)
                    && matches!(text.as_bytes().get(3), None | Some(b' '));
                p.lines.push(text);
                if ends {
                    Ok(Some(Reply::new(p.code, p.lines)))
                } else {
                    self.pending = Some(p);
                    Ok(None)
                }
            }
        }
    }
}

/// Replaces C0 controls (except TAB), DEL and C1 controls with U+FFFD, so no terminal
/// escape from the server reaches a log or the UI.
fn sanitise(text: &str) -> String {
    if !text.chars().any(is_unsafe_control) {
        return text.to_owned();
    }
    text.chars()
        .map(|c| {
            if is_unsafe_control(c) {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

fn is_unsafe_control(c: char) -> bool {
    (c.is_control() && c != '\t') || ('\u{80}'..='\u{9f}').contains(&c)
}

/// At most 80 characters of a malformed line, for the error message.
fn excerpt(text: &str) -> String {
    let mut s: String = text.chars().take(80).collect();
    if s.len() < text.len() {
        s.push('…');
    }
    s
}

/// The path of a `257` reply (PWD/MKD): between the first `"` and the next `"` that is
/// not doubled, with `""` meaning a literal `"` (RFC 959 Appendix II). Without quotes,
/// the first whitespace-separated token of the text.
///
/// # Errors
///
/// `Protocol` when the path is empty.
pub fn parse_pwd(reply: &Reply) -> Result<String> {
    let text = reply.first_line_text();
    let path = match text.find('"') {
        Some(start) => {
            let mut out = String::new();
            let mut chars = text[start + 1..].chars().peekable();
            while let Some(c) = chars.next() {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        out.push('"');
                    } else {
                        break;
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }
        None => text.split_whitespace().next().unwrap_or("").to_owned(),
    };
    if path.is_empty() {
        return Err(Error::Protocol {
            code: Some(reply.code()),
            message: format!("no directory in reply: {}", reply.text()),
        });
    }
    Ok(path)
}

/// Fuzz/property entry point (T91 §7): feeds `data` split at boundaries derived from
/// the first byte; must never panic or allocate beyond the parser limits. Checks that
/// the split and unsplit parses agree, and runs every reply through
/// [`parse_feat`](crate::features::parse_feat) and [`parse_pwd`].
#[doc(hidden)]
pub fn fuzz_reply_parser(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let whole = parse_all(body, &[]);
    // Up to two split points derived from the selector byte.
    let len = body.len();
    let (a, b) = if len == 0 {
        (0, 0)
    } else {
        let a = usize::from(sel) * len / 256;
        let b = (usize::from(sel.rotate_left(4)) * len / 256).max(a);
        (a, b)
    };
    let split = parse_all(body, &[a, b]);
    assert_eq!(whole, split, "chunking changed the parse");
    if let Ok(replies) = whole {
        for reply in &replies {
            let _ = crate::features::parse_feat(reply);
            let _ = parse_pwd(reply);
            let _ = reply.text();
        }
    }
}

/// Parses `data` split at `points`; `Err` if any chunk failed.
fn parse_all(data: &[u8], points: &[usize]) -> Result<Vec<Reply>, ReplyError> {
    let mut parser = ReplyParser::new(LineDecoder::new(Charset::Auto));
    let mut out = Vec::new();
    let mut start = 0;
    for &p in points.iter().chain(std::iter::once(&data.len())) {
        let p = p.clamp(start, data.len());
        out.extend(parser.push(&data[start..p])?);
        start = p;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
