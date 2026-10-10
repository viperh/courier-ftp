//! FTP replies (RFC 959 §4.2) and an incremental, I/O-free reply parser
//! ([`ReplyParser`] documents the format and limits).

use std::fmt;

use courier_ftp_core::{Error, model::Charset};

/// The longest accepted reply line in bytes (without the line ending).
pub const MAX_LINE: usize = 64 * 1024;

/// The longest accepted reply in bytes, all lines together (a `STAT` or `HELP`
/// reply can be long, but never this long).
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// One reply from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The three-digit reply code, `100..=599`.
    pub code: u16,
    /// Every line as received and decoded, including the code prefix of the
    /// first and last line (`211-Features:`, ` MDTM`, `211 End`), without line
    /// endings.
    pub lines: Vec<String>,
}

impl Reply {
    /// A reply with these lines (tests and synthetic replies).
    pub fn new(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// `1xx`: positive preliminary, another reply follows.
    pub fn is_preliminary(&self) -> bool {
        (100..200).contains(&self.code)
    }

    /// `2xx`: positive completion.
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// `3xx`: positive intermediate, the server wants another command
    /// (`331` after `USER`, `350` after `REST`/`RNFR`).
    pub fn is_intermediate(&self) -> bool {
        (300..400).contains(&self.code)
    }

    /// `4xx`: transient negative completion (retrying may work).
    pub fn is_transient_err(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// `5xx`: permanent negative completion.
    pub fn is_permanent_err(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// `4xx` or `5xx`.
    pub fn is_err(&self) -> bool {
        self.is_transient_err() || self.is_permanent_err()
    }

    /// The text of the reply without the code prefixes, lines joined with
    /// `\n`. `257 "/home" is current` gives `"/home" is current`.
    pub fn text(&self) -> String {
        let code = self.code.to_string();
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(strip_code(line, &code));
        }
        out
    }

    /// The text of the first line without its code (`215 UNIX Type: L8` gives
    /// `UNIX Type: L8`).
    pub fn first_line_text(&self) -> &str {
        let code = self.code.to_string();
        self.lines.first().map_or("", |l| strip_code(l, &code))
    }

    /// The lines between the first and the last line of a multi-line reply
    /// (the feature lines of a `FEAT` reply). Empty for a single-line reply.
    pub fn inner_lines(&self) -> &[String] {
        match self.lines.len() {
            0..=2 => &[],
            n => self.lines.get(1..n - 1).unwrap_or_default(),
        }
    }

    /// The error this reply means when it was not the expected one: `421`
    /// (service closing) is [`Error::Connection`], everything else
    /// [`Error::Protocol`] with the code and the reply text.
    pub fn to_error(&self) -> Error {
        if self.code == 421 {
            Error::Connection(self.text())
        } else {
            Error::reply(self.code, self.text())
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            f.write_str(line)?;
        }
        Ok(())
    }
}

/// `line` without a leading `NNN ` / `NNN-` / `NNN` when it starts with `code`.
fn strip_code<'a>(line: &'a str, code: &str) -> &'a str {
    match line.strip_prefix(code) {
        Some(rest) if rest.is_empty() => rest,
        Some(rest) if rest.starts_with([' ', '-']) => rest.get(1..).unwrap_or_default(),
        _ => line,
    }
}

/// Why the reply stream could not be parsed. The control connection is
/// unusable afterwards: client and server no longer agree where a reply
/// starts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplyError {
    /// A line was longer than [`MAX_LINE`].
    #[error("reply line longer than {MAX_LINE} bytes")]
    LineTooLong,
    /// A multi-line reply grew beyond [`MAX_REPLY_BYTES`].
    #[error("reply longer than {MAX_REPLY_BYTES} bytes")]
    ReplyTooLong,
    /// A reply did not start with a three-digit code `1xx`..`5xx` followed by
    /// a space, a dash or the end of the line.
    #[error("malformed reply line: {0:?}")]
    Malformed(String),
}

impl From<ReplyError> for Error {
    fn from(err: ReplyError) -> Self {
        Error::Protocol {
            code: None,
            message: err.to_string(),
        }
    }
}

/// A multi-line reply being collected.
#[derive(Debug)]
struct Partial {
    code: u16,
    lines: Vec<String>,
    bytes: usize,
}

/// Incremental, I/O-free reply parser.
///
/// It is fed raw bytes as they arrive ([`feed`](Self::feed)) and hands out
/// complete replies ([`next_reply`](Self::next_reply)). It never reads from a
/// socket itself, so the control connection can swap its stream (TLS upgrade,
/// T12) without losing parser state, and it can be tested and fuzzed with
/// arbitrary chunking.
///
/// Format:
///
/// - lines end in CRLF; a bare LF is accepted too;
/// - single-line reply: `NNN text` (or just `NNN`);
/// - multi-line reply: starts with `NNN-text` and ends at the first line that
///   starts with the same code followed by a space (`NNN text`, or exactly
///   `NNN`). Lines in between may contain anything, including other codes or
///   the same code followed by `-`, and may be indented;
/// - empty lines between replies are ignored.
///
/// Limits: a line longer than [`MAX_LINE`] bytes or a reply longer than
/// [`MAX_REPLY_BYTES`] is a protocol error, and so is a line that doesn't
/// start with a reply code where a reply must begin.
#[derive(Debug, Default)]
pub struct ReplyParser {
    /// Bytes received but not yet consumed as a line.
    buf: Vec<u8>,
    /// `buf[..scanned]` holds no `\n`.
    scanned: usize,
    partial: Option<Partial>,
}

impl ReplyParser {
    /// An empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append received bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Whether nothing is buffered: no partial line and no partial
    /// multi-line reply. Before a TLS upgrade this must hold, or the server
    /// (or an attacker on the path) sent plain-text bytes that would be
    /// mistaken for protected ones.
    pub fn is_idle(&self) -> bool {
        self.buf.is_empty() && self.partial.is_none()
    }

    /// The next complete reply, `Ok(None)` when more bytes are needed. Each
    /// line is decoded with `charset` on its own ([`Charset::decode`]).
    ///
    /// # Errors
    ///
    /// [`ReplyError`] for an over-long line or reply and for a line that
    /// can't start a reply. The parser should not be used afterwards.
    pub fn next_reply(&mut self, charset: Charset) -> Result<Option<Reply>, ReplyError> {
        loop {
            let Some(line) = self.next_line()? else {
                return Ok(None);
            };
            if let Some(reply) = self.push_line(&line, charset)? {
                return Ok(Some(reply));
            }
        }
    }

    /// The next line without its line ending, or `None` when no complete line
    /// is buffered.
    fn next_line(&mut self) -> Result<Option<Vec<u8>>, ReplyError> {
        let tail = self.buf.get(self.scanned..).unwrap_or_default();
        let Some(pos) = tail.iter().position(|&b| b == b'\n') else {
            self.scanned = self.buf.len();
            // One byte of slack for a CR that belongs to the line ending.
            if self.buf.len() > MAX_LINE + 1 {
                return Err(ReplyError::LineTooLong);
            }
            return Ok(None);
        };
        let end = self.scanned + pos;
        let mut line: Vec<u8> = self.buf.drain(..=end).collect();
        self.scanned = 0;
        line.pop(); // '\n'
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() > MAX_LINE {
            return Err(ReplyError::LineTooLong);
        }
        Ok(Some(line))
    }

    fn push_line(&mut self, line: &[u8], charset: Charset) -> Result<Option<Reply>, ReplyError> {
        if let Some(partial) = self.partial.as_mut() {
            let text = charset.decode(line).into_owned();
            partial.bytes = partial.bytes.saturating_add(line.len() + 2);
            if partial.bytes > MAX_REPLY_BYTES {
                return Err(ReplyError::ReplyTooLong);
            }
            partial.lines.push(text);
            let is_end = parse_code(line).is_some_and(|(code, sep)| {
                code == partial.code && matches!(sep, Separator::Space | Separator::End)
            });
            if is_end {
                return Ok(self.partial.take().map(|p| Reply {
                    code: p.code,
                    lines: p.lines,
                }));
            }
            return Ok(None);
        }
        if line.is_empty() {
            return Ok(None);
        }
        let Some((code, sep)) = parse_code(line) else {
            let shown = charset.decode(line.get(..80).unwrap_or(line)).into_owned();
            return Err(ReplyError::Malformed(shown));
        };
        let text = charset.decode(line).into_owned();
        match sep {
            Separator::Space | Separator::End => Ok(Some(Reply {
                code,
                lines: vec![text],
            })),
            Separator::Dash => {
                self.partial = Some(Partial {
                    code,
                    bytes: line.len() + 2,
                    lines: vec![text],
                });
                Ok(None)
            }
        }
    }
}

/// What follows the code on a reply line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Separator {
    Space,
    Dash,
    End,
}

/// The code and separator when `line` starts with `[1-5]\d\d` followed by a
/// space, a dash or the end of the line.
fn parse_code(line: &[u8]) -> Option<(u16, Separator)> {
    let digits = line.get(..3)?;
    if !digits.iter().all(u8::is_ascii_digit) || !(b'1'..=b'5').contains(&digits[0]) {
        return None;
    }
    let sep = match line.get(3) {
        None => Separator::End,
        Some(b' ') => Separator::Space,
        Some(b'-') => Separator::Dash,
        Some(_) => return None,
    };
    let code = digits
        .iter()
        .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    Some((code, sep))
}

/// Fuzz body (T91 §7): feed `data` to a parser in chunks whose sizes come from
/// the first byte, with every charset, and drain every reply. Must never
/// panic. Used by the cargo-fuzz target `ftp_reply` and the property tests.
#[doc(hidden)]
pub fn fuzz_reply_parser(data: &[u8]) {
    let (chunk, data) = match data.split_first() {
        Some((first, rest)) => (usize::from(*first % 64) + 1, rest),
        None => (1, data),
    };
    for charset in [
        Charset::Auto,
        Charset::Utf8,
        Charset::Custom(encoding_rs::SHIFT_JIS),
    ] {
        let mut parser = ReplyParser::new();
        'feed: for piece in data.chunks(chunk) {
            parser.feed(piece);
            loop {
                match parser.next_reply(charset) {
                    Ok(Some(reply)) => {
                        let _ = (reply.text(), reply.first_line_text(), reply.inner_lines());
                        let _ = super::features::Features::parse(&reply);
                        let _ = super::pwd::parse_quoted_path(&reply.text());
                    }
                    Ok(None) => break,
                    Err(_) => break 'feed,
                }
            }
        }
        let _ = parser.is_idle();
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn parse_all(bytes: &[u8]) -> Result<Vec<Reply>, ReplyError> {
        let mut parser = ReplyParser::new();
        parser.feed(bytes);
        let mut out = Vec::new();
        while let Some(reply) = parser.next_reply(Charset::Auto)? {
            out.push(reply);
        }
        Ok(out)
    }

    /// Feed `bytes` split at `splits` and collect every reply.
    fn parse_split(bytes: &[u8], splits: &[usize]) -> Vec<Reply> {
        let mut parser = ReplyParser::new();
        let mut out = Vec::new();
        let mut start = 0;
        for &end in splits.iter().chain(std::iter::once(&bytes.len())) {
            let end = end.clamp(start, bytes.len());
            parser.feed(&bytes[start..end]);
            start = end;
            while let Some(reply) = parser.next_reply(Charset::Auto).unwrap() {
                out.push(reply);
            }
        }
        assert!(parser.is_idle());
        out
    }

    /// RFC 959 §4.2 example, an indented continuation line, a line with a
    /// different code and the same code with a dash in the middle.
    const MULTI: &[u8] = b"123-First line\r\n\
        Second line\r\n  234 A line beginning with numbers\r\n\
        456 different code\r\n123-same code with dash\r\n\
        123 The last line\r\n200 next\r\n";

    #[test]
    fn rfc_multiline_example() {
        let replies = parse_all(MULTI).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].code, 123);
        assert_eq!(
            replies[0].lines,
            vec![
                "123-First line",
                "Second line",
                "  234 A line beginning with numbers",
                "456 different code",
                "123-same code with dash",
                "123 The last line",
            ]
        );
        assert_eq!(replies[1], Reply::new(200, vec!["200 next".into()]));
        assert_eq!(
            replies[0].inner_lines(),
            &replies[0].lines[1..5],
            "inner lines"
        );
        assert!(replies[0].text().starts_with("First line\nSecond line\n"));
        assert!(
            replies[0]
                .text()
                .ends_with("\nsame code with dash\nThe last line")
        );
    }

    #[test]
    fn every_split_point_gives_the_same_replies() {
        let whole = parse_all(MULTI).unwrap();
        for a in 0..=MULTI.len() {
            assert_eq!(parse_split(MULTI, &[a]), whole, "split at {a}");
        }
        // Two split points, byte by byte over a shorter prefix.
        for a in 0..40 {
            for b in a..60 {
                assert_eq!(parse_split(MULTI, &[a, b]), whole, "split at {a},{b}");
            }
        }
        // One byte at a time.
        let all: Vec<usize> = (0..MULTI.len()).collect();
        assert_eq!(parse_split(MULTI, &all), whole);
    }

    proptest::proptest! {
        /// Any chunking of a valid reply stream gives the same replies.
        #[test]
        fn random_chunking_gives_the_same_replies(
            mut splits in proptest::collection::vec(0..MULTI.len(), 0..12)
        ) {
            splits.sort_unstable();
            proptest::prop_assert_eq!(parse_split(MULTI, &splits), parse_all(MULTI).unwrap());
        }
    }

    #[test]
    fn bare_lf_bare_code_and_blank_lines() {
        let replies = parse_all(b"\r\n220 hi\n\n200\r\n230-a\n230\n").unwrap();
        assert_eq!(
            replies.iter().map(|r| r.code).collect::<Vec<_>>(),
            vec![220, 200, 230]
        );
        assert_eq!(replies[1].text(), "");
        assert_eq!(replies[2].lines, vec!["230-a", "230"]);
    }

    #[test]
    fn helpers_and_classes() {
        let r = |code| Reply::new(code, vec![format!("{code} x")]);
        assert!(r(150).is_preliminary() && !r(150).is_ok());
        assert!(r(226).is_ok());
        assert!(r(331).is_intermediate());
        assert!(r(450).is_transient_err() && r(450).is_err());
        assert!(r(550).is_permanent_err() && r(550).is_err());
        assert!(matches!(r(421).to_error(), Error::Connection(_)));
        assert!(matches!(
            r(550).to_error(),
            Error::Protocol {
                code: Some(550),
                ..
            }
        ));
        assert_eq!(r(215).first_line_text(), "x");
    }

    #[test]
    fn malformed_lines_are_errors() {
        for bad in [
            &b"hello\r\n"[..],
            b"22 short\r\n",
            b"620 out of range\r\n",
            b"099 out of range\r\n",
            b"220x no separator\r\n",
            b"2a0 letters\r\n",
        ] {
            assert!(
                matches!(parse_all(bad), Err(ReplyError::Malformed(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn line_and_reply_limits() {
        // Exactly MAX_LINE is fine, one more byte is not.
        let mut ok = b"200 ".to_vec();
        ok.resize(MAX_LINE, b'a');
        ok.extend_from_slice(b"\r\n");
        assert_eq!(parse_all(&ok).unwrap().len(), 1);

        let mut long = b"200 ".to_vec();
        long.resize(MAX_LINE + 1, b'a');
        long.extend_from_slice(b"\r\n");
        assert_eq!(parse_all(&long), Err(ReplyError::LineTooLong));

        // An endless line without a newline fails before it is complete.
        let mut parser = ReplyParser::new();
        parser.feed(&vec![b'2'; MAX_LINE + 2]);
        assert_eq!(
            parser.next_reply(Charset::Auto),
            Err(ReplyError::LineTooLong)
        );

        // A multi-line reply that never ends.
        let mut parser = ReplyParser::new();
        parser.feed(b"211-start\r\n");
        let line = vec![b'x'; 1000];
        let mut result = Ok(None);
        for _ in 0..(MAX_REPLY_BYTES / 1000 + 2) {
            parser.feed(&line);
            parser.feed(b"\r\n");
            result = parser.next_reply(Charset::Auto);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(ReplyError::ReplyTooLong));
    }

    #[test]
    fn charset_per_line() {
        // A Latin-1 line among UTF-8 lines (Auto falls back per line).
        let replies = parse_all("211-é\r\n caf\u{e9}\r\n211 end\r\n".as_bytes()).unwrap();
        assert_eq!(replies[0].lines[1], " café");
        let replies = parse_all(b"211-x\r\n caf\xe9\r\n211 end\r\n").unwrap();
        assert_eq!(replies[0].lines[1], " café");
    }

    #[test]
    fn idle_tracking() {
        let mut parser = ReplyParser::new();
        assert!(parser.is_idle());
        parser.feed(b"211-a\r\n");
        assert_eq!(parser.next_reply(Charset::Auto), Ok(None));
        assert!(!parser.is_idle(), "inside a multi-line reply");
        parser.feed(b"211 b\r\n22");
        assert!(parser.next_reply(Charset::Auto).unwrap().is_some());
        assert!(!parser.is_idle(), "partial line buffered");
    }
}
