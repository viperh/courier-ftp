//! Message-log lines and their sanitising (T04).

use std::fmt::Write as _;

use time::OffsetDateTime;

use super::SessionId;

/// Maximum length of one log line in characters (before the `…` marker).
pub const MAX_LINE_CHARS: usize = 4096;

/// What a message-log line is (FileZilla's message types).
///
/// There is no separate warning kind: user-visible warnings are logged as
/// [`LogKind::Status`] with the text prefixed `Warning: `.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogKind {
    /// Progress of the session ("Connecting to …", "Directory listing successful").
    Status,
    /// A command sent to the server (masked, see [`mask_command`](super::mask_command)).
    Command,
    /// A server reply.
    Response,
    /// An error.
    Error,
    /// Raw listing line (only produced when `logging.show_raw_listing`, T71).
    ListingRaw,
    /// FileZilla "Trace" lines; level 1..=4 (= `DebugLevel` Warning..=Debug as u8).
    Debug(u8),
}

/// One line of the message log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogMessage {
    /// UTC; the UI formats it in local time.
    pub time: OffsetDateTime,
    /// The session the line belongs to ([`SessionId::APP`] for the application).
    pub session: SessionId,
    /// The line's kind.
    pub kind: LogKind,
    /// One line, sanitised (no control characters except TAB), at most 4096 chars plus
    /// a `…` marker when cut.
    pub text: String,
}

/// Splits `text` into lines: on `'\n'`, stripping one trailing `'\r'` per line; an empty
/// trailing line is dropped (so `"a\r\nb\n"` gives `["a", "b"]`).
pub(crate) fn split_lines(text: &str) -> impl Iterator<Item = &str> {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let empty = text.is_empty();
    body.split('\n')
        .filter(move |_| !empty)
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
}

/// Sanitises one line: C0 controls (except TAB) and DEL in caret notation (`ESC` → `^[`,
/// NUL → `^@`, DEL → `^?`), C1 controls as `\u{9b}`-style escapes, truncated to
/// [`MAX_LINE_CHARS`] characters with `…` appended when cut.
pub(crate) fn sanitise_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len().min(MAX_LINE_CHARS * 4));
    let mut chars = 0usize;
    let mut truncated = false;
    for c in line.chars() {
        if chars >= MAX_LINE_CHARS {
            truncated = true;
            break;
        }
        let code = u32::from(c);
        if c == '\t' {
            out.push(c);
            chars += 1;
        } else if code < 0x20 {
            out.push('^');
            // 0x00..=0x1F map to '@'..='_'; `code < 0x20` so the cast is lossless.
            out.push(char::from(b'@' + code as u8));
            chars += 2;
        } else if code == 0x7F {
            out.push_str("^?");
            chars += 2;
        } else if (0x80..=0x9F).contains(&code) {
            let _ = write!(out, "\\u{{{code:x}}}");
            chars += 6;
        } else {
            out.push(c);
            chars += 1;
        }
    }
    if chars > MAX_LINE_CHARS {
        // An escape crossed the limit: cut back to exactly MAX_LINE_CHARS.
        if let Some((idx, _)) = out.char_indices().nth(MAX_LINE_CHARS) {
            out.truncate(idx);
        }
        truncated = true;
    }
    if truncated {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn sanitise_control_chars_caret_notation() {
        assert_eq!(sanitise_line("a\x1b[31mb"), "a^[[31mb");
        assert_eq!(sanitise_line("\0x\x7f"), "^@x^?");
        assert_eq!(sanitise_line("\u{9b}"), "\\u{9b}");
        assert_eq!(sanitise_line("a\tb"), "a\tb");
        assert_eq!(sanitise_line("a\rb"), "a^Mb");
        assert_eq!(sanitise_line("héllo ✓"), "héllo ✓");
    }

    #[test]
    fn split_lines_rules() {
        assert_eq!(split_lines("a\r\nb\n").collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(split_lines("a").collect::<Vec<_>>(), ["a"]);
        assert_eq!(split_lines("a\n\nb").collect::<Vec<_>>(), ["a", "", "b"]);
        assert_eq!(split_lines("").count(), 0);
    }

    #[test]
    fn truncation_boundaries() {
        let exact = "x".repeat(MAX_LINE_CHARS);
        assert_eq!(sanitise_line(&exact), exact);
        let over = "x".repeat(MAX_LINE_CHARS + 1);
        let out = sanitise_line(&over);
        assert_eq!(out.chars().count(), MAX_LINE_CHARS + 1);
        assert!(out.ends_with('…'));
        let esc = format!("{}\u{1b}", "x".repeat(MAX_LINE_CHARS - 1));
        let out = sanitise_line(&esc);
        assert_eq!(out.chars().count(), MAX_LINE_CHARS + 1);
        assert!(out.ends_with('…'));
    }

    proptest! {
        #[test]
        fn prop_sanitised_text_has_no_control_chars(s in any::<String>(), pad in 0usize..5000) {
            let input = format!("{}{s}", "y".repeat(pad));
            let out = sanitise_line(&input);
            prop_assert!(out.chars().count() <= MAX_LINE_CHARS + 1);
            for c in out.chars() {
                let code = u32::from(c);
                prop_assert!(c == '\t' || !(code < 0x20 || (0x7F..=0x9F).contains(&code)));
            }
        }
    }
}
