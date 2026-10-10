//! Text handling: sanitising server text (`sanitize_server_text`, T20) and
//! localisation (`Localizable`, `loc!`, T75).

use std::iter::Peekable;
use std::str::Chars;

/// Make server-provided text safe to show: strips ANSI/C1 escape sequences (CSI, OSC,
/// DCS, APC, PM, SOS), control characters (keeps `\n`, maps `\t` to a space) and bidi
/// overrides; caps at `max_chars` characters (`…` marks a cut). Trailing whitespace is
/// trimmed. Copied from sverb `ssh/auth.rs::sanitize_server_text` (D13).
///
/// ```
/// use courier_ftp_core::text::sanitize_server_text;
///
/// assert_eq!(sanitize_server_text("\u{1b}[31mred\u{1b}[0m\tok", 512), "red ok");
/// assert_eq!(sanitize_server_text("abcdef", 3), "abc…");
/// ```
pub fn sanitize_server_text(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let keep = match c {
            '\u{1b}' => {
                skip_escape(&mut chars);
                None
            }
            // C1 CSI.
            '\u{9b}' => {
                skip_csi(&mut chars);
                None
            }
            // C1 OSC / DCS / APC / PM / SOS: a string up to ST or BEL.
            '\u{9d}' | '\u{90}' | '\u{9f}' | '\u{9e}' | '\u{98}' => {
                skip_string(&mut chars);
                None
            }
            '\n' => Some('\n'),
            '\t' => Some(' '),
            c if c.is_control() => None,
            // Bidi overrides and isolates could reorder what the user reads.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => None,
            c => Some(c),
        };
        if let Some(c) = keep {
            if count == max_chars {
                out.push('…');
                break;
            }
            out.push(c);
            count += 1;
        }
    }
    out.truncate(out.trim_end().len());
    out
}

fn skip_escape(chars: &mut Peekable<Chars<'_>>) {
    match chars.next() {
        Some('[') => skip_csi(chars),
        Some(']' | 'P' | '_' | '^' | 'X') => skip_string(chars),
        // Charset selection and other three-character sequences.
        Some('(' | ')' | '*' | '+' | '#' | '%') => {
            chars.next();
        }
        // Two-character sequences (`ESC c`, `ESC 7`, …).
        _ => {}
    }
}

fn skip_csi(chars: &mut Peekable<Chars<'_>>) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            break;
        }
    }
}

fn skip_string(chars: &mut Peekable<Chars<'_>>) {
    while let Some(c) = chars.next() {
        match c {
            '\u{7}' | '\u{9c}' => break,
            '\u{1b}' => {
                if chars.peek() == Some(&'\\') {
                    chars.next();
                }
                break;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_csi_osc_c1_and_bidi() {
        let cases = [
            ("\u{1b}[1;31mred\u{1b}[0m", "red"),
            ("a\u{1b}]0;title\u{7}b", "ab"),
            (
                "a\u{1b}]8;;http://x\u{1b}\\link\u{1b}]8;;\u{1b}\\b",
                "alinkb",
            ),
            ("a\u{1b}Pdcs\u{1b}\\b", "ab"),
            ("a\u{9b}2Jb", "ab"),
            ("a\u{9d}osc\u{9c}b", "ab"),
            ("a\u{1b}(Bb", "ab"),
            ("a\u{1b}cb", "ab"),
            ("evil\u{202e}txt.exe", "eviltxt.exe"),
            ("x\u{2066}y\u{2069}z", "xyz"),
            ("bell\u{7}\r\0end", "bellend"),
            ("tab\there", "tab here"),
            ("line1\nline2\n", "line1\nline2"),
            ("trailing   ", "trailing"),
            ("ünïcödé ✓", "ünïcödé ✓"),
        ];
        for (input, want) in cases {
            assert_eq!(sanitize_server_text(input, 512), want, "{input:?}");
        }
    }

    #[test]
    fn sanitize_caps_length_with_ellipsis() {
        assert_eq!(sanitize_server_text("abcdef", 6), "abcdef");
        assert_eq!(sanitize_server_text("abcdefg", 6), "abcdef…");
        assert_eq!(sanitize_server_text("", 6), "");
        // Removed characters don't count.
        assert_eq!(sanitize_server_text("\u{1b}[0mabc", 3), "abc");
        let long = "x".repeat(10_000);
        let out = sanitize_server_text(&long, 512);
        assert_eq!(out.chars().count(), 513);
        assert!(out.ends_with('…'));
        assert_eq!(sanitize_server_text("ab", 0), "…");
    }

    mod props {
        use proptest::prelude::*;

        use super::super::sanitize_server_text;

        proptest! {
            #[test]
            fn sanitize_output_has_no_control_chars(s in "\\PC*|[\\x00-\\x1f\\x7f-\\u{9f}\\u{202a}-\\u{202e}a-z]*", max in 0usize..64) {
                let out = sanitize_server_text(&s, max);
                prop_assert!(out.chars().all(|c| c == '\n' || !c.is_control()), "{out:?}");
                let bidi = out.chars().any(|c| matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'));
                prop_assert!(!bidi);
                prop_assert!(out.chars().count() <= max + 1);
            }
        }
    }
}
