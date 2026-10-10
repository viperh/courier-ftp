//! Server-provided text (banners, prompts, disconnect messages) is untrusted:
//! [`sanitize_server_text`] makes it safe to show in the terminal UI.

/// Server-provided text is capped at this many characters.
pub const MAX_SERVER_TEXT: usize = 2048;

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Remove ANSI escape sequences (CSI, OSC, DCS, …), control characters (line
/// breaks are kept as `\n`, tabs become spaces) and bidi overrides, and cap the
/// result at [`MAX_SERVER_TEXT`] characters (`…` marks a cut). Trailing
/// whitespace is trimmed.
pub fn sanitize_server_text(text: &str) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let keep = match c {
            '\u{1b}' => {
                skip_escape(&mut chars);
                None
            }
            // C1 CSI / OSC / DCS / APC / PM / SOS introducers.
            '\u{9b}' => {
                skip_csi(&mut chars);
                None
            }
            '\u{9d}' | '\u{90}' | '\u{9f}' | '\u{9e}' | '\u{98}' => {
                skip_string(&mut chars);
                None
            }
            '\n' => Some('\n'),
            '\t' => Some(' '),
            c if c.is_control() => None,
            // Bidi overrides could reorder what the user reads.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => None,
            c => Some(c),
        };
        if let Some(c) = keep {
            if count == MAX_SERVER_TEXT {
                out.push('…');
                break;
            }
            out.push(c);
            count += 1;
        }
    }
    out.trim_end().to_owned()
}

fn skip_escape(chars: &mut Chars<'_>) {
    match chars.next() {
        Some('[') => skip_csi(chars),
        Some(']' | 'P' | '_' | '^' | 'X') => skip_string(chars),
        // Charset selection and other two-character sequences.
        Some('(' | ')' | '*' | '+' | '#' | '%') => {
            chars.next();
        }
        _ => {}
    }
}

fn skip_csi(chars: &mut Chars<'_>) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            break;
        }
    }
}

fn skip_string(chars: &mut Chars<'_>) {
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
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn strips_escapes_and_controls() {
        assert_eq!(
            sanitize_server_text("\u{1b}[31mred\u{1b}[0m\r\nline\u{7}2\t!\u{1b}]0;title\u{7}"),
            "red\nline2 !"
        );
        assert_eq!(sanitize_server_text("a\u{202e}b"), "ab");
        assert_eq!(sanitize_server_text("Password: \n\n"), "Password:");
    }

    #[test]
    fn caps_length() {
        let long = "x".repeat(MAX_SERVER_TEXT + 10);
        let out = sanitize_server_text(&long);
        assert_eq!(out.chars().count(), MAX_SERVER_TEXT + 1);
        assert!(out.ends_with('…'));
    }
}
