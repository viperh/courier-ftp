//! Making untrusted text safe to draw, and cutting it to a width (T50).
//!
//! Every string that can come from a server, a file name or an error message goes
//! through [`sanitize`] (or [`sanitize_spans`]) before it is drawn: a control
//! character could otherwise move the cursor, clear the screen or reorder the text.

use std::borrow::Cow;

use ratatui::{style::Style, text::Span};
use unicode_width::UnicodeWidthChar;

/// How one character is drawn.
enum Escape {
    /// Drawn as is.
    Keep,
    /// C0 or DEL: caret notation (`^[`, `^?`).
    Caret(char),
    /// C1, bidi controls and line separators: `<U+XXXX>`.
    CodePoint(u32),
}

fn classify(c: char) -> Escape {
    let n = u32::from(c);
    match n {
        0x00..=0x1F => Escape::Caret(char::from_u32(n + 0x40).unwrap_or('?')),
        0x7F => Escape::Caret('?'),
        0x80..=0x9F
        | 0x061C
        | 0x200E
        | 0x200F
        | 0x202A..=0x202E
        | 0x2066..=0x2069
        | 0x2028
        | 0x2029 => Escape::CodePoint(n),
        _ => Escape::Keep,
    }
}

/// Whether `s` needs no escaping. Checks bytes: every character to escape is either
/// ASCII (C0, DEL) or starts with a lead byte `0xC2` (C1), `0xD8` (U+061C) or `0xE2`
/// (the U+20xx controls), so plain ASCII and most text skip the char scan.
fn is_safe(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !bytes
        .iter()
        .any(|&b| b < 0x20 || b == 0x7F || b == 0xC2 || b == 0xD8 || b == 0xE2)
    {
        return true;
    }
    s.chars().all(|c| matches!(classify(c), Escape::Keep))
}

fn push_escape(out: &mut String, e: &Escape) {
    match e {
        Escape::Keep => {}
        Escape::Caret(c) => {
            out.push('^');
            out.push(*c);
        }
        Escape::CodePoint(n) => out.push_str(&format!("<U+{n:04X}>")),
    }
}

/// Make untrusted text safe to draw: C0 controls (incl. TAB, CR, LF) become caret
/// notation (`^[`, `^I`, `^M`), DEL becomes `^?`, C1 controls (U+0080–U+009F), bidi
/// controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) and line/paragraph
/// separators (U+2028, U+2029) become `<U+XXXX>`. Returns `Cow::Borrowed` when the
/// input needs no change.
pub(crate) fn sanitize(s: &str) -> Cow<'_, str> {
    if is_safe(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match classify(c) {
            Escape::Keep => out.push(c),
            e => push_escape(&mut out, &e),
        }
    }
    Cow::Owned(out)
}

/// As [`sanitize`], but returns spans so escapes can be drawn in the `text.escape`
/// style (`escape`); the rest uses `base`.
pub(crate) fn sanitize_spans<'a>(s: &'a str, base: Style, escape: Style) -> Vec<Span<'a>> {
    if is_safe(s) {
        return vec![Span::styled(s, base)];
    }
    let mut spans = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices() {
        let e = classify(c);
        if matches!(e, Escape::Keep) {
            continue;
        }
        if start < i {
            spans.push(Span::styled(&s[start..i], base));
        }
        let mut text = String::new();
        push_escape(&mut text, &e);
        spans.push(Span::styled(text, escape));
        start = i + c.len_utf8();
    }
    if start < s.len() {
        spans.push(Span::styled(&s[start..], base));
    }
    spans
}

/// Cut `s` to `width` display columns (`unicode-width`), appending `ellipsis` (`…`, or
/// `~` in ASCII mode) when it was cut; never splits a wide character. The result
/// including the ellipsis is at most `width` columns.
pub(crate) fn truncate_to_width<'a>(s: &'a str, width: usize, ellipsis: &str) -> Cow<'a, str> {
    let total: usize = s.chars().map(|c| c.width().unwrap_or(0)).sum();
    if total <= width {
        return Cow::Borrowed(s);
    }
    let ell_w: usize = ellipsis.chars().map(|c| c.width().unwrap_or(0)).sum();
    if ell_w > width {
        return Cow::Owned(String::new());
    }
    let budget = width - ell_w;
    let mut used = 0;
    let mut out = String::new();
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > budget {
            break;
        }
        used += w;
        out.push(c);
    }
    out.push_str(ellipsis);
    Cow::Owned(out)
}

/// Display width of `s` in columns.
pub(crate) fn width(s: &str) -> usize {
    s.chars().map(|c| c.width().unwrap_or(0)).sum()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    use super::*;

    fn is_control(c: char) -> bool {
        matches!(classify(c), Escape::Caret(_) | Escape::CodePoint(_))
    }

    #[test]
    fn sanitize_plain_text_is_borrowed() {
        for s in [
            "",
            "hello",
            "héllo wörld",
            "日本語",
            "a-b_c.d/e",
            "emoji 🔒",
        ] {
            assert!(matches!(sanitize(s), Cow::Borrowed(_)), "{s}");
        }
    }

    #[test]
    fn sanitize_caret_and_codepoints() {
        assert_eq!(sanitize("a\x1b[2Jb"), "a^[[2Jb");
        assert_eq!(sanitize("x\x7fy"), "x^?y");
        assert_eq!(sanitize("\t\r\n\0"), "^I^M^J^@");
        assert_eq!(sanitize("a\u{85}b"), "a<U+0085>b");
        assert_eq!(sanitize("\u{202e}evil"), "<U+202E>evil");
        assert_eq!(sanitize("\u{2066}x\u{2069}"), "<U+2066>x<U+2069>");
        assert_eq!(
            sanitize("\u{2028}\u{2029}\u{61c}"),
            "<U+2028><U+2029><U+061C>"
        );
        // Characters sharing a lead byte with controls stay.
        assert_eq!(sanitize("é€…"), "é€…");
    }

    #[test]
    fn sanitize_spans_marks_escapes() {
        let base = Style::default();
        let esc = Style::default().add_modifier(ratatui::style::Modifier::REVERSED);
        let spans = sanitize_spans("a\x1bb", base, esc);
        let texts: Vec<_> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(texts, ["a", "^[", "b"]);
        assert_eq!(spans[1].style, esc);
        assert_eq!(sanitize_spans("ok", base, esc).len(), 1);
    }

    #[test]
    fn truncate_to_width_counts_wide_chars() {
        assert_eq!(truncate_to_width("hello", 5, "…"), "hello");
        assert!(matches!(
            truncate_to_width("hello", 5, "…"),
            Cow::Borrowed(_)
        ));
        assert_eq!(truncate_to_width("hello world", 6, "…"), "hello…");
        assert_eq!(truncate_to_width("hello world", 6, "~"), "hello~");
        // Each CJK char is 2 columns: never split one.
        assert_eq!(truncate_to_width("日本語テキスト", 6, "…"), "日本…");
        assert_eq!(width(&truncate_to_width("日本語テキスト", 6, "…")), 5);
        assert_eq!(truncate_to_width("abc", 0, "…"), "");
    }

    proptest! {
        #[test]
        fn prop_sanitize_output_has_no_control_chars(s in any::<String>()) {
            let out = sanitize(&s);
            prop_assert!(!out.chars().any(is_control), "{out:?}");
            if !s.chars().any(is_control) {
                prop_assert!(matches!(out, Cow::Borrowed(_)));
            }
        }

        #[test]
        fn prop_truncate_fits(s in any::<String>(), w in 0usize..40) {
            let out = truncate_to_width(&s, w, "…");
            prop_assert!(width(&out) <= w.max(width(&s).min(w)));
        }
    }
}
