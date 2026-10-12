//! Text from servers drawn safely: no control characters or bidirectional
//! overrides reach the terminal, and widths are measured in columns (wide
//! characters count 2), so hostile or non-Latin names can't misalign a row.

use unicode_width::UnicodeWidthChar;

/// A name as it may be drawn: control characters (escape sequences from a
/// hostile server) and bidirectional overrides (which can make `exe.txt`
/// read as `txt.exe`) become `?`, so the terminal only ever gets plain
/// text and every character takes the width it is measured with.
pub(crate) fn display_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// The display width of `text` (wide characters count 2).
pub(crate) fn width(text: &str) -> usize {
    text.chars().map(|c| c.width().unwrap_or(0)).sum()
}

/// The longest start of `text` at most `max` columns wide.
pub(crate) fn take_width(text: &str, max: usize) -> String {
    let mut used = 0;
    text.chars()
        .take_while(|c| {
            used += c.width().unwrap_or(0);
            used <= max
        })
        .collect()
}

/// `s` made safe and fitted into `width` columns: cut from the left (paths
/// keep their file name) with `ellipsis`, padded on the right.
pub(crate) fn fit_left(s: &str, width_: usize, ellipsis: char) -> String {
    let s = display_name(s);
    let n = width(&s);
    if n <= width_ {
        return format!("{s}{}", " ".repeat(width_ - n));
    }
    if width_ == 0 {
        return String::new();
    }
    // Keep the end: walk back from the last character.
    let mut used = 0;
    let mut keep: Vec<char> = s
        .chars()
        .rev()
        .take_while(|c| {
            used += c.width().unwrap_or(0);
            used < width_
        })
        .collect();
    keep.reverse();
    let keep: String = keep.into_iter().collect();
    let pad = width_.saturating_sub(1 + width(&keep));
    format!("{ellipsis}{keep}{}", " ".repeat(pad))
}

/// `s` made safe and fitted into `width` columns, cut on the right.
pub(crate) fn fit_right(s: &str, width_: usize, ellipsis: char) -> String {
    let s = display_name(s);
    let n = width(&s);
    if n <= width_ {
        return format!("{s}{}", " ".repeat(width_ - n));
    }
    if width_ == 0 {
        return String::new();
    }
    let keep = take_width(&s, width_ - 1);
    let pad = width_.saturating_sub(1 + width(&keep));
    format!("{keep}{ellipsis}{}", " ".repeat(pad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fits_are_exactly_the_width() {
        for s in [
            "short",
            "日本語のファイル名.txt",
            "a\u{1b}[2Jb",
            "much-longer-than-ten.txt",
        ] {
            assert_eq!(width(&fit_left(s, 10, '…')), 10, "{s}");
            assert_eq!(width(&fit_right(s, 10, '…')), 10, "{s}");
        }
        assert_eq!(fit_left("/a/b/file.txt", 9, '…'), "…file.txt");
        assert_eq!(fit_right("file.txt", 5, '>'), "file>");
        assert!(!fit_left("x\u{1b}]0;t\u{7}", 20, '…').contains('\u{1b}'));
    }
}
