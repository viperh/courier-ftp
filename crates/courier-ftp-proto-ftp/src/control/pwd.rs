//! Quoted path parsing for `257` replies (`PWD`, `MKD`; RFC 959 Appendix II).

/// The path in a `257` reply text: `"/home/user" is current directory` gives
/// `/home/user`. Inside the quotes a doubled quote `""` is a literal `"`.
///
/// Servers that don't quote (`257 /home/user is current directory`) are
/// tolerated: the first word is taken when it looks like a path (starts with
/// `/` or a drive letter, or contains `[` as VMS paths do). `None` when no path
/// can be found or the quotes are never closed.
pub fn parse_quoted_path(text: &str) -> Option<String> {
    let Some(start) = text.find('"') else {
        let word = text.split_ascii_whitespace().next()?;
        let looks_like_path =
            word.starts_with('/') || word.contains('[') || word.as_bytes().get(1) == Some(&b':');
        return looks_like_path.then(|| word.to_owned());
    };
    let mut out = String::new();
    let mut chars = text.get(start + 1..)?.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if chars.peek() == Some(&'"') {
                chars.next();
                out.push('"');
            } else {
                return Some(out);
            }
        } else {
            out.push(c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn quoted_paths() {
        for (text, want) in [
            ("\"/home/user\" is current directory", Some("/home/user")),
            ("\"/a \"\"b\"\" c\" created", Some("/a \"b\" c")),
            ("\"/\"", Some("/")),
            ("\"\"\"\"", Some("\"")),
            ("MKD command successful: \"/new dir\"", Some("/new dir")),
            ("\"/with spaces/ \" ok", Some("/with spaces/ ")),
            (
                "\"DISK$USER:[ALICE]\" is current",
                Some("DISK$USER:[ALICE]"),
            ),
            ("\"unterminated", None),
            ("\"also \"\" unterminated", None),
        ] {
            assert_eq!(parse_quoted_path(text).as_deref(), want, "{text:?}");
        }
    }

    #[test]
    fn unquoted_paths() {
        assert_eq!(
            parse_quoted_path("/home/user is current directory").as_deref(),
            Some("/home/user")
        );
        assert_eq!(
            parse_quoted_path("C:/ftp is cwd").as_deref(),
            Some("C:/ftp")
        );
        assert_eq!(parse_quoted_path("is current directory"), None);
        assert_eq!(parse_quoted_path(""), None);
    }
}
