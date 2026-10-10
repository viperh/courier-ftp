//! Making remote file names safe for the local filesystem (used by T42).

/// The rules of which OS to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRules {
    /// `/` and NUL are invalid.
    Unix,
    /// `\ / : * ? " < > |` and control characters are invalid, names may not
    /// end in a dot or space, and device names (`CON`, `COM1`…) are reserved.
    Windows,
}

impl NameRules {
    /// The rules of the OS this was built for.
    pub fn current() -> Self {
        if cfg!(windows) {
            NameRules::Windows
        } else {
            NameRules::Unix
        }
    }
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// `name` with every character the current OS can't store replaced by
/// `replacement` (see [`sanitize_name`]).
pub fn sanitize_local_name(name: &str, replacement: char) -> String {
    sanitize_name(name, replacement, NameRules::current())
}

/// `name` made valid under `rules`:
///
/// - invalid characters become `replacement`;
/// - on Windows, trailing dots and spaces become `replacement`, and a reserved
///   device name (with or without extension, any case) gets `replacement`
///   appended to its stem: `con.txt` → `con_.txt`;
/// - an empty result becomes `replacement` itself.
pub fn sanitize_name(name: &str, replacement: char, rules: NameRules) -> String {
    let invalid = |c: char| match rules {
        NameRules::Unix => c == '/' || c == '\0',
        NameRules::Windows => {
            c.is_control() || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        }
    };
    let mut out: String = name
        .chars()
        .map(|c| if invalid(c) { replacement } else { c })
        .collect();
    if rules == NameRules::Windows {
        let trimmed = out.trim_end_matches(['.', ' ']).len();
        let tail = out.len() - trimmed;
        if tail > 0 {
            out.truncate(trimmed);
            out.extend(std::iter::repeat_n(replacement, tail));
        }
        let stem_len = out.find('.').unwrap_or(out.len());
        if RESERVED
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&out[..stem_len]))
        {
            out.insert(stem_len, replacement);
        }
    }
    if out.is_empty() {
        out.push(replacement);
    }
    // `.` and `..` are not names: joined to a directory they would point at it
    // or at its parent (path traversal from a hostile listing, T91).
    if out == "." || out == ".." {
        out = std::iter::repeat_n(replacement, out.len()).collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn unix_rules() {
        let cases = [
            ("normal.txt", "normal.txt"),
            ("a/b", "a_b"),
            ("nul\0byte", "nul_byte"),
            ("what?:<>|*\"\\", "what?:<>|*\"\\"),
            ("CON", "CON"),
            ("trailing. ", "trailing. "),
            ("", "_"),
            (".", "_"),
            ("..", "__"),
            ("...", "..."),
            ("../x", ".._x"),
            ("..\0", ".._"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_name(input, '_', NameRules::Unix),
                expected,
                "{input:?}"
            );
        }
    }

    #[test]
    fn windows_rules() {
        let cases = [
            ("normal.txt", "normal.txt"),
            (r#"a\b/c:d*e?f"g<h>i|j"#, "a_b_c_d_e_f_g_h_i_j"),
            ("tab\there", "tab_here"),
            ("trailing.", "trailing_"),
            ("trailing. .", "trailing___"),
            ("...", "___"),
            ("", "_"),
            ("console.txt", "console.txt"),
            ("COM10", "COM10"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_name(input, '_', NameRules::Windows),
                expected,
                "{input:?}"
            );
        }
    }

    #[test]
    fn every_reserved_windows_name_any_case() {
        for name in RESERVED {
            for variant in [
                name.to_string(),
                name.to_lowercase(),
                format!("{}.tar.gz", name.to_lowercase()),
            ] {
                let out = sanitize_name(&variant, '_', NameRules::Windows);
                let stem = out.split('.').next().unwrap_or("");
                assert!(
                    !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)),
                    "{variant} -> {out}"
                );
                assert!(out.contains('_'), "{variant} -> {out}");
            }
        }
        assert_eq!(
            sanitize_name("con.txt", '_', NameRules::Windows),
            "con_.txt"
        );
        assert_eq!(sanitize_name("Lpt1", '-', NameRules::Windows), "Lpt1-");
    }

    /// Hostile remote names (T91): `..`, separators, NUL, drive letters,
    /// escape sequences.
    fn hostile_name() -> impl proptest::strategy::Strategy<Value = String> {
        "(\\.|\\.\\.|/|\\\\|\0|C:|\u{1b}\\[31m|\u{1b}\\]0;x\u{7}|a|b|\\s|\u{202e}){0,12}"
    }

    proptest::proptest! {
        // A sanitized name is always exactly one plain component under the
        // target directory: it can't climb out or name the directory itself.
        #[test]
        fn sanitized_names_never_escape_the_directory(name in hostile_name()) {
            for rules in [NameRules::Unix, NameRules::Windows] {
                let out = sanitize_name(&name, '_', rules);
                proptest::prop_assert!(!out.is_empty());
                proptest::prop_assert!(out != "." && out != "..", "{:?} -> {:?}", name, out);
                proptest::prop_assert!(!out.contains('/') && !out.contains('\0'), "{:?}", out);
                if rules == NameRules::Windows {
                    proptest::prop_assert!(!out.contains('\\') && !out.contains(':'), "{:?}", out);
                    proptest::prop_assert!(!out.chars().any(char::is_control), "{:?}", out);
                }
            }
            let base = std::path::Path::new("target-dir");
            let out = sanitize_local_name(&name, '_');
            let joined = base.join(&out);
            let rest: Vec<_> = joined.strip_prefix(base).unwrap().components().collect();
            proptest::prop_assert!(
                matches!(rest[..], [std::path::Component::Normal(_)]),
                "{:?} -> {:?}",
                name,
                rest
            );
        }
    }
}
