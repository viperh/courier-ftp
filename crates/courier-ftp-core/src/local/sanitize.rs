//! File name sanitising for downloads (T42 "replace invalid characters", T91 path
//! traversal mitigation).

/// Characters Windows does not allow in file names (besides control characters).
const WINDOWS_INVALID: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Windows reserved device names (compared case-insensitively on the part before the
/// first '.').
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM¹", "COM²",
    "COM³", "LPT¹", "LPT²", "LPT³",
];

/// Which rules to apply (both tables are testable on every OS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rules {
    Unix,
    Windows,
}

const HOST: Rules = if cfg!(windows) {
    Rules::Windows
} else {
    Rules::Unix
};

fn is_invalid_char(c: char, rules: Rules) -> bool {
    c.is_ascii_control()
        || match rules {
            Rules::Unix => c == '/',
            Rules::Windows => WINDOWS_INVALID.contains(&c),
        }
}

fn is_reserved(stem: &str) -> bool {
    let upper = stem.to_uppercase();
    WINDOWS_RESERVED.contains(&upper.as_str())
}

/// The replacement actually used: T05 validates the setting, but an unsafe character
/// (control, separator, '.', ' ') falls back to '_' so the guarantees hold for any input.
fn safe_replacement(replacement: char, rules: Rules) -> char {
    if is_invalid_char(replacement, rules) || replacement == '.' || replacement == ' ' {
        '_'
    } else {
        replacement
    }
}

fn sanitize_with(name: &str, replacement: char, rules: Rules) -> String {
    let r = safe_replacement(replacement, rules);
    let mut out: String = name
        .chars()
        .map(|c| if is_invalid_char(c, rules) { r } else { c })
        .collect();
    if rules == Rules::Windows {
        // Windows silently strips trailing dots and spaces.
        let kept = out.trim_end_matches(['.', ' ']).len();
        let trailing = out[kept..].chars().count();
        out.truncate(kept);
        out.extend(std::iter::repeat_n(r, trailing));
        let stem_end = out.find('.').unwrap_or(out.len());
        if is_reserved(&out[..stem_end]) {
            out.insert(stem_end, r);
        }
    }
    match out.as_str() {
        "" | "." => r.to_string(),
        ".." => [r, r].iter().collect(),
        _ => out,
    }
}

/// Makes `name` valid as one file name on this OS (T42 "replace invalid characters").
///
/// Replaces C0 control characters and DEL everywhere, `/` on Unix, and
/// `< > : " / \ | ? *` on Windows with `replacement`. On Windows, trailing dots and
/// spaces are replaced too, and reserved device names (`CON`, `com1.txt`, …) get the
/// replacement appended to the part before the first '.'. Never returns `""`, `"."`,
/// `".."`, or a name containing a separator. Names longer than 255 bytes are not
/// shortened.
///
/// `replacement` should be a character that is valid in file names (T05 validates the
/// setting); an invalid one (control, separator, '.', ' ') is replaced by '_'.
pub fn sanitize_local_name(name: &str, replacement: char) -> String {
    sanitize_with(name, replacement, HOST)
}

/// True if `name` needs no change on this OS (`sanitize_local_name(name, _) == name`).
pub fn is_valid_local_name(name: &str) -> bool {
    sanitize_with(name, '_', HOST) == name
}

/// Fuzz body of the `remote_name_sanitize` target (T91 §7), also run by a property
/// test: for any input the result is non-empty, not "."/"..", has no separator, NUL or
/// control character and (on Windows) is not a reserved device name. Panics otherwise.
#[doc(hidden)]
pub fn fuzz_sanitize_local_name(data: &[u8]) {
    let name = String::from_utf8_lossy(data);
    let replacement = data
        .first()
        .map(|&b| char::from(b))
        .filter(|c| c.is_ascii_graphic())
        .unwrap_or('_');
    for r in [replacement, '_'] {
        let out = sanitize_local_name(&name, r);
        assert!(!out.is_empty(), "empty result for {name:?}");
        assert!(out != "." && out != "..", "{out:?} for {name:?}");
        assert!(
            !out.chars().any(|c| std::path::is_separator(c) || c == '/'),
            "separator in {out:?}"
        );
        assert!(
            !out.chars().any(|c| c.is_ascii_control()),
            "control in {out:?}"
        );
        assert!(is_valid_local_name(&out), "not stable: {out:?}");
        #[cfg(windows)]
        {
            let stem = out.split('.').next().unwrap_or_default();
            assert!(!is_reserved(stem), "reserved name {out:?}");
            assert!(!out.ends_with(['.', ' ']), "trailing dot/space in {out:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn unix(name: &str) -> String {
        sanitize_with(name, '_', Rules::Unix)
    }

    fn win(name: &str) -> String {
        sanitize_with(name, '_', Rules::Windows)
    }

    fn check_unix_table() {
        for (input, want) in [
            ("a/b", "a_b"),
            ("a\0b", "a_b"),
            ("con.txt", "con.txt"),
            ("..", "__"),
            (".", "_"),
            ("", "_"),
            ("a\\b:c", "a\\b:c"),
            ("name. ", "name. "),
            (".hidden", ".hidden"),
        ] {
            assert_eq!(unix(input), want, "{input:?}");
        }
    }

    fn check_windows_table() {
        for c in WINDOWS_INVALID {
            assert_eq!(win(&format!("a{c}b")), "a_b", "{c:?}");
        }
        for (input, want) in [
            ("\x01", "_"),
            ("name. ", "name__"),
            ("name...", "name___"),
            ("CON", "CON_"),
            ("con.tar.gz", "con_.tar.gz"),
            ("con.txt", "con_.txt"),
            ("Com1", "Com1_"),
            ("lpt9.log", "lpt9_.log"),
            ("LPT¹", "LPT¹_"),
            ("com³.x", "com³_.x"),
            ("nul", "nul_"),
            ("aux.", "aux_"),
            ("CONSOLE", "CONSOLE"),
            ("COM0", "COM0"),
            ("COM10", "COM10"),
            ("..", "__"),
            (".", "_"),
            ("", "_"),
            (" ", "_"),
            (".hidden", ".hidden"),
        ] {
            assert_eq!(win(input), want, "{input:?}");
        }
        for name in WINDOWS_RESERVED {
            for variant in [name.to_string(), name.to_lowercase()] {
                assert_eq!(win(&variant), format!("{variant}_"));
                assert_eq!(win(&format!("{variant}.txt")), format!("{variant}_.txt"));
            }
        }
    }

    #[test]
    fn sanitize_unix_table() {
        check_unix_table();
        if HOST == Rules::Unix {
            assert_eq!(sanitize_local_name("a/b", '_'), "a_b");
            assert!(is_valid_local_name("con.txt"));
            assert!(!is_valid_local_name(""));
        }
    }

    /// The Windows rules are pure logic; the table runs on every OS.
    #[test]
    fn sanitize_windows_rules_table() {
        check_windows_table();
    }

    #[cfg(windows)]
    #[test]
    fn sanitize_windows_table() {
        check_windows_table();
        assert_eq!(sanitize_local_name("CON", '_'), "CON_");
        assert_eq!(sanitize_local_name("name. ", '_'), "name__");
        assert!(!is_valid_local_name("a:b"));
    }

    #[test]
    fn sanitize_replaces_control_chars_everywhere() {
        for rules in [Rules::Unix, Rules::Windows] {
            assert_eq!(sanitize_with("a\x1b[31mb", '_', rules), "a_[31mb");
            assert_eq!(sanitize_with("\x7f", '_', rules), "_");
            assert_eq!(sanitize_with("a\nb\tc", '_', rules), "a_b_c");
        }
        assert_eq!(sanitize_local_name("\x7f", '_'), "_");
    }

    #[test]
    fn unsafe_replacement_falls_back_to_underscore() {
        assert_eq!(sanitize_with("a/b", '/', Rules::Unix), "a_b");
        assert_eq!(sanitize_with("..", '.', Rules::Unix), "__");
        assert_eq!(sanitize_with("a:b", '?', Rules::Windows), "a_b");
        assert_eq!(sanitize_with("a/b", '-', Rules::Unix), "a-b");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn prop_sanitized_name_is_valid(name in any::<String>(), r in any::<char>()) {
            fuzz_sanitize_local_name(name.as_bytes());
            let out = sanitize_local_name(&name, r);
            prop_assert!(is_valid_local_name(&out));
            prop_assert!(!out.is_empty() && out != "." && out != "..");
            prop_assert!(!out.chars().any(|c| c.is_ascii_control()));
            // The Windows rules hold on every OS as pure logic.
            let w = sanitize_with(&name, r, Rules::Windows);
            prop_assert_eq!(sanitize_with(&w, '_', Rules::Windows), w.clone());
            let stem = w.split('.').next().unwrap_or_default();
            prop_assert!(!is_reserved(stem));
            prop_assert!(!w.ends_with(['.', ' ']));
        }

        /// T91 AC9: a hostile name cannot leave the target directory.
        #[test]
        fn prop_sanitized_name_stays_inside_target(name in any::<String>()) {
            let target = crate::model::LocalPath::new(std::env::temp_dir().join("courier-target"));
            let joined = target.join(&sanitize_local_name(&name, '_'));
            let joined = match joined {
                Ok(j) => j,
                Err(e) => return Err(TestCaseError::fail(format!("join failed: {e}"))),
            };
            prop_assert_eq!(joined.parent(), Some(target.clone()));
            prop_assert!(joined.as_path().starts_with(target.as_path()));
            prop_assert_eq!(
                joined.as_path().components().count(),
                target.as_path().components().count() + 1
            );
        }
    }

    #[test]
    fn fuzz_body_accepts_seeds() {
        for seed in [
            &b"report.txt"[..],
            b"../../etc/passwd",
            b"CON.txt",
            b"a\x00b\x1fc",
            b"",
            b"\xff\xfe",
            b".",
            b"..",
        ] {
            fuzz_sanitize_local_name(seed);
        }
    }
}
