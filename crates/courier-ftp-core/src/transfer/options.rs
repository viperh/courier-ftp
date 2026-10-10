//! Per-file transfer options (T42): safe local names for downloads.
//!
//! - [`download_name`] turns a remote file name into a local one: with
//!   `transfers.replace_invalid_chars` every character the local filesystem
//!   can't store becomes `invalid_char_replacement`
//!   ([`sanitize_local_name`]); without it only path separators, NUL and
//!   (on Windows) `:` are replaced, so a name can never point elsewhere.
//!   `.` and `..` always become `_` / `__`. Whoever builds download items
//!   (the UI, T43's recursive listing) joins names with
//!   [`download_target`].
//! - The worker checks every download target again with
//!   [`check_download_target`]: a path with a `..` component is refused and
//!   the file name is sanitized as above, so a hostile listing can't write
//!   outside the chosen directory (T91).
//!
//! Preallocation (`transfers.preallocate`) is done by the local backend from
//! [`TransferOpts::preallocate_hint`](crate::backend::TransferOpts), and
//! `transfers.preserve_timestamps` by the worker after the transfer.

use std::path::Component;

use crate::{
    Error, Result,
    local::{NameRules, sanitize_local_name, sanitize_name},
    model::LocalPath,
    settings::TransferSettings,
};

/// The local file name for the remote name `name`; see the module docs.
pub fn download_name(name: &str, settings: &TransferSettings) -> String {
    let replacement = settings.invalid_char_replacement;
    if settings.replace_invalid_chars {
        return sanitize_local_name(name, replacement);
    }
    let separators: &[char] = if cfg!(windows) {
        &['/', '\\', ':', '\0']
    } else {
        &['/', '\0']
    };
    let name: String = name
        .chars()
        .map(|c| {
            if separators.contains(&c) {
                replacement
            } else {
                c
            }
        })
        .collect();
    // Only for the empty / `.` / `..` handling; separators are gone already.
    sanitize_name(&name, replacement, NameRules::Unix)
}

/// `dir` joined with the local name for the remote name `name`. The result
/// is always a direct child of `dir`.
pub fn download_target(dir: &LocalPath, name: &str, settings: &TransferSettings) -> LocalPath {
    dir.join(download_name(name, settings))
}

/// The download target `path` made safe: an error when it has a `..`
/// component or no file name, else the path with its file name sanitized
/// ([`download_name`]). The `bool` is whether the name changed.
pub fn check_download_target(
    path: &LocalPath,
    settings: &TransferSettings,
) -> Result<(LocalPath, bool)> {
    let p = path.as_path();
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::InvalidInput(format!(
            "refusing to download to {}: the path leaves its directory",
            path.to_display()
        )));
    }
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
        return Err(Error::InvalidInput(format!(
            "{} is not a file path",
            path.to_display()
        )));
    };
    let name = name.to_string_lossy();
    let safe = download_name(&name, settings);
    if safe == name {
        Ok((path.clone(), false))
    } else {
        Ok((LocalPath::new(parent.join(safe)), true))
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use pretty_assertions::assert_eq;

    use super::*;

    fn settings(replace: bool) -> TransferSettings {
        TransferSettings {
            replace_invalid_chars: replace,
            ..TransferSettings::default()
        }
    }

    /// Hostile remote names never leave the target directory (T91).
    #[test]
    fn hostile_names_stay_in_the_target_dir() {
        let dir = std::env::temp_dir().join("courier-ftp-t42-target");
        let hostile = [
            "../x",
            "..",
            ".",
            "",
            "a/b",
            "/etc/passwd",
            "..\\..\\x",
            "C:\\Windows\\x",
            "C:x",
            "\\\\server\\share",
            "nul\0byte",
            "\u{1b}[31mred",
            "../../../../../../tmp/evil",
        ];
        for replace in [true, false] {
            let s = settings(replace);
            for name in hostile {
                let target = download_target(&LocalPath::new(&dir), name, &s);
                let path = target.as_path();
                assert_eq!(path.parent(), Some(dir.as_path()), "{name:?} ({replace})");
                assert!(
                    path.components()
                        .all(|c| !matches!(c, Component::ParentDir | Component::CurDir)),
                    "{name:?}"
                );
                let (checked, _) = check_download_target(&target, &s).unwrap();
                assert_eq!(checked.as_path().parent(), Some(dir.as_path()));
            }
        }
    }

    #[test]
    fn traversal_in_a_target_path_is_refused() {
        let s = settings(true);
        let bad = LocalPath::new(PathBuf::from("dl").join("..").join("x"));
        assert!(matches!(
            check_download_target(&bad, &s),
            Err(Error::InvalidInput(_))
        ));
        assert!(check_download_target(&LocalPath::new(Path::new("/")), &s).is_err());
    }

    #[test]
    fn invalid_characters_are_replaced_only_when_enabled() {
        let dir = LocalPath::new("dl");
        let name = if cfg!(windows) { "a?b" } else { "a\0b" };
        let (p, changed) = check_download_target(&dir.join(name), &settings(true)).unwrap();
        assert!(changed);
        assert_eq!(p, dir.join("a_b"));
        let (p, changed) = check_download_target(&dir.join("plain.txt"), &settings(true)).unwrap();
        assert!(!changed);
        assert_eq!(p, dir.join("plain.txt"));
        // Characters that are only invalid on Windows stay without the option.
        assert_eq!(download_name("a?b", &settings(false)), "a?b");
        let mut custom = settings(true);
        custom.invalid_char_replacement = '-';
        assert_eq!(download_name("a/b", &custom), "a-b");
    }
}
