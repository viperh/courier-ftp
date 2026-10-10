//! The single mapping between the [`Backend`](crate::backend::Backend) trait's
//! '/'-paths ([`RemotePath`]) and native paths ([`LocalPath`]).
//!
//! - Unix: identity (`"/home/u"` ↔ `/home/u`).
//! - Windows: `"/"` is a virtual root (the drive list); `"/C:/Users/u"` ↔
//!   `C:\Users\u`; `"/UNC/server/share/dir"` ↔ `\\server\share\dir`. Verbatim paths
//!   (`\\?\C:\x`, `\\?\UNC\srv\share`) map to the same forms.
//!
//! Windows names cannot contain '/', so the mapping is lossless; on Unix a name
//! containing '\\' is just a character.

use std::path::Path;

use crate::model::{LocalPath, RemotePath};
use crate::{Error, Result};

/// Maps a trait path to the native path.
///
/// Unix: identity. Windows: see the [module docs](self).
///
/// # Errors
///
/// Windows only: `InvalidInput` for `"/"` itself (the virtual drive list, not a real
/// path), for `"/X"` where `X` is neither a drive (`"C:"`) nor `"UNC"`, for a UNC path
/// without server and share, and for components containing '\\'.
pub fn to_native(path: &RemotePath) -> Result<LocalPath> {
    #[cfg(windows)]
    {
        windows_native_string(path).map(LocalPath::new)
    }
    #[cfg(not(windows))]
    {
        Ok(LocalPath::new(path.as_str()))
    }
}

/// Maps a native path to the trait path (inverse of [`to_native`]).
///
/// # Errors
///
/// `InvalidInput` for relative paths, non-UTF-8 paths and (Windows) verbatim prefixes
/// other than `\\?\C:\` and `\\?\UNC\`.
pub fn from_native(path: &Path) -> Result<RemotePath> {
    #[cfg(windows)]
    {
        from_native_windows(path)
    }
    #[cfg(not(windows))]
    {
        if !path.is_absolute() {
            return Err(Error::InvalidInput(format!(
                "path is not absolute: \"{}\"",
                path.display()
            )));
        }
        let Some(s) = path.to_str() else {
            return Err(Error::InvalidInput(format!(
                "path is not valid UTF-8: \"{}\"",
                path.display()
            )));
        };
        RemotePath::parse(s)
    }
}

/// True if `c` is a drive component (`"C:"`).
#[cfg_attr(not(windows), allow(dead_code))]
fn is_drive(c: &str) -> bool {
    let b = c.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// The Windows native spelling of `path` (pure string logic, testable on every OS).
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_native_string(path: &RemotePath) -> Result<String> {
    let comps: Vec<&str> = path.components().collect();
    if let Some(bad) = comps.iter().find(|c| c.contains('\\')) {
        return Err(Error::InvalidInput(format!(
            "file name contains '\\': \"{}\"",
            bad.escape_debug()
        )));
    }
    match comps.split_first() {
        None => Err(Error::InvalidInput(
            "\"/\" is the drive list, not a folder".into(),
        )),
        Some((first, rest)) if is_drive(first) => {
            let mut s = format!("{}:\\", first[..1].to_ascii_uppercase());
            s.push_str(&rest.join("\\"));
            Ok(s)
        }
        Some((&"UNC", rest)) if rest.len() >= 2 => Ok(format!("\\\\{}", rest.join("\\"))),
        Some((&"UNC", _)) => Err(Error::InvalidInput(
            "a UNC path needs a server and a share (/UNC/server/share)".into(),
        )),
        Some((first, _)) => Err(Error::InvalidInput(format!(
            "\"/{}\" is not a drive (\"/C:\") or \"/UNC\"",
            first.escape_debug()
        ))),
    }
}

#[cfg(windows)]
fn from_native_windows(path: &Path) -> Result<RemotePath> {
    use std::path::{Component, Prefix};

    let invalid = |why: &str| Error::InvalidInput(format!("{why}: \"{}\"", path.display()));
    let mut comps = path.components();
    let mut stack: Vec<String> = match comps.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                vec![format!("{}:", char::from(d).to_ascii_uppercase())]
            }
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                let server = server
                    .to_str()
                    .ok_or_else(|| invalid("path is not valid UTF-8"))?;
                let share = share
                    .to_str()
                    .ok_or_else(|| invalid("path is not valid UTF-8"))?;
                vec!["UNC".into(), server.into(), share.into()]
            }
            Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
                return Err(invalid("unsupported path prefix"));
            }
        },
        _ => return Err(invalid("path is not absolute")),
    };
    let base = stack.len();
    if !path.has_root() {
        return Err(invalid("path is not absolute"));
    }
    for c in comps {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if stack.len() > base {
                    stack.pop();
                }
            }
            Component::Normal(n) => {
                let n = n
                    .to_str()
                    .ok_or_else(|| invalid("path is not valid UTF-8"))?;
                stack.push(n.to_owned());
            }
            Component::Prefix(_) => return Err(invalid("unexpected path prefix")),
        }
    }
    RemotePath::root().join_all(stack.iter().map(String::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> RemotePath {
        RemotePath::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[cfg(unix)]
    #[test]
    fn path_map_unix_identity() {
        let p = rp("/a b/c");
        let native = to_native(&p).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(native.as_path(), Path::new("/a b/c"));
        assert_eq!(from_native(native.as_path()).ok(), Some(p));
        assert_eq!(from_native(Path::new("/")).ok(), Some(RemotePath::root()));
        assert_eq!(from_native(Path::new("/x\\y")).ok(), Some(rp("/x\\y")));
        assert!(matches!(
            from_native(Path::new("rel/x")),
            Err(Error::InvalidInput(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn from_native_rejects_non_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let p = Path::new(OsStr::from_bytes(b"/bad\xff"));
        assert!(matches!(from_native(p), Err(Error::InvalidInput(_))));
    }

    /// The Windows string mapping is pure logic, so it is checked on every OS.
    #[test]
    fn windows_native_string_table() {
        let ok = |s: &str| windows_native_string(&rp(s)).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(ok("/C:/Users/u"), "C:\\Users\\u");
        assert_eq!(ok("/c:"), "C:\\");
        assert_eq!(ok("/UNC/srv/share/d"), "\\\\srv\\share\\d");
        assert_eq!(ok("/UNC/srv/share"), "\\\\srv\\share");
        for bad in ["/", "/foo", "/UNC", "/UNC/srv", "/C:/a\\..\\b", "/CC:"] {
            assert!(
                matches!(windows_native_string(&rp(bad)), Err(Error::InvalidInput(_))),
                "{bad}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn path_map_windows_drives_and_unc() {
        let to = |s: &str| to_native(&rp(s)).unwrap_or_else(|e| panic!("{s}: {e}"));
        let from = |s: &str| from_native(Path::new(s)).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(to("/C:/Users/u").as_path(), Path::new("C:\\Users\\u"));
        assert_eq!(from("C:\\Users\\u"), rp("/C:/Users/u"));
        assert_eq!(
            to("/UNC/srv/share/d").as_path(),
            Path::new("\\\\srv\\share\\d")
        );
        assert_eq!(from("\\\\srv\\share\\d"), rp("/UNC/srv/share/d"));
        assert_eq!(from("\\\\?\\C:\\x"), rp("/C:/x"));
        assert_eq!(from("\\\\?\\UNC\\srv\\share\\d"), rp("/UNC/srv/share/d"));
        assert_eq!(from("C:\\a\\..\\..\\b"), rp("/C:/b"));
        assert!(matches!(
            to_native(&rp("/foo")),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(to_native(&rp("/")), Err(Error::InvalidInput(_))));
        for bad in ["rel\\x", "C:rel", "\\\\?\\GLOBALROOT\\x", "\\\\.\\pipe\\x"] {
            assert!(
                matches!(from_native(Path::new(bad)), Err(Error::InvalidInput(_))),
                "{bad}"
            );
        }
    }
}
