//! Mapping between [`RemotePath`] and native local paths.
//!
//! - **Unix**: the same string. `/home/me` is `/home/me`.
//! - **Windows**: `/` is a virtual root whose entries are the drives;
//!   `/C:/Users/me` is `C:\Users\me`; `/UNC/server/share/dir` is
//!   `\\server\share\dir`.
//!
//! Non-UTF-8 local names are converted lossily; such files are listed but
//! can't be operated on.

use std::path::{Path, PathBuf};

use crate::{Error, Result, model::RemotePath};

/// The native path for `path`, or `None` for the virtual root on Windows.
pub fn remote_to_local(path: &RemotePath) -> Option<PathBuf> {
    if cfg!(windows) {
        windows_remote_to_local(path.as_str()).map(PathBuf::from)
    } else {
        Some(PathBuf::from(path.as_str()))
    }
}

/// The [`RemotePath`] for an absolute native path.
pub fn local_to_remote(path: &Path) -> Result<RemotePath> {
    let s = path.to_string_lossy();
    if cfg!(windows) {
        windows_local_to_remote(&s)
    } else if path.is_absolute() {
        Ok(RemotePath::new(&*s))
    } else {
        Err(Error::InvalidInput(format!(
            "`{s}` is not an absolute path"
        )))
    }
}

/// The path as the user expects to see it (native separators).
pub fn display_native(path: &RemotePath) -> String {
    match remote_to_local(path) {
        Some(p) => p.display().to_string(),
        None => String::new(),
    }
}

/// Windows mapping, `RemotePath` → native, as plain strings (testable on any OS).
pub(crate) fn windows_remote_to_local(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [] => None,
        ["UNC", server, share, rest @ ..] => {
            let mut s = format!(r"\\{server}\{share}");
            for p in rest {
                s.push('\\');
                s.push_str(p);
            }
            Some(s)
        }
        [drive, rest @ ..] => {
            let mut s = format!(r"{drive}\");
            s.push_str(&rest.join(r"\"));
            Some(s)
        }
    }
}

/// Windows mapping, native → `RemotePath`, as plain strings.
pub(crate) fn windows_local_to_remote(path: &str) -> Result<RemotePath> {
    let mut path = path.replace('\\', "/");
    // Verbatim disk paths (`\\?\C:\…`, what `canonicalize` returns).
    if let Some(rest) = path.strip_prefix("//?/")
        && rest.as_bytes().get(1) == Some(&b':')
    {
        path = rest.to_owned();
    }
    if let Some(rest) = path.strip_prefix("//") {
        let rest = rest.strip_prefix("?/UNC/").unwrap_or(rest);
        return Ok(RemotePath::new(format!("/UNC/{rest}")));
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = path[..1].to_ascii_uppercase();
        return Ok(RemotePath::new(format!("/{drive}:{}", &path[2..])));
    }
    Err(Error::InvalidInput(format!(
        "`{path}` is not an absolute Windows path"
    )))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn windows_mapping() {
        let cases = [
            ("/C:", r"C:\"),
            ("/C:/Users/me", r"C:\Users\me"),
            ("/D:/a b/ü", r"D:\a b\ü"),
            ("/UNC/server/share", r"\\server\share"),
            ("/UNC/server/share/dir/f.txt", r"\\server\share\dir\f.txt"),
        ];
        for (remote, local) in cases {
            assert_eq!(
                windows_remote_to_local(remote).as_deref(),
                Some(local),
                "{remote}"
            );
            assert_eq!(
                windows_local_to_remote(local).unwrap().as_str(),
                remote,
                "{local}"
            );
        }
        assert_eq!(windows_remote_to_local("/"), None);
        assert_eq!(windows_local_to_remote(r"c:\x").unwrap().as_str(), "/C:/x");
        assert_eq!(
            windows_local_to_remote(r"\\?\UNC\srv\sh\x")
                .unwrap()
                .as_str(),
            "/UNC/srv/sh/x"
        );
        assert_eq!(
            windows_local_to_remote(r"\\?\C:\Temp\x").unwrap().as_str(),
            "/C:/Temp/x"
        );
        assert!(windows_local_to_remote(r"relative\x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_mapping_is_identity() {
        let r = RemotePath::new("/home/me/a b");
        assert_eq!(remote_to_local(&r), Some(PathBuf::from("/home/me/a b")));
        assert_eq!(local_to_remote(Path::new("/home/me/a b")).unwrap(), r);
        assert!(local_to_remote(Path::new("relative")).is_err());
        assert_eq!(display_native(&r), "/home/me/a b");
    }
}
