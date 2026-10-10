//! Translation between [`RemotePath`] (always `/`-separated) and the
//! server's own path syntax (T14).
//!
//! - **Unix**: unchanged.
//! - **DOS/Windows** (`PWD` gives `C:\dir` or `\dir`): `/C:/dir` ↔ `C:\dir`,
//!   `/dir` ↔ `\dir`.
//! - **VMS** (`DISK$USER:[BOB.SUB]`): `/DISK$USER/BOB/SUB`; the first
//!   component is the device, `[000000]` is the device's root.
//! - **MVS** (best effort, `'HLQ.DATA.'`): `/HLQ/DATA` ↔ `'HLQ.DATA.'`.
//!
//! For VMS and MVS, commands on files go to the parent directory with `CWD`
//! and use the bare file name (see `FtpBackend`); Unix and DOS servers get
//! full paths.

use courier_ftp_core::model::{PathStyle, RemotePath};

/// The server's path style from its `PWD` reply and `SYST`.
pub fn detect_style(pwd: &str, syst: Option<&str>) -> PathStyle {
    let syst = syst.unwrap_or_default().to_ascii_uppercase();
    if pwd.starts_with('/') {
        PathStyle::Unix
    } else if pwd.contains(":[") || (pwd.starts_with('[') && pwd.ends_with(']')) {
        PathStyle::Vms
    } else if pwd.starts_with('\'') || syst.starts_with("MVS") || syst.contains("Z/OS") {
        PathStyle::Mvs
    } else if pwd.starts_with('\\') || pwd.as_bytes().get(1) == Some(&b':') {
        PathStyle::Dos
    } else {
        PathStyle::Unix
    }
}

/// A server path (from `PWD`, `257`) as a [`RemotePath`].
pub fn from_server(path: &str, style: PathStyle) -> RemotePath {
    match style {
        PathStyle::Unix => RemotePath::new(path),
        PathStyle::Dos => RemotePath::new(path.replace('\\', "/")),
        PathStyle::Vms => {
            let (device, rest) = match path.split_once(":[") {
                Some((d, r)) => (Some(d), r),
                None => (None, path.trim_start_matches('[')),
            };
            let dirs = rest.split(']').next().unwrap_or_default();
            let mut out = String::new();
            if let Some(d) = device {
                out.push('/');
                out.push_str(d);
            }
            for part in dirs.split('.').filter(|p| !p.is_empty() && *p != "000000") {
                out.push('/');
                out.push_str(part);
            }
            RemotePath::new(out)
        }
        PathStyle::Mvs => {
            let inner = path.trim_matches('\'');
            RemotePath::new(
                inner
                    .split('.')
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        }
    }
}

/// A directory in server syntax, for `CWD`.
pub fn dir_to_server(dir: &RemotePath, style: PathStyle) -> String {
    match style {
        PathStyle::Unix => dir.as_str().to_owned(),
        PathStyle::Dos => dos(dir, true),
        PathStyle::Vms => {
            let mut parts = dir.components();
            match parts.next() {
                None => "[000000]".to_owned(),
                Some(device) => {
                    let rest: Vec<&str> = parts.collect();
                    if rest.is_empty() {
                        format!("{device}:[000000]")
                    } else {
                        format!("{device}:[{}]", rest.join("."))
                    }
                }
            }
        }
        PathStyle::Mvs => {
            let parts: Vec<&str> = dir.components().collect();
            format!("'{}.'", parts.join("."))
        }
    }
}

/// A file path in server syntax (Unix and DOS servers).
pub fn file_to_server(path: &RemotePath, style: PathStyle) -> String {
    match style {
        PathStyle::Dos => dos(path, false),
        _ => path.as_str().to_owned(),
    }
}

fn dos(path: &RemotePath, dir: bool) -> String {
    let parts: Vec<&str> = path.components().collect();
    match parts.split_first() {
        None => "\\".to_owned(),
        Some((first, rest)) if first.len() == 2 && first.ends_with(':') => {
            if rest.is_empty() && dir {
                format!("{first}\\")
            } else {
                format!("{first}\\{}", rest.join("\\"))
            }
        }
        Some(_) => format!("\\{}", parts.join("\\")),
    }
}

/// Whether file commands should use a bare name after `CWD` to the parent
/// (VMS and MVS) instead of a full path.
pub fn uses_cwd_for_files(style: PathStyle) -> bool {
    matches!(style, PathStyle::Vms | PathStyle::Mvs)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn detection() {
        assert_eq!(
            detect_style("/home/bob", Some("UNIX Type: L8")),
            PathStyle::Unix
        );
        assert_eq!(
            detect_style("C:\\Users\\bob", Some("Windows_NT")),
            PathStyle::Dos
        );
        assert_eq!(detect_style("\\pub", None), PathStyle::Dos);
        assert_eq!(
            detect_style("DISK$USER:[BOB.SUB]", Some("VMS")),
            PathStyle::Vms
        );
        assert_eq!(
            detect_style("'BOB.'", Some("MVS is the operating system")),
            PathStyle::Mvs
        );
        assert_eq!(detect_style("/", Some("Windows_NT")), PathStyle::Unix);
    }

    #[test]
    fn round_trips() {
        let cases = [
            (PathStyle::Unix, "/home/bob", "/home/bob"),
            (PathStyle::Dos, "C:\\Users\\bob", "/C:/Users/bob"),
            (PathStyle::Dos, "\\pub\\files", "/pub/files"),
            (PathStyle::Vms, "DISK$USER:[BOB.SUB]", "/DISK$USER/BOB/SUB"),
            (PathStyle::Mvs, "'BOB.DATA.'", "/BOB/DATA"),
        ];
        for (style, server, remote) in cases {
            let path = from_server(server, style);
            assert_eq!(path.as_str(), remote, "{server}");
            assert_eq!(dir_to_server(&path, style), server, "{remote}");
        }
        assert_eq!(
            dir_to_server(&RemotePath::new("/C:"), PathStyle::Dos),
            "C:\\"
        );
        assert_eq!(
            from_server("DISK$USER:[000000]", PathStyle::Vms).as_str(),
            "/DISK$USER"
        );
        assert_eq!(
            dir_to_server(&RemotePath::new("/DISK$USER"), PathStyle::Vms),
            "DISK$USER:[000000]"
        );
        assert_eq!(
            file_to_server(&RemotePath::new("/C:/a/b.txt"), PathStyle::Dos),
            "C:\\a\\b.txt"
        );
        assert!(uses_cwd_for_files(PathStyle::Vms));
        assert!(!uses_cwd_for_files(PathStyle::Dos));
    }
}
