//! Remote and local paths ([`RemotePath`], [`LocalPath`]) and how servers spell paths
//! ([`PathStyle`], [`ServerTypeOverride`]).

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Maximum length of a normalised [`RemotePath`] in bytes.
const MAX_REMOTE_PATH_LEN: usize = 4096;

/// How many characters of an offending path an error message echoes.
const ERROR_ECHO_CHARS: usize = 200;

/// An absolute, normalised, '/'-separated path on a server (or on the local side when it
/// goes through the Backend trait, see T06).
///
/// Invariants (enforced by every constructor):
/// - starts with '/'; no empty components; no "." or ".." components;
/// - no trailing '/' except the root "/";
/// - components never contain '/' or NUL; any other character is allowed, including
///   spaces (leading/trailing), '\\', ':', control characters and non-ASCII.
///
/// Servers with other path syntaxes (VMS `DISK:[DIR]FILE`, MVS datasets, DOS `C:\`) are
/// still represented in this Unix form; the FTP crate translates when it sends commands
/// (T14) using the session's [`PathStyle`].
/// Callers rendering a RemotePath in the terminal must escape control characters (T53/T55).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RemotePath(String);

/// Escapes (and shortens) path text for an error message, so control characters cannot
/// reach the terminal through it.
fn echo(s: &str) -> String {
    let mut out: String = s
        .chars()
        .take(ERROR_ECHO_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if s.chars().nth(ERROR_ECHO_CHARS).is_some() {
        out.push('…');
    }
    out
}

/// Pushes the components of `input` onto `stack`, applying "." and "..".
fn push_components<'a>(stack: &mut Vec<&'a str>, input: &'a str) {
    for c in input.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            c => stack.push(c),
        }
    }
}

/// Builds a path from already validated components and checks the length limit.
fn from_components(stack: &[&str]) -> Result<RemotePath> {
    let mut s = String::with_capacity(stack.iter().map(|c| c.len() + 1).sum::<usize>().max(1));
    for c in stack {
        s.push('/');
        s.push_str(c);
    }
    if s.is_empty() {
        s.push('/');
    }
    if s.len() > MAX_REMOTE_PATH_LEN {
        return Err(Error::InvalidInput(format!(
            "path is longer than {MAX_REMOTE_PATH_LEN} bytes: \"{}\"",
            echo(&s)
        )));
    }
    Ok(RemotePath(s))
}

fn check_no_nul(s: &str) -> Result<()> {
    if s.contains('\0') {
        return Err(Error::InvalidInput(format!(
            "path contains NUL: \"{}\"",
            echo(s)
        )));
    }
    Ok(())
}

/// Validates one path component (shared by `RemotePath::join` and `LocalPath::join`).
fn check_component(name: &str) -> Result<()> {
    match name {
        "" => Err(Error::InvalidInput("empty file name".into())),
        "." | ".." => Err(Error::InvalidInput(format!("invalid file name \"{name}\""))),
        _ if name.contains('/') => Err(Error::InvalidInput(format!(
            "file name contains '/': \"{}\"",
            echo(name)
        ))),
        _ if name.contains('\0') => Err(Error::InvalidInput(format!(
            "file name contains NUL: \"{}\"",
            echo(name)
        ))),
        _ => Ok(()),
    }
}

impl RemotePath {
    /// The root directory "/".
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    /// Parses an absolute path and normalises it (empty and "." components dropped, ".."
    /// pops one component and is ignored at the root).
    ///
    /// Errors: `InvalidInput` for "", relative input, NUL, or more than 4096 bytes after
    /// normalisation.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::InvalidInput("empty path".into()));
        }
        check_no_nul(s)?;
        if !s.starts_with('/') {
            return Err(Error::InvalidInput(format!(
                "path is not absolute: \"{}\"",
                echo(s)
            )));
        }
        let mut stack = Vec::new();
        push_components(&mut stack, s);
        from_components(&stack)
    }

    /// Resolves `input` (absolute, or relative to `self`; may contain "." and "..") —
    /// the address bar and CWD. `resolve("")` returns `self`.
    ///
    /// Errors: as [`RemotePath::parse`].
    pub fn resolve(&self, input: &str) -> Result<Self> {
        if input.is_empty() {
            return Ok(self.clone());
        }
        if input.starts_with('/') {
            return Self::parse(input);
        }
        check_no_nul(input)?;
        let mut stack: Vec<&str> = self.components().collect();
        push_components(&mut stack, input);
        from_components(&stack)
    }

    /// Appends one component.
    ///
    /// Errors: `InvalidInput` if `name` is empty, ".", "..", contains '/' or NUL, or the
    /// result is longer than 4096 bytes.
    pub fn join(&self, name: &str) -> Result<Self> {
        self.join_all([name])
    }

    /// Appends several components (each validated like [`RemotePath::join`]).
    pub fn join_all<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        let mut stack: Vec<&str> = self.components().collect();
        for name in names {
            check_component(name)?;
            stack.push(name);
        }
        from_components(&stack)
    }

    /// The parent directory; `None` for the root.
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let idx = self.0.rfind('/')?;
        if idx == 0 {
            Some(Self::root())
        } else {
            Some(Self(self.0[..idx].to_owned()))
        }
    }

    /// The last component; `None` for the root.
    pub fn file_name(&self) -> Option<&str> {
        self.components().next_back()
    }

    /// The components from the root down (none for the root).
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> + '_ {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// Number of components; the root has depth 0.
    pub fn depth(&self) -> usize {
        self.components().count()
    }

    /// True for "/".
    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// Component-wise prefix test ("/ab" does not start with "/a"). Every path starts
    /// with the root and with itself.
    pub fn starts_with(&self, base: &RemotePath) -> bool {
        self.strip_prefix(base).is_some()
    }

    /// Components of `self` below `base`, or `None` if `self` is not under `base`
    /// (T49, T66). Empty when `self == base`.
    pub fn strip_prefix(&self, base: &RemotePath) -> Option<Vec<&str>> {
        let mut mine = self.components();
        for b in base.components() {
            if mine.next()? != b {
                return None;
            }
        }
        Some(mine.collect())
    }

    /// The path as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RemotePath {
    /// The raw path string (not escaped).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RemotePath {
    /// `RemotePath("/a/b")`, with control characters escaped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RemotePath").field(&self.0).finish()
    }
}

impl FromStr for RemotePath {
    type Err = Error;

    /// Same as [`RemotePath::parse`].
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl TryFrom<String> for RemotePath {
    type Error = Error;

    /// Same as [`RemotePath::parse`] (used by serde, so invalid paths fail to load).
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl From<RemotePath> for String {
    fn from(p: RemotePath) -> Self {
        p.0
    }
}

/// A local filesystem path. A newtype so local and remote paths cannot be mixed up.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalPath(PathBuf);

impl LocalPath {
    /// Wraps a path as given (not normalised, not checked).
    pub fn new(p: impl Into<PathBuf>) -> Self {
        Self(p.into())
    }

    /// Borrows the inner path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Unwraps the inner path.
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Appends one component; same rejection rules as [`RemotePath::join`], plus any
    /// platform separator ('\\' on Windows) and, on Windows, a drive prefix ("C:"). Safe
    /// for names received from servers (path traversal, T91).
    ///
    /// Errors: `InvalidInput`.
    pub fn join(&self, name: &str) -> Result<Self> {
        check_component(name)?;
        if name.chars().any(std::path::is_separator) {
            return Err(Error::InvalidInput(format!(
                "file name contains a path separator: \"{}\"",
                echo(name)
            )));
        }
        #[cfg(windows)]
        {
            let b = name.as_bytes();
            if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                return Err(Error::InvalidInput(format!(
                    "file name has a drive prefix: \"{}\"",
                    echo(name)
                )));
            }
        }
        Ok(Self(self.0.join(name)))
    }

    /// The parent directory, if any.
    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|p| Self(p.to_path_buf()))
    }

    /// The last component, if any.
    pub fn file_name(&self) -> Option<&OsStr> {
        self.0.file_name()
    }

    /// Native separators; the home directory prefix shown as "~" ("~/projects",
    /// "~\\Desktop"). The home directory comes from `directories::BaseDirs`.
    pub fn to_display(&self) -> String {
        let base = directories::BaseDirs::new();
        self.display_with_home(base.as_ref().map(directories::BaseDirs::home_dir))
    }

    /// [`LocalPath::to_display`] with an explicit home directory (testable variant).
    /// The prefix test is component-wise ("/home/user2" is not under "/home/u").
    pub fn display_with_home(&self, home: Option<&Path>) -> String {
        if let Some(rest) = home.and_then(|h| self.0.strip_prefix(h).ok()) {
            if rest.as_os_str().is_empty() {
                return "~".to_owned();
            }
            return format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display());
        }
        self.0.display().to_string()
    }
}

/// How a server spells paths. Detected by the FTP crate (SYST + listing), forced by
/// [`ServerTypeOverride`]. SFTP and local backends are always `Unix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PathStyle {
    /// `/dir/file`.
    #[default]
    Unix,
    /// `C:\dir\file`.
    Dos,
    /// `DISK:[DIR]FILE;1`.
    Vms,
    /// MVS datasets (`'HLQ.DATA.SET'`).
    Mvs,
}

/// Site Manager "Server type" (T31 Advanced tab).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ServerTypeOverride {
    /// Detect the path style (SYST + listing).
    #[default]
    Auto,
    /// Force [`PathStyle::Unix`].
    Unix,
    /// Force [`PathStyle::Dos`].
    Dos,
    /// Force [`PathStyle::Vms`].
    Vms,
    /// Force [`PathStyle::Mvs`].
    Mvs,
}

impl ServerTypeOverride {
    /// The forced path style; `None` for `Auto`.
    pub fn path_style(self) -> Option<PathStyle> {
        match self {
            Self::Auto => None,
            Self::Unix => Some(PathStyle::Unix),
            Self::Dos => Some(PathStyle::Dos),
            Self::Vms => Some(PathStyle::Vms),
            Self::Mvs => Some(PathStyle::Mvs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> RemotePath {
        RemotePath::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    #[test]
    fn remote_path_normalisation_table() {
        let long = format!("/{}", "a".repeat(4096));
        let max = format!("/{}", "a".repeat(4095));
        let rows: Vec<(&str, Option<&str>)> = vec![
            ("/", Some("/")),
            ("//", Some("/")),
            ("///", Some("/")),
            ("/.", Some("/")),
            ("/..", Some("/")),
            ("/a", Some("/a")),
            ("/a/", Some("/a")),
            ("//a//b/", Some("/a/b")),
            ("/a/./b/../c", Some("/a/c")),
            ("/a/../..", Some("/")),
            ("/a/b/../../c", Some("/c")),
            ("/../a", Some("/a")),
            ("/ ä b /c ", Some("/ ä b /c ")),
            ("/-x", Some("/-x")),
            ("/...", Some("/...")),
            ("/a\\b", Some("/a\\b")),
            ("/C:/x", Some("/C:/x")),
            ("/a\tb\u{1b}", Some("/a\tb\u{1b}")),
            ("/.hidden/..x", Some("/.hidden/..x")),
            ("/a/b/c/./../d", Some("/a/b/d")),
            (&max, Some(&max)),
            ("", None),
            ("a/b", None),
            ("./a", None),
            ("..", None),
            ("~/x", None),
            ("/a\0b", None),
            (&long, None),
        ];
        assert!(rows.len() >= 25);
        for (input, want) in rows {
            let got = RemotePath::parse(input);
            match want {
                Some(w) => assert_eq!(
                    got.ok().as_ref().map(RemotePath::as_str),
                    Some(w),
                    "{input:?}"
                ),
                None => assert!(
                    matches!(got, Err(Error::InvalidInput(_))),
                    "{input:?} should fail, got {got:?}"
                ),
            }
        }
    }

    #[test]
    fn remote_path_errors_escape_control_chars() {
        let Err(Error::InvalidInput(msg)) = RemotePath::parse("rel\u{1b}[31m") else {
            panic!("expected InvalidInput");
        };
        assert!(!msg.contains('\u{1b}'), "{msg:?}");
        assert!(msg.contains("\\u{1b}"), "{msg:?}");
        let Err(Error::InvalidInput(msg)) = RemotePath::parse("/a\0b") else {
            panic!("expected InvalidInput");
        };
        assert!(msg.contains("NUL"), "{msg}");
    }

    #[test]
    fn remote_path_join_rejects_traversal_names() {
        let base = rp("/a");
        for bad in ["", ".", "..", "a/b", "a\0", "/"] {
            assert!(
                matches!(base.join(bad), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
        for good in ["...", " ", "a\\b", "C:", ".x"] {
            let p = base.join(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
            assert_eq!(p.file_name(), Some(good));
            assert_eq!(p.parent(), Some(base.clone()));
        }
        assert_eq!(RemotePath::root().join("x").ok(), Some(rp("/x")));
        assert_eq!(base.join_all(["b", "c"]).ok(), Some(rp("/a/b/c")));
        assert!(base.join_all(["b", ".."]).is_err());
        let near = rp(&format!("/{}", "a".repeat(4092)));
        assert!(near.join("bb").is_ok());
        assert!(near.join("bbb").is_err());
    }

    #[test]
    fn remote_path_parent_and_file_name() {
        let root = RemotePath::root();
        assert_eq!(root.parent(), None);
        assert_eq!(root.file_name(), None);
        assert!(root.is_root());
        assert_eq!(root.depth(), 0);
        assert_eq!(root.components().count(), 0);
        let p = rp("/a/b");
        assert_eq!(p.parent(), Some(rp("/a")));
        assert_eq!(p.file_name(), Some("b"));
        assert_eq!(p.depth(), 2);
        assert_eq!(rp("/a").parent(), Some(root));
        assert_eq!(p.components().rev().collect::<Vec<_>>(), ["b", "a"]);
    }

    #[test]
    fn remote_path_starts_with_is_component_wise() {
        assert!(!rp("/ab").starts_with(&rp("/a")));
        assert!(rp("/a/b").starts_with(&rp("/a")));
        assert!(rp("/a").starts_with(&rp("/a")));
        assert!(rp("/a").starts_with(&RemotePath::root()));
        assert!(!rp("/a").starts_with(&rp("/a/b")));
        assert_eq!(rp("/a/b").strip_prefix(&rp("/a")), Some(vec!["b"]));
        assert_eq!(
            rp("/a/b/c").strip_prefix(&RemotePath::root()),
            Some(vec!["a", "b", "c"])
        );
        assert_eq!(rp("/a").strip_prefix(&rp("/a")), Some(vec![]));
        assert_eq!(rp("/ab").strip_prefix(&rp("/a")), None);
    }

    #[test]
    fn remote_path_resolve_relative_and_absolute() {
        let a = rp("/a");
        assert_eq!(a.resolve("../b/./c").ok(), Some(rp("/b/c")));
        assert_eq!(a.resolve("/x").ok(), Some(rp("/x")));
        assert_eq!(a.resolve("").ok(), Some(a.clone()));
        assert_eq!(a.resolve("b").ok(), Some(rp("/a/b")));
        assert_eq!(a.resolve("../../..").ok(), Some(RemotePath::root()));
        assert_eq!(a.resolve(".").ok(), Some(a.clone()));
        assert!(a.resolve("b\0").is_err());
    }

    #[test]
    fn remote_path_formatting_and_conversions() {
        let p = rp("/a/b");
        assert_eq!(p.to_string(), "/a/b");
        assert_eq!(format!("{p:?}"), "RemotePath(\"/a/b\")");
        assert_eq!("/a//b".parse::<RemotePath>().ok(), Some(p.clone()));
        assert_eq!(
            RemotePath::try_from(String::from("/a/b")).ok(),
            Some(p.clone())
        );
        assert_eq!(String::from(p), "/a/b");
    }

    #[test]
    fn remote_path_serde_rejects_invalid() {
        assert!(serde_json::from_str::<RemotePath>("\"rel\"").is_err());
        assert!(serde_json::from_str::<RemotePath>("\"\"").is_err());
        let p: RemotePath = serde_json::from_str("\"/a//b/\"").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p, rp("/a/b"));
        assert_eq!(serde_json::to_string(&p).ok().as_deref(), Some("\"/a/b\""));
    }

    #[test]
    fn local_path_join_rejects_separators() {
        let base = LocalPath::new("base");
        for bad in ["", ".", "..", "a/b", "a\0", "/"] {
            assert!(
                matches!(base.join(bad), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
        #[cfg(windows)]
        assert!(base.join("a\\b").is_err());
        #[cfg(not(windows))]
        assert!(base.join("a\\b").is_ok());
        let j = base.join("x y").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(j.as_path(), Path::new("base").join("x y"));
        assert_eq!(j.file_name(), Some(OsStr::new("x y")));
        assert_eq!(j.parent(), Some(base.clone()));
        assert_eq!(j.into_path_buf(), PathBuf::from("base").join("x y"));
    }

    #[cfg(windows)]
    #[test]
    fn local_path_join_rejects_drive_prefix() {
        let base = LocalPath::new("C:\\base");
        assert!(base.join("C:").is_err());
        assert!(base.join("d:evil").is_err());
        assert!(base.join("a:b").is_err());
        assert!(base.join("ab:c").is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn local_path_display_uses_tilde() {
        let home = Path::new("/home/u");
        assert_eq!(
            LocalPath::new("/home/u/x").display_with_home(Some(home)),
            "~/x"
        );
        assert_eq!(LocalPath::new("/home/u").display_with_home(Some(home)), "~");
        assert_eq!(
            LocalPath::new("/home/user2").display_with_home(Some(home)),
            "/home/user2"
        );
        assert_eq!(
            LocalPath::new("/home/u/x").display_with_home(None),
            "/home/u/x"
        );
        assert!(!LocalPath::new("/tmp").to_display().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn local_path_display_uses_tilde() {
        let home = Path::new("C:\\Users\\u");
        assert_eq!(
            LocalPath::new("C:\\Users\\u\\Desktop").display_with_home(Some(home)),
            "~\\Desktop"
        );
        assert_eq!(
            LocalPath::new("C:\\Users\\u2").display_with_home(Some(home)),
            "C:\\Users\\u2"
        );
    }

    #[test]
    fn local_path_serde_is_a_string() {
        let p = LocalPath::new("/tmp/x");
        let json = serde_json::to_string(&p).unwrap_or_default();
        assert_eq!(json, "\"/tmp/x\"");
        assert_eq!(serde_json::from_str::<LocalPath>(&json).ok(), Some(p));
    }

    #[test]
    fn server_type_override_path_style() {
        assert_eq!(ServerTypeOverride::Auto.path_style(), None);
        assert_eq!(ServerTypeOverride::Vms.path_style(), Some(PathStyle::Vms));
        assert_eq!(ServerTypeOverride::default(), ServerTypeOverride::Auto);
        assert_eq!(PathStyle::default(), PathStyle::Unix);
        assert_eq!(
            serde_json::to_string(&PathStyle::Mvs).ok().as_deref(),
            Some("\"mvs\"")
        );
    }
}
