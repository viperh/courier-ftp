//! [`RemotePath`], [`LocalPath`] and [`PathStyle`].

use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// An absolute, normalised path on a remote server.
///
/// Always `/`-separated and absolute, with no empty, `.` or `..` components:
/// `/a/./b/../c` is stored as `/a/c`, `..` at the root stays at the root, and the
/// empty string means `/`. Names may contain anything except `/` and NUL,
/// including spaces (also leading or trailing), unicode, backslashes and leading
/// dashes; they are never trimmed.
///
/// Servers that don't use Unix paths (VMS, MVS, some DOS-style FTP servers, see
/// [`PathStyle`]) still get a `RemotePath`: the FTP crate translates to and from
/// the server's own syntax (T13/T14), so the rest of the program only ever sees
/// this form. Never use [`std::path::Path`] for remote paths.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemotePath(String);

impl RemotePath {
    /// Parse and normalise `path`. Relative input is taken relative to `/`.
    pub fn new(path: impl AsRef<str>) -> Self {
        let mut out: Vec<&str> = Vec::new();
        for part in path.as_ref().split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                name => out.push(name),
            }
        }
        if out.is_empty() {
            Self::root()
        } else {
            let mut s = String::with_capacity(path.as_ref().len() + 1);
            for name in out {
                s.push('/');
                s.push_str(name);
            }
            Self(s)
        }
    }

    /// The root directory, `/`.
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    /// Whether this is `/`.
    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// The path as a string (always starts with `/`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The child `name` of this directory.
    ///
    /// Fails with [`Error::InvalidInput`] when `name` is empty, `.` or `..`, or
    /// contains `/` or NUL: a single name must name a single entry. Use
    /// [`RemotePath::parent`] to go up and [`RemotePath::join_path`] for
    /// multi-component relative paths.
    pub fn join(&self, name: &str) -> Result<Self> {
        validate_name(name)?;
        let mut s = self.0.clone();
        if !self.is_root() {
            s.push('/');
        }
        s.push_str(name);
        Ok(Self(s))
    }

    /// Resolve a relative (or absolute) `path` against this directory, the way a
    /// shell `cd` would: `..` goes up, an absolute path replaces this one.
    pub fn join_path(&self, path: &str) -> Self {
        if path.starts_with('/') {
            Self::new(path)
        } else {
            Self::new(format!("{}/{path}", self.0))
        }
    }

    /// The parent directory, or `None` for `/`.
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        match self.0.rfind('/') {
            Some(0) | None => Some(Self::root()),
            Some(i) => Some(Self(self.0[..i].to_owned())),
        }
    }

    /// The last component, or `None` for `/`.
    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    /// The components from the root down (`/a/b` yields `a`, `b`; `/` yields
    /// nothing).
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> + '_ {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// Whether `other` is this path or one of its ancestors (component-wise:
    /// `/ab` does not start with `/a`).
    pub fn starts_with(&self, other: &RemotePath) -> bool {
        other.is_root()
            || self.0 == other.0
            || (self.0.starts_with(&other.0) && self.0.as_bytes().get(other.0.len()) == Some(&b'/'))
    }

    /// This path relative to `base`, or `None` when `base` is not an ancestor.
    /// The result has no leading `/` and is empty when the paths are equal.
    pub fn strip_prefix(&self, base: &RemotePath) -> Option<&str> {
        if !self.starts_with(base) {
            None
        } else if base.is_root() {
            Some(&self.0[1..])
        } else {
            Some(self.0[base.0.len()..].trim_start_matches('/'))
        }
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(Error::InvalidInput(format!("`{name}` is not a file name")));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(Error::InvalidInput(format!(
            "file name `{}` contains `/` or NUL",
            name.escape_debug()
        )));
    }
    Ok(())
}

impl Default for RemotePath {
    fn default() -> Self {
        Self::root()
    }
}

impl fmt::Display for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RemotePath({:?})", self.0)
    }
}

impl From<&str> for RemotePath {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for RemotePath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for RemotePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RemotePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

/// How a server spells its paths. [`RemotePath`] is always Unix-style; the FTP
/// crate uses this to translate (T13/T14).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStyle {
    /// `/home/user/file` — almost every server.
    #[default]
    Unix,
    /// `C:\dir\file` or `\dir\file` — some Windows FTP servers.
    Dos,
    /// `DISK:[DIR.SUB]FILE.TXT;1` — OpenVMS.
    Vms,
    /// `'HLQ.DATASET.NAME'` — z/OS (MVS) datasets.
    Mvs,
}

/// A path on the local machine.
///
/// A thin newtype over [`PathBuf`] so APIs can't mix local and remote paths.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalPath(PathBuf);

impl LocalPath {
    /// Wrap a local path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The underlying path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consume into the underlying [`PathBuf`].
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// The child `name` of this directory.
    pub fn join(&self, name: impl AsRef<Path>) -> Self {
        Self(self.0.join(name))
    }

    /// The parent directory, if any.
    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|p| Self(p.to_path_buf()))
    }

    /// The path for display, with the user's home directory shown as `~`.
    pub fn to_display(&self) -> String {
        self.to_display_with_home(std::env::home_dir().as_deref())
    }

    /// Like [`LocalPath::to_display`] with an explicit home directory (for tests).
    pub fn to_display_with_home(&self, home: Option<&Path>) -> String {
        if let Some(home) = home.filter(|h| !h.as_os_str().is_empty())
            && let Ok(rest) = self.0.strip_prefix(home)
        {
            return if rest.as_os_str().is_empty() {
                "~".to_owned()
            } else {
                format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display())
            };
        }
        self.0.display().to_string()
    }
}

impl From<PathBuf> for LocalPath {
    fn from(p: PathBuf) -> Self {
        Self(p)
    }
}

impl From<&Path> for LocalPath {
    fn from(p: &Path) -> Self {
        Self(p.to_path_buf())
    }
}

impl AsRef<Path> for LocalPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn normalisation() {
        let cases = [
            ("", "/"),
            ("/", "/"),
            ("//", "/"),
            ("//a//b/", "/a/b"),
            ("/a/./b/../c", "/a/c"),
            ("/a/../..", "/"),
            ("/../a", "/a"),
            ("a/b", "/a/b"),
            ("/./.", "/"),
            ("/dir with spaces/ trailing ", "/dir with spaces/ trailing "),
            ("/ünïcödé/日本語", "/ünïcödé/日本語"),
            ("/-rf/--help", "/-rf/--help"),
            ("/back\\slash", "/back\\slash"),
            ("/...", "/..."),
        ];
        for (input, expected) in cases {
            assert_eq!(RemotePath::new(input).as_str(), expected, "input {input:?}");
        }
    }

    #[test]
    fn join_and_parent() {
        let root = RemotePath::root();
        let a = root.join("a").unwrap();
        assert_eq!(a.as_str(), "/a");
        let b = a.join("b c ").unwrap();
        assert_eq!(b.as_str(), "/a/b c ");
        assert_eq!(b.parent(), Some(a.clone()));
        assert_eq!(a.parent(), Some(root.clone()));
        assert_eq!(root.parent(), None);
        assert_eq!(a.join("-x").unwrap().as_str(), "/a/-x");
    }

    #[test]
    fn join_rejects_bad_names() {
        let root = RemotePath::root();
        for bad in ["", ".", "..", "a/b", "/", "nul\0"] {
            assert!(
                matches!(root.join(bad), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn join_path() {
        let d = RemotePath::new("/a/b");
        assert_eq!(d.join_path("c/d").as_str(), "/a/b/c/d");
        assert_eq!(d.join_path("..").as_str(), "/a");
        assert_eq!(d.join_path("/x").as_str(), "/x");
        assert_eq!(d.join_path("../../../..").as_str(), "/");
    }

    #[test]
    fn file_name_and_components() {
        let p = RemotePath::new("/a/b/c.txt");
        assert_eq!(p.file_name(), Some("c.txt"));
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b", "c.txt"]);
        assert_eq!(RemotePath::root().file_name(), None);
        assert_eq!(RemotePath::root().components().count(), 0);
    }

    #[test]
    fn starts_with_is_component_wise() {
        let p = RemotePath::new("/ab/c");
        assert!(p.starts_with(&RemotePath::new("/ab")));
        assert!(p.starts_with(&RemotePath::new("/ab/c")));
        assert!(p.starts_with(&RemotePath::root()));
        assert!(!p.starts_with(&RemotePath::new("/a")));
        assert!(!p.starts_with(&RemotePath::new("/ab/c/d")));
    }

    #[test]
    fn strip_prefix() {
        let p = RemotePath::new("/a/b/c");
        assert_eq!(p.strip_prefix(&RemotePath::new("/a")), Some("b/c"));
        assert_eq!(p.strip_prefix(&RemotePath::root()), Some("a/b/c"));
        assert_eq!(p.strip_prefix(&p), Some(""));
        assert_eq!(p.strip_prefix(&RemotePath::new("/x")), None);
    }

    #[test]
    fn serde_normalises() {
        let p: RemotePath = serde_json::from_str("\"/a//b/../c/\"").unwrap();
        assert_eq!(p.as_str(), "/a/c");
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"/a/c\"");
    }

    #[test]
    fn local_display_uses_tilde() {
        let home = Path::new("/home/me");
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            LocalPath::new("/home/me/src").to_display_with_home(Some(home)),
            format!("~{sep}src")
        );
        assert_eq!(
            LocalPath::new("/home/me").to_display_with_home(Some(home)),
            "~"
        );
        assert_eq!(
            LocalPath::new("/home/meow").to_display_with_home(Some(home)),
            "/home/meow"
        );
        assert_eq!(LocalPath::new("/etc").to_display_with_home(None), "/etc");
    }
}
