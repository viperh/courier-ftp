//! Directory [`Entry`] and [`EntryKind`].

use serde::{Deserialize, Serialize};

use super::{Permissions, Timestamp};

/// What kind of filesystem object an [`Entry`] is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link. The target and its kind are filled in when the server
    /// reports them (`LIST` shows `name -> target`; SFTP can `stat` through).
    Symlink {
        /// Where the link points, as the server reported it.
        target: Option<String>,
        /// The kind of the target, when known.
        target_kind: Option<Box<EntryKind>>,
    },
    /// Anything else: devices, sockets, FIFOs.
    Other,
}

impl EntryKind {
    /// A directory, or a symlink known to point at one: something you can enter.
    pub fn is_dir_like(&self) -> bool {
        match self {
            EntryKind::Dir => true,
            EntryKind::Symlink {
                target_kind: Some(kind),
                ..
            } => kind.is_dir_like(),
            _ => false,
        }
    }

    /// Whether this is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self, EntryKind::Symlink { .. })
    }
}

/// One entry of a directory listing, local or remote.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Entry {
    /// The file name (one component, never containing `/`).
    pub name: String,
    /// File, directory, symlink or other.
    pub kind: EntryKind,
    /// Size in bytes, when known.
    pub size: Option<u64>,
    /// Last modification time, when known.
    pub modified: Option<Timestamp>,
    /// Permissions, when known.
    pub permissions: Option<Permissions>,
    /// Owner name or uid, when known.
    pub owner: Option<String>,
    /// Group name or gid, when known.
    pub group: Option<String>,
    /// A dotfile, or hidden according to the server or local filesystem.
    pub hidden: bool,
    /// The original listing line, for the raw-listing view (T71).
    pub raw: Option<String>,
}

impl Entry {
    /// An entry with only a name and kind; `hidden` is set for dotfiles.
    pub fn new(name: impl Into<String>, kind: EntryKind) -> Self {
        let name = name.into();
        let hidden = name.starts_with('.');
        Self {
            name,
            kind,
            size: None,
            modified: None,
            permissions: None,
            owner: None,
            group: None,
            hidden,
            raw: None,
        }
    }

    /// A file entry of the given size.
    pub fn file(name: impl Into<String>, size: u64) -> Self {
        Self {
            size: Some(size),
            ..Self::new(name, EntryKind::File)
        }
    }

    /// A directory entry.
    pub fn dir(name: impl Into<String>) -> Self {
        Self::new(name, EntryKind::Dir)
    }

    /// Whether this entry can be entered (see [`EntryKind::is_dir_like`]).
    pub fn is_dir_like(&self) -> bool {
        self.kind.is_dir_like()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn dotfiles_are_hidden() {
        assert!(Entry::file(".bashrc", 10).hidden);
        assert!(!Entry::file("bashrc", 10).hidden);
    }

    #[test]
    fn symlink_to_dir_is_dir_like() {
        let link = EntryKind::Symlink {
            target: Some("/var/www".into()),
            target_kind: Some(Box::new(EntryKind::Dir)),
        };
        assert!(link.is_dir_like());
        assert!(link.is_symlink());
        let dangling = EntryKind::Symlink {
            target: None,
            target_kind: None,
        };
        assert!(!dangling.is_dir_like());
        assert!(EntryKind::Dir.is_dir_like());
        assert!(!EntryKind::File.is_dir_like());
    }

    #[test]
    fn serde_round_trip() {
        let mut e = Entry::file("a.txt", 42);
        e.permissions = Some(Permissions::from_mode(0o100_644));
        e.kind = EntryKind::Symlink {
            target: Some("b.txt".into()),
            target_kind: Some(Box::new(EntryKind::File)),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Entry>(&json).unwrap(), e);
    }
}
