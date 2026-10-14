//! SFTP attributes and `longname` lines to [`Entry`].

use courier_ftp_core::{
    listing::{ListingContext, unix},
    model::{Entry, EntryKind, Permissions, Precision, Timestamp},
};
use russh_sftp::protocol::FileAttributes;
use time::{Duration, OffsetDateTime};

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// The kind of entry the mode's file-type bits say, `None` without a mode.
pub(crate) fn kind_of(attrs: &FileAttributes) -> Option<EntryKind> {
    let mode = attrs.permissions?;
    Some(match mode & S_IFMT {
        S_IFDIR => EntryKind::Dir,
        S_IFREG => EntryKind::File,
        S_IFLNK => EntryKind::Symlink {
            target: None,
            target_kind: None,
        },
        // Servers that send only permission bits: assume a file.
        0 => EntryKind::File,
        _ => EntryKind::Other,
    })
}

/// A timestamp from SFTP seconds since the epoch, shifted by the site's
/// timezone offset.
pub(crate) fn timestamp(secs: u32, offset: Duration) -> Option<Timestamp> {
    let time = OffsetDateTime::from_unix_timestamp(i64::from(secs)).ok()?;
    Some(Timestamp::new(time, Precision::Second).shifted(offset))
}

/// Build an entry for `name` from its attributes. `longname` (the server's
/// `ls -l` line) supplies owner and group names (SFTP v3 attributes carry only
/// numeric ids) and anything the attributes lack.
pub(crate) fn entry(
    name: String,
    attrs: &FileAttributes,
    longname: Option<&str>,
    ctx: &ListingContext,
) -> Entry {
    let parsed = longname
        .filter(|l| !l.is_empty())
        .and_then(|l| unix::parse_line(l, ctx));
    let kind = kind_of(attrs)
        .or_else(|| parsed.as_ref().map(|p| strip_target(&p.kind)))
        .unwrap_or(EntryKind::File);
    let mut entry = Entry::new(name, kind);
    entry.size = attrs.size.or_else(|| parsed.as_ref().and_then(|p| p.size));
    entry.modified = attrs
        .mtime
        .and_then(|m| timestamp(m, ctx.timezone_offset))
        .or_else(|| parsed.as_ref().and_then(|p| p.modified));
    entry.permissions = attrs
        .permissions
        .map(Permissions::from_mode)
        .or_else(|| parsed.as_ref().and_then(|p| p.permissions.clone()));
    entry.owner = attrs
        .user
        .clone()
        .or_else(|| parsed.as_ref().and_then(|p| p.owner.clone()))
        .or_else(|| attrs.uid.map(|u| u.to_string()));
    entry.group = attrs
        .group
        .clone()
        .or_else(|| parsed.as_ref().and_then(|p| p.group.clone()))
        .or_else(|| attrs.gid.map(|g| g.to_string()));
    entry.raw = longname.filter(|l| !l.is_empty()).map(str::to_owned);
    entry
}

/// A symlink kind from a parsed line, without the target (the line's
/// `-> target` is resolved properly with `READLINK`).
fn strip_target(kind: &EntryKind) -> EntryKind {
    match kind {
        EntryKind::Symlink { .. } => EntryKind::Symlink {
            target: None,
            target_kind: None,
        },
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;

    fn attrs(mode: u32) -> FileAttributes {
        FileAttributes {
            size: Some(11),
            uid: Some(1000),
            gid: Some(100),
            permissions: Some(mode),
            atime: Some(0),
            mtime: Some(981_173_106), // 2001-02-03 04:05:06 UTC
            ..FileAttributes::default()
        }
    }

    #[test]
    fn longname_supplies_owner_and_group() {
        let ctx = ListingContext::new(Duration::ZERO);
        let line = "-rw-r--r--    1 alice    staff          11 Feb  3  2001 a.txt";
        let e = entry("a.txt".into(), &attrs(0o100_644), Some(line), &ctx);
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, Some(11));
        assert_eq!(e.owner.as_deref(), Some("alice"));
        assert_eq!(e.group.as_deref(), Some("staff"));
        assert_eq!(e.permissions.and_then(|p| p.bits()), Some(0o644));
        assert_eq!(
            e.modified.map(|m| m.time),
            Some(datetime!(2001-02-03 04:05:06 UTC))
        );
        assert_eq!(e.raw.as_deref(), Some(line));
    }

    #[test]
    fn numeric_ids_without_longname() {
        let ctx = ListingContext::new(Duration::ZERO);
        let e = entry(".hidden".into(), &attrs(0o040_755), None, &ctx);
        assert_eq!(e.kind, EntryKind::Dir);
        assert!(e.hidden);
        assert_eq!(e.owner.as_deref(), Some("1000"));
        assert_eq!(e.group.as_deref(), Some("100"));
        assert_eq!(e.raw, None);
    }

    #[test]
    fn kinds_and_timezone() {
        assert!(matches!(
            kind_of(&attrs(0o120_777)),
            Some(EntryKind::Symlink { .. })
        ));
        assert_eq!(kind_of(&attrs(0o020_644)), Some(EntryKind::Other));
        assert_eq!(kind_of(&attrs(0o644)), Some(EntryKind::File));
        assert_eq!(kind_of(&FileAttributes::default()), None);
        let shifted = timestamp(981_173_106, Duration::hours(2)).map(|t| t.time);
        assert_eq!(shifted, Some(datetime!(2001-02-03 06:05:06 UTC)));
    }

    #[test]
    fn longname_fills_missing_attributes() {
        let ctx = ListingContext::new(Duration::ZERO);
        let line = "drwxr-x---    2 bob      users        4096 Feb  3  2001 d";
        let e = entry("d".into(), &FileAttributes::default(), Some(line), &ctx);
        assert_eq!(e.kind, EntryKind::Dir);
        assert_eq!(e.size, Some(4096));
        assert_eq!(e.permissions.and_then(|p| p.bits()), Some(0o750));
        assert_eq!(e.owner.as_deref(), Some("bob"));
    }
}
