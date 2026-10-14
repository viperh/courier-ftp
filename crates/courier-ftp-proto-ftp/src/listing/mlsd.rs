//! `MLSD` / `MLST` lines (RFC 3659): `fact=value;fact=value; name`.

use courier_ftp_core::model::{Entry, EntryKind, Permissions, Precision, Timestamp};
use time::{PrimitiveDateTime, Time};

use super::Parsed;

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// Parse one `MLSD` line. `None` if it isn't one; [`Parsed::Skip`] for the
/// `cdir`/`pdir` entries.
///
/// The name is everything after the first space, verbatim: it may contain
/// `;`, spaces, and leading or trailing spaces.
pub(super) fn parse_line(line: &str) -> Option<Parsed> {
    let (facts, name) = line.split_once(' ')?;
    let facts = facts.strip_suffix(';')?;
    if name.is_empty() || facts.is_empty() {
        return None;
    }
    let mut kind = EntryKind::File;
    let mut size = None;
    let mut modified = None;
    let mut perm = None;
    let mut mode = None;
    let (mut owner, mut owner_name, mut group, mut group_name) = (None, None, None, None);
    for fact in facts.split(';') {
        let (key, value) = fact.split_once('=')?;
        match key.to_ascii_lowercase().as_str() {
            "type" => match parse_type(value) {
                Some(k) => kind = k,
                None => return Some(Parsed::Skip),
            },
            "size" | "sizd" => size = value.parse::<u64>().ok(),
            "modify" => modified = parse_modify(value),
            "perm" => perm = Some(value),
            "unix.mode" => mode = u32::from_str_radix(value, 8).ok().filter(|m| *m <= 0o7777),
            "unix.owner" | "unix.uid" => owner = Some(value),
            "unix.ownername" => owner_name = Some(value),
            "unix.group" | "unix.gid" => group = Some(value),
            "unix.groupname" => group_name = Some(value),
            _ => {}
        }
    }
    let permissions = match (mode, perm) {
        (Some(bits), _) => Some(Permissions::from_mode(bits | type_bits(&kind))),
        (None, Some(p)) => Some(Permissions::from_raw(p)),
        (None, None) => None,
    };
    let mut entry = Entry::new(name, kind);
    entry.size = size;
    entry.modified = modified;
    entry.permissions = permissions;
    entry.owner = owner_name.or(owner).map(str::to_owned);
    entry.group = group_name.or(group).map(str::to_owned);
    entry.raw = Some(line.to_owned());
    Some(Parsed::Entry(entry))
}

/// The `type` fact. `None` for `cdir`/`pdir`.
fn parse_type(value: &str) -> Option<EntryKind> {
    let lower = value.to_ascii_lowercase();
    Some(match lower.as_str() {
        "file" => EntryKind::File,
        "dir" => EntryKind::Dir,
        "cdir" | "pdir" => return None,
        "os.unix=symlink" | "os.unix=slink" => EntryKind::Symlink {
            target: None,
            target_kind: None,
        },
        _ if lower.starts_with("os.unix=slink:") => EntryKind::Symlink {
            // Keep the original case of the target.
            target: value
                .split_once(':')
                .map(|(_, t)| t.to_owned())
                .filter(|t| !t.is_empty()),
            target_kind: None,
        },
        "os.unix=dir" => EntryKind::Dir,
        _ => EntryKind::Other,
    })
}

fn type_bits(kind: &EntryKind) -> u32 {
    match kind {
        EntryKind::File => S_IFREG,
        EntryKind::Dir => S_IFDIR,
        EntryKind::Symlink { .. } => S_IFLNK,
        EntryKind::Other => 0,
    }
}

/// `YYYYMMDDHHMMSS[.sss]`, always UTC.
pub(crate) fn parse_modify(value: &str) -> Option<Timestamp> {
    let (main, fraction) = match value.split_once('.') {
        Some((m, f)) => (m, Some(f)),
        None => (value, None),
    };
    if main.len() != 14 || !main.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| main.get(r).and_then(|s| s.parse::<u32>().ok());
    let date = courier_ftp_core::listing::date_from_numbers(
        i32::try_from(num(0..4)?).ok()?,
        num(4..6)?,
        num(6..8)?,
    )?;
    let (h, m, s) = (num(8..10)?, num(10..12)?, num(12..14)?);
    let mut precision = Precision::Second;
    let mut millis = 0u16;
    if let Some(f) = fraction {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let digits: String = f.chars().chain("000".chars()).take(3).collect();
        millis = digits.parse().ok()?;
        precision = Precision::Millis;
    }
    let time = Time::from_hms_milli(
        u8::try_from(h).ok()?,
        u8::try_from(m).ok()?,
        u8::try_from(s.min(59)).ok()?,
        millis,
    )
    .ok()?;
    let wall = PrimitiveDateTime::new(date, time);
    Some(Timestamp::new(wall.assume_utc(), precision))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;

    fn entry(line: &str) -> Entry {
        match parse_line(line) {
            Some(Parsed::Entry(e)) => e,
            other => panic!("{line:?}: {other:?}"),
        }
    }

    #[test]
    fn file_with_unix_facts() {
        let e = entry(
            "type=file;size=1234;modify=20240131120000;UNIX.mode=0644;UNIX.owner=1000;UNIX.ownername=alice;UNIX.group=100;unique=801g4804045; notes.txt",
        );
        assert_eq!(e.name, "notes.txt");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, Some(1234));
        assert_eq!(e.owner.as_deref(), Some("alice"));
        assert_eq!(e.group.as_deref(), Some("100"));
        assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o100_644));
        let m = e.modified.unwrap();
        assert_eq!(m.time, datetime!(2024-01-31 12:00 UTC));
        assert_eq!(m.precision, Precision::Second);
    }

    #[test]
    fn names_are_verbatim() {
        assert_eq!(entry("type=file; a; b ").name, "a; b ");
        assert_eq!(entry("type=file;  leading").name, " leading");
    }

    #[test]
    fn types() {
        assert!(matches!(parse_line("type=cdir; ."), Some(Parsed::Skip)));
        assert!(matches!(parse_line("Type=PDIR; .."), Some(Parsed::Skip)));
        assert_eq!(entry("TYPE=DIR; d").kind, EntryKind::Dir);
        assert_eq!(
            entry("type=OS.unix=slink:/Var/Www;perm=r; www").kind,
            EntryKind::Symlink {
                target: Some("/Var/Www".into()),
                target_kind: None
            }
        );
        assert!(entry("type=OS.unix=symlink; l").kind.is_symlink());
        assert_eq!(entry("type=OS.unix=chr-1/3; null").kind, EntryKind::Other);
        assert_eq!(
            entry("type=dir;perm=flcdmpe; d").permissions,
            Some(Permissions::from_raw("flcdmpe"))
        );
    }

    #[test]
    fn modify_fraction() {
        let t = parse_modify("20240131120000.5").unwrap();
        assert_eq!(t.time, datetime!(2024-01-31 12:00:00.5 UTC));
        assert_eq!(t.precision, Precision::Millis);
        assert_eq!(parse_modify("2024013112000"), None);
        assert_eq!(parse_modify("20241331120000"), None);
        assert_eq!(parse_modify("20240131120000."), None);
    }

    #[test]
    fn not_mlsd() {
        for line in [
            "-rw-r--r-- 1 u g 7 Jan 31 12:00 f",
            "type=file;",
            "type=file name",
            "type; x",
            " name",
        ] {
            assert!(parse_line(line).is_none(), "{line:?}");
        }
    }
}
