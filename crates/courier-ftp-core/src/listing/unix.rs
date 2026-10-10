//! The Unix `ls -l` listing parser, shared by FTP `LIST` (T13) and the SFTP
//! `longname` (T22).
//!
//! Handles the usual variants:
//!
//! - with or without the group column, with or without the link count,
//!   numeric owners;
//! - device files (`major, minor` instead of a size);
//! - an ACL / SELinux / xattr marker (`+`, `.`, `@`) after the mode;
//! - Windows servers that imitate `ls -l` (`----------   1 owner group ...`);
//! - dates `Mon DD HH:MM` (year inferred), `Mon DD YYYY`, `DD Mon ...`, ISO
//!   `YYYY-MM-DD HH:MM`, `ls --full-time`, localised and CJK month names (see
//!   [`parse_date_fields`]);
//! - symlinks `name -> target`;
//! - names with leading spaces (exactly one separator after the date is
//!   dropped; the rest is the name, trailing spaces included).
//!
//! **Symlink limitation:** a symlink line is split at the *first* ` -> `, so a
//! link whose own name contains ` -> ` is split wrongly (its target, however,
//! may contain ` -> `). Names of files, directories and other entries are never
//! split, because only lines whose mode starts with `l` are treated as links.
//!
//! The `total N` header is not an entry: [`is_total_line`] recognises it.

use super::{ListingContext, parse_date_fields, split_fields};
use crate::model::{Entry, EntryKind, Permissions};

/// Parse one `ls -l` line. `None` if it isn't one (or is a `total` header).
pub fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let (mode, rest) = fields.split_first()?;
    let (kind, permissions) = parse_mode(mode.text)?;
    let texts: Vec<&str> = rest.iter().map(|f| f.text).collect();

    // The date is the first position that parses as one and is preceded by a
    // size (or a `major, minor` device number).
    for date_at in 1..texts.len() {
        let Some((size, meta_len)) = size_before(&texts[..date_at]) else {
            continue;
        };
        let Some((modified, used)) = parse_date_fields(&texts[date_at..], ctx) else {
            continue;
        };
        let last = rest.get(date_at + used - 1)?;
        let Some(name) = super::rest_after(line, last.end()) else {
            continue;
        };
        let (owner, group) = owner_group(&texts[..meta_len]);
        let (name, kind) = split_symlink(name, kind);
        if name.is_empty() {
            return None;
        }
        let mut entry = Entry::new(name, kind);
        entry.size = size;
        entry.modified = Some(modified);
        entry.permissions = Some(permissions);
        entry.owner = owner;
        entry.group = group;
        entry.raw = Some(line.to_owned());
        return Some(entry);
    }
    None
}

/// Whether `line` is the `total N` header `ls -l` prints first.
pub fn is_total_line(line: &str) -> bool {
    let fields = split_fields(line);
    matches!(fields.as_slice(), [t, n]
        if t.text.eq_ignore_ascii_case("total")
            && n.text.trim_end_matches(['k', 'K', 'M', 'G']).bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// The mode field: file-type character plus nine permission characters,
/// optionally followed by `+`, `.` or `@`.
fn parse_mode(token: &str) -> Option<(EntryKind, Permissions)> {
    let chars: Vec<char> = token.chars().collect();
    let base = match chars.len() {
        10 => &chars[..],
        11 if matches!(chars[10], '+' | '.' | '@') => &chars[..10],
        _ => return None,
    };
    let kind = match base[0] {
        '-' | 'f' => EntryKind::File,
        'd' => EntryKind::Dir,
        'l' => EntryKind::Symlink {
            target: None,
            target_kind: None,
        },
        'b' | 'c' | 'p' | 's' | 'D' | 'P' | 'n' | '?' => EntryKind::Other,
        _ => return None,
    };
    if !base[1..]
        .iter()
        .all(|c| matches!(c, 'r' | 'w' | 'x' | 's' | 'S' | 't' | 'T' | 'l' | 'L' | '-'))
    {
        return None;
    }
    let permissions = match Permissions::from_rwx_string(token) {
        Ok(p) => p,
        Err(_) => Permissions::from_raw(token),
    };
    Some((kind, permissions))
}

/// The size (or device number) at the end of `meta`, and how many fields come
/// before it (links, owner, group).
fn size_before(meta: &[&str]) -> Option<(Option<u64>, usize)> {
    let (last, before) = meta.split_last()?;
    if is_number(last) {
        // `major, minor`
        if let Some(prev) = before.last()
            && prev.strip_suffix(',').is_some_and(is_number)
        {
            return Some((None, before.len() - 1));
        }
        return Some((last.parse().ok(), before.len()));
    }
    // `major,minor`
    if let Some((major, minor)) = last.split_once(',')
        && is_number(major)
        && is_number(minor)
    {
        return Some((None, before.len()));
    }
    None
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Owner and group from the fields between the mode and the size.
fn owner_group(meta: &[&str]) -> (Option<String>, Option<String>) {
    // A leading number is the link count, unless it's the only field.
    let meta = match meta {
        [links, rest @ ..] if is_number(links) && !rest.is_empty() => rest,
        [links] if is_number(links) => &[],
        _ => meta,
    };
    match meta {
        [] => (None, None),
        [owner] => (Some((*owner).to_owned()), None),
        [owner, group @ ..] => (Some((*owner).to_owned()), Some(group.join(" "))),
    }
}

fn split_symlink(name: &str, kind: EntryKind) -> (&str, EntryKind) {
    if !kind.is_symlink() {
        return (name, kind);
    }
    match name.split_once(" -> ") {
        Some((link, target)) => (
            link,
            EntryKind::Symlink {
                target: Some(target.to_owned()),
                target_kind: None,
            },
        ),
        None => (name, kind),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::{
        Duration,
        macros::{datetime, offset},
    };

    use super::*;
    use crate::model::Precision;

    fn ctx() -> ListingContext {
        ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO)
    }

    fn parse(line: &str) -> Entry {
        parse_line(line, &ctx()).unwrap_or_else(|| panic!("not parsed: {line:?}"))
    }

    #[test]
    fn plain_file() {
        let e = parse("-rw-r--r--   1 alice    staff        1234 Jan 31 12:00 notes.txt");
        assert_eq!(e.name, "notes.txt");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, Some(1234));
        assert_eq!(e.owner.as_deref(), Some("alice"));
        assert_eq!(e.group.as_deref(), Some("staff"));
        assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o100_644));
        let m = e.modified.unwrap();
        assert_eq!(m.time, datetime!(2024-01-31 12:00 UTC));
        assert_eq!(m.precision, Precision::Minute);
        assert!(!e.hidden);
    }

    #[test]
    fn year_and_no_group() {
        let e = parse("drwxr-xr-x   2 1000         4096 Mar  3  2019 .config");
        assert_eq!(e.kind, EntryKind::Dir);
        assert_eq!(e.owner.as_deref(), Some("1000"));
        assert_eq!(e.group, None);
        assert!(e.hidden);
        let m = e.modified.unwrap();
        assert_eq!(m.time, datetime!(2019-03-03 0:00 UTC));
        assert_eq!(m.precision, Precision::Day);
    }

    #[test]
    fn devices_and_acl_markers() {
        let e = parse("crw-rw-rw-   1 root     root       1,   3 Jan 31 12:00 null");
        assert_eq!((e.kind, e.size), (EntryKind::Other, None));
        let e = parse("brw-rw----   1 root     disk       8,0 Jan 31 12:00 sda");
        assert_eq!(
            (e.kind, e.size, e.name.as_str()),
            (EntryKind::Other, None, "sda")
        );
        for mark in ["+", ".", "@"] {
            let e = parse(&format!("drwxr-xr-x{mark} 3 u g 96 Jan 31 12:00 d"));
            assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o040_755));
        }
    }

    #[test]
    fn symlinks() {
        let e = parse("lrwxrwxrwx   1 root     root          7 Jan 31  2024 bin -> usr/bin");
        assert_eq!(e.name, "bin");
        assert_eq!(
            e.kind,
            EntryKind::Symlink {
                target: Some("usr/bin".into()),
                target_kind: None
            }
        );
        // The target may contain ` -> `.
        let e = parse("lrwxrwxrwx 1 u g 7 Jan 31 2024 a -> b -> c");
        assert_eq!(e.name, "a");
        // A regular file whose name contains ` -> ` is not split.
        let e = parse("-rw-r--r-- 1 u g 7 Jan 31 2024 a -> b");
        assert_eq!(e.name, "a -> b");
    }

    #[test]
    fn leading_and_trailing_spaces() {
        let e = parse("-rw-r--r-- 1 u g 7 Jan 31 12:00   spaced  ");
        assert_eq!(e.name, "  spaced  ");
    }

    #[test]
    fn full_time_uses_explicit_zone() {
        let c = ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::hours(5));
        let e = parse_line(
            "-rw-r--r-- 1 u g 7 2024-01-31 12:00:00.500000000 +0100 f",
            &c,
        )
        .unwrap();
        let m = e.modified.unwrap();
        assert_eq!(
            m.time,
            datetime!(2024-01-31 12:00:00.5 +01:00).to_offset(offset!(UTC))
        );
        assert_eq!(m.precision, Precision::Millis);
    }

    #[test]
    fn not_unix() {
        let c = ctx();
        for line in [
            "",
            "total 12",
            "01-31-24  12:00PM       <DIR>          dir",
            "-rw-r--r-- 1 u g 7 Jan 31 12:00",
            "-rw-r--r-- 1 u g x Jan 31 12:00 f",
            "xrw-r--r-- 1 u g 7 Jan 31 12:00 f",
            "-rw-r--r-- 1 u g 7 Foo 31 12:00 f",
        ] {
            assert_eq!(parse_line(line, &c), None, "{line:?}");
        }
        assert!(is_total_line("total 12"));
        assert!(is_total_line("total 1.5M"));
        assert!(!is_total_line("total x"));
    }
}
