//! Directory entries ([`Entry`], [`EntryKind`]), timestamps with precision
//! ([`Timestamp`], [`Precision`]) and [`Permissions`].

use std::cmp::Ordering;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, Time, UtcOffset};

use crate::{Error, Result};

/// One directory entry as reported by a backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// File name only (one valid RemotePath component: non-empty, not "."/"..", no '/',
    /// no NUL). See [`Entry::is_valid_name`].
    pub name: String,
    /// File, directory, symlink or other.
    pub kind: EntryKind,
    /// Bytes. None when the server does not say (MVS, some VMS, directories on most servers).
    pub size: Option<u64>,
    /// Last modification time, with the precision the server gave.
    pub modified: Option<Timestamp>,
    /// Permissions as far as the server reports them.
    pub permissions: Option<Permissions>,
    /// Owner name (or numeric id as text when names are unknown).
    pub owner: Option<String>,
    /// Group name (or numeric id as text when names are unknown).
    pub group: Option<String>,
    /// Dotfile on Unix-like sides, FILE_ATTRIBUTE_HIDDEN locally on Windows, or server-flagged.
    pub hidden: bool,
}

impl Entry {
    /// An entry with only a name and a kind; every other field is `None`/`false`.
    pub fn new(name: impl Into<String>, kind: EntryKind) -> Self {
        Self {
            name: name.into(),
            kind,
            size: None,
            modified: None,
            permissions: None,
            owner: None,
            group: None,
            hidden: false,
        }
    }

    /// `kind == EntryKind::Dir`.
    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }

    /// A directory, or a symlink whose target is a directory (can be entered).
    pub fn is_dir_like(&self) -> bool {
        matches!(
            self.kind,
            EntryKind::Dir
                | EntryKind::Symlink {
                    target_kind: Some(SymlinkTarget::Dir),
                    ..
                }
        )
    }

    /// True if `name` is acceptable as an entry name: non-empty, not "." or "..", no '/'
    /// and no NUL.
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
    }
}

/// The type of a directory entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink {
        /// The link text, when the server reports it.
        target: Option<String>,
        /// What the link points to; `None` = not resolved yet.
        target_kind: Option<SymlinkTarget>,
    },
    /// Devices, sockets, FIFOs, MVS datasets that are neither.
    Other,
}

impl EntryKind {
    /// The `ls -l` type character: 'd', 'l', '-', or '?' for `Other`.
    pub fn type_char(&self) -> char {
        match self {
            Self::File => '-',
            Self::Dir => 'd',
            Self::Symlink { .. } => 'l',
            Self::Other => '?',
        }
    }
}

/// What a symlink points to, when resolved. `None` in `target_kind` = not resolved yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymlinkTarget {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// Something else (device, socket, …).
    Other,
    /// The target does not exist.
    Broken,
}

/// A point in time (always stored in UTC) plus how precise the source was.
///
/// Day-precision values are dates; the listing parser (T13) does not apply the server
/// time-zone offset to them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    /// The time in UTC, truncated to `precision`.
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    /// How precise the source was.
    pub precision: Precision,
}

/// Timestamp precision, ordered coarse → fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Precision {
    /// A date only (00:00:00 UTC).
    Day,
    /// Hours and minutes.
    Minute,
    /// Whole seconds.
    Second,
    /// Milliseconds.
    Millis,
}

fn truncate(t: OffsetDateTime, p: Precision) -> OffsetDateTime {
    match p {
        Precision::Day => t.replace_time(Time::MIDNIGHT),
        Precision::Minute => t
            .replace_second(0)
            .and_then(|t| t.replace_nanosecond(0))
            .unwrap_or(t),
        Precision::Second => t.replace_nanosecond(0).unwrap_or(t),
        Precision::Millis => t
            .replace_nanosecond(t.nanosecond() / 1_000_000 * 1_000_000)
            .unwrap_or(t),
    }
}

impl Timestamp {
    /// Converts to UTC and truncates to `precision` (Day → 00:00:00, Minute → seconds = 0,
    /// Second → nanos = 0, Millis → nanos rounded down to ms).
    pub fn new(time: OffsetDateTime, precision: Precision) -> Self {
        Self {
            time: truncate(time.to_offset(UtcOffset::UTC), precision),
            precision,
        }
    }

    /// Truncates to a (coarser) precision; finer requests return `self` unchanged.
    pub fn truncated(self, p: Precision) -> Self {
        if p >= self.precision {
            self
        } else {
            Self::new(self.time, p)
        }
    }

    /// Compares at the coarser precision of the two (T42 "newer", T48 comparison).
    pub fn cmp_coarse(&self, other: &Timestamp) -> Ordering {
        let p = self.precision.min(other.precision);
        self.truncated(p).time.cmp(&other.truncated(p).time)
    }

    /// `|self - other|` after truncating both to the coarser precision.
    pub fn abs_diff_coarse(&self, other: &Timestamp) -> Duration {
        let p = self.precision.min(other.precision);
        (self.truncated(p).time - other.truncated(p).time).unsigned_abs()
    }
}

/// Permissions as far as the server reports them.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permissions {
    /// Unix mode bits, masked to 0o7777 (setuid 0o4000, setgid 0o2000, sticky 0o1000).
    pub mode: Option<u32>,
    /// Text for servers with non-Unix permissions (MLSD `perm=` facts, Windows "R"),
    /// shown as-is.
    pub raw: Option<String>,
}

const MODE_MASK: u32 = 0o7777;
const SETUID: u32 = 0o4000;
const SETGID: u32 = 0o2000;
const STICKY: u32 = 0o1000;

impl Permissions {
    /// Unix mode bits (masked to 0o7777).
    pub fn from_mode(mode: u32) -> Self {
        Self {
            mode: Some(mode & MODE_MASK),
            raw: None,
        }
    }

    /// Non-Unix permission text, shown as-is.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self {
            mode: None,
            raw: Some(raw.into()),
        }
    }

    /// 9 chars, e.g. "rwxr-xr-x", "rwsr-sr-t", "rwSr--r-T". `None` without a mode.
    pub fn to_rwx_string(&self) -> Option<String> {
        let m = self.mode?;
        let mut s = String::with_capacity(9);
        for (shift, special, set, unset) in [
            (6, SETUID, 's', 'S'),
            (3, SETGID, 's', 'S'),
            (0, STICKY, 't', 'T'),
        ] {
            let bits = (m >> shift) & 0o7;
            s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
            s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
            let x = bits & 0o1 != 0;
            s.push(match (m & special != 0, x) {
                (true, true) => set,
                (true, false) => unset,
                (false, true) => 'x',
                (false, false) => '-',
            });
        }
        Some(s)
    }

    /// 10 chars with the type char: `perms.ls_string(&kind)` → "drwxr-xr-x".
    pub fn ls_string(&self, kind: &EntryKind) -> Option<String> {
        let rwx = self.to_rwx_string()?;
        let mut s = String::with_capacity(10);
        s.push(kind.type_char());
        s.push_str(&rwx);
        Some(s)
    }

    /// Accepts 9 chars, or 10 (first = type char, ignored), optionally followed by one ACL
    /// marker '+', '.' or '@'.
    ///
    /// Errors: `InvalidInput`.
    pub fn from_rwx_string(s: &str) -> Result<Self> {
        let invalid = || {
            Error::InvalidInput(format!(
                "invalid permission string \"{}\"",
                s.escape_debug()
            ))
        };
        let mut chars: Vec<char> = s.chars().take(12).collect();
        if chars.len() > 11 {
            return Err(invalid());
        }
        if matches!(chars.len(), 10 | 11) && matches!(chars.last(), Some('+' | '.' | '@')) {
            chars.pop();
        }
        let rwx = match chars.len() {
            9 => &chars[..],
            10 => &chars[1..],
            _ => return Err(invalid()),
        };
        let mut mode = 0;
        for (i, (shift, special, set, unset)) in [
            (6, SETUID, 's', 'S'),
            (3, SETGID, 's', 'S'),
            (0, STICKY, 't', 'T'),
        ]
        .into_iter()
        .enumerate()
        {
            let part = &rwx[i * 3..i * 3 + 3];
            mode |= match part[0] {
                'r' => 0o4 << shift,
                '-' => 0,
                _ => return Err(invalid()),
            };
            mode |= match part[1] {
                'w' => 0o2 << shift,
                '-' => 0,
                _ => return Err(invalid()),
            };
            mode |= match part[2] {
                'x' => 0o1 << shift,
                '-' => 0,
                c if c == set => special | (0o1 << shift),
                c if c == unset => special,
                _ => return Err(invalid()),
            };
        }
        Ok(Self::from_mode(mode))
    }

    /// "644", or 4 digits ("4755") when any of setuid/setgid/sticky is set. `None`
    /// without a mode.
    pub fn to_octal_string(&self) -> Option<String> {
        let m = self.mode?;
        Some(if m & 0o7000 != 0 {
            format!("{m:04o}")
        } else {
            format!("{m:03o}")
        })
    }

    /// Parses 3 or 4 octal digits ("644", "0644", "4755").
    ///
    /// Errors: `InvalidInput`.
    pub fn parse_octal(s: &str) -> Result<u32> {
        let invalid =
            || Error::InvalidInput(format!("invalid octal mode \"{}\"", s.escape_debug()));
        if !matches!(s.len(), 3 | 4) || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return Err(invalid());
        }
        u32::from_str_radix(s, 8).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn ts(t: OffsetDateTime, p: Precision) -> Timestamp {
        Timestamp::new(t, p)
    }

    #[test]
    fn permissions_rwx_roundtrip_all_modes() {
        for m in 0..=0o7777 {
            let p = Permissions::from_mode(m);
            let s = p.to_rwx_string().unwrap_or_default();
            assert_eq!(s.len(), 9);
            let back =
                Permissions::from_rwx_string(&s).unwrap_or_else(|e| panic!("{m:o} {s}: {e}"));
            assert_eq!(back.mode, Some(m), "{s}");
            let oct = p.to_octal_string().unwrap_or_default();
            assert_eq!(Permissions::parse_octal(&oct).ok(), Some(m), "{oct}");
        }
    }

    #[test]
    fn permissions_special_bits_render() {
        let r = |m| {
            Permissions::from_mode(m)
                .to_rwx_string()
                .unwrap_or_default()
        };
        assert_eq!(r(0o4755), "rwsr-xr-x");
        assert_eq!(r(0o2644), "rw-r-Sr--");
        assert_eq!(r(0o1777), "rwxrwxrwt");
        assert_eq!(r(0o1776), "rwxrwxrwT");
        assert_eq!(r(0o7777), "rwsrwsrwt");
        assert_eq!(r(0o644), "rw-r--r--");
        assert_eq!(r(0o7644), "rwSr-Sr-T");
        assert_eq!(r(0o177644), "rwSr-Sr-T");
        assert_eq!(Permissions::from_mode(0o100644).mode, Some(0o644));
        assert_eq!(Permissions::from_raw("R").to_rwx_string(), None);
        assert_eq!(
            Permissions::from_mode(0o755)
                .ls_string(&EntryKind::Dir)
                .as_deref(),
            Some("drwxr-xr-x")
        );
        assert_eq!(Permissions::from_raw("R").ls_string(&EntryKind::File), None);
    }

    #[test]
    fn permissions_octal_strings() {
        let o = |m| {
            Permissions::from_mode(m)
                .to_octal_string()
                .unwrap_or_default()
        };
        assert_eq!(o(0o644), "644");
        assert_eq!(o(0o4755), "4755");
        assert_eq!(o(0o7), "007");
        assert_eq!(o(0o1000), "1000");
        assert_eq!(Permissions::from_raw("x").to_octal_string(), None);
        assert_eq!(Permissions::parse_octal("0644").ok(), Some(0o644));
        assert_eq!(Permissions::parse_octal("644").ok(), Some(0o644));
        assert_eq!(Permissions::parse_octal("4755").ok(), Some(0o4755));
        for bad in ["8", "", "64", "64a", "06448", "688", "+644", "７７７"] {
            assert!(
                matches!(Permissions::parse_octal(bad), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn permissions_from_rwx_accepts_type_char_and_acl() {
        let m = |s: &str| Permissions::from_rwx_string(s).ok().and_then(|p| p.mode);
        assert_eq!(m("drwxr-xr-x+"), Some(0o755));
        assert_eq!(m("drwxr-xr-x"), Some(0o755));
        assert_eq!(m("-rw-r--r--@"), Some(0o644));
        assert_eq!(m("rw-r--r--."), Some(0o644));
        assert_eq!(m("rw-r--r--"), Some(0o644));
        assert_eq!(m("lrwxrwxrwx"), Some(0o777));
        for bad in [
            "",
            "rwx",
            "rw-r--r-",
            "drwxr-xr-x++",
            "rwxr-xr-q",
            "xwrr-xr-x",
            "dr\u{e4}xr-xr-x",
        ] {
            assert!(Permissions::from_rwx_string(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn timestamp_cmp_coarse_minute_vs_second() {
        let a = ts(datetime!(2024-01-31 12:00 UTC), Precision::Minute);
        let b = ts(datetime!(2024-01-31 12:00:59 UTC), Precision::Second);
        let c = ts(datetime!(2024-01-31 12:01:00 UTC), Precision::Second);
        assert_eq!(a.cmp_coarse(&b), Ordering::Equal);
        assert_eq!(b.cmp_coarse(&a), Ordering::Equal);
        assert_eq!(a.cmp_coarse(&c), Ordering::Less);
        assert_eq!(c.cmp_coarse(&a), Ordering::Greater);
        assert_eq!(a.abs_diff_coarse(&b), Duration::ZERO);
        assert_eq!(a.abs_diff_coarse(&c), Duration::from_secs(60));
        assert_eq!(c.abs_diff_coarse(&a), Duration::from_secs(60));
    }

    #[test]
    fn timestamp_day_precision_truncates_to_midnight() {
        let t = ts(datetime!(2024-01-31 23:59:59.999 UTC), Precision::Day);
        assert_eq!(t.time, datetime!(2024-01-31 0:00 UTC));
        // Converted to UTC before truncating.
        let t = ts(datetime!(2024-02-01 01:30 +02:00), Precision::Day);
        assert_eq!(t.time, datetime!(2024-01-31 0:00 UTC));
        assert_eq!(t.time.offset(), UtcOffset::UTC);
    }

    #[test]
    fn timestamp_truncation_per_precision() {
        let t = datetime!(2024-01-31 12:34:56.789_654_321 UTC);
        assert_eq!(
            ts(t, Precision::Minute).time,
            datetime!(2024-01-31 12:34 UTC)
        );
        assert_eq!(
            ts(t, Precision::Second).time,
            datetime!(2024-01-31 12:34:56 UTC)
        );
        assert_eq!(
            ts(t, Precision::Millis).time,
            datetime!(2024-01-31 12:34:56.789 UTC)
        );
        let s = ts(t, Precision::Second);
        assert_eq!(s.truncated(Precision::Millis), s);
        let m = s.truncated(Precision::Minute);
        assert_eq!(m.precision, Precision::Minute);
        assert_eq!(m.time, datetime!(2024-01-31 12:34 UTC));
        assert!(Precision::Day < Precision::Minute && Precision::Second < Precision::Millis);
    }

    #[test]
    fn timestamp_serde_format() {
        let t = ts(datetime!(2024-01-31 12:00 UTC), Precision::Minute);
        let json = serde_json::to_string(&t).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"time":"2024-01-31T12:00:00Z","precision":"minute"}"#
        );
        assert_eq!(serde_json::from_str::<Timestamp>(&json).ok(), Some(t));
    }

    #[test]
    fn entry_helpers_and_serde() {
        let e = Entry::new("a", EntryKind::File);
        assert!(!e.is_dir() && !e.is_dir_like() && !e.hidden && e.size.is_none());
        assert!(Entry::new("d", EntryKind::Dir).is_dir_like());
        let link = EntryKind::Symlink {
            target: Some("/x".into()),
            target_kind: Some(SymlinkTarget::Dir),
        };
        let l = Entry::new("l", link.clone());
        assert!(l.is_dir_like() && !l.is_dir());
        assert!(
            !Entry::new(
                "l",
                EntryKind::Symlink {
                    target: None,
                    target_kind: None
                }
            )
            .is_dir_like()
        );
        assert_eq!(
            serde_json::to_string(&link).unwrap_or_default(),
            r#"{"type":"symlink","target":"/x","target_kind":"dir"}"#
        );
        assert_eq!(
            serde_json::to_string(&EntryKind::File).unwrap_or_default(),
            r#"{"type":"file"}"#
        );
        assert_eq!(
            [
                EntryKind::Dir.type_char(),
                link.type_char(),
                EntryKind::File.type_char(),
                EntryKind::Other.type_char()
            ],
            ['d', 'l', '-', '?']
        );
        for good in ["a", "...", " ", "a\\b", ".x"] {
            assert!(Entry::is_valid_name(good), "{good:?}");
        }
        for bad in ["", ".", "..", "a/b", "a\0"] {
            assert!(!Entry::is_valid_name(bad), "{bad:?}");
        }
    }
}
