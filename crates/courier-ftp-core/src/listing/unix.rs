//! Unix `ls -l` lines: GNU/BSD ls, vsftpd, ProFTPD, pure-ftpd, Windows servers with
//! Unix-style output, and SFTP `longname` (T22).
//!
//! A hand-written token scanner (no regex, no recursion); every number is parsed with
//! overflow checks.

use time::{PrimitiveDateTime, Time};

use super::{
    ListingContext, infer_year, local_to_utc, make_date, parse_hh_mm, parse_month, parse_small,
    parse_year4,
};
use crate::model::{Entry, EntryKind, Permissions, Precision};

/// Why [`try_parse_line`] did not return an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineError {
    /// A `total N` header line.
    Header,
    /// Not a Unix `ls -l` line.
    NotUnix,
    /// A Unix line whose size does not fit in a `u64`.
    BadNumber,
}

/// One `ls -l` line → `Entry`. `None` for headers (`total N`) and
/// lines that are not Unix format.
///
/// The name is returned as the server sent it (it may be `.`, `..`, empty, or contain
/// characters that are unsafe locally); callers apply their own name rules.
/// `hidden` is set for names starting with `.`.
pub fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry> {
    try_parse_line(line, ctx).ok()
}

/// `true` for the `total N` summary line (`total 24`, `total 1.5M`).
pub fn is_header(line: &str) -> bool {
    let mut it = line.split_ascii_whitespace();
    matches!(
        (it.next(), it.next(), it.next()),
        (Some(t), Some(n), None)
            if t.eq_ignore_ascii_case("total")
                && n.starts_with(|c: char| c.is_ascii_digit())
                && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b',')
    )
}

/// Like [`parse_line`], with the reason when no entry is returned.
///
/// Errors: [`LineError`].
pub fn try_parse_line(line: &str, ctx: &ListingContext) -> Result<Entry, LineError> {
    if is_header(line) {
        return Err(LineError::Header);
    }
    let toks = Tokens::new(line);
    if toks.len() < 4 {
        return Err(LineError::NotUnix);
    }
    let mode = toks.get(0);
    if !is_mode(mode) {
        return Err(LineError::NotUnix);
    }
    let links_numeric = is_digits(toks.get(1));

    let mut found = None;
    for i in 2..toks.len() {
        let Some(size_first) = size_start(&toks, i) else {
            continue;
        };
        if let Some(date) = match_date(&toks, i, ctx) {
            found = Some((size_first, i, date));
            break;
        }
    }
    let Some((size_first, size_end, date)) = found else {
        return Err(LineError::NotUnix);
    };

    // Size: digits, or `major,` `minor` / `major,minor` for device files.
    let device = size_first + 1 != size_end || toks.get(size_end - 1).contains(',');
    let size = if device {
        None
    } else {
        Some(
            toks.get(size_end - 1)
                .parse::<u64>()
                .map_err(|_| LineError::BadNumber)?,
        )
    };

    // Owner and group: the tokens between the link count and the size.
    let owner_start = if links_numeric { 2 } else { 1 };
    let (owner, group) = if size_first > owner_start {
        let owner = toks.get(owner_start).to_owned();
        let group = if size_first > owner_start + 1 {
            let parts: Vec<&str> = (owner_start + 1..size_first).map(|j| toks.get(j)).collect();
            Some(parts.join(" "))
        } else {
            None
        };
        (Some(owner), group)
    } else {
        (None, None)
    };

    // Name: everything after the date's last token and one separator.
    let rest = &line[toks.end(date.last)..];
    let rest = rest
        .strip_prefix(' ')
        .or_else(|| rest.strip_prefix('\t'))
        .unwrap_or(rest);

    let type_char = mode.as_bytes().first().copied().unwrap_or(b'?');
    let (name, kind) = match type_char {
        b'-' if !device => (rest.to_owned(), EntryKind::File),
        b'd' => (rest.to_owned(), EntryKind::Dir),
        b'l' => match rest.split_once(" -> ") {
            Some((n, t)) => (
                n.to_owned(),
                EntryKind::Symlink {
                    target: Some(t.to_owned()),
                    target_kind: None,
                },
            ),
            None => (
                rest.to_owned(),
                EntryKind::Symlink {
                    target: None,
                    target_kind: None,
                },
            ),
        },
        _ => (rest.to_owned(), EntryKind::Other),
    };

    let perm_chars = mode.get(..10).unwrap_or(mode);
    let permissions = Permissions::from_rwx_string(perm_chars)
        .unwrap_or_else(|_| Permissions::from_raw(perm_chars.get(1..).unwrap_or(perm_chars)));

    let local_ctx = match date.zone {
        Some(z) => ListingContext {
            tz_offset_minutes: z,
            ..*ctx
        },
        None => *ctx,
    };
    let modified = local_to_utc(date.dt, date.precision, &local_ctx);

    let hidden = name.starts_with('.');
    Ok(Entry {
        name,
        kind,
        size,
        modified: Some(modified),
        permissions: Some(permissions),
        owner,
        group,
        hidden,
    })
}

/// At most this many tokens are scanned (mode … date); the name is taken from the line.
const MAX_TOKENS: usize = 32;

/// Byte ranges of the space/tab-separated tokens of a line.
struct Tokens<'a> {
    line: &'a str,
    /// Fixed-size storage: no allocation per line.
    spans: [(usize, usize); MAX_TOKENS],
    len: usize,
}

impl<'a> Tokens<'a> {
    fn new(line: &'a str) -> Self {
        let mut spans = [(0, 0); MAX_TOKENS];
        let mut len = 0;
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() && len < MAX_TOKENS {
            while i < bytes.len() && is_sep(bytes[i]) {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            let start = i;
            while i < bytes.len() && !is_sep(bytes[i]) {
                i += 1;
            }
            spans[len] = (start, i);
            len += 1;
        }
        Self { line, spans, len }
    }

    fn len(&self) -> usize {
        self.len
    }

    /// Token `i`, or "" past the end.
    fn get(&self, i: usize) -> &'a str {
        self.spans[..self.len]
            .get(i)
            .and_then(|&(s, e)| self.line.get(s..e))
            .unwrap_or("")
    }

    /// End byte offset of token `i` (line length past the end).
    fn end(&self, i: usize) -> usize {
        self.spans[..self.len]
            .get(i)
            .map_or(self.line.len(), |&(_, e)| e)
    }
}

fn is_sep(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `drwxr-xr-x`, optionally followed by one ACL/xattr marker (`+`, `.`, `@`).
fn is_mode(s: &str) -> bool {
    let b = s.as_bytes();
    if !(b.len() == 10 || b.len() == 11) {
        return false;
    }
    b"-dlbcpsDn?".contains(&b[0])
        && b[1..10].iter().all(|c| b"rwxsStTlL-".contains(c))
        && (b.len() == 10 || b"+.@".contains(&b[10]))
}

/// If the token(s) just before index `date_idx` are a size (digits) or a device number
/// (`major,` `minor` or `major,minor`), the index of the first of them.
fn size_start(toks: &Tokens<'_>, date_idx: usize) -> Option<usize> {
    let t = toks.get(date_idx - 1);
    if is_digits(t) {
        if date_idx >= 3 {
            let prev = toks.get(date_idx - 2);
            if let Some(major) = prev.strip_suffix(',')
                && is_digits(major)
            {
                return Some(date_idx - 2);
            }
        }
        return Some(date_idx - 1);
    }
    if let Some((a, b)) = t.split_once(',')
        && is_digits(a)
        && is_digits(b)
    {
        return Some(date_idx - 1);
    }
    None
}

struct DateMatch {
    /// Index of the date's last token.
    last: usize,
    dt: PrimitiveDateTime,
    precision: Precision,
    /// An explicit `±HHMM` zone in minutes (full-iso).
    zone: Option<i32>,
}

/// A day of month: 1–2 digits, optional trailing `.`, `日` or `일`.
fn parse_day(s: &str) -> Option<u8> {
    let s = s
        .strip_suffix('.')
        .or_else(|| s.strip_suffix('日'))
        .or_else(|| s.strip_suffix('일'))
        .unwrap_or(s);
    let d = parse_small(s, 1, 2)?;
    (1..=31).contains(&d).then_some(d)
}

enum TimeOrYear {
    Time(u8, u8),
    Year(i32),
}

fn parse_time_or_year(s: &str) -> Option<TimeOrYear> {
    if let Some((h, m)) = parse_hh_mm(s) {
        return Some(TimeOrYear::Time(h, m));
    }
    let y = s
        .strip_suffix('年')
        .or_else(|| s.strip_suffix('년'))
        .unwrap_or(s);
    parse_year4(y).map(TimeOrYear::Year)
}

fn match_date(toks: &Tokens<'_>, i: usize, ctx: &ListingContext) -> Option<DateMatch> {
    let t0 = toks.get(i);
    if t0.is_empty() {
        return None;
    }
    // `YYYY-MM-DD HH:MM[:SS[.frac]] [±HHMM]`.
    if t0.len() == 10 && t0.as_bytes()[4] == b'-' {
        return match_iso(toks, i);
    }
    let t1 = toks.get(i + 1);
    let t2 = toks.get(i + 2);
    if t1.is_empty() || t2.is_empty() {
        return None;
    }
    // `Mon DD HH:MM|YYYY` (also `N月 DD …`), then `DD Mon HH:MM|YYYY` (also `DD.`).
    let (month, day) = if let (Some(m), Some(d)) = (parse_month(t0), parse_day(t1)) {
        (m, d)
    } else if let (Some(d), Some(m)) = (parse_day(t0), parse_month(t1)) {
        (m, d)
    } else {
        return None;
    };
    let (dt, precision) = match parse_time_or_year(t2)? {
        TimeOrYear::Year(y) => (
            PrimitiveDateTime::new(make_date(y, month, day)?, Time::MIDNIGHT),
            Precision::Day,
        ),
        TimeOrYear::Time(h, m) => {
            let y = infer_year(month, day, h, m, ctx)?;
            (
                PrimitiveDateTime::new(make_date(y, month, day)?, Time::from_hms(h, m, 0).ok()?),
                Precision::Minute,
            )
        }
    };
    Some(DateMatch {
        last: i + 2,
        dt,
        precision,
        zone: None,
    })
}

fn match_iso(toks: &Tokens<'_>, i: usize) -> Option<DateMatch> {
    let d = toks.get(i);
    let (y, rest) = d.split_once('-')?;
    let (mo, da) = rest.split_once('-')?;
    let date = make_date(
        parse_year4(y)?,
        parse_small(mo, 2, 2)?,
        parse_small(da, 2, 2)?,
    )?;

    let t = toks.get(i + 1);
    let (hm, sec_part) = match t.get(..5) {
        Some(hm) if t.len() == 5 => (hm, None),
        Some(hm) if t.as_bytes().get(5) == Some(&b':') => (hm, t.get(6..)),
        _ => return None,
    };
    let (h, m) = parse_hh_mm(hm)?;
    let (sec, nanos, precision) = match sec_part {
        None => (0, 0, Precision::Minute),
        Some(s) => {
            let (whole, frac) = match s.split_once('.') {
                Some((w, f)) => (w, Some(f)),
                None => (s, None),
            };
            let sec = parse_small(whole, 2, 2)?;
            if sec > 59 {
                return None;
            }
            match frac {
                None => (sec, 0, Precision::Second),
                Some(f) => {
                    if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                    let mut nanos: u32 = 0;
                    for k in 0..9 {
                        let digit = f.as_bytes().get(k).map_or(0, |b| u32::from(b - b'0'));
                        nanos = nanos * 10 + digit;
                    }
                    (sec, nanos, Precision::Millis)
                }
            }
        }
    };
    let time = Time::from_hms_nano(h, m, sec, nanos).ok()?;

    let z = toks.get(i + 2);
    let zone = parse_zone(z);
    Some(DateMatch {
        last: if zone.is_some() { i + 2 } else { i + 1 },
        dt: PrimitiveDateTime::new(date, time),
        precision,
        zone,
    })
}

/// `+0100` / `-0530` → minutes.
fn parse_zone(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    if b.len() != 5 || !(b[0] == b'+' || b[0] == b'-') {
        return None;
    }
    let hh = i32::from(parse_small(s.get(1..3)?, 2, 2)?);
    let mm = i32::from(parse_small(s.get(3..5)?, 2, 2)?);
    if hh > 23 || mm > 59 {
        return None;
    }
    let total = hh * 60 + mm;
    Some(if b[0] == b'-' { -total } else { total })
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::model::Timestamp;

    fn ctx() -> ListingContext {
        ListingContext::new(datetime!(2024-06-15 12:00 UTC), 0)
    }

    fn p(line: &str) -> Entry {
        parse_line(line, &ctx()).unwrap_or_else(|| panic!("no entry for {line:?}"))
    }

    #[test]
    fn unix_parses_group_and_groupless() {
        let e = p("drwxr-xr-x    2 alice    staff        4096 Jan 31 12:00 public_html");
        assert_eq!(e.name, "public_html");
        assert_eq!(e.kind, EntryKind::Dir);
        assert_eq!(e.size, Some(4096));
        assert_eq!(e.owner.as_deref(), Some("alice"));
        assert_eq!(e.group.as_deref(), Some("staff"));
        assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o755));
        assert_eq!(
            e.modified,
            Some(Timestamp::new(
                datetime!(2024-01-31 12:00 UTC),
                Precision::Minute
            ))
        );
        let e = p("-rw-r--r--    1 ftp            42 Mar 15 08:00 no-group.txt");
        assert_eq!(e.owner.as_deref(), Some("ftp"));
        assert_eq!(e.group, None);
        assert_eq!(e.size, Some(42));
        // No link count column, two-word group.
        let e = p("-rw-r--r-- alice domain users 7 Jan 31 12:00 x");
        assert_eq!(e.owner.as_deref(), Some("alice"));
        assert_eq!(e.group.as_deref(), Some("domain users"));
        let e = p("-rw-r--r-- 7 Jan 31 12:00 x");
        assert_eq!((e.owner, e.group, e.size), (None, None, Some(7)));
    }

    #[test]
    fn unix_numeric_owner() {
        let e = p("-rw-r--r--    1 1000     1000            12 Jan 31 12:00 n.txt");
        assert_eq!(e.owner.as_deref(), Some("1000"));
        assert_eq!(e.group.as_deref(), Some("1000"));
        assert_eq!(e.size, Some(12));
    }

    #[test]
    fn unix_device_file_has_no_size() {
        let e = p("crw-rw-rw-    1 root     root        1,   3 Jan  1  2024 null");
        assert_eq!(e.kind, EntryKind::Other);
        assert_eq!(e.size, None);
        assert_eq!(e.name, "null");
        assert_eq!(e.group.as_deref(), Some("root"));
        let e = p("brw-rw----    1 root     disk      8,0 Jan  1  2024 sda");
        assert_eq!((e.kind, e.size), (EntryKind::Other, None));
    }

    #[test]
    fn unix_acl_marker_accepted() {
        for m in ['+', '.', '@'] {
            let e = p(&format!("-rw-r--r--{m}   1 a b 12 Jan 31 12:00 f"));
            assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o644));
        }
        assert!(parse_line("-rw-r--r--x   1 a b 12 Jan 31 12:00 f", &ctx()).is_none());
    }

    #[test]
    fn unix_total_line_is_header() {
        assert!(is_header("total 24"));
        assert!(is_header("total 1.5M"));
        assert!(!is_header("total"));
        assert!(!is_header("totally 24"));
        assert_eq!(try_parse_line("total 24", &ctx()), Err(LineError::Header));
        assert_eq!(
            try_parse_line("hello world foo bar", &ctx()),
            Err(LineError::NotUnix)
        );
    }

    #[test]
    fn unix_iso_and_full_iso_dates() {
        let e = p("-rw-r--r--    1 alice    staff        100 2024-01-31 12:00 iso.txt");
        assert_eq!(e.name, "iso.txt");
        assert_eq!(
            e.modified,
            Some(Timestamp::new(
                datetime!(2024-01-31 12:00 UTC),
                Precision::Minute
            ))
        );
        let e = p(
            "-rw-r--r--    1 alice    staff        100 2024-01-31 12:00:05.123456789 +0100 full-iso.txt",
        );
        assert_eq!(e.name, "full-iso.txt");
        let m = e.modified.unwrap_or_else(|| panic!("no time"));
        assert_eq!(m.precision, Precision::Millis);
        assert_eq!(m.time, datetime!(2024-01-31 11:00:05.123 UTC));
        // The explicit zone overrides the site offset.
        let c = ListingContext::new(datetime!(2024-06-15 12:00 UTC), 600);
        let e = parse_line("-rw-r--r-- 1 a b 1 2024-01-31 12:00:05 -0130 x", &c)
            .unwrap_or_else(|| panic!("no entry"));
        let m = e.modified.unwrap_or_else(|| panic!("no time"));
        assert_eq!(m.precision, Precision::Second);
        assert_eq!(m.time, datetime!(2024-01-31 13:30:05 UTC));
    }

    #[test]
    fn unix_name_with_leading_spaces() {
        let e = p("-rw-r--r--+   1 1000     1000            12 Jan 31 12:00  leading space.txt");
        assert_eq!(e.name, " leading space.txt");
        let e = p("-rw-r--r-- 1 a b 12 Jan 31 12:00 trailing  ");
        assert_eq!(e.name, "trailing  ");
    }

    #[test]
    fn unix_symlink_with_arrow_in_name_split_at_first() {
        let e = p("lrwxrwxrwx    1 root     root            11 Feb  3 09:15 www -> /var/www");
        assert_eq!(e.name, "www");
        assert_eq!(
            e.kind,
            EntryKind::Symlink {
                target: Some("/var/www".into()),
                target_kind: None
            }
        );
        let e = p("lrwxrwxrwx 1 a b 1 Feb  3 09:15 a -> b -> c");
        assert_eq!(e.name, "a");
        assert!(matches!(e.kind, EntryKind::Symlink { target: Some(ref t), .. } if t == "b -> c"));
    }

    #[test]
    fn unix_regular_file_with_arrow_kept() {
        let e = p("-rw-r--r-- 1 a b 1 Feb  3 09:15 a -> b");
        assert_eq!(e.name, "a -> b");
        assert_eq!(e.kind, EntryKind::File);
    }

    #[test]
    fn unix_size_over_4gib() {
        let e = p("-rw-r--r--    1 alice    staff     5368709120 Jan 31  2023 big.iso");
        assert_eq!(e.size, Some(5_368_709_120));
        let m = e.modified.unwrap_or_else(|| panic!("no time"));
        assert_eq!(m.precision, Precision::Day);
        assert_eq!(m.time, datetime!(2023-01-31 0:00 UTC));
        assert_eq!(
            try_parse_line(
                "-rw-r--r-- 1 a b 99999999999999999999999 Jan 31  2023 big.iso",
                &ctx()
            ),
            Err(LineError::BadNumber)
        );
    }

    #[test]
    fn unix_localised_dates() {
        let e = p("-rw-r--r--    1 hans     users        100 31. Jän 12:00 datei.txt");
        assert_eq!(e.name, "datei.txt");
        assert_eq!(
            e.modified.map(|m| m.time),
            Some(datetime!(2024-01-31 12:00 UTC))
        );
        let e = p("-rw-r--r-- 1 a b 100 1月 31 2023 中文.txt");
        assert_eq!(e.name, "中文.txt");
        assert_eq!(
            e.modified.map(|m| m.time),
            Some(datetime!(2023-01-31 0:00 UTC))
        );
        let e = p("-rw-r--r-- 1 a b 100 12월 31일 12:00 한국어.txt");
        assert_eq!(
            e.modified.map(|m| m.time),
            Some(datetime!(2023-12-31 12:00 UTC))
        );
    }

    #[test]
    fn unix_rejects_garbage() {
        for l in [
            "",
            "-",
            "drwxr-xr-x",
            "drwxr-xr-x 2 a b 4096",
            "xrwxr-xr-x 2 a b 4096 Jan 31 12:00 x",
            "drwxr-xr-x 2 a b 4096 Foo 31 12:00 x",
            "drwxr-xr-x 2 a b 4096 Jan 32 12:00 x",
            "drwxr-xr-x 2 a b 4096 Feb 30 2023 x",
            "01-31-24  12:00PM       <DIR>          wwwroot",
        ] {
            assert!(parse_line(l, &ctx()).is_none(), "{l:?}");
        }
    }

    #[test]
    fn unix_hidden_and_windows_style() {
        let e = p("----------    1 owner    group        1234 Jan 31 12:00 windows-nt.txt");
        assert_eq!(e.permissions.and_then(|p| p.mode), Some(0));
        assert!(!e.hidden);
        assert!(p("-rw------- 1 a b 1 Jan 31 12:00 .profile").hidden);
        // Mandatory-locking chars are kept as raw text.
        let e = p("-rw-r-lr-- 1 a b 1 Jan 31 12:00 locked");
        assert_eq!(
            e.permissions.and_then(|p| p.raw).as_deref(),
            Some("rw-r-lr--")
        );
    }
}
