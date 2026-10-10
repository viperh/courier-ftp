//! OpenVMS lines:
//!
//! ```text
//! NAME.EXT;1  12/24  31-JAN-2024 12:00:00  [GROUP,OWNER]  (RWED,RWED,RE,)
//! ```
//!
//! The version (`;1`) is stripped, `NAME.DIR` is the directory `NAME`. The
//! size column is in 512-byte blocks (the used count when `used/allocated` is
//! shown). Long names put the details on the next line; the
//! [`ListingParser`](super::ListingParser) joins the two.

use courier_ftp_core::{
    listing::{Field, ListingContext, parse_digits, parse_month, parse_time, split_fields},
    model::{Entry, EntryKind, Permissions},
};
use time::{Date, PrimitiveDateTime, Time};

const BLOCK: u64 = 512;

pub(super) fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let (first, rest) = fields.split_first()?;
    let (name, kind) = parse_name(first.text)?;
    let mut entry = Entry::new(name, kind);
    entry.raw = Some(line.to_owned());

    let size_field = rest.first()?;
    // `%RMS-E-PRV, insufficient privilege or file protection violation`
    if size_field.text.starts_with('%') {
        return Some(entry);
    }
    let used = size_field
        .text
        .split_once('/')
        .map_or(size_field.text, |(u, _)| u);
    let blocks: u64 = parse_digits(used, 1, 10)?.into();
    entry.size = blocks.checked_mul(BLOCK);

    let date = parse_date(rest.get(1)?.text)?;
    let mut next = 2;
    let (time, precision) = match rest.get(2).and_then(|f| parse_vms_time(f.text)) {
        Some(t) => {
            next = 3;
            t
        }
        None => (Time::MIDNIGHT, courier_ftp_core::model::Precision::Day),
    };
    entry.modified = ctx.server_time(PrimitiveDateTime::new(date, time), precision);

    let mut tail = rest.get(next..).unwrap_or_default();
    if let Some((owner, used)) = bracketed(tail, '[', ']') {
        match owner.split_once(',') {
            Some((group, owner)) => {
                entry.group = Some(group.to_owned());
                entry.owner = Some(owner.to_owned());
            }
            None => entry.owner = Some(owner),
        }
        tail = &tail[used..];
    }
    if let Some((perms, _)) = bracketed(tail, '(', ')') {
        entry.permissions = Some(Permissions::from_raw(format!("({perms})")));
    }
    Some(entry)
}

/// Whether `line` is only a VMS file name (a long name whose details follow
/// on the next line).
pub(super) fn is_name_only(line: &str) -> bool {
    let fields = split_fields(line);
    matches!(fields.as_slice(), [f] if parse_name(f.text).is_some())
}

/// `NAME.EXT;N` → name without version; `.DIR` → directory.
fn parse_name(token: &str) -> Option<(String, EntryKind)> {
    let (name, version) = token.rsplit_once(';')?;
    if name.is_empty() || parse_digits(version, 1, 5).is_none() {
        return None;
    }
    let upper = name.to_ascii_uppercase();
    match upper.strip_suffix(".DIR") {
        Some(_) if name.len() > 4 => Some((name[..name.len() - 4].to_owned(), EntryKind::Dir)),
        _ => Some((name.to_owned(), EntryKind::File)),
    }
}

/// `31-JAN-2024`.
fn parse_date(token: &str) -> Option<Date> {
    let mut parts = token.split('-');
    let day = u8::try_from(parse_digits(parts.next()?, 1, 2)?).ok()?;
    let month = parse_month(parts.next()?)?;
    let year = i32::try_from(parse_digits(parts.next()?, 4, 4)?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Date::from_calendar_date(year, month, day).ok()
}

/// `12:00`, `12:00:00` or `12:00:00.00` (hundredths are dropped).
fn parse_vms_time(token: &str) -> Option<(Time, courier_ftp_core::model::Precision)> {
    let clock = token.split_once('.').map_or(token, |(c, _)| c);
    parse_time(clock)
}

/// The text between `open` and `close`, which may span several fields, and how
/// many fields it took.
fn bracketed(fields: &[Field<'_>], open: char, close: char) -> Option<(String, usize)> {
    let first = fields.first()?;
    if !first.text.starts_with(open) {
        return None;
    }
    let mut text = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            text.push(' ');
        }
        text.push_str(f.text);
        if f.text.ends_with(close) {
            let inner = text.get(open.len_utf8()..text.len() - close.len_utf8())?;
            return Some((inner.to_owned(), i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::{Duration, macros::datetime};

    use super::*;

    fn ctx() -> ListingContext {
        ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO)
    }

    #[test]
    fn vms_lines() {
        let e = parse_line(
            "LOGIN.COM;12          5/6       31-JAN-2024 12:00:00.45  [STAFF,ALICE]  (RWED,RWED,RE,)",
            &ctx(),
        )
        .unwrap();
        assert_eq!(e.name, "LOGIN.COM");
        assert_eq!(e.size, Some(5 * 512));
        assert_eq!(e.owner.as_deref(), Some("ALICE"));
        assert_eq!(e.group.as_deref(), Some("STAFF"));
        assert_eq!(e.modified.unwrap().time, datetime!(2024-01-31 12:00 UTC));
        assert_eq!(
            e.permissions.unwrap().raw.as_deref(),
            Some("(RWED,RWED,RE,)")
        );
        let e = parse_line(
            "MAIL.DIR;1  1  2-FEB-2023 08:15  [ALICE]  (RWE,RWE,,)",
            &ctx(),
        )
        .unwrap();
        assert_eq!((e.name.as_str(), &e.kind), ("MAIL", &EntryKind::Dir));
        assert_eq!(e.owner.as_deref(), Some("ALICE"));
        let e = parse_line(
            "SECRET.DAT;1 %RMS-E-PRV, insufficient privilege or file protection violation",
            &ctx(),
        )
        .unwrap();
        assert_eq!((e.name.as_str(), e.size), ("SECRET.DAT", None));
        assert!(is_name_only("A_VERY_LONG_FILE_NAME_INDEED.TXT;3"));
        assert!(!is_name_only("NAME.TXT"));
        assert!(parse_line("NAME.TXT;1 5 31-XYZ-2024", &ctx()).is_none());
    }
}
