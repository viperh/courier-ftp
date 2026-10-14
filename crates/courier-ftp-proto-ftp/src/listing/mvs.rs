//! IBM MVS / z/OS listings (basic support: name, directory-ness, a date).
//!
//! Datasets (`LIST` at a high-level qualifier):
//!
//! ```text
//! Volume Unit    Referred Ext Used Recfm Lrecl BlkSz Dsorg Dsname
//! WORK01 3390   2024/01/31  1   15  FB      80 27920  PO  SOURCE.COBOL
//! Migrated                                                OLD.DATA
//! ```
//!
//! Partitioned dataset (PDS) members:
//!
//! ```text
//!  Name     VV.MM   Created       Changed      Size  Init   Mod   Id
//!  MEMBER1   01.03 2002/09/12 2024/01/31 09:37    11    11     0 USER01
//! ```
//!
//! Sizes are unknown (tracks and line counts are not bytes). A partitioned
//! dataset (`PO`, `PO-E`) and a "Pseudo Directory" are directories. The
//! dataset date is the *referred* (last used) date, with day precision.

use courier_ftp_core::{
    listing::{ListingContext, date_from_numbers, parse_digits, parse_time, split_fields},
    model::{Entry, EntryKind, Precision},
};
use time::{Date, PrimitiveDateTime, Time};

/// A dataset line.
pub(super) fn parse_dataset(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let texts: Vec<&str> = fields.iter().map(|f| f.text).collect();
    let (name, before) = texts.split_last()?;
    if !is_dsname(name) {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    let mut entry = if lower.starts_with("migrated") {
        Entry::new(*name, EntryKind::File)
    } else if lower.starts_with("pseudo directory") {
        Entry::new(*name, EntryKind::Dir)
    } else if lower.contains("not direct access device") || lower.starts_with("tape ") {
        Entry::new(*name, EntryKind::File)
    } else {
        // VOLUME UNIT REFERRED EXT USED [RECFM LRECL BLKSZ] DSORG
        if !(5..=9).contains(&before.len()) {
            return None;
        }
        let dsorg = before.last()?;
        if !is_dsorg(dsorg) {
            return None;
        }
        let referred = before.get(2)?;
        let date = match *referred {
            "**NONE**" => None,
            d => Some(parse_slash_date(d)?),
        };
        if !before
            .get(3..5)?
            .iter()
            .all(|f| parse_digits(f, 1, 6).is_some() || *f == "?")
        {
            return None;
        }
        let kind = if dsorg.starts_with("PO") {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let mut e = Entry::new(*name, kind);
        e.modified = date.and_then(|d| {
            ctx.server_time(PrimitiveDateTime::new(d, Time::MIDNIGHT), Precision::Day)
        });
        e
    };
    entry.raw = Some(line.to_owned());
    Some(entry)
}

/// A PDS member line with statistics, or a load-module member line
/// (`NAME  000A40  00000E  00  FO ...`).
pub(super) fn parse_member(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let texts: Vec<&str> = fields.iter().map(|f| f.text).collect();
    let name = *texts.first()?;
    if !is_member_name(name) {
        return None;
    }
    let mut entry = Entry::new(name, EntryKind::File);
    entry.raw = Some(line.to_owned());
    // Source member: NAME VV.MM CREATED CHANGED TIME SIZE INIT MOD ID
    if texts.len() >= 5 && is_version(texts[1]) {
        parse_slash_date(texts[2])?;
        let changed = parse_slash_date(texts[3])?;
        let (time, precision) = parse_time(texts[4])?;
        entry.modified = ctx.server_time(PrimitiveDateTime::new(changed, time), precision);
        if texts.len() >= 9 {
            entry.owner = texts.get(8).map(|s| (*s).to_owned());
        }
        return Some(entry);
    }
    // Load module: NAME SIZE(hex) TTR(hex) ...
    if texts.len() >= 3 && is_hex(texts[1]) && is_hex(texts[2]) {
        return Some(entry);
    }
    None
}

/// Whether `line` is a header of a dataset or member listing.
pub(super) fn is_header(line: &str) -> bool {
    let fields = split_fields(line);
    match fields.as_slice() {
        [a, b, ..] => {
            (a.text.eq_ignore_ascii_case("volume") && b.text.eq_ignore_ascii_case("unit"))
                || (a.text.eq_ignore_ascii_case("name")
                    && (b.text.eq_ignore_ascii_case("vv.mm")
                        || b.text.eq_ignore_ascii_case("size")))
        }
        _ => false,
    }
}

/// A member name alone (members without statistics).
pub(super) fn is_bare_member(line: &str) -> bool {
    let fields = split_fields(line);
    matches!(fields.as_slice(), [f] if is_member_name(f.text))
}

/// `YYYY/MM/DD`.
fn parse_slash_date(token: &str) -> Option<Date> {
    let mut parts = token.split('/');
    let year = i32::try_from(parse_digits(parts.next()?, 4, 4)?).ok()?;
    let month = parse_digits(parts.next()?, 1, 2)?;
    let day = parse_digits(parts.next()?, 1, 2)?;
    if parts.next().is_some() {
        return None;
    }
    date_from_numbers(year, month, day)
}

fn is_dsname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 44
        && s.split('.').all(|q| {
            (1..=8).contains(&q.len())
                && q.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '$' | '#' | '@' | '-'))
        })
}

fn is_member_name(s: &str) -> bool {
    (1..=8).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '$' | '#' | '@'))
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

fn is_dsorg(s: &str) -> bool {
    matches!(
        s,
        "PS" | "PO" | "PO-E" | "DA" | "IS" | "VS" | "PS-E" | "PS-L" | "U" | "?"
    )
}

/// `01.03`.
fn is_version(s: &str) -> bool {
    matches!(s.split_once('.'), Some((v, m)) if parse_digits(v, 2, 2).is_some() && parse_digits(m, 2, 2).is_some())
}

fn is_hex(s: &str) -> bool {
    (2..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
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
    fn datasets() {
        let e = parse_dataset(
            "WORK01 3390   2024/01/31  1   15  FB      80 27920  PO  SOURCE.COBOL",
            &ctx(),
        )
        .unwrap();
        assert_eq!(
            (e.name.as_str(), &e.kind),
            ("SOURCE.COBOL", &EntryKind::Dir)
        );
        assert_eq!(e.modified.unwrap().time, datetime!(2024-01-31 0:00 UTC));
        let e = parse_dataset(
            "WORK02 3390   2023/12/01  2  300  VB   32756 32760  PS  LOGS.DAILY",
            &ctx(),
        )
        .unwrap();
        assert_eq!((e.kind, e.size), (EntryKind::File, None));
        let e = parse_dataset(
            "Migrated                                         OLD.DATA",
            &ctx(),
        )
        .unwrap();
        assert_eq!(e.name, "OLD.DATA");
        let e = parse_dataset(
            "Pseudo Directory                                 SUB",
            &ctx(),
        )
        .unwrap();
        assert_eq!(e.kind, EntryKind::Dir);
        assert!(is_header(
            "Volume Unit    Referred Ext Used Recfm Lrecl BlkSz Dsorg Dsname"
        ));
    }

    #[test]
    fn members() {
        let e = parse_member(
            " MEMBER1   01.03 2002/09/12 2024/01/31 09:37    11    11     0 USER01",
            &ctx(),
        )
        .unwrap();
        assert_eq!(e.name, "MEMBER1");
        assert_eq!(e.owner.as_deref(), Some("USER01"));
        assert_eq!(e.modified.unwrap().time, datetime!(2024-01-31 9:37 UTC));
        let e = parse_member(
            "LOADMOD1  000A40   00000E  00  FO RN RU   31    ANY",
            &ctx(),
        )
        .unwrap();
        assert_eq!(e.name, "LOADMOD1");
        assert!(is_header(
            " Name     VV.MM   Created       Changed      Size  Init   Mod   Id"
        ));
        assert!(is_bare_member(" MEMBER9"));
        assert!(parse_member("toolongname 01.03 2002/09/12 2024/01/31 09:37", &ctx()).is_none());
    }
}
