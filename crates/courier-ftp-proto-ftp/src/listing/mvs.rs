//! MVS / z/OS dataset and PDS member lists (basic: name, directory-ness, date).
//!
//! ```text
//! Volume Unit    Referred Ext Used Recfm Lrecl BlkSz Dsorg Dsname
//! WYOSPT 3390   2024/01/31  1   15  FB      80  6160  PO  ALICE.SOURCE
//! Migrated                                                ALICE.OLD.DATA
//! Pseudo Directory                                        ALICE.PROJECTS
//!
//!  Name     VV.MM   Created       Changed      Size  Init   Mod   Id
//! MEMBER1   01.03 2024/01/30 2024/01/31 12:00    15    10     0 ALICE
//! MEMBER2
//! ```

use courier_ftp_core::listing::{ListingContext, local_to_utc};
use courier_ftp_core::model::{Entry, EntryKind, Precision};
use time::Time;

use super::Outcome;
use super::util::{date_ymd_slash, dt, time_hms};

fn entry(name: &str, kind: EntryKind) -> Entry {
    Entry {
        hidden: name.starts_with('.'),
        ..Entry::new(name, kind)
    }
}

/// One line of a dataset list. A dataset header ends member mode.
pub(super) fn parse_dataset(line: &str, ctx: &ListingContext, member_mode: &mut bool) -> Outcome {
    let toks: Vec<&str> = line.split_ascii_whitespace().take(16).collect();
    match toks.as_slice() {
        [] => return Outcome::NoMatch,
        [first, ..] if *first == "Volume" && toks.contains(&"Dsname") => {
            *member_mode = false;
            return Outcome::Header;
        }
        [m, name] if m.eq_ignore_ascii_case("Migrated") => {
            return Outcome::Entry(entry(unquote(name), EntryKind::File));
        }
        [p, d, name] if *p == "Pseudo" && *d == "Directory" => {
            return Outcome::Entry(entry(unquote(name), EntryKind::Dir));
        }
        _ => {}
    }
    if toks.len() < 5 {
        return Outcome::NoMatch;
    }
    let unit = toks[1];
    if !unit.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Outcome::NoMatch;
    }
    let referred = toks[2];
    let date = if referred == "**NONE**" {
        None
    } else {
        match date_ymd_slash(referred) {
            Some(d) => Some(d),
            None => return Outcome::NoMatch,
        }
    };
    let dsorg = toks[toks.len() - 2];
    if dsorg.is_empty()
        || dsorg.len() > 5
        || !dsorg.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
    {
        return Outcome::NoMatch;
    }
    let name = unquote(toks[toks.len() - 1]);
    let kind = if dsorg == "PO" || dsorg == "PO-E" {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    let mut e = entry(name, kind);
    e.modified = date.map(|d| local_to_utc(dt(d, Time::MIDNIGHT), Precision::Day, ctx));
    Outcome::Entry(e)
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(s)
}

/// 1–8 characters: a letter or `@#$`, then letters, digits or `@#$`.
fn is_member_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 8
        && (b[0].is_ascii_alphabetic() || b"@#$".contains(&b[0]))
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"@#$".contains(c))
}

/// `VV.MM`.
fn is_version(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 5 && b[2] == b'.' && [0, 1, 3, 4].iter().all(|&i| b[i].is_ascii_digit())
}

/// One line of a member list. The member-list header switches member mode on, in which
/// bare member names (and rows of other member-list layouts) are files.
pub(super) fn parse_member(line: &str, ctx: &ListingContext, member_mode: &mut bool) -> Outcome {
    let toks: Vec<&str> = line.split_ascii_whitespace().take(16).collect();
    let Some(&first) = toks.first() else {
        return Outcome::NoMatch;
    };
    if first == "Name" && toks.len() > 1 && (toks.contains(&"VV.MM") || toks.contains(&"Size")) {
        *member_mode = true;
        return Outcome::Header;
    }
    if !is_member_name(first) {
        return Outcome::NoMatch;
    }
    // `NAME VV.MM created changed HH:MM[:SS] size init mod id`
    if toks.len() >= 5 && is_version(toks[1]) && date_ymd_slash(toks[2]).is_some() {
        if let (Some(changed), Some((time, secs))) = (date_ymd_slash(toks[3]), time_hms(toks[4])) {
            let precision = if secs {
                Precision::Second
            } else {
                Precision::Minute
            };
            let mut e = entry(first, EntryKind::File);
            e.modified = Some(local_to_utc(dt(changed, time), precision, ctx));
            return Outcome::Entry(e);
        }
    }
    // Bare names, and load-library rows (`NAME 000060 000005 …`, size in hex).
    let loadlib_row = toks
        .get(1)
        .is_some_and(|t| t.len() == 6 && t.bytes().all(|b| b.is_ascii_hexdigit()));
    if *member_mode && (toks.len() == 1 || loadlib_row) {
        return Outcome::Entry(entry(first, EntryKind::File));
    }
    Outcome::NoMatch
}
