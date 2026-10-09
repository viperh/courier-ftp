//! OpenVMS `DIRECTORY` style lines.
//!
//! ```text
//! Directory DISK$USER:[ALICE]
//!
//! LOGIN.COM;3               2/4        31-JAN-2024 12:00:05.32  [STAFF,ALICE]   (RWED,RWED,RE,)
//! A_VERY_LONG_FILE_NAME_THAT_WRAPS.TXT;12
//!                          10/12       01-FEB-2024 09:15        [STAFF,ALICE]   (RWED,RWED,R,)
//!
//! Total of 3 files, 13/18 blocks.
//! ```
//!
//! Sizes are used blocks × 512 bytes (an approximation: VMS does not report bytes).

use std::collections::HashSet;

use courier_ftp_core::listing::{ListingContext, local_to_utc, parse_month};
use courier_ftp_core::model::{Entry, EntryKind, Permissions, Precision};
use time::{Date, Time};

use super::Outcome;
use super::util::{dt, is_digits, make_date, num, num8, time_hms};

const BLOCK_SIZE: u64 = 512;

/// `NAME.EXT;VERSION` → (`NAME.EXT`, version ok).
fn split_version(tok: &str) -> Option<&str> {
    let (base, ver) = tok.rsplit_once(';')?;
    if base.is_empty() || ver.is_empty() || ver.len() > 5 || !is_digits(ver) {
        return None;
    }
    Some(base)
}

/// `DD-MMM-YYYY`.
fn parse_date(s: &str) -> Option<Date> {
    let mut it = s.split('-');
    let d = num8(it.next()?, 1, 2)?;
    let m = parse_month(it.next()?)?;
    let y = i32::try_from(num(it.next()?, 4, 4)?).ok()?;
    if it.next().is_some() {
        return None;
    }
    make_date(y, m, d)
}

/// `%FACILITY-L-IDENT, text` message lines.
fn is_message(t: &str) -> bool {
    let Some(rest) = t.strip_prefix('%') else {
        return false;
    };
    let head = rest.split([',', ' ']).next().unwrap_or("");
    let mut parts = head.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(fac), Some(sev), Some(id))
            if !fac.is_empty() && sev.len() == 1 && !id.is_empty()
    )
}

/// One VMS line. `seen` holds names already listed (only the first, highest version of
/// a file is kept).
pub(super) fn parse(line: &str, ctx: &ListingContext, seen: &mut HashSet<String>) -> Outcome {
    let t = line.trim();
    if t.starts_with("Directory ") || t.starts_with("Total of ") || t.starts_with("Grand total of ")
    {
        return Outcome::Header;
    }
    if is_message(t) {
        return Outcome::LoggedHeader;
    }
    let mut toks = t.split_ascii_whitespace();
    let Some(first) = toks.next() else {
        return Outcome::NoMatch;
    };
    let Some(base) = split_version(first) else {
        return Outcome::NoMatch;
    };
    let rest: Vec<&str> = toks.take(16).collect();
    if rest.is_empty() {
        return Outcome::Pending;
    }
    let mut i = 0;
    // Optional size column: `used` or `used/allocated` blocks.
    let mut blocks = None;
    if let Some(tok) = rest.first() {
        let used = tok.split('/').next().unwrap_or("");
        if is_digits(used) && tok.split('/').all(is_digits) {
            match used.parse::<u64>() {
                Ok(n) => blocks = Some(n),
                Err(_) => return Outcome::BadNumber,
            }
            i += 1;
        }
    }
    let Some(date) = rest.get(i).and_then(|d| parse_date(d)) else {
        return Outcome::NoMatch;
    };
    i += 1;
    let (time, precision) = match rest.get(i).and_then(|t| time_hms(t)) {
        Some((time, secs)) => {
            i += 1;
            (
                time,
                if secs {
                    Precision::Second
                } else {
                    Precision::Minute
                },
            )
        }
        None => (Time::MIDNIGHT, Precision::Day),
    };
    let mut owner = None;
    let mut group = None;
    let mut permissions = None;
    for tok in &rest[i..] {
        if let Some(inner) = tok.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match inner.split_once(',') {
                Some((g, o)) => {
                    group = Some(g.to_owned());
                    owner = Some(o.to_owned());
                }
                None => owner = Some(inner.to_owned()),
            }
        } else if tok.starts_with('(') && tok.ends_with(')') {
            permissions = Some(Permissions::from_raw(*tok));
        }
    }

    let upper = base.to_ascii_uppercase();
    let (name, kind) = if upper.ends_with(".DIR") {
        (&base[..base.len() - 4], EntryKind::Dir)
    } else {
        (base, EntryKind::File)
    };
    let size = match (kind == EntryKind::File, blocks) {
        (true, Some(b)) => match b.checked_mul(BLOCK_SIZE) {
            Some(n) => Some(n),
            None => return Outcome::BadNumber,
        },
        _ => None,
    };
    if !seen.insert(name.to_owned()) {
        return Outcome::Ignore;
    }
    Outcome::Entry(Entry {
        name: name.to_owned(),
        kind,
        size,
        modified: Some(local_to_utc(dt(date, time), precision, ctx)),
        permissions,
        owner,
        group,
        hidden: name.starts_with('.'),
    })
}
