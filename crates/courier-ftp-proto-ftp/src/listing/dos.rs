//! DOS / IIS `dir` style lines.
//!
//! ```text
//! 01-31-24  12:00PM       <DIR>          wwwroot
//! 01-31-2024  09:05AM              1,234 report.txt
//! 2024-01-31  23:59                  42 iso-date.txt
//! 31.01.2024  12:00    <DIR>          Ordner
//! 01-31-24  12:00PM    <JUNCTION>     Documents [C:\Users\alice\Documents]
//! ```

use courier_ftp_core::listing::{ListingContext, local_to_utc};
use courier_ftp_core::model::{Entry, EntryKind, Precision};
use time::{Date, Time};

use super::Outcome;
use super::util::{dt, make_date, next_token, num8, rest_after_blanks, year};

/// `MM-DD-YY`, `MM-DD-YYYY`, `YYYY-MM-DD`, `DD.MM.YYYY` (also `DD.MM.YY`, `MM/DD/YYYY`).
fn parse_date(s: &str) -> Option<Date> {
    let sep = if s.contains('-') {
        '-'
    } else if s.contains('.') {
        '.'
    } else if s.contains('/') {
        '/'
    } else {
        return None;
    };
    let mut it = s.split(sep);
    let (a, b, c) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let (y, m, d) = match sep {
        '-' if a.len() == 4 => (year(a)?, num8(b, 1, 2)?, num8(c, 1, 2)?),
        '-' | '/' => (year(c)?, num8(a, 1, 2)?, num8(b, 1, 2)?),
        _ => (year(c)?, num8(b, 1, 2)?, num8(a, 1, 2)?),
    };
    make_date(y, m, d)
}

/// `HH:MM` with an optional attached `AM`/`PM`; `ampm` is a separate AM/PM token.
fn parse_time(s: &str, ampm: Option<&str>) -> Option<Time> {
    let upper = s.to_ascii_uppercase();
    let (hm, suffix) = if let Some(x) = upper.strip_suffix("AM") {
        (x.to_owned(), Some(false))
    } else if let Some(x) = upper.strip_suffix("PM") {
        (x.to_owned(), Some(true))
    } else {
        let sep = ampm.map(str::to_ascii_uppercase);
        (
            upper.clone(),
            match sep.as_deref() {
                Some("AM") => Some(false),
                Some("PM") => Some(true),
                _ => None,
            },
        )
    };
    let (h, m) = hm.split_once(':')?;
    let h = num8(h, 1, 2)?;
    let m = num8(m, 2, 2)?;
    let h = match suffix {
        None => h,
        Some(pm) => {
            if !(1..=12).contains(&h) {
                return None;
            }
            match (pm, h) {
                (false, 12) => 0,
                (false, h) => h,
                (true, 12) => 12,
                (true, h) => h + 12,
            }
        }
    };
    Time::from_hms(h, m, 0).ok()
}

fn is_header(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("Volume in drive")
        || t.starts_with("Volume Serial Number")
        || t.starts_with("Directory of ")
        || t.contains(" File(s)")
        || t.contains(" Dir(s)")
}

/// One DOS / IIS line.
pub(super) fn parse(line: &str, ctx: &ListingContext) -> Outcome {
    if is_header(line) {
        return Outcome::Header;
    }
    let Some((date_tok, rest)) = next_token(line) else {
        return Outcome::NoMatch;
    };
    let Some(date) = parse_date(date_tok) else {
        return Outcome::NoMatch;
    };
    let Some((time_tok, mut rest)) = next_token(rest) else {
        return Outcome::NoMatch;
    };
    let mut ampm = None;
    if let Some((t, r)) = next_token(rest)
        && (t.eq_ignore_ascii_case("AM") || t.eq_ignore_ascii_case("PM"))
    {
        ampm = Some(t);
        rest = r;
    }
    let Some(time) = parse_time(time_tok, ampm) else {
        return Outcome::NoMatch;
    };
    let Some((field, rest)) = next_token(rest) else {
        return Outcome::NoMatch;
    };
    let name_part = rest_after_blanks(rest);
    let upper = field.to_ascii_uppercase();
    let (kind, size, name) = match upper.as_str() {
        "<DIR>" => (EntryKind::Dir, None, name_part),
        "<JUNCTION>" | "<SYMLINKD>" | "<SYMLINK>" => {
            let (name, target) = match name_part
                .strip_suffix(']')
                .and_then(|s| s.rsplit_once(" ["))
            {
                Some((n, t)) => (n, Some(t.to_owned())),
                None => (name_part, None),
            };
            (
                EntryKind::Symlink {
                    target,
                    target_kind: None,
                },
                None,
                name,
            )
        }
        _ => {
            let digits: String = field.chars().filter(|&c| c != ',' && c != '.').collect();
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Outcome::NoMatch;
            }
            match digits.parse::<u64>() {
                Ok(n) => (EntryKind::File, Some(n), name_part),
                Err(_) => return Outcome::BadNumber,
            }
        }
    };
    Outcome::Entry(Entry {
        name: name.to_owned(),
        kind,
        size,
        modified: Some(local_to_utc(dt(date, time), Precision::Minute, ctx)),
        permissions: None,
        owner: None,
        group: None,
        hidden: name.starts_with('.'),
    })
}
