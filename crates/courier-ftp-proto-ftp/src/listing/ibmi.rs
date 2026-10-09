//! IBM i (OS/400, QSYS) lines.
//!
//! ```text
//! ALICE          36864 01/31/24 12:00:05 *DIR       projects/
//! QSYS           77824 01/30/24 08:00:00 *FILE      MYLIB.LIB/MYFILE.FILE
//!                                        *MEM       MYLIB.LIB/MYFILE.FILE/MBR1.MBR
//! ```

use courier_ftp_core::listing::{ListingContext, local_to_utc};
use courier_ftp_core::model::{Entry, EntryKind, Precision};
use time::Date;

use super::Outcome;
use super::util::{dt, make_date, next_token, num8, rest_after_blanks, time_hms, year};

/// `MM/DD/YY` (or `MM/DD/YYYY`) and `DD.MM.YY` (or `DD.MM.YYYY`).
fn parse_date(s: &str) -> Option<Date> {
    let (sep, us) = if s.contains('/') {
        ('/', true)
    } else if s.contains('.') {
        ('.', false)
    } else {
        return None;
    };
    let mut it = s.split(sep);
    let (a, b, c) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let (a, b) = (num8(a, 1, 2)?, num8(b, 1, 2)?);
    let (m, d) = if us { (a, b) } else { (b, a) };
    make_date(year(c)?, m, d)
}

/// `*TYPE`: `*` and 2–10 upper-case letters or digits.
fn object_type(s: &str) -> Option<&str> {
    let t = s.strip_prefix('*')?;
    ((2..=10).contains(&t.len())
        && t.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
    .then_some(t)
}

fn kind_for(t: &str) -> EntryKind {
    match t {
        "DIR" | "LIB" | "FILE" | "FLR" => EntryKind::Dir,
        _ => EntryKind::File,
    }
}

/// The last `/` component of the name, trailing `/` stripped.
fn last_component(name: &str) -> &str {
    let trimmed = name.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// One IBM i line.
pub(super) fn parse(line: &str, ctx: &ListingContext) -> Outcome {
    let Some((first, rest)) = next_token(line) else {
        return Outcome::NoMatch;
    };
    // Continuation row: only `*TYPE` and the name.
    if let Some(t) = object_type(first) {
        let name = last_component(rest_after_blanks(rest));
        if name.is_empty() {
            return Outcome::NoMatch;
        }
        return Outcome::Entry(Entry::new(name, kind_for(t)));
    }
    let owner = first;
    let Some((size_tok, rest)) = next_token(rest) else {
        return Outcome::NoMatch;
    };
    if size_tok.is_empty() || !size_tok.bytes().all(|b| b.is_ascii_digit()) {
        return Outcome::NoMatch;
    }
    let Some((date_tok, rest)) = next_token(rest) else {
        return Outcome::NoMatch;
    };
    let Some(date) = parse_date(date_tok) else {
        return Outcome::NoMatch;
    };
    let Some((time_tok, rest)) = next_token(rest) else {
        return Outcome::NoMatch;
    };
    let Some((time, secs)) = time_hms(time_tok) else {
        return Outcome::NoMatch;
    };
    let Some((type_tok, rest)) = next_token(rest) else {
        return Outcome::NoMatch;
    };
    let Some(t) = object_type(type_tok) else {
        return Outcome::NoMatch;
    };
    let name = last_component(rest_after_blanks(rest));
    if name.is_empty() {
        return Outcome::NoMatch;
    }
    let Ok(size) = size_tok.parse::<u64>() else {
        return Outcome::BadNumber;
    };
    let kind = kind_for(t);
    let precision = if secs {
        Precision::Second
    } else {
        Precision::Minute
    };
    Outcome::Entry(Entry {
        name: name.to_owned(),
        size: (kind == EntryKind::File).then_some(size),
        kind,
        modified: Some(local_to_utc(dt(date, time), precision, ctx)),
        permissions: None,
        owner: Some(owner.to_owned()),
        group: None,
        hidden: name.starts_with('.'),
    })
}
