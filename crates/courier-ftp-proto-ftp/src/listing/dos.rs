//! DOS / IIS / Windows `dir` style lines:
//!
//! ```text
//! 01-31-24  12:00PM       <DIR>          name
//! 01-31-2024  13:05                 1234 name
//! ```
//!
//! Also `YYYY-MM-DD`, `MM/DD/YY` and `DD.MM.YYYY` dates, `AM`/`PM` attached or
//! as a separate field, thousands separators in sizes, and `<JUNCTION>` /
//! `<SYMLINKD>` entries (`name [target]`).

use courier_ftp_core::{
    listing::{
        ListingContext, date_from_numbers, expand_year, parse_digits, rest_after, split_fields,
    },
    model::{Entry, EntryKind, Precision},
};
use time::{Date, PrimitiveDateTime, Time};

pub(super) fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let date = parse_date(fields.first()?.text)?;
    let mut i = 1;
    let mut time_text = fields.get(i)?.text.to_owned();
    i += 1;
    if let Some(ampm) = fields.get(i)
        && (ampm.text.eq_ignore_ascii_case("AM") || ampm.text.eq_ignore_ascii_case("PM"))
    {
        time_text.push_str(ampm.text);
        i += 1;
    }
    let (time, precision) = parse_time(&time_text)?;
    let what = fields.get(i)?;
    let (kind, size, name) = match what.text.to_ascii_uppercase().as_str() {
        "<DIR>" => (EntryKind::Dir, None, rest_trimmed(line, what.end())?),
        "<JUNCTION>" | "<SYMLINKD>" | "<SYMLINK>" => {
            let rest = rest_trimmed(line, what.end())?;
            let (name, target) = split_target(rest);
            let kind = EntryKind::Symlink {
                target: target.map(str::to_owned),
                target_kind: (!what.text.eq_ignore_ascii_case("<SYMLINK>"))
                    .then(|| Box::new(EntryKind::Dir)),
            };
            (kind, None, name)
        }
        _ => {
            let size = parse_size(what.text)?;
            (EntryKind::File, Some(size), rest_after(line, what.end())?)
        }
    };
    let mut entry = Entry::new(name, kind);
    entry.size = size;
    entry.modified = ctx.server_time(PrimitiveDateTime::new(date, time), precision);
    entry.raw = Some(line.to_owned());
    Some(entry)
}

fn rest_trimmed(line: &str, end: usize) -> Option<&str> {
    let rest = line.get(end..)?.trim_start_matches([' ', '\t']);
    (!rest.is_empty()).then_some(rest)
}

/// `name [target]`.
fn split_target(rest: &str) -> (&str, Option<&str>) {
    if let Some(inner) = rest.strip_suffix(']')
        && let Some((name, target)) = inner.rsplit_once(" [")
        && !name.is_empty()
    {
        return (name, Some(target));
    }
    (rest, None)
}

/// `MM-DD-YY`, `MM-DD-YYYY`, `YYYY-MM-DD`, `MM/DD/YY(YY)`, `DD.MM.YY(YY)`.
/// Used by the AS/400 parser too.
pub(super) fn parse_date(token: &str) -> Option<Date> {
    let sep = token.chars().find(|c| matches!(c, '-' | '/' | '.'))?;
    let parts: Vec<&str> = token.split(sep).collect();
    let [a, b, c] = parts.as_slice() else {
        return None;
    };
    let year = |s: &str| -> Option<i32> {
        match s.len() {
            2 => Some(expand_year(parse_digits(s, 2, 2)?)),
            4 => i32::try_from(parse_digits(s, 4, 4)?).ok(),
            _ => None,
        }
    };
    if a.len() == 4 {
        return date_from_numbers(year(a)?, parse_digits(b, 1, 2)?, parse_digits(c, 1, 2)?);
    }
    let (x, y) = (parse_digits(a, 1, 2)?, parse_digits(b, 1, 2)?);
    let year = year(c)?;
    let (month, day) = if sep == '.' || (x > 12 && y <= 12) {
        (y, x)
    } else {
        (x, y)
    };
    date_from_numbers(year, month, day)
}

/// `HH:MM`, `HH:MM:SS`, optionally with `AM`/`PM` attached.
fn parse_time(text: &str) -> Option<(Time, Precision)> {
    let upper = text.to_ascii_uppercase();
    let (clock, pm) = if let Some(c) = upper.strip_suffix("PM") {
        (c, Some(true))
    } else if let Some(c) = upper.strip_suffix("AM") {
        (c, Some(false))
    } else {
        (upper.as_str(), None)
    };
    let (time, precision) = courier_ftp_core::listing::parse_time(clock)?;
    let hour = match pm {
        None => time.hour(),
        Some(_) if time.hour() == 0 || time.hour() > 12 => return None,
        Some(false) => time.hour() % 12,
        Some(true) => time.hour() % 12 + 12,
    };
    Some((
        Time::from_hms(hour, time.minute(), time.second()).ok()?,
        precision,
    ))
}

/// Digits, optionally with `,` or `.` thousands separators.
fn parse_size(token: &str) -> Option<u64> {
    let digits: String = token.chars().filter(|c| !matches!(c, ',' | '.')).collect();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::{
        Duration,
        macros::{date, datetime},
    };

    use super::*;

    fn ctx() -> ListingContext {
        ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO)
    }

    #[test]
    fn iis_lines() {
        let e = parse_line(
            "01-31-24  12:00PM       <DIR>          My Documents",
            &ctx(),
        )
        .unwrap();
        assert_eq!(
            (e.name.as_str(), &e.kind),
            ("My Documents", &EntryKind::Dir)
        );
        assert_eq!(e.modified.unwrap().time, datetime!(2024-01-31 12:00 UTC));
        let e = parse_line("01-31-24  12:05AM                 1234 a.txt", &ctx()).unwrap();
        assert_eq!(
            (e.size, e.modified.unwrap().time),
            (Some(1234), datetime!(2024-01-31 0:05 UTC))
        );
        let e = parse_line("2024-01-31  23:59    1,234,567 big.iso", &ctx()).unwrap();
        assert_eq!(e.size, Some(1_234_567));
        let e = parse_line("31.01.2024  09:00 <JUNCTION> Link [C:\\Target]", &ctx()).unwrap();
        assert_eq!(e.name, "Link");
        assert!(e.is_dir_like());
    }

    #[test]
    fn dates() {
        assert_eq!(parse_date("01-31-24"), Some(date!(2024 - 01 - 31)));
        assert_eq!(parse_date("01-31-99"), Some(date!(1999 - 01 - 31)));
        assert_eq!(parse_date("31-01-2024"), Some(date!(2024 - 01 - 31)));
        assert_eq!(parse_date("2024/01/31"), Some(date!(2024 - 01 - 31)));
        assert_eq!(parse_date("31.01.24"), Some(date!(2024 - 01 - 31)));
        assert_eq!(parse_date("13-13-24"), None);
        assert_eq!(parse_date("1-2"), None);
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("12:00AM").map(|t| t.0.hour()), Some(0));
        assert_eq!(parse_time("12:00PM").map(|t| t.0.hour()), Some(12));
        assert_eq!(parse_time("01:00pm").map(|t| t.0.hour()), Some(13));
        assert_eq!(parse_time("13:00PM"), None);
        assert_eq!(parse_time("23:59").map(|t| t.0.hour()), Some(23));
    }
}
