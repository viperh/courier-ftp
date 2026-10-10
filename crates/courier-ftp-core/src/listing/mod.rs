//! Directory listing helpers shared by the protocol backends (T13).
//!
//! The FTP backend parses `LIST` output in many server formats
//! (`courier-ftp-proto-ftp`'s `listing` module); the SFTP backend (T22) reads
//! the `ls -l` style `longname` of each entry. Both need the Unix parser in
//! [`unix`] and the date helpers here: month names in several languages, year
//! inference for `Mon DD HH:MM` dates and the server time-zone offset, all
//! relative to an injectable "now" ([`ListingContext`]) so they can be tested.

pub mod unix;

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

use crate::model::{Precision, Timestamp};

/// What a listing parser needs besides the text: the current time (for year
/// inference) and the server's time-zone offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingContext {
    /// The current time. Injectable so year inference can be tested.
    pub now: OffsetDateTime,
    /// The site's server time-zone offset (Site Manager, T31). It is *added*
    /// to the server-local times of a `LIST` listing to get UTC, like
    /// [`ConnectInfo::timezone_offset`](crate::backend::ConnectInfo::timezone_offset).
    /// Times that are UTC by definition (`MLSD`, EPLF) ignore it.
    pub timezone_offset: Duration,
}

impl Default for ListingContext {
    fn default() -> Self {
        Self::new(Duration::ZERO)
    }
}

impl ListingContext {
    /// A context at the current time with the given server offset.
    pub fn new(timezone_offset: Duration) -> Self {
        Self::at(OffsetDateTime::now_utc(), timezone_offset)
    }

    /// A context at a fixed time (tests, replaying a stored listing).
    pub fn at(now: OffsetDateTime, timezone_offset: Duration) -> Self {
        Self {
            now,
            timezone_offset,
        }
    }

    /// "Now" as the server's wall clock shows it.
    pub fn server_now(&self) -> PrimitiveDateTime {
        let utc = self
            .now
            .checked_to_offset(UtcOffset::UTC)
            .unwrap_or(self.now);
        let local = utc.checked_sub(self.timezone_offset).unwrap_or(utc);
        PrimitiveDateTime::new(local.date(), local.time())
    }

    /// Convert a server-local wall time to a UTC [`Timestamp`] by applying the
    /// offset. `None` only when the result is out of range.
    pub fn server_time(&self, wall: PrimitiveDateTime, precision: Precision) -> Option<Timestamp> {
        let utc = wall.assume_utc().checked_add(self.timezone_offset)?;
        Some(Timestamp::new(utc, precision))
    }

    /// The most recent date with this month and day that is not more than one
    /// day after the server's "now" (`ls` drops the year for dates within the
    /// last six months). February 29 goes back to the last leap year.
    pub fn infer_year(&self, month: Month, day: u8, time: Time) -> Option<PrimitiveDateTime> {
        let now = self.server_now();
        let limit = now.checked_add(Duration::DAY).unwrap_or(now);
        // Start one year ahead: on 31 December a server clock that is slightly
        // ahead may already list files from 1 January.
        let year = now.year() + 1;
        (0..9).find_map(|back| {
            let date = Date::from_calendar_date(year - back, month, day).ok()?;
            let candidate = PrimitiveDateTime::new(date, time);
            (candidate <= limit).then_some(candidate)
        })
    }
}

/// A whitespace-separated field of a listing line and its byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    /// Byte offset of the field in the line.
    pub start: usize,
    /// The field text.
    pub text: &'a str,
}

impl Field<'_> {
    /// Byte offset just past the field.
    pub fn end(&self) -> usize {
        self.start + self.text.len()
    }
}

/// Split a line into fields separated by spaces or tabs, keeping offsets so
/// the caller can take the rest of the line verbatim (file names).
pub fn split_fields(line: &str) -> Vec<Field<'_>> {
    let mut fields = Vec::new();
    let mut start = None;
    for (i, c) in line.char_indices() {
        if c == ' ' || c == '\t' {
            if let Some(s) = start.take() {
                fields.push(Field {
                    start: s,
                    text: &line[s..i],
                });
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        fields.push(Field {
            start: s,
            text: &line[s..],
        });
    }
    fields
}

/// The rest of `line` after byte offset `end`, minus exactly one separating
/// space or tab. Further leading spaces belong to the name. `None` when nothing
/// is left.
pub fn rest_after(line: &str, end: usize) -> Option<&str> {
    let rest = line.get(end..)?;
    let rest = rest
        .strip_prefix(' ')
        .or_else(|| rest.strip_prefix('\t'))
        .unwrap_or(rest);
    (!rest.is_empty()).then_some(rest)
}

/// Month names as `ls` and FTP servers print them, in English, German, French,
/// Spanish, Italian, Dutch, Portuguese and the Scandinavian languages, plus
/// numeric CJK forms (`1月`, `1월`). Case-insensitive; a trailing `.` is ignored.
pub fn parse_month(token: &str) -> Option<Month> {
    let token = token.strip_suffix('.').unwrap_or(token);
    if let Some(n) = token
        .strip_suffix('月')
        .or_else(|| token.strip_suffix('월'))
    {
        return n.parse::<u8>().ok().and_then(|n| Month::try_from(n).ok());
    }
    let lower = token.to_lowercase();
    let n = MONTHS
        .iter()
        .position(|names| names.contains(&lower.as_str()))?;
    Month::try_from(u8::try_from(n + 1).ok()?).ok()
}

const MONTHS: [&[&str]; 12] = [
    &[
        "jan", "january", "jän", "jänner", "janv", "janvier", "ene", "enero", "gen", "gennaio",
        "januar", "januari", "janeiro",
    ],
    &[
        "feb",
        "february",
        "febr",
        "februar",
        "februari",
        "févr",
        "fevr",
        "février",
        "fev",
        "fevereiro",
        "febrero",
        "febbraio",
    ],
    &[
        "mar", "march", "mär", "mrz", "märz", "mars", "marzo", "mrt", "maart", "março", "marco",
    ],
    &["apr", "april", "avr", "avril", "abr", "abril", "aprile"],
    &["may", "mai", "mayo", "mag", "maggio", "mei", "maj", "maio"],
    &[
        "jun", "june", "juin", "juni", "junio", "giu", "giugno", "junho",
    ],
    &[
        "jul", "july", "juil", "juillet", "juli", "julio", "lug", "luglio", "julho",
    ],
    &["aug", "august", "août", "aout", "ago", "agosto", "augustus"],
    &[
        "sep",
        "sept",
        "september",
        "set",
        "settembre",
        "septembre",
        "septiembre",
        "setembro",
    ],
    &[
        "oct", "october", "okt", "oktober", "octobre", "octubre", "ott", "ottobre", "out",
        "outubro",
    ],
    &["nov", "november", "novembre", "noviembre", "novembro"],
    &[
        "dec",
        "december",
        "dez",
        "dezember",
        "déc",
        "décembre",
        "decembre",
        "dic",
        "diciembre",
        "dicembre",
        "dezembro",
    ],
];

/// A day of the month: `5`, `05`, `5.` (German), `5日` (CJK) or `5일`.
pub fn parse_day(token: &str) -> Option<u8> {
    let digits = token
        .strip_suffix('.')
        .or_else(|| token.strip_suffix('日'))
        .or_else(|| token.strip_suffix('일'))
        .unwrap_or(token);
    let day = parse_digits(digits, 1, 2)?;
    u8::try_from(day).ok().filter(|d| (1..=31).contains(d))
}

/// `HH:MM` or `HH:MM:SS`, with the precision it carries.
pub fn parse_time(token: &str) -> Option<(Time, Precision)> {
    let mut parts = token.split(':');
    let hour = parse_digits(parts.next()?, 1, 2)?;
    let minute = parse_digits(parts.next()?, 2, 2)?;
    let (second, precision) = match parts.next() {
        Some(s) => (parse_digits(s, 2, 2)?, Precision::Second),
        None => (0, Precision::Minute),
    };
    if parts.next().is_some() {
        return None;
    }
    let time = Time::from_hms(
        u8::try_from(hour).ok()?,
        u8::try_from(minute).ok()?,
        u8::try_from(second).ok()?,
    )
    .ok()?;
    Some((time, precision))
}

/// A four-digit year.
pub fn parse_year(token: &str) -> Option<i32> {
    parse_digits(token, 4, 4).and_then(|y| i32::try_from(y).ok())
}

/// A two-digit year: `00`–`69` are 2000–2069, `70`–`99` are 1970–1999.
pub fn expand_year(yy: u32) -> i32 {
    let yy = i32::try_from(yy % 100).unwrap_or(0);
    if yy < 70 { 2000 + yy } else { 1900 + yy }
}

/// A number of `min..=max` ASCII digits.
pub fn parse_digits(s: &str, min: usize, max: usize) -> Option<u32> {
    if s.len() < min || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// A date and optional time at the start of `fields`, in one of the forms
/// `ls`-like listings use. Returns the timestamp and the number of fields it
/// took.
///
/// - `Mon DD HH:MM` (year inferred, see [`ListingContext::infer_year`]),
///   `Mon DD YYYY`, `Mon DD HH:MM:SS YYYY`;
/// - `DD Mon HH:MM` / `DD Mon YYYY` (French, German `31. Jan`, …);
/// - `YYYY-MM-DD HH:MM[:SS[.fraction]] [+hhmm]` (`ls --full-time`, ISO style);
///   an explicit zone wins over the site offset.
pub fn parse_date_fields(fields: &[&str], ctx: &ListingContext) -> Option<(Timestamp, usize)> {
    let first = *fields.first()?;
    if let Some(found) = parse_iso_fields(fields, ctx) {
        return Some(found);
    }
    let second = *fields.get(1)?;
    let third = *fields.get(2)?;
    let (month, day) = match (parse_month(first), parse_day(second)) {
        (Some(m), Some(d)) => (m, d),
        _ => (parse_month(second)?, parse_day(first)?),
    };
    if let Some(year) = parse_year(third) {
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let wall = PrimitiveDateTime::new(date, Time::MIDNIGHT);
        return Some((ctx.server_time(wall, Precision::Day)?, 3));
    }
    let (time, precision) = parse_time(third)?;
    if let Some(year) = fields.get(3).and_then(|f| parse_year(f)) {
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let wall = PrimitiveDateTime::new(date, time);
        return Some((ctx.server_time(wall, precision)?, 4));
    }
    let wall = ctx.infer_year(month, day, time)?;
    Some((ctx.server_time(wall, precision)?, 3))
}

fn parse_iso_fields(fields: &[&str], ctx: &ListingContext) -> Option<(Timestamp, usize)> {
    let date = parse_iso_date(fields.first()?)?;
    let time_field = fields.get(1)?;
    let (clock, fraction) = match time_field.split_once('.') {
        Some((c, f)) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) => (c, Some(f)),
        Some(_) => return None,
        None => (*time_field, None),
    };
    let (mut time, mut precision) = parse_time(clock)?;
    if let Some(f) = fraction
        && precision == Precision::Second
    {
        let millis: String = f.chars().chain("000".chars()).take(3).collect();
        let millis: u16 = millis.parse().ok()?;
        time = Time::from_hms_milli(time.hour(), time.minute(), time.second(), millis).ok()?;
        precision = Precision::Millis;
    }
    let wall = PrimitiveDateTime::new(date, time);
    if let Some(zone) = fields.get(2).and_then(|z| parse_zone(z)) {
        let utc = wall.assume_offset(zone).checked_to_offset(UtcOffset::UTC)?;
        return Some((Timestamp::new(utc, precision), 3));
    }
    Some((ctx.server_time(wall, precision)?, 2))
}

/// `YYYY-MM-DD`.
pub fn parse_iso_date(token: &str) -> Option<Date> {
    let mut parts = token.split('-');
    let year = i32::try_from(parse_digits(parts.next()?, 4, 4)?).ok()?;
    let month = parse_digits(parts.next()?, 1, 2)?;
    let day = parse_digits(parts.next()?, 1, 2)?;
    if parts.next().is_some() {
        return None;
    }
    date_from_numbers(year, month, day)
}

/// A calendar date from numbers, `None` if it doesn't exist.
pub fn date_from_numbers(year: i32, month: u32, day: u32) -> Option<Date> {
    let month = Month::try_from(u8::try_from(month).ok()?).ok()?;
    Date::from_calendar_date(year, month, u8::try_from(day).ok()?).ok()
}

/// `+hhmm` / `-hhmm`.
fn parse_zone(token: &str) -> Option<UtcOffset> {
    let (sign, digits) = match token.as_bytes().first()? {
        b'+' => (1, &token[1..]),
        b'-' => (-1, &token[1..]),
        _ => return None,
    };
    let n = parse_digits(digits, 4, 4)?;
    let hours = i8::try_from(n / 100).ok()?;
    let minutes = i8::try_from(n % 100).ok()?;
    UtcOffset::from_hms(sign * hours, sign * minutes, 0).ok()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::{datetime, time};

    use super::*;

    fn ctx(now: OffsetDateTime) -> ListingContext {
        ListingContext::at(now, Duration::ZERO)
    }

    #[test]
    fn months_in_many_languages() {
        for (name, month) in [
            ("Jan", Month::January),
            ("JAN", Month::January),
            ("Jän", Month::January),
            ("janv.", Month::January),
            ("ene", Month::January),
            ("gen", Month::January),
            ("févr.", Month::February),
            ("Mär", Month::March),
            ("Mrz", Month::March),
            ("mrt", Month::March),
            ("avr.", Month::April),
            ("abr", Month::April),
            ("Mai", Month::May),
            ("mag", Month::May),
            ("juin", Month::June),
            ("juil.", Month::July),
            ("août", Month::August),
            ("ago", Month::August),
            ("sept.", Month::September),
            ("set", Month::September),
            ("Okt", Month::October),
            ("out", Month::October),
            ("Dez", Month::December),
            ("déc.", Month::December),
            ("dic", Month::December),
            ("1月", Month::January),
            ("12月", Month::December),
            ("3월", Month::March),
        ] {
            assert_eq!(parse_month(name), Some(month), "{name}");
        }
        for bad in ["", "foo", "13月", "0月", "ja", "月"] {
            assert_eq!(parse_month(bad), None, "{bad}");
        }
    }

    #[test]
    fn year_inference_around_new_year() {
        let c = ctx(datetime!(2024-01-02 10:00 UTC));
        // Yesterday's file is this year.
        assert_eq!(
            c.infer_year(Month::January, 1, time!(12:30)),
            Some(datetime!(2024-01-01 12:30))
        );
        // Late December is last year.
        assert_eq!(
            c.infer_year(Month::December, 31, time!(23:59)),
            Some(datetime!(2023-12-31 23:59))
        );
        // Up to one day in the future (clock skew) stays this year.
        assert_eq!(
            c.infer_year(Month::January, 3, time!(9:00)),
            Some(datetime!(2024-01-03 9:00))
        );
        // More than a day ahead: last year.
        assert_eq!(
            c.infer_year(Month::January, 5, time!(12:30)),
            Some(datetime!(2023-01-05 12:30))
        );
        // New Year's Eve, a file from 1 January.
        let c = ctx(datetime!(2023-12-31 23:00 UTC));
        assert_eq!(
            c.infer_year(Month::January, 1, time!(0:10)),
            Some(datetime!(2024-01-01 0:10))
        );
        assert_eq!(
            c.infer_year(Month::January, 5, time!(0:10)),
            Some(datetime!(2023-01-05 0:10))
        );
    }

    #[test]
    fn february_29_goes_back_to_a_leap_year() {
        let c = ctx(datetime!(2025-03-10 12:00 UTC));
        assert_eq!(
            c.infer_year(Month::February, 29, time!(8:00)),
            Some(datetime!(2024-02-29 8:00))
        );
    }

    #[test]
    fn year_inference_uses_server_clock() {
        // UTC is 2024-01-01 01:00; a server whose offset is +3h runs three
        // hours behind UTC, so its wall clock still shows 2023.
        let c = ListingContext::at(datetime!(2024-01-01 01:00 UTC), Duration::hours(3));
        assert_eq!(c.server_now(), datetime!(2023-12-31 22:00));
        assert_eq!(
            c.infer_year(Month::January, 3, time!(12:00)),
            Some(datetime!(2023-01-03 12:00))
        );
    }

    #[test]
    fn offset_is_added() {
        let c = ListingContext::at(datetime!(2024-06-01 0:00 UTC), Duration::minutes(-90));
        let fields = ["Jan", "31", "12:00"];
        let (ts, n) = parse_date_fields(&fields, &c).unwrap();
        assert_eq!(n, 3);
        assert_eq!(ts.time, datetime!(2024-01-31 10:30 UTC));
        assert_eq!(ts.precision, Precision::Minute);
    }

    #[test]
    fn date_forms() {
        let c = ctx(datetime!(2024-06-15 12:00 UTC));
        let cases: [(&[&str], OffsetDateTime, Precision, usize); 8] = [
            (
                &["Jan", "31", "2020", "x"],
                datetime!(2020-01-31 0:00 UTC),
                Precision::Day,
                3,
            ),
            (
                &["Jan", "31", "12:00:05", "2020"],
                datetime!(2020-01-31 12:00:05 UTC),
                Precision::Second,
                4,
            ),
            (
                &["31", "janv.", "12:00"],
                datetime!(2024-01-31 12:00 UTC),
                Precision::Minute,
                3,
            ),
            (
                &["31.", "Dez", "2019"],
                datetime!(2019-12-31 0:00 UTC),
                Precision::Day,
                3,
            ),
            (
                &["2024-01-31", "12:00"],
                datetime!(2024-01-31 12:00 UTC),
                Precision::Minute,
                2,
            ),
            (
                &["2024-01-31", "12:00:01.123456789", "+0100"],
                datetime!(2024-01-31 11:00:01.123 UTC),
                Precision::Millis,
                3,
            ),
            (
                &["1月", "5日", "09:15"],
                datetime!(2024-01-05 9:15 UTC),
                Precision::Minute,
                3,
            ),
            (
                &["12月", "5", "09:15"],
                datetime!(2023-12-05 9:15 UTC),
                Precision::Minute,
                3,
            ),
        ];
        for (fields, time, precision, n) in cases {
            let (ts, used) = parse_date_fields(fields, &c).unwrap();
            assert_eq!(
                (ts.time, ts.precision, used),
                (time, precision, n),
                "{fields:?}"
            );
        }
        for bad in [
            &["Jan", "32", "12:00"][..],
            &["Feb", "30", "2024"],
            &["Jan", "31"],
            &["2024-13-01", "12:00"],
            &["Jan", "31", "25:00"],
            &["31", "32", "2024"],
        ] {
            assert_eq!(parse_date_fields(bad, &c), None, "{bad:?}");
        }
    }

    #[test]
    fn fields_and_rest() {
        let line = "a  bb\tc   name with  spaces ";
        let f = split_fields(line);
        let texts: Vec<&str> = f.iter().map(|f| f.text).collect();
        assert_eq!(texts, ["a", "bb", "c", "name", "with", "spaces"]);
        assert_eq!(rest_after(line, f[2].end()), Some("  name with  spaces "));
        assert_eq!(rest_after("abc", 3), None);
        assert_eq!(rest_after("abc ", 3), None);
    }
}
