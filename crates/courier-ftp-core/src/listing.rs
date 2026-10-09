//! Directory listing helpers shared by the protocol crates (T13): the listing context
//! (current time, server time-zone offset), byte → text decoding per line, month-name
//! and year inference helpers, and the Unix `ls -l` parser ([`unix`]), which the FTP
//! `LIST` parser and SFTP `longname` (T22) both use.
//!
//! Everything here is pure: no I/O, no logging. Input is untrusted server data, so the
//! helpers never panic and use checked arithmetic.

pub mod unix;

use encoding_rs::Encoding;
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::model::{Charset, Precision, Timestamp};

/// Inputs every listing parser needs. `now` is injectable for tests (year inference).
#[derive(Debug, Clone, Copy)]
pub struct ListingContext {
    /// The current UTC time.
    pub now: OffsetDateTime,
    /// The server's UTC offset in minutes for LIST times (site `timezone_offset_minutes`,
    /// T31): utc = server_local_time − offset. MLSD, EPLF and MDTM times are UTC already.
    pub tz_offset_minutes: i32,
}

impl ListingContext {
    /// A context for `now` with the given server offset.
    pub fn new(now: OffsetDateTime, tz_offset_minutes: i32) -> Self {
        Self {
            now,
            tz_offset_minutes,
        }
    }

    /// `now` shifted into server-local time (as a wall-clock value). Falls back to
    /// `now` if the offset would overflow the supported date range.
    fn local_now(&self) -> PrimitiveDateTime {
        let utc = self.now.to_offset(time::UtcOffset::UTC);
        let local = utc
            .checked_add(Duration::minutes(i64::from(self.tz_offset_minutes)))
            .unwrap_or(utc);
        PrimitiveDateTime::new(local.date(), local.time())
    }
}

/// Bytes → text for one line (RFC 2640 / site charset).
#[derive(Debug, Clone, Copy)]
pub enum TextDecoder {
    /// Always UTF-8; invalid bytes become U+FFFD.
    Utf8,
    /// UTF-8 when the line is valid UTF-8, otherwise the fallback encoding (the `Auto`
    /// charset before UTF-8 is confirmed).
    Utf8OrFallback(&'static Encoding),
    /// Always the given encoding.
    Fixed(&'static Encoding),
}

impl TextDecoder {
    /// Returns the text and whether the fallback encoding was used.
    pub fn decode(&self, bytes: &[u8]) -> (String, bool) {
        match self {
            Self::Utf8 => (String::from_utf8_lossy(bytes).into_owned(), false),
            Self::Utf8OrFallback(enc) => match std::str::from_utf8(bytes) {
                Ok(s) => (s.to_owned(), false),
                Err(_) => (enc.decode_without_bom_handling(bytes).0.into_owned(), true),
            },
            Self::Fixed(enc) => (enc.decode_without_bom_handling(bytes).0.into_owned(), false),
        }
    }

    /// The decoder for a site charset: `Auto` = UTF-8 with a Windows-1252 fallback,
    /// `Utf8` = UTF-8, `Custom(e)` = always `e`.
    pub fn for_charset(charset: Charset) -> Self {
        match charset {
            Charset::Auto => Self::Utf8OrFallback(encoding_rs::WINDOWS_1252),
            Charset::Utf8 => Self::Utf8,
            Charset::Custom(e) => Self::Fixed(e),
        }
    }
}

/// Full month names (lower case) per month, in every supported language. A token
/// matches when it equals one of these or is a prefix (≥ 3 characters) of names of
/// exactly one month.
const MONTH_NAMES: [&[&str]; 12] = [
    &[
        "january", "januar", "jänner", "jaenner", "janvier", "enero", "gennaio", "januari",
        "janeiro",
    ],
    &[
        "february",
        "februar",
        "février",
        "fevrier",
        "febrero",
        "febbraio",
        "februari",
        "fevereiro",
    ],
    &[
        "march", "märz", "maerz", "mars", "marzo", "maart", "março", "marco", "marts",
    ],
    &["april", "avril", "abril", "aprile"],
    &["may", "mai", "mayo", "maggio", "mei", "maio", "maj"],
    &["june", "juni", "juin", "junio", "giugno", "junho"],
    &["july", "juli", "juillet", "julio", "luglio", "julho"],
    &["august", "août", "aout", "agosto", "augustus", "augusti"],
    &[
        "september",
        "septembre",
        "septiembre",
        "settembre",
        "setembro",
    ],
    &[
        "october", "oktober", "octobre", "octubre", "ottobre", "outubro",
    ],
    &["november", "novembre", "noviembre", "novembro"],
    &[
        "december",
        "dezember",
        "décembre",
        "decembre",
        "diciembre",
        "dicembre",
        "dezembro",
        "desember",
    ],
];

/// Abbreviations that are not prefixes of a full name.
const MONTH_ABBREVIATIONS: [(&str, u8); 2] = [("mrz", 3), ("mrt", 3)];

const ENGLISH_ABBR: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Month names: English, German (incl. Austrian "Jän"), French, Spanish, Italian, Dutch,
/// Portuguese, Swedish/Norwegian/Danish, and CJK "N月"/"N월". Case-insensitive, trailing
/// '.' ignored, 3-letter prefixes and full names. Returns 1–12.
pub fn parse_month(token: &str) -> Option<u8> {
    // Fast path: English three-letter abbreviations (the vast majority of listings).
    if token.len() == 3
        && let Some(i) = ENGLISH_ABBR
            .iter()
            .position(|m| m.eq_ignore_ascii_case(token))
    {
        return u8::try_from(i + 1).ok();
    }
    let token = token.strip_suffix('.').unwrap_or(token);
    if token.is_empty() || token.len() > 32 {
        return None;
    }
    if let Some(num) = token
        .strip_suffix('月')
        .or_else(|| token.strip_suffix('월'))
    {
        if num.is_empty() || num.len() > 2 || !num.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u8 = num.parse().ok()?;
        return (1..=12).contains(&n).then_some(n);
    }
    let lower = token.to_lowercase();
    if let Some(&(_, m)) = MONTH_ABBREVIATIONS.iter().find(|(a, _)| *a == lower) {
        return Some(m);
    }
    if lower.chars().count() < 3 {
        return None;
    }
    let mut found: Option<u8> = None;
    for (i, names) in MONTH_NAMES.iter().enumerate() {
        if names.iter().any(|n| n.starts_with(lower.as_str())) {
            let m = u8::try_from(i + 1).ok()?;
            match found {
                None => found = Some(m),
                Some(prev) if prev == m => {}
                Some(_) => return None,
            }
        }
    }
    found
}

/// A calendar date, or `None` if it does not exist.
pub(crate) fn make_date(year: i32, month: u8, day: u8) -> Option<Date> {
    let month = Month::try_from(month).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// Year for a "Mon DD HH:MM" date (no year): this year in server-local time, or the
/// previous year if that would be more than 1 day in the future; Feb 29 walks back to the
/// last leap year (≤ 8 steps).
pub fn infer_year(month: u8, day: u8, hour: u8, minute: u8, ctx: &ListingContext) -> Option<i32> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let time = Time::from_hms(hour, minute, 0).ok()?;
    let local_now = ctx.local_now();
    let limit = local_now.checked_add(Duration::days(1))?;
    let mut year = local_now.year();
    if let Some(date) = make_date(year, month, day)
        && PrimitiveDateTime::new(date, time) <= limit
    {
        return Some(year);
    }
    // The previous year, walking back further only for dates that do not exist in it
    // (Feb 29).
    for _ in 0..8 {
        year = year.checked_sub(1)?;
        if make_date(year, month, day).is_some() {
            return Some(year);
        }
    }
    None
}

/// Server-local date-time → UTC `Timestamp` with the given precision. For
/// `Precision::Day` no offset is applied: the date is kept as-is at 00:00 UTC (T02 rule).
pub fn local_to_utc(
    dt: PrimitiveDateTime,
    precision: Precision,
    ctx: &ListingContext,
) -> Timestamp {
    let utc = dt.assume_utc();
    if precision == Precision::Day {
        return Timestamp::new(utc, precision);
    }
    let shifted = utc
        .checked_sub(Duration::minutes(i64::from(ctx.tz_offset_minutes)))
        .unwrap_or(utc);
    Timestamp::new(shifted, precision)
}

/// Parses "HH:MM" (hour 0–23, minute 0–59).
pub(crate) fn parse_hh_mm(s: &str) -> Option<(u8, u8)> {
    let (h, m) = s.split_once(':')?;
    let h = parse_small(h, 1, 2)?;
    let m = parse_small(m, 2, 2)?;
    (h < 24 && m < 60).then_some((h, m))
}

/// A decimal number of `min..=max` ASCII digits that fits in a `u8`.
pub(crate) fn parse_small(s: &str, min: usize, max: usize) -> Option<u8> {
    if s.len() < min || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// A 4-digit year (1000–9999).
pub(crate) fn parse_year4(s: &str) -> Option<i32> {
    if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let y: i32 = s.parse().ok()?;
    (y >= 1000).then_some(y)
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn ctx(now: OffsetDateTime, off: i32) -> ListingContext {
        ListingContext::new(now, off)
    }

    #[test]
    fn month_names_all_languages_table() {
        let table: &[(&str, u8)] = &[
            // English
            ("Jan", 1),
            ("feb", 2),
            ("MAR", 3),
            ("April", 4),
            ("Sept", 9),
            ("December", 12),
            // German / Austrian
            ("Jän", 1),
            ("Jänner", 1),
            ("Mär", 3),
            ("Mrz", 3),
            ("Mai", 5),
            ("Okt", 10),
            ("Dez", 12),
            // French
            ("janv.", 1),
            ("févr.", 2),
            ("mars", 3),
            ("avr.", 4),
            ("juin", 6),
            ("juil.", 7),
            ("août", 8),
            ("déc.", 12),
            // Spanish
            ("ene", 1),
            ("abr", 4),
            ("ago", 8),
            ("dic", 12),
            // Italian
            ("gen", 1),
            ("mag", 5),
            ("giu", 6),
            ("lug", 7),
            ("set", 9),
            ("ott", 10),
            ("dic", 12),
            // Dutch
            ("mrt", 3),
            ("mei", 5),
            ("okt", 10),
            // Portuguese
            ("fev", 2),
            ("out", 10),
            ("dez", 12),
            // Swedish / Norwegian / Danish
            ("maj", 5),
            ("okt", 10),
            ("des", 12),
            ("marts", 3),
            // CJK
            ("1月", 1),
            ("12月", 12),
            ("3월", 3),
            ("12월", 12),
        ];
        for &(tok, m) in table {
            assert_eq!(parse_month(tok), Some(m), "{tok}");
        }
        for bad in [
            "", "j", "ja", "jui", "13月", "0월", "月", "foo", "x.", "12", "-", "mä",
        ] {
            assert_eq!(parse_month(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn infer_year_new_year_boundaries() {
        // Just after New Year (UTC), servers on both sides of the date line.
        let now = datetime!(2024-01-01 0:30 UTC);
        // UTC−12: local time is 2023-12-31 12:30.
        let c = ctx(now, -720);
        assert_eq!(infer_year(12, 31, 12, 0, &c), Some(2023));
        assert_eq!(infer_year(1, 1, 0, 15, &c), Some(2023));
        assert_eq!(infer_year(1, 1, 12, 0, &c), Some(2023));
        // UTC: local 2024-01-01 00:30.
        let c = ctx(now, 0);
        assert_eq!(infer_year(12, 31, 23, 59, &c), Some(2023));
        assert_eq!(infer_year(1, 1, 0, 15, &c), Some(2024));
        // A clock skew of less than a day still counts as this year.
        assert_eq!(infer_year(1, 1, 23, 0, &c), Some(2024));
        assert_eq!(infer_year(1, 3, 0, 0, &c), Some(2023));
        // UTC+14: local 2024-01-01 14:30.
        let c = ctx(now, 840);
        assert_eq!(infer_year(1, 1, 14, 0, &c), Some(2024));
        assert_eq!(infer_year(12, 31, 23, 0, &c), Some(2023));

        // Just before New Year (UTC).
        let now = datetime!(2024-12-31 23:30 UTC);
        assert_eq!(infer_year(12, 31, 23, 0, &ctx(now, 0)), Some(2024));
        assert_eq!(infer_year(1, 1, 0, 30, &ctx(now, 0)), Some(2024));
        // UTC+14: local is already 2025-01-01 13:30.
        assert_eq!(infer_year(1, 1, 13, 0, &ctx(now, 840)), Some(2025));
        assert_eq!(infer_year(12, 31, 23, 59, &ctx(now, 840)), Some(2024));
        // UTC−12: local 2024-12-31 11:30.
        assert_eq!(infer_year(12, 31, 11, 0, &ctx(now, -720)), Some(2024));
        assert_eq!(infer_year(1, 1, 11, 0, &ctx(now, -720)), Some(2024));

        // March 2025.
        let now = datetime!(2025-03-01 12:00 UTC);
        for off in [-720, 0, 840] {
            assert_eq!(infer_year(2, 28, 12, 0, &ctx(now, off)), Some(2025));
            assert_eq!(infer_year(12, 1, 12, 0, &ctx(now, off)), Some(2024));
            assert_eq!(infer_year(3, 1, 0, 0, &ctx(now, off)), Some(2025));
        }
        assert_eq!(infer_year(13, 1, 0, 0, &ctx(now, 0)), None);
        assert_eq!(infer_year(2, 30, 0, 0, &ctx(now, 0)), None);
        assert_eq!(infer_year(1, 1, 24, 0, &ctx(now, 0)), None);
    }

    #[test]
    fn infer_year_feb_29_walks_back_to_leap_year() {
        for off in [-720, 0, 840] {
            assert_eq!(
                infer_year(2, 29, 12, 0, &ctx(datetime!(2025-03-01 12:00 UTC), off)),
                Some(2024)
            );
            assert_eq!(
                infer_year(2, 29, 12, 0, &ctx(datetime!(2024-03-01 12:00 UTC), off)),
                Some(2024)
            );
            // In January 2024, Feb 29 2024 is in the future: the previous leap year.
            assert_eq!(
                infer_year(2, 29, 12, 0, &ctx(datetime!(2024-01-01 0:30 UTC), off)),
                Some(2020)
            );
            assert_eq!(
                infer_year(2, 29, 12, 0, &ctx(datetime!(2024-12-31 23:30 UTC), off)),
                Some(2024)
            );
        }
        // 2100 is not a leap year: from 2101, 8 steps back reach 2096.
        assert_eq!(
            infer_year(2, 29, 0, 0, &ctx(datetime!(2101-01-01 0:00 UTC), 0)),
            Some(2096)
        );
    }

    #[test]
    fn local_to_utc_applies_offset() {
        let dt = datetime!(2024-01-31 12:00);
        let t = local_to_utc(dt, Precision::Minute, &ctx(OffsetDateTime::UNIX_EPOCH, 60));
        assert_eq!(t.time, datetime!(2024-01-31 11:00 UTC));
        assert_eq!(t.precision, Precision::Minute);
        let t = local_to_utc(
            dt,
            Precision::Second,
            &ctx(OffsetDateTime::UNIX_EPOCH, -720),
        );
        assert_eq!(t.time, datetime!(2024-02-01 0:00 UTC));
        let t = local_to_utc(dt, Precision::Minute, &ctx(OffsetDateTime::UNIX_EPOCH, 840));
        assert_eq!(t.time, datetime!(2024-01-30 22:00 UTC));
    }

    #[test]
    fn local_to_utc_day_precision_ignores_offset() {
        let dt = datetime!(2024-01-31 0:00);
        for off in [-720, 0, 840] {
            let t = local_to_utc(dt, Precision::Day, &ctx(OffsetDateTime::UNIX_EPOCH, off));
            assert_eq!(t.time, datetime!(2024-01-31 0:00 UTC), "{off}");
            assert_eq!(t.precision, Precision::Day);
        }
    }

    #[test]
    fn decoder_fallback_reports_and_decodes_cp1252() {
        let d = TextDecoder::Utf8OrFallback(encoding_rs::WINDOWS_1252);
        assert_eq!(d.decode("grüße".as_bytes()), ("grüße".to_owned(), false));
        assert_eq!(d.decode(b"gr\xfc\xdfe \x80"), ("grüße €".to_owned(), true));
        assert_eq!(
            TextDecoder::Utf8.decode(b"a\xffb"),
            ("a\u{fffd}b".to_owned(), false)
        );
        assert_eq!(
            TextDecoder::Fixed(encoding_rs::WINDOWS_1252).decode(b"\xfc"),
            ("ü".to_owned(), false)
        );
        assert!(matches!(
            TextDecoder::for_charset(Charset::Auto),
            TextDecoder::Utf8OrFallback(e) if e == encoding_rs::WINDOWS_1252
        ));
        assert!(matches!(
            TextDecoder::for_charset(Charset::Utf8),
            TextDecoder::Utf8
        ));
    }

    #[test]
    fn small_number_helpers() {
        assert_eq!(parse_hh_mm("9:05"), Some((9, 5)));
        assert_eq!(parse_hh_mm("23:59"), Some((23, 59)));
        assert_eq!(parse_hh_mm("24:00"), None);
        assert_eq!(parse_hh_mm("12:5"), None);
        assert_eq!(parse_hh_mm("123:00"), None);
        assert_eq!(parse_year4("2024"), Some(2024));
        assert_eq!(parse_year4("0999"), None);
        assert_eq!(parse_year4("+202"), None);
    }
}
