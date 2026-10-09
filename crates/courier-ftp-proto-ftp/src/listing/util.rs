//! Small checked parsing helpers shared by the LIST parsers.

use time::{Date, Month, PrimitiveDateTime, Time};

/// The next whitespace-separated token and the text right after it (not trimmed).
pub(super) fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start_matches([' ', '\t']);
    if s.is_empty() {
        return None;
    }
    let end = s.find([' ', '\t']).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

/// Text after the separator that follows a column (all leading blanks removed).
pub(super) fn rest_after_blanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// A decimal number of `min..=max` ASCII digits.
pub(super) fn num(s: &str, min: usize, max: usize) -> Option<u32> {
    if s.len() < min || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `u8` version of [`num`].
pub(super) fn num8(s: &str, min: usize, max: usize) -> Option<u8> {
    u8::try_from(num(s, min, max)?).ok()
}

/// All ASCII digits, non-empty.
pub(super) fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A calendar date, or `None` if it does not exist.
pub(super) fn make_date(year: i32, month: u8, day: u8) -> Option<Date> {
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

/// A two- or four-digit year; two digits: < 70 → 20YY, else 19YY.
pub(super) fn year(s: &str) -> Option<i32> {
    match s.len() {
        2 => {
            let y = i32::try_from(num(s, 2, 2)?).ok()?;
            Some(if y < 70 { 2000 + y } else { 1900 + y })
        }
        4 => i32::try_from(num(s, 4, 4)?).ok(),
        _ => None,
    }
}

/// `HH:MM`, `HH:MM:SS` or `HH:MM:SS.cc` → (time, has seconds).
pub(super) fn time_hms(s: &str) -> Option<(Time, bool)> {
    let mut parts = s.splitn(3, ':');
    let h = num8(parts.next()?, 1, 2)?;
    let m = num8(parts.next()?, 2, 2)?;
    match parts.next() {
        None => Some((Time::from_hms(h, m, 0).ok()?, false)),
        Some(sec) => {
            let whole = match sec.split_once('.') {
                Some((w, frac)) => {
                    if !is_digits(frac) {
                        return None;
                    }
                    w
                }
                None => sec,
            };
            let s = num8(whole, 2, 2)?;
            Some((Time::from_hms(h, m, s).ok()?, true))
        }
    }
}

/// `YYYY/MM/DD` (MVS).
pub(super) fn date_ymd_slash(s: &str) -> Option<Date> {
    let mut it = s.split('/');
    let y = i32::try_from(num(it.next()?, 4, 4)?).ok()?;
    let m = num8(it.next()?, 2, 2)?;
    let d = num8(it.next()?, 2, 2)?;
    if it.next().is_some() {
        return None;
    }
    make_date(y, m, d)
}

/// A local date-time.
pub(super) fn dt(date: Date, time: Time) -> PrimitiveDateTime {
    PrimitiveDateTime::new(date, time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(next_token("  ab  cd"), Some(("ab", "  cd")));
        assert_eq!(next_token("   "), None);
        assert_eq!(year("69"), Some(2069));
        assert_eq!(year("70"), Some(1970));
        assert_eq!(year("2024"), Some(2024));
        assert_eq!(year("202"), None);
        assert!(time_hms("12:00:05.32").is_some_and(|(_, s)| s));
        assert!(time_hms("12:00").is_some_and(|(_, s)| !s));
        assert!(time_hms("25:00").is_none());
        assert!(time_hms("12:00:5x").is_none());
        assert!(date_ymd_slash("2024/01/31").is_some());
        assert!(date_ymd_slash("2024/02/30").is_none());
        assert!(date_ymd_slash("01/31/24").is_none());
        assert_eq!(num("99999999999", 1, 20), None);
    }
}
