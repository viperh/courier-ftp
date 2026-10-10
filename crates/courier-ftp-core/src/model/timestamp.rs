//! [`Timestamp`] with a [`Precision`].

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, Time};

/// How precise a [`Timestamp`] is.
///
/// Ordered from coarsest to finest. An FTP `LIST` line like `Jan 05 2021` only
/// has day precision, `Jan 05 12:30` has minutes, `MLSD`/`MDTM` give seconds (or
/// milliseconds), SFTP gives seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    /// Only the date is known.
    Day,
    /// Hours and minutes are known.
    Minute,
    /// Whole seconds are known.
    Second,
    /// Milliseconds are known.
    Millis,
}

/// A modification time together with how precise it is.
///
/// Directory comparison (T48) must not report a file as "newer" because one
/// side's listing carries more digits than the other: compare with
/// [`Timestamp::cmp_coarse`], which truncates both sides to the coarser
/// precision first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    /// The point in time. Digits finer than `precision` carry no meaning.
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    /// How much of `time` is meaningful.
    pub precision: Precision,
}

impl Timestamp {
    /// A timestamp of the given precision; finer digits are cleared.
    pub fn new(time: OffsetDateTime, precision: Precision) -> Self {
        Self {
            time: truncate(time, precision),
            precision,
        }
    }

    /// The time truncated to `precision` (never finer than this timestamp's own).
    pub fn truncated(&self, precision: Precision) -> OffsetDateTime {
        truncate(self.time, precision.min(self.precision))
    }

    /// Compare at the coarser of the two precisions.
    ///
    /// `2021-01-05` (day) and `2021-01-05 12:30` (minute) are `Equal`.
    pub fn cmp_coarse(&self, other: &Timestamp) -> Ordering {
        let p = self.precision.min(other.precision);
        self.truncated(p).cmp(&other.truncated(p))
    }

    /// Shift by a server time-zone offset (Site Manager setting, T31).
    pub fn shifted(&self, offset: Duration) -> Self {
        Self {
            time: self.time + offset,
            precision: self.precision,
        }
    }
}

fn truncate(t: OffsetDateTime, precision: Precision) -> OffsetDateTime {
    let (h, m, s, ns) = (t.hour(), t.minute(), t.second(), t.nanosecond());
    let time = match precision {
        Precision::Day => Time::MIDNIGHT,
        Precision::Minute => Time::from_hms(h, m, 0).unwrap_or(Time::MIDNIGHT),
        Precision::Second => Time::from_hms(h, m, s).unwrap_or(Time::MIDNIGHT),
        Precision::Millis => {
            Time::from_hms_nano(h, m, s, ns - ns % 1_000_000).unwrap_or(Time::MIDNIGHT)
        }
    };
    t.replace_time(time)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn new_clears_finer_digits() {
        let t = Timestamp::new(datetime!(2021-01-05 12:30:45.678_9 UTC), Precision::Minute);
        assert_eq!(t.time, datetime!(2021-01-05 12:30 UTC));
        let t = Timestamp::new(datetime!(2021-01-05 12:30:45.678_9 UTC), Precision::Millis);
        assert_eq!(t.time, datetime!(2021-01-05 12:30:45.678 UTC));
        let t = Timestamp::new(datetime!(2021-01-05 12:30:45 UTC), Precision::Day);
        assert_eq!(t.time, datetime!(2021-01-05 0:00 UTC));
    }

    #[test]
    fn precision_noise_is_not_newer() {
        let day = Timestamp::new(datetime!(2021-01-05 0:00 UTC), Precision::Day);
        let minute = Timestamp::new(datetime!(2021-01-05 12:30 UTC), Precision::Minute);
        let second = Timestamp::new(datetime!(2021-01-05 12:30:59 UTC), Precision::Second);
        assert_eq!(day.cmp_coarse(&minute), Ordering::Equal);
        assert_eq!(minute.cmp_coarse(&second), Ordering::Equal);
        assert_eq!(second.cmp_coarse(&day), Ordering::Equal);

        let next_day = Timestamp::new(datetime!(2021-01-06 0:00 UTC), Precision::Day);
        assert_eq!(next_day.cmp_coarse(&second), Ordering::Greater);
        let later = Timestamp::new(datetime!(2021-01-05 12:31 UTC), Precision::Minute);
        assert_eq!(second.cmp_coarse(&later), Ordering::Less);
    }

    #[test]
    fn serde_round_trip() {
        let t = Timestamp::new(datetime!(2024-02-29 23:59:59 +02:00), Precision::Second);
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), t);
    }
}
