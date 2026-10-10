//! Injectable time source, so token expiry can be tested by time travel
//! [`Clock`] in [`super::AuthRuntime`], also for SQL (bound as a parameter
//! instead of `now()`).

use std::sync::Mutex;

use chrono::{DateTime, TimeDelta, Utc};

/// A source of the current time.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// The current time.
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug)]
pub struct ManualClock(Mutex<DateTime<Utc>>);

impl ManualClock {
    /// Starts at the current system time.
    #[must_use]
    pub fn new() -> Self {
        Self(Mutex::new(Utc::now()))
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: TimeDelta) {
        if let Ok(mut t) = self.0.lock() {
            *t += by;
        }
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        self.0.lock().map_or_else(|_| Utc::now(), |t| *t)
    }
}

/// A server timestamp as the `time` type the wire DTOs use
/// (`courier_ftp_proto` timestamps are RFC 3339 via `time`).
#[must_use]
pub fn to_offset(t: DateTime<Utc>) -> time::OffsetDateTime {
    let nanos = i128::from(t.timestamp()) * 1_000_000_000 + i128::from(t.timestamp_subsec_nanos());
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrono_to_time_keeps_the_instant() {
        let t = DateTime::<Utc>::from_timestamp(1_700_000_000, 123_456_789).unwrap_or_default();
        let o = to_offset(t);
        assert_eq!(o.unix_timestamp(), 1_700_000_000);
        assert_eq!(o.nanosecond(), 123_456_789);
    }
}
