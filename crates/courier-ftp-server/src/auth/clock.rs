//! Injectable time source, so token expiry can be tested by time travel. The
//! store binds `now` from here as a parameter instead of SQL `now()`.

use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

/// A source of the current time.
pub trait Clock: Send + Sync + 'static {
    /// The current time (UTC).
    fn now(&self) -> OffsetDateTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug)]
pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    /// Starts at the current system time, rounded down to whole seconds (so it
    /// survives PostgreSQL's microsecond precision unchanged).
    #[must_use]
    pub fn new() -> Self {
        let now = OffsetDateTime::now_utc();
        Self::at(now.replace_nanosecond(0).unwrap_or(now))
    }

    /// Starts at `t`.
    #[must_use]
    pub const fn at(t: OffsetDateTime) -> Self {
        Self(Mutex::new(t))
    }

    /// Sets the time.
    pub fn set(&self, t: OffsetDateTime) {
        *self.lock() = t;
    }

    /// Moves the clock by `by` (may be negative).
    pub fn advance(&self, by: Duration) {
        let mut t = self.lock();
        *t += by;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OffsetDateTime> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_moves_only_when_told() {
        let c = TestClock::new();
        let t0 = c.now();
        assert_eq!(t0.nanosecond(), 0);
        assert_eq!(c.now(), t0);
        c.advance(Duration::minutes(15));
        assert_eq!(c.now() - t0, Duration::minutes(15));
        c.set(t0);
        assert_eq!(c.now(), t0);
    }
}
