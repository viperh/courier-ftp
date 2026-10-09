//! Rate limiting with `governor` (GCRA; the full quota is available as a burst
//! and refills evenly over the minute).
//!
//! | Limiter | Key | Quota |
//! |---|---|---|
//! | `auth_email` | normalized email | 5 / min |
//! | `auth_ip` | client IP | 50 / min |
//!
//! Applied to `register/start`, `login/start`, `recovery/code`,
//! `recovery/start` and `recovery`. The email is only known after the JSON body
//! is parsed, so this is not a tower layer: those handlers call
//! [`RateLimiters::check`] with the email and the [`ClientIp`] extension. The IP
//! limit is checked first. Exceeding either → `429 rate_limited` with
//! `retry_after_s` (governor's wait, rounded up) and `Retry-After`. Limiters are
//! per replica. [`RateLimiters::spawn_cleanup`] drops keys whose state has fully
//! recovered every 60 s.
//!
//! [`ClientIp`]: crate::middleware::client_ip::ClientIp

use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use crate::error::ApiError;

/// How often stale keys are dropped.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// One keyed GCRA limiter.
pub struct KeyedLimiter<K: Hash + Eq + Clone, C: Clock = DefaultClock> {
    limiter: RateLimiter<K, DefaultKeyedStateStore<K>, C, NoOpMiddleware<C::Instant>>,
}

impl<K: Hash + Eq + Clone, C: Clock> std::fmt::Debug for KeyedLimiter<K, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyedLimiter")
            .field("keys", &self.limiter.len())
            .finish()
    }
}

impl<K: Hash + Eq + Clone> KeyedLimiter<K> {
    /// `per_minute` events per key and minute on the real clock.
    #[must_use]
    pub fn per_minute(per_minute: NonZeroU32) -> Self {
        Self::with_clock(Quota::per_minute(per_minute), DefaultClock::default())
    }
}

impl<K: Hash + Eq + Clone, C: Clock> KeyedLimiter<K, C> {
    /// A limiter on an explicit clock (tests: governor's `FakeRelativeClock`).
    #[must_use]
    pub fn with_clock(quota: Quota, clock: C) -> Self {
        Self {
            limiter: RateLimiter::dashmap_with_clock(quota, clock),
        }
    }

    /// Counts one event for `key`; `Err(wait)` when the key is over its quota.
    ///
    /// # Errors
    /// The time until the next event would be allowed.
    pub fn check(&self, key: &K) -> Result<(), Duration> {
        self.limiter
            .check_key(key)
            .map_err(|not_until| not_until.wait_time_from(self.limiter.clock().now()))
    }

    /// Drops keys whose state has fully recovered.
    pub fn cleanup(&self) {
        self.limiter.retain_recent();
        self.limiter.shrink_to_fit();
    }

    /// Number of tracked keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.limiter.len()
    }

    /// Whether no key is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.limiter.is_empty()
    }
}

/// Quotas per minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthLimits {
    /// Attempts per email per minute (5).
    pub per_email_per_minute: NonZeroU32,
    /// Attempts per client IP per minute (50).
    pub per_ip_per_minute: NonZeroU32,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            per_email_per_minute: NonZeroU32::MIN.saturating_add(4),
            per_ip_per_minute: NonZeroU32::MIN.saturating_add(49),
        }
    }
}

/// The server's keyed limiters.
#[derive(Debug)]
pub struct RateLimiters {
    auth_email: KeyedLimiter<String>,
    auth_ip: KeyedLimiter<IpAddr>,
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new(AuthLimits::default())
    }
}

/// `retry_after_s`: the wait rounded up, at least 1.
#[must_use]
pub fn retry_after_secs(wait: Duration) -> u64 {
    (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1)
}

impl RateLimiters {
    /// Limiters with the given quotas.
    #[must_use]
    pub fn new(limits: AuthLimits) -> Self {
        Self {
            auth_email: KeyedLimiter::per_minute(limits.per_email_per_minute),
            auth_ip: KeyedLimiter::per_minute(limits.per_ip_per_minute),
        }
    }

    /// Counts one attempt for the normalized `email` from `ip` (IP first).
    ///
    /// # Errors
    /// [`ApiError::RateLimited`] when either limit is exceeded.
    pub fn check(&self, email: &str, ip: IpAddr) -> Result<(), ApiError> {
        let limited = |wait| ApiError::RateLimited {
            retry_after_s: retry_after_secs(wait),
        };
        self.auth_ip.check(&ip).map_err(limited)?;
        self.auth_email.check(&email.to_owned()).map_err(limited)
    }

    /// Drops keys whose state has fully recovered.
    pub fn cleanup(&self) {
        self.auth_email.cleanup();
        self.auth_ip.cleanup();
    }

    /// Runs [`Self::cleanup`] every [`CLEANUP_INTERVAL`] until the runtime stops.
    pub fn spawn_cleanup(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                self.cleanup();
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use governor::clock::FakeRelativeClock;

    use super::*;

    #[test]
    fn burst_then_refill() {
        let clock = FakeRelativeClock::default();
        let l: KeyedLimiter<&str, FakeRelativeClock> = KeyedLimiter::with_clock(
            Quota::per_minute(NonZeroU32::new(5).unwrap()),
            clock.clone(),
        );
        // The full burst at once…
        for _ in 0..5 {
            assert!(l.check(&"a@example.test").is_ok());
        }
        // …then the 6th waits one emission interval (60 s / 5 = 12 s).
        let wait = l.check(&"a@example.test").unwrap_err();
        assert_eq!(retry_after_secs(wait), 12);
        // Other keys are independent.
        assert!(l.check(&"b@example.test").is_ok());
        // One interval later exactly one more is allowed.
        clock.advance(Duration::from_secs(12));
        assert!(l.check(&"a@example.test").is_ok());
        assert!(l.check(&"a@example.test").is_err());
        // Long after, the whole burst is back and cleanup drops the keys.
        clock.advance(Duration::from_secs(120));
        assert_eq!(l.len(), 2);
        l.cleanup();
        assert!(l.is_empty());
        for _ in 0..5 {
            assert!(l.check(&"a@example.test").is_ok());
        }
    }

    #[test]
    fn ip_limit_is_checked_first_and_retry_after_rounds_up() {
        let rl = RateLimiters::new(AuthLimits {
            per_email_per_minute: NonZeroU32::new(5).unwrap(),
            per_ip_per_minute: NonZeroU32::new(2).unwrap(),
        });
        let ip: IpAddr = [192, 0, 2, 1].into();
        assert!(rl.check("a@x.test", ip).is_ok());
        assert!(rl.check("b@x.test", ip).is_ok());
        match rl.check("c@x.test", ip) {
            Err(ApiError::RateLimited { retry_after_s }) => assert_eq!(retry_after_s, 30),
            other => panic!("expected rate limit, got {other:?}"),
        }
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1001)), 2);
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
    }
}
