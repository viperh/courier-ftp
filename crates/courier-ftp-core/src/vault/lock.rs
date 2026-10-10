//! The lock state machine and auto-lock (sverb `vault/lock.rs`).
//!
//! The UI only knows [`LockState`]; keys live in the engine. [`AutoLock`] is a
//! reset-on-input idle timer plus suspend detection: the app feeds it every key
//! press ([`AutoLock::on_input`]) and calls [`AutoLock::tick`] periodically;
//! when it returns a [`LockReason`] the app locks the vault.
//!
//! Suspend/resume is detected as a wall-clock jump between two ticks that the
//! monotonic clock did not see (the monotonic clock stops while the machine
//! sleeps on Linux and macOS).

use std::time::{Duration, SystemTime};

use tokio::time::Instant;

use crate::settings::VaultSettings;

/// What the UI knows about the vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LockState {
    /// No keys in memory: items are unreadable, panes are covered.
    #[default]
    Locked,
    /// An unlock (Argon2 or keyring) is running.
    Unlocking,
    /// Keys are in memory (owned by the engine, never by the UI).
    Unlocked,
}

impl LockState {
    /// `Locked` or `Unlocking`.
    pub fn is_locked(self) -> bool {
        !matches!(self, Self::Unlocked)
    }

    /// Whether an unlock may start (not while one runs).
    pub fn can_start_unlock(self) -> bool {
        matches!(self, Self::Locked)
    }
}

/// Why the vault locked itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// No input for `vault.auto_lock_minutes`.
    Idle,
    /// The machine was suspended (wall clock jumped between ticks).
    Suspend,
}

/// The idle timeout for `vault.auto_lock_minutes`; `None` when `0` (off).
pub fn auto_lock_timeout(minutes: u32) -> Option<Duration> {
    (minutes > 0).then(|| Duration::from_secs(u64::from(minutes) * 60))
}

/// A wall-clock jump larger than the monotonic time between two ticks plus
/// this much counts as a suspend/resume.
pub const SUSPEND_JUMP: Duration = Duration::from_secs(60);

/// The auto-lock timer (see the module docs).
#[derive(Debug, Clone)]
pub struct AutoLock {
    idle: Option<Duration>,
    lock_on_suspend: bool,
    last_input: Instant,
    last_tick: Option<(Instant, SystemTime)>,
}

impl AutoLock {
    /// A timer with `vault.auto_lock_minutes` = `minutes` (0 = off), armed at
    /// `now`.
    pub fn new(minutes: u32, lock_on_suspend: bool, now: Instant) -> Self {
        Self {
            idle: auto_lock_timeout(minutes),
            lock_on_suspend,
            last_input: now,
            last_tick: None,
        }
    }

    /// A timer configured from the `vault` settings.
    pub fn from_settings(settings: &VaultSettings, now: Instant) -> Self {
        Self::new(settings.auto_lock_minutes, settings.lock_on_suspend, now)
    }

    /// Applies changed settings without resetting the idle timer.
    pub fn configure(&mut self, settings: &VaultSettings) {
        self.idle = auto_lock_timeout(settings.auto_lock_minutes);
        self.lock_on_suspend = settings.lock_on_suspend;
    }

    /// The idle timeout, `None` when idle auto-lock is off.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle
    }

    /// Any input (key press): re-arms the idle timer.
    pub fn on_input(&mut self, now: Instant) {
        self.last_input = now;
    }

    /// Re-arms everything (after an unlock).
    pub fn reset(&mut self, now: Instant) {
        self.last_input = now;
        self.last_tick = None;
    }

    /// When the idle timer fires, `None` when idle auto-lock is off. The app
    /// can sleep until then.
    pub fn deadline(&self) -> Option<Instant> {
        self.idle.map(|d| self.last_input + d)
    }

    /// Checks the timers at `now` (monotonic) / `wall` (system time). Returns
    /// why the vault must lock, if it must. Call it regularly (every second or
    /// so) while the vault is unlocked.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> Option<LockReason> {
        let previous = self.last_tick.replace((now, wall));
        if self.lock_on_suspend
            && let Some((prev_now, prev_wall)) = previous
        {
            let mono = now.saturating_duration_since(prev_now);
            let jumped = wall
                .duration_since(prev_wall)
                .is_ok_and(|w| w > mono + SUSPEND_JUMP);
            if jumped {
                return Some(LockReason::Suspend);
            }
        }
        match self.deadline() {
            Some(deadline) if now >= deadline => Some(LockReason::Idle),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_rule() {
        assert_eq!(auto_lock_timeout(0), None);
        assert_eq!(auto_lock_timeout(1), Some(Duration::from_secs(60)));
        assert_eq!(auto_lock_timeout(15), Some(Duration::from_secs(900)));
    }

    #[test]
    fn states() {
        assert!(LockState::default().is_locked());
        assert!(LockState::Unlocking.is_locked());
        assert!(!LockState::Unlocked.is_locked());
        assert!(LockState::Locked.can_start_unlock());
        assert!(!LockState::Unlocking.can_start_unlock());
    }

    const WALL0: SystemTime = SystemTime::UNIX_EPOCH;

    fn wall(secs: u64) -> SystemTime {
        WALL0 + Duration::from_secs(1_800_000_000 + secs)
    }

    #[tokio::test(start_paused = true)]
    async fn fires_after_timeout_and_input_resets_it() {
        let t0 = Instant::now();
        let mut lock = AutoLock::new(15, true, t0);
        assert_eq!(lock.deadline(), Some(t0 + Duration::from_secs(900)));

        // 14 minutes idle, then a key press.
        tokio::time::advance(Duration::from_secs(14 * 60)).await;
        assert_eq!(lock.tick(Instant::now(), wall(14 * 60)), None);
        lock.on_input(Instant::now());

        // 14 more minutes: still unlocked (the press re-armed the timer).
        tokio::time::advance(Duration::from_secs(14 * 60)).await;
        assert_eq!(lock.tick(Instant::now(), wall(28 * 60)), None);

        // One more minute after the timeout: locks.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(
            lock.tick(Instant::now(), wall(29 * 60)),
            Some(LockReason::Idle)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_minutes_is_off() {
        let mut lock = AutoLock::new(0, false, Instant::now());
        assert_eq!(lock.deadline(), None);
        tokio::time::advance(Duration::from_secs(24 * 3600)).await;
        assert_eq!(lock.tick(Instant::now(), wall(24 * 3600)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn wall_clock_jump_is_a_suspend() {
        let mut lock = AutoLock::new(0, true, Instant::now());
        assert_eq!(lock.tick(Instant::now(), wall(0)), None);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(lock.tick(Instant::now(), wall(1)), None);
        // One monotonic second, but an hour on the wall clock.
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            lock.tick(Instant::now(), wall(3600)),
            Some(LockReason::Suspend)
        );
        // Off: no suspend lock.
        let mut off = AutoLock::new(0, false, Instant::now());
        off.tick(Instant::now(), wall(0));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(off.tick(Instant::now(), wall(7200)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn configure_keeps_the_timer() {
        let t0 = Instant::now();
        let mut lock = AutoLock::new(15, true, t0);
        let settings = VaultSettings {
            auto_lock_minutes: 5,
            ..VaultSettings::default()
        };
        lock.configure(&settings);
        assert_eq!(lock.idle_timeout(), Some(Duration::from_secs(300)));
        assert_eq!(lock.deadline(), Some(t0 + Duration::from_secs(300)));
        lock.reset(t0 + Duration::from_secs(10));
        assert_eq!(lock.deadline(), Some(t0 + Duration::from_secs(310)));
    }
}
