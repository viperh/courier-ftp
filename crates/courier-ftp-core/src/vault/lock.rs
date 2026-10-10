//! Why the vault locks, the idle auto-lock timer and the suspend detector (sverb
//! `vault/lock.rs`, D13). Both timers are pure: the app loop (T50/T60) feeds them.

use std::time::{Duration, Instant, SystemTime};

/// Why [`VaultEngine::lock`](super::VaultEngine::lock) was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockReason {
    /// The user locked (`Ctrl-x Ctrl-l`, T51).
    Manual,
    /// `vault.auto_lock_minutes` passed without input.
    Idle,
    /// The system suspended (or the process was frozen).
    Suspend,
    /// The application is quitting.
    Shutdown,
}

impl LockReason {
    /// A stable lowercase name for logs.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Idle => "idle",
            Self::Suspend => "suspend",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Longest accepted `vault.auto_lock_minutes` (one day).
pub const MAX_AUTO_LOCK_MINUTES: u32 = 1440;

/// Reset-on-input idle timer. Every key press calls [`AutoLock::on_input`]; the app
/// loop asks [`AutoLock::due`] and locks with [`LockReason::Idle`]. The timer is armed
/// by the first `on_input` (call it once when the vault unlocks).
#[derive(Debug, Clone)]
pub struct AutoLock {
    timeout: Option<Duration>,
    last_input: Option<Instant>,
}

fn timeout_for(minutes: u32) -> Option<Duration> {
    (minutes > 0).then(|| Duration::from_secs(u64::from(minutes.min(MAX_AUTO_LOCK_MINUTES)) * 60))
}

impl AutoLock {
    /// A timer for `minutes` (0 = off, capped at [`MAX_AUTO_LOCK_MINUTES`]).
    pub fn new(minutes: u32) -> Self {
        Self {
            timeout: timeout_for(minutes),
            last_input: None,
        }
    }

    /// Input happened at `now`: restart the countdown.
    pub fn on_input(&mut self, now: Instant) {
        self.last_input = Some(now);
    }

    /// The setting changed (T68). The countdown keeps its start.
    pub fn set_minutes(&mut self, minutes: u32) {
        self.timeout = timeout_for(minutes);
    }

    /// Whether the idle time is up at `now`. Always false when off or not yet armed.
    pub fn due(&self, now: Instant) -> bool {
        match (self.timeout, self.last_input) {
            (Some(timeout), Some(last)) => now.saturating_duration_since(last) >= timeout,
            _ => false,
        }
    }
}

/// The wall clock moved this much more than the monotonic clock: a suspend (Linux and
/// macOS monotonic clocks stop during sleep).
pub const SUSPEND_WALL_GAP: Duration = Duration::from_secs(10);
/// The monotonic clock moved this much between two one-second ticks: the process was
/// frozen (covers Windows, where the monotonic clock may include sleep).
pub const FROZEN_GAP: Duration = Duration::from_secs(30);

/// Suspend/resume detector, fed about once per second by the app loop.
#[derive(Debug, Clone, Default)]
pub struct SuspendDetector {
    last: Option<(SystemTime, Instant)>,
}

impl SuspendDetector {
    /// A detector without a previous sample.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a sample; true when a resume from suspend (or a frozen process) is
    /// detected since the previous one. A wall clock that jumps backwards never
    /// counts.
    pub fn tick(&mut self, wall: SystemTime, mono: Instant) -> bool {
        let Some((prev_wall, prev_mono)) = self.last.replace((wall, mono)) else {
            return false;
        };
        let mono_delta = mono.saturating_duration_since(prev_mono);
        if mono_delta > FROZEN_GAP {
            return true;
        }
        // A backwards wall jump gives `Err` here and never locks.
        wall.duration_since(prev_wall)
            .is_ok_and(|wall_delta| wall_delta.saturating_sub(mono_delta) > SUSPEND_WALL_GAP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn auto_lock_due_after_timeout() {
        let t0 = Instant::now();
        let mut a = AutoLock::new(15);
        assert!(!a.due(t0 + 20 * MIN), "not armed before the first input");
        a.on_input(t0);
        assert!(!a.due(t0 + 15 * MIN - Duration::from_secs(1)));
        assert!(a.due(t0 + 15 * MIN));
        a.set_minutes(30);
        assert!(!a.due(t0 + 15 * MIN));
        assert!(a.due(t0 + 30 * MIN));
        a.set_minutes(5000);
        assert!(a.due(t0 + 1440 * MIN), "capped at one day");
    }

    #[test]
    fn input_resets() {
        let t0 = Instant::now();
        let mut a = AutoLock::new(15);
        a.on_input(t0);
        a.on_input(t0 + 10 * MIN);
        assert!(!a.due(t0 + 24 * MIN + Duration::from_secs(59)));
        assert!(a.due(t0 + 25 * MIN));
    }

    #[test]
    fn zero_disables() {
        let t0 = Instant::now();
        let mut a = AutoLock::new(0);
        a.on_input(t0);
        assert!(!a.due(t0 + 10_000 * MIN));
    }

    #[test]
    fn suspend_detected_by_wall_jump() {
        let (w, m) = (SystemTime::UNIX_EPOCH + MIN * 1000, Instant::now());
        let mut d = SuspendDetector::new();
        assert!(!d.tick(w, m));
        assert!(!d.tick(w + Duration::from_secs(1), m + Duration::from_secs(1)));
        assert!(d.tick(w + Duration::from_secs(61), m + Duration::from_secs(2)));
        // A small drift is not a suspend.
        assert!(!d.tick(w + Duration::from_secs(66), m + Duration::from_secs(3)));
    }

    #[test]
    fn frozen_process_detected() {
        let (w, m) = (SystemTime::UNIX_EPOCH + MIN * 1000, Instant::now());
        let mut d = SuspendDetector::new();
        d.tick(w, m);
        assert!(d.tick(w + Duration::from_secs(31), m + Duration::from_secs(31)));
        assert!(!d.tick(w + Duration::from_secs(61), m + Duration::from_secs(61)));
    }

    #[test]
    fn backwards_wall_jump_ignored() {
        let (w, m) = (SystemTime::UNIX_EPOCH + MIN * 1000, Instant::now());
        let mut d = SuspendDetector::new();
        d.tick(w, m);
        assert!(!d.tick(w - 60 * MIN, m + Duration::from_secs(1)));
        assert!(!d.tick(
            w - 60 * MIN + Duration::from_secs(1),
            m + Duration::from_secs(2)
        ));
    }
}
