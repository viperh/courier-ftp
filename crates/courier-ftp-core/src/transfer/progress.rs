//! [`ProgressTracker`]: speed (exponential moving average) and ETA for one
//! transfer, throttled to at most 10 updates per second.

use std::time::Duration;

use tokio::time::Instant;

use crate::events::{TransferId, TransferProgress};

/// Time constant of the speed average.
pub const SPEED_WINDOW: Duration = Duration::from_secs(5);
/// Minimum interval between two progress reports of one item (10 Hz).
pub const REPORT_INTERVAL: Duration = Duration::from_millis(100);

/// Tracks one transfer's progress. Feed it bytes with
/// [`ProgressTracker::advance`]; it returns a report at most every
/// [`REPORT_INTERVAL`].
#[derive(Debug, Clone)]
pub struct ProgressTracker {
    id: TransferId,
    total: Option<u64>,
    done: u64,
    /// Bytes since the last speed sample.
    pending: u64,
    last_sample: Instant,
    last_report: Option<Instant>,
    speed: f64,
    has_speed: bool,
}

impl ProgressTracker {
    /// A tracker starting at `done` bytes (a resume offset) of `total`.
    pub fn new(id: TransferId, done: u64, total: Option<u64>, now: Instant) -> Self {
        Self {
            id,
            total,
            done,
            pending: 0,
            last_sample: now,
            last_report: None,
            speed: 0.0,
            has_speed: false,
        }
    }

    /// Bytes done so far.
    pub fn done(&self) -> u64 {
        self.done
    }

    /// Records `bytes` more; returns a report when one is due.
    pub fn advance(&mut self, bytes: u64, now: Instant) -> Option<TransferProgress> {
        self.done = self.done.saturating_add(bytes);
        self.pending = self.pending.saturating_add(bytes);
        let due = self
            .last_report
            .is_none_or(|t| now.saturating_duration_since(t) >= REPORT_INTERVAL);
        if !due {
            return None;
        }
        self.sample(now);
        self.last_report = Some(now);
        Some(self.report())
    }

    /// Restart the speed average (after a pause: the idle time is no
    /// transfer speed).
    pub fn restart_speed(&mut self, now: Instant) {
        self.pending = 0;
        self.last_sample = now;
        self.speed = 0.0;
        self.has_speed = false;
    }

    fn sample(&mut self, now: Instant) {
        let dt = now
            .saturating_duration_since(self.last_sample)
            .as_secs_f64();
        if dt <= 0.0 {
            return;
        }
        #[allow(clippy::cast_precision_loss)]
        let instant = self.pending as f64 / dt;
        if self.has_speed {
            let alpha = 1.0 - (-dt / SPEED_WINDOW.as_secs_f64()).exp();
            self.speed += alpha * (instant - self.speed);
        } else {
            self.speed = instant;
            self.has_speed = true;
        }
        self.pending = 0;
        self.last_sample = now;
    }

    /// The current progress, unthrottled (for the final report).
    pub fn report(&self) -> TransferProgress {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let speed_bps = self.speed.max(0.0).round() as u64;
        let eta = match (self.total, speed_bps) {
            (Some(total), s) if s > 0 => {
                #[allow(clippy::cast_precision_loss)]
                let left = total.saturating_sub(self.done) as f64;
                Some(Duration::from_secs_f64(left / self.speed))
            }
            _ => None,
        };
        TransferProgress {
            id: self.id,
            bytes_done: self.done,
            total: self.total,
            speed_bps,
            eta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttles_and_averages() {
        let t0 = Instant::now();
        let mut p = ProgressTracker::new(TransferId(1), 0, Some(10_000), t0);
        // First call reports immediately (speed unknown yet: dt = 0).
        assert!(p.advance(100, t0).is_some());
        // Within 100 ms: no report.
        assert!(p.advance(100, t0 + Duration::from_millis(50)).is_none());
        let r = p.advance(800, t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(r.bytes_done, 1000);
        // The bytes of the first call count too (it had no interval yet).
        assert_eq!(r.speed_bps, 1000);
        assert_eq!(r.eta, Some(Duration::from_secs(9)));
        // A sudden burst moves the average only part of the way.
        let r = p.advance(10_000, t0 + Duration::from_secs(2)).unwrap();
        assert!(
            r.speed_bps > 1000 && r.speed_bps < 10_000,
            "{}",
            r.speed_bps
        );
        assert_eq!(r.eta, Some(Duration::ZERO));
    }

    #[test]
    fn resume_offset_counts_as_done() {
        let t0 = Instant::now();
        let mut p = ProgressTracker::new(TransferId(1), 500, Some(1000), t0);
        assert_eq!(p.advance(0, t0).unwrap().bytes_done, 500);
        p.restart_speed(t0);
        assert_eq!(p.report().speed_bps, 0);
        assert_eq!(p.report().eta, None);
    }
}
