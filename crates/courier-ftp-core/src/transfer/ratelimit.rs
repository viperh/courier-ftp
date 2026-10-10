//! Global speed limits (T44): one token bucket per direction, shared by
//! every transfer of the engine (and so by every tab), changeable at
//! runtime.
//!
//! # Model
//!
//! - **Rate** = `transfers.download_limit_kib` / `upload_limit_kib` × 1024
//!   bytes per second. A limit of 0, or `speed_limit_enabled = false`, means
//!   unlimited for that direction: [`RateLimiter::acquire`] returns at once.
//! - **Capacity** (burst tolerance) = rate × [`burst_duration`]:
//!   [`Normal`](BurstTolerance::Normal) 1 s,
//!   [`High`](BurstTolerance::High) 2 s,
//!   [`VeryHigh`](BurstTolerance::VeryHigh) 5 s. Tokens accrue while the
//!   direction is idle (or slower than the limit), up to the capacity; a
//!   transfer may then run that far ahead of the limit.
//! - The bucket starts **empty** when a limit is switched on (from
//!   unlimited), so a fresh limit is exact from the first second instead of
//!   starting with a burst.
//! - **Fairness**: waiters are served FIFO (a fair `tokio` mutex holds the
//!   queue), so concurrent transfers alternate chunks and share the limit
//!   about equally.
//! - **Chunks**: [`RateLimiter::chunk_size`] caps the engine's read size to
//!   about a tenth of the rate (at least [`MIN_CHUNK`]), so a slow limit is
//!   met in small, even steps rather than one large chunk every few seconds.
//!   A chunk larger than the capacity waits for a full bucket and leaves a
//!   debt.
//! - **Runtime changes** ([`RateLimiter::settings_changed`], the engine's
//!   `SettingsChanged` command): a waiting transfer is woken and re-checks
//!   at once, so switching the limit off frees it within the current chunk
//!   and a new rate applies to the next chunk. Tokens (or debt) are kept but
//!   clamped to ± the new capacity.
//!
//! # Wiring
//!
//! ```ignore
//! let limiter = Arc::new(SpeedLimiter::new(&settings.transfers));
//! let (engine, handle) = TransferEngine::builder(queue, factory, resolver, events)
//!     .settings(settings.clone())
//!     .rate_limiter(limiter.clone())
//!     .build();
//! // Status bar toggle (<Ctrl-x><l>, T57): flip the setting and tell the engine.
//! settings.transfers.speed_limit_enabled ^= true;
//! handle.settings_changed(settings.clone());
//! // Status bar indicator:
//! let down = limiter.limit_kib(Direction::Download); // None = unlimited
//! ```
//!
//! The binary does not construct the engine yet; its status bar keeps its
//! own on/off flag until it does (see `tasks/44-speed-limits.md`).

use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{sync::watch, time::Instant};

use super::hooks::RateLimiter;
use crate::{
    model::Direction,
    settings::{BurstTolerance, TransferSettings},
};

/// Smallest chunk [`SpeedLimiter::chunk_size`] asks for (1 KiB).
pub const MIN_CHUNK: usize = 1024;

/// How many seconds of the rate the bucket holds for a burst tolerance.
pub fn burst_duration(burst: BurstTolerance) -> Duration {
    Duration::from_secs(match burst {
        BurstTolerance::Normal => 1,
        BurstTolerance::High => 2,
        BurstTolerance::VeryHigh => 5,
    })
}

/// The token-bucket [`RateLimiter`]: global download and upload limits.
///
/// Share it with `Arc` (the engine takes an `Arc<dyn RateLimiter>`; keep a
/// clone for [`limit_kib`](Self::limit_kib)).
#[derive(Debug, Default)]
pub struct SpeedLimiter {
    download: Bucket,
    upload: Bucket,
}

impl SpeedLimiter {
    /// A limiter configured from `settings`.
    pub fn new(settings: &TransferSettings) -> Self {
        let limiter = Self::default();
        limiter.update(settings);
        limiter
    }

    /// Apply new settings now (also through
    /// [`RateLimiter::settings_changed`]).
    pub fn update(&self, settings: &TransferSettings) {
        let burst = burst_duration(settings.burst_tolerance);
        let (down, up) = if settings.speed_limit_enabled {
            (settings.download_limit_kib, settings.upload_limit_kib)
        } else {
            (0, 0)
        };
        self.download.configure(down, burst);
        self.upload.configure(up, burst);
    }

    /// The effective limit for `direction` in KiB/s, `None` when unlimited
    /// (switched off or 0). For the status bar indicator (T57).
    pub fn limit_kib(&self, direction: Direction) -> Option<u64> {
        let kib = self.bucket(direction).state().kib;
        (kib > 0).then_some(kib)
    }

    fn bucket(&self, direction: Direction) -> &Bucket {
        match direction {
            Direction::Download => &self.download,
            Direction::Upload => &self.upload,
        }
    }
}

#[async_trait]
impl RateLimiter for SpeedLimiter {
    async fn acquire(&self, direction: Direction, bytes: usize) {
        self.bucket(direction).acquire(bytes).await;
    }

    fn chunk_size(&self, direction: Direction, preferred: usize) -> usize {
        let rate = self.bucket(direction).state().rate;
        if rate <= 0.0 {
            return preferred;
        }
        // Float to int casts saturate.
        ((rate / 10.0) as usize).max(MIN_CHUNK).min(preferred)
    }

    fn settings_changed(&self, settings: &TransferSettings) {
        self.update(settings);
    }
}

/// One direction's bucket.
#[derive(Debug)]
struct Bucket {
    state: Mutex<State>,
    /// FIFO turn: only the holder waits for tokens, the rest queue behind.
    turn: tokio::sync::Mutex<()>,
    /// Pinged when the limit changes so the waiter re-checks.
    changed: watch::Sender<()>,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                kib: 0,
                rate: 0.0,
                capacity: 0.0,
                tokens: 0.0,
                last: Instant::now(),
            }),
            turn: tokio::sync::Mutex::new(()),
            changed: watch::Sender::new(()),
        }
    }
}

#[derive(Debug)]
struct State {
    /// The limit in KiB/s; 0 = unlimited.
    kib: u64,
    /// Bytes per second; 0 = unlimited.
    rate: f64,
    /// Bucket size in bytes.
    capacity: f64,
    /// Available bytes; negative after a chunk larger than the capacity.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    last: Instant,
}

impl State {
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        if self.rate > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        }
    }
}

impl Bucket {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn configure(&self, kib: u64, burst: Duration) {
        let now = Instant::now();
        let rate = kib as f64 * 1024.0;
        let capacity = rate * burst.as_secs_f64();
        {
            let mut s = self.state();
            if s.kib == kib && s.capacity == capacity {
                return;
            }
            s.refill(now);
            let was_unlimited = s.rate <= 0.0;
            s.kib = kib;
            s.rate = rate;
            s.capacity = capacity;
            s.tokens = if was_unlimited || rate <= 0.0 {
                0.0
            } else {
                s.tokens.clamp(-capacity, capacity)
            };
        }
        self.changed.send_replace(());
    }

    async fn acquire(&self, bytes: usize) {
        if bytes == 0 || self.state().rate <= 0.0 {
            return;
        }
        let _turn = self.turn.lock().await;
        let mut changed = self.changed.subscribe();
        let n = bytes as f64;
        loop {
            let wait = {
                let mut s = self.state();
                if s.rate <= 0.0 {
                    return;
                }
                s.refill(Instant::now());
                let need = n.min(s.capacity);
                // A microsecond of slack absorbs float and nanosecond
                // rounding, so a wait never ends a hair short of the goal.
                if s.tokens + s.rate * 1e-6 >= need {
                    s.tokens -= n;
                    return;
                }
                Duration::from_secs_f64((need - s.tokens) / s.rate)
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                r = changed.changed() => {
                    if r.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    use super::*;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    fn limits(down_kib: u64, up_kib: u64, burst: BurstTolerance) -> TransferSettings {
        TransferSettings {
            speed_limit_enabled: true,
            download_limit_kib: down_kib,
            upload_limit_kib: up_kib,
            burst_tolerance: burst,
            ..TransferSettings::default()
        }
    }

    /// Spawns a transfer that pushes chunks through `limiter` like the
    /// engine does, counting bytes, until `stop` is set.
    fn pump(
        limiter: &Arc<SpeedLimiter>,
        direction: Direction,
        stop: &Arc<AtomicBool>,
    ) -> (Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
        let counter = Arc::new(AtomicU64::new(0));
        let (l, c, s) = (Arc::clone(limiter), Arc::clone(&counter), Arc::clone(stop));
        let task = tokio::spawn(async move {
            while !s.load(Ordering::Relaxed) {
                let chunk = l.chunk_size(direction, super::super::BUFFER_SIZE);
                l.acquire(direction, chunk).await;
                c.fetch_add(chunk as u64, Ordering::Relaxed);
                // The write itself.
                tokio::task::yield_now().await;
            }
        });
        (counter, task)
    }

    fn within(actual: u64, expected: u64, tolerance: f64) -> bool {
        let (a, e) = (actual as f64, expected as f64);
        (a - e).abs() <= e * tolerance
    }

    #[test]
    fn burst_mapping() {
        assert_eq!(
            burst_duration(BurstTolerance::Normal),
            Duration::from_secs(1)
        );
        assert_eq!(burst_duration(BurstTolerance::High), Duration::from_secs(2));
        assert_eq!(
            burst_duration(BurstTolerance::VeryHigh),
            Duration::from_secs(5)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn effective_limits_and_chunk_sizes() {
        let l = SpeedLimiter::new(&limits(10, 0, BurstTolerance::Normal));
        assert_eq!(l.limit_kib(Direction::Download), Some(10));
        assert_eq!(l.limit_kib(Direction::Upload), None, "0 = unlimited");
        assert_eq!(l.chunk_size(Direction::Download, 128 * 1024), 1024);
        assert_eq!(l.chunk_size(Direction::Upload, 128 * 1024), 128 * 1024);

        l.update(&limits(500, 1, BurstTolerance::Normal));
        assert_eq!(l.chunk_size(Direction::Download, 128 * 1024), 51_200);
        assert_eq!(l.chunk_size(Direction::Upload, 128 * 1024), MIN_CHUNK);
        l.update(&limits(100_000, 0, BurstTolerance::Normal));
        assert_eq!(l.chunk_size(Direction::Download, 128 * 1024), 128 * 1024);

        let mut off = limits(500, 500, BurstTolerance::Normal);
        off.speed_limit_enabled = false;
        l.update(&off);
        assert_eq!(l.limit_kib(Direction::Download), None);
        assert_eq!(l.limit_kib(Direction::Upload), None);

        assert_eq!(SpeedLimiter::default().limit_kib(Direction::Download), None);
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_returns_at_once() {
        let l = SpeedLimiter::new(&TransferSettings::default());
        let start = Instant::now();
        for _ in 0..1000 {
            l.acquire(Direction::Download, 1 << 20).await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    async fn measure(kib: u64, burst: BurstTolerance) -> u64 {
        let l = Arc::new(SpeedLimiter::new(&limits(kib, 0, burst)));
        let stop = Arc::new(AtomicBool::new(false));
        let (bytes, task) = pump(&l, Direction::Download, &stop);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let done = bytes.load(Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
        task.abort();
        done
    }

    #[tokio::test(start_paused = true)]
    async fn throughput_100_kib_within_5_percent() {
        let done = measure(100, BurstTolerance::Normal).await;
        assert!(within(done, 1000 * KIB, 0.05), "{done} bytes in 10 s");
    }

    #[tokio::test(start_paused = true)]
    async fn throughput_1_mib_within_5_percent() {
        for burst in [BurstTolerance::Normal, BurstTolerance::VeryHigh] {
            let done = measure(1024, burst).await;
            assert!(within(done, 10 * MIB, 0.05), "{burst:?}: {done} bytes");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_limit_is_exact_too() {
        let done = measure(3, BurstTolerance::Normal).await;
        assert!(within(done, 30 * KIB, 0.05), "{done} bytes");
    }

    #[tokio::test(start_paused = true)]
    async fn two_transfers_share_equally() {
        let l = Arc::new(SpeedLimiter::new(&limits(100, 0, BurstTolerance::Normal)));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, ta) = pump(&l, Direction::Download, &stop);
        let (b, tb) = pump(&l, Direction::Download, &stop);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let (a, b) = (a.load(Ordering::Relaxed), b.load(Ordering::Relaxed));
        stop.store(true, Ordering::Relaxed);
        ta.abort();
        tb.abort();
        assert!(within(a + b, 1000 * KIB, 0.05), "total {}", a + b);
        assert!(within(a, b, 0.2), "a {a}, b {b}");
    }

    #[tokio::test(start_paused = true)]
    async fn directions_are_independent() {
        let l = Arc::new(SpeedLimiter::new(&limits(100, 50, BurstTolerance::Normal)));
        let stop = Arc::new(AtomicBool::new(false));
        let (down, td) = pump(&l, Direction::Download, &stop);
        let (up, tu) = pump(&l, Direction::Upload, &stop);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let (down, up) = (down.load(Ordering::Relaxed), up.load(Ordering::Relaxed));
        stop.store(true, Ordering::Relaxed);
        td.abort();
        tu.abort();
        assert!(within(down, 1000 * KIB, 0.05), "down {down}");
        assert!(within(up, 500 * KIB, 0.05), "up {up}");
    }

    #[tokio::test(start_paused = true)]
    async fn burst_after_idle_up_to_capacity() {
        for (burst, secs) in [(BurstTolerance::Normal, 1), (BurstTolerance::High, 2)] {
            let l = SpeedLimiter::new(&limits(100, 0, burst));
            // Idle for longer than the bucket holds.
            tokio::time::sleep(Duration::from_secs(30)).await;
            let start = Instant::now();
            let chunk = l.chunk_size(Direction::Download, 128 * 1024);
            let mut sent = 0;
            while sent < secs * 100 * KIB {
                l.acquire(Direction::Download, chunk).await;
                sent += chunk as u64;
            }
            assert_eq!(start.elapsed(), Duration::ZERO, "{burst:?}: burst is free");
            // The next chunk waits for the rate again.
            l.acquire(Direction::Download, chunk).await;
            let waited = start.elapsed().as_secs_f64();
            assert!((0.09..0.11).contains(&waited), "{burst:?}: {waited}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn turning_off_frees_a_waiter_at_once() {
        let l = Arc::new(SpeedLimiter::new(&limits(1, 0, BurstTolerance::Normal)));
        // Drain the (empty) bucket into debt: a 64 KiB chunk at 1 KiB/s.
        l.acquire(Direction::Download, 1024).await;
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                let start = Instant::now();
                l.acquire(Direction::Download, 1024).await;
                start.elapsed()
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished());
        let mut off = limits(1, 0, BurstTolerance::Normal);
        off.speed_limit_enabled = false;
        l.settings_changed(&off);
        let waited = waiter.await.unwrap();
        assert_eq!(waited, Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn changing_the_limit_mid_transfer() {
        let l = Arc::new(SpeedLimiter::new(&limits(100, 0, BurstTolerance::Normal)));
        let stop = Arc::new(AtomicBool::new(false));
        let (bytes, task) = pump(&l, Direction::Download, &stop);

        tokio::time::sleep(Duration::from_secs(5)).await;
        let first = bytes.load(Ordering::Relaxed);
        assert!(within(first, 500 * KIB, 0.05), "{first}");

        l.settings_changed(&limits(400, 0, BurstTolerance::Normal));
        tokio::time::sleep(Duration::from_secs(5)).await;
        let second = bytes.load(Ordering::Relaxed) - first;
        assert!(within(second, 2000 * KIB, 0.05), "{second}");

        l.settings_changed(&limits(20, 0, BurstTolerance::Normal));
        tokio::time::sleep(Duration::from_secs(5)).await;
        let third = bytes.load(Ordering::Relaxed) - first - second;
        // The 400 KiB/s chunk in flight (40 KiB) may still land as debt.
        assert!(within(third, 100 * KIB, 0.5), "{third}");

        let mut off = limits(20, 0, BurstTolerance::Normal);
        off.speed_limit_enabled = false;
        l.settings_changed(&off);
        let (before, at) = (bytes.load(Ordering::Relaxed), Instant::now());
        // The pump never sleeps now, so paused time would never advance:
        // let it run a while, then stop it.
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        stop.store(true, Ordering::Relaxed);
        assert_eq!(at.elapsed(), Duration::ZERO);
        assert!(
            bytes.load(Ordering::Relaxed) - before > 5 * MIB,
            "unthrottled"
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn turning_on_starts_with_an_empty_bucket() {
        let l = SpeedLimiter::new(&TransferSettings::default());
        tokio::time::sleep(Duration::from_secs(60)).await;
        l.update(&limits(100, 0, BurstTolerance::VeryHigh));
        let start = Instant::now();
        l.acquire(Direction::Download, 10 * 1024).await;
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_chunk_waits_for_full_bucket_then_owes() {
        let l = SpeedLimiter::new(&limits(10, 0, BurstTolerance::Normal));
        let start = Instant::now();
        // 20 KiB with a 10 KiB bucket: waits 1 s for a full bucket…
        l.acquire(Direction::Download, 20 * 1024).await;
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        // …and the 10 KiB debt delays the next KiB by 1.1 s.
        l.acquire(Direction::Download, 1024).await;
        let total = start.elapsed().as_secs_f64();
        assert!((2.09..2.11).contains(&total), "{total}");
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_are_served_in_order() {
        let l = Arc::new(SpeedLimiter::new(&limits(1, 0, BurstTolerance::Normal)));
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for i in 0..5 {
            let (l, order) = (Arc::clone(&l), Arc::clone(&order));
            tasks.push(tokio::spawn(async move {
                l.acquire(Direction::Download, 1024).await;
                order.lock().unwrap().push(i);
            }));
            // Queue them in a known order.
            tokio::task::yield_now().await;
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3, 4]);
    }

    #[tokio::test(start_paused = true)]
    async fn engine_download_is_throttled_and_toggled_off() {
        use crate::{
            backend::{Backend, BackendFactory, ConnectInfo, MockServer},
            events::{self, CoreEvent, SessionId},
            local::local_to_remote,
            model::{LocalPath, Protocol, RemotePath, ServerAddress},
            queue::{NewItem, Queue, QueueServer, SharedQueue},
            settings::{Settings, TransferTypeChoice},
            transfer::{QuickResolver, TransferEngine},
        };

        struct One(MockServer);
        impl BackendFactory for One {
            fn create(
                &self,
                _: &ConnectInfo,
                _: SessionId,
                _: events::EventSender,
            ) -> Box<dyn Backend> {
                Box::new(self.0.backend())
            }
        }

        let remote = MockServer::new();
        remote.add_dir("/r");
        remote.add_file("/r/big", &vec![7u8; 3 * MIB as usize]);
        let local = MockServer::new();
        let dir = std::env::temp_dir().join("courier-ftp-t44");
        local.add_dir(local_to_remote(&dir).unwrap().as_str());

        let mut settings = Settings::default();
        settings.connection.keepalive = false;
        settings.file_types.default_type = TransferTypeChoice::Binary;
        settings.transfers = limits(100, 0, BurstTolerance::Normal);
        let limiter = Arc::new(SpeedLimiter::new(&settings.transfers));

        let queue: SharedQueue = Arc::new(Mutex::new(Queue::default()));
        let id = queue.lock().unwrap().add(
            NewItem::file(
                QueueServer::Quick {
                    address: ServerAddress::new(Protocol::Sftp, "a"),
                    password: None,
                },
                Direction::Download,
                LocalPath::new(dir.join("big")),
                RemotePath::new("/r/big"),
                Some(3 * MIB),
            ),
            time::OffsetDateTime::UNIX_EPOCH,
        );
        let (tx, mut rx) = events::channel(2);
        let (engine, handle) = TransferEngine::builder(
            Arc::clone(&queue),
            Arc::new(One(remote)),
            Arc::new(QuickResolver::new(None)),
            tx,
        )
        .settings(settings.clone())
        .local_backends(Arc::new(local))
        .rate_limiter(Arc::clone(&limiter) as Arc<dyn RateLimiter>)
        .build();
        let engine = engine.spawn();
        let finished = tokio::spawn(async move {
            let mut last = 0;
            while let Some(e) = rx.recv().await {
                match e {
                    CoreEvent::TransferProgress(p) => last = p.bytes_done,
                    CoreEvent::QueueFinished { .. } => return (Instant::now(), last),
                    _ => {}
                }
            }
            (Instant::now(), last)
        });
        let start = Instant::now();
        handle.start();

        // 100 KiB/s for 10 s ≈ 1000 KiB.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let done = match queue.lock().unwrap().get(id).map(|i| i.state.clone()) {
            Some(crate::queue::ItemState::Active { progress }) => progress.bytes,
            other => panic!("not active: {other:?}"),
        };
        assert!(within(done, 1000 * KIB, 0.05), "{done} bytes in 10 s");

        // Off: the rest (~2 MiB) goes through at once.
        settings.transfers.speed_limit_enabled = false;
        handle.settings_changed(settings);
        let (end, last) = finished.await.unwrap();
        assert_eq!(last, 3 * MIB);
        assert!(
            end - start < Duration::from_millis(10_100),
            "{:?}",
            end - start
        );
        handle.shutdown();
        engine.await.unwrap();
    }
}
