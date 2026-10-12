//! Segmented transfers (T41b) against mock servers with paced streams.

use pretty_assertions::assert_eq;

use super::*;
use crate::queue::ByteRange;

const MIB: usize = 1024 * 1024;

/// Segmentation from 1 MiB files, 1 MiB ranges, up to 4 connections.
fn seg_settings() -> Settings {
    let mut s = test_settings();
    s.transfers.segmented.enabled = true;
    s.transfers.segmented.min_file_size_mib = 1;
    s.transfers.segmented.min_segment_size_mib = 1;
    s.transfers.segmented.max_segments = 4;
    s
}

/// Distinct `open_read` offsets on `server`.
fn distinct_offsets(server: &MockServer) -> usize {
    let mut offsets = server.read_offsets();
    offsets.sort_unstable();
    offsets.dedup();
    offsets.len()
}

#[tokio::test(start_paused = true)]
async fn segmented_download_is_byte_identical_over_several_connections() {
    let h = harness(&["a"], seg_settings());
    h.remote("a")
        .set_stream_pace(64 * 1024, Duration::from_millis(1));
    let data = pattern(16 * MIB, 1);
    let id = h.download("a", "big", &data);
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert_eq!(stats.bytes, data.len() as u64);
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    assert_eq!(h.remote("a").peak_streams(), 4, "four segments at once");
    assert!(h.remote("a").peak_connections() <= 4);
    assert!(distinct_offsets(h.remote("a")) >= 4);
    // The target was created once, then written at offsets.
    let modes = h.local.write_modes();
    assert_eq!(modes[0], WriteMode::Truncate);
    assert!(modes[1..].iter().all(|m| matches!(m, WriteMode::At(_))));
    let item = h.item(id).unwrap();
    assert!(item.segments.is_none(), "cleared when done");
    assert!(matches!(item.state, ItemState::Done { bytes, .. } if bytes == 16 * MIB as u64));
    // Progress never goes past the size.
    let max_progress = h
        .records()
        .iter()
        .filter_map(|(_, r)| match r {
            Rec::Progress(p) if p.id == id => Some(p.bytes_done),
            _ => None,
        })
        .max();
    assert_eq!(max_progress, Some(16 * MIB as u64));
    // All connections went back to the pool.
    let status = h.handle.status();
    assert_eq!((status.active, status.slots), (0, 0));
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn segmented_upload_is_byte_identical() {
    let h = harness(&["a"], seg_settings());
    h.local.set_stream_pace(64 * 1024, Duration::from_millis(1));
    let data = pattern(8 * MIB + 12_345, 2);
    h.upload("a", "up", &data);
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert!(h.remote("a").read_file(&remote_key("up")) == Some(data));
    assert!(h.remote("a").peak_connections() > 1, "uploaded in segments");
    assert!(
        h.remote("a")
            .write_modes()
            .iter()
            .filter(|m| matches!(m, WriteMode::At(_)))
            .count()
            >= 2
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn small_files_and_disabled_setting_are_not_segmented() {
    let mut settings = seg_settings();
    settings.transfers.segmented.min_file_size_mib = 4;
    let h = harness(&["a"], settings);
    h.download("a", "small", &pattern(3 * MIB, 3));
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(h.remote("a").read_offsets(), [0]);
    h.shutdown().await;

    let mut settings = seg_settings();
    settings.transfers.segmented.enabled = false;
    let h = harness(&["a"], settings);
    h.download("a", "big", &pattern(8 * MIB, 4));
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(h.remote("a").read_offsets(), [0]);
    assert_eq!(h.local.write_modes(), [WriteMode::Truncate]);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn new_files_start_before_a_file_gets_more_segments() {
    let h = harness(&["a"], seg_settings());
    h.remote("a")
        .set_stream_pace(64 * 1024, Duration::from_millis(1));
    let files: Vec<Vec<u8>> = (0..4).map(|i| pattern(4 * MIB, 10 + i)).collect();
    for (i, data) in files.iter().enumerate() {
        h.download("a", &format!("f{i}"), data);
    }
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 4);
    // Every file started (offset 0) before any range was split off.
    let offsets = h.remote("a").read_offsets();
    assert_eq!(offsets[..4], [0, 0, 0, 0], "{offsets:?}");
    for (i, data) in files.iter().enumerate() {
        assert!(h.local.read_file(&local_key(&format!("f{i}"))).as_ref() == Some(data));
    }
    assert!(h.remote("a").peak_connections() <= 4);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn segments_respect_the_site_connection_limit() {
    let resolver = Resolver {
        limits: HashMap::from([("a".to_owned(), 2)]),
    };
    let h = harness_with(&["a"], seg_settings(), resolver, |b| b);
    h.remote("a")
        .set_stream_pace(64 * 1024, Duration::from_millis(1));
    let data = pattern(8 * MIB, 5);
    h.download("a", "big", &data);
    h.handle.start();
    h.wait_finished().await;
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    assert_eq!(h.remote("a").peak_connections(), 2);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_refused_extra_connection_lowers_the_limit_and_the_file_completes() {
    let h = harness(&["a"], seg_settings());
    h.remote("a")
        .set_max_connections(2)
        .set_stream_pace(64 * 1024, Duration::from_millis(1));
    let data = pattern(8 * MIB, 6);
    h.download("a", "big", &data);
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    assert!(
        h.records()
            .iter()
            .any(|(_, r)| matches!(r, Rec::Log(t) if t.contains("refused another connection")))
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn work_stealing_shortens_the_tail_of_a_throttled_connection() {
    let h = harness(&["a"], seg_settings());
    // The first connection crawls (1.3 MB/s), the others are fast.
    h.remote("a")
        .set_stream_pace(256 * 1024, Duration::from_millis(1))
        .pace_next_stream(64 * 1024, Duration::from_millis(50));
    let data = pattern(32 * MIB, 7);
    h.download("a", "big", &data);
    let t0 = Instant::now();
    h.handle.start();
    h.wait_finished().await;
    let elapsed = t0.elapsed();
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    // Without stealing the slow connection would keep its first range
    // (0..8 MiB, 6.4 s at its pace); with stealing it keeps < 2 MiB.
    assert!(
        elapsed < Duration::from_secs(3),
        "tail not shortened: {elapsed:?}"
    );
    assert!(
        distinct_offsets(h.remote("a")) > 4,
        "ranges were stolen: {:?}",
        h.remote("a").read_offsets()
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_failed_segment_is_retried_and_the_file_is_identical() {
    let h = harness(&["a"], seg_settings());
    h.remote("a")
        .set_stream_pace(64 * 1024, Duration::from_millis(1))
        .fail_stream_after(3 * MIB as u64 / 2, io::ErrorKind::ConnectionReset)
        .fail_stream_after(MIB as u64 / 2, io::ErrorKind::ConnectionReset);
    let data = pattern(8 * MIB, 8);
    let id = h.download("a", "big", &data);
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!((stats.files_ok, stats.files_failed), (1, 0));
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    // Retried inside the attempt, not by the engine.
    assert_eq!(h.item(id).unwrap().attempts, 0);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_stopped_segmented_transfer_resumes_only_the_missing_ranges() {
    let h = harness(&["a"], seg_settings());
    h.remote("a")
        .set_stream_pace(64 * 1024, Duration::from_millis(10));
    let total = 16 * MIB;
    let data = pattern(total, 9);
    let id = h.download("a", "big", &data);
    h.handle.start();
    until(|| h.progress_of(id) > 6 * MIB as u64).await;
    h.handle.stop();
    until(|| h.handle.status().tasks == 0).await;
    let item = h.item(id).unwrap();
    assert_eq!(item.state, ItemState::Queued);
    let missing = item.segments.clone().expect("missing ranges saved");
    let missing_bytes: u64 = missing.iter().map(ByteRange::len).sum();
    assert!(
        missing_bytes > 0 && missing_bytes < total as u64 - 4 * MIB as u64,
        "{missing:?}"
    );
    assert!(missing.len() > 1, "several ranges in progress: {missing:?}");
    // The preallocated target has the full size.
    assert_eq!(h.local.read_file(&local_key("big")).unwrap().len(), total);

    let reads_before = h.remote("a").read_offsets().len();
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert_eq!(stats.bytes, missing_bytes, "only the missing ranges moved");
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    // Every new read starts inside a missing range.
    for offset in &h.remote("a").read_offsets()[reads_before..] {
        assert!(
            missing
                .iter()
                .any(|r| r.start <= *offset && *offset < r.end),
            "read at {offset} outside {missing:?}"
        );
    }
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn saved_ranges_from_a_previous_run_are_continued_without_asking() {
    // As after a crash: the target exists at full size, the queue item
    // remembers what is missing.
    let h = harness(&["a"], seg_settings());
    let total = 8 * MIB;
    let data = pattern(total, 10);
    let mut partial = data.clone();
    let missing = vec![
        ByteRange::new(MIB as u64, 2 * MIB as u64),
        ByteRange::new(5 * MIB as u64, total as u64),
    ];
    for r in &missing {
        partial[r.start as usize..r.end as usize].fill(0);
    }
    h.local.add_file(&local_key("big"), &partial);
    let id = h.download("a", "big", &data);
    h.queue
        .lock()
        .unwrap()
        .set_segments(id, Some(missing.clone()))
        .unwrap();
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert_eq!(stats.bytes, 4 * MIB as u64);
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    assert!(
        !h.local.write_modes().contains(&WriteMode::Truncate),
        "the target was not recreated"
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn saved_ranges_that_no_longer_match_start_over() {
    let h = harness(&["a"], seg_settings());
    let data = pattern(4 * MIB, 11);
    // The local file is shorter than the source: not the preallocated
    // target the ranges belong to.
    h.local.add_file(&local_key("big"), &[1, 2, 3]);
    let id = h.download("a", "big", &data);
    h.queue
        .lock()
        .unwrap()
        .set_segments(id, Some(vec![ByteRange::new(0, 10)]))
        .unwrap();
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert_eq!(stats.bytes, 4 * MIB as u64);
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn speed_limit_holds_across_segments() {
    let mut settings = seg_settings();
    settings.transfers.speed_limit_enabled = true;
    settings.transfers.download_limit_kib = 1024;
    let limiter = Arc::new(SpeedLimiter::new(&settings.transfers));
    let h = harness_with(&["a"], settings, Resolver::default(), |b| {
        b.rate_limiter(limiter)
    });
    let data = pattern(4 * MIB, 12);
    h.download("a", "big", &data);
    let t0 = Instant::now();
    h.handle.start();
    h.wait_finished().await;
    let elapsed = t0.elapsed();
    assert!(h.local.read_file(&local_key("big")) == Some(data));
    assert!(h.remote("a").peak_streams() > 1, "segmented");
    // 4 MiB at 1 MiB/s: about 4 s whatever the number of segments (minus
    // the initial burst).
    assert!(elapsed >= Duration::from_millis(2500), "{elapsed:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn segmented_download_to_the_real_filesystem() {
    let tmp = tempfile::tempdir().unwrap();
    let remote = MockServer::new();
    let data = pattern(6 * MIB + 7, 13);
    remote.add_file("/r/big.bin", &data);
    let queue: SharedQueue = Arc::new(Mutex::new(Queue::default()));
    let (tx, _rx) = events::channel(2);
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(remote.clone()),
        Arc::new(Resolver::default()),
        tx,
    )
    .settings(seg_settings())
    .build();
    let engine = engine.spawn();
    let target = tmp.path().join("big.bin");
    let id = queue.lock().unwrap().add(
        NewItem::file(
            server("a"),
            Direction::Download,
            LocalPath::new(&target),
            RemotePath::new("/r/big.bin"),
            Some(data.len() as u64),
        ),
        OffsetDateTime::UNIX_EPOCH,
    );
    handle.start();
    let mut status = handle.watch_status();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let done = matches!(
                queue.lock().unwrap().get(id).map(|i| &i.state),
                Some(ItemState::Done { .. })
            );
            if done {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), status.changed()).await;
        }
    })
    .await
    .expect("transfer finished");
    assert!(std::fs::read(&target).unwrap() == data);
    assert!(distinct_offsets(&remote) > 1, "segmented");
    handle.shutdown();
    engine.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn connections_warm_up_in_parallel_when_the_queue_starts() {
    let h = harness(&["a"], test_settings());
    // Every operation, connecting included, takes one second.
    h.remote("a").set_latency(Duration::from_secs(1));
    for i in 0..8 {
        h.download("a", &format!("f{i}"), &pattern(1000, 20 + i));
    }
    let t0 = Instant::now();
    h.handle.start();
    until(|| h.remote("a").open_connections() == 4).await;
    // All four allowed connections were opened at once, not one by one.
    assert!(
        t0.elapsed() < Duration::from_millis(1500),
        "{:?}",
        t0.elapsed()
    );
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 8);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn small_files_reuse_warm_connections_back_to_back() {
    let mut settings = test_settings();
    settings.transfers.max_concurrent = 2;
    let h = harness(&["a"], settings);
    h.remote("a").set_latency(Duration::from_millis(5));
    for i in 0..40 {
        h.download("a", &format!("s{i}"), &pattern(4096, 40 + i));
    }
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 40);
    // Two connections carried all 40 files.
    assert_eq!(h.remote("a").connects(), 2);
    // The next file started on a connection as soon as the previous one
    // finished: no gap waiting for a scheduler tick (whose fallback is 1 s).
    let starts = h.starts();
    let longest_gap = starts
        .windows(2)
        .map(|w| w[1].0.saturating_duration_since(w[0].0))
        .max()
        .unwrap();
    assert!(longest_gap < Duration::from_millis(200), "{longest_gap:?}");
    h.shutdown().await;
}
