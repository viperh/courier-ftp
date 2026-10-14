#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pretty_assertions::assert_eq;
use secrecy::SecretString;
use time::OffsetDateTime;
use time::macros::datetime;
use tokio_util::sync::CancellationToken;

use super::persist::{DEBOUNCE, decode, encode};
use super::*;
use crate::events::TransferId;
use crate::model::item::ItemId;
use crate::model::{Direction, LocalPath, Protocol, RemotePath, ServerAddress};
use crate::settings::ExistsAction;
use crate::vault::{DeviceBlobVault, MemDeviceBlobs};

const NOW: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);
const SECRET: &str = "quick-secret-canary-7f3a";

fn site() -> ItemId {
    ItemId::from_bytes([7; 16])
}

fn quick(password: Option<&str>) -> QueueServer {
    let mut address = ServerAddress::new(Protocol::Sftp, "files.example.com");
    address.user = Some("me".into());
    QueueServer::Quick {
        address,
        password: password.map(|p| SecretString::from(p.to_owned())),
    }
}

fn file(name: &str) -> NewItem {
    NewItem::file(
        QueueServer::Site(site()),
        Direction::Download,
        LocalPath::new(format!("/tmp/{name}")),
        RemotePath::new(format!("/pub/{name}")),
        Some(100),
    )
}

fn queue_of(n: usize) -> (Queue, Vec<TransferId>) {
    let mut q = Queue::default();
    let ids = q.add_batch((0..n).map(|i| file(&format!("f{i}"))), NOW);
    (q, ids)
}

fn order(q: &Queue, list: QueueList) -> Vec<TransferId> {
    q.ids(list).collect()
}

fn ids(v: &[u64]) -> Vec<TransferId> {
    v.iter().map(|i| TransferId(*i)).collect()
}

// ------------------------------------------------------------------ add/remove

#[test]
fn add_assigns_increasing_ids_and_queues_in_order() {
    let mut q = Queue::default();
    let a = q.add(file("a"), NOW);
    let rest = q.add_batch([file("b"), file("c")], NOW);
    assert_eq!(a, TransferId(1));
    assert_eq!(rest, ids(&[2, 3]));
    assert_eq!(order(&q, QueueList::Queued), ids(&[1, 2, 3]));
    let item = q.get(a).unwrap();
    assert_eq!(item.state, ItemState::Queued);
    assert_eq!(item.attempts, 0);
    assert_eq!(item.added_at, NOW);
    assert_eq!(q.len(), 3);
    assert!(q.revision() > 0);
    assert!(!q.is_processing());
}

#[test]
fn remove_selected_reports_active_items() {
    let (mut q, i) = queue_of(4);
    q.start(i[1]).unwrap();
    let r = q.remove(&[i[1], i[2], TransferId(99)]);
    assert_eq!(r.count, 2);
    assert_eq!(r.active, vec![i[1]]);
    assert_eq!(order(&q, QueueList::Queued), vec![i[0], i[3]]);
    assert!(q.get(i[1]).is_none());
    // Nothing selected that exists: no change.
    let rev = q.revision();
    assert_eq!(q.remove(&[TransferId(99)]), Removed::default());
    assert_eq!(q.revision(), rev);
}

#[test]
fn remove_all_clears_only_the_queued_list() {
    let (mut q, i) = queue_of(3);
    q.start(i[0]).unwrap();
    q.fail(i[0], "boom", 1).unwrap();
    q.start(i[1]).unwrap();
    let r = q.remove_all();
    assert_eq!(r.count, 2);
    assert_eq!(r.active, vec![i[1]]);
    assert_eq!(q.count(QueueList::Queued), 0);
    assert_eq!(q.count(QueueList::Failed), 1);
}

#[test]
fn clear_failed_and_successful() {
    let (mut q, i) = queue_of(3);
    q.start(i[0]).unwrap();
    q.fail(i[0], "x", 1).unwrap();
    q.start(i[1]).unwrap();
    q.finish(i[1], 100, Duration::from_secs(1), NOW).unwrap();
    assert_eq!(q.clear_failed(), 1);
    assert_eq!(q.clear_failed(), 0);
    assert_eq!(q.clear_successful(), 1);
    assert_eq!(q.len(), 1);
    assert!(q.get(i[0]).is_none() && q.get(i[1]).is_none());
}

// ------------------------------------------------------------------ ordering

#[test]
fn move_up_and_down_move_blocks_by_one() {
    let (mut q, _) = queue_of(5);
    assert!(q.move_up(&ids(&[3, 4])));
    assert_eq!(order(&q, QueueList::Queued), ids(&[1, 3, 4, 2, 5]));
    assert!(!q.move_up(&ids(&[1, 3])));
    // 1 is already at the top; 3 can't pass the selected 1.
    assert_eq!(order(&q, QueueList::Queued), ids(&[1, 3, 4, 2, 5]));
    assert!(!q.move_up(&ids(&[1])));
    assert!(q.move_down(&ids(&[1, 2])));
    assert_eq!(order(&q, QueueList::Queued), ids(&[3, 1, 4, 5, 2]));
    assert!(!q.move_down(&ids(&[2])));
    assert!(!q.move_down(&[]));
}

#[test]
fn move_to_top_and_bottom_keep_relative_order() {
    let (mut q, _) = queue_of(5);
    assert!(q.move_to_top(&ids(&[4, 2])));
    assert_eq!(order(&q, QueueList::Queued), ids(&[2, 4, 1, 3, 5]));
    assert!(!q.move_to_top(&ids(&[2, 4])));
    assert!(q.move_to_bottom(&ids(&[2, 1])));
    assert_eq!(order(&q, QueueList::Queued), ids(&[4, 3, 5, 2, 1]));
    assert!(!q.move_to_bottom(&ids(&[1])));
    let rev = q.revision();
    assert!(!q.move_to_top(&ids(&[99])));
    assert_eq!(q.revision(), rev);
}

#[test]
fn scheduler_takes_highest_priority_then_queue_order() {
    let (mut q, i) = queue_of(5);
    assert_eq!(q.next_runnable(|_| true), Some(i[0]));
    assert_eq!(q.set_priority(&[i[3], i[2]], Priority::High), 2);
    assert_eq!(q.set_priority(&[i[3]], Priority::High), 0);
    assert_eq!(q.next_runnable(|_| true), Some(i[2]));
    q.set_priority(&[i[4]], Priority::Highest);
    assert_eq!(q.next_runnable(|_| true), Some(i[4]));
    // Eligibility filter (e.g. no free slot on that server).
    assert_eq!(q.next_runnable(|it| it.id != i[4]), Some(i[2]));
    // Active and paused items are skipped.
    q.start(i[4]).unwrap();
    q.pause(&[i[2]]);
    assert_eq!(q.next_runnable(|_| true), Some(i[3]));
    q.set_priority(&[i[0], i[1], i[3]], Priority::Lowest);
    assert_eq!(q.next_runnable(|_| true), Some(i[0]));
    assert_eq!(q.next_runnable(|_| false), None);
}

#[test]
fn moving_changes_scheduling_among_equal_priorities() {
    let (mut q, i) = queue_of(3);
    q.move_to_top(&[i[2]]);
    assert_eq!(q.next_runnable(|_| true), Some(i[2]));
}

// ------------------------------------------------------------------ states

#[test]
fn pause_and_resume() {
    let (mut q, i) = queue_of(3);
    q.start(i[0]).unwrap();
    let active = q.pause(&[i[0], i[1]]);
    assert_eq!(active, vec![i[0]]);
    assert_eq!(q.get(i[0]).unwrap().state, ItemState::Paused);
    assert_eq!(q.get(i[1]).unwrap().state, ItemState::Paused);
    assert_eq!(q.next_runnable(|_| true), Some(i[2]));
    assert_eq!(q.resume(&[i[0], i[2]]), 1);
    assert_eq!(q.next_runnable(|_| true), Some(i[0]));
    assert_eq!(
        q.start(i[1]),
        Err(QueueError::WrongState {
            id: i[1],
            expected: "queued"
        })
    );
}

#[test]
fn engine_lifecycle_finish_and_cap() {
    let mut q = Queue::new(2);
    let i = q.add_batch((0..4).map(|n| file(&n.to_string())), NOW);
    for id in &i[..3] {
        q.start(*id).unwrap();
        q.set_progress(*id, 50).unwrap();
        assert_eq!(q.get(*id).unwrap().remaining(), Some(50));
        q.finish(*id, 100, Duration::from_millis(5), NOW).unwrap();
    }
    // Cap 2: the oldest successful item dropped off.
    assert_eq!(order(&q, QueueList::Successful), vec![i[1], i[2]]);
    assert!(q.get(i[0]).is_none());
    assert_eq!(order(&q, QueueList::Queued), vec![i[3]]);
    assert!(matches!(
        q.get(i[2]).unwrap().state,
        ItemState::Done { bytes: 100, .. }
    ));
    q.set_max_successful(1);
    assert_eq!(order(&q, QueueList::Successful), vec![i[2]]);
    assert_eq!(
        q.finish(i[3], 1, Duration::ZERO, NOW),
        Err(QueueError::WrongState {
            id: i[3],
            expected: "active"
        })
    );
    assert_eq!(
        q.set_progress(TransferId(99), 1),
        Err(QueueError::UnknownItem(TransferId(99)))
    );
    q.start(i[3]).unwrap();
    q.stop(i[3]).unwrap();
    assert_eq!(q.get(i[3]).unwrap().state, ItemState::Queued);
}

#[test]
fn fail_retries_then_moves_to_failed_and_requeue_resets() {
    let (mut q, i) = queue_of(3);
    q.start(i[1]).unwrap();
    assert_eq!(q.fail(i[1], "timeout", 2).unwrap(), FailOutcome::Requeued);
    // Retried in place.
    assert_eq!(order(&q, QueueList::Queued), i);
    assert_eq!(q.get(i[1]).unwrap().attempts, 1);
    q.start(i[1]).unwrap();
    assert_eq!(q.fail(i[1], "timeout", 2).unwrap(), FailOutcome::Failed);
    assert_eq!(order(&q, QueueList::Failed), vec![i[1]]);
    assert_eq!(
        q.get(i[1]).unwrap().state,
        ItemState::Failed {
            error: "timeout".into()
        }
    );
    q.start(i[0]).unwrap();
    q.fail(i[0], "denied", 1).unwrap();
    assert_eq!(order(&q, QueueList::Failed), vec![i[1], i[0]]);

    // Reset and requeue selected: back at the end, attempts reset.
    assert_eq!(q.requeue_failed(&[i[0]]), 1);
    assert_eq!(order(&q, QueueList::Queued), vec![i[2], i[0]]);
    assert_eq!(q.get(i[0]).unwrap().attempts, 0);
    assert_eq!(q.get(i[0]).unwrap().state, ItemState::Queued);
    assert_eq!(q.requeue_all_failed(), 1);
    assert_eq!(order(&q, QueueList::Queued), vec![i[2], i[0], i[1]]);
    assert_eq!(q.count(QueueList::Failed), 0);
}

#[test]
fn per_item_overrides() {
    let (mut q, i) = queue_of(1);
    q.set_on_exists(i[0], Some(ExistsAction::Overwrite))
        .unwrap();
    q.set_size(i[0], Some(5)).unwrap();
    let item = q.get(i[0]).unwrap();
    assert_eq!(item.on_exists, Some(ExistsAction::Overwrite));
    assert_eq!(item.size, Some(5));
    assert!(q.set_size(TransferId(9), None).is_err());
}

#[test]
fn placeholder_expands_in_place() {
    let mut q = Queue::default();
    let a = q.add(file("a"), NOW);
    let mut dir = file("dir");
    dir.is_dir_placeholder = true;
    let d = q.add(dir, NOW);
    let b = q.add(file("b"), NOW);
    let kids = q
        .expand_placeholder(d, [file("dir/x"), file("dir/y")], NOW)
        .unwrap();
    assert_eq!(order(&q, QueueList::Queued), vec![a, kids[0], kids[1], b]);
    assert!(q.get(d).is_none());
    assert!(q.expand_placeholder(a, [], NOW).is_err());
}

// ------------------------------------------------------------------ views

#[test]
fn groups_and_rows_by_server() {
    let mut q = Queue::default();
    let a = q.add(file("a"), NOW);
    let mut qi = file("q");
    qi.server = quick(Some(SECRET));
    let b = q.add(qi, NOW);
    let c = q.add(file("c"), NOW);
    let groups = q.groups(QueueList::Queued);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].key, ServerKey::Site(site()));
    assert_eq!(groups[0].ids, vec![a, c]);
    assert_eq!(groups[0].bytes, 200);
    assert_eq!(groups[1].ids, vec![b]);

    let flat = q.rows(QueueList::Queued, false);
    assert_eq!(flat.len(), 3);
    let grouped = q.rows(QueueList::Queued, true);
    let shape: Vec<String> = grouped
        .iter()
        .map(|r| match r {
            QueueRow::Server(h) => format!("server:{}", h.items),
            QueueRow::Item(i) => format!("item:{}", i.id.0),
        })
        .collect();
    assert_eq!(
        shape,
        ["server:2", "item:1", "item:3", "server:1", "item:2"]
    );
}

#[test]
fn stats_and_eta() {
    let (mut q, i) = queue_of(3);
    let mut unknown = file("u");
    unknown.size = None;
    q.add(unknown, NOW);
    q.start(i[0]).unwrap();
    q.set_progress(i[0], 40).unwrap();
    q.pause(&[i[1]]);
    let s = q.stats(Some(10.0));
    assert_eq!(s.items, 4);
    assert_eq!(s.active, 1);
    assert_eq!(s.paused, 1);
    assert_eq!(s.unknown_size, 1);
    assert_eq!(s.bytes, 60 + 100 + 100);
    assert_eq!(s.eta, Some(Duration::from_secs(26)));
    assert_eq!(q.stats(None).eta, None);
    assert_eq!(q.stats(Some(0.0)).eta, None);
}

#[test]
fn speed_meter_averages_over_window() {
    let t0 = Instant::now();
    let mut m = SpeedMeter::new(Duration::from_secs(10));
    assert_eq!(m.bytes_per_sec(t0), None);
    m.record(1000, t0);
    m.record(1000, t0 + Duration::from_secs(2));
    assert_eq!(m.bytes_per_sec(t0 + Duration::from_secs(4)), Some(500.0));
    // The first sample leaves the window.
    let r = m.bytes_per_sec(t0 + Duration::from_secs(11)).unwrap();
    assert!((r - 1000.0 / 9.0).abs() < 1e-9, "{r}");
    assert_eq!(m.bytes_per_sec(t0 + Duration::from_secs(60)), None);
}

// ------------------------------------------------------------------ export

#[test]
fn export_contains_no_secrets_and_imports_back() {
    let mut q = Queue::default();
    let mut qi = file("q");
    qi.server = quick(Some(SECRET));
    qi.priority = Priority::High;
    q.add(qi, NOW);
    q.add(file("s"), NOW);
    let mut gone = file("gone");
    gone.server = QueueServer::Site(ItemId::from_bytes([9; 16]));
    let g = q.add(gone, NOW);
    q.start(g).unwrap();
    q.fail(g, "x", 1).unwrap();
    // Successful items are not exported.
    let d = q.add(file("done"), NOW);
    q.start(d).unwrap();
    q.finish(d, 1, Duration::ZERO, NOW).unwrap();

    let json = q.export_json();
    assert!(!json.contains(SECRET), "{json}");
    assert!(!json.contains("password"), "{json}");
    assert!(json.contains("courier-ftp-queue"));

    let report = import_json(&json, |id| id == site()).unwrap();
    assert_eq!(report.missing_sites, 1);
    assert_eq!(report.ask_password, 1);
    assert_eq!(report.items.len(), 2);
    assert!(report.items[0].server.needs_password());
    assert_eq!(report.items[0].priority, Priority::High);
    assert_eq!(report.items[1].server, QueueServer::Site(site()));
    let mut q2 = Queue::default();
    q2.add_batch(report.items, NOW);
    assert_eq!(q2.count(QueueList::Queued), 2);
}

#[test]
fn import_rejects_foreign_and_newer_files() {
    assert!(matches!(
        import_json("not json", |_| true),
        Err(ExportError::Invalid(_))
    ));
    assert!(matches!(
        import_json(r#"{"format":"other","version":1,"items":[]}"#, |_| true),
        Err(ExportError::Invalid(_))
    ));
    assert_eq!(
        import_json(
            r#"{"format":"courier-ftp-queue","version":9,"items":[]}"#,
            |_| true
        ),
        Err(ExportError::NewerVersion(9))
    );
}

// ------------------------------------------------------------------ persistence

fn sample_queue() -> Queue {
    let mut q = Queue::new(10);
    let mut qi = file("q");
    qi.server = quick(Some(SECRET));
    qi.on_exists = Some(ExistsAction::Resume);
    let i = q.add_batch([file("a"), qi, file("c"), file("d"), file("e")], NOW);
    q.start(i[0]).unwrap();
    q.set_progress(i[0], 10).unwrap();
    q.pause(&[i[2]]);
    q.start(i[3]).unwrap();
    q.fail(i[3], "denied", 1).unwrap();
    q.start(i[4]).unwrap();
    q.finish(i[4], 100, Duration::from_millis(1500), NOW)
        .unwrap();
    q.set_priority(&[i[1]], Priority::Lowest);
    q.set_processing(true);
    q
}

#[test]
fn encode_decode_round_trip_active_becomes_queued() {
    let q = sample_queue();
    let bytes = encode(&q).unwrap();
    let back = decode(&bytes, 10).unwrap();
    assert!(!back.is_processing());
    for list in [QueueList::Queued, QueueList::Failed, QueueList::Successful] {
        assert_eq!(order(&back, list), order(&q, list), "{list:?}");
    }
    for item in q.items(QueueList::Queued).chain(q.items(QueueList::Failed)) {
        let mut want = item.clone();
        if want.state.is_active() {
            want.state = ItemState::Queued;
        }
        assert_eq!(back.get(item.id), Some(&want));
    }
    assert_eq!(back.get(TransferId(1)).unwrap().state, ItemState::Queued);
    assert_eq!(
        back.get(TransferId(5)).unwrap().state,
        q.get(TransferId(5)).unwrap().state
    );
    // New ids continue after the restored ones.
    let mut back = back;
    assert_eq!(back.add(file("z"), NOW), TransferId(6));
}

#[test]
fn decode_rejects_garbage_and_newer_formats() {
    assert!(matches!(
        decode(b"\xff\x00", 10),
        Err(PersistError::Decode(_))
    ));
    let mut newer = Vec::new();
    ciborium::into_writer(&serde_json::json!({"v": 99, "items": []}), &mut newer).unwrap();
    assert_eq!(
        decode(&newer, 10).err(),
        Some(PersistError::NewerFormat(99))
    );
}

fn persister(vault: &Arc<MemDeviceBlobs>, queue: Queue, debounce: Duration) -> Arc<QueuePersister> {
    QueuePersister::with_debounce(
        Arc::new(Mutex::new(queue)),
        Arc::clone(vault) as Arc<dyn DeviceBlobVault>,
        true,
        debounce,
    )
}

#[tokio::test]
async fn persisted_queue_survives_restart() {
    let vault = Arc::new(MemDeviceBlobs::unlocked());
    let p = persister(&vault, sample_queue(), DEBOUNCE);
    assert_eq!(p.restore().await.unwrap(), 0);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Saved);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Unchanged);

    // "Restart": a new queue and persister over the same vault.
    let p2 = persister(&vault, Queue::new(10), DEBOUNCE);
    assert_eq!(p2.restore().await.unwrap(), 5);
    {
        let q = lock_queue(p2.queue());
        assert!(!q.is_processing());
        assert_eq!(q.get(TransferId(1)).unwrap().state, ItemState::Queued);
        assert_eq!(q.get(TransferId(3)).unwrap().state, ItemState::Paused);
        assert_eq!(q.get(TransferId(2)).unwrap().server, quick(Some(SECRET)));
        assert_eq!(q.count(QueueList::Failed), 1);
        assert_eq!(q.count(QueueList::Successful), 1);
    }
    // Restored as saved: nothing to write; restore is one-shot.
    assert_eq!(p2.save_now().await.unwrap(), SaveOutcome::Unchanged);
    assert_eq!(p2.restore().await.unwrap(), 0);
}

#[tokio::test]
async fn locked_vault_persists_nothing_and_warns() {
    let vault = Arc::new(MemDeviceBlobs::unlocked());
    // An earlier session saved one item.
    let earlier = persister(&vault, Queue::default(), DEBOUNCE);
    earlier.restore().await.unwrap();
    lock_queue(earlier.queue()).add(file("old"), NOW);
    earlier.save_now().await.unwrap();
    let saved = vault.raw(QUEUE_BLOB).unwrap();

    // This session starts with the vault locked (skipped).
    vault.set_unlocked(false);
    let p = persister(&vault, Queue::default(), DEBOUNCE);
    assert!(matches!(
        p.restore().await,
        Err(PersistError::Vault(crate::vault::VaultError::Locked))
    ));
    assert_eq!(p.quit_check().await, QuitCheck::Safe);
    lock_queue(p.queue()).add(file("new"), NOW);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Locked);
    assert_eq!(
        p.quit_check().await,
        QuitCheck::WouldLose {
            items: 1,
            reason: LossReason::VaultLocked
        }
    );

    // Unlocked later, but not restored yet: the old queue isn't overwritten.
    vault.set_unlocked(true);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::NotRestored);
    assert_eq!(vault.raw(QUEUE_BLOB).unwrap(), saved);
    // Restore merges the saved item after the current one.
    assert_eq!(p.restore().await.unwrap(), 1);
    {
        let q = lock_queue(p.queue());
        let names: Vec<String> = q
            .items(QueueList::Queued)
            .map(|i| i.remote.to_string())
            .collect();
        assert_eq!(names, ["/pub/new", "/pub/old"]);
    }
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Saved);
    assert_eq!(p.quit_check().await, QuitCheck::Safe);
}

#[tokio::test]
async fn disabling_persistence_deletes_the_blob() {
    let vault = Arc::new(MemDeviceBlobs::unlocked());
    let p = persister(&vault, Queue::default(), DEBOUNCE);
    p.restore().await.unwrap();
    lock_queue(p.queue()).add(file("a"), NOW);
    p.save_now().await.unwrap();
    p.set_enabled(false).await.unwrap();
    assert!(vault.raw(QUEUE_BLOB).is_none());
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Disabled);
    assert_eq!(
        p.quit_check().await,
        QuitCheck::WouldLose {
            items: 1,
            reason: LossReason::Disabled
        }
    );
    p.set_enabled(true).await.unwrap();
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Saved);
}

#[tokio::test(start_paused = true)]
async fn writes_are_debounced_and_flushed_on_quit() {
    let vault = Arc::new(MemDeviceBlobs::unlocked());
    let p = persister(&vault, Queue::default(), DEBOUNCE);
    p.restore().await.unwrap();
    let cancel = CancellationToken::new();
    let task = p.spawn(cancel.clone());

    for n in 0..5 {
        lock_queue(p.queue()).add(file(&n.to_string()), NOW);
        p.changed();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // 1.5 s after the first change: not written yet.
    assert_eq!(vault.saves(), 0);
    tokio::time::sleep(Duration::from_millis(600)).await;
    // ≤ 2 s after the first change: one write for all five.
    assert_eq!(vault.saves(), 1);
    assert_eq!(
        decode(&vault.raw(QUEUE_BLOB).unwrap(), 10).unwrap().len(),
        5
    );

    // A change right before quitting is written by the final flush.
    lock_queue(p.queue()).add(file("last"), NOW);
    p.changed();
    cancel.cancel();
    task.await.unwrap();
    assert_eq!(vault.saves(), 2);
    assert_eq!(
        decode(&vault.raw(QUEUE_BLOB).unwrap(), 10).unwrap().len(),
        6
    );
}

// ------------------------------------------------------------------ benchmark

/// 100 000 items: add, reorder and render-model generation each < 50 ms.
/// Release-only gate (debug builds are much slower); run by `bench.yml`:
/// `cargo test --release -p courier-ftp-core --lib queue_100k_items_gate -- --ignored`.
#[test]
#[ignore = "timing gate; run in release"]
fn queue_100k_items_gate() {
    const N: usize = 100_000;
    const LIMIT: Duration = Duration::from_millis(50);
    let items: Vec<NewItem> = (0..N).map(|i| file(&i.to_string())).collect();
    let mut q = Queue::new(1000);

    let t = Instant::now();
    let ids = q.add_batch(items, NOW);
    let add = t.elapsed();

    let sel: Vec<TransferId> = ids.iter().step_by(10).copied().collect();
    let t = Instant::now();
    q.move_up(&sel);
    q.move_down(&sel);
    q.move_to_top(&sel);
    q.move_to_bottom(&sel);
    let reorder = t.elapsed() / 4;

    let t = Instant::now();
    let flat = q.rows(QueueList::Queued, false).len();
    let flat_time = t.elapsed();
    let t = Instant::now();
    let grouped = q.rows(QueueList::Queued, true).len();
    let grouped_time = t.elapsed();
    let t = Instant::now();
    let stats = q.stats(Some(1.0));
    let stats_time = t.elapsed();

    assert_eq!(flat, N);
    assert_eq!(grouped, N + 1);
    assert_eq!(stats.items, N);
    for (what, took) in [
        ("add", add),
        ("reorder", reorder),
        ("rows", flat_time),
        ("grouped rows", grouped_time),
        ("stats", stats_time),
    ] {
        assert!(took < LIMIT, "{what} took {took:?}");
    }
}
