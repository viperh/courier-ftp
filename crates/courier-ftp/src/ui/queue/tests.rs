//! T56: the queue pane against an in-memory [`Queue`]: each tab as a
//! snapshot (grouping, an active transfer's progress line, paused and failed
//! items), and every control mapped to its queue operation.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use courier_ftp_core::{
    events::{CoreEvent, TransferId, TransferProgress, TransferState},
    model::{Direction, LocalPath, Protocol, RemotePath, ServerAddress},
    queue::{ItemState, NewItem, Priority, Queue, QueueList, QueueServer, SharedQueue, lock_queue},
    settings::ExistsAction,
};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use time::{OffsetDateTime, UtcOffset, macros::datetime};

use super::{QueuePane, RunState};

const RUN: RunState = RunState {
    processing: true,
    paused: false,
};
use crate::{
    action::Action,
    ui::{file_list::Effect, theme::Theme},
};

const T: OffsetDateTime = datetime!(2026-10-10 14:30:00 UTC);

fn server(user: &str, host: &str) -> QueueServer {
    let mut address = ServerAddress::new(Protocol::Sftp, host);
    address.user = Some(user.to_owned());
    QueueServer::Quick {
        address,
        password: None,
    }
}

fn item(server: &QueueServer, dir: Direction, name: &str, size: u64) -> NewItem {
    NewItem::file(
        server.clone(),
        dir,
        LocalPath::new(format!("/home/alice/site/{name}")),
        RemotePath::new(format!("/var/www/{name}")),
        Some(size),
    )
}

/// Two servers; the first item is active (40 % done), one is paused, one
/// waits for a retry, one failed and two finished.
fn sample() -> (SharedQueue, Vec<TransferId>) {
    let web = server("alice", "web01");
    let backup = server("bob", "backup.example.com");
    let mut q = Queue::new(100);
    let ids = q.add_batch(
        [
            item(&web, Direction::Upload, "index.html", 10 * 1024 * 1024),
            item(&web, Direction::Upload, "style.css", 2048),
            item(&backup, Direction::Download, "db.sql.gz", 300 * 1024 * 1024),
            item(&web, Direction::Upload, "logo.png", 50_000),
            item(&backup, Direction::Download, "notes.txt", 1200),
            item(&web, Direction::Upload, "app.js", 8000),
            item(&web, Direction::Upload, "about.html", 3000),
            item(&backup, Direction::Download, "retry.bin", 4096),
        ],
        T,
    );
    q.start(ids[0]).unwrap();
    q.set_progress(ids[0], 4 * 1024 * 1024).unwrap();
    q.pause(&[ids[1]]);
    // logo.png fails for good.
    q.start(ids[3]).unwrap();
    q.fail(ids[3], "permission denied", 1).unwrap();
    // app.js and about.html finished.
    for (id, secs) in [(ids[5], 2), (ids[6], 1)] {
        q.start(id).unwrap();
        q.finish(id, 8000, Duration::from_secs(secs), T).unwrap();
    }
    // retry.bin failed once and waits for another attempt.
    q.start(ids[7]).unwrap();
    q.fail(ids[7], "connection reset", 3).unwrap();
    (Arc::new(Mutex::new(q)), ids)
}

fn pane(queue: &SharedQueue) -> QueuePane {
    let mut p = QueuePane::new(queue.clone(), true, UtcOffset::UTC);
    p.set_offset(UtcOffset::UTC);
    p
}

/// Draw at `now`, with the engine processing.
fn render(p: &mut QueuePane, width: u16, height: u16, now: Instant) -> String {
    let mut t = Terminal::new(TestBackend::new(width, height)).unwrap();
    t.draw(|f| p.draw(f, f.area(), true, RUN, &Theme::new(None, true), now))
        .unwrap();
    t.backend().to_string()
}

/// The engine reports the active transfer: started at `t0`, 1 MiB more by
/// now, 200 KiB/s, 30 s left.
fn report(p: &mut QueuePane, id: TransferId, t0: Instant) {
    p.handle_core(
        &CoreEvent::TransferStateChanged {
            id,
            state: TransferState::Active,
        },
        t0,
    );
    p.handle_core(
        &CoreEvent::TransferProgress(TransferProgress {
            id,
            bytes_done: 5 * 1024 * 1024,
            total: Some(10 * 1024 * 1024),
            speed_bps: 200 * 1024,
            eta: Some(Duration::from_secs(30)),
        }),
        t0,
    );
}

fn edited(effect: Option<Effect>) -> (Vec<TransferId>, bool) {
    match effect {
        Some(Effect::Action(Action::QueueEdited { cancel, wake })) => (cancel, wake),
        Some(Effect::Action(other)) => panic!("unexpected action {other:?}"),
        Some(Effect::Modal(_)) => panic!("unexpected modal"),
        None => panic!("nothing changed"),
    }
}

#[test]
fn queued_tab_groups_by_server_with_progress() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    let t0 = Instant::now();
    report(&mut p, ids[0], t0);
    let text = render(&mut p, 120, 14, t0 + Duration::from_secs(5));
    insta::assert_snapshot!("queue_queued_grouped", text);
    assert!(text.contains("sftp://alice@web01 — 2 files"), "{text}");
    assert!(text.contains("[██████████"), "{text}");
    assert!(text.contains("⏸ Paused"), "{text}");
}

#[test]
fn queued_tab_ungrouped_ascii() {
    let (q, ids) = sample();
    let mut p = QueuePane::new(q.clone(), false, UtcOffset::UTC);
    p.update(&Action::QueueGroupByServer, None);
    let t0 = Instant::now();
    report(&mut p, ids[0], t0);
    let text = render(&mut p, 120, 10, t0 + Duration::from_secs(5));
    insta::assert_snapshot!("queue_queued_ascii", text);
    assert!(text.contains("[##########"), "{text}");
    assert!(!text.contains("sftp://"), "{text}");
}

#[test]
fn failed_tab() {
    let (q, _) = sample();
    let mut p = pane(&q);
    p.update(&Action::QueueTabFailed, None);
    let text = render(&mut p, 120, 8, Instant::now());
    insta::assert_snapshot!("queue_failed", text);
    assert!(text.contains("permission denied"), "{text}");
}

#[test]
fn successful_tab() {
    let (q, _) = sample();
    let mut p = pane(&q);
    p.update(&Action::QueueTabSuccessful, None);
    let text = render(&mut p, 120, 8, Instant::now());
    insta::assert_snapshot!("queue_successful", text);
    assert!(text.contains("3.9 KiB/s"), "{text}");
}

#[test]
fn collapsed_server_hides_its_items() {
    let (q, _) = sample();
    let mut p = pane(&q);
    // The cursor starts on the first header.
    p.update(&Action::Open, None);
    let text = render(&mut p, 120, 10, Instant::now());
    assert!(text.contains("▸ sftp://alice@web01"), "{text}");
    assert!(!text.contains("index.html"), "{text}");
    assert!(text.contains("db.sql.gz"), "{text}");
    p.update(&Action::Open, None);
    assert!(render(&mut p, 120, 10, Instant::now()).contains("index.html"));
}

#[test]
fn empty_tabs_say_so() {
    let q: SharedQueue = Arc::new(Mutex::new(Queue::new(10)));
    let mut p = pane(&q);
    let text = render(&mut p, 80, 6, Instant::now());
    assert!(text.contains("The queue is empty"), "{text}");
    assert!(text.contains("Queue: empty"), "{text}");
}

#[test]
fn header_totals_and_eta() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    let t0 = Instant::now();
    report(&mut p, ids[0], t0);
    let (stats, speed) = p.stats(t0 + Duration::from_secs(5));
    assert_eq!(stats.items, 5);
    assert_eq!(stats.active, 1);
    assert!(speed > 0);
    let summary = QueuePane::summary(&stats);
    assert!(summary.starts_with("Queue: 5 files, "), "{summary}");
    assert!(summary.contains("remaining"), "{summary}");
}

// ---------------------------------------------------------------- controls

/// Put the cursor on the row of `id`.
fn cursor_to(p: &mut QueuePane, id: TransferId) {
    p.update(&Action::Top, None);
    for _ in 0..20 {
        if p.selection() == vec![id] {
            return;
        }
        p.update(&Action::CursorDown, None);
    }
    panic!("{id:?} not found");
}

#[test]
fn tabs_switch_from_anywhere() {
    let (q, _) = sample();
    let mut p = pane(&q);
    assert!(QueuePane::handles_anywhere(&Action::QueueTabFailed));
    p.update(&Action::QueueTabFailed, None);
    assert_eq!(p.tab(), QueueList::Failed);
    p.update(&Action::QueueTabSuccessful, None);
    assert_eq!(p.tab(), QueueList::Successful);
    p.update(&Action::QueueTabQueued, None);
    assert_eq!(p.tab(), QueueList::Queued);
}

#[test]
fn pausing_an_active_item_cancels_it_and_resuming_wakes() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    cursor_to(&mut p, ids[0]);
    let (cancel, wake) = edited(p.update(&Action::QueueToggleItem, None));
    assert_eq!(cancel, vec![ids[0]]);
    assert!(!wake);
    assert_eq!(lock_queue(&q).get(ids[0]).unwrap().state, ItemState::Paused);
    let (cancel, wake) = edited(p.update(&Action::QueueToggleItem, None));
    assert!(cancel.is_empty() && wake);
    assert_eq!(lock_queue(&q).get(ids[0]).unwrap().state, ItemState::Queued);
}

#[test]
fn a_header_selects_all_its_items() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    p.update(&Action::Top, None);
    assert_eq!(p.selection(), vec![ids[0], ids[1]]);
    // Removing the header removes the server's items, cancelling the active one.
    let (cancel, _) = edited(p.update(&Action::RemoveItem, None));
    assert_eq!(cancel, vec![ids[0]]);
    assert_eq!(lock_queue(&q).count(QueueList::Queued), 3);
}

#[test]
fn priority_and_order() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    cursor_to(&mut p, ids[4]);
    edited(p.update(&Action::PriorityUp, None));
    edited(p.update(&Action::PriorityUp, None));
    assert_eq!(
        lock_queue(&q).get(ids[4]).unwrap().priority,
        Priority::Highest
    );
    // Already highest: nothing changes.
    assert!(p.update(&Action::PriorityUp, None).is_none());
    edited(p.update(&Action::PriorityDown, None));
    assert_eq!(lock_queue(&q).get(ids[4]).unwrap().priority, Priority::High);

    let (_, wake) = edited(p.update(&Action::MoveItemTop, None));
    assert!(wake);
    assert_eq!(lock_queue(&q).nth(QueueList::Queued, 0).unwrap().id, ids[4]);
    // The cursor stays on the moved item.
    assert_eq!(p.selection(), vec![ids[4]]);
    edited(p.update(&Action::MoveItemBottom, None));
    let last = lock_queue(&q).count(QueueList::Queued) - 1;
    assert_eq!(
        lock_queue(&q).nth(QueueList::Queued, last).unwrap().id,
        ids[4]
    );
    edited(p.update(&Action::MoveItemUp, None));
    assert_eq!(
        lock_queue(&q).nth(QueueList::Queued, last - 1).unwrap().id,
        ids[4]
    );
    edited(p.update(&Action::MoveItemDown, None));
    assert_eq!(
        lock_queue(&q).nth(QueueList::Queued, last).unwrap().id,
        ids[4]
    );
}

#[test]
fn marked_and_visual_selections() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    p.update(&Action::QueueGroupByServer, None);
    // Ungrouped rows: index, style, db, notes, retry.
    p.update(&Action::Top, None);
    p.update(&Action::ToggleSelect, None);
    p.update(&Action::CursorDown, None);
    p.update(&Action::ToggleSelect, None);
    assert_eq!(p.selection(), vec![ids[0], ids[2]]);
    p.update(&Action::SelectAll, None);
    assert_eq!(p.selection().len(), 5);
    assert!(p.handle_key(crossterm::event::KeyEvent::from(
        crossterm::event::KeyCode::Esc
    )));
    p.update(&Action::Top, None);
    p.update(&Action::VisualSelect, None);
    p.update(&Action::CursorDown, None);
    p.update(&Action::CursorDown, None);
    assert_eq!(p.selection(), vec![ids[0], ids[1], ids[2]]);
}

#[test]
fn failed_items_requeue_and_remove() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    p.update(&Action::QueueTabFailed, None);
    p.update(&Action::Top, None);
    // Grouped: header, then logo.png.
    p.update(&Action::CursorDown, None);
    assert_eq!(p.selection(), vec![ids[3]]);
    let (_, wake) = edited(p.update(&Action::Requeue, None));
    assert!(wake);
    let item = lock_queue(&q).get(ids[3]).cloned().unwrap();
    assert_eq!((item.state, item.attempts), (ItemState::Queued, 0));
    assert_eq!(lock_queue(&q).count(QueueList::Failed), 0);
    // Requeue does nothing outside the failed tab.
    p.update(&Action::QueueTabQueued, None);
    assert!(p.update(&Action::Requeue, None).is_none());
}

#[test]
fn x_clears_the_successful_tab_without_a_selection() {
    let (q, _) = sample();
    let mut p = pane(&q);
    p.update(&Action::QueueTabSuccessful, None);
    edited(p.update(&Action::RemoveItem, None));
    assert_eq!(lock_queue(&q).count(QueueList::Successful), 0);
}

#[test]
fn clearing_the_queued_tab_asks_first() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    assert!(matches!(
        p.update(&Action::QueueClear, None),
        Some(Effect::Modal(_))
    ));
    assert_eq!(lock_queue(&q).count(QueueList::Queued), 5);
    let (cancel, _) = edited(p.update(&Action::QueueRemoveAll, None));
    assert_eq!(cancel, vec![ids[0]]);
    assert_eq!(lock_queue(&q).count(QueueList::Queued), 0);
}

#[test]
fn exists_action_for_the_selection() {
    let (q, ids) = sample();
    let mut p = pane(&q);
    p.update(&Action::Top, None);
    edited(p.update(&Action::QueueSetExists(Some(ExistsAction::Skip)), None));
    for id in [ids[0], ids[1]] {
        assert_eq!(
            lock_queue(&q).get(id).unwrap().on_exists,
            Some(ExistsAction::Skip)
        );
    }
    assert!(matches!(
        p.update(&Action::QueueExistsMenu, None),
        Some(Effect::Modal(_))
    ));
}

#[test]
fn the_menu_lists_every_action_of_the_tab() {
    let (q, _) = sample();
    let mut p = pane(&q);
    let actions: Vec<Action> = p.menu_entries(false).into_iter().map(|e| e.1).collect();
    for a in [
        Action::ProcessQueue,
        Action::QueueToggleItem,
        Action::PriorityUp,
        Action::PriorityDown,
        Action::MoveItemUp,
        Action::MoveItemDown,
        Action::MoveItemTop,
        Action::MoveItemBottom,
        Action::QueueExistsMenu,
        Action::RemoveItem,
        Action::QueueClear,
        Action::ToggleTransfersPaused,
    ] {
        assert!(actions.contains(&a), "{a:?} missing");
    }
    p.update(&Action::QueueTabFailed, None);
    let actions: Vec<Action> = p.menu_entries(true).into_iter().map(|e| e.1).collect();
    assert!(actions.contains(&Action::Requeue));
    assert!(matches!(
        p.update(&Action::QueueMenu, None),
        Some(Effect::Modal(_))
    ));
}

/// 100 000 queued items render in under 5 ms per frame once the rows are
/// built. Timing is only meaningful with optimisations: run `cargo test
/// --release -p courier-ftp hundred_thousand`.
#[test]
#[cfg_attr(debug_assertions, ignore = "timing needs --release")]
fn hundred_thousand_items_render_fast() {
    let q: SharedQueue = Arc::new(Mutex::new(Queue::new(10)));
    let servers: Vec<QueueServer> = (0..10).map(|i| server("u", &format!("h{i}"))).collect();
    lock_queue(&q).add_batch(
        (0..100_000).map(|i| {
            item(
                &servers[i % 10],
                Direction::Upload,
                &format!("f{i:06}"),
                1000,
            )
        }),
        T,
    );
    let mut p = pane(&q);
    let theme = Theme::default();
    let mut t = Terminal::new(TestBackend::new(200, 60)).unwrap();
    let now = Instant::now();
    t.draw(|f| p.draw(f, f.area(), true, RUN, &theme, now))
        .unwrap();
    let frames = 50;
    let start = Instant::now();
    for _ in 0..frames {
        p.update(&Action::PageDown, None);
        t.draw(|f| p.draw(f, f.area(), true, RUN, &theme, now))
            .unwrap();
    }
    let per_frame = start.elapsed() / frames;
    assert!(per_frame.as_millis() < 5, "{per_frame:?} per frame");
}
