//! T88 against an in-process `courier-ftp-server` (in-memory store): two and
//! three devices syncing sites through the engine — both ways, conflicts
//! merged field by field (T81), offline edits converging, live updates over
//! the WebSocket, `410 gone` resyncs, too-large items and network cuts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::proxy::{Mode, Proxy};
use common::{Device, PW, PW2, Server, secret};
use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{HistoryEntry, ItemId, Site};
use courier_ftp_core::sites::SiteManager;
use courier_ftp_core::vault::local_acting::KEY_PATH_FIELD;
use courier_ftp_core::vault::{ItemVault, ItemVaultExt};
use courier_ftp_sync::engine::{EngineConfig, SyncEngine, SyncPolicy};
use courier_ftp_sync::status::{SyncEvent, SyncStatus};
use courier_ftp_sync::ws::BackoffPolicy;
use courier_ftp_sync::{SyncSession, account};
use pretty_assertions::assert_eq;
use tokio::sync::mpsc;

const EMAIL: &str = "alice@example.com";

fn mt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// Fast timers for tests (the defaults are 2 s / 300 s / 1–300 s).
fn fast() -> EngineConfig {
    let quick = BackoffPolicy {
        initial: Duration::from_millis(50),
        max: Duration::from_millis(500),
    };
    EngineConfig {
        push_debounce: Duration::from_millis(50),
        retry: quick,
        ws_backoff: quick,
        ..EngineConfig::default()
    }
}

/// A manual engine (no WS, no timers) with an event receiver.
fn manual(session: &SyncSession) -> (SyncEngine, mpsc::UnboundedReceiver<SyncEvent>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut cfg = fast();
    cfg.websocket = false;
    (session.engine(cfg, Some(tx)), rx)
}

fn drain(rx: &mut mpsc::UnboundedReceiver<SyncEvent>) -> Vec<SyncEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// A registers (with `sites`), B logs in on a fresh device.
async fn pair(server: &Server, url: &str) -> (Device, SyncSession, Device, SyncSession) {
    let a = Device::new("laptop", PW).await;
    let mut prepared = account::prepare_registration(&a.vault, url, EMAIL, &secret(PW), &a.cfg)
        .await
        .unwrap();
    common::confirm(&mut prepared);
    let (_, sa) = account::finish_registration(&a.vault, &prepared, None, &a.cfg)
        .await
        .unwrap();
    let b = Device::new("desktop", PW).await;
    let req = account::LoginRequest {
        server_url: url.to_owned(),
        email: EMAIL.into(),
        password: secret(PW),
        totp: None,
    };
    let (_, sb) = account::start_login(&b.vault, &req, &b.cfg)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let _ = server;
    (a, sa, b, sb)
}

async fn wait_until<F, Fut>(what: &str, limit: Duration, mut f: F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    loop {
        if f().await {
            return start.elapsed();
        }
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
fn sites_sync_both_ways_through_the_site_manager() {
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        let (mut ea, _) = manual(&sa);
        let (mut eb, mut rb) = manual(&sb);
        let id = a.add_site("db", "db.example.com", "root").await;
        assert_eq!(ea.sync_once().await, SyncStatus::Synced);
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 0);
        assert_eq!(eb.sync_once().await, SyncStatus::Synced);
        assert_eq!(b.sites().await, a.sites().await);
        assert!(
            drain(&mut rb)
                .iter()
                .any(|e| matches!(e, SyncEvent::Applied { items, .. } if items.contains(&id)))
        );

        // B edits through the Site Manager (T31); A's manager sees it after
        // a sync and a reload.
        let store_a = std::sync::Arc::new(a.store.clone());
        let mut mgr_a = SiteManager::load(std::sync::Arc::new(a.vault.clone()), store_a)
            .await
            .unwrap();
        assert_eq!(mgr_a.tree().site(id).unwrap().host, "db.example.com");
        b.edit_site(id, |s| s.host = "db2.example.com".into()).await;
        assert_eq!(eb.sync_once().await, SyncStatus::Synced);
        assert_eq!(ea.sync_once().await, SyncStatus::Synced);
        mgr_a.reload().await.unwrap();
        assert_eq!(mgr_a.tree().site(id).unwrap().host, "db2.example.com");

        // A synced value that acts locally (a key file path) changed
        // remotely: the approval is revoked and the UI told.
        b.edit_site(id, |s| s.key_path = Some("/home/me/.ssh/id_ed25519".into()))
            .await;
        a.store
            .approvals()
            .put(id, KEY_PATH_FIELD, [7; 32])
            .await
            .unwrap();
        let (mut ea2, mut ra) = manual(&sa);
        eb.sync_once().await;
        ea2.sync_once().await;
        assert!(drain(&mut ra).iter().any(|e| matches!(
            e,
            SyncEvent::ApprovalNeeded { item, field } if *item == id && *field == KEY_PATH_FIELD
        )));
        assert!(
            a.store
                .approvals()
                .get(id, KEY_PATH_FIELD)
                .await
                .unwrap()
                .is_none()
        );

        // Deletes sync too.
        a.vault.delete(id).await.unwrap();
        ea.sync_once().await;
        eb.sync_once().await;
        assert!(b.site(id).await.is_none());
        assert!(b.sites().await.is_empty());
    });
}

#[test]
fn offline_edits_of_different_fields_converge_and_same_field_newest_wins() {
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        let (mut ea, _) = manual(&sa);
        let (mut eb, _) = manual(&sb);
        let id = a.add_site("db", "db.example.com", "root").await;
        ea.sync_once().await;
        eb.sync_once().await;

        // Both offline: different fields, and the same field (B's later).
        a.edit_site(id, |s| s.host = "a-host".into()).await;
        a.edit_site(id, |s| s.comments = "from A".into()).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        b.edit_site(id, |s| s.user = "b-user".into()).await;
        b.edit_site(id, |s| s.comments = "from B".into()).await;

        assert_eq!(ea.sync_once().await, SyncStatus::Synced);
        assert_eq!(eb.sync_once().await, SyncStatus::Synced); // conflict → merge → push
        assert_eq!(ea.sync_once().await, SyncStatus::Synced);
        let sa_site = a.site(id).await.unwrap();
        let sb_site = b.site(id).await.unwrap();
        for s in [&sa_site, &sb_site] {
            assert_eq!(s.host, "a-host");
            assert_eq!(s.user, "b-user");
            assert_eq!(s.comments, "from B", "newest HLC wins on both devices");
        }
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 0);
        assert_eq!(b.store.outbox().pending_count().await.unwrap(), 0);
    });
}

#[test]
fn delete_versus_edit_newer_action_wins_and_resurrection_is_toasted() {
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        let (mut ea, mut ra) = manual(&sa);
        let (mut eb, _) = manual(&sb);
        let x = a.add_site("x", "x.example.com", "root").await;
        let y = a.add_site("y", "y.example.com", "root").await;
        ea.sync_once().await;
        eb.sync_once().await;

        // x: A deletes, then B edits (newer) → restored everywhere, toast on A.
        a.vault.delete(x).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        b.edit_site(x, |s| s.comments = "still needed".into()).await;
        // y: B edits, then A deletes (newer) → deleted everywhere.
        b.edit_site(y, |s| s.comments = "edit".into()).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        a.vault.delete(y).await.unwrap();

        eb.sync_once().await;
        ea.sync_once().await;
        eb.sync_once().await;
        assert_eq!(a.site(x).await.unwrap().comments, "still needed");
        assert_eq!(b.site(x).await.unwrap().comments, "still needed");
        assert!(a.site(y).await.is_none());
        assert!(b.site(y).await.is_none());
        let toasts: Vec<String> = drain(&mut ra)
            .into_iter()
            .filter_map(|e| match e {
                SyncEvent::Toast { message, .. } => Some(message),
                _ => None,
            })
            .collect();
        assert!(
            toasts.iter().any(|t| t.contains("‘x’ was restored")),
            "{toasts:?}"
        );
    });
}

#[test]
fn killing_the_network_mid_push_loses_nothing() {
    mt().block_on(async {
        let server = Server::start().await;
        let proxy = Proxy::start(&server.url).await;
        let (a, sa, b, sb) = pair(&server, &proxy.url).await;
        let (mut ea, _) = manual(&sa);
        let (mut eb, _) = manual(&sb);

        // The response is lost after the server committed.
        let id = a.add_site("db", "db.example.com", "root").await;
        proxy.set(Mode::DropPushResponses);
        assert!(matches!(
            ea.sync_once().await,
            SyncStatus::Offline { pending: 1 }
        ));
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 1);
        let personal = sa.vault().personal_vault().await.unwrap();
        let row = &a.store.outbox().list(personal).await.unwrap()[0];
        assert!(row.attempts >= 1, "the failed push was counted");
        // Every request fails now.
        proxy.set(Mode::DropResponses);
        assert!(matches!(
            ea.sync_once().await,
            SyncStatus::Offline { pending: 1 }
        ));

        // Fully down: offline edits queue up.
        proxy.set(Mode::Down);
        a.edit_site(id, |s| s.user = "admin".into()).await;
        a.add_site("web", "web.example.com", "deploy").await;
        assert_eq!(ea.sync_once().await, SyncStatus::Offline { pending: 2 });

        // Back up: the push resumes; the lost-response item merges cleanly.
        proxy.set(Mode::Up);
        assert_eq!(ea.sync_once().await, SyncStatus::Synced);
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 0);
        assert_eq!(eb.sync_once().await, SyncStatus::Synced);
        assert_eq!(b.sites().await, a.sites().await);
        assert_eq!(b.site(id).await.unwrap().user, "admin");
    });
}

#[test]
fn gone_triggers_a_resync_that_keeps_dirty_items() {
    use courier_ftp_server::sync::gc;
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        let (mut ea, _) = manual(&sa);
        let (mut eb, _) = manual(&sb);
        let keep = a.add_site("keep", "keep.example.com", "root").await;
        let gone = a.add_site("gone", "gone.example.com", "root").await;
        ea.sync_once().await;
        eb.sync_once().await;

        // B goes offline with an edit; A deletes `gone` and the server's GC
        // purges the tombstone above B's cursor.
        b.edit_site(keep, |s| s.comments = "offline edit".into())
            .await;
        a.vault.delete(gone).await.unwrap();
        ea.sync_once().await;
        {
            use courier_ftp_server::auth::Clock as _;
            let later = server.clock.now() + chrono::TimeDelta::days(91);
            let out = server
                .state
                .sync()
                .store()
                .gc_tombstones(gc::cutoff(later, 90))
                .await
                .unwrap();
            assert_eq!(out.purged_tombstones, 1);
        }

        // B: 410 → full resync: `gone` (clean, purged on the server) is
        // removed, the dirty `keep` survives and is pushed.
        assert_eq!(eb.sync_once().await, SyncStatus::Synced);
        assert!(b.site(gone).await.is_none());
        assert!(b.store.items().get(gone).await.unwrap().is_none());
        assert_eq!(b.site(keep).await.unwrap().comments, "offline edit");
        assert_eq!(b.store.outbox().pending_count().await.unwrap(), 0);
        ea.sync_once().await;
        assert_eq!(a.site(keep).await.unwrap().comments, "offline edit");
    });
}

#[test]
fn too_large_items_are_held_back_with_an_error() {
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = fast();
        cfg.websocket = false;
        let handle = sa.start_engine(cfg, Some(tx));
        let (mut eb, _) = manual(&sb);
        wait_until("first cycle", Duration::from_secs(10), || async {
            handle.status() == SyncStatus::Synced
        })
        .await;

        // ~2 MiB of incompressible text.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let big: String = (0..2 * 1024 * 1024)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                char::from(b'!' + u8::try_from(seed % 90).unwrap())
            })
            .collect();
        let mut site = Site::new("huge", Protocol::Sftp, "huge.example.com");
        site.comments = big;
        let huge = ItemId::new();
        a.vault.put_view(huge, None, site).await.unwrap();
        let small = a.add_site("small", "small.example.com", "root").await;
        handle.local_change();
        wait_until("the small item pushed", Duration::from_secs(10), || async {
            matches!(handle.status(), SyncStatus::Error(_))
                && a.store.outbox().pending_count().await.unwrap() == 1
        })
        .await;
        let SyncStatus::Error(msg) = handle.status() else {
            unreachable!()
        };
        assert!(msg.contains("too large"), "{msg}");
        assert!(handle.item_errors().contains_key(&huge));
        let events: Vec<SyncEvent> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SyncEvent::ItemError { item, .. } if *item == huge))
        );
        eb.sync_once().await;
        assert!(b.site(small).await.is_some());
        assert!(b.site(huge).await.is_none());
        // The local change is kept.
        assert!(a.site(huge).await.is_some());
        handle.shutdown().await;
    });
}

#[test]
fn history_syncs_only_when_enabled() {
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        let (mut ea, _) = manual(&sa);
        let (mut eb, _) = manual(&sb);
        let h = ItemId::new();
        a.vault
            .put_view(h, None, HistoryEntry::new(Protocol::Sftp, "h.example.com"))
            .await
            .unwrap();
        ea.sync_once().await;
        eb.sync_once().await;
        assert!(b.vault.get(h).await.unwrap().is_none());
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 0);
        // Still dirty: enabling history later pushes it once it is queued again.
        a.vault
            .put_view(
                h,
                None,
                HistoryEntry {
                    port: Some(2222),
                    ..HistoryEntry::new(Protocol::Sftp, "h.example.com")
                },
            )
            .await
            .unwrap();
        let mut cfg = fast();
        cfg.websocket = false;
        cfg.policy = SyncPolicy { history: true };
        let mut ea = sa.engine(cfg, None);
        ea.sync_once().await;
        eb.sync_once().await;
        assert!(b.vault.get(h).await.unwrap().is_some());
    });
}

#[test]
fn live_updates_over_the_websocket() {
    mt().block_on(async {
        let server = Server::start().await;
        let (a, sa, b, sb) = pair(&server, &server.url).await;
        // Default timers (2 s debounce): a change shows on B within 3 s.
        let ha = sa.start_engine(EngineConfig::default(), None);
        let hb = sb.start_engine(EngineConfig::default(), None);
        for h in [&ha, &hb] {
            wait_until("first cycle", Duration::from_secs(10), || async {
                h.status() == SyncStatus::Synced
            })
            .await;
        }
        // Let both sockets authenticate.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let id = a.add_site("live", "live.example.com", "root").await;
        let took = wait_until("the site on B", Duration::from_secs(3), || async {
            b.site(id).await.is_some()
        })
        .await;
        assert!(took < Duration::from_secs(3), "{took:?}");

        // Once A's push is accepted, B applies it in well under a second.
        a.edit_site(id, |s| s.comments = "now".into()).await;
        ha.sync_now().await.unwrap();
        let took = wait_until("the edit on B", Duration::from_secs(1), || async {
            b.site(id).await.is_some_and(|s| s.comments == "now")
        })
        .await;
        assert!(took < Duration::from_secs(1), "{took:?}");

        // A password change on A: B's engine learns over the socket that it
        // must sign in again.
        sa.change_password(&secret(PW), &secret(PW2), None)
            .await
            .unwrap();
        wait_until("B needs login", Duration::from_secs(5), || async {
            hb.status() == SyncStatus::NeedsLogin
        })
        .await;
        ha.shutdown().await;
        hb.shutdown().await;
    });
}

/// Random edit sequences on three devices converge to identical state.
mod convergence {
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    use super::*;

    #[derive(Debug, Clone)]
    enum Op {
        Create(usize),
        Edit(usize, usize, u8, u8),
        Delete(usize, usize),
        Sync(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..3usize).prop_map(Op::Create),
            (0..3usize, 0..8usize, 0..4u8, 0..20u8).prop_map(|(d, i, f, v)| Op::Edit(d, i, f, v)),
            (0..3usize, 0..8usize).prop_map(|(d, i)| Op::Delete(d, i)),
            (0..3usize).prop_map(Op::Sync),
        ]
    }

    async fn snapshot(d: &Device) -> Vec<(ItemId, String, String, String, String)> {
        let mut v: Vec<_> = d
            .vault
            .list_views::<Site>()
            .await
            .unwrap()
            .into_iter()
            .map(|(i, s)| (i.id, s.name, s.host, s.user, s.comments))
            .collect();
        v.sort();
        v
    }

    fn run(ops: Vec<Op>) {
        mt().block_on(async {
            let server = Server::start().await;
            let (a, sa, b, sb) = pair(&server, &server.url).await;
            let c = Device::new("tablet", PW).await;
            let sc = c.login(&server, EMAIL, PW).await;
            let devices = [&a, &b, &c];
            let mut engines = [manual(&sa).0, manual(&sb).0, manual(&sc).0];
            let mut ids: Vec<ItemId> = Vec::new();
            for op in ops {
                match op {
                    Op::Create(d) => {
                        let n = ids.len();
                        ids.push(
                            devices[d]
                                .add_site(&format!("s{n}"), &format!("h{n}"), "u")
                                .await,
                        );
                    }
                    Op::Edit(d, i, f, v) => {
                        let Some(&id) = ids.get(i % ids.len().max(1)) else {
                            continue;
                        };
                        if devices[d].site(id).await.is_none() {
                            continue;
                        }
                        let val = format!("v{v}");
                        devices[d]
                            .edit_site(id, move |s| match f {
                                0 => s.name = format!("{val}-{id}"),
                                1 => s.host = val,
                                2 => s.user = val,
                                _ => s.comments = val,
                            })
                            .await;
                    }
                    Op::Delete(d, i) => {
                        if let Some(&id) = ids.get(i % ids.len().max(1)) {
                            let _ = devices[d].vault.delete(id).await;
                        }
                    }
                    Op::Sync(d) => {
                        engines[d].sync_once().await;
                    }
                }
            }
            for _ in 0..2 {
                for e in &mut engines {
                    assert_eq!(e.sync_once().await, SyncStatus::Synced);
                }
            }
            let sa_ = snapshot(&a).await;
            assert_eq!(sa_, snapshot(&b).await);
            assert_eq!(sa_, snapshot(&c).await);
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 6, ..ProptestConfig::default() })]
        #[test]
        fn three_devices_converge(ops in proptest::collection::vec(op(), 1..30)) {
            run(ops);
        }
    }
}
