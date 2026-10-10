//! Vault list, pull and push (T85) end to end over HTTP against an
//! in-process server: gap-free revisions, conflicts, pagination,
//! concurrency, permissions, rotation, limits, quota and tombstone GC.
//!
//! Every scenario runs on the in-memory store (`*_mem`) and on PostgreSQL
//! (`*_pg`, `COURIER_SERVER_PG_TEST=1` + `DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::TimeDelta;
use common::client::{Account, open_and_register, register};
use common::sync::*;
use common::{Server, assert_error, config, generous};
use courier_ftp_crypto::envelope::seal_item;
use courier_ftp_crypto::keys::{os_rng, random_key32};
use courier_ftp_proto::limits::MAX_ENVELOPE;
use courier_ftp_proto::sync::{Permission, PushStatus, QUOTA_EXCEEDED_MESSAGE, VaultKind};
use courier_ftp_server::sync::{ChangeNotifier, gc};
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

async fn user(h: &Server, email: &str) -> Account {
    open_and_register(h, email).await
}

/// New items with base 0 → ok, revisions 1..n; the vault list shows head,
/// permission and the self-grant.
async fn t01_push_new(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let list = vaults(h, a.access()).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, a.vault_id);
    assert_eq!(list[0].head_revision, 0);

    let res = push(h, a.access(), a.vault_id, new_items(3, 16)).await;
    assert!(res.results.iter().all(|r| r.status == PushStatus::Ok));
    assert_eq!(revisions(&res), vec![Some(1), Some(2), Some(3)]);

    let list = vaults(h, a.access()).await;
    let v = &list[0];
    assert_eq!(v.head_revision, 3);
    assert_eq!(v.kind, VaultKind::Personal);
    assert_eq!(v.permission, Permission::Manage);
    assert_eq!(v.key_version, 1);
    assert_eq!(v.grants.len(), 1);
    assert_eq!(v.grants[0].wrapped_by, a.user_id);
    assert!(v.rotation.is_none());
    // The self-grant verifies and opens to the registered vault key.
    let grant = v.grants[0].to_grant().unwrap();
    let vk = courier_ftp_crypto::grant::verify_and_open_grant(
        &grant,
        a.vault_id.as_bytes(),
        1,
        a.user_id.as_bytes(),
        &a.keys,
        &a.keys.public().ed25519,
    )
    .unwrap();
    assert_eq!(vk, a.vault_key);

    let page = pull(h, a.access(), a.vault_id, 0, None).await;
    assert_eq!(page.head_revision, 3);
    assert_eq!(
        page.items.iter().map(|i| i.revision).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(!page.more);
    assert_eq!(page.next_cursor(0), 3);

    let res = push(h, a.access(), a.vault_id, vec![]).await;
    assert!(res.results.is_empty());
    let id = Uuid::now_v7();
    let (st, v) = push_raw(
        h,
        a.access(),
        a.vault_id,
        vec![change(id, 0, b"x", false), change(id, 0, b"y", false)],
    )
    .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    assert_eq!(
        pull(h, a.access(), a.vault_id, 0, None).await.head_revision,
        3
    );
}

/// Stale base → conflict with `current`; rejected changes consume no
/// revisions.
async fn t02_conflicts(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let x = Uuid::now_v7();
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![change(x, 0, b"x-v1", false)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(1));
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![change(x, 1, b"x-v2", false)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(2));

    let (y, z, ghost) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![
            change(y, 0, b"y", false),
            change(x, 1, b"x-stale", false),
            change(ghost, 9, b"ghost", false),
            change(z, 0, b"z", false),
        ],
    )
    .await;
    let st: Vec<_> = res.results.iter().map(|r| r.status).collect();
    assert_eq!(
        st,
        vec![
            PushStatus::Ok,
            PushStatus::Conflict,
            PushStatus::Conflict,
            PushStatus::Ok
        ]
    );
    assert_eq!(revisions(&res), vec![Some(3), None, None, Some(4)]);
    let cur = res.results[1].current.as_ref().unwrap();
    assert_eq!((cur.id, cur.revision, cur.key_version), (x, 2, 1));
    assert_eq!(cur.envelope, b"x-v2");
    assert!(res.results[2].current.is_none());

    let res = push(h, a.access(), a.vault_id, vec![change(y, 1, b"y2", false)]).await;
    assert_eq!(res.results[0].status, PushStatus::Conflict);
    assert_eq!(res.results[0].current.as_ref().unwrap().revision, 3);
    let page = pull(h, a.access(), a.vault_id, 0, None).await;
    assert_eq!(page.head_revision, 4);
    assert_eq!(
        page.items
            .iter()
            .map(|i| (i.id, i.revision))
            .collect::<Vec<_>>(),
        vec![(x, 2), (y, 3), (z, 4)]
    );
    // A second device sees the same thing and resolves the conflict.
    let other = common::client::login(h, &a).await;
    let res = push(
        h,
        &other.tokens.access_token,
        a.vault_id,
        vec![change(y, 3, b"y-merged", false)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(5));
}

/// 1,200 items, limit 500 → pages of 500/500/200, ascending, each item once.
async fn t03_pagination(h: &Server) {
    let a = user(h, "alice@example.com").await;
    for _ in 0..3 {
        push(h, a.access(), a.vault_id, new_items(400, 8)).await;
    }
    let mut cursor = 0;
    let mut seen = BTreeSet::new();
    let mut shape = Vec::new();
    loop {
        let page = pull(h, a.access(), a.vault_id, cursor, Some(500)).await;
        assert_eq!(page.head_revision, 1200);
        shape.push((page.items.len(), page.more));
        for i in &page.items {
            assert!(i.revision > cursor, "ascending and after the cursor");
            assert!(seen.insert(i.id), "duplicate item");
        }
        cursor = page.next_cursor(cursor);
        if !page.more {
            break;
        }
    }
    assert_eq!(shape, vec![(500, true), (500, true), (200, false)]);
    assert_eq!(seen.len(), 1200);
    assert_eq!(cursor, 1200);
    assert_eq!(
        pull(h, a.access(), a.vault_id, 0, None).await.items.len(),
        500
    );
    assert_eq!(
        pull(h, a.access(), a.vault_id, 0, Some(5000))
            .await
            .items
            .len(),
        500
    );
    let (st, v) = pull_raw(h, a.access(), a.vault_id, 0, Some(0)).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
}

/// Parallel pushers (two devices) while a puller follows the cursor: every
/// revision is assigned exactly once, without gaps, and the puller sees each
/// in order.
async fn t04_concurrency(h: &Server) {
    const PUSHERS: usize = 8;
    const PUSHES: usize = 60;
    const TOTAL: u64 = (PUSHERS * PUSHES) as u64;
    for iteration in 0..2 {
        let a = user(h, &format!("conc{iteration}@example.com")).await;
        let second = common::client::login(h, &a).await.tokens.access_token;
        let pushes = (0..PUSHERS).map(|p| {
            let token = if p % 2 == 0 {
                a.access().to_owned()
            } else {
                second.clone()
            };
            let vault = a.vault_id;
            async move {
                let mut revs = Vec::with_capacity(PUSHES);
                for _ in 0..PUSHES {
                    let res = push(h, &token, vault, new_items(1, 24)).await;
                    assert_eq!(res.results[0].status, PushStatus::Ok);
                    revs.push(res.results[0].revision.unwrap());
                }
                revs
            }
        });
        let puller = async {
            let mut cursor = 0u64;
            let mut seen = Vec::with_capacity(TOTAL as usize);
            while cursor < TOTAL {
                let page = pull(h, a.access(), a.vault_id, cursor, Some(37)).await;
                for i in &page.items {
                    assert_eq!(
                        i.revision,
                        cursor + 1,
                        "gap: missed revision {}",
                        cursor + 1
                    );
                    cursor = i.revision;
                    seen.push(i.revision);
                }
                if page.items.is_empty() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            seen
        };
        let (pushed, seen) = tokio::time::timeout(
            Duration::from_secs(300),
            futures::future::join(futures::future::join_all(pushes), puller),
        )
        .await
        .expect("pushers and puller finish");
        let mut pushed: Vec<u64> = pushed.into_iter().flatten().collect();
        pushed.sort_unstable();
        let all: Vec<u64> = (1..=TOTAL).collect();
        assert_eq!(pushed, all, "pushers got every revision exactly once");
        assert_eq!(
            seen, all,
            "puller saw every revision exactly once, in order"
        );
    }
}

/// Concurrent conflicting edits of one item: exactly one wins per base.
async fn t04b_concurrent_conflicts(h: &Server) {
    let a = user(h, "race@example.com").await;
    let b = common::client::login(h, &a).await.tokens.access_token;
    let x = Uuid::now_v7();
    push(h, a.access(), a.vault_id, vec![change(x, 0, b"v1", false)]).await;
    let (ra, rb) = tokio::join!(
        push(
            h,
            a.access(),
            a.vault_id,
            vec![change(x, 1, b"from-a", false)]
        ),
        push(h, &b, a.vault_id, vec![change(x, 1, b"from-b", false)]),
    );
    let mut st = vec![ra.results[0].status, rb.results[0].status];
    st.sort_by_key(|s| *s == PushStatus::Conflict);
    assert_eq!(st, vec![PushStatus::Ok, PushStatus::Conflict]);
    let loser = if ra.results[0].status == PushStatus::Conflict {
        &ra
    } else {
        &rb
    };
    assert_eq!(loser.results[0].current.as_ref().unwrap().revision, 2);
}

/// A read-only member's push → 403; pull works.
async fn t05_read_only(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let b = register(h, "bob@example.com", "pw").await;
    let v = h.shared_vault(&[a.user_id], "manage").await;
    h.add_member(v, b.user_id, "read").await;
    let res = push(h, a.access(), v, new_items(2, 8)).await;
    assert_eq!(revisions(&res), vec![Some(1), Some(2)]);

    let (st, body) = push_raw(h, b.access(), v, new_items(1, 8)).await;
    assert_error(st, &body, StatusCode::FORBIDDEN, "forbidden");
    let page = pull(h, b.access(), v, 0, None).await;
    assert_eq!(page.items.len(), 2);

    let list = vaults(h, b.access()).await;
    let shared = list.iter().find(|x| x.id == v).unwrap();
    assert_eq!(shared.permission, Permission::Read);
    assert_eq!(shared.kind, VaultKind::Shared);
    assert_eq!(list.len(), 2, "personal + shared");
}

/// Rotation in progress → push 409 rotating, pull works.
async fn t06_rotating(h: &Server) {
    let a = user(h, "alice@example.com").await;
    push(h, a.access(), a.vault_id, new_items(1, 8)).await;
    h.set_rotation(a.vault_id, Some(2)).await;
    let (st, v) = push_raw(h, a.access(), a.vault_id, new_items(1, 8)).await;
    assert_error(st, &v, StatusCode::CONFLICT, "rotating");
    assert_eq!(
        pull(h, a.access(), a.vault_id, 0, None).await.items.len(),
        1
    );
    let rot = vaults(h, a.access()).await[0].rotation.clone().unwrap();
    assert_eq!(rot.new_key_version, 2);
    assert!(!rot.abandoned);
    // 16 minutes later (a fresh login: the access token has expired too).
    h.clock.advance(TimeDelta::minutes(16));
    let token = common::client::login(h, &a).await.tokens.access_token;
    assert!(
        vaults(h, &token).await[0]
            .rotation
            .clone()
            .unwrap()
            .abandoned
    );
    h.set_rotation(a.vault_id, None).await;
    let res = push(h, &token, a.vault_id, new_items(1, 8)).await;
    assert_eq!(
        res.results[0].revision,
        Some(2),
        "nothing consumed by the 409"
    );
}

/// Envelope over 1 MiB → `too_large`; 501 changes → 400; over 8 MiB → 400;
/// exactly 8 MiB passes.
async fn t07_limits(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let (big, ok) = (Uuid::now_v7(), Uuid::now_v7());
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![
            change(big, 0, &vec![1; MAX_ENVELOPE + 1], false),
            change(ok, 0, &vec![1; MAX_ENVELOPE], false),
        ],
    )
    .await;
    assert_eq!(res.results[0].status, PushStatus::TooLarge);
    assert_eq!(
        res.results[0].message.as_deref(),
        Some(courier_ftp_proto::sync::ENVELOPE_TOO_LARGE_MESSAGE)
    );
    assert_eq!(res.results[1].revision, Some(1));

    let (st, v) = push_raw(h, a.access(), a.vault_id, new_items(501, 1)).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");

    let mut batch = new_items(8, MAX_ENVELOPE);
    batch.push(change(Uuid::now_v7(), 0, &[1], false));
    let (st, v) = push_raw(h, a.access(), a.vault_id, batch).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");

    let res = push(h, a.access(), a.vault_id, new_items(8, MAX_ENVELOPE)).await;
    assert!(res.results.iter().all(|r| r.status == PushStatus::Ok));
    assert_eq!(
        pull(h, a.access(), a.vault_id, 0, Some(1))
            .await
            .head_revision,
        9
    );
}

/// Quota 1 MiB: nothing accepted beyond it; shrinking is always allowed.
async fn t08_quota(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let batch = new_items(5, 300_000);
    let first = batch[0]["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let res = push(h, a.access(), a.vault_id, batch).await;
    let st: Vec<_> = res.results.iter().map(|r| r.status).collect();
    assert_eq!(
        st,
        vec![
            PushStatus::Ok,
            PushStatus::Ok,
            PushStatus::Ok,
            PushStatus::TooLarge,
            PushStatus::TooLarge
        ]
    );
    assert_eq!(
        res.results[3].message.as_deref(),
        Some(QUOTA_EXCEEDED_MESSAGE)
    );
    let res = push(h, a.access(), a.vault_id, new_items(1, 148_577)).await;
    assert_eq!(res.results[0].status, PushStatus::TooLarge);
    let res = push(h, a.access(), a.vault_id, new_items(1, 148_576)).await;
    assert_eq!(res.results[0].revision, Some(4));
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![change(first, 1, &[0; 16], true)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(5));
    let res = push(h, a.access(), a.vault_id, new_items(1, 299_984)).await;
    assert_eq!(res.results[0].revision, Some(6));
    let res = push(h, a.access(), a.vault_id, new_items(1, 1)).await;
    assert_eq!(res.results[0].status, PushStatus::TooLarge);
    let total: usize = pull(h, a.access(), a.vault_id, 0, None)
        .await
        .items
        .iter()
        .map(|i| i.envelope.len())
        .sum();
    assert_eq!(total, 1024 * 1024);
}

/// GC purges old tombstones and raises the floor; `since` below it → 410.
async fn t09_gc(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let (x, y, z) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    push(
        h,
        a.access(),
        a.vault_id,
        vec![change(x, 0, b"x", false), change(y, 0, b"y", false)],
    )
    .await;
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![change(x, 1, b"x-dead", true)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(3));
    let t_old = h.now();
    h.clock.advance(TimeDelta::minutes(10));
    push(h, a.access(), a.vault_id, vec![change(z, 0, b"z", false)]).await;
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![change(z, 4, b"z-dead", true)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(5));

    let gc_now = t_old + TimeDelta::days(90) + TimeDelta::minutes(5);
    let out = h
        .state
        .sync()
        .store()
        .gc_tombstones(gc::cutoff(gc_now, 90))
        .await
        .unwrap();
    assert_eq!((out.purged_tombstones, out.vaults), (1, 1));
    assert_eq!(h.gc_floor(a.vault_id).await, 3);

    let (st, v) = pull_raw(h, a.access(), a.vault_id, 2, None).await;
    assert_error(st, &v, StatusCode::GONE, "gone");
    let full = pull(h, a.access(), a.vault_id, 0, None).await;
    assert_eq!(
        full.items
            .iter()
            .map(|i| (i.id, i.revision, i.deleted))
            .collect::<Vec<_>>(),
        vec![(y, 2, false), (z, 5, true)]
    );
    assert_eq!(
        pull(h, a.access(), a.vault_id, 3, None).await.items.len(),
        1
    );
    let out = h
        .state
        .sync()
        .store()
        .gc_tombstones(gc::cutoff(gc_now, 90))
        .await
        .unwrap();
    assert_eq!(out.purged_tombstones, 0);
    let res = push(
        h,
        a.access(),
        a.vault_id,
        vec![change(x, 0, b"x-again", false)],
    )
    .await;
    assert_eq!(res.results[0].revision, Some(6));
}

/// Non-members and unknown vaults: 404 for pull and push, same message.
async fn t10_non_member(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let b = register(h, "bob@example.com", "pw").await;
    push(h, a.access(), a.vault_id, new_items(1, 8)).await;
    for vault in [a.vault_id, Uuid::now_v7()] {
        let (st1, v1) = pull_raw(h, b.access(), vault, 0, None).await;
        assert_error(st1, &v1, StatusCode::NOT_FOUND, "not_found");
        let (st2, v2) = push_raw(h, b.access(), vault, new_items(1, 8)).await;
        assert_error(st2, &v2, StatusCode::NOT_FOUND, "not_found");
        assert_eq!(v1["error"]["message"], v2["error"]["message"]);
    }
    assert!(
        vaults(h, b.access())
            .await
            .iter()
            .all(|v| v.id != a.vault_id)
    );
    let (st, v) = h.get("/v1/vaults", None).await;
    assert_error(st, &v, StatusCode::UNAUTHORIZED, "auth_required");
    // Malformed vault id and body.
    let (st, v) = h
        .get("/v1/vaults/not-a-uuid/changes", Some(a.access()))
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    let (st, v) = h
        .post(
            &format!("/v1/vaults/{}/changes", a.vault_id),
            json!({ "changes": [{ "id": 1 }] }),
            Some(a.access()),
        )
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
}

/// A key-version mismatch → 400 for the whole batch.
async fn t11_key_version(h: &Server) {
    let a = user(h, "alice@example.com").await;
    let mut stale = change(Uuid::now_v7(), 0, b"x", false);
    stale["key_version"] = json!(2);
    let (st, v) = push_raw(
        h,
        a.access(),
        a.vault_id,
        vec![change(Uuid::now_v7(), 0, b"ok", false), stale],
    )
    .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    assert_eq!(
        pull(h, a.access(), a.vault_id, 0, None).await.head_revision,
        0
    );
}

/// Items sealed client-side with a canary host name: the server stores
/// no plaintext.
async fn t12_no_plaintext(h: &Server) {
    const CANARY: &str = "CANARY-ftp.prod-7731.internal";
    let a = user(h, "alice@example.com").await;
    let mut rng = os_rng();
    let vk = random_key32(&mut rng);
    let mut changes = Vec::new();
    for i in 0..5 {
        let id = Uuid::now_v7();
        let body = format!("{{\"name\":\"{CANARY}-{i}\",\"host\":\"{CANARY}\"}}");
        let env = seal_item(
            &vk,
            a.vault_id.as_bytes(),
            id.as_bytes(),
            1,
            body.as_bytes(),
            &mut rng,
        )
        .unwrap();
        changes.push(change(id, 0, &env, false));
    }
    let res = push(h, a.access(), a.vault_id, changes).await;
    assert!(res.results.iter().all(|r| r.status == PushStatus::Ok));
    let (blobs, text) = h.blob_dump().await;
    assert!(!blobs.is_empty());
    let needle = CANARY.as_bytes();
    for b in &blobs {
        assert!(
            !b.windows(needle.len()).any(|w| w == needle),
            "plaintext stored"
        );
    }
    assert!(!text.contains(CANARY));
}

#[derive(Debug, Default)]
struct Recorder(Mutex<Vec<(Uuid, u64)>>);

impl ChangeNotifier for Recorder {
    fn vault_changed(&self, vault_id: Uuid, head_revision: u64) {
        self.0.lock().unwrap().push((vault_id, head_revision));
    }
}

/// The notifier fires once per committing push, after the commit.
async fn notify_hook(h: &Server) {
    let rec = Arc::new(Recorder::default());
    h.state.sync().set_notifier(rec.clone());
    let a = user(h, "alice@example.com").await;
    let x = Uuid::now_v7();
    push(h, a.access(), a.vault_id, vec![change(x, 0, b"x", false)]).await;
    push(
        h,
        a.access(),
        a.vault_id,
        vec![change(x, 0, b"stale", false)],
    )
    .await;
    push(h, a.access(), a.vault_id, new_items(2, 4)).await;
    assert_eq!(
        *rec.0.lock().unwrap(),
        vec![(a.vault_id, 1), (a.vault_id, 3)]
    );
}

/// Account deletion removes the personal vault's items.
async fn delete_removes_items(h: &Server) {
    let a = user(h, "del@example.com").await;
    push(h, a.access(), a.vault_id, new_items(3, 8)).await;
    assert_eq!(h.count_items(a.vault_id).await, 3);
    let token = common::client::reauth(h, &a, &a.password).await;
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": token })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(h.count_items(a.vault_id).await, 0);
}

macro_rules! both {
    ($scenario:ident, $mem:ident, $pg:ident) => {
        both!($scenario, $mem, $pg, &[]);
    };
    ($scenario:ident, $mem:ident, $pg:ident, $cfg:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        async fn $mem() {
            let h = Server::mem_with(generous(), config($cfg)).await;
            $scenario(&h).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        async fn $pg() {
            let h = $crate::db_or_skip!(Server::pg_with(config($cfg)));
            $scenario(&h).await;
            h.cleanup().await;
        }
    };
}

both!(t01_push_new, push_new_items_mem, push_new_items_pg);
both!(
    t02_conflicts,
    conflicts_consume_no_revisions_mem,
    conflicts_consume_no_revisions_pg
);
both!(t03_pagination, pull_pagination_mem, pull_pagination_pg);
both!(
    t04_concurrency,
    parallel_pushers_gap_free_mem,
    parallel_pushers_gap_free_pg
);
both!(
    t04b_concurrent_conflicts,
    concurrent_conflict_one_wins_mem,
    concurrent_conflict_one_wins_pg
);
both!(
    t05_read_only,
    read_member_push_forbidden_mem,
    read_member_push_forbidden_pg
);
both!(
    t06_rotating,
    rotation_blocks_push_not_pull_mem,
    rotation_blocks_push_not_pull_pg
);
both!(
    t07_limits,
    item_and_batch_limits_mem,
    item_and_batch_limits_pg
);
both!(
    t08_quota,
    quota_exceeded_mem,
    quota_exceeded_pg,
    &[("COURIER_STORAGE_QUOTA_MIB", "1")]
);
both!(t09_gc, tombstone_gc_and_gone_mem, tombstone_gc_and_gone_pg);
both!(
    t10_non_member,
    non_member_not_found_mem,
    non_member_not_found_pg
);
both!(
    t11_key_version,
    key_version_mismatch_mem,
    key_version_mismatch_pg
);
both!(
    t12_no_plaintext,
    no_plaintext_stored_mem,
    no_plaintext_stored_pg
);
both!(notify_hook, notify_after_commit_mem, notify_after_commit_pg);
both!(
    delete_removes_items,
    delete_removes_items_mem,
    delete_removes_items_pg
);

/// Model check: while a push holds the vault lock before commit, its
/// changes are invisible, a second push waits, and both land in lock order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vault_lock_serializes_and_hides_uncommitted_mem() {
    let h = Arc::new(Server::mem().await);
    let a = user(&h, "alice@example.com").await;
    let paused = h.mem_sync().pause_next_commit();
    let (h1, token, vault) = (h.clone(), a.access().to_owned(), a.vault_id);
    let first = tokio::spawn(async move { push(&h1, &token, vault, new_items(2, 8)).await });
    paused.reached.await.unwrap();

    let page = pull(&h, a.access(), a.vault_id, 0, None).await;
    assert!(page.items.is_empty());
    assert_eq!(page.head_revision, 0);

    let (h2, token, vault) = (h.clone(), a.access().to_owned(), a.vault_id);
    let second = tokio::spawn(async move { push(&h2, &token, vault, new_items(1, 8)).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !second.is_finished(),
        "a second push must wait for the vault lock"
    );

    paused.resume.send(()).unwrap();
    let r1 = first.await.unwrap();
    let r2 = second.await.unwrap();
    assert_eq!(revisions(&r1), vec![Some(1), Some(2)]);
    assert_eq!(revisions(&r2), vec![Some(3)]);
}
