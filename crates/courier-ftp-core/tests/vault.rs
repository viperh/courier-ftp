//! Vault engine integration tests (T30): temp dirs, `Argon2Cost::TEST`, `MemKeyring`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use courier_ftp_core::model::item::{
    ItemId, ItemKind, ItemView, KnownHostItem, SecretField, UnixMillis,
};
use courier_ftp_core::trust::{HostKeyStore, KnownHost, KnownHostId};
use courier_ftp_core::vault::{
    Argon2Cost, DeviceBlobStore, KdfParams, LockReason, MemKeyring, UnlockMethod, VaultChange,
    VaultError, VaultState,
};
use courier_ftp_store::ManualClock;
use courier_ftp_store::meta::keys;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t01_initialize_lock_unlock_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(&db(&dir), MemKeyring::new()).await;
    assert_eq!(e.status().await.unwrap().state, VaultState::Uninitialised);
    // AC8: a weak master password is refused with zxcvbn feedback.
    match e.initialize(pw("password123"), false).await {
        Err(VaultError::WeakPassword(w)) => assert!(!w.strength.feedback().is_empty()),
        other => panic!("{other:?}"),
    }
    let report = e.initialize(pw(PASSWORD), false).await.unwrap();
    assert_eq!(report.keyring_error, None);
    assert_eq!(
        e.state(),
        VaultState::Unlocked {
            method: UnlockMethod::Created
        }
    );
    let vault = e.personal_vault().unwrap();
    let mut ids = Vec::new();
    for i in 0..3 {
        let id = ItemId::new();
        e.put(
            vault,
            id,
            site(&format!("host{i}.example"), "CANARY-site-pw"),
        )
        .await
        .unwrap();
        ids.push(id);
    }
    for i in 0..2 {
        let id = ItemId::new();
        let kh = KnownHostItem::new(
            &format!("h{i}.example"),
            22,
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIA",
            UnixMillis(1_700_000_000_000),
        );
        e.put(vault, id, kh).await.unwrap();
        ids.push(id);
    }
    let bm = ItemId::new();
    e.put(
        vault,
        bm,
        TestBookmark {
            remote: "/www".into(),
        },
    )
    .await
    .unwrap();
    ids.push(bm);

    let mut before = Vec::new();
    for id in &ids {
        before.push(
            e.get_body(*id)
                .await
                .unwrap()
                .unwrap()
                .body
                .to_cbor()
                .unwrap(),
        );
    }
    // The cache hands out views without secret values.
    let listed = e.list::<TestSite>().unwrap();
    assert_eq!(listed.len(), 3);
    assert!(
        listed
            .iter()
            .all(|l| l.view.password == SecretField::Kept && !l.secrets_loaded)
    );

    e.lock(LockReason::Manual).await;
    assert_eq!(e.state(), VaultState::Locked);
    let r = e.unlock(pw(PASSWORD)).await.unwrap();
    assert_eq!(r.method, UnlockMethod::Password);
    assert_eq!(r.items, 6);
    for (id, b) in ids.iter().zip(&before) {
        let after = e
            .get_body(*id)
            .await
            .unwrap()
            .unwrap()
            .body
            .to_cbor()
            .unwrap();
        assert_eq!(&after, b, "byte-identical body");
    }
    let got = e.get::<TestSite>(ids[0]).await.unwrap().unwrap();
    assert!(got.secrets_loaded);
    assert_eq!(
        got.view.password.value().map(|s| s.expose().to_owned()),
        Some("CANARY-site-pw".to_owned())
    );
    assert_eq!(e.list::<KnownHostItem>().unwrap().len(), 2);
    assert_eq!(e.list::<TestBookmark>().unwrap().len(), 1);
    // A wrong-kind get is NotFound; a second identical put writes nothing.
    assert!(matches!(
        e.get::<TestBookmark>(ids[0]).await,
        Err(VaultError::NotFound(_))
    ));
    let again = e
        .put(vault, ids[0], site("host0.example", "CANARY-site-pw"))
        .await
        .unwrap();
    assert!(!again.changed);
    // Saving a listed view (password Kept) keeps the stored secret.
    let listed = e.list::<TestSite>().unwrap();
    let first = listed.into_iter().find(|l| l.id == ids[0]).unwrap();
    e.put(vault, ids[0], first.view).await.unwrap();
    let got = e.get::<TestSite>(ids[0]).await.unwrap().unwrap();
    assert!(got.view.password.value().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_keyring_unlock_fallback_and_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let kr = MemKeyring::new();
    let e = engine(&db(&dir), kr.clone()).await;
    e.initialize(pw(PASSWORD), true).await.unwrap();
    assert!(e.status().await.unwrap().keyring_enabled);
    let accounts = kr.accounts();
    assert_eq!(accounts.len(), 1);
    assert!(accounts[0].starts_with("lmk-kek:"));
    e.lock(LockReason::Manual).await;

    let kdf_before = e.kdf_runs();
    let r = e.unlock_with_keyring().await.unwrap();
    assert_eq!(r.method, UnlockMethod::Keyring);
    assert_eq!(e.kdf_runs(), kdf_before, "keyring unlock runs no Argon2");
    assert!(kr.get_calls() >= 1);
    e.lock(LockReason::Manual).await;

    kr.set_unavailable(true);
    assert!(matches!(
        e.unlock_with_keyring().await,
        Err(VaultError::Keyring(_))
    ));
    assert_eq!(e.state(), VaultState::Locked);
    e.unlock(pw(PASSWORD)).await.unwrap();
    // Recovery without a keyring unlock is refused.
    assert_eq!(
        e.change_password(None, pw(NEW_PASSWORD)).await,
        Err(VaultError::KeyringNotEnabled)
    );
    e.lock(LockReason::Manual).await;

    kr.set_unavailable(false);
    kr.remove(&accounts[0]);
    assert!(matches!(
        e.unlock_with_keyring().await,
        Err(VaultError::Keyring(_))
    ));
    e.unlock(pw(PASSWORD)).await.unwrap();
    e.set_keyring_unlock(true).await.unwrap();
    e.lock(LockReason::Manual).await;

    // Forgot password: keyring unlock, then a new password.
    e.unlock_with_keyring().await.unwrap();
    e.change_password(None, pw(NEW_PASSWORD)).await.unwrap();
    e.lock(LockReason::Manual).await;
    assert!(matches!(
        e.unlock(pw(PASSWORD)).await,
        Err(VaultError::WrongPassword { failures: 1, .. })
    ));
    e.unlock(pw(NEW_PASSWORD)).await.unwrap();

    // Disabling removes the entry and the meta key.
    e.set_keyring_unlock(false).await.unwrap();
    assert!(kr.accounts().is_empty());
    assert!(!e.status().await.unwrap().keyring_enabled);
    e.lock(LockReason::Manual).await;
    assert_eq!(
        e.unlock_with_keyring().await,
        Err(VaultError::KeyringNotEnabled)
    );

    // An unavailable keyring cannot be enabled; first run reports, but succeeds.
    let dir2 = tempfile::tempdir().unwrap();
    let kr2 = MemKeyring::new();
    kr2.set_unavailable(true);
    let e2 = engine(&db(&dir2), kr2.clone()).await;
    assert!(!e2.keyring_available().await);
    let rep = e2.initialize(pw(PASSWORD), true).await.unwrap();
    assert!(rep.keyring_error.is_some());
    assert!(!e2.status().await.unwrap().keyring_enabled);
    assert_eq!(
        e2.set_keyring_unlock(true).await,
        Err(VaultError::KeyringUnavailable)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_wrong_password_touches_only_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let e = engine(&path, MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    let vault = e.personal_vault().unwrap();
    e.put(vault, ItemId::new(), site("a.example", "pw"))
        .await
        .unwrap();
    e.lock(LockReason::Manual).await;
    let before = snapshot(&e_store(&path).await).await;
    let err = e.unlock(pw("wrong horse battery staple violin")).await;
    assert!(matches!(
        err,
        Err(VaultError::WrongPassword {
            failures: 1,
            retry_after: None
        })
    ));
    let after = snapshot(&e_store(&path).await).await;
    let strip = |s: &Vec<(String, [u8; 32])>| {
        s.iter()
            .filter(|(k, _)| {
                k != &format!("meta:{}", keys::UNLOCK_FAILURES)
                    && k != &format!("meta:{}", keys::UNLOCK_NEXT_ALLOWED_AT)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(strip(&before), strip(&after));
    assert!(
        after
            .iter()
            .any(|(k, _)| k == &format!("meta:{}", keys::UNLOCK_FAILURES))
    );
    // Success resets the counter.
    e.unlock(pw(PASSWORD)).await.unwrap();
    let st = e.status().await.unwrap();
    assert_eq!(st.backoff.failures, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_backoff_shared_between_engines() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let clock = Arc::new(ManualClock::new(1_800_000_000_000));
    let a = engine_with_clock(&path, MemKeyring::new(), Arc::clone(&clock)).await;
    let b = engine_with_clock(&path, MemKeyring::new(), Arc::clone(&clock)).await;
    a.initialize(pw(PASSWORD), false).await.unwrap();
    a.lock(LockReason::Manual).await;
    let wrong = "wrong horse battery staple violin";
    let expected: [(u32, u64); 10] = [
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 1),
        (6, 2),
        (7, 4),
        (8, 8),
        (9, 16),
        (10, 30),
    ];
    for (i, (failures, secs)) in expected.into_iter().enumerate() {
        let e = if i % 2 == 0 { &a } else { &b };
        let runs = e.kdf_runs();
        let r = e.unlock(pw(wrong)).await;
        let delay = (secs > 0).then(|| Duration::from_secs(secs));
        assert_eq!(
            r,
            Err(VaultError::WrongPassword {
                failures,
                retry_after: delay
            }),
            "failure {failures}"
        );
        assert_eq!(e.kdf_runs(), runs + 1);
        if let Some(d) = delay {
            // During the backoff: refused without Argon2, from either engine.
            let other = if i % 2 == 0 { &b } else { &a };
            let runs = other.kdf_runs();
            assert!(matches!(
                other.unlock(pw(PASSWORD)).await,
                Err(VaultError::Backoff { .. })
            ));
            assert_eq!(other.kdf_runs(), runs);
            clock.advance(i64::try_from(d.as_millis()).unwrap());
        }
    }
    // Failures 11..20 stay at the cap.
    for failures in 11..=20 {
        let r = a.unlock(pw(wrong)).await;
        assert_eq!(
            r,
            Err(VaultError::WrongPassword {
                failures,
                retry_after: Some(Duration::from_secs(30))
            })
        );
        clock.advance(30_000);
    }
    let st = b.status().await.unwrap();
    assert_eq!(st.backoff.failures, 20);
    b.unlock(pw(PASSWORD)).await.unwrap();
    assert_eq!(a.status().await.unwrap().backoff.failures, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_lock_drops_every_key() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(&db(&dir), MemKeyring::new()).await;
    let hk = e.host_key_store();
    assert!(!hk.can_persist());
    e.initialize(pw(PASSWORD), false).await.unwrap();
    assert!(e.live_keys() >= 3, "LMK, VK, device key");
    assert!(hk.can_persist());
    let mut rx = e.subscribe();
    e.put(e.personal_vault().unwrap(), ItemId::new(), site("x", "y"))
        .await
        .unwrap();
    e.lock(LockReason::Idle).await;
    assert_eq!(e.live_keys(), 0);
    assert_eq!(e.list::<TestSite>().err(), Some(VaultError::Locked));
    assert!(!hk.can_persist());
    assert!(matches!(e.crypto(), Err(VaultError::Locked)));
    assert!(matches!(
        e.put_blob("tabs", Zeroizing::new(vec![1])).await,
        Err(courier_ftp_core::Error::VaultLocked)
    ));
    let mut saw = Vec::new();
    while let Ok(c) = rx.try_recv() {
        saw.push(c);
    }
    assert!(matches!(
        saw.first(),
        Some(VaultChange::ItemsChanged { .. })
    ));
    assert_eq!(saw.last(), Some(&VaultChange::Locked(LockReason::Idle)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_tampered_kdf_rejected_before_argon2() {
    use ciborium::Value;
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let e = engine(&path, MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    e.lock(LockReason::Manual).await;
    drop(e);
    let kdf = |alg: &str, m: u64, t: u64, p: u64| {
        let v = Value::Map(vec![
            (Value::Text("alg".into()), Value::Text(alg.into())),
            (Value::Text("m_kib".into()), Value::Integer(m.into())),
            (Value::Text("t".into()), Value::Integer(t.into())),
            (Value::Text("p".into()), Value::Integer(p.into())),
            (Value::Text("salt".into()), Value::Bytes(vec![0; 16])),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).unwrap();
        out
    };
    let cases = [
        kdf("argon2id", 1024, 3, 1),
        kdf("argon2id", 8 * 1024 * 1024, 3, 1),
        kdf("argon2id", 65_536, 0, 1),
        kdf("argon2id", 65_536, 65, 1),
        kdf("argon2id", 65_536, 3, 17),
        kdf("scrypt", 65_536, 3, 1),
    ];
    for (i, bad) in cases.into_iter().enumerate() {
        let store = e_store(&path).await;
        store.set_meta(keys::KDF, bad).await.unwrap();
        let e = engine(&path, MemKeyring::new()).await;
        let r = e.unlock(pw(PASSWORD)).await;
        assert!(matches!(r, Err(VaultError::Corrupt(_))), "case {i}: {r:?}");
        assert_eq!(e.kdf_runs(), 0, "case {i}");
    }
}

// Current-thread runtime: the log capture is thread-local.
#[tokio::test]
async fn t07_tampered_wraps_and_envelopes() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let e = engine(&path, MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    let vault = e.personal_vault().unwrap();
    let a = ItemId::new();
    let b = ItemId::new();
    e.put(vault, a, site("a", "1")).await.unwrap();
    e.put(vault, b, site("b", "2")).await.unwrap();
    e.lock(LockReason::Manual).await;
    let store = e_store(&path).await;

    // 1. An item envelope: counted as unreadable, never a panic.
    let row = store.get_item(*a.as_bytes()).await.unwrap().unwrap();
    let mut env = row.envelope.clone();
    let last = env.len() - 1;
    env[last] ^= 1;
    store
        .reseal_item(row.id, row.key_version, env)
        .await
        .unwrap();
    let r = e.unlock(pw(PASSWORD)).await.unwrap();
    assert_eq!(r.unreadable_items, 1);
    assert_eq!(e.status().await.unwrap().unreadable_items, 1);
    assert_eq!(e.list::<TestSite>().unwrap().len(), 1);
    e.lock(LockReason::Manual).await;

    // 2. A vault key: the vault is skipped with a warning.
    let vrow = store.get_vault(*vault.as_bytes()).await.unwrap().unwrap();
    let mut wk = vrow.wrapped_key.clone();
    wk[30] ^= 1;
    store
        .update_wrapped_key(vrow.id, vrow.key_version, wk)
        .await
        .unwrap();
    let logs = capture_logs(|| async {
        let r = e.unlock(pw(PASSWORD)).await.unwrap();
        assert_eq!(r.skipped_vaults, 1);
        assert_eq!(r.unreadable_items, 2);
    })
    .await;
    assert!(
        logs.contains("WARN") && logs.contains("vault key does not unwrap"),
        "{logs}"
    );
    assert!(e.personal_vault().is_err());
    e.lock(LockReason::Manual).await;

    // 3. The password wrap: a wrong password.
    let mut lmk = store.get_meta(keys::LMK_WRAPPED_PW).await.unwrap().unwrap();
    lmk[40] ^= 1;
    store.set_meta(keys::LMK_WRAPPED_PW, lmk).await.unwrap();
    assert!(matches!(
        e.unlock(pw(PASSWORD)).await,
        Err(VaultError::WrongPassword { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_store_passwords_off_and_history_not_dirty() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let e = engine(&path, MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    let mut o = opts();
    o.store_passwords = false;
    e.set_options(o);
    let vault = e.personal_vault().unwrap();
    let id = ItemId::new();
    e.put(vault, id, site("a.example", "CANARY-not-stored"))
        .await
        .unwrap();
    let body = e.get_body(id).await.unwrap().unwrap().body;
    assert!(body.get("host").is_some());
    assert!(!body.contains("password"), "{body:?}");
    let h = ItemId::new();
    e.put(
        vault,
        h,
        TestHistory {
            host: "h.example".into(),
            password: SecretField::Value("x".into()),
        },
    )
    .await
    .unwrap();
    let store = e_store(&path).await;
    let row = store.get_item(*h.as_bytes()).await.unwrap().unwrap();
    assert!(!row.dirty, "history is not queued for sync");
    let row = store.get_item(*id.as_bytes()).await.unwrap().unwrap();
    assert!(row.dirty);
    let hb = e.get_body(h).await.unwrap().unwrap().body;
    assert!(!hb.contains("password"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t09_two_engines_see_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let a = engine(&path, MemKeyring::new()).await;
    a.initialize(pw(PASSWORD), false).await.unwrap();
    let b = engine(&path, MemKeyring::new()).await;
    b.unlock(pw(PASSWORD)).await.unwrap();
    let vault = a.personal_vault().unwrap();
    let mut rx = b.subscribe();
    let id = ItemId::new();
    a.put(vault, id, site("seen.example", "p")).await.unwrap();
    let start = std::time::Instant::now();
    loop {
        if b.list::<TestSite>().unwrap().iter().any(|l| l.id == id) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "not seen within 3 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut got_event = false;
    while let Ok(c) = rx.try_recv() {
        if let VaultChange::ItemsChanged { ids, kinds } = c {
            got_event |= ids.contains(&id) && kinds.contains(&ItemKind::Site);
        }
    }
    assert!(got_event);

    let wa = {
        let a = a.clone();
        tokio::spawn(async move {
            for i in 0..100 {
                a.put(vault, ItemId::new(), site(&format!("a{i}"), "p"))
                    .await
                    .unwrap();
            }
        })
    };
    let wb = {
        let b = b.clone();
        tokio::spawn(async move {
            for i in 0..100 {
                b.put(vault, ItemId::new(), site(&format!("b{i}"), "p"))
                    .await
                    .unwrap();
            }
        })
    };
    wa.await.unwrap();
    wb.await.unwrap();
    let start = std::time::Instant::now();
    while a.list::<TestSite>().unwrap().len() != 201 || b.list::<TestSite>().unwrap().len() != 201 {
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "engines did not converge"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10_change_password_rewraps_and_old_fails() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(&db(&dir), MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    assert!(matches!(
        e.change_password(Some(pw(PASSWORD)), pw("password123"))
            .await,
        Err(VaultError::WeakPassword(_))
    ));
    assert!(matches!(
        e.change_password(
            Some(pw("wrong horse battery staple violin")),
            pw(NEW_PASSWORD)
        )
        .await,
        Err(VaultError::WrongPassword { .. })
    ));
    e.change_password(Some(pw(PASSWORD)), pw(NEW_PASSWORD))
        .await
        .unwrap();
    e.verify_password(pw(NEW_PASSWORD)).await.unwrap();
    e.lock(LockReason::Manual).await;
    assert!(matches!(
        e.unlock(pw(PASSWORD)).await,
        Err(VaultError::WrongPassword { .. })
    ));
    e.unlock(pw(NEW_PASSWORD)).await.unwrap();
    assert_eq!(e.status().await.unwrap().backoff.failures, 0);
    e.lock(LockReason::Manual).await;
    assert_eq!(
        e.change_password(Some(pw(NEW_PASSWORD)), pw(PASSWORD))
            .await,
        Err(VaultError::Locked)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t11_cost_upgrade_on_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let e = engine(&path, MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    e.lock(LockReason::Manual).await;
    let store = e_store(&path).await;
    let old = KdfParams::from_cbor(&store.get_meta(keys::KDF).await.unwrap().unwrap()).unwrap();
    assert_eq!(old.cost(), Argon2Cost::TEST);
    let upgraded = Argon2Cost {
        m_kib: Argon2Cost::TEST.m_kib,
        t: 2,
        p: 1,
    };
    let mut o = opts();
    o.cost = upgraded;
    e.set_options(o);
    let runs = e.kdf_runs();
    e.unlock(pw(PASSWORD)).await.unwrap();
    e.wait_background().await;
    assert_eq!(
        e.kdf_runs(),
        runs + 2,
        "one extra Argon2 run for the upgrade"
    );
    let new = KdfParams::from_cbor(&store.get_meta(keys::KDF).await.unwrap().unwrap()).unwrap();
    assert_eq!(new.cost(), upgraded);
    assert_ne!(new.salt, old.salt);
    e.lock(LockReason::Manual).await;
    e.unlock(pw(PASSWORD)).await.unwrap();
    e.wait_background().await;
    assert_eq!(e.kdf_runs(), runs + 3, "no upgrade when the cost matches");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_device_blob_roundtrip_and_locked() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let e = engine(&path, MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    assert_eq!(e.get_blob("transfer-queue").await.unwrap(), None);
    e.put_blob("transfer-queue", Zeroizing::new(b"queue v1".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        e.get_blob("transfer-queue")
            .await
            .unwrap()
            .map(|z| z.to_vec()),
        Some(b"queue v1".to_vec())
    );
    // Sealed: the stored bytes are not the plaintext, and bound to the name.
    let raw = e_store(&path)
        .await
        .get_device_blob("transfer-queue")
        .await
        .unwrap()
        .unwrap();
    assert!(!raw.windows(8).any(|w| w == b"queue v1"));
    e.lock(LockReason::Manual).await;
    assert!(matches!(
        e.get_blob("transfer-queue").await,
        Err(courier_ftp_core::Error::VaultLocked)
    ));
    e.unlock(pw(PASSWORD)).await.unwrap();
    assert_eq!(
        e.get_blob("transfer-queue")
            .await
            .unwrap()
            .map(|z| z.to_vec()),
        Some(b"queue v1".to_vec())
    );
    e.delete_blob("transfer-queue").await.unwrap();
    assert_eq!(e.get_blob("transfer-queue").await.unwrap(), None);
}

fn known(host: &str, blob: &str) -> KnownHost {
    KnownHost {
        id: KnownHostId::new_v7(),
        host: host.into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        public_key: blob.into(),
        added_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        comment: Some("test".into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t13_host_key_store_add_replace_remove() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(&db(&dir), MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    let hk = e.host_key_store();
    let first = known("Example.ORG", "AAAAC3NzaC1lZDI1NTE5AAAAIA");
    hk.add(first.clone(), vec![]).await.unwrap();
    let found = hk.lookup("example.org", 22);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, first.id);
    assert_eq!(found[0].host, "example.org");
    assert_eq!(found[0].added_at, first.added_at);
    assert_eq!(found[0].comment.as_deref(), Some("test"));

    let mut rx = e.subscribe();
    let second = known("example.org", "AAAAC3NzaC1lZDI1NTE5AAAAIB");
    hk.add(second.clone(), vec![first.id]).await.unwrap();
    // One transaction: one change event naming both items.
    match rx.try_recv() {
        Ok(VaultChange::ItemsChanged { ids, .. }) => {
            assert_eq!(ids.len(), 2);
            assert!(ids.contains(&ItemId::from_uuid(first.id.0)));
            assert!(ids.contains(&ItemId::from_uuid(second.id.0)));
        }
        other => panic!("{other:?}"),
    }
    assert!(rx.try_recv().is_err());
    let found = hk.lookup("EXAMPLE.org", 22);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, second.id);
    assert_eq!(hk.list().len(), 1);

    e.lock(LockReason::Manual).await;
    assert!(hk.lookup("example.org", 22).is_empty());
    e.unlock(pw(PASSWORD)).await.unwrap();
    assert_eq!(hk.lookup("example.org", 22).len(), 1, "persisted");
    hk.remove(second.id).await.unwrap();
    hk.remove(second.id).await.unwrap();
    assert!(hk.lookup("example.org", 22).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t14_initialize_race() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let a = engine(&path, MemKeyring::new()).await;
    let b = engine(&path, MemKeyring::new()).await;
    let (ra, rb) = tokio::join!(
        a.initialize(pw(PASSWORD), false),
        b.initialize(pw(PASSWORD), false)
    );
    let oks = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "{ra:?} {rb:?}");
    assert!(ra == Err(VaultError::AlreadyInitialized) || rb == Err(VaultError::AlreadyInitialized));
    // The loser can unlock the winner's vault.
    let loser = if ra.is_ok() { &b } else { &a };
    loser.unlock(pw(PASSWORD)).await.unwrap();
    assert!(matches!(
        a.initialize(pw(PASSWORD), false).await,
        Err(VaultError::AlreadyInitialized | VaultError::UnlockInProgress)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t15_delete_restore_device_local_and_approvals() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(&db(&dir), MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    let vault = e.personal_vault().unwrap();
    let id = ItemId::new();
    e.put(vault, id, site("a", "secret")).await.unwrap();
    e.touch_connected(id).await.unwrap();
    e.set_tree_expanded(id, Some(true)).await.unwrap();
    let local = e.device_local(id).unwrap();
    assert!(local.last_connected_at.is_some() && local.frecency > 0.0);
    assert_eq!(local.tree_expanded, Some(true));
    e.approve(id, "key_file_path", [7; 32]).await.unwrap();
    assert!(e.is_approved(id, "key_file_path", &[7; 32]));
    assert!(!e.is_approved(id, "key_file_path", &[8; 32]));

    e.delete(id).await.unwrap();
    assert!(e.list::<TestSite>().unwrap().is_empty());
    assert!(e.get::<TestSite>(id).await.unwrap().is_none());
    let body = e.get_body(id).await.unwrap().unwrap().body;
    assert!(body.is_deleted());
    assert!(
        body.contains("password") && body.get("password").is_none(),
        "secret cleared"
    );
    assert!(e.device_local(id).is_none());
    assert!(!e.is_approved(id, "key_file_path", &[7; 32]));
    e.restore(id).await.unwrap();
    assert_eq!(e.list::<TestSite>().unwrap().len(), 1);
    assert!(matches!(
        e.delete(ItemId::new()).await,
        Err(VaultError::NotFound(_))
    ));

    let ids: Vec<ItemId> = (0..5).map(|_| ItemId::new()).collect();
    for i in &ids {
        e.put(vault, *i, site("x", "y")).await.unwrap();
    }
    assert_eq!(e.delete_many(ids.clone()).await.unwrap(), 5);
    assert_eq!(e.delete_many(ids).await.unwrap(), 0);
    e.set_local_dir_override(id, Some(courier_ftp_core::model::LocalPath::new("/tmp/x")))
        .await
        .unwrap();
    assert!(e.device_local(id).unwrap().local_dir_override.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t16_put_many_merge_and_too_large() {
    use courier_ftp_core::model::item::{FieldWriter, HlcClock, ItemBody};
    use courier_ftp_core::vault::{BodyEdit, BodyWrite};
    let dir = tempfile::tempdir().unwrap();
    let e = engine(&db(&dir), MemKeyring::new()).await;
    e.initialize(pw(PASSWORD), false).await.unwrap();
    let vault = e.personal_vault().unwrap();
    let mut clock = HlcClock::default();
    let dev = courier_ftp_core::model::item::DeviceId::new();
    let mut w = FieldWriter::new(&mut clock, dev);
    let writes: Vec<BodyWrite> = (0..50)
        .map(|i| BodyWrite {
            vault,
            id: ItemId::new(),
            body: BodyEdit::Replace(site(&format!("imp{i}"), "p").to_new_body(&mut w)),
        })
        .collect();
    let first = writes[0].clone();
    assert_eq!(e.put_many(writes).await.unwrap(), 50);
    assert_eq!(e.list::<TestSite>().unwrap().len(), 50);
    // Merging the same body again changes nothing.
    let BodyEdit::Replace(b) = first.body else {
        unreachable!()
    };
    assert_eq!(
        e.put_many(vec![BodyWrite {
            vault,
            id: first.id,
            body: BodyEdit::Merge(b)
        }])
        .await
        .unwrap(),
        0
    );
    let mut huge = ItemBody::new(ItemKind::Site, 1);
    let blob: String = (0..1_100_000)
        .map(|i| char::from(b'a' + (i * 7 % 26) as u8))
        .collect();
    huge.set("host", blob, &mut clock, dev);
    let r = e
        .put_many(vec![BodyWrite {
            vault,
            id: ItemId::new(),
            body: BodyEdit::Replace(huge),
        }])
        .await;
    assert!(matches!(r, Err(VaultError::ItemTooLarge { .. })), "{r:?}");
}
