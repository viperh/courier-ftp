//! The vault engine (T30): first run, unlock and lock, backoff, keyring unlock
//! and recovery, password change, tamper resistance, item CRUD, the
//! vault-backed host key store and the canary-secret scan. Ported and adapted
//! from sverb's `sverb-tui/tests/vault.rs`.
//!
//! Cheap Argon2 (`Argon2Cost::TEST`) and an in-memory keyring: the OS keyring is
//! never touched. Time is a `ManualClock` shared by every engine of a fixture,
//! so backoff tests are deterministic (paused time).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{self, ItemId, ItemKind, Site};
use courier_ftp_core::trust::{
    HostKey, HostKeyStore, HostKeyStoreSlot, KnownHost, MemoryHostKeyStore,
};
use courier_ftp_core::vault::backup;
use courier_ftp_core::vault::{
    ItemVault, ItemVaultExt, ItemWrite, MemKeyring, UnlockMethod, VaultError, VaultHostKeyStore,
    VaultState,
};
use courier_ftp_crypto::kdf::{Argon2Cost, KdfParams};
use courier_ftp_store::meta::keys;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store, VaultKind};
use pretty_assertions::assert_eq;
use secrecy::SecretString;

const PW: &str = "correct horse battery staple violin";
const PW2: &str = "tangerine submarine quietly orbits jupiter";
const T0: i64 = 1_800_000_000_000;

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

struct Fixture {
    dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock::new(T0)),
            keyring: MemKeyring::new(),
        }
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("courier-ftp.db")
    }

    /// A fresh store connection and engine (like another process, or a restart).
    fn engine(&self) -> VaultEngine {
        self.engine_with_cost(Argon2Cost::TEST)
    }

    fn engine_with_cost(&self, cost: Argon2Cost) -> VaultEngine {
        let store = Store::open_at(self.db(), self.clock.clone()).unwrap();
        VaultEngine::new(store, Arc::new(self.keyring.clone()), cost)
    }

    async fn initialized(&self, keyring: bool) -> VaultEngine {
        let engine = self.engine();
        let report = engine.initialize(&pw(PW), keyring).await.unwrap();
        assert_eq!(report.keyring_error, None);
        engine
    }
}

async fn meta(store: &Store, key: &str) -> Option<Vec<u8>> {
    store.meta().get(key).await.unwrap()
}

fn failures(err: &VaultError) -> Option<u32> {
    match err {
        VaultError::WrongPassword { failures, .. } => Some(*failures),
        _ => None,
    }
}

fn site(name: &str, password: &str) -> Site {
    let mut s = Site::new(name, Protocol::Sftp, format!("{name}.example.com"));
    s.user = "deploy".into();
    s.password = Some(pw(password));
    s
}

/// Every row of every persistent table, except the two backoff meta keys.
async fn snapshot(store: &Store) -> Vec<String> {
    store
        .read(|r| {
            let mut out = Vec::new();
            for table in courier_ftp_store::schema::TABLES {
                let mut stmt = r.conn().prepare(&format!("SELECT * FROM {table}"))?;
                let cols = stmt.column_count();
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let mut vals = Vec::new();
                    for i in 0..cols {
                        vals.push(format!("{:?}", row.get::<_, rusqlite::types::Value>(i)?));
                    }
                    let line = format!("{table}: {}", vals.join(" | "));
                    let skip = table == &"meta"
                        && (line.contains(&format!("{:?}", keys::UNLOCK_FAILURES))
                            || line.contains(&format!("{:?}", keys::UNLOCK_NEXT_ALLOWED_AT)));
                    if !skip {
                        out.push(line);
                    }
                }
            }
            out.sort();
            Ok(out)
        })
        .await
        .unwrap()
}

// ------------------------------------------------------------------ first run

#[tokio::test]
async fn first_run_creates_meta_vault_and_device() {
    let fx = Fixture::new();
    let engine = fx.engine();
    let status = engine.status().await.unwrap();
    assert_eq!(status.state, VaultState::Uninitialised);
    assert!(!status.keyring_enabled);

    engine.initialize(&pw(PW), false).await.unwrap();
    let status = engine.status().await.unwrap();
    assert_eq!(status.state, VaultState::Unlocked);
    assert_eq!(status.unlock_method, Some(UnlockMethod::Created));

    let store = engine.store();
    let kdf = KdfParams::from_cbor(&meta(store, keys::KDF).await.unwrap()).unwrap();
    assert_eq!(kdf.cost(), Argon2Cost::TEST);
    assert!(meta(store, keys::LMK_WRAPPED_PW).await.is_some());
    assert!(meta(store, keys::LMK_WRAPPED_KEYRING).await.is_none());
    assert_eq!(
        meta(store, keys::DEVICE_ID).await.map(|d| d.len()),
        Some(16)
    );
    assert!(meta(store, keys::DB_ID).await.is_some());
    assert!(meta(store, keys::HLC_LAST).await.is_some());
    let vaults = store.vaults().list().await.unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].kind, VaultKind::Personal);
    assert_eq!(engine.personal_vault().await, Some(vaults[0].id));
    assert_eq!(engine.live_keys(), 2, "LMK + personal vault key");

    // A second first run is refused, from this engine and another one.
    assert_eq!(
        engine.initialize(&pw(PW), false).await.err(),
        Some(VaultError::AlreadyInitialized)
    );
    assert_eq!(
        fx.engine().initialize(&pw(PW2), false).await.err(),
        Some(VaultError::AlreadyInitialized)
    );
    assert_eq!(
        fx.engine().status().await.unwrap().state,
        VaultState::Locked
    );
}

#[tokio::test]
async fn weak_passwords_are_rejected_with_feedback() {
    let fx = Fixture::new();
    let engine = fx.engine();
    let Err(VaultError::WeakPassword(weak)) = engine.initialize(&pw("password123"), false).await
    else {
        panic!("weak password accepted");
    };
    assert!(weak.strength.score < 3);
    assert!(!weak.strength.feedback().is_empty());
    assert!(weak.to_string().contains(&weak.strength.feedback()));
    assert_eq!(engine.kdf_runs(), 0, "weak passwords never reach Argon2");
    assert_eq!(
        engine.status().await.unwrap().state,
        VaultState::Uninitialised
    );

    // Also on change and on keyring reset.
    let engine = fx.initialized(true).await;
    assert!(matches!(
        engine.change_password(&pw(PW), &pw("qwerty")).await,
        Err(VaultError::WeakPassword(_))
    ));
    assert!(matches!(
        engine.reset_password_with_keyring(&pw("letmein1")).await,
        Err(VaultError::WeakPassword(_))
    ));
}

// ------------------------------------------------------------ unlock and lock

#[tokio::test]
async fn initialize_lock_unlock_returns_identical_items() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let site_id = ItemId::new();
    let host_id = ItemId::new();
    assert!(
        engine
            .put_view(site_id, None, site("web01", "s3cret"))
            .await
            .unwrap()
    );
    let host = item::KnownHost {
        host: "web01.example.com".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        public_key: "AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH".into(),
        added_at: Some(item::UnixMillis(T0)),
        read_only: false,
    };
    assert!(engine.put_view(host_id, None, host.clone()).await.unwrap());
    // Writing the same view again changes nothing.
    assert!(!engine.put_view(host_id, None, host.clone()).await.unwrap());

    let before_site = engine.get(site_id).await.unwrap().unwrap();
    let before_host = engine.get(host_id).await.unwrap().unwrap();
    engine.lock().await;
    assert_eq!(engine.live_keys(), 0);
    assert_eq!(engine.get(site_id).await, Err(VaultError::Locked));
    assert_eq!(engine.list(ItemKind::Site).await, Err(VaultError::Locked));

    // Same engine.
    let report = engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!(report.method, UnlockMethod::Password);
    assert_eq!((report.items, report.undecryptable), (2, 0));
    assert_eq!(engine.get(site_id).await.unwrap().unwrap(), before_site);
    assert_eq!(engine.get(host_id).await.unwrap().unwrap(), before_host);
    drop(engine);

    // A restart (new store connection and engine).
    let engine = fx.engine();
    engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!(engine.get(site_id).await.unwrap().unwrap(), before_site);
    let sites = engine.list_views::<Site>().await.unwrap();
    assert_eq!(sites.len(), 1);
    let (_, view) = &sites[0];
    assert_eq!(view.name, "web01");
    use secrecy::ExposeSecret;
    assert_eq!(
        view.password.as_ref().map(|p| p.expose_secret().to_owned()),
        Some("s3cret".to_owned())
    );
    let hosts = engine.list_views::<item::KnownHost>().await.unwrap();
    assert_eq!(hosts[0].1, host);
}

#[tokio::test]
async fn live_key_counter_is_zero_after_lock() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    engine
        .put_view(ItemId::new(), None, site("a", "pw"))
        .await
        .unwrap();
    assert_eq!(engine.live_keys(), 2);
    engine.lock().await;
    assert_eq!(engine.live_keys(), 0);
    assert!(!engine.is_unlocked().await);
    engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!(engine.live_keys(), 2);
    // A clone shares the state: locking it locks both.
    engine.clone().lock().await;
    assert_eq!(engine.live_keys(), 0);
    // Wrong password: nothing loaded.
    assert!(engine.unlock(&pw("nope")).await.is_err());
    assert_eq!(engine.live_keys(), 0);
}

#[tokio::test]
async fn wrong_password_changes_nothing_but_the_counter() {
    let fx = Fixture::new();
    let engine = fx.initialized(true).await;
    engine
        .put_view(ItemId::new(), None, site("a", "pw"))
        .await
        .unwrap();
    engine.lock().await;
    let before = snapshot(engine.store()).await;

    let err = engine.unlock(&pw("not it")).await.unwrap_err();
    assert_eq!(failures(&err), Some(1));
    assert_eq!(err.to_string(), "wrong master password");
    assert_eq!(snapshot(engine.store()).await, before);
    assert_eq!(
        meta(engine.store(), keys::UNLOCK_FAILURES).await,
        Some(1u32.to_be_bytes().to_vec())
    );
    assert!(!engine.is_unlocked().await);

    // A tampered wrap fails exactly the same way (no distinguishable error).
    let mut wrapped = meta(engine.store(), keys::LMK_WRAPPED_PW).await.unwrap();
    let last = wrapped.len() - 1;
    wrapped[last] ^= 1;
    engine
        .store()
        .meta()
        .set(keys::LMK_WRAPPED_PW, wrapped)
        .await
        .unwrap();
    let err = engine.unlock(&pw(PW)).await.unwrap_err();
    assert_eq!(failures(&err), Some(2));
    assert_eq!(err.to_string(), "wrong master password");
}

// -------------------------------------------------------------------- backoff

#[tokio::test]
async fn backoff_matches_the_table_and_is_shared_between_engines() {
    let fx = Fixture::new();
    fx.initialized(false).await;
    let a = fx.engine();
    let b = fx.engine();
    let expected = [0, 0, 0, 0, 1, 2, 4, 8, 16, 30, 30];
    for (i, secs) in expected.iter().enumerate() {
        let n = u32::try_from(i + 1).unwrap();
        // Alternate between two engines (two processes) on one database.
        let engine = if n % 2 == 0 { &a } else { &b };
        let runs = engine.kdf_runs();
        let err = engine.unlock(&pw("nope")).await.unwrap_err();
        assert_eq!(failures(&err), Some(n), "attempt {n}");
        assert_eq!(engine.kdf_runs(), runs + 1);
        let delay = (*secs > 0).then(|| Duration::from_secs(*secs));
        assert_eq!(err.retry_after(), delay, "attempt {n}");

        if let Some(delay) = delay {
            // Both engines refuse until the delay is over, without Argon2,
            // even with the right password.
            for other in [&a, &b] {
                let runs = other.kdf_runs();
                let err = other.unlock(&pw(PW)).await.unwrap_err();
                assert!(
                    matches!(err, VaultError::Backoff { retry_after } if retry_after == delay),
                    "{err:?}"
                );
                assert_eq!(other.kdf_runs(), runs);
                let status = other.status().await.unwrap();
                assert_eq!(status.retry_after, Some(delay));
                assert_eq!(status.backoff.failures, n);
            }
            fx.clock
                .advance(i64::try_from(delay.as_millis()).unwrap() - 1);
            assert!(matches!(
                a.unlock(&pw(PW)).await,
                Err(VaultError::Backoff { .. })
            ));
            fx.clock.advance(1);
        }
    }

    // Success resets the counter; the next failure is #1 again.
    a.unlock(&pw(PW)).await.unwrap();
    let status = b.status().await.unwrap();
    assert_eq!(status.backoff.failures, 0);
    assert_eq!(status.retry_after, None);
    assert!(meta(a.store(), keys::UNLOCK_FAILURES).await.is_none());
    let err = b.unlock(&pw("nope")).await.unwrap_err();
    assert!(matches!(
        err,
        VaultError::WrongPassword {
            failures: 1,
            retry_after: None
        }
    ));
}

#[tokio::test]
async fn backoff_survives_a_restart() {
    let fx = Fixture::new();
    fx.initialized(false).await;
    let engine = fx.engine();
    for _ in 0..6 {
        fx.clock.advance(60_000);
        engine.unlock(&pw("nope")).await.unwrap_err();
    }
    drop(engine);
    let engine = fx.engine();
    let status = engine.status().await.unwrap();
    assert_eq!(status.backoff.failures, 6);
    assert_eq!(status.retry_after, Some(Duration::from_secs(2)));
    assert!(matches!(
        engine.unlock(&pw(PW)).await,
        Err(VaultError::Backoff { .. })
    ));
    assert_eq!(engine.kdf_runs(), 0);
}

// -------------------------------------------------------------------- keyring

#[tokio::test]
async fn keyring_unlock_and_fallback_to_password() {
    let fx = Fixture::new();
    fx.initialized(true).await;
    assert_eq!(fx.keyring.accounts().len(), 1);
    assert!(fx.keyring.accounts()[0].starts_with("lmk-kek:"));

    let engine = fx.engine();
    assert!(engine.status().await.unwrap().keyring_enabled);
    assert!(engine.keyring_available().await);
    let report = engine.unlock_with_keyring().await.unwrap();
    assert_eq!(report.method, UnlockMethod::Keyring);
    assert_eq!(engine.kdf_runs(), 0, "no password prompt, no Argon2");
    assert_eq!(
        engine.status().await.unwrap().unlock_method,
        Some(UnlockMethod::Keyring)
    );
    engine.lock().await;

    // Keyring unavailable (locked keychain, no Secret Service): error, then the
    // password still works.
    fx.keyring.set_unavailable(true);
    assert!(!engine.keyring_available().await);
    assert!(matches!(
        engine.unlock_with_keyring().await,
        Err(VaultError::Keyring(_))
    ));
    fx.keyring.set_unavailable(false);

    // Entry deleted behind courier-ftp's back.
    let account = engine.keyring_account().await.unwrap().unwrap();
    fx.keyring.remove(&account);
    assert!(matches!(
        engine.unlock_with_keyring().await,
        Err(VaultError::Keyring(_))
    ));
    // Entry replaced by something else.
    fx.keyring.overwrite(&account, &[1; 32]);
    let err = engine.unlock_with_keyring().await.unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err}");
    assert!(!engine.is_unlocked().await);
    engine.unlock(&pw(PW)).await.unwrap();

    // Re-enable (new keyring KEK), then disable: entry and wrap are deleted.
    engine.set_keyring_unlock(true).await.unwrap();
    engine.lock().await;
    engine.unlock_with_keyring().await.unwrap();
    engine.set_keyring_unlock(false).await.unwrap();
    assert!(fx.keyring.accounts().is_empty());
    assert!(
        meta(engine.store(), keys::LMK_WRAPPED_KEYRING)
            .await
            .is_none()
    );
    assert_eq!(
        engine.unlock_with_keyring().await.err(),
        Some(VaultError::KeyringNotEnabled)
    );
    engine.lock().await;
    assert_eq!(
        engine.set_keyring_unlock(true).await.err(),
        Some(VaultError::Locked)
    );
}

#[tokio::test]
async fn keyring_unavailable_at_first_run() {
    let fx = Fixture::new();
    fx.keyring.set_unavailable(true);
    let report = fx.engine().initialize(&pw(PW), true).await.unwrap();
    assert!(report.keyring_error.is_some());
    assert!(!fx.engine().status().await.unwrap().keyring_enabled);
    assert_eq!(
        fx.engine().unlock_with_keyring().await.err(),
        Some(VaultError::KeyringNotEnabled)
    );
}

#[tokio::test]
async fn forgot_password_via_keyring_sets_a_new_password() {
    let fx = Fixture::new();
    let engine = fx.initialized(true).await;
    let id = ItemId::new();
    engine.put_view(id, None, site("kept", "pw")).await.unwrap();
    let before = engine.get(id).await.unwrap();
    let old_kdf = meta(engine.store(), keys::KDF).await.unwrap();
    drop(engine);

    let engine = fx.engine();
    // Some failed attempts first: the reset clears them.
    engine.unlock(&pw("forgotten")).await.unwrap_err();
    let report = engine.reset_password_with_keyring(&pw(PW2)).await.unwrap();
    assert_eq!(report.method, UnlockMethod::Keyring);
    assert!(engine.is_unlocked().await);
    assert_eq!(engine.get(id).await.unwrap(), before);
    assert_ne!(
        meta(engine.store(), keys::KDF).await.unwrap(),
        old_kdf,
        "new salt"
    );
    assert_eq!(engine.status().await.unwrap().backoff.failures, 0);
    drop(engine);

    let engine = fx.engine();
    assert_eq!(
        failures(&engine.unlock(&pw(PW)).await.unwrap_err()),
        Some(1)
    );
    engine.unlock(&pw(PW2)).await.unwrap();
    assert_eq!(engine.get(id).await.unwrap(), before);
    // The keyring still works after the reset.
    engine.lock().await;
    engine.unlock_with_keyring().await.unwrap();

    // Without keyring unlock there is no local recovery.
    let fx2 = Fixture::new();
    fx2.initialized(false).await;
    assert_eq!(
        fx2.engine()
            .reset_password_with_keyring(&pw(PW2))
            .await
            .err(),
        Some(VaultError::KeyringNotEnabled)
    );
}

#[tokio::test]
async fn two_databases_use_distinct_keyring_accounts() {
    let shared = MemKeyring::new();
    let mut a = Fixture::new();
    let mut b = Fixture::new();
    a.keyring = shared.clone();
    b.keyring = shared.clone();
    a.initialized(true).await;
    b.initialized(true).await;
    assert_eq!(shared.accounts().len(), 2);
    a.engine().unlock_with_keyring().await.unwrap();
    b.engine().unlock_with_keyring().await.unwrap();
}

// ------------------------------------------------------------ password change

#[tokio::test]
async fn change_password_rewraps_with_a_new_salt() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let old_kdf = KdfParams::from_cbor(&meta(engine.store(), keys::KDF).await.unwrap()).unwrap();
    assert_eq!(
        failures(
            &engine
                .change_password(&pw("wrong"), &pw(PW2))
                .await
                .unwrap_err()
        ),
        Some(1)
    );
    engine.change_password(&pw(PW), &pw(PW2)).await.unwrap();
    let new_kdf = KdfParams::from_cbor(&meta(engine.store(), keys::KDF).await.unwrap()).unwrap();
    assert_ne!(old_kdf.salt, new_kdf.salt);
    assert!(
        engine.is_unlocked().await,
        "a password change keeps the session"
    );
    engine.lock().await;
    assert_eq!(
        failures(&engine.unlock(&pw(PW)).await.unwrap_err()),
        Some(1)
    );
    engine.unlock(&pw(PW2)).await.unwrap();
}

#[tokio::test]
async fn unlock_rewraps_when_the_argon2_cost_changed() {
    let fx = Fixture::new();
    fx.initialized(false).await;
    let stronger = Argon2Cost {
        m_kib: KdfParams::MIN_M_KIB,
        t: 1,
        p: 1,
    };
    let engine = fx.engine_with_cost(stronger);
    engine.unlock(&pw(PW)).await.unwrap();
    let kdf = KdfParams::from_cbor(&meta(engine.store(), keys::KDF).await.unwrap()).unwrap();
    assert_eq!(kdf.cost(), stronger);
    assert_eq!(engine.kdf_runs(), 2, "unlock + re-wrap");
    engine.lock().await;
    engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!(engine.kdf_runs(), 3, "no second re-wrap");
}

// --------------------------------------------------------------------- tamper

#[tokio::test]
async fn out_of_bounds_kdf_params_are_rejected_before_argon2() {
    let fx = Fixture::new();
    fx.initialized(false).await;
    let engine = fx.engine();
    let stored = KdfParams::from_cbor(&meta(engine.store(), keys::KDF).await.unwrap()).unwrap();
    let cases = [
        // 8 GiB of memory: would hang or abort if Argon2 ran.
        KdfParams {
            m_kib: 8 * 1024 * 1024,
            ..stored
        },
        KdfParams {
            m_kib: 1024,
            ..stored
        },
        KdfParams { t: 1000, ..stored },
        KdfParams { p: 255, ..stored },
    ];
    for bad in cases {
        // Encoded by hand: `to_cbor` itself doesn't validate.
        engine
            .store()
            .meta()
            .set(keys::KDF, bad.to_cbor())
            .await
            .unwrap();
        let err = engine.unlock(&pw(PW)).await.unwrap_err();
        assert!(
            matches!(err, VaultError::Corrupt(ref m) if m.contains("meta.kdf")),
            "{err:?}"
        );
        assert_eq!(engine.kdf_runs(), 0);
    }
    // Garbage instead of CBOR.
    engine
        .store()
        .meta()
        .set(keys::KDF, b"junk".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        engine.unlock(&pw(PW)).await,
        Err(VaultError::Corrupt(_))
    ));
    assert_eq!(engine.kdf_runs(), 0);
    assert_eq!(engine.status().await.unwrap().backoff.failures, 0);

    // A different salt (in bounds): just a wrong password.
    let other = KdfParams {
        salt: [9; 16],
        ..stored
    };
    engine
        .store()
        .meta()
        .set(keys::KDF, other.to_cbor())
        .await
        .unwrap();
    assert_eq!(
        failures(&engine.unlock(&pw(PW)).await.unwrap_err()),
        Some(1)
    );
}

#[tokio::test]
async fn tampered_item_envelopes_are_skipped() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let good = ItemId::new();
    let bad = ItemId::new();
    engine
        .put_view(good, None, site("good", "pw"))
        .await
        .unwrap();
    engine.put_view(bad, None, site("bad", "pw")).await.unwrap();
    engine.lock().await;
    let mut envelope = engine
        .store()
        .items()
        .get(bad)
        .await
        .unwrap()
        .unwrap()
        .envelope;
    let last = envelope.len() - 1;
    envelope[last] ^= 1;
    engine
        .store()
        .write(move |w| {
            w.conn().execute(
                "UPDATE items SET envelope = ?1 WHERE id = ?2",
                rusqlite::params![envelope, bad.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let report = engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!((report.items, report.undecryptable), (1, 1));
    assert!(engine.get(good).await.unwrap().is_some());
    assert!(engine.get(bad).await.unwrap().is_none());
}

// ---------------------------------------------------------------- item rules

#[tokio::test]
async fn delete_writes_a_tombstone() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let id = ItemId::new();
    engine.put_view(id, None, site("gone", "pw")).await.unwrap();
    assert!(engine.delete(id).await.unwrap());
    assert!(!engine.delete(id).await.unwrap());
    assert!(engine.get(id).await.unwrap().is_none());
    let row = engine.store().items().get(id).await.unwrap().unwrap();
    assert!(row.deleted && row.dirty);
    engine.lock().await;
    engine.unlock(&pw(PW)).await.unwrap();
    assert!(engine.list(ItemKind::Site).await.unwrap().is_empty());
    // Writing the id again starts a new body.
    assert!(engine.put_view(id, None, site("back", "pw")).await.unwrap());
    assert_eq!(engine.list(ItemKind::Site).await.unwrap().len(), 1);
}

#[tokio::test]
async fn items_are_dirty_and_queued_with_hlc_persisted() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let hlc0 = engine.store().meta().hlc_last().await.unwrap().unwrap();
    let id = ItemId::new();
    engine.put_view(id, None, site("x", "pw")).await.unwrap();
    let row = engine.store().items().get(id).await.unwrap().unwrap();
    assert!(row.dirty);
    assert_eq!(Some(row.vault_id), engine.personal_vault().await);
    let hlc1 = engine.store().meta().hlc_last().await.unwrap().unwrap();
    assert!(hlc1 > hlc0);
    let outbox = engine.store().outbox().list(row.vault_id).await.unwrap();
    assert_eq!(outbox.len(), 1);
}

#[tokio::test]
async fn wrong_kind_and_read_only_items_are_refused() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let id = ItemId::new();
    engine.put_view(id, None, site("x", "pw")).await.unwrap();
    let wrong = engine
        .put_view(
            id,
            None,
            item::SiteFolder {
                name: "f".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(wrong, VaultError::WrongKind { .. }), "{wrong:?}");

    // An item written by a newer courier-ftp (schema 99).
    let newer = ItemId::new();
    engine
        .put(ItemWrite {
            id: newer,
            kind: ItemKind::Bookmark,
            vault: None,
            edit: Box::new(|body, clock, device| {
                body.schema_version = 99;
                body.set("name", "from the future", clock, device);
            }),
        })
        .await
        .unwrap();
    engine.lock().await;
    let report = engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!(report.read_only, 1);
    assert!(engine.get(newer).await.unwrap().unwrap().read_only);
    assert!(engine.store().is_read_only(newer));
    let edit = engine
        .put(ItemWrite {
            id: newer,
            kind: ItemKind::Bookmark,
            vault: None,
            edit: Box::new(|body, clock, device| {
                body.set("name", "edited", clock, device);
            }),
        })
        .await;
    assert_eq!(edit, Err(VaultError::ReadOnlyItem(newer)));
    assert_eq!(
        engine.delete(newer).await,
        Err(VaultError::ReadOnlyItem(newer))
    );
}

#[tokio::test]
async fn store_passwords_off_never_writes_passwords() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let id = ItemId::new();
    engine.put_view(id, None, site("x", "first")).await.unwrap();
    engine.set_store_passwords(false);
    let mut s = site("x", "second");
    s.comments = "edited".into();
    engine.put_view(id, None, s).await.unwrap();
    engine.lock().await;
    engine.unlock(&pw(PW)).await.unwrap();
    let item = engine.get(id).await.unwrap().unwrap();
    let view: Site = item.view().unwrap();
    assert!(view.password.is_none(), "the stored password was erased");
    assert_eq!(view.comments, "edited");
}

#[tokio::test]
async fn backup_export_round_trips() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let id = ItemId::new();
    engine.put_view(id, None, site("x", "pw")).await.unwrap();
    let file = engine.export_backup(&pw("backup password")).await.unwrap();
    let items = backup::open(&file, &pw("backup password")).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, id);
    assert_eq!(items[0].body, engine.get(id).await.unwrap().unwrap().body);
    engine.lock().await;
    assert_eq!(
        engine.export_backup(&pw("x")).await.err(),
        Some(VaultError::Locked)
    );
}

// ----------------------------------------------------------------- trust store

fn ed25519(seed: u8) -> HostKey {
    let mut blob = Vec::new();
    for f in [&b"ssh-ed25519"[..], &[seed; 32]] {
        blob.extend_from_slice(&u32::try_from(f.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(f);
    }
    HostKey::from_blob(blob).unwrap()
}

#[tokio::test]
async fn vault_host_key_store_persists_known_hosts() {
    let fx = Fixture::new();
    let engine = fx.initialized(false).await;
    let added = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();

    // The app's slot: locked memory store until unlock, then the vault store.
    let slot = HostKeyStoreSlot::new(Arc::new(MemoryHostKeyStore::locked()));
    assert!(!slot.can_remember().await);
    slot.replace(Arc::new(VaultHostKeyStore::new(Arc::new(engine.clone()))));
    assert!(slot.can_remember().await);
    slot.remember(KnownHost::new("Web01.Example.com", 22, ed25519(1), added))
        .await
        .unwrap();
    assert_eq!(engine.list(ItemKind::KnownHost).await.unwrap().len(), 1);

    // After a restart the key is still trusted.
    drop(engine);
    let engine = fx.engine();
    let store = VaultHostKeyStore::new(Arc::new(engine.clone()));
    assert!(!store.can_remember().await);
    assert!(store.keys_for("web01.example.com", 22).await.is_err());
    engine.unlock(&pw(PW)).await.unwrap();
    let keys = store.keys_for("web01.example.com", 22).await.unwrap();
    assert_eq!(
        keys,
        [KnownHost::new("web01.example.com", 22, ed25519(1), added)]
    );
    assert!(
        store
            .forget("web01.example.com", 22, "ssh-ed25519")
            .await
            .unwrap()
    );
    assert!(store.list().await.unwrap().is_empty());
}
