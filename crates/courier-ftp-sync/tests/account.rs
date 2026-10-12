//! T87 against an in-process `courier-ftp-server` (in-memory store):
//! registration, login on more devices, duplicates, password change,
//! recovery, devices, token refresh and logout.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Device, PW, PW2, PW3, Server, confirm, push_all, secret, setup_token};
use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{ItemId, Site, SiteFolder};
use courier_ftp_core::vault::{ItemVault, ItemVaultExt, VaultError, VaultState};
use courier_ftp_server::registration::RegistrationMode;
use courier_ftp_sync::account::{self, DuplicateChoice};
use courier_ftp_sync::{AccountError, Revoked, SyncSession};
use pretty_assertions::assert_eq;

const EMAIL: &str = "alice@example.com";

fn mt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn register_then_login_on_a_second_device_sees_the_same_sites() {
    mt().block_on(async {
        let server = Server::start().await;
        let a = Device::new("laptop", PW).await;
        a.add_site("db", "db.example.com", "root").await;
        a.add_site("web", "web.example.com", "deploy").await;
        assert!(!a.vault.status().await.unwrap().sync_account);

        let mut prepared = a.prepare(&server, EMAIL, PW).await;
        assert_eq!(prepared.recovery_words().len(), 24);
        // The recovery words must be re-typed first.
        let err = account::finish_registration(&a.vault, &prepared, None, &a.cfg)
            .await
            .unwrap_err();
        assert_eq!(err, AccountError::RecoveryNotConfirmed);
        assert!(!prepared.confirm_words(&["x", "y", "z"]));
        confirm(&mut prepared);
        let (registered, session_a) =
            account::finish_registration(&a.vault, &prepared, None, &a.cfg)
                .await
                .unwrap();
        assert_eq!(registered.queued, 2);
        assert_eq!(Some(registered.vault), a.vault.personal_vault().await);
        assert!(a.vault.status().await.unwrap().sync_account);
        let acct = session_a.account().await.unwrap().unwrap();
        assert_eq!((acct.email.as_str(), acct.key_version), (EMAIL, 1));
        assert_eq!(push_all(&a, &session_a).await, 2);

        // A second device: initialized with the same (account) password.
        let b = Device::new("desktop", PW).await;
        let req = Device::login_request(&server, EMAIL, PW);
        let login = account::start_login(&b.vault, &req, &b.cfg).await.unwrap();
        assert!(
            login.will_import(),
            "the new device's empty vault is replaced"
        );
        assert!(!login.password_differs());
        assert_eq!(login.preview().new_items, 0);
        let (logged_in, session_b) = login.commit().await.unwrap();
        assert_eq!(logged_in.downloaded, 2);
        assert_eq!(logged_in.vault, registered.vault);
        assert_eq!(b.vault.personal_vault().await, Some(registered.vault));
        assert_eq!(b.sites().await, a.sites().await);
        assert!(b.vault.status().await.unwrap().sync_account);

        // After a restart and unlock the session comes back from the store.
        let mut b = b;
        drop(session_b);
        b.restart();
        b.vault.unlock(&secret(PW)).await.unwrap();
        assert_eq!(b.sites().await.len(), 2);
        let session_b = SyncSession::open(&b.vault, b.cfg.clone())
            .await
            .unwrap()
            .unwrap();
        let devices = session_b.list_devices().await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices[0].current);
        assert_eq!(devices[0].name, "desktop");
        assert_eq!(devices[1].name, "laptop");
    });
}

#[test]
fn registration_needs_the_local_password_and_a_token_when_invite_only() {
    mt().block_on(async {
        let server = Server::start_with_mode(RegistrationMode::InviteOnly).await;
        server.set_setup_token("setup-token-123");
        let a = Device::new("laptop", PW).await;
        let wrong =
            account::prepare_registration(&a.vault, &server.url, EMAIL, &secret(PW2), &a.cfg)
                .await
                .unwrap_err();
        assert_eq!(wrong, AccountError::WrongLocalPassword);
        let bad_url = account::prepare_registration(
            &a.vault,
            "http://sync.example.com",
            EMAIL,
            &secret(PW),
            &a.cfg,
        )
        .await
        .unwrap_err();
        assert!(matches!(bad_url, AccountError::Local(_)), "{bad_url:?}");

        let mut prepared = a.prepare(&server, EMAIL, PW).await;
        confirm(&mut prepared);
        let err = account::finish_registration(&a.vault, &prepared, None, &a.cfg)
            .await
            .unwrap_err();
        assert!(matches!(err, AccountError::InviteRequired(_)), "{err:?}");
        let (_, _session) = account::finish_registration(
            &a.vault,
            &prepared,
            Some(&setup_token("setup-token-123")),
            &a.cfg,
        )
        .await
        .unwrap();

        // The same email again (another device): already registered.
        server
            .mem
            .with_data(|d| d.registration_mode = RegistrationMode::Open);
        let b = Device::new("desktop", PW).await;
        let mut prepared = b.prepare(&server, EMAIL, PW).await;
        confirm(&mut prepared);
        let err = account::finish_registration(&b.vault, &prepared, None, &b.cfg)
            .await
            .unwrap_err();
        assert_eq!(err, AccountError::AlreadyRegistered);
        // Already signed in: refused before anything is sent.
        let err = account::prepare_registration(&a.vault, &server.url, EMAIL, &secret(PW), &a.cfg)
            .await
            .unwrap_err();
        assert!(matches!(err, AccountError::Local(_)), "{err:?}");
    });
}

/// A device with local data logs in: duplicates are detected and each of the
/// three choices does what it says; references are remapped.
#[test]
fn duplicate_preview_and_the_three_choices() {
    mt().block_on(async {
        let server = Server::start().await;
        let a = Device::new("laptop", PW).await;
        let account_db = a.add_site("db", "db.example.com", "root").await;
        let session_a = a.register(&server, EMAIL, PW).await;
        push_all(&a, &session_a).await;

        for choice in [
            DuplicateChoice::KeepBoth,
            DuplicateChoice::KeepLocal,
            DuplicateChoice::KeepAccount,
        ] {
            let b = Device::new("desktop", PW).await;
            let folder = ItemId::new();
            b.vault
                .put_view(
                    folder,
                    None,
                    SiteFolder {
                        name: "work".into(),
                        ..SiteFolder::default()
                    },
                )
                .await
                .unwrap();
            let mut dup = Site::new("db (local)", Protocol::Sftp, "DB.example.com");
            dup.user = "root".into();
            dup.port = Some(22);
            dup.comments = "local note".into();
            let dup_id = ItemId::new();
            b.vault.put_view(dup_id, None, dup).await.unwrap();
            let mut other = Site::new("x", Protocol::Sftp, "x.example.com");
            other.parent = Some(folder);
            let other_id = ItemId::new();
            b.vault.put_view(other_id, None, other).await.unwrap();

            let req = Device::login_request(&server, EMAIL, PW);
            let mut login = account::start_login(&b.vault, &req, &b.cfg).await.unwrap();
            let preview = login.preview().clone();
            assert_eq!(preview.new_items, 2, "{preview:?}");
            assert_eq!(preview.duplicates.len(), 1);
            assert_eq!(preview.duplicates[0].local, dup_id);
            assert_eq!(preview.duplicates[0].account, account_db);
            assert_eq!(preview.duplicates[0].matched, "sftp root@db.example.com:22");
            assert!(login.preview_mut().set(dup_id, choice));
            let (done, _session) = login.commit().await.unwrap();
            let sites = b.sites().await;
            match choice {
                DuplicateChoice::KeepBoth => {
                    assert_eq!(done.imported, 3);
                    assert_eq!(sites.len(), 3, "{sites:?}");
                }
                DuplicateChoice::KeepLocal => {
                    assert_eq!(done.imported, 3);
                    assert_eq!(sites.len(), 2, "{sites:?}");
                    let db = b.site(account_db).await.unwrap();
                    assert_eq!(db.name, "db (local)");
                    assert_eq!(db.comments, "local note");
                }
                DuplicateChoice::KeepAccount => {
                    assert_eq!(done.imported, 2);
                    assert_eq!(sites.len(), 2, "{sites:?}");
                    let db = b.site(account_db).await.unwrap();
                    assert_eq!(db.name, "db");
                }
            }
            // Every imported item has a new id; references follow.
            assert!(b.site(dup_id).await.is_none());
            assert!(b.site(other_id).await.is_none());
            let folders = b.vault.list_views::<SiteFolder>().await.unwrap();
            assert_eq!(folders.len(), 1);
            let new_folder = folders[0].0.id;
            assert_ne!(new_folder, folder);
            let (_, x) = b
                .vault
                .list_views::<Site>()
                .await
                .unwrap()
                .into_iter()
                .find(|(_, s)| s.name == "x")
                .unwrap();
            assert_eq!(x.parent, Some(new_folder));
            // The old local vault is gone; the imported items are queued.
            assert_eq!(b.vault.loaded_vaults().await, vec![done.vault]);
            assert_eq!(
                b.store.outbox().pending_count().await.unwrap(),
                u64::try_from(done.imported).unwrap()
            );
        }
    });
}

#[test]
fn password_change_on_one_device_logs_out_the_other() {
    mt().block_on(async {
        let server = Server::start().await;
        let a = Device::new("laptop", PW).await;
        a.add_site("db", "db.example.com", "root").await;
        let session_a = a.register(&server, EMAIL, PW).await;
        push_all(&a, &session_a).await;
        let mut b = Device::new("desktop", PW).await;
        let session_b = b.login(&server, EMAIL, PW).await;
        assert_eq!(session_b.list_devices().await.unwrap().len(), 2);

        // Weak or wrong passwords change nothing.
        assert!(matches!(
            session_a
                .change_password(&secret(PW), &secret("abc"), None)
                .await,
            Err(AccountError::WeakPassword(_))
        ));
        assert_eq!(
            session_a
                .change_password(&secret(PW3), &secret(PW2), None)
                .await
                .unwrap_err(),
            AccountError::LoginFailed
        );

        let v = session_a
            .change_password(&secret(PW), &secret(PW2), None)
            .await
            .unwrap();
        assert_eq!(v, 2);
        // A keeps working and unlocks with the new password.
        assert_eq!(session_a.list_devices().await.unwrap().len(), 2);
        a.vault.lock().await;
        assert!(matches!(
            a.vault.unlock(&secret(PW)).await,
            Err(VaultError::WrongPassword { .. })
        ));
        a.vault.unlock(&secret(PW2)).await.unwrap();

        // B is logged out, but still unlocks locally with the old password.
        assert_eq!(
            session_b.list_devices().await.unwrap_err(),
            AccountError::NeedsLogin
        );
        drop(session_b);
        b.restart();
        b.vault.unlock(&secret(PW)).await.unwrap();
        assert_eq!(b.sites().await.len(), 1);
        // The old password no longer logs in; the new one does and re-wraps
        // the LMK (nothing imported: same personal vault).
        let req = Device::login_request(&server, EMAIL, PW);
        assert_eq!(
            account::start_login(&b.vault, &req, &b.cfg)
                .await
                .unwrap_err(),
            AccountError::LoginFailed
        );
        let req = Device::login_request(&server, EMAIL, PW2);
        let login = account::start_login(&b.vault, &req, &b.cfg).await.unwrap();
        assert!(login.password_differs());
        assert!(!login.will_import());
        let (done, session_b) = login.commit().await.unwrap();
        assert!(done.password_changed);
        assert_eq!(done.imported, 0);
        assert_eq!(session_b.list_devices().await.unwrap().len(), 2);
        assert_eq!(session_b.account().await.unwrap().unwrap().key_version, 2);
        b.vault.lock().await;
        assert!(b.vault.unlock(&secret(PW)).await.is_err());
        b.vault.unlock(&secret(PW2)).await.unwrap();
        assert_eq!(b.sites().await.len(), 1);
    });
}

#[test]
fn recovery_restores_access_with_the_24_words() {
    mt().block_on(async {
        let server = Server::start().await;
        let mut a = Device::new("laptop", PW).await;
        a.add_site("db", "db.example.com", "root").await;
        let mut prepared = a.prepare(&server, EMAIL, PW).await;
        let words = prepared.recovery_phrase();
        confirm(&mut prepared);
        let (_, session_a) = account::finish_registration(&a.vault, &prepared, None, &a.cfg)
            .await
            .unwrap();
        push_all(&a, &session_a).await;
        let b = Device::new("desktop", PW).await;
        let session_b = b.login(&server, EMAIL, PW).await;
        drop(session_a);

        // A forgot the password: restart, locked, sync account known.
        a.restart();
        let status = a.vault.status().await.unwrap();
        assert_eq!(status.state, VaultState::Locked);
        assert!(status.sync_account);
        let acct = account::load_account(&a.store).await.unwrap().unwrap();
        assert_eq!(acct.email, EMAIL);

        account::request_recovery_code(&server.url, EMAIL, &a.cfg)
            .await
            .unwrap();
        let code = server.recovery_code(EMAIL).await;
        // Wrong words or code change nothing.
        let mut other_words: Vec<&str> = words.split(' ').collect();
        other_words.swap(0, 1);
        let err = account::recover_locked_device(
            &a.vault,
            &server.url,
            EMAIL,
            &secret(&code),
            &secret(&other_words.join(" ")),
            &secret(PW3),
            &a.cfg,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AccountError::BadRecoveryPhrase(_)), "{err:?}");
        let err = account::recover_locked_device(
            &a.vault,
            &server.url,
            EMAIL,
            &secret("000000"),
            &secret(&words),
            &secret(PW3),
            &a.cfg,
        )
        .await
        .unwrap_err();
        assert_eq!(err, AccountError::BadRecoveryCode);

        let (recovered, session_a) = account::recover_locked_device(
            &a.vault,
            &server.url,
            EMAIL,
            &secret(&code),
            &secret(&words),
            &secret(PW3),
            &a.cfg,
        )
        .await
        .unwrap();
        assert_eq!(recovered.key_version, 2);
        // Unlocked, local data intact, signed in again.
        assert!(a.vault.is_unlocked().await);
        assert_eq!(a.sites().await.len(), 1);
        // The server logs devices out on recovery (tokens dropped) but keeps
        // them listed; this device resumed its own entry.
        let devices = session_a.list_devices().await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices[0].current && devices[0].name == "laptop");
        a.vault.lock().await;
        assert!(a.vault.unlock(&secret(PW)).await.is_err());
        a.vault.unlock(&secret(PW3)).await.unwrap();
        assert_eq!(a.sites().await.len(), 1);
        // A can still write and the session survives a restart.
        a.add_site("new", "new.example.com", "me").await;
        drop(session_a);
        a.restart();
        a.vault.unlock(&secret(PW3)).await.unwrap();
        let session_a = SyncSession::open(&a.vault, a.cfg.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(push_all(&a, &session_a).await, 1);

        // Every other device was logged out.
        assert_eq!(
            session_b.list_devices().await.unwrap_err(),
            AccountError::NeedsLogin
        );
    });
}

#[test]
fn token_refresh_race_results_in_one_refresh() {
    mt().block_on(async {
        let server = Server::start().await;
        let mut a = Device::new("laptop", PW).await;
        let session = a.register(&server, EMAIL, PW).await;
        drop(session);
        let session = SyncSession::open(&a.vault, a.cfg.clone())
            .await
            .unwrap()
            .unwrap();
        // The access token expires (15 min) on the device's clock.
        a.clock.advance(16 * 60 * 1000);
        let (x, y, z) = tokio::join!(
            session.list_devices(),
            session.list_devices(),
            session.list_devices()
        );
        assert!(x.is_ok() && y.is_ok() && z.is_ok(), "{x:?} {y:?} {z:?}");
        assert_eq!(session.tokens().refresh_count(), 1);
        // The rotated pair was persisted before use: after a restart the
        // stored refresh token is the new one (reusing the old one would
        // revoke the whole family).
        drop(session);
        a.restart();
        a.vault.unlock(&secret(PW)).await.unwrap();
        let session = SyncSession::open(&a.vault, a.cfg.clone())
            .await
            .unwrap()
            .unwrap();
        a.clock.advance(16 * 60 * 1000);
        assert!(session.list_devices().await.is_ok());
        assert_eq!(session.tokens().refresh_count(), 1);
    });
}

#[test]
fn devices_list_and_revoke() {
    mt().block_on(async {
        let server = Server::start().await;
        let a = Device::new("laptop", PW).await;
        a.add_site("db", "db.example.com", "root").await;
        let session_a = a.register(&server, EMAIL, PW).await;
        let b = Device::new("desktop", PW).await;
        let session_b = b.login(&server, EMAIL, PW).await;

        let list = session_a.list_devices().await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].current && list[0].name == "laptop");
        let b_id = list[1].id;
        assert_eq!(session_a.revoke_device(b_id).await.unwrap(), Revoked::Other);
        assert_eq!(
            session_b.list_devices().await.unwrap_err(),
            AccountError::NeedsLogin
        );
        assert_eq!(session_a.list_devices().await.unwrap().len(), 1);

        // Revoking this device is a local logout; the data stays.
        let me = session_a.list_devices().await.unwrap()[0].id;
        let Revoked::ThisDevice(report) = session_a.revoke_device(me).await.unwrap() else {
            panic!("expected a local logout");
        };
        assert!(report.revoked);
        assert_eq!(report.kept_items, 1);
        assert!(a.store.sync_state().get().await.unwrap().is_none());
        assert!(!a.vault.status().await.unwrap().sync_account);
        assert_eq!(a.sites().await.len(), 1);
        assert!(
            SyncSession::open(&a.vault, a.cfg.clone())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn logout_keeps_local_data_and_queues_it_for_a_later_login() {
    mt().block_on(async {
        let server = Server::start().await;
        let a = Device::new("laptop", PW).await;
        a.add_site("db", "db.example.com", "root").await;
        let session = a.register(&server, EMAIL, PW).await;
        push_all(&a, &session).await;
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 0);
        let report = session.logout().await.unwrap();
        assert!(report.revoked, "{report:?}");
        assert_eq!(report.kept_items, 1);
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 1);
        assert!(a.store.sync_state().get().await.unwrap().is_none());
        assert_eq!(a.sites().await.len(), 1);
        assert_eq!(
            session.list_devices().await.unwrap_err(),
            AccountError::NeedsLogin
        );
        // Logging in again: same personal vault, nothing imported.
        let req = Device::login_request(&server, EMAIL, PW);
        let login = account::start_login(&a.vault, &req, &a.cfg).await.unwrap();
        assert!(!login.will_import());
        let (_, session) = login.commit().await.unwrap();
        // Still queued as never synced (base 0): the engine's push merges it
        // with the server copy (T88).
        assert_eq!(a.store.outbox().pending_count().await.unwrap(), 1);
        assert!(session.list_devices().await.is_ok());
        assert_eq!(a.sites().await.len(), 1);
    });
}

#[test]
fn the_device_ids_and_errors_carry_no_secrets() {
    mt().block_on(async {
        let server = Server::start().await;
        let a = Device::new("laptop", PW).await;
        let mut prepared = a.prepare(&server, EMAIL, PW).await;
        let phrase = prepared.recovery_phrase();
        let dbg = format!("{prepared:?}");
        assert!(!dbg.contains(PW));
        for w in phrase.split(' ') {
            assert!(!dbg.contains(&format!("\"{w}\"")));
        }
        confirm(&mut prepared);
        let (_, session) = account::finish_registration(&a.vault, &prepared, None, &a.cfg)
            .await
            .unwrap();
        let dbg = format!("{session:?} {:?}", session.tokens());
        let raw = a.store.sync_state().get().await.unwrap().unwrap();
        let enc = raw.tokens_enc.unwrap();
        // The stored tokens are sealed (no JSON in clear).
        assert!(!enc.windows(3).any(|w| w == b"\"a\""));
        assert!(!dbg.contains("Bearer"));
        let _ = a.vault.loaded_vaults().await;
        assert!(ItemVault::is_unlocked(&a.vault).await);
    });
}
