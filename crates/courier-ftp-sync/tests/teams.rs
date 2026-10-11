//! T89 against an in-process `courier-ftp-server` (in-memory store): teams
//! and shared vaults with several accounts, each on its own device — org,
//! invite, accept, share a vault, read-only members, revoke → key rotation,
//! crash resume, safety numbers and key-change detection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{Device, PW, PW2, PW3, Server};
use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{ItemId, Site, VaultId};
use courier_ftp_core::vault::{ItemVault, ItemVaultExt, VaultError};
use courier_ftp_crypto::account::generate_account_keys;
use courier_ftp_crypto::envelope::open_item;
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_proto::orgs::Role;
use courier_ftp_proto::sync::Permission;
use courier_ftp_store::PinState;
use courier_ftp_sync::engine::{EngineConfig, SyncEngine};
use courier_ftp_sync::rotation::RotationOptions;
use courier_ftp_sync::status::{SyncEvent, SyncStatus};
use courier_ftp_sync::teams::TeamError;
use courier_ftp_sync::trust::TrustError;
use courier_ftp_sync::{RotationError, SyncSession, Teams};
use pretty_assertions::assert_eq;
use tokio::sync::mpsc;
use uuid::Uuid;

fn mt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// A manual engine (no WS, no timers) with an event receiver.
fn manual(session: &SyncSession) -> (SyncEngine, mpsc::UnboundedReceiver<SyncEvent>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let cfg = EngineConfig {
        websocket: false,
        push_debounce: Duration::from_millis(50),
        ..EngineConfig::default()
    };
    (session.engine(cfg, Some(tx)), rx)
}

fn drain(rx: &mut mpsc::UnboundedReceiver<SyncEvent>) -> Vec<SyncEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn no_progress(_: courier_ftp_sync::RotationProgress) {}

/// One person: a device, its session, teams handle and engine.
struct Person {
    email: &'static str,
    dev: Device,
    session: SyncSession,
    teams: Teams,
    engine: SyncEngine,
    events: mpsc::UnboundedReceiver<SyncEvent>,
}

impl Person {
    async fn new(server: &Server, name: &str, email: &'static str, pw: &str) -> Self {
        let dev = Device::new(name, pw).await;
        let session = dev.register(server, email, pw).await;
        let teams = session.teams().await.unwrap();
        let (engine, events) = manual(&session);
        Self {
            email,
            dev,
            session,
            teams,
            engine,
            events,
        }
    }

    fn id(&self) -> Uuid {
        self.teams.me()
    }

    async fn sync(&mut self) -> SyncStatus {
        self.engine.sync_once().await
    }

    async fn add_site(&self, vault: VaultId, name: &str, host: &str) -> ItemId {
        let mut site = Site::new(name, Protocol::Sftp, host);
        site.user = "deploy".into();
        let id = ItemId::new();
        self.dev
            .vault
            .put_view(id, Some(vault), site)
            .await
            .unwrap();
        id
    }

    async fn has_vault(&self, vault: VaultId) -> bool {
        self.dev.vault.loaded_vaults().await.contains(&vault)
    }
}

/// Owner alice with org "Acme", and bob invited (by email, link copied) and
/// accepted as `member`.
async fn team(server: &Server) -> (Person, Person, Uuid) {
    let alice = Person::new(server, "alice-laptop", "alice@example.com", PW).await;
    let bob = Person::new(server, "bob-laptop", "bob@example.com", PW2).await;
    let org = alice.teams.create_org("Acme").await.unwrap();
    assert_eq!(org.role, Role::Owner);
    let invite = alice
        .teams
        .invite(org.id, Some(bob.email), Role::Member)
        .await
        .unwrap();
    assert!(!invite.emailed, "no SMTP: the link is handed out");
    let link = invite.link.clone().unwrap();
    assert!(link.starts_with("https://sync.example.test/invite/"));
    let accepted = bob.teams.accept_invite(&link).await.unwrap();
    assert_eq!((accepted.org_id, accepted.role), (org.id, Role::Member));
    // The link is single-use.
    assert!(bob.teams.accept_invite(&link).await.is_err());
    let orgs = bob.teams.list_orgs().await.unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].name, "Acme");
    (alice, bob, org.id)
}

#[test]
fn owner_shares_a_vault_member_sees_items_read_only_cannot_edit() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;

        // A team vault with a site.
        let vault = alice.teams.create_vault(org, "Production").await.unwrap();
        let site = alice.add_site(vault, "web01", "web01.example.com").await;
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        assert_eq!(
            alice.teams.vault_names().await.unwrap().get(&vault),
            Some(&"Production".to_owned())
        );

        // A plain member does not see vaults they have no grant on.
        let listed = bob.teams.org_vaults(org).await;
        assert!(listed.unwrap().iter().all(|v| v.view.id != vault.uuid()));
        assert_eq!(bob.sync().await, SyncStatus::Synced);
        assert!(!bob.has_vault(vault).await);

        // Alice grants read: bob's keys are pinned on first sight.
        alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap();
        let pin = alice.teams.trust().pin(bob.id()).await.unwrap().unwrap();
        assert_eq!(pin.state(), PinState::Pinned);

        // Bob's engine adopts it after verifying the grant against alice's
        // pinned key, and pulls the site.
        assert_eq!(bob.sync().await, SyncStatus::Synced);
        assert!(bob.has_vault(vault).await);
        let events = drain(&mut bob.events);
        assert!(
            events.iter().any(|e| matches!(
                e,
                SyncEvent::VaultAdded { vault: v, name: Some(n) } if *v == vault && n == "Production"
            )),
            "{events:?}"
        );
        let got = bob.dev.site(site).await.unwrap();
        assert_eq!(got.host, "web01.example.com");
        assert_eq!(
            bob.teams.vault_names().await.unwrap().get(&vault),
            Some(&"Production".to_owned())
        );
        assert_eq!(
            bob.teams
                .trust()
                .pin(alice.id())
                .await
                .unwrap()
                .unwrap()
                .state(),
            PinState::Pinned,
            "the granter was pinned"
        );

        // Read-only: the vault engine refuses edits and new items.
        assert!(bob.dev.vault.is_vault_read_only(vault).await);
        let mut edited = got.clone();
        edited.host = "evil.example.com".into();
        let err = bob.dev.vault.put_view(site, None, edited).await.unwrap_err();
        assert_eq!(err, VaultError::ReadOnlyVault(vault));
        let err = bob
            .dev
            .vault
            .put_view(ItemId::new(), Some(vault), Site::new("x", Protocol::Ftp, "x"))
            .await
            .unwrap_err();
        assert_eq!(err, VaultError::ReadOnlyVault(vault));
        assert!(matches!(
            bob.dev.vault.delete(site).await,
            Err(VaultError::ReadOnlyVault(_))
        ));

        // Upgraded to write: bob's edit reaches alice.
        alice
            .teams
            .grant(vault, bob.id(), Permission::Write)
            .await
            .unwrap();
        assert_eq!(bob.sync().await, SyncStatus::Synced);
        assert!(!bob.dev.vault.is_vault_read_only(vault).await);
        bob.dev
            .edit_site(site, |s| s.host = "web02.example.com".into())
            .await;
        assert_eq!(bob.sync().await, SyncStatus::Synced);
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        assert_eq!(
            alice.dev.site(site).await.unwrap().host,
            "web02.example.com"
        );

        // The audit log has the story, ids only.
        let page = alice.teams.audit(org, None, 100).await.unwrap();
        let kinds: Vec<&str> = page.events.iter().map(|e| e.kind.as_str()).collect();
        for k in ["invite.sent", "invite.accepted", "vault.created", "vault.member_granted"] {
            assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
        }
        // Members can't read it.
        assert!(bob.teams.audit(org, None, 10).await.is_err());

        // Alice's personal vault is not visible to bob.
        let personal = alice.add_site(
            alice.dev.vault.personal_vault().await.unwrap(),
            "home",
            "home.example.com",
        );
        let personal = personal.await;
        alice.sync().await;
        bob.sync().await;
        assert!(bob.dev.site(personal).await.is_none());
    });
}

#[test]
fn read_only_member_cannot_push_even_bypassing_the_engine() {
    mt().block_on(async {
        use courier_ftp_proto::sync::{PushChange, PushRequest};
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;
        let vault = alice.teams.create_vault(org, "Shared").await.unwrap();
        let site = alice.add_site(vault, "db", "db.example.com").await;
        alice.sync().await;
        alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap();
        bob.sync().await;
        // Bob crafts a push with the item he pulled.
        let row = bob.dev.store.items().get(site).await.unwrap().unwrap();
        let token = bob.session.tokens().access().await.unwrap();
        let err = bob
            .session
            .tokens()
            .api()
            .push(
                &token,
                vault.uuid(),
                &PushRequest {
                    changes: vec![PushChange {
                        id: site.uuid(),
                        base_revision: u64::try_from(row.revision).unwrap(),
                        key_version: row.key_version,
                        envelope: row.envelope,
                        deleted: false,
                    }],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some(courier_ftp_proto::ErrorCode::Forbidden));
    });
}

#[test]
fn revoking_a_member_rotates_the_key_and_they_cannot_read_new_items() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;
        let carol = Person::new(&server, "carol-laptop", "carol@example.com", PW3).await;
        let mut carol = carol;
        let inv = alice.teams.invite(org, None, Role::Member).await.unwrap();
        carol
            .teams
            .accept_invite(inv.link.as_deref().unwrap())
            .await
            .unwrap();

        let vault = alice.teams.create_vault(org, "Ops").await.unwrap();
        let old_site = alice.add_site(vault, "old", "old.example.com").await;
        alice.sync().await;
        for p in [&bob, &carol] {
            alice
                .teams
                .grant(vault, p.id(), Permission::Write)
                .await
                .unwrap();
        }
        bob.sync().await;
        carol.sync().await;
        assert!(bob.dev.site(old_site).await.is_some());
        let (v1, bob_old_key) = bob.dev.vault.vault_key(vault).await.unwrap();
        assert_eq!(v1, 1);

        // Revoke bob → rotation.
        let report = alice
            .teams
            .revoke_and_rotate(vault, bob.id(), &no_progress)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.key_version, 2);
        assert_eq!(report.members, 2, "alice and carol");
        assert!(report.items >= 1);

        // Bob's device drops the vault.
        bob.sync().await;
        assert!(!bob.has_vault(vault).await);
        assert!(
            drain(&mut bob.events)
                .iter()
                .any(|e| matches!(e, SyncEvent::VaultRemoved { vault: v } if *v == vault))
        );

        // Alice and carol install the new key and keep syncing.
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        assert_eq!(alice.dev.vault.vault_key(vault).await.unwrap().0, 2);
        let new_site = alice.add_site(vault, "new", "new.example.com").await;
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        assert_eq!(carol.sync().await, SyncStatus::Synced);
        assert_eq!(carol.dev.vault.vault_key(vault).await.unwrap().0, 2);
        assert_eq!(
            carol.dev.site(new_site).await.unwrap().host,
            "new.example.com"
        );
        assert_eq!(
            carol.dev.site(old_site).await.unwrap().host,
            "old.example.com"
        );

        // Bob can't pull any more, and the old key doesn't open new items.
        let token = bob.session.tokens().access().await.unwrap();
        assert!(
            bob.session
                .tokens()
                .api()
                .pull(&token, vault.uuid(), 0, 100)
                .await
                .is_err()
        );
        let token = alice.session.tokens().access().await.unwrap();
        let page = alice
            .session
            .tokens()
            .api()
            .pull(&token, vault.uuid(), 0, 100)
            .await
            .unwrap();
        let item = page.items.iter().find(|i| i.id == new_site.uuid()).unwrap();
        assert_eq!(item.key_version, 2);
        assert!(
            open_item(
                |_| Some(&bob_old_key),
                vault.as_bytes(),
                new_site.as_bytes(),
                &item.envelope
            )
            .is_err()
        );
        // Every item on the server is under the new key.
        assert!(page.items.iter().all(|i| i.key_version == 2));
    });
}

#[test]
fn safety_numbers_and_a_changed_key_blocks_grants_until_accepted() {
    mt().block_on(async {
        let server = Server::start().await;
        let (alice, bob, org) = team(&server).await;
        let vault = alice.teams.create_vault(org, "Keys").await.unwrap();

        // Both sides compute the same 60-digit safety number.
        alice.teams.member_keys(bob.id()).await.unwrap();
        bob.teams.member_keys(alice.id()).await.unwrap();
        let sa = alice.teams.safety_number(bob.id()).await.unwrap();
        let sb = bob.teams.safety_number(alice.id()).await.unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.chars().filter(char::is_ascii_digit).count(), 60);
        alice.teams.mark_verified(bob.id()).await.unwrap();
        let members = alice.teams.org_members(org).await.unwrap();
        let bob_entry = members
            .iter()
            .find(|m| m.member.user_id == bob.id())
            .unwrap();
        assert_eq!(bob_entry.state(), Some(PinState::Verified));
        assert!(members.iter().any(|m| m.is_me));

        // The server swaps bob's public keys (a compromised server, or bob
        // reset his account).
        let fake = generate_account_keys(&mut os_rng()).public();
        let bob_id = bob.id();
        server.mem.with_data(|d| {
            let row = d.account_keys.get_mut(&bob_id).unwrap();
            row.x25519_pub = fake.x25519.to_vec();
            row.ed25519_pub = fake.ed25519.to_vec();
        });

        // Granting is refused, and the change is visible.
        let err = alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap_err();
        assert_eq!(err, TeamError::Trust(TrustError::KeyChanged(bob.id())));
        let members = alice.teams.org_members(org).await.unwrap();
        let bob_entry = members
            .iter()
            .find(|m| m.member.user_id == bob.id())
            .unwrap();
        assert_eq!(bob_entry.state(), Some(PinState::KeyChanged));
        let changed = alice.teams.safety_number(bob.id()).await.unwrap();
        assert_ne!(changed, sa, "the new key's number is shown");
        assert!(matches!(
            alice.teams.mark_verified(bob.id()).await,
            Err(TeamError::Trust(TrustError::KeyChanged(_)))
        ));

        // Accepting the new key unblocks grants.
        assert!(alice.teams.accept_new_key(bob.id(), false).await.unwrap());
        assert_eq!(
            alice
                .teams
                .trust()
                .pin(bob.id())
                .await
                .unwrap()
                .unwrap()
                .state(),
            PinState::Pinned
        );
        alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap();
    });
}

#[test]
fn a_changed_member_key_blocks_the_rotation_commit() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;
        let carol = Person::new(&server, "carol-laptop", "carol@example.com", PW3).await;
        let inv = alice.teams.invite(org, None, Role::Member).await.unwrap();
        carol
            .teams
            .accept_invite(inv.link.as_deref().unwrap())
            .await
            .unwrap();
        let vault = alice.teams.create_vault(org, "Ops").await.unwrap();
        alice.add_site(vault, "a", "a.example.com").await;
        alice.sync().await;
        for p in [&bob, &carol] {
            alice
                .teams
                .grant(vault, p.id(), Permission::Write)
                .await
                .unwrap();
        }
        bob.sync().await;

        // Carol's key changes on the server; bob is revoked.
        let fake = generate_account_keys(&mut os_rng()).public();
        let carol_id = carol.id();
        server.mem.with_data(|d| {
            let row = d.account_keys.get_mut(&carol_id).unwrap();
            row.x25519_pub = fake.x25519.to_vec();
            row.ed25519_pub = fake.ed25519.to_vec();
        });
        let err = alice
            .teams
            .revoke_and_rotate(vault, bob.id(), &no_progress)
            .await
            .unwrap_err();
        match &err {
            RotationError::UntrustedMembers(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].user, carol_id);
            }
            other => panic!("unexpected {other:?}"),
        }
        // Pushes are paused while the rotation is open.
        assert!(alice.teams.has_pending_rotation(vault).await);
        let views = {
            let token = alice.session.tokens().access().await.unwrap();
            alice
                .session
                .tokens()
                .api()
                .list_vaults(&token)
                .await
                .unwrap()
        };
        assert!(
            views
                .iter()
                .find(|v| v.id == vault.uuid())
                .unwrap()
                .rotation
                .is_some()
        );

        // Carol is accepted after comparing numbers; the rotation resumes.
        alice.teams.accept_new_key(carol_id, true).await.unwrap();
        let report = alice.teams.rotate(vault, &no_progress).await.unwrap();
        assert!(report.resumed);
        assert_eq!(report.key_version, 2);
        assert!(!alice.teams.has_pending_rotation(vault).await);
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        bob.sync().await;
        assert!(!bob.has_vault(vault).await);
    });
}

#[test]
fn an_interrupted_rotation_resumes_on_the_same_device() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;
        let vault = alice.teams.create_vault(org, "Big").await.unwrap();
        let mut ids = Vec::new();
        for i in 0..7 {
            ids.push(
                alice
                    .add_site(vault, &format!("s{i}"), &format!("s{i}.example.com"))
                    .await,
            );
        }
        alice.sync().await;
        alice
            .teams
            .grant(vault, bob.id(), Permission::Write)
            .await
            .unwrap();
        bob.sync().await;

        // "Crash" after the first chunk of 2.
        let opts = RotationOptions {
            chunk_items: 2,
            stop_after_chunks: Some(1),
        };
        let err = alice
            .teams
            .rotate_with(vault, opts, &no_progress)
            .await
            .unwrap_err();
        assert_eq!(err, RotationError::Interrupted);
        assert!(alice.teams.has_pending_rotation(vault).await);

        // Meanwhile bob's pushes are paused, not lost.
        bob.dev
            .edit_site(ids[0], |s| s.comments = "while rotating".into())
            .await;
        bob.sync().await;
        assert_eq!(bob.dev.store.outbox().pending_count().await.unwrap(), 1);

        // Resume (a new Teams handle, as after a restart).
        let teams = alice.session.teams().await.unwrap();
        let report = teams
            .rotate_with(
                vault,
                RotationOptions {
                    chunk_items: 2,
                    stop_after_chunks: None,
                },
                &no_progress,
            )
            .await
            .unwrap();
        assert!(report.resumed);
        assert_eq!(report.items, 7);
        assert!(report.uploaded < 7, "{report:?}");
        assert_eq!(report.members, 2);

        // Everyone converges on key 2, bob's paused edit included.
        assert_eq!(bob.sync().await, SyncStatus::Synced);
        assert_eq!(bob.dev.vault.vault_key(vault).await.unwrap().0, 2);
        assert_eq!(bob.sync().await, SyncStatus::Synced);
        assert_eq!(bob.dev.store.outbox().pending_count().await.unwrap(), 0);
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        assert_eq!(
            alice.dev.site(ids[0]).await.unwrap().comments,
            "while rotating"
        );
        for id in &ids {
            assert!(alice.dev.site(*id).await.is_some());
        }
    });
}

#[test]
fn an_abandoned_rotation_is_discarded_and_reported() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, _bob, org) = team(&server).await;
        let vault = alice.teams.create_vault(org, "V").await.unwrap();
        alice.add_site(vault, "a", "a.example.com").await;
        alice.add_site(vault, "z", "z.example.com").await;
        alice.sync().await;
        let opts = RotationOptions {
            chunk_items: 1,
            stop_after_chunks: Some(1),
        };
        assert_eq!(
            alice.teams.rotate_with(vault, opts, &no_progress).await,
            Err(RotationError::Interrupted)
        );

        // 16 minutes later the rotation is abandoned: reported once…
        server.clock.advance(chrono::Duration::minutes(16));
        drain(&mut alice.events);
        alice.sync().await;
        assert!(
            drain(&mut alice.events)
                .iter()
                .any(|e| matches!(e, SyncEvent::RotationAbandoned { vault: v } if *v == vault))
        );
        // …and GC discards it, so pushes work again.
        use courier_ftp_server::auth::Clock as _;
        let discarded = server
            .state
            .sync()
            .store()
            .discard_abandoned_rotations(server.clock.now())
            .await
            .unwrap();
        assert_eq!(discarded, vec![vault.uuid()]);
        alice.add_site(vault, "b", "b.example.com").await;
        assert_eq!(alice.sync().await, SyncStatus::Synced);
        assert_eq!(alice.dev.store.outbox().pending_count().await.unwrap(), 0);
        // A fresh rotation starts over.
        let report = alice.teams.rotate(vault, &no_progress).await.unwrap();
        assert_eq!(report.key_version, 2);
    });
}

#[test]
fn removing_a_member_from_the_org_rotates_and_leaving_removes_vaults() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;
        let vault = alice.teams.create_vault(org, "Ops").await.unwrap();
        alice.add_site(vault, "a", "a.example.com").await;
        alice.sync().await;
        alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap();
        bob.sync().await;
        assert!(bob.has_vault(vault).await);

        let report = alice
            .teams
            .remove_member(org, bob.id(), &no_progress)
            .await
            .unwrap();
        assert_eq!(report.rotations.len(), 1);
        assert_eq!(report.rotations[0].0, vault);
        assert_eq!(report.rotations[0].1.as_ref().unwrap().key_version, 2);
        bob.sync().await;
        assert!(!bob.has_vault(vault).await);
        assert!(bob.teams.list_orgs().await.unwrap().is_empty());

        // Leaving: a re-invited bob leaves; the org's vaults leave his device,
        // his personal vault stays.
        let inv = alice.teams.invite(org, None, Role::Member).await.unwrap();
        bob.teams
            .accept_invite(inv.link.as_deref().unwrap())
            .await
            .unwrap();
        alice.sync().await;
        alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap();
        bob.sync().await;
        assert!(bob.has_vault(vault).await);
        let removed = bob.teams.leave_org(org).await.unwrap();
        assert_eq!(removed, vec![vault]);
        assert!(!bob.has_vault(vault).await);
        assert!(bob.dev.vault.personal_vault().await.is_some());
    });
}

#[test]
fn copy_and_move_sites_between_personal_and_team_vaults() {
    mt().block_on(async {
        let server = Server::start().await;
        let (mut alice, mut bob, org) = team(&server).await;
        let vault = alice.teams.create_vault(org, "Ops").await.unwrap();
        let personal = alice.dev.vault.personal_vault().await.unwrap();
        let a = alice.add_site(personal, "mine", "mine.example.com").await;
        let copy = alice.teams.copy_site_to_vault(a, vault).await.unwrap();
        assert_ne!(copy, a);
        assert!(alice.dev.site(a).await.is_some());
        let moved = alice.teams.move_site_to_vault(a, vault).await.unwrap();
        assert!(alice.dev.site(a).await.is_none());
        alice.sync().await;
        alice
            .teams
            .grant(vault, bob.id(), Permission::Read)
            .await
            .unwrap();
        bob.sync().await;
        assert_eq!(bob.dev.site(moved).await.unwrap().host, "mine.example.com");
        assert!(bob.dev.site(copy).await.is_some());
    });
}
