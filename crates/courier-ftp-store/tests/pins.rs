//! The `pinned_keys` repository (ported from sverb `tests/pins.rs`; AC12).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::open;
use courier_ftp_crypto::fingerprint::key_fingerprint;
use courier_ftp_store::{
    PinObservation, PinState, PinTrust, PinnedKey, SetVerified, StoreError, VerifyOutcome,
};

const BOB: [u8; 16] = [0xb0; 16];

fn obs(user: [u8; 16], label: Option<&str>, x: u8, e: u8, is_self: bool) -> PinObservation {
    PinObservation {
        user_id: user,
        label: label.map(str::to_owned),
        x25519_pub: [x; 32],
        ed25519_pub: [e; 32],
        is_self,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_sight_pins_then_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let state = store
        .observe_pin(obs(BOB, Some("bob@example.test"), 1, 2, false))
        .await
        .unwrap();
    assert_eq!(state, PinState::FirstSeen);
    clock.set(5_000);
    let state = store
        .observe_pin(obs(BOB, None, 1, 2, false))
        .await
        .unwrap();
    assert_eq!(state, PinState::Unchanged);
    let pin = store.get_pin(BOB).await.unwrap().unwrap();
    assert_eq!(pin.fingerprint, key_fingerprint(&[1; 32], &[2; 32]));
    assert_eq!(pin.first_seen_at, 1_000);
    assert_eq!(pin.label.as_deref(), Some("bob@example.test"));
    assert_eq!(pin.trust(), PinTrust::Pinned);
    assert!(!pin.verified);
    assert!(!pin.is_self);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_is_parked_and_clears_verified() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    store
        .observe_pin(obs(BOB, None, 1, 2, false))
        .await
        .unwrap();
    clock.set(2_000);
    assert_eq!(
        store
            .set_verified(BOB, SetVerified::Verified)
            .await
            .unwrap(),
        VerifyOutcome::Set
    );
    let pin = store.get_pin(BOB).await.unwrap().unwrap();
    assert_eq!(pin.trust(), PinTrust::Verified);
    assert_eq!(pin.verified_at, Some(2_000));

    clock.set(3_000);
    let state = store
        .observe_pin(obs(BOB, None, 9, 2, false))
        .await
        .unwrap();
    assert_eq!(
        state,
        PinState::Changed {
            pinned: key_fingerprint(&[1; 32], &[2; 32]),
            seen: key_fingerprint(&[9; 32], &[2; 32]),
        }
    );
    let pin = store.get_pin(BOB).await.unwrap().unwrap();
    // The pin is not replaced, verified is cleared, the change is pending.
    assert_eq!(pin.x25519_pub, [1; 32]);
    assert_eq!(pin.trust(), PinTrust::KeyChanged);
    assert!(!pin.verified);
    assert_eq!(pin.verified_at, None);
    let change = pin.changed.clone().unwrap();
    assert_eq!((change.x25519_pub, change.seen_at), ([9; 32], 3_000));
    assert_eq!(
        pin.current_fingerprint(),
        key_fingerprint(&[9; 32], &[2; 32])
    );
    // Verifying is refused while the change is pending.
    assert_eq!(
        store
            .set_verified(BOB, SetVerified::Verified)
            .await
            .unwrap(),
        VerifyOutcome::KeyChangePending
    );
    // The old key again: still pending (the server flip-flopped).
    assert_eq!(
        store
            .observe_pin(obs(BOB, None, 1, 2, false))
            .await
            .unwrap(),
        PinState::Unchanged
    );
    assert_eq!(
        store.get_pin(BOB).await.unwrap().unwrap().trust(),
        PinTrust::KeyChanged
    );

    // Accept the new key: it moves over, unverified.
    clock.set(4_000);
    assert!(store.accept_key_change(BOB).await.unwrap());
    let pin = store.get_pin(BOB).await.unwrap().unwrap();
    assert_eq!(pin.x25519_pub, [9; 32]);
    assert_eq!(pin.fingerprint, key_fingerprint(&[9; 32], &[2; 32]));
    assert_eq!(pin.trust(), PinTrust::Pinned);
    assert!(!pin.verified);
    assert_eq!((pin.first_seen_at, pin.verified_at), (4_000, None));
    assert!(pin.changed.is_none());
    assert!(!store.accept_key_change(BOB).await.unwrap());
    assert_eq!(
        store
            .observe_pin(obs(BOB, None, 9, 2, false))
            .await
            .unwrap(),
        PinState::Unchanged
    );
    // Now it can be verified, and unverified again.
    clock.set(5_000);
    assert_eq!(
        store
            .set_verified(BOB, SetVerified::Verified)
            .await
            .unwrap(),
        VerifyOutcome::Set
    );
    assert_eq!(
        store.get_pin(BOB).await.unwrap().unwrap().verified_at,
        Some(5_000)
    );
    store
        .set_verified(BOB, SetVerified::Unverified)
        .await
        .unwrap();
    let pin = store.get_pin(BOB).await.unwrap().unwrap();
    assert_eq!((pin.verified, pin.verified_at), (false, None));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_self_first_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    store
        .observe_pin(obs(BOB, Some("bob"), 1, 2, false))
        .await
        .unwrap();
    store
        .observe_pin(obs([0xa1; 16], Some("alice"), 3, 4, true))
        .await
        .unwrap();
    let pins = store.list_pins().await.unwrap();
    assert_eq!(pins.len(), 2);
    assert!(pins[0].is_self);
    assert_eq!(pins[1].user_id, BOB);
    assert_eq!(
        store
            .set_verified([7; 16], SetVerified::Verified)
            .await
            .unwrap(),
        VerifyOutcome::NoPin
    );
    assert!(store.delete_pin(BOB).await.unwrap());
    assert!(!store.delete_pin(BOB).await.unwrap());
    assert!(store.get_pin(BOB).await.unwrap().is_none());
}

// Pins are never items, envelopes or outbox rows (they never reach sync).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pins_never_in_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    store
        .observe_pin(obs(BOB, None, 1, 2, false))
        .await
        .unwrap();
    assert_eq!(store.pending_count().await.unwrap(), 0);
    assert_eq!(store.item_count().await.unwrap(), 0);
}

// Partially set changed_* columns (a damaged or hostile file) read as Corrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_change_columns_are_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    store
        .observe_pin(obs(BOB, None, 1, 2, false))
        .await
        .unwrap();
    store
        .write(|w| {
            w.conn().execute(
                "UPDATE pinned_keys SET changed_fingerprint = zeroblob(32) WHERE user_id = ?1",
                [&BOB[..]],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        store.get_pin(BOB).await,
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        store.list_pins().await,
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn find_pin_by_id_label_and_local_part() {
    use courier_ftp_store::pins::{find_pin, parse_user_id};
    let mk = |b: u8, l: &str| PinnedKey {
        user_id: [b; 16],
        label: Some(l.into()),
        fingerprint: [b; 32],
        x25519_pub: [0; 32],
        ed25519_pub: [0; 32],
        first_seen_at: 0,
        verified: false,
        verified_at: None,
        is_self: false,
        changed: None,
    };
    let pins = vec![
        mk(1, "bob@example.com"),
        mk(2, "bobby@example.com"),
        mk(3, "bob@other.test"),
    ];
    assert_eq!(
        find_pin(&pins, "BOBBY@example.com").unwrap().user_id,
        [2; 16]
    );
    assert_eq!(find_pin(&pins, "bobby").unwrap().user_id, [2; 16]);
    assert!(find_pin(&pins, "bob").unwrap_err().contains("several"));
    assert!(find_pin(&pins, "zed").is_err());
    assert_eq!(
        find_pin(&pins, "03030303-0303-0303-0303-030303030303")
            .unwrap()
            .user_id,
        [3; 16]
    );
    assert_eq!(
        parse_user_id("0303030303030303030303030303030a"),
        Some({
            let mut b = [3; 16];
            b[15] = 0x0a;
            b
        })
    );
    assert_eq!(parse_user_id("not-a-uuid"), None);
    // Symmetric safety numbers.
    assert_eq!(
        pins[0].safety_number_with(&pins[1]),
        pins[1].safety_number_with(&pins[0])
    );
}
