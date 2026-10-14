//! The `pinned_keys` repository.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_core::model::item::UserId;
use courier_ftp_crypto::fingerprint::key_fingerprint;
use courier_ftp_store::{ManualClock, PinObservation, PinState, SetVerified, Store};

fn open(dir: &std::path::Path) -> (Store, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000));
    let store = Store::open_at(dir.join("courier-ftp.db"), clock.clone()).unwrap();
    (store, clock)
}

const BOB: UserId = UserId::from_bytes([0xb0; 16]);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_sight_pins_then_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let pins = store.pins();
    let obs = pins
        .observe(
            BOB,
            Some("bob@example.test".into()),
            [1; 32],
            [2; 32],
            false,
        )
        .await
        .unwrap();
    assert_eq!(obs, PinObservation::FirstSeen);
    clock.set(5_000);
    let obs = pins
        .observe(BOB, None, [1; 32], [2; 32], false)
        .await
        .unwrap();
    assert_eq!(obs, PinObservation::Unchanged);
    let pin = pins.get(BOB).await.unwrap().unwrap();
    assert_eq!(pin.fingerprint, key_fingerprint(&[1; 32], &[2; 32]));
    assert_eq!(pin.pinned_at, 1_000);
    assert_eq!(pin.label.as_deref(), Some("bob@example.test"));
    assert_eq!(pin.state(), PinState::Pinned);
    assert!(!pin.is_self);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_is_parked_and_clears_verified() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let pins = store.pins();
    pins.observe(BOB, None, [1; 32], [2; 32], false)
        .await
        .unwrap();
    clock.set(2_000);
    assert_eq!(
        pins.set_verified(BOB, true).await.unwrap(),
        SetVerified::Set
    );
    let pin = pins.get(BOB).await.unwrap().unwrap();
    assert_eq!(pin.state(), PinState::Verified);
    assert_eq!(pin.verified_at, Some(2_000));

    clock.set(3_000);
    let obs = pins
        .observe(BOB, None, [9; 32], [2; 32], false)
        .await
        .unwrap();
    assert_eq!(
        obs,
        PinObservation::Changed {
            pinned: key_fingerprint(&[1; 32], &[2; 32]),
            seen: key_fingerprint(&[9; 32], &[2; 32]),
        }
    );
    let pin = pins.get(BOB).await.unwrap().unwrap();
    // The pin is not replaced, verified is cleared, the change is pending.
    assert_eq!(pin.x25519_pub, [1; 32]);
    assert_eq!(pin.state(), PinState::KeyChanged);
    assert!(!pin.verified);
    let change = pin.changed.clone().unwrap();
    assert_eq!((change.x25519_pub, change.seen_at), ([9; 32], 3_000));
    assert_eq!(
        pin.current_fingerprint(),
        key_fingerprint(&[9; 32], &[2; 32])
    );
    assert_eq!(
        pins.set_verified(BOB, true).await.unwrap(),
        SetVerified::KeyChangePending
    );
    // The old key again: still pending (the server flip-flopped).
    assert_eq!(
        pins.observe(BOB, None, [1; 32], [2; 32], false)
            .await
            .unwrap(),
        PinObservation::Unchanged
    );
    assert_eq!(
        pins.get(BOB).await.unwrap().unwrap().state(),
        PinState::KeyChanged
    );

    // Accept the new key after comparing safety numbers.
    clock.set(4_000);
    assert!(pins.accept_new_key(BOB, true).await.unwrap());
    let pin = pins.get(BOB).await.unwrap().unwrap();
    assert_eq!(pin.x25519_pub, [9; 32]);
    assert_eq!(pin.state(), PinState::Verified);
    assert_eq!((pin.pinned_at, pin.verified_at), (4_000, Some(4_000)));
    assert!(!pins.accept_new_key(BOB, true).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_self_first_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let pins = store.pins();
    pins.observe(BOB, Some("bob".into()), [1; 32], [2; 32], false)
        .await
        .unwrap();
    let alice = UserId::from_bytes([0xa1; 16]);
    pins.observe(alice, Some("alice".into()), [3; 32], [4; 32], true)
        .await
        .unwrap();
    let all = pins.list().await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all[0].is_self);
    assert_eq!(all[1].user_id, BOB);
    assert_eq!(
        pins.set_verified(UserId::from_bytes([7; 16]), true)
            .await
            .unwrap(),
        SetVerified::NoPin
    );
    assert!(pins.delete(BOB).await.unwrap());
    assert!(pins.get(BOB).await.unwrap().is_none());
    // Pins are never items or outbox rows (they never reach sync).
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);
}

#[test]
fn find_pin_by_id_label_and_local_part() {
    use courier_ftp_store::pins::{find_pin, parse_user_id};
    let mk = |b: u8, l: &str| courier_ftp_store::PinnedKey {
        user_id: UserId::from_bytes([b; 16]),
        label: Some(l.into()),
        fingerprint: [b; 32],
        x25519_pub: [0; 32],
        ed25519_pub: [0; 32],
        pinned_at: 0,
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
    let two = UserId::from_bytes([2; 16]);
    assert_eq!(find_pin(&pins, "BOBBY@example.com").unwrap().user_id, two);
    assert_eq!(find_pin(&pins, "bobby").unwrap().user_id, two);
    assert!(find_pin(&pins, "bob").unwrap_err().contains("several"));
    assert!(find_pin(&pins, "zed").is_err());
    assert_eq!(
        find_pin(&pins, "03030303-0303-0303-0303-030303030303")
            .unwrap()
            .user_id,
        UserId::from_bytes([3; 16])
    );
    let mut b = [3; 16];
    b[15] = 0x0a;
    assert_eq!(
        parse_user_id("0303030303030303030303030303030a"),
        Some(UserId::from_bytes(b))
    );
    assert_eq!(parse_user_id("not-a-uuid"), None);
    assert_eq!(
        pins[0].safety_number_with(&pins[1]),
        pins[1].safety_number_with(&pins[0])
    );
}
