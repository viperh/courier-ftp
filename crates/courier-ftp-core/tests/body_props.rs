//! Decoding untrusted item bodies (T81): `ItemBody::from_cbor` never panics, whether
//! fed random bytes or mutations of valid bodies, and every body it accepts re-encodes
//! deterministically.

use std::time::Duration;

use ciborium::Value;
use courier_ftp_core::model::item::{
    DeviceId, HlcClock, ItemBody, ItemKind, ItemView, KnownHostItem, ManualClock,
    ProxyCredentialItem, SshKeyItem, TrustedCertItem,
};
use proptest::prelude::*;

fn sample_body() -> Vec<u8> {
    let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
    let d = DeviceId::from_bytes([1; 16]);
    let mut b = ItemBody::new(ItemKind::Site, 1);
    b.set("name", "web", &mut clock, d);
    b.set("port", 21, &mut clock, d);
    b.set("parent_id", Value::Bytes(vec![7; 16]), &mut clock, d);
    b.set(
        "x.list",
        Value::Array(vec![Value::from(1), Value::from("a")]),
        &mut clock,
        d,
    );
    b.delete(&mut clock, d);
    b.to_cbor().unwrap_or_default()
}

/// Every view must reject or accept, never panic.
fn exercise(body: &ItemBody) {
    let _ = KnownHostItem::from_body(body);
    let _ = TrustedCertItem::from_body(body);
    let _ = SshKeyItem::from_body(body);
    let _ = ProxyCredentialItem::from_body(body);
    let _ = format!("{body:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn from_cbor_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(body) = ItemBody::from_cbor(&bytes) {
            exercise(&body);
            let again = body.to_cbor();
            prop_assert!(again.is_ok());
        }
    }

    #[test]
    fn mutated_bodies_never_panic(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        truncate in any::<prop::sample::Index>(),
        do_truncate in any::<bool>(),
    ) {
        let mut bytes = sample_body();
        prop_assert!(!bytes.is_empty());
        for (i, b) in edits {
            let i = i.index(bytes.len());
            bytes[i] = b;
        }
        if do_truncate {
            bytes.truncate(truncate.index(bytes.len()));
        }
        if let Ok(body) = ItemBody::from_cbor(&bytes) {
            exercise(&body);
            let enc = body.to_cbor();
            prop_assert!(enc.is_ok());
            let enc = enc.unwrap_or_default();
            let back = ItemBody::from_cbor(&enc);
            prop_assert!(back.is_ok());
            prop_assert_eq!(back.ok().and_then(|b| b.to_cbor().ok()), Some(enc));
        }
    }
}

#[test]
fn sample_body_decodes() {
    let bytes = sample_body();
    let body = ItemBody::from_cbor(&bytes);
    assert!(body.is_ok(), "{body:?}");
}
