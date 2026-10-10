#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use pretty_assertions::assert_eq;
use time::OffsetDateTime;

use super::*;

const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBhYxpK5M9dWWLkngJsG1h11alcrHTyZO7bn447uw5it";

fn entry(host: &str, port: u16, key_type: &str, blob: &str) -> KnownHost {
    KnownHost {
        id: KnownHostId::new_v7(),
        host: host.to_owned(),
        port,
        key_type: key_type.to_owned(),
        public_key: blob.to_owned(),
        added_at: OffsetDateTime::UNIX_EPOCH,
        comment: None,
    }
}

#[test]
fn normalize_host_lowercases_strips_dot_and_brackets() {
    for (input, want) in [
        ("Web01.Example.COM", "web01.example.com"),
        ("example.com.", "example.com"),
        ("[::1]", "::1"),
        ("[2001:DB8::1]", "2001:db8::1"),
        (" host ", "host"),
        ("10.0.0.1", "10.0.0.1"),
    ] {
        assert_eq!(normalize_host(input), want, "{input}");
    }
}

#[test]
fn fingerprint_of_entry() {
    let e = entry("h", 22, "ssh-ed25519", ED25519);
    assert_eq!(
        e.fingerprint_sha256(),
        "SHA256:uYxmMoF3aflKiV/iuu80yjcxVbhqOX/6YopX8ub8Jko"
    );
    assert_eq!(entry("h", 22, "x", "!!").fingerprint_sha256(), "?");
}

#[tokio::test]
async fn memory_store_add_replaces_and_lists_sorted() {
    let store = MemoryHostKeyStore::new();
    assert!(!store.can_persist());
    assert!(MemoryHostKeyStore::persistent_for_tests().can_persist());
    let b = entry("b.example", 22, "ssh-ed25519", ED25519);
    let a2 = entry("a.example", 2222, "ssh-rsa", "AAAA");
    let a1 = entry("a.example", 22, "ssh-rsa", "AAAA");
    let a1e = entry("a.example", 22, "ecdsa-sha2-nistp256", "AAAA");
    for e in [&b, &a2, &a1, &a1e] {
        store.add(e.clone(), vec![]).await.unwrap();
    }
    let listed: Vec<(String, u16, String)> = store
        .list()
        .into_iter()
        .map(|e| (e.host, e.port, e.key_type))
        .collect();
    assert_eq!(
        listed,
        [
            ("a.example".to_owned(), 22, "ecdsa-sha2-nistp256".to_owned()),
            ("a.example".to_owned(), 22, "ssh-rsa".to_owned()),
            ("a.example".to_owned(), 2222, "ssh-rsa".to_owned()),
            ("b.example".to_owned(), 22, "ssh-ed25519".to_owned()),
        ]
    );
    assert_eq!(store.lookup("a.example", 22).len(), 2);
    assert!(store.lookup("a.example", 23).is_empty());

    // Replace a1 with a new rsa key.
    let new = entry("a.example", 22, "ssh-rsa", "BBBB");
    store.add(new.clone(), vec![a1.id]).await.unwrap();
    let rsa: Vec<KnownHost> = store
        .lookup("a.example", 22)
        .into_iter()
        .filter(|e| e.key_type == "ssh-rsa")
        .collect();
    assert_eq!(rsa, std::slice::from_ref(&new));

    // Remove (AC12), removing an unknown id is not an error.
    store.remove(new.id).await.unwrap();
    store.remove(new.id).await.unwrap();
    assert_eq!(store.list().len(), 3);
}

#[tokio::test]
async fn switchable_store_delegates_after_set() {
    let locked: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::new());
    let vault: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());
    let store = SwitchableHostKeyStore::new(Arc::clone(&locked));
    assert!(!store.can_persist());
    store
        .add(entry("h", 22, "ssh-ed25519", ED25519), vec![])
        .await
        .unwrap();
    assert_eq!(locked.list().len(), 1);

    store.set(Arc::clone(&vault));
    assert!(store.can_persist());
    assert!(store.lookup("h", 22).is_empty());
    let e = entry("h", 22, "ssh-ed25519", ED25519);
    store.add(e.clone(), vec![]).await.unwrap();
    assert_eq!(vault.lookup("h", 22), std::slice::from_ref(&e));
    assert_eq!(store.list(), std::slice::from_ref(&e));
    store.remove(e.id).await.unwrap();
    assert!(vault.list().is_empty());
    assert_eq!(locked.list().len(), 1);
    assert!(format!("{store:?}").contains("SwitchableHostKeyStore"));
}

#[test]
fn session_trust_insert_contains_clear() {
    let t = SessionTrust::default();
    assert!(!t.contains("h", 22, "ssh-ed25519", ED25519));
    t.insert("H.", 22, "ssh-ed25519", ED25519);
    assert!(t.contains("h", 22, "ssh-ed25519", ED25519));
    assert!(!t.contains("h", 2222, "ssh-ed25519", ED25519));
    assert!(!t.contains("h", 22, "ssh-rsa", ED25519));
    assert!(!t.contains("h", 22, "ssh-ed25519", "AAAA"));
    t.clear();
    assert!(!t.contains("h", 22, "ssh-ed25519", ED25519));
}

#[test]
fn known_host_serde_round_trip() {
    let e = entry("h", 22, "ssh-ed25519", ED25519);
    let json = serde_json::to_string(&e).unwrap();
    assert!(
        json.contains("\"added_at\":\"1970-01-01T00:00:00Z\""),
        "{json}"
    );
    let back: KnownHost = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}
