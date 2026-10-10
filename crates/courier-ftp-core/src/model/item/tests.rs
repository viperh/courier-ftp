//! Cross-module tests for the item model.

use std::time::Duration;

use ciborium::Value;
use proptest::prelude::*;
use secrecy::{ExposeSecret, SecretString};

use super::*;
use crate::model::{Charset, FtpEncryption, Protocol};

const T0: Duration = Duration::from_secs(1_800_000_000);

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn clock() -> (ManualClock, HlcClock) {
    let pc = ManualClock::new(T0);
    (pc.clone(), HlcClock::new(pc))
}

fn at(secs: u64) -> Hlc {
    Hlc::from_duration(T0 + Duration::from_secs(secs))
}

fn stamp_of(body: &ItemBody, field: &str) -> Option<(Hlc, DeviceId)> {
    body.get_stamped(field).map(Stamped::stamp)
}

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn exposed(s: Option<&SecretString>) -> Option<&str> {
    s.map(|s| s.expose_secret())
}

#[test]
fn stamped_ties_break_on_device() {
    let a = Stamped::new(Value::from(1), at(1), dev(1));
    let b = Stamped::new(Value::from(2), at(1), dev(2));
    assert!(b.is_newer_than(&a));
    assert!(!a.is_newer_than(&b));
    assert_eq!(a.cmp_stamp(&b), std::cmp::Ordering::Less);
    let c = Stamped::new(Value::from(99), at(1), dev(1));
    assert_eq!(c.cmp_stamp(&b), a.cmp_stamp(&b));
    // HLC dominates the device.
    let d = Stamped::new(Value::from(3), at(2), dev(0));
    assert!(d.is_newer_than(&b));
}

#[test]
fn set_stamps_and_skips_equal_values() {
    let (pc, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Site, 1);
    assert!(body.set("port", 22_u16, &mut clock, dev(1)));
    let first = stamp_of(&body, "port");
    pc.advance(Duration::from_secs(1));
    assert!(!body.set("port", 22_u16, &mut clock, dev(1)));
    assert_eq!(stamp_of(&body, "port"), first);
    assert!(body.set("port", 2222_u16, &mut clock, dev(1)));
    assert!(stamp_of(&body, "port") > first);
}

#[test]
fn tombstone_rule_and_resurrection() {
    let mut body = ItemBody::new(ItemKind::Site, 1);
    body.fields.insert(
        "host".into(),
        Stamped::new(Value::from("a.example"), at(3), dev(1)),
    );
    body.deleted = Some(Stamped::new(true, at(5), dev(1)));
    assert!(body.is_deleted());
    body.fields.insert(
        "port".into(),
        Stamped::new(Value::from(2222), at(7), dev(2)),
    );
    assert!(!body.is_deleted());
    assert_eq!(body.max_field_hlc(), Some(at(7)));
    body.deleted = Some(Stamped::new(false, at(9), dev(1)));
    assert!(!body.is_deleted());
}

#[test]
fn unknown_fields_survive_view_round_trip() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut body = Site::new("web", Protocol::Sftp, "a.example").to_body(&mut clock, dev(1));
    body.set("port", 22_u16, &mut clock, dev(1));
    // A field written by a newer courier-ftp this build doesn't know.
    body.fields.insert(
        "future.field".into(),
        Stamped::new(Value::from("from the future"), at(1), dev(7)),
    );
    let before = body.clone();

    let mut site = Site::from_body(&body)?;
    site.port = Some(2200);
    site.apply_to(&mut body, &mut clock, dev(1));

    assert_eq!(
        body.get_stamped("future.field"),
        before.get_stamped("future.field")
    );
    assert_eq!(body.get("port"), Some(&Value::from(2200)));
    for (k, v) in &before.fields {
        if k != "port" {
            assert_eq!(body.get_stamped(k), Some(v), "{k}");
        }
    }
    assert_eq!(body.fields.len(), before.fields.len());

    // ...and through a CBOR save / load, as the store does.
    let reloaded = ItemBody::from_cbor(&body.to_cbor().map_err(|_| ViewError::MissingField {
        field: "cbor".into(),
    })?)
    .map_err(|_| ViewError::MissingField {
        field: "cbor".into(),
    })?;
    assert_eq!(reloaded, body);
    Ok(())
}

#[test]
fn applying_an_unchanged_view_creates_no_stamps() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut body = Site::new("web", Protocol::Ftp, "a.example").to_body(&mut clock, dev(1));
    let before = body.clone();
    Site::from_body(&body)?.apply_to(&mut body, &mut clock, dev(1));
    assert_eq!(body, before);
    Ok(())
}

#[test]
fn logon_is_flattened_and_sub_fields_stamp_independently() -> Result<(), ViewError> {
    let (pc, mut clock) = clock();
    let mut site = Site::new("web", Protocol::Ftp, "a.example");
    site.user = "u".into();
    site.password = Some(secret("pw"));
    let mut body = site.to_body(&mut clock, dev(1));
    assert_eq!(body.get("logon.type"), Some(&Value::from("normal")));
    assert_eq!(body.get("logon.user"), Some(&Value::from("u")));
    assert_eq!(body.get("logon.password"), Some(&Value::from("pw")));
    assert!(!body.contains("logon.account"));
    assert!(!body.contains("logon"));

    let before = body.clone();
    pc.advance(Duration::from_secs(1));
    let mut site = Site::from_body(&body)?;
    site.user = "v".into();
    site.apply_to(&mut body, &mut clock, dev(1));
    for (k, v) in &before.fields {
        if k == "logon.user" {
            assert!(body.get_stamped(k).is_some_and(|n| n.is_newer_than(v)));
        } else {
            assert_eq!(body.get_stamped(k), Some(v), "{k}");
        }
    }

    // Clearing the password writes an explicit Null that wins merges.
    let mut site = Site::from_body(&body)?;
    site.logon = LogonKind::AskForPassword;
    site.password = None;
    site.apply_to(&mut body, &mut clock, dev(1));
    assert_eq!(body.get("logon.password"), None);
    assert!(body.contains("logon.password"));
    assert!(merge(&before, &body).body.get("logon.password").is_none());
    Ok(())
}

fn value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("no NaN", |f| !f.is_nan())
            .prop_map(Value::Float),
        ".{0,12}".prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..20).prop_map(Value::Bytes),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::vec(("[a-z]{1,4}".prop_map(Value::Text), inner), 0..4)
                .prop_map(Value::Map),
        ]
    })
}

fn stamped<T: std::fmt::Debug>(v: impl Strategy<Value = T>) -> impl Strategy<Value = Stamped<T>> {
    (v, any::<u64>(), any::<[u8; 16]>())
        .prop_map(|(value, h, d)| Stamped::new(value, Hlc::from_u64(h), DeviceId::from_bytes(d)))
}

fn body_strategy() -> impl Strategy<Value = ItemBody> {
    (
        proptest::sample::select(ItemKind::ALL.to_vec()),
        any::<u16>(),
        proptest::collection::btree_map("[a-z_.]{1,12}", stamped(value_strategy()), 0..8),
        proptest::option::of(stamped(any::<bool>())),
    )
        .prop_map(|(kind, schema_version, fields, deleted)| ItemBody {
            kind,
            schema_version,
            fields,
            deleted,
        })
}

proptest! {
    #[test]
    fn cbor_round_trip_is_lossless_and_deterministic(body in body_strategy()) {
        let bytes = body.to_cbor().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let back = ItemBody::from_cbor(&bytes).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(&back, &body);
        let again = back.to_cbor().map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(again, bytes);
    }

    // The `item_body` fuzz body (T91 §7): arbitrary bytes, and valid bodies
    // with one byte flipped or the tail cut off.
    #[test]
    fn fuzz_item_body_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        fuzz_item_body(&data);
    }

    #[test]
    fn fuzz_item_body_mutated_never_panics(
        body in body_strategy(),
        at in any::<prop::sample::Index>(),
        xor in 1u8..,
        cut in any::<prop::sample::Index>(),
    ) {
        let bytes = body.to_cbor().map_err(|e| TestCaseError::fail(e.to_string()))?;
        fuzz_item_body(&bytes);
        let mut flipped = bytes.clone();
        let i = at.index(flipped.len());
        flipped[i] ^= xor;
        fuzz_item_body(&flipped);
        fuzz_item_body(&bytes[..cut.index(bytes.len())]);
    }
}

#[test]
fn cbor_shape_matches_the_spec() -> Result<(), Box<dyn std::error::Error>> {
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::SiteFolder, 1);
    body.set("name", "Work", &mut clock, dev(3));
    body.delete(&mut clock, dev(3));
    let v: Value = ciborium::from_reader(body.to_cbor()?.as_slice())?;
    let map = v.as_map().ok_or("not a map")?;
    let keys: Vec<_> = map.iter().filter_map(|(k, _)| k.as_text()).collect();
    assert_eq!(keys, ["kind", "schema_version", "fields", "deleted"]);
    assert_eq!(map[0].1.as_text(), Some("site-folder"));
    // `Stamped` = [value, hlc: u64, device: 16 bytes].
    let fields = map[2].1.as_map().ok_or("fields")?;
    let reg = fields[0].1.as_array().ok_or("register")?;
    assert_eq!(reg[0].as_text(), Some("Work"));
    assert!(reg[1].as_integer().is_some());
    assert_eq!(reg[2].as_bytes().map(Vec::len), Some(16));
    Ok(())
}

#[test]
fn cbor_bytes_feed_seal_item() -> Result<(), Box<dyn std::error::Error>> {
    use courier_ftp_crypto::{Key32, Nonce24, envelope};
    let (_, mut clock) = clock();
    let mut site = Site::new("web", Protocol::Sftp, "a.example");
    site.password = Some(secret("CANARY-pw"));
    let body = site.to_body(&mut clock, dev(1));
    let bytes = body.to_cbor()?;
    let vk = Key32::from_bytes([7_u8; 32]);
    let item = id(1);
    let vault = VaultId::from_bytes([2; 16]);
    let env = envelope::seal_item_with_nonce(
        &vk,
        vault.as_bytes(),
        item.as_bytes(),
        1,
        &bytes,
        &Nonce24::from_bytes([3; 24]),
    )?;
    assert!(!env.windows(9).any(|w| w == b"CANARY-pw"));
    let plain = envelope::open_item(
        |v| (v == 1).then_some(&vk),
        vault.as_bytes(),
        item.as_bytes(),
        &env,
    )?;
    assert_eq!(ItemBody::from_cbor(&plain)?, body);
    Ok(())
}

#[test]
fn newer_schema_yields_read_only_views() -> Result<(), ViewError> {
    let mut body = ItemBody::new(ItemKind::SiteFolder, 99);
    body.fields.insert(
        "name".into(),
        Stamped::new(Value::from("Work"), at(1), dev(1)),
    );
    assert!(SiteFolder::from_body(&body)?.read_only);
    assert!(migrate(body.clone()).read_only);
    body.schema_version = 1;
    assert!(!SiteFolder::from_body(&body)?.read_only);
    Ok(())
}

#[test]
fn wrong_field_types_are_reported() {
    let mut body = ItemBody::new(ItemKind::KnownHost, 1);
    body.fields.insert(
        "port".into(),
        Stamped::new(Value::from("twenty-two"), at(1), dev(1)),
    );
    assert_eq!(
        KnownHost::from_body(&body).err(),
        Some(ViewError::FieldTypeError {
            field: "port".into()
        })
    );
    body.fields.insert(
        "port".into(),
        Stamped::new(Value::from(70_000), at(1), dev(1)),
    );
    assert!(matches!(
        KnownHost::from_body(&body),
        Err(ViewError::FieldTypeError { .. })
    ));
    body.fields.remove("port");
    assert_eq!(
        KnownHost::from_body(&body).err(),
        Some(ViewError::MissingField {
            field: "port".into()
        })
    );
    assert!(matches!(
        Bookmark::try_from(&body),
        Err(ViewError::WrongKind {
            expected: ItemKind::Bookmark,
            found: ItemKind::KnownHost
        })
    ));
    let mut site = ItemBody::new(ItemKind::Site, 1);
    site.fields.insert(
        "protocol".into(),
        Stamped::new(Value::from("gopher"), at(1), dev(1)),
    );
    assert!(matches!(
        Site::from_body(&site),
        Err(ViewError::FieldTypeError { .. })
    ));
}

#[test]
fn secrets_are_typed_and_redacted() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut site = Site::new("web", Protocol::Ftp, "a.example");
    site.password = Some(secret("CANARY-7f3a"));
    site.passphrase = Some(secret("CANARY-pass"));
    let body = site.to_body(&mut clock, dev(1));
    let site = Site::from_body(&body)?;
    assert_eq!(exposed(site.password.as_ref()), Some("CANARY-7f3a"));
    let dbg = format!("{site:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(!format!("{body:?}").contains("CANARY"));
    Ok(())
}

#[test]
fn unset_beats_older_value() {
    let pc = ManualClock::new(T0 + Duration::from_secs(3));
    let mut clock = HlcClock::new(pc.clone());
    let mut body = ItemBody::new(ItemKind::Site, 1);
    body.set("port", 2222_u16, &mut clock, dev(1));
    let set_stamp = body.get_stamped("port").map(|s| s.hlc);
    pc.set(T0 + Duration::from_secs(5));
    assert!(body.unset("port", &mut clock, dev(1)));
    assert_eq!(body.get("port"), None);
    assert!(body.contains("port"));
    assert!(body.get_stamped("port").map(|s| s.hlc) > set_stamp);
    assert!(!body.unset("port", &mut clock, dev(1)));
}

/// Writes `view` to a fresh body, reads it back and checks: Debug output equal
/// (secrets are redacted there and compared separately), and applying the
/// read-back view changes nothing.
fn round_trip<V: ItemView + std::fmt::Debug>(
    view: &V,
    clock: &mut HlcClock,
) -> Result<V, ViewError> {
    let mut body = view.to_body(clock, dev(1));
    assert_eq!(body.kind, V::KIND);
    assert_eq!(body.schema_version, current_schema(V::KIND));
    let bytes = body.to_cbor().map_err(|_| ViewError::MissingField {
        field: "<cbor>".into(),
    })?;
    let loaded = ItemBody::from_cbor(&bytes).map_err(|_| ViewError::MissingField {
        field: "<cbor>".into(),
    })?;
    assert_eq!(loaded, body);
    let back = V::from_body(&loaded)?;
    assert_eq!(format!("{back:?}"), format!("{view:?}"));
    let before = body.clone();
    back.apply_to(&mut body, clock, dev(1));
    assert_eq!(body, before, "re-applying {:?} changed the body", V::KIND);
    Ok(back)
}

#[test]
fn every_view_round_trips() -> Result<(), ViewError> {
    let (_, mut clock) = clock();

    // Defaults only.
    round_trip(&Site::new("s", Protocol::Ftp, "h"), &mut clock)?;
    round_trip(&HistoryEntry::new(Protocol::Sftp, "h"), &mut clock)?;
    round_trip(&SiteFolder::default(), &mut clock)?;
    round_trip(&Bookmark::default(), &mut clock)?;
    round_trip(&ProxyCredential::default(), &mut clock)?;
    round_trip(&CredentialOverride::new(id(4)), &mut clock)?;

    // Every field set.
    let site = Site {
        name: "Production web".into(),
        parent: Some(id(9)),
        protocol: Protocol::FtpsExplicit,
        encryption: Some(FtpEncryption::RequireExplicit),
        host: "ftp.example.com".into(),
        port: Some(2121),
        logon: LogonKind::Account,
        user: "deploy".into(),
        password: Some(secret("pw")),
        account: Some("acct".into()),
        key_id: Some(id(5)),
        key_path: Some("/home/me/.ssh/id_ed25519".into()),
        passphrase: Some(secret("pp")),
        try_agent_first: true,
        color: SiteColor::Magenta,
        comments: "line 1\nline 2".into(),
        server_type: ServerType::Vms,
        bypass_proxy: true,
        default_remote_dir: Some("/var/www".into()),
        sync_browsing: true,
        directory_comparison: true,
        timezone_offset_minutes: -90,
        transfer_mode: SiteTransferMode::Active,
        limit_connections: Some(3),
        charset: Charset::from_label("windows-1252").map_err(|_| ViewError::MissingField {
            field: "charset".into(),
        })?,
        created_at: Some(UnixMillis(1_700_000_000_000)),
        read_only: false,
    };
    let back = round_trip(&site, &mut clock)?;
    assert_eq!(exposed(back.password.as_ref()), Some("pw"));
    assert_eq!(exposed(back.passphrase.as_ref()), Some("pp"));

    round_trip(
        &SiteFolder {
            name: "Work/ünïcode".into(),
            parent: Some(id(2)),
            read_only: false,
        },
        &mut clock,
    )?;
    round_trip(
        &Bookmark {
            name: "logs".into(),
            site_id: Some(id(3)),
            local_dir: Some("C:\\logs".into()),
            remote_dir: Some("/var/log".into()),
            sync_browsing: true,
            comparison: true,
            position: Some(-4),
            read_only: false,
        },
        &mut clock,
    )?;
    round_trip(
        &KnownHost {
            host: "sftp.example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            public_key: "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                .into(),
            added_at: Some(UnixMillis(1)),
            read_only: false,
        },
        &mut clock,
    )?;
    round_trip(
        &TrustedCert {
            host: "ftp.example.com".into(),
            port: 990,
            sha256: vec![0xab; 32],
            der: vec![0x30, 0x82, 0x01, 0x0a],
            subject: "CN=ftp.example.com".into(),
            added_at: Some(UnixMillis(2)),
            read_only: false,
        },
        &mut clock,
    )?;
    let key = round_trip(
        &SshKey {
            label: "laptop".into(),
            algorithm: "ssh-ed25519".into(),
            public_key: "ssh-ed25519 AAAA… me@host".into(),
            private_key: secret("-----BEGIN OPENSSH PRIVATE KEY-----\n…"),
            passphrase: Some(secret("kp")),
            read_only: false,
        },
        &mut clock,
    )?;
    assert!(key.private_key.expose_secret().starts_with("-----BEGIN"));
    assert_eq!(exposed(key.passphrase.as_ref()), Some("kp"));
    let proxy = round_trip(
        &ProxyCredential {
            label: "corp".into(),
            user: "proxyuser".into(),
            password: Some(secret("proxypw")),
            read_only: false,
        },
        &mut clock,
    )?;
    assert_eq!(exposed(proxy.password.as_ref()), Some("proxypw"));
    let over = round_trip(
        &CredentialOverride {
            shared_site_id: id(8),
            user: Some("me".into()),
            password: Some(secret("mine")),
            key_id: Some(id(6)),
            passphrase: Some(secret("kp2")),
            read_only: false,
        },
        &mut clock,
    )?;
    assert!(!over.is_empty());
    assert!(CredentialOverride::new(id(8)).is_empty());
    let hist = round_trip(
        &HistoryEntry {
            protocol: Protocol::FtpsImplicit,
            host: "h.example".into(),
            port: Some(990),
            logon: LogonKind::Normal,
            user: "me".into(),
            password: Some(secret("hpw")),
            used_at: Some(UnixMillis(3)),
            read_only: false,
        },
        &mut clock,
    )?;
    assert_eq!(exposed(hist.password.as_ref()), Some("hpw"));
    Ok(())
}

#[test]
fn every_kind_has_a_schema_and_views_cover_all_kinds() {
    let view_kinds = [
        Site::KIND,
        SiteFolder::KIND,
        Bookmark::KIND,
        KnownHost::KIND,
        TrustedCert::KIND,
        SshKey::KIND,
        ProxyCredential::KIND,
        CredentialOverride::KIND,
        HistoryEntry::KIND,
    ];
    for kind in ItemKind::ALL {
        assert!(CURRENT_SCHEMA.iter().any(|(k, _)| *k == kind), "{kind}");
        assert!(view_kinds.contains(&kind), "{kind}");
    }
}
