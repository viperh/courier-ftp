#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ssh_key::HashAlg;

use super::*;

const PASS: &str = "fixture";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("keys")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(dir().join(name)).unwrap()
}

/// `(file, fingerprint)` from `fingerprints.txt`.
fn fingerprints() -> Vec<(String, String)> {
    fixture("fingerprints.txt")
        .lines()
        .filter_map(|l| {
            let (name, fp) = l.split_once(' ')?;
            Some((name.to_owned(), fp.trim().to_owned()))
        })
        .collect()
}

fn encrypted(name: &str) -> bool {
    name.contains("_enc")
}

/// AC5: every fixture decodes to the listed fingerprint.
#[test]
fn decode_every_fixture_matches_fingerprint() {
    let rows = fingerprints();
    assert_eq!(rows.len(), 13);
    for (name, fp) in rows {
        let text = fixture(&name);
        assert_eq!(is_encrypted(&text), encrypted(&name), "{name}");
        let key = decode(&text, encrypted(&name).then_some(PASS))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            fp,
            "{name}"
        );
        assert!(!key.is_encrypted(), "{name}");
    }
}

#[test]
fn formats_are_detected() {
    let cases = [
        ("id_ed25519", KeyFormat::OpenSsh),
        ("id_rsa_pkcs1.pem", KeyFormat::PemPkcs1Rsa),
        ("id_ec_sec1.pem", KeyFormat::PemSec1Ec),
        ("id_ed25519_pkcs8.pem", KeyFormat::Pkcs8),
        ("id_rsa_pkcs8_enc.pem", KeyFormat::Pkcs8Encrypted),
        ("id_ed25519.ppk", KeyFormat::PpkV2),
        ("id_ecdsa_v3_enc.ppk", KeyFormat::PpkV3),
        ("fingerprints.txt", KeyFormat::Unknown),
    ];
    for (name, want) in cases {
        assert_eq!(detect(&fixture(name)), want, "{name}");
    }
    assert_eq!(
        detect(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINzl4nqdWtkfWYym8Wn7Yi5D0+NUw6t76V3JYVYP8M6Y c"
        ),
        KeyFormat::PublicOnly
    );
    assert_eq!(KeyFormat::PpkV3.name(), "PuTTY v3");
}

#[test]
fn encrypted_fixtures_need_passphrase() {
    for (name, _) in fingerprints().into_iter().filter(|(n, _)| encrypted(n)) {
        assert_eq!(
            decode(&fixture(&name), None).unwrap_err(),
            KeyError::NeedsPassphrase,
            "{name}"
        );
    }
}

#[test]
fn wrong_passphrase_is_reported() {
    for (name, _) in fingerprints().into_iter().filter(|(n, _)| encrypted(n)) {
        assert_eq!(
            decode(&fixture(&name), Some("not-the-passphrase")).unwrap_err(),
            KeyError::WrongPassphrase,
            "{name}"
        );
    }
}

#[test]
fn public_key_file_is_rejected_with_hint() {
    let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINzl4nqdWtkfWYym8Wn7Yi5D0+NUw6t76V3JYVYP8M6Y courier-ftp-e2e-fixture-TEST-ONLY\n";
    let err = decode(line, None).unwrap_err();
    assert_eq!(err, KeyError::PublicKey);
    assert_eq!(
        err.to_string(),
        "This is a public key; choose the private key file (without .pub)"
    );
    assert_eq!(
        decode("hello", None).unwrap_err().to_string(),
        "Not a private key format courier-ftp can read (OpenSSH, PEM, PKCS#8, PuTTY)"
    );
}

#[test]
fn dsa_and_small_rsa_are_unsupported() {
    for name in [
        "unsupported_dsa.pem",
        "unsupported_dsa_openssh",
        "unsupported_rsa1024.pem",
    ] {
        let err = decode(&fixture(name), None).unwrap_err();
        assert!(matches!(err, KeyError::Unsupported(_)), "{name}: {err:?}");
    }
    let err = decode(&fixture("unsupported_rsa1024.pem"), None).unwrap_err();
    assert!(err.to_string().contains("2048"), "{err}");
}

#[test]
fn file_over_64k_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let big = tmp.path().join("big");
    std::fs::write(&big, vec![b'A'; 64 * 1024 + 1]).unwrap();
    assert_eq!(read_key_file(&big).unwrap_err(), KeyError::TooLarge);
    let exact = tmp.path().join("exact");
    std::fs::write(&exact, vec![b'A'; 64 * 1024]).unwrap();
    assert_eq!(read_key_file(&exact).unwrap().len(), 64 * 1024);
    assert!(matches!(
        read_key_file(&tmp.path().join("missing")).unwrap_err(),
        KeyError::Read(_)
    ));
    assert_eq!(
        decode(&"A".repeat(64 * 1024 + 1), None).unwrap_err(),
        KeyError::TooLarge
    );
    let text = read_key_file(&dir().join("id_ed25519")).unwrap();
    assert!(decode(&text, None).is_ok());
}

#[test]
fn key_sizes() {
    let bits = |name: &str| {
        let pass = encrypted(name).then_some(PASS);
        key_bits(decode(&fixture(name), pass).unwrap().public_key())
    };
    assert_eq!(bits("id_rsa4096"), 4096);
    assert_eq!(bits("id_ecdsa_p256"), 256);
    assert_eq!(bits("id_ed25519"), 256);
}
