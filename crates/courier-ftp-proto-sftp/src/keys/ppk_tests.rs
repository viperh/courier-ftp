//! `.ppk` parser tests (ported from sverb `ppk_tests.rs` t02–t04, t07).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use proptest::prelude::*;

use super::{
    MAX_ARGON2_MEMORY_KIB, MAX_PPK_BYTES, PpkVersion, decode, fuzz_ppk_parse, parse, public_key,
};
use crate::keys::KeyError;

const PASS: &str = "fixture";

fn ppk(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("keys")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

/// Replace the value of the header line `name`.
fn set_header(text: &str, name: &str, value: &str) -> String {
    text.lines()
        .map(|l| match l.split_once(": ") {
            Some((k, _)) if k == name => format!("{k}: {value}"),
            _ => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Flip one base64 character of the first private line.
fn tamper_private(text: &str) -> String {
    let mut out = Vec::new();
    let mut in_private = false;
    let mut done = false;
    for l in text.lines() {
        if in_private && !done {
            let mut chars: Vec<char> = l.chars().collect();
            chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
            out.push(chars.into_iter().collect::<String>());
            done = true;
            continue;
        }
        in_private = l.starts_with("Private-Lines:");
        out.push(l.to_owned());
    }
    out.join("\n")
}

fn is_mac_error(e: &KeyError) -> bool {
    matches!(e, KeyError::Invalid(m) if m.contains("MAC"))
}

#[test]
fn versions_and_encryption_are_parsed() {
    let cases = [
        ("id_ed25519.ppk", PpkVersion::V2, false),
        ("id_ed25519_v3.ppk", PpkVersion::V3, false),
        ("id_rsa_v2_enc.ppk", PpkVersion::V2, true),
        ("id_ecdsa_v3_enc.ppk", PpkVersion::V3, true),
    ];
    for (name, version, encrypted) in cases {
        let file = parse(&ppk(name)).unwrap();
        assert_eq!(file.version, version, "{name}");
        assert_eq!(file.encrypted, encrypted, "{name}");
        assert_eq!(file.kdf.is_some(), encrypted && version == PpkVersion::V3);
        // The public key is readable without the passphrase.
        assert!(public_key(&ppk(name)).is_ok(), "{name}");
    }
}

/// t02: a tampered MAC line or comment fails the MAC check before the private blob is
/// used (unencrypted: "damaged"; encrypted: indistinguishable from a wrong passphrase).
#[test]
fn v2_mac_checked_before_parse() {
    for name in ["id_ed25519.ppk", "id_ed25519_v3.ppk"] {
        let text = ppk(name);
        let hex: String = text
            .lines()
            .find_map(|l| l.strip_prefix("Private-MAC: "))
            .unwrap()
            .to_owned();
        let flipped = format!(
            "{}{}",
            if hex.starts_with('0') { '1' } else { '0' },
            &hex[1..]
        );
        let e = decode(&set_header(&text, "Private-MAC", &flipped), None).unwrap_err();
        assert!(is_mac_error(&e), "{name}: {e:?}");
        let e = decode(&set_header(&text, "Comment", "someone else"), None).unwrap_err();
        assert!(is_mac_error(&e), "{name}: {e:?}");
        // A MAC of the wrong length or not hex: not a key file.
        let e = decode(&set_header(&text, "Private-MAC", &hex[2..]), None).unwrap_err();
        assert_eq!(e, KeyError::Format);
        let e = decode(
            &set_header(&text, "Private-MAC", &"zz".repeat(hex.len() / 2)),
            None,
        )
        .unwrap_err();
        assert_eq!(e, KeyError::Format);
    }
    let text = ppk("id_rsa_v2_enc.ppk");
    assert_eq!(
        decode(&text, Some("not-it")).unwrap_err(),
        KeyError::WrongPassphrase
    );
    assert_eq!(decode(&text, None).unwrap_err(), KeyError::NeedsPassphrase);
}

/// t02: a tampered private blob is caught by the MAC.
#[test]
fn tampered_private_blob() {
    for name in ["id_ed25519.ppk", "id_ed25519_v3.ppk"] {
        let e = decode(&tamper_private(&ppk(name)), None).unwrap_err();
        assert!(is_mac_error(&e), "{name}: {e:?}");
    }
    let e = decode(&tamper_private(&ppk("id_rsa_v2_enc.ppk")), Some(PASS)).unwrap_err();
    assert_eq!(e, KeyError::WrongPassphrase);
}

/// t03: DSA, v1 and unknown ciphers are refused; truncated files are errors.
#[test]
fn unsupported_and_truncated() {
    let dss = ppk("id_ed25519.ppk").replace("ssh-ed25519", "ssh-dss");
    assert!(matches!(
        decode(&dss, None).unwrap_err(),
        KeyError::Unsupported(a) if a.contains("ssh-dss")
    ));
    let v1 = ppk("id_ed25519.ppk").replace("File-2", "File-1");
    assert!(matches!(
        decode(&v1, None).unwrap_err(),
        KeyError::Unsupported(_)
    ));
    let cipher = set_header(&ppk("id_rsa_v2_enc.ppk"), "Encryption", "3des-cbc");
    assert!(matches!(
        decode(&cipher, Some(PASS)).unwrap_err(),
        KeyError::Unsupported(_)
    ));
    for name in ["id_ed25519.ppk", "id_ed25519_v3.ppk"] {
        let text = ppk(name);
        let full = text.trim_end();
        let lines: Vec<&str> = full.lines().collect();
        for n in 0..lines.len() {
            let cut = lines[..n].join("\n");
            assert!(decode(&cut, Some(PASS)).is_err(), "{name}: {n} lines");
        }
        for n in (0..full.len()).step_by(7) {
            if let Some(cut) = full.get(..n) {
                assert!(decode(cut, Some(PASS)).is_err(), "{name}: {n} bytes");
            }
        }
    }
    let big = format!("{}{}", ppk("id_ed25519.ppk"), "A".repeat(MAX_PPK_BYTES));
    assert!(matches!(
        decode(&big, None).unwrap_err(),
        KeyError::Invalid(_)
    ));
    let lines = set_header(&ppk("id_ed25519.ppk"), "Public-Lines", "100000");
    assert!(matches!(
        decode(&lines, None).unwrap_err(),
        KeyError::Invalid(_)
    ));
}

/// t04: v3 Argon2 parameters out of bounds are refused before any derivation.
#[test]
fn v3_argon2_bounds_rejected() {
    let text = ppk("id_ecdsa_v3_enc.ppk");
    let cases = [
        ("Argon2-Memory", (MAX_ARGON2_MEMORY_KIB + 1).to_string()),
        ("Argon2-Memory", "4294967295".to_owned()),
        ("Argon2-Passes", "0".to_owned()),
        ("Argon2-Passes", "100000".to_owned()),
        ("Argon2-Parallelism", "0".to_owned()),
        ("Argon2-Parallelism", "16777215".to_owned()),
    ];
    for (header, value) in cases {
        let bad = set_header(&text, header, &value);
        let start = std::time::Instant::now();
        let e = parse(&bad).unwrap_err();
        assert!(matches!(e, KeyError::Invalid(_)), "{header}={value}: {e:?}");
        assert!(matches!(
            decode(&bad, Some(PASS)).unwrap_err(),
            KeyError::Invalid(_)
        ));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
    // memory × passes over the work budget (each alone in range).
    let bad = set_header(
        &set_header(&text, "Argon2-Memory", &MAX_ARGON2_MEMORY_KIB.to_string()),
        "Argon2-Passes",
        "500",
    );
    assert!(matches!(parse(&bad).unwrap_err(), KeyError::Invalid(_)));
    assert_eq!(
        parse(&set_header(&text, "Argon2-Salt", "0011")).unwrap_err(),
        KeyError::Format
    );
    assert!(matches!(
        parse(&set_header(&text, "Key-Derivation", "scrypt")).unwrap_err(),
        KeyError::Unsupported(_)
    ));
}

mod props {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

        /// AC17 (the body of `fuzz/fuzz_targets/ppk_parse.rs`): arbitrary text after a
        /// PuTTY header never panics.
        #[test]
        fn parse_never_panics(body in "\\PC{0,300}", ver in 0u8..5) {
            let text = format!("PuTTY-User-Key-File-{ver}: ssh-ed25519\n{body}");
            fuzz_ppk_parse(text.as_bytes());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

        /// Single-line mutations of real (no Argon2) fixtures never panic.
        #[test]
        fn mutated_fixture_never_panics(which in 0usize..3, line in 0usize..40, junk in "[ -~]{0,80}") {
            let name = ["id_ed25519.ppk", "id_ed25519_v3.ppk", "id_rsa_v2_enc.ppk"][which];
            let text = ppk(name);
            let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
            let i = line % lines.len();
            lines[i] = junk;
            fuzz_ppk_parse(lines.join("\n").as_bytes());
            let _ = decode(&lines.join("\n"), Some(PASS));
        }
    }
}
