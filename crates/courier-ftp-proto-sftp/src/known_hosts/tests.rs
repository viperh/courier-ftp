//! Parser, matcher and fingerprint tests (ported from sverb `known_hosts/tests.rs`).
//! Fixtures: `tests/fixtures/known_hosts/` (see its README).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use pretty_assertions::assert_eq;

use super::{lookup::glob, *};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/known_hosts/",
            $name
        ))
    };
}

const ED25519: &str = fixture!("ed25519.pub");
const ECDSA: &str = fixture!("ecdsa.pub");
const RSA: &str = fixture!("rsa.pub");
const HASHED: &str = fixture!("hashed_example_com.txt");
const PARSER: &str = fixture!("known_hosts.txt");
const MATCHING: &str = fixture!("matching.txt");
const FINGERPRINTS: &str = fixture!("fingerprints.txt");

fn src() -> PathBuf {
    PathBuf::from("known_hosts")
}

fn blob_of(pub_line: &str) -> Vec<u8> {
    key_blob(pub_line.split_whitespace().nth(1).unwrap()).unwrap()
}

#[test]
fn lookup_key_port_22_and_bracketed() {
    for (host, port, want) in [
        ("h", 22, "h"),
        ("h", 2222, "[h]:2222"),
        ("::1", 22, "::1"),
        ("::1", 2222, "[::1]:2222"),
    ] {
        assert_eq!(lookup_key(host, port), want, "{host}:{port}");
    }
}

/// A line hashed by `ssh-keygen -H` matches `example.com` only.
#[test]
fn hashed_entry_matches() {
    let (entries, warnings) = parse_known_hosts(HASHED, &src());
    assert!(warnings.is_empty(), "{warnings:?}");
    let pattern = &entries[0].host_pattern;
    assert!(hashed::is_hashed(pattern));
    assert!(hashed::matches(pattern, "example.com"));
    assert!(!hashed::matches(pattern, "example.org"));
    assert!(!hashed::matches(pattern, "[example.com]:2222"));
    assert_eq!(lookup(&entries, "example.com", 22).matching.len(), 1);
    assert!(lookup(&entries, "example.org", 22).is_empty());
    // Malformed hashed fields never match.
    assert!(!hashed::matches("|1|bm9wZQ==|bm9wZQ==", "example.com"));
    assert!(!hashed::matches("|1|", "example.com"));
    assert!(host_field_matches(pattern, "example.com"));
}

/// Globs, negation and comma lists.
#[test]
fn pattern_globbing_and_negation() {
    let list = "*.example.com,!bad.example.com";
    assert!(pattern_list_matches(list, "a.example.com"));
    assert!(!pattern_list_matches(list, "bad.example.com"));
    assert!(!pattern_list_matches(list, "example.com"));
    assert!(pattern_list_matches("host,10.0.0.1", "10.0.0.1"));
    assert!(pattern_list_matches("web?.test", "web1.test"));
    assert!(!pattern_list_matches("web?.test", "web12.test"));
    assert!(pattern_list_matches("[*.test]:2222", "[a.test]:2222"));
    assert!(!pattern_list_matches("*.test", "[a.test]:2222"));
    assert!(pattern_list_matches("EXAMPLE.com", "example.COM"));
    // Only negations: nothing matches.
    assert!(!pattern_list_matches("!bad", "good"));
    assert!(glob("a*b*c", "aXXbYYc"));
    assert!(!glob("a*b*c", "aXXbYY"));
    assert!(glob("*", ""));
}

/// AC5: what `ssh-keygen -F <host> -f matching.txt` finds (line numbers).
#[test]
fn matching_fixture_like_ssh_keygen_f() {
    let (entries, warnings) = parse_known_hosts(MATCHING, &src());
    assert_eq!(
        warnings,
        [ParseWarning {
            line: 9,
            reason: "missing key type".into()
        }]
    );
    let lines = |host: &str, port: u16| -> Vec<usize> {
        lookup(&entries, host, port)
            .matching
            .iter()
            .map(|e| e.line)
            .collect()
    };
    let cases: [(&str, u16, &[usize]); 14] = [
        ("plain.example.com", 22, &[3]),
        ("PLAIN.example.com", 22, &[3]),
        ("plain.example.com", 2222, &[]),
        ("example.com", 22, &[4]),
        ("example.com", 2222, &[]),
        ("web.example.com", 2222, &[5]),
        ("web.example.com", 22, &[]),
        ("a.wild.example", 22, &[6]),
        ("x.y.wild.example", 22, &[6]),
        ("bad.wild.example", 22, &[]),
        ("wild.example", 22, &[]),
        ("web1.test", 22, &[8]),
        ("web12.test", 22, &[]),
        ("10.0.0.7", 22, &[8]),
    ];
    for (host, port, want) in cases {
        assert_eq!(lines(host, port), want, "{host}:{port}");
    }
}

/// Comments, markers, hashed lines, certs, sk keys and one malformed line (sverb t09).
#[test]
fn parser_fixture_and_edge_cases() {
    let path = Path::new("/fixture/known_hosts");
    let (entries, warnings) = parse_known_hosts(PARSER, path);
    assert_eq!(
        warnings,
        [ParseWarning {
            line: 12,
            reason: "missing key".into()
        }]
    );
    let summary: Vec<(&str, &str, Marker, usize)> = entries
        .iter()
        .map(|e| {
            (
                if hashed::is_hashed(&e.host_pattern) {
                    "(hashed)"
                } else {
                    e.host_pattern.as_str()
                },
                e.key_type.as_str(),
                e.marker,
                e.line,
            )
        })
        .collect();
    use Marker::{CertAuthority, None as Plain, Revoked};
    assert_eq!(
        summary,
        [
            ("example.com,10.0.0.1", "ssh-ed25519", Plain, 3),
            ("[web.example.com]:2222", "ecdsa-sha2-nistp256", Plain, 4),
            ("(hashed)", "ssh-ed25519", Plain, 6),
            ("*.test,!bad.test", "ssh-ed25519", CertAuthority, 7),
            ("*", "ssh-rsa", Revoked, 8),
            (
                "host.test",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                Plain,
                9
            ),
            ("sk.example.com", "sk-ssh-ed25519@openssh.com", Plain, 10),
            (
                "sk2.example.com",
                "sk-ecdsa-sha2-nistp256@openssh.com",
                Plain,
                11
            ),
            ("rsa.example.com", "ssh-rsa", Plain, 13),
        ]
    );
    assert!(entries.iter().all(|e| e.source == path));
    // CA lines are dropped by lookup; revoked ones are separate.
    let m = lookup(&entries, "a.test", 22);
    assert!(m.matching.is_empty());
    assert_eq!(m.revoked.len(), 1);
    let m = lookup(&entries, "example.com", 22);
    assert_eq!(m.matching.len(), 2, "plain + hashed");

    // sverb `parser_edge_cases`.
    let ed = ED25519.split_whitespace().nth(1).unwrap();
    let text = format!(
        "h ssh-foo {ed}\n\
         @weird h ssh-ed25519 {ed}\n\
         h ssh-ed25519 !!notbase64\n\
         h ssh-rsa {ed}\n\
         |1|bad|bad ssh-ed25519 {ed}\n\
         @cert-authority\n\
         h2 ssh-ed25519 {ed}\n\
         \n\
         # comment\n\
         h3 ssh-ed25519 AAAA\n"
    );
    let (entries, warnings) = parse_known_hosts(&text, &src());
    let reasons: Vec<(usize, &str)> = warnings
        .iter()
        .map(|w| (w.line, w.reason.as_str()))
        .collect();
    assert_eq!(
        reasons,
        [
            (1, "key type ssh-foo does not match the key (ssh-ed25519)"),
            (2, "unknown marker @weird"),
            (3, "the key is not valid base64"),
            (4, "key type ssh-rsa does not match the key (ssh-ed25519)"),
            (5, "malformed hashed host name"),
            (6, "missing host patterns"),
            (10, "the key is not an SSH public key"),
        ]
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].line, 7);

    // An unknown key type whose blob says the same is kept with a warning.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let mut blob = Vec::new();
    blob.extend_from_slice(&15_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-future-key1");
    blob.extend_from_slice(&[0, 0, 0, 1, 7]);
    let line = format!("f.example ssh-future-key1 {} c", STANDARD.encode(&blob));
    let (entries, warnings) = parse_known_hosts(&line, &src());
    assert_eq!(entries.len(), 1);
    assert_eq!(
        warnings[0].reason,
        "unknown key type ssh-future-key1 (kept as is)"
    );
}

#[test]
fn rsa_signature_names_share_the_key_type() {
    assert!(same_key_type("ssh-rsa", "rsa-sha2-512"));
    assert!(same_key_type("rsa-sha2-256", "ssh-rsa"));
    assert!(same_key_type("ssh-ed25519", "ssh-ed25519"));
    assert!(!same_key_type("ssh-ed25519", "ssh-rsa"));
    assert!(!same_key_type("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"));
}

/// AC11: equal to `ssh-keygen -l` / `ssh-keygen -l -E md5` (recorded in the fixture).
#[test]
fn fingerprints_match_ssh_keygen() {
    for (pub_line, comment) in [
        (ED25519, "fixture-ed25519"),
        (ECDSA, "fixture-ecdsa"),
        (RSA, "fixture-rsa"),
    ] {
        let blob = blob_of(pub_line);
        let recorded: Vec<&str> = FINGERPRINTS
            .lines()
            .filter(|l| l.contains(comment))
            .map(|l| l.split_whitespace().nth(1).unwrap())
            .collect();
        assert_eq!(
            recorded,
            [fingerprint_sha256(&blob), fingerprint_md5(&blob)],
            "{comment}"
        );
    }
    assert_eq!(
        fingerprint_sha256(&blob_of(ED25519)),
        "SHA256:uYxmMoF3aflKiV/iuu80yjcxVbhqOX/6YopX8ub8Jko"
    );
    let md5 = fingerprint_md5(&blob_of(ED25519));
    assert_eq!(md5.len(), "MD5:".len() + 16 * 3 - 1);
}
