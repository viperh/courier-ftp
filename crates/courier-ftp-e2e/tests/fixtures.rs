//! The fixture directories match the harness (no Docker): profile files ↔ enum names,
//! keys present, parseable and marked TEST-ONLY, the duplicated files identical, every
//! base image from the ECR mirror, and `check-configs.sh` passes when `sshd` exists.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::BTreeSet, path::Path, process::Command};

use courier_ftp_e2e::{
    FtpdProfile, ProxyProfile, SshdProfile,
    keys::{FixtureKey, KEY_COMMENT, PASSPHRASE, fixtures_dir},
};

fn profile_files(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "conf"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect()
}

fn names(it: impl IntoIterator<Item = &'static str>) -> BTreeSet<String> {
    it.into_iter().map(str::to_owned).collect()
}

#[test]
fn sshd_profiles_match_files() {
    assert_eq!(
        profile_files(&fixtures_dir().join("sshd/profiles")),
        names(SshdProfile::ALL.map(SshdProfile::name))
    );
}

#[test]
fn ftpd_profiles_match_files() {
    assert_eq!(
        profile_files(&fixtures_dir().join("ftpd/profiles")),
        names(FtpdProfile::ALL.map(FtpdProfile::name))
    );
}

#[test]
fn proxy_profiles_match_files() {
    assert_eq!(
        profile_files(&fixtures_dir().join("proxy/profiles")),
        names(ProxyProfile::ALL.map(ProxyProfile::name))
    );
}

#[test]
fn fixture_keys_present_and_marked_test_only() {
    for dir in ["sshd/keys", "tls", "ftpd/tls"] {
        let readme = fixtures_dir().join(dir).join("README.md");
        let text = std::fs::read_to_string(&readme)
            .unwrap_or_else(|e| panic!("{}: {e}", readme.display()));
        assert!(
            text.contains("TEST-ONLY"),
            "{} must say TEST-ONLY",
            readme.display()
        );
    }
    for key in FixtureKey::ALL {
        assert!(
            key.path().is_file(),
            "{key:?}: {} missing",
            key.path().display()
        );
        let public = key.public();
        assert!(
            public.ends_with(KEY_COMMENT) || public.contains(KEY_COMMENT),
            "{public}"
        );
    }
    let authorized =
        std::fs::read_to_string(fixtures_dir().join("sshd/keys/authorized_keys")).unwrap();
    for key in [
        FixtureKey::Ed25519,
        FixtureKey::Ecdsa,
        FixtureKey::Rsa,
        FixtureKey::Ed25519Encrypted,
    ] {
        assert!(authorized.contains(&key.public()), "{key:?} not authorized");
    }
    for name in ["ca.pem", "ca.key"] {
        assert!(
            fixtures_dir().join("tls").join(name).is_file(),
            "tls/{name}"
        );
    }
}

/// Every key parses (and decrypts) with the `ssh-key` crate the client uses, and its
/// public half equals the committed `.pub`.
#[test]
fn fixture_keys_parse() {
    for key in FixtureKey::ALL {
        let text = std::fs::read_to_string(key.path()).unwrap();
        let private = match key {
            FixtureKey::PpkV2 | FixtureKey::PpkV3 | FixtureKey::PpkV3Encrypted => {
                ssh_key::PrivateKey::from_ppk(&text, key.passphrase().map(str::to_owned))
                    .unwrap_or_else(|e| panic!("{key:?}: {e}"))
            }
            _ => {
                let parsed = ssh_key::PrivateKey::from_openssh(&text)
                    .unwrap_or_else(|e| panic!("{key:?}: {e}"));
                if parsed.is_encrypted() {
                    parsed.decrypt(PASSPHRASE).unwrap()
                } else {
                    parsed
                }
            }
        };
        let public = private.public_key().to_openssh().unwrap();
        let want_line = key.public();
        let want: Vec<&str> = want_line.split_whitespace().take(2).collect();
        let got: Vec<&str> = public.split_whitespace().take(2).collect();
        assert_eq!(got, want, "{key:?}");
    }
    // The encrypted PPK refuses a wrong passphrase.
    let text = std::fs::read_to_string(FixtureKey::PpkV3Encrypted.path()).unwrap();
    assert!(ssh_key::PrivateKey::from_ppk(&text, Some("wrong".into())).is_err());
}

/// Files the image build contexts need twice stay identical.
#[test]
fn duplicated_fixture_files_are_identical() {
    let d = fixtures_dir();
    for (a, b) in [
        ("sshd/bin/make-fixture-tree", "ftpd/bin/make-fixture-tree"),
        ("tls/ca.pem", "ftpd/tls/ca.pem"),
        ("tls/ca.key", "ftpd/tls/ca.key"),
    ] {
        assert_eq!(
            std::fs::read(d.join(a)).unwrap(),
            std::fs::read(d.join(b)).unwrap(),
            "{a} and {b} differ"
        );
    }
}

/// `make-fixture-tree` and `files::FIXTURE_TREE` describe the same tree.
#[test]
fn make_fixture_tree_matches_fixture_tree() {
    let script =
        std::fs::read_to_string(fixtures_dir().join("sshd/bin/make-fixture-tree")).unwrap();
    for (path, size) in courier_ftp_e2e::files::FIXTURE_TREE {
        assert!(
            script.contains(&format!("(\"{path}\", {size})")),
            "{path} ({size}) missing in make-fixture-tree"
        );
    }
    for (link, target) in courier_ftp_e2e::files::FIXTURE_SYMLINKS {
        assert!(script.contains(&format!("(\"{link}\", \"{target}\")")));
    }
}

/// Every image is based on the ECR mirror of the Docker official images (no Docker
/// Hub pulls on CI).
#[test]
fn dockerfiles_use_the_ecr_mirror() {
    for image in courier_ftp_e2e::docker::FIXTURE_IMAGES {
        let path = fixtures_dir().join(image).join("Dockerfile");
        let text = std::fs::read_to_string(&path).unwrap();
        let froms: Vec<&str> = text
            .lines()
            .filter(|l| l.trim_start().to_ascii_uppercase().starts_with("FROM "))
            .collect();
        assert!(!froms.is_empty(), "{}", path.display());
        for from in froms {
            assert!(
                from.contains("public.ecr.aws/docker/library/"),
                "{}: {from}",
                path.display()
            );
        }
    }
}

#[test]
fn sshd_configs_pass_sshd_t() {
    let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let Some(sshd) = sshd else {
        eprintln!("skipped: no sshd binary installed");
        return;
    };
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("skipped: no ssh-keygen");
        return;
    }
    let out = Command::new("bash")
        .arg(fixtures_dir().join("sshd/check-configs.sh"))
        .arg(sshd)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
