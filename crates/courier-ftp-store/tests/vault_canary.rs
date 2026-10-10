//! The canary-secret scan for the vault engine (T30, T91 §5): a unique master
//! password, site password and backup password never appear in the database
//! files (DB, WAL, SHM), the backup file, trace-level logs or `Debug` output.
//!
//! Its own test binary, so the thread-local trace subscriber sees every event.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{ItemId, ItemKind, Site};
use courier_ftp_core::vault::{ItemVault, ItemVaultExt, MemKeyring};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store};
use secrecy::SecretString;

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn site(name: &str, password: &str) -> Site {
    let mut s = Site::new(name, Protocol::Sftp, format!("{name}.example.com"));
    s.user = "deploy".into();
    s.password = Some(pw(password));
    s
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn files_in(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

// No secret on disk (DB, WAL, SHM), in trace-level logs or in `Debug` output.
#[tokio::test]
async fn canary_secrets_never_leak() {
    const MASTER: &str = "CANARY-MASTER-7f3a orbit lantern cobalt";
    const SITE_PW: &str = "CANARY-SITE-PW-91be";
    const NEW_MASTER: &str = "CANARY-NEWMASTER-c4d2 meadow quartz violin";
    const BACKUP_PW: &str = "CANARY-BACKUP-PW-55aa";
    let canaries = [MASTER, SITE_PW, NEW_MASTER, BACKUP_PW, "CANARY"];

    let logs = LogBuf::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let store = Store::open_at(
        dir.path().join("courier-ftp.db"),
        Arc::new(ManualClock::new(1_800_000_000_000)),
    )
    .unwrap();
    let engine = VaultEngine::new(store, Arc::new(keyring.clone()), Argon2Cost::TEST);
    engine.initialize(&pw(MASTER), true).await.unwrap();
    let id = ItemId::new();
    engine
        .put_view(id, None, site("canary-site", SITE_PW))
        .await
        .unwrap();
    let mut debug = vec![
        format!("{engine:?}"),
        format!("{:?}", engine.status().await.unwrap()),
        format!("{:?}", engine.get(id).await.unwrap()),
        format!("{:?}", engine.list(ItemKind::Site).await.unwrap()),
        format!("{:?}", engine.list_views::<Site>().await.unwrap()),
        format!("{:?}", engine.backup_items().await.unwrap()),
        format!("{keyring:?}"),
    ];
    engine.lock().await;
    debug.push(format!("{:?}", engine.unlock(&pw("CANARY-wrong")).await));
    engine.unlock(&pw(MASTER)).await.unwrap();
    engine
        .change_password(&pw(MASTER), &pw(NEW_MASTER))
        .await
        .unwrap();
    let backup = engine.export_backup(&pw(BACKUP_PW)).await.unwrap();
    engine.lock().await;
    engine.unlock_with_keyring().await.unwrap();
    engine.lock().await;
    let store_path = engine.store().path().to_path_buf();
    drop(engine);

    let files = files_in(store_path.parent().unwrap());
    assert!(
        files.iter().any(|(p, _)| p == &store_path),
        "the database was scanned"
    );
    for (path, bytes) in files {
        for canary in canaries {
            assert!(!contains(&bytes, canary), "{canary} in {}", path.display());
        }
    }
    for canary in canaries {
        assert!(!contains(&backup, canary), "{canary} in the backup");
    }
    let log = logs.0.lock().unwrap().clone();
    assert!(contains(&log, "vault unlocked"), "logs were captured");
    for canary in canaries {
        assert!(!contains(&log, canary), "{canary} in the logs");
        for d in &debug {
            assert!(!d.contains(canary), "{canary} in Debug output: {d}");
        }
    }
}
