//! The end-to-end canary fixture for the vault (T91 §5).
//!
//! Plants canary secrets (master password, site password, backup password) and a
//! canary hostname in a real vault, and leaves everything a session writes in
//! `target/tmp/canary-vault/` (kept after the run, rewritten each time): the
//! SQLite database, copies of its `-wal`/`-shm` taken while it is open, a
//! `.cftp-backup` export and a trace-level log in the binary's format.
//! `scripts/canary-scan.sh --require-files` (CI job `canary`) then fails if a
//! secret canary appears anywhere, or the hostname appears in an `info`+ log line,
//! a database file or the backup. On Linux this test also runs the scanner itself.
//!
//! Its own test binary, so the thread-local trace subscriber sees every event.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{ItemId, Site};
use courier_ftp_core::vault::{ItemVaultExt, MemKeyring};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store};
use secrecy::SecretString;

const MASTER: &str = "CANARY-PW-master-7f3a orbit lantern";
const NEW_MASTER: &str = "CANARY-PW-newmaster-c4d2 meadow quartz";
const SITE_PW: &str = "CANARY-PW-site-91be";
const BACKUP_PW: &str = "CANARY-PASS-backup-55aa";
const HOST: &str = "canary-host-vault.example";

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("canary-vault")
}

fn copy_sidecars(db: &Path, into: &Path) -> usize {
    let mut copied = 0;
    for suffix in ["-wal", "-shm"] {
        let mut name = db.file_name().unwrap().to_os_string();
        name.push(suffix);
        let from = db.with_file_name(&name);
        if from.exists() {
            std::fs::copy(&from, into.join(&name)).unwrap();
            copied += 1;
        }
    }
    copied
}

#[tokio::test]
async fn vault_session_leaves_no_canary_behind() {
    let root = root();
    let _ = std::fs::remove_dir_all(&root);
    let (data, state, snapshot) = (root.join("data"), root.join("state"), root.join("snapshot"));
    for dir in [&data, &state, &snapshot] {
        std::fs::create_dir_all(dir).unwrap();
    }

    let log = std::fs::File::create(state.join("courier-ftp.log")).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .with_writer(Mutex::new(log))
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let keyring = MemKeyring::new();
    let db = data.join("courier-ftp.db");
    let store = Store::open_at(&db, Arc::new(ManualClock::new(1_800_000_000_000))).unwrap();
    let engine = VaultEngine::new(store, Arc::new(keyring), Argon2Cost::TEST);
    engine.initialize(&pw(MASTER), true).await.unwrap();

    let mut site = Site::new("canary-site", Protocol::Sftp, HOST);
    site.user = "deploy".into();
    site.password = Some(pw(SITE_PW));
    let id = ItemId::new();
    engine.put_view(id, None, site).await.unwrap();
    tracing::info!(item = %id, "site saved");

    engine.lock().await;
    let _ = engine.unlock(&pw("CANARY-PW-wrong")).await;
    engine.unlock(&pw(MASTER)).await.unwrap();
    engine
        .change_password(&pw(MASTER), &pw(NEW_MASTER))
        .await
        .unwrap();
    let backup = engine.export_backup(&pw(BACKUP_PW)).await.unwrap();
    std::fs::write(data.join("export.cftp-backup"), backup).unwrap();
    engine.unlock_with_keyring().await.unwrap();
    // While the database is open its WAL holds the latest pages.
    copy_sidecars(&db, &snapshot);
    engine.lock().await;
    drop(engine);
    drop(guard);

    assert!(db.exists());
    let log = std::fs::read_to_string(state.join("courier-ftp.log")).unwrap();
    assert!(log.contains(" INFO "), "logs were captured:\n{log}");

    #[cfg(target_os = "linux")]
    run_scanner(&root);
}

/// `scripts/canary-scan.sh --require-files <root>` must pass (bash 4, GNU tools:
/// Linux only; macOS ships bash 3).
#[cfg(target_os = "linux")]
fn run_scanner(root: &Path) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/canary-scan.sh");
    let out = std::process::Command::new("bash")
        .arg(&script)
        .arg("--require-files")
        .arg(root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "canary scan failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
