//! Shared helpers of the vault integration tests.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use courier_ftp_core::model::item::{
    FieldReader, FieldWriter, ItemBody, ItemKind, ItemView, SecretField, ViewError,
};
use courier_ftp_core::secret::SecretString;
use courier_ftp_core::trust::{MemoryHostKeyStore, SwitchableHostKeyStore};
use courier_ftp_core::vault::{Argon2Cost, MemKeyring, VaultEngine, VaultOptions};
use courier_ftp_store::{ManualClock, Store};
use sha2::{Digest, Sha256};

pub const PASSWORD: &str = "correct horse battery staple violin";
pub const NEW_PASSWORD: &str = "purple elephant dances quietly tonight";

pub fn pw(s: &str) -> SecretString {
    SecretString::from(s)
}

pub fn db(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("courier-ftp.db")
}

pub fn opts() -> VaultOptions {
    VaultOptions {
        cost: Argon2Cost::TEST,
        ..VaultOptions::default()
    }
}

pub async fn e_store(path: &Path) -> Store {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || Store::open(path))
        .await
        .unwrap()
        .unwrap()
}

fn host_keys() -> Arc<SwitchableHostKeyStore> {
    Arc::new(SwitchableHostKeyStore::new(Arc::new(
        MemoryHostKeyStore::new(),
    )))
}

pub async fn engine(path: &Path, keyring: MemKeyring) -> VaultEngine {
    VaultEngine::new(e_store(path).await, Arc::new(keyring), opts(), host_keys())
}

pub async fn engine_with_clock(
    path: &Path,
    keyring: MemKeyring,
    clock: Arc<ManualClock>,
) -> VaultEngine {
    let path = path.to_path_buf();
    let store = tokio::task::spawn_blocking(move || Store::open_with_clock(path, clock))
        .await
        .unwrap()
        .unwrap();
    VaultEngine::new(store, Arc::new(keyring), opts(), host_keys())
}

/// A minimal `site` view (T31 owns the real one).
#[derive(Debug, PartialEq, Eq)]
pub struct TestSite {
    pub host: String,
    pub user: String,
    pub password: SecretField,
}

pub fn site(host: &str, password: &str) -> TestSite {
    TestSite {
        host: host.into(),
        user: "user".into(),
        password: SecretField::Value(password.into()),
    }
}

impl ItemView for TestSite {
    const KIND: ItemKind = ItemKind::Site;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        Ok(Self {
            host: r.req_text("host")?,
            user: r.text("user", "")?,
            password: r.secret("password")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.req_text(body, "host", &self.host);
        w.text(body, "user", &self.user, "");
        w.secret(body, "password", &self.password);
    }
}

/// A minimal `bookmark` view (T33 owns the real one).
#[derive(Debug, PartialEq, Eq)]
pub struct TestBookmark {
    pub remote: String,
}

impl ItemView for TestBookmark {
    const KIND: ItemKind = ItemKind::Bookmark;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        Ok(Self {
            remote: r.req_text("remote")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.req_text(body, "remote", &self.remote);
    }
}

/// A minimal `history-entry` view (T33 owns the real one).
#[derive(Debug, PartialEq, Eq)]
pub struct TestHistory {
    pub host: String,
    pub password: SecretField,
}

impl ItemView for TestHistory {
    const KIND: ItemKind = ItemKind::HistoryEntry;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let r = FieldReader::for_kind(body, Self::KIND)?;
        Ok(Self {
            host: r.req_text("host")?,
            password: r.secret("password")?,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>) {
        w.req_text(body, "host", &self.host);
        w.secret(body, "password", &self.password);
    }
}

/// `(table:key, sha256(row))` of every meta, vault and item row, sorted.
pub async fn snapshot(store: &Store) -> Vec<(String, [u8; 32])> {
    store
        .read(|r| {
            let mut out = Vec::new();
            let conn = r.conn();
            let mut stmt = conn.prepare("SELECT key, value FROM meta")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (k, v) = row?;
                out.push((format!("meta:{k}"), Sha256::digest(&v).into()));
            }
            let mut stmt = conn.prepare(
                "SELECT id, kind, key_version, wrapped_key, sync_cursor FROM vaults",
            )?;
            let rows = stmt.query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let rest = format!(
                    "{}:{}:{}",
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(4)?
                );
                let wk: Vec<u8> = row.get(3)?;
                Ok((id, rest, wk))
            })?;
            for row in rows {
                let (id, rest, wk) = row?;
                let mut h = Sha256::new();
                h.update(rest.as_bytes());
                h.update(&wk);
                out.push((format!("vault:{}", hex(&id)), h.finalize().into()));
            }
            let mut stmt = conn.prepare(
                "SELECT id, vault_id, revision, key_version, envelope, deleted, dirty, updated_at FROM items",
            )?;
            let rows = stmt.query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let mut h = Sha256::new();
                h.update(row.get::<_, Vec<u8>>(1)?);
                h.update(row.get::<_, i64>(2)?.to_be_bytes());
                h.update(row.get::<_, i64>(3)?.to_be_bytes());
                h.update(row.get::<_, Vec<u8>>(4)?);
                h.update([u8::from(row.get::<_, bool>(5)?), u8::from(row.get::<_, bool>(6)?)]);
                h.update(row.get::<_, i64>(7)?.to_be_bytes());
                Ok((id, <[u8; 32]>::from(h.finalize())))
            })?;
            for row in rows {
                let (id, h) = row?;
                out.push((format!("item:{}", hex(&id)), h));
            }
            out.sort();
            Ok(out)
        })
        .await
        .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A `tracing` writer into a shared buffer.
#[derive(Clone, Default)]
pub struct LogBuf(pub Arc<Mutex<Vec<u8>>>);

impl LogBuf {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `f` with a thread-local TRACE subscriber (only events on this thread are
/// captured: use a current-thread runtime) and returns the log text.
pub async fn capture_logs<F, Fut>(f: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    // Parallel tests leave the process-wide callsite interest cache stale.
    tracing::callsite::rebuild_interest_cache();
    f().await;
    drop(guard);
    buf.text()
}
