//! Vault, pull and push helpers (T85) and sync store fixtures.

use courier_ftp_proto::b64;
use courier_ftp_proto::sync::{PullResponse, PushResponse, VaultView};
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Backend, Server};

/// One push change as JSON (key version 1).
pub fn change(id: Uuid, base: u64, envelope: &[u8], deleted: bool) -> Value {
    json!({
        "id": id,
        "base_revision": base,
        "key_version": 1,
        "envelope": b64::encode(envelope),
        "deleted": deleted,
    })
}

/// `n` new items with `len`-byte envelopes.
pub fn new_items(n: usize, len: usize) -> Vec<Value> {
    (0..n)
        .map(|i| change(Uuid::now_v7(), 0, &vec![(i % 251) as u8; len], false))
        .collect()
}

/// `POST /v1/vaults/{vault}/changes`.
pub async fn push_raw(
    h: &Server,
    token: &str,
    vault: Uuid,
    changes: Vec<Value>,
) -> (StatusCode, Value) {
    h.post(
        &format!("/v1/vaults/{vault}/changes"),
        json!({ "changes": changes }),
        Some(token),
    )
    .await
}

/// A successful push.
pub async fn push(h: &Server, token: &str, vault: Uuid, changes: Vec<Value>) -> PushResponse {
    let (st, v) = push_raw(h, token, vault, changes).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

/// `GET /v1/vaults/{vault}/changes`.
pub async fn pull_raw(
    h: &Server,
    token: &str,
    vault: Uuid,
    since: u64,
    limit: Option<u32>,
) -> (StatusCode, Value) {
    let q = limit.map_or(String::new(), |l| format!("&limit={l}"));
    h.get(
        &format!("/v1/vaults/{vault}/changes?since={since}{q}"),
        Some(token),
    )
    .await
}

/// A successful pull.
pub async fn pull(
    h: &Server,
    token: &str,
    vault: Uuid,
    since: u64,
    limit: Option<u32>,
) -> PullResponse {
    let (st, v) = pull_raw(h, token, vault, since, limit).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

/// `GET /v1/vaults`.
pub async fn vaults(h: &Server, token: &str) -> Vec<VaultView> {
    let (st, v) = h.get("/v1/vaults", Some(token)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

/// The assigned revisions of a push.
pub fn revisions(res: &PushResponse) -> Vec<Option<u64>> {
    res.results.iter().map(|r| r.revision).collect()
}

impl Server {
    /// Sets (`Some(new_key_version)`) or clears `vaults.rotation`.
    pub async fn set_rotation(&self, vault: Uuid, new_kv: Option<i32>) {
        let json = new_kv.map(|kv| {
            courier_ftp_server::sync::rotation::RotationState {
                by: Uuid::now_v7(),
                device: None,
                new_key_version: kv,
                started_at: self.now(),
            }
            .to_json()
        });
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                if let Some(v) = d.vaults.get_mut(&vault) {
                    v.rotation = json;
                }
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query("UPDATE vaults SET rotation = $2 WHERE id = $1")
                    .bind(vault)
                    .bind(json)
                    .execute(&db.pool)
                    .await
                    .unwrap();
            }
        }
    }

    /// Adds a membership row for `user` to `vault` (key version 1).
    pub async fn add_member(&self, vault: Uuid, user: Uuid, permission: &str) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vault_members
                    .push(courier_ftp_server::auth::store::mem::MemMember {
                        vault_id: vault,
                        user_id: user,
                        permission: permission.into(),
                        key_version: 1,
                        wrapped_vault_key: vec![2],
                        wrapped_by: user,
                        signature: vec![3; 64],
                    });
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO vault_members (vault_id, user_id, permission, key_version, \
                     wrapped_vault_key, wrapped_by, signature) \
                     VALUES ($1, $2, $3, 1, '\\x02', $2, '\\x03')",
                )
                .bind(vault)
                .bind(user)
                .bind(permission)
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
    }

    /// `vaults.gc_floor_revision`.
    pub async fn gc_floor(&self, vault: Uuid) -> i64 {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.vaults[&vault].gc_floor_revision),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar(
                "SELECT gc_floor_revision FROM vaults WHERE id = $1",
            )
            .bind(vault)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    /// Every stored item envelope and vault name, plus a text dump of the
    /// sync tables.
    pub async fn blob_dump(&self) -> (Vec<Vec<u8>>, String) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                let mut blobs: Vec<Vec<u8>> =
                    d.items.values().map(|i| i.envelope.clone()).collect();
                blobs.extend(d.vaults.values().map(|v| v.name_enc.clone()));
                (blobs, format!("{:?}\n{:?}", d.items, d.vaults))
            }),
            Backend::Pg(db) => {
                let mut blobs: Vec<Vec<u8>> =
                    sqlx_core::query_scalar::query_scalar("SELECT envelope FROM items")
                        .fetch_all(&db.pool)
                        .await
                        .unwrap();
                let names: Vec<Vec<u8>> =
                    sqlx_core::query_scalar::query_scalar("SELECT name_enc FROM vaults")
                        .fetch_all(&db.pool)
                        .await
                        .unwrap();
                blobs.extend(names);
                let mut text = String::new();
                for table in ["items", "vaults", "vault_members", "audit_events"] {
                    let rows: Vec<String> = sqlx_core::query_scalar::query_scalar(&format!(
                        "SELECT row_to_json(t)::text FROM {table} t"
                    ))
                    .fetch_all(&db.pool)
                    .await
                    .unwrap();
                    text.push_str(&rows.join("\n"));
                }
                (blobs, text)
            }
        }
    }

    /// The in-memory sync model (memory servers only).
    pub fn mem_sync(&self) -> &courier_ftp_server::sync::MemSync {
        match self.state.sync().store() {
            courier_ftp_server::sync::SyncStore::Memory(m) => m,
            courier_ftp_server::sync::SyncStore::Postgres(_) => panic!("not a memory server"),
        }
    }
}
