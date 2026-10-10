//! The client side of the tests: registration, login and the account
//! crypto exactly as the sync client (T87) will do it, with the real
//! `courier_ftp_crypto` code (cheap test KSF), plus store-level fixtures
//! for both backends.

use courier_ftp_crypto::account::{
    AccountKeys, derive_akek, generate_account_keys, seal_private_bundle,
};
use courier_ftp_crypto::grant::self_grant;
use courier_ftp_crypto::keys::{Key32, os_rng, random_key32};
use courier_ftp_crypto::opaque::{CourierKsf, client_login_start, client_registration_start};
use courier_ftp_crypto::recovery::{RecoveryKey, recovery_key_generate, seal_recovery_bundle};
use courier_ftp_proto::auth::SessionResponse;
use courier_ftp_proto::b64;
use courier_ftp_server::registration::{self, RegistrationMode, hash_token};
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Backend, Server};

/// The cheap OPAQUE KSF (feature `insecure-test-ksf`).
pub fn ksf() -> CourierKsf {
    CourierKsf::insecure_for_tests()
}

/// A registered account as the client sees it.
#[derive(Debug)]
pub struct Account {
    pub email: String,
    pub password: Vec<u8>,
    pub user_id: Uuid,
    pub keys: AccountKeys,
    pub recovery: RecoveryKey,
    pub vault_id: Uuid,
    /// The personal vault key.
    pub vault_key: Key32,
    pub session: SessionResponse,
}

impl Account {
    /// The registration device's access token.
    pub fn access(&self) -> &str {
        &self.session.tokens.access_token
    }
}

/// Shallow-merges the keys of `extra` into `into`.
pub fn merge(into: &mut Value, extra: &Value) {
    if let (Some(a), Some(b)) = (into.as_object_mut(), extra.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
}

/// Registration through both endpoints, building keys, bundles and the
/// self-grant like the client will.
pub async fn try_register(
    h: &Server,
    email: &str,
    password: &str,
    extra: Value,
    vault_id: Option<Uuid>,
) -> Result<Account, (StatusCode, Value)> {
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password.as_bytes()).unwrap();
    let mut start = json!({ "email": email, "registration_request": b64::encode(&request) });
    merge(&mut start, &extra);
    let (st, v) = h.post("/v1/auth/register/start", start, None).await;
    if st != StatusCode::OK {
        return Err((st, v));
    }
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let fin = state
        .finish(&mut rng, password.as_bytes(), &response, &ksf())
        .unwrap();
    let akek = derive_akek(&fin.export_key);
    let keys = generate_account_keys(&mut rng);
    let uid = *user_id.as_bytes();
    let private = seal_private_bundle(&akek, &uid, 1, &keys, &mut rng).unwrap();
    let (recovery, _words) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, &uid, &keys, &mut rng).unwrap();
    let vault_id = vault_id.unwrap_or_else(Uuid::now_v7);
    let vk = random_key32(&mut rng);
    let grant = self_grant(&vk, vault_id.as_bytes(), 1, &uid, &keys, &mut rng).unwrap();
    let pubk = keys.public();
    let mut finish = json!({
        "email": email,
        "user_id": user_id,
        "registration_upload": b64::encode(&fin.upload),
        "account_keys": {
            "x25519_pub": b64::encode(&pubk.x25519),
            "ed25519_pub": b64::encode(&pubk.ed25519),
            "private_bundle_enc": b64::encode(&private),
            "recovery_bundle_enc": b64::encode(&rbundle),
            "version": 1,
        },
        "personal_vault": {
            "id": vault_id,
            "name_enc": b64::encode(b"encrypted-name"),
            "self_grant": {
                "wrapped_vault_key": b64::encode(&grant.wrapped),
                "signature": b64::encode(&grant.signature),
                "key_version": 1,
            },
        },
        "device": { "name": "laptop", "platform": "linux" },
    });
    merge(&mut finish, &extra);
    let (st, v) = h.post("/v1/auth/register/finish", finish, None).await;
    if st != StatusCode::OK {
        return Err((st, v));
    }
    let session: SessionResponse = serde_json::from_value(v).unwrap();
    Ok(Account {
        email: email.to_owned(),
        password: password.as_bytes().to_vec(),
        user_id,
        keys,
        recovery,
        vault_id,
        vault_key: vk,
        session,
    })
}

/// Registers or panics.
pub async fn register(h: &Server, email: &str, password: &str) -> Account {
    match try_register(h, email, password, json!({}), None).await {
        Ok(a) => a,
        Err((st, v)) => panic!("registration failed: {st} {v}"),
    }
}

/// Opens registration and registers one account.
pub async fn open_and_register(h: &Server, email: &str) -> Account {
    h.set_mode(RegistrationMode::Open).await;
    register(h, email, "correct horse battery staple").await
}

/// The outcome of one login attempt.
#[derive(Debug)]
pub struct Login {
    pub status: StatusCode,
    pub body: Value,
    pub export_key: Option<[u8; 64]>,
}

/// One login attempt; when the client can't open KE2 (wrong password,
/// unknown account) it sends a random KE3 like an attacker would.
pub async fn login_with(h: &Server, email: &str, password: &[u8], extra: Value) -> Login {
    let mut rng = os_rng();
    let (client, ke1) = client_login_start(&mut rng, password).unwrap();
    let (st, v) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": email, "credential_request": b64::encode(&ke1) }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "login/start: {v}");
    let ke2 = b64::decode(v["credential_response"].as_str().unwrap()).unwrap();
    let (ke3, export_key) = match client.finish(&mut rng, password, &ke2, &ksf()) {
        Ok(f) => (f.finalization, Some(*f.export_key)),
        Err(_) => (random_key32(&mut rng).expose_secret().repeat(2), None),
    };
    let mut body = json!({
        "login_state_id": v["login_state_id"],
        "credential_finalization": b64::encode(&ke3),
        "device": { "name": "phone", "platform": "android" },
    });
    merge(&mut body, &extra);
    let (status, body) = h.post("/v1/auth/login/finish", body, None).await;
    Login {
        status,
        body,
        export_key,
    }
}

/// A successful login on a new device.
pub async fn login(h: &Server, a: &Account) -> SessionResponse {
    let l = login_with(h, &a.email, &a.password, json!({})).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    serde_json::from_value(l.body).unwrap()
}

/// A reauth token from a `purpose: reauth` login.
pub async fn reauth(h: &Server, a: &Account, password: &[u8]) -> String {
    let l = login_with(h, &a.email, password, json!({ "purpose": "reauth" })).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    assert!(l.body.get("tokens").is_none());
    l.body["reauth_token"].as_str().unwrap().to_owned()
}

/// Status of `GET /v1/devices` with `access`.
pub async fn devices_status(h: &Server, access: &str) -> StatusCode {
    h.get("/v1/devices", Some(access)).await.0
}

/// A new OPAQUE registration for `new_password` via `start`, returning the
/// upload, the new private bundle (bound to `version`) and the start
/// response.
pub async fn new_password_material(
    h: &Server,
    start: (&str, Value, Option<&str>),
    response_field: &str,
    new_password: &str,
    user_id: Uuid,
    keys: &AccountKeys,
    version: u32,
) -> (Vec<u8>, Vec<u8>, Value) {
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, new_password.as_bytes()).unwrap();
    let mut body = start.1;
    merge(
        &mut body,
        &json!({ "registration_request": b64::encode(&request) }),
    );
    let (st, v) = h.post(start.0, body, start.2).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let response = b64::decode(v[response_field].as_str().unwrap()).unwrap();
    let fin = state
        .finish(&mut rng, new_password.as_bytes(), &response, &ksf())
        .unwrap();
    let akek = derive_akek(&fin.export_key);
    let bundle = seal_private_bundle(&akek, user_id.as_bytes(), version, keys, &mut rng).unwrap();
    (fin.upload, bundle, v)
}

// --------------------------------------------------------- store fixtures

impl Server {
    /// Sets the registration mode.
    pub async fn set_mode(&self, mode: RegistrationMode) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.registration_mode = mode),
            Backend::Pg(db) => registration::set_mode(&db.pool, mode).await.unwrap(),
        }
    }

    /// Replaces the setup-token hash.
    pub async fn set_setup_token(&self, token: &str) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.set_setup_token(token)),
            Backend::Pg(db) => courier_ftp_server::settings::set(
                &db.pool,
                courier_ftp_server::settings::SETUP_TOKEN_HASH,
                &hex::encode(hash_token(token)),
            )
            .await
            .unwrap(),
        }
    }

    /// An email-bound instance invite; returns the token.
    pub async fn invite(&self, email: &str) -> String {
        let token = registration::generate_token();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.add_invite(&token, Some(email))),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO invites (id, org_id, email, token_hash, expires_at) \
                     VALUES ($1, NULL, $2, $3, now() + interval '7 days')",
                )
                .bind(Uuid::now_v7())
                .bind(email)
                .bind(&hash_token(&token)[..])
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
        token
    }

    /// Whether an account with `email` exists.
    pub async fn user_exists(&self, email: &str) -> bool {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.users
                    .values()
                    .any(|u| u.email.eq_ignore_ascii_case(email))
            }),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM users WHERE email = $1::citext)",
            )
            .bind(email)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    /// Disables an account.
    pub async fn disable(&self, email: &str) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                for u in d.users.values_mut().filter(|u| u.email == email) {
                    u.disabled = true;
                }
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "UPDATE users SET disabled = true WHERE email = $1::citext",
                )
                .bind(email)
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
    }

    /// Issues a recovery code (what the admin CLI does).
    pub async fn recovery_code(&self, email: &str) -> String {
        courier_ftp_server::routes::account::issue_recovery_code(
            self.state.auth().store(),
            email,
            self.now(),
        )
        .await
        .unwrap()
        .unwrap()
    }

    /// Text of everything stored about tokens (a stand-in for a DB dump).
    pub async fn dump(&self) -> String {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                format!(
                    "{:?}\n{:?}\n{:?}\n{:?}",
                    d.tokens, d.reauth, d.devices, d.login_states
                )
            }),
            Backend::Pg(db) => {
                let mut out = String::new();
                for table in [
                    "auth_tokens",
                    "reauth_tokens",
                    "devices",
                    "login_states",
                    "users",
                    "account_keys",
                    "audit_events",
                ] {
                    let rows: Vec<String> = sqlx_core::query_scalar::query_scalar(&format!(
                        "SELECT row_to_json(t)::text FROM {table} t"
                    ))
                    .fetch_all(&db.pool)
                    .await
                    .unwrap();
                    out.push_str(&rows.join("\n"));
                    out.push('\n');
                }
                out
            }
        }
    }

    /// Number of `auth_tokens` rows.
    pub async fn token_rows(&self) -> usize {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.tokens.len()),
            Backend::Pg(db) => {
                let n: i64 =
                    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM auth_tokens")
                        .fetch_one(&db.pool)
                        .await
                        .unwrap();
                usize::try_from(n).unwrap()
            }
        }
    }

    /// Audit event kinds, oldest first.
    pub async fn audit_kinds(&self) -> Vec<String> {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.audit.iter().map(|a| a.kind.clone()).collect()),
            Backend::Pg(db) => {
                sqlx_core::query_scalar::query_scalar("SELECT kind FROM audit_events ORDER BY id")
                    .fetch_all(&db.pool)
                    .await
                    .unwrap()
            }
        }
    }

    /// Makes the personal-vault insert of the next registration with `id`
    /// fail.
    pub async fn occupy_vault_id(&self, id: Uuid) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.fail_vault_insert = true),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO vaults (id, kind, owner_user_id, org_id, name_enc) \
                     VALUES ($1, 'shared', NULL, NULL, '\\x00')",
                )
                .bind(id)
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
    }

    /// Undoes [`Self::occupy_vault_id`].
    pub async fn release_vault_id(&self, id: Uuid) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.fail_vault_insert = false),
            Backend::Pg(db) => {
                sqlx_core::query::query("DELETE FROM vaults WHERE id = $1")
                    .bind(id)
                    .execute(&db.pool)
                    .await
                    .unwrap();
            }
        }
    }

    /// A shared vault (no org) with `members` at `permission`; the first
    /// member is the granter. Team vaults proper are T89.
    pub async fn shared_vault(&self, members: &[Uuid], permission: &str) -> Uuid {
        let id = Uuid::now_v7();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vaults.insert(
                    id,
                    courier_ftp_server::auth::store::mem::MemVault::shared(None, vec![1], 1),
                );
                for u in members {
                    d.vault_members
                        .push(courier_ftp_server::auth::store::mem::MemMember {
                            vault_id: id,
                            user_id: *u,
                            permission: permission.into(),
                            key_version: 1,
                            wrapped_vault_key: vec![2],
                            wrapped_by: members[0],
                            signature: vec![3; 64],
                        });
                }
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO vaults (id, kind, owner_user_id, org_id, name_enc) \
                     VALUES ($1, 'shared', NULL, NULL, '\\x01')",
                )
                .bind(id)
                .execute(&db.pool)
                .await
                .unwrap();
                for u in members {
                    sqlx_core::query::query(
                        "INSERT INTO vault_members (vault_id, user_id, permission, key_version, \
                         wrapped_vault_key, wrapped_by, signature) \
                         VALUES ($1, $2, $4, 1, '\\x02', $3, '\\x03')",
                    )
                    .bind(id)
                    .bind(u)
                    .bind(members[0])
                    .bind(permission)
                    .execute(&db.pool)
                    .await
                    .unwrap();
                }
            }
        }
        id
    }

    /// Inserts an item row directly.
    pub async fn add_item(&self, vault: Uuid, revision: i64) {
        let item = Uuid::now_v7();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.items.insert(
                    (vault, item),
                    courier_ftp_server::auth::store::mem::MemItem {
                        revision,
                        key_version: 1,
                        envelope: vec![9; 8],
                        deleted: false,
                        updated_at: chrono::Utc::now(),
                        updated_by_device: None,
                    },
                );
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO items (vault_id, id, revision, key_version, envelope, updated_at) \
                     VALUES ($1, $2, $3, 1, '\\x09', now())",
                )
                .bind(vault)
                .bind(item)
                .bind(revision)
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
    }

    /// Number of items in `vault`.
    pub async fn count_items(&self, vault: Uuid) -> usize {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.items.keys().filter(|(v, _)| *v == vault).count()),
            Backend::Pg(db) => {
                let n: i64 = sqlx_core::query_scalar::query_scalar(
                    "SELECT count(*) FROM items WHERE vault_id = $1",
                )
                .bind(vault)
                .fetch_one(&db.pool)
                .await
                .unwrap();
                usize::try_from(n).unwrap()
            }
        }
    }

    /// Whether `vault` exists.
    pub async fn vault_exists(&self, vault: Uuid) -> bool {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.vaults.contains_key(&vault)),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM vaults WHERE id = $1)",
            )
            .bind(vault)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    /// Whether `user` has a grant for `vault`.
    pub async fn is_member(&self, vault: Uuid, user: Uuid) -> bool {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vault_members
                    .iter()
                    .any(|x| x.vault_id == vault && x.user_id == user)
            }),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM vault_members WHERE vault_id = $1 AND user_id = $2)",
            )
            .bind(vault)
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }
}
