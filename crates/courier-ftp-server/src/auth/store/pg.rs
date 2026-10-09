//! PostgreSQL backend of [`super::Store`]. Runtime-checked queries
//! (`sqlx_core::query*`), so building never needs a database; timestamps are
//! bound from the injectable clock.

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::{PgConnection, PgPool};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    AccountKeysRow, DeviceChoice, DeviceRow, KEY_VERSION_CHANGED_MESSAGE, LoginStateRow, LoginUser,
    NewAccount, NewCredentials, NewDevice, NewInvite, REAUTH_REQUIRED_MESSAGE,
    RECOVERY_CODE_INVALID_MESSAGE, RecoveryInfo, RefreshOutcome, RegisterOutcome,
    RegistrationCredential, TotpState,
};
use crate::auth::extractor::AuthCtx;
use crate::auth::tokens::{
    IssuedTokens, LAST_SEEN_THROTTLE, RECOVERY_CODE_MAX_ATTEMPTS, TokenHash,
};
use crate::error::ApiError;
use crate::registration::{
    self, Decision, EMAIL_TAKEN_MESSAGE, InviteFacts, PolicyFacts, RegistrationMode,
    VAULT_TAKEN_MESSAGE,
};
use crate::settings_kv;

type Res<T> = Result<T, ApiError>;

/// The constraint of a unique violation (`23505`), if `e` is one.
fn unique_violation(e: &sqlx_core::Error) -> Option<String> {
    match e {
        sqlx_core::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            Some(db.constraint().unwrap_or_default().to_owned())
        }
        _ => None,
    }
}

async fn insert_tokens(
    conn: &mut PgConnection,
    device_id: Uuid,
    tokens: &IssuedTokens,
    family: Uuid,
) -> Res<()> {
    for rec in tokens.records() {
        query(
            "INSERT INTO auth_tokens (token_hash, device_id, kind, expires_at, family, used_at) \
             VALUES ($1, $2, $3, $4, $5, NULL)",
        )
        .bind(&rec.hash.0[..])
        .bind(device_id)
        .bind(rec.kind.as_str())
        .bind(rec.expires_at)
        .bind(family)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn insert_device(
    conn: &mut PgConnection,
    user_id: Uuid,
    d: &NewDevice,
    now: OffsetDateTime,
) -> Res<()> {
    query(
        "INSERT INTO devices (id, user_id, name, platform, created_at, last_seen_at, revoked_at) \
         VALUES ($1, $2, $3, $4, $5, $5, NULL)",
    )
    .bind(d.id)
    .bind(user_id)
    .bind(&d.name)
    .bind(&d.platform)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn audit_in(
    conn: &mut PgConnection,
    actor: Option<Uuid>,
    kind: &str,
    target: Option<Uuid>,
    meta: serde_json::Value,
    now: OffsetDateTime,
) -> Res<()> {
    query(
        "INSERT INTO audit_events (org_id, actor_user_id, kind, target, at, meta) \
         VALUES (NULL, $1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(kind)
    .bind(target)
    .bind(now)
    .bind(meta)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Gathers the policy facts. With `lock`, the setup-token setting and the invite
/// row are locked (`FOR UPDATE`) until the transaction ends, so two
/// registrations can't consume the same token.
async fn policy_facts(
    conn: &mut PgConnection,
    cred: RegistrationCredential<'_>,
    lock: bool,
) -> Res<PolicyFacts> {
    let for_update = if lock { " FOR UPDATE" } else { "" };
    let mode: Option<String> = query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(settings_kv::REGISTRATION_MODE)
        .fetch_optional(&mut *conn)
        .await?;
    let no_users: bool = query_scalar("SELECT NOT EXISTS (SELECT 1 FROM users)")
        .fetch_one(&mut *conn)
        .await?;
    let setup_token_hash: Option<String> = match cred {
        RegistrationCredential::SetupToken(_) => {
            query_scalar(&format!(
                "SELECT value FROM settings WHERE key = $1{for_update}"
            ))
            .bind(settings_kv::SETUP_TOKEN_HASH)
            .fetch_optional(&mut *conn)
            .await?
        }
        _ => None,
    };
    let invite = match cred {
        RegistrationCredential::InviteToken(t) => {
            let row: Option<(
                Uuid,
                Option<Uuid>,
                Option<String>,
                Vec<u8>,
                OffsetDateTime,
                bool,
            )> = query_as(&format!(
                "SELECT id, org_id, lower(email::text), token_hash, expires_at, \
                            accepted_at IS NOT NULL \
                     FROM invites WHERE token_hash = $1{for_update}"
            ))
            .bind(&registration::hash_token(t)[..])
            .fetch_optional(&mut *conn)
            .await?;
            row.map(
                |(id, org_id, email, token_hash, expires_at, accepted)| InviteFacts {
                    id,
                    org_id,
                    email,
                    token_hash,
                    expires_at,
                    accepted,
                },
            )
        }
        _ => None,
    };
    Ok(PolicyFacts {
        mode: RegistrationMode::from_stored(mode.as_deref()),
        no_users,
        setup_token_hash,
        invite,
    })
}

async fn email_taken(conn: &mut PgConnection, email: &str) -> Res<bool> {
    Ok(
        query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1::citext)")
            .bind(email)
            .fetch_one(&mut *conn)
            .await?,
    )
}

pub(super) async fn check_registration(
    pool: &PgPool,
    email: &str,
    cred: RegistrationCredential<'_>,
    now: OffsetDateTime,
) -> Res<()> {
    let mut conn = pool.acquire().await?;
    let facts = policy_facts(&mut conn, cred, false).await?;
    registration::authorize(&facts, email, cred, now)?;
    if email_taken(&mut conn, email).await? {
        return Err(ApiError::Conflict(EMAIL_TAKEN_MESSAGE.into()));
    }
    Ok(())
}

async fn apply_decision(conn: &mut PgConnection, d: &Decision, now: OffsetDateTime) -> Res<()> {
    if d.consume_setup_token {
        query("DELETE FROM settings WHERE key = $1")
            .bind(settings_kv::SETUP_TOKEN_HASH)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(id) = d.accept_invite {
        query("UPDATE invites SET accepted_at = $2 WHERE id = $1")
            .bind(id)
            .bind(now)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

pub(super) async fn register(
    pool: &PgPool,
    a: &NewAccount,
    cred: RegistrationCredential<'_>,
    tokens: &IssuedTokens,
    family: Uuid,
    now: OffsetDateTime,
) -> Res<RegisterOutcome> {
    let mut tx = pool.begin().await?;
    let facts = policy_facts(&mut tx, cred, true).await?;
    let decision = registration::authorize(&facts, &a.email, cred, now)?;
    apply_decision(&mut tx, &decision, now).await?;
    let conflict = |e: sqlx_core::Error| -> ApiError {
        match unique_violation(&e).as_deref() {
            Some("vaults_pkey") => ApiError::Conflict(VAULT_TAKEN_MESSAGE.into()),
            Some(_) => ApiError::Conflict(EMAIL_TAKEN_MESSAGE.into()),
            None => e.into(),
        }
    };
    query(
        "INSERT INTO users (id, email, created_at, is_instance_admin, opaque_record) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(a.user_id)
    .bind(&a.email)
    .bind(now)
    .bind(decision.consume_setup_token)
    .bind(&a.opaque_record)
    .execute(&mut *tx)
    .await
    .map_err(conflict)?;
    query(
        "INSERT INTO account_keys \
         (user_id, x25519_pub, ed25519_pub, private_bundle_enc, recovery_bundle_enc, version) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(a.user_id)
    .bind(&a.keys.x25519_pub)
    .bind(&a.keys.ed25519_pub)
    .bind(&a.keys.private_bundle_enc)
    .bind(&a.keys.recovery_bundle_enc)
    .bind(a.keys.version)
    .execute(&mut *tx)
    .await?;
    insert_device(&mut tx, a.user_id, &a.device, now).await?;
    query(
        "INSERT INTO vaults (id, kind, owner_user_id, org_id, created_by, key_version, \
                             head_revision, name_enc, created_at) \
         VALUES ($1, 'personal', $2, NULL, $2, $3, 0, $4, $5)",
    )
    .bind(a.vault_id)
    .bind(a.user_id)
    .bind(a.grant_key_version)
    .bind(&a.vault_name_enc)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(conflict)?;
    query(
        "INSERT INTO vault_members \
         (vault_id, user_id, permission, key_version, wrapped_vault_key, wrapped_by, signature) \
         VALUES ($1, $2, 'manage', $3, $4, $2, $5)",
    )
    .bind(a.vault_id)
    .bind(a.user_id)
    .bind(a.grant_key_version)
    .bind(&a.grant_wrapped)
    .bind(&a.grant_signature)
    .execute(&mut *tx)
    .await?;
    insert_tokens(&mut tx, a.device.id, tokens, family).await?;
    tx.commit().await?;
    Ok(RegisterOutcome {
        is_instance_admin: decision.consume_setup_token,
        org_invite: decision.org_invite,
    })
}

type UserTuple = (Uuid, String, Vec<u8>, bool, bool, Option<Vec<u8>>);

fn login_user(t: UserTuple) -> LoginUser {
    LoginUser {
        id: t.0,
        email: t.1,
        opaque_record: t.2,
        disabled: t.3,
        is_instance_admin: t.4,
        totp_secret_enc: t.5,
    }
}

const USER_COLS: &str =
    "id, lower(email::text), opaque_record, disabled, is_instance_admin, totp_secret_enc";

pub(super) async fn user_by_email(pool: &PgPool, email: &str) -> Res<Option<LoginUser>> {
    let row: Option<UserTuple> = query_as(&format!(
        "SELECT {USER_COLS} FROM users WHERE email = $1::citext"
    ))
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(login_user))
}

pub(super) async fn user_by_id(pool: &PgPool, id: Uuid) -> Res<Option<LoginUser>> {
    let row: Option<UserTuple> = query_as(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(login_user))
}

pub(super) async fn put_login_state(
    pool: &PgPool,
    row: &LoginStateRow,
    now: OffsetDateTime,
) -> Res<()> {
    query(
        "DELETE FROM login_states WHERE id IN \
         (SELECT id FROM login_states WHERE expires_at <= $1 LIMIT 100)",
    )
    .bind(now)
    .execute(pool)
    .await?;
    query("INSERT INTO login_states (id, user_id, state_enc, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(row.id)
        .bind(row.user_id)
        .bind(&row.state_enc)
        .bind(row.expires_at)
        .execute(pool)
        .await?;
    Ok(())
}

pub(super) async fn take_login_state(
    pool: &PgPool,
    id: Uuid,
    now: OffsetDateTime,
) -> Res<Option<LoginStateRow>> {
    let row: Option<(Uuid, Option<Uuid>, Vec<u8>, OffsetDateTime)> = query_as(
        "DELETE FROM login_states WHERE id = $1 RETURNING id, user_id, state_enc, expires_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .filter(|r| r.3 > now)
        .map(|(id, user_id, state_enc, expires_at)| LoginStateRow {
            id,
            user_id,
            state_enc,
            expires_at,
        }))
}

pub(super) async fn consume_totp_step(pool: &PgPool, user: Uuid, step: i64) -> Res<bool> {
    let n = query(
        "UPDATE users SET totp_last_step = $2 \
         WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user)
    .bind(step)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub(super) async fn start_session(
    pool: &PgPool,
    user: Uuid,
    choice: &DeviceChoice,
    tokens: &IssuedTokens,
    family: Uuid,
    now: OffsetDateTime,
) -> Res<Uuid> {
    let mut tx = pool.begin().await?;
    let device_id = match choice {
        DeviceChoice::Existing(id, fallback) => {
            let resumed: Option<Uuid> = query_scalar(
                "UPDATE devices SET last_seen_at = $3, name = $4, platform = $5 \
                 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING id",
            )
            .bind(id)
            .bind(user)
            .bind(now)
            .bind(&fallback.name)
            .bind(&fallback.platform)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(id) = resumed {
                query("DELETE FROM auth_tokens WHERE device_id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                id
            } else {
                insert_device(&mut tx, user, fallback, now).await?;
                fallback.id
            }
        }
        DeviceChoice::New(d) => {
            insert_device(&mut tx, user, d, now).await?;
            d.id
        }
    };
    insert_tokens(&mut tx, device_id, tokens, family).await?;
    tx.commit().await?;
    Ok(device_id)
}

pub(super) async fn authenticate(
    pool: &PgPool,
    hash: &TokenHash,
    now: OffsetDateTime,
) -> Res<Option<AuthCtx>> {
    let row: Option<(Uuid, Uuid, bool, Option<OffsetDateTime>)> = query_as(
        "SELECT d.user_id, d.id, u.is_instance_admin, d.last_seen_at FROM auth_tokens t \
         JOIN devices d ON d.id = t.device_id \
         JOIN users u ON u.id = d.user_id \
         WHERE t.token_hash = $1 AND t.kind = 'access' AND t.expires_at > $2 \
           AND d.revoked_at IS NULL AND NOT u.disabled",
    )
    .bind(&hash.0[..])
    .bind(now)
    .fetch_optional(pool)
    .await?;
    let Some((user_id, device_id, is_instance_admin, last_seen)) = row else {
        return Ok(None);
    };
    if last_seen.is_none_or(|t| t + LAST_SEEN_THROTTLE <= now) {
        // Best effort: a failed bookkeeping write must not fail the request.
        let updated = query(
            "UPDATE devices SET last_seen_at = $2 \
             WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at <= $3)",
        )
        .bind(device_id)
        .bind(now)
        .bind(now - LAST_SEEN_THROTTLE)
        .execute(pool)
        .await;
        if let Err(e) = updated {
            tracing::debug!(%device_id, error = %e, "last_seen_at update failed");
        }
    }
    Ok(Some(AuthCtx {
        user_id,
        device_id,
        is_instance_admin,
    }))
}

pub(super) async fn refresh(
    pool: &PgPool,
    hash: &TokenHash,
    new: &IssuedTokens,
    now: OffsetDateTime,
) -> Res<RefreshOutcome> {
    let mut tx = pool.begin().await?;
    // The row lock serializes concurrent presentations of the same token: the
    // second one sees `used_at` and triggers reuse detection.
    let row: Option<(Uuid, Uuid, Option<OffsetDateTime>, OffsetDateTime)> = query_as(
        "SELECT device_id, family, used_at, expires_at FROM auth_tokens \
         WHERE token_hash = $1 AND kind = 'refresh' FOR UPDATE",
    )
    .bind(&hash.0[..])
    .fetch_optional(&mut *tx)
    .await?;
    let Some((device_id, family, used_at, expires_at)) = row else {
        return Ok(RefreshOutcome::Invalid);
    };
    if expires_at <= now {
        return Ok(RefreshOutcome::Invalid);
    }
    let user_id: Option<Uuid> = query_scalar(
        "SELECT d.user_id FROM devices d JOIN users u ON u.id = d.user_id \
         WHERE d.id = $1 AND d.revoked_at IS NULL AND NOT u.disabled",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(RefreshOutcome::Invalid);
    };
    if used_at.is_some() {
        query("DELETE FROM auth_tokens WHERE family = $1")
            .bind(family)
            .execute(&mut *tx)
            .await?;
        audit_in(
            &mut tx,
            Some(user_id),
            "auth.refresh_token_reuse",
            Some(device_id),
            serde_json::json!({ "user_id": user_id, "device_id": device_id, "family": family }),
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(RefreshOutcome::Reused {
            device_id,
            user_id,
            family,
        });
    }
    query("UPDATE auth_tokens SET used_at = $2 WHERE token_hash = $1")
        .bind(&hash.0[..])
        .bind(now)
        .execute(&mut *tx)
        .await?;
    query("DELETE FROM auth_tokens WHERE family = $1 AND kind = 'access'")
        .bind(family)
        .execute(&mut *tx)
        .await?;
    insert_tokens(&mut tx, device_id, new, family).await?;
    query("UPDATE devices SET last_seen_at = $2 WHERE id = $1")
        .bind(device_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(RefreshOutcome::Rotated { device_id })
}

pub(super) async fn logout(pool: &PgPool, device: Uuid, now: OffsetDateTime) -> Res<()> {
    let mut tx = pool.begin().await?;
    query("DELETE FROM auth_tokens WHERE device_id = $1")
        .bind(device)
        .execute(&mut *tx)
        .await?;
    query("UPDATE devices SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1")
        .bind(device)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn list_devices(pool: &PgPool, user: Uuid) -> Res<Vec<DeviceRow>> {
    type Row = (
        Uuid,
        String,
        String,
        OffsetDateTime,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    );
    let rows: Vec<Row> = query_as(
        "SELECT id, name, platform, created_at, last_seen_at, revoked_at FROM devices \
         WHERE user_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(user)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DeviceRow {
            id: r.0,
            name: r.1,
            platform: r.2,
            created_at: r.3,
            last_seen_at: r.4,
            revoked_at: r.5,
        })
        .collect())
}

pub(super) async fn revoke_device(
    pool: &PgPool,
    user: Uuid,
    device: Uuid,
    now: OffsetDateTime,
) -> Res<bool> {
    let mut tx = pool.begin().await?;
    let found: Option<Uuid> = query_scalar(
        "UPDATE devices SET revoked_at = $3 \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING id",
    )
    .bind(device)
    .bind(user)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if found.is_none() {
        return Ok(false);
    }
    query("DELETE FROM auth_tokens WHERE device_id = $1")
        .bind(device)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub(super) async fn insert_reauth(
    pool: &PgPool,
    hash: &TokenHash,
    user: Uuid,
    expires: OffsetDateTime,
) -> Res<()> {
    query("INSERT INTO reauth_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(&hash.0[..])
        .bind(user)
        .bind(expires)
        .execute(pool)
        .await?;
    Ok(())
}

async fn consume_reauth(
    conn: &mut PgConnection,
    user: Uuid,
    hash: &TokenHash,
    now: OffsetDateTime,
) -> Res<()> {
    let ok: Option<OffsetDateTime> = query_scalar(
        "DELETE FROM reauth_tokens WHERE token_hash = $1 AND user_id = $2 RETURNING expires_at",
    )
    .bind(&hash.0[..])
    .bind(user)
    .fetch_optional(&mut *conn)
    .await?;
    match ok {
        Some(exp) if exp > now => Ok(()),
        _ => Err(ApiError::AuthRequired(REAUTH_REQUIRED_MESSAGE.into())),
    }
}

async fn replace_credentials(conn: &mut PgConnection, user: Uuid, new: &NewCredentials) -> Res<()> {
    let current: Option<i32> =
        query_scalar("SELECT version FROM account_keys WHERE user_id = $1 FOR UPDATE")
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(current) = current else {
        return Err(ApiError::NotFound("account not found".into()));
    };
    if current.checked_add(1) != Some(new.version) {
        return Err(ApiError::Conflict(KEY_VERSION_CHANGED_MESSAGE.into()));
    }
    query("UPDATE users SET opaque_record = $2 WHERE id = $1")
        .bind(user)
        .bind(&new.opaque_record)
        .execute(&mut *conn)
        .await?;
    query("UPDATE account_keys SET private_bundle_enc = $2, version = $3 WHERE user_id = $1")
        .bind(user)
        .bind(&new.private_bundle_enc)
        .bind(new.version)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub(super) async fn change_password(
    pool: &PgPool,
    ctx: AuthCtx,
    reauth: &TokenHash,
    new: &NewCredentials,
    now: OffsetDateTime,
) -> Res<Vec<Uuid>> {
    let mut tx = pool.begin().await?;
    consume_reauth(&mut tx, ctx.user_id, reauth, now).await?;
    replace_credentials(&mut tx, ctx.user_id, new).await?;
    let others: Vec<Uuid> = query_scalar(
        "SELECT id FROM devices WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL \
         ORDER BY id",
    )
    .bind(ctx.user_id)
    .bind(ctx.device_id)
    .fetch_all(&mut *tx)
    .await?;
    query(
        "DELETE FROM auth_tokens WHERE device_id IN \
         (SELECT id FROM devices WHERE user_id = $1 AND id <> $2)",
    )
    .bind(ctx.user_id)
    .bind(ctx.device_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(others)
}

pub(super) async fn issue_recovery_code(
    pool: &PgPool,
    email: &str,
    code_hash: &[u8; 32],
    expires: OffsetDateTime,
) -> Res<Option<Uuid>> {
    let user: Option<Uuid> = query_scalar("SELECT id FROM users WHERE email = $1::citext")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    let Some(user_id) = user else {
        return Ok(None);
    };
    query(
        "INSERT INTO recovery_codes (user_id, code_hash, expires_at, attempts) \
         VALUES ($1, $2, $3, 0) \
         ON CONFLICT (user_id) DO UPDATE SET code_hash = EXCLUDED.code_hash, \
           expires_at = EXCLUDED.expires_at, attempts = 0",
    )
    .bind(user_id)
    .bind(&code_hash[..])
    .bind(expires)
    .execute(pool)
    .await?;
    Ok(Some(user_id))
}

pub(super) async fn check_recovery_code(
    pool: &PgPool,
    email: &str,
    code_hash: &[u8; 32],
    now: OffsetDateTime,
) -> Res<Option<RecoveryInfo>> {
    type Row = (
        Uuid,
        String,
        bool,
        Vec<u8>,
        OffsetDateTime,
        Option<Vec<u8>>,
        i32,
        Vec<u8>,
    );
    let mut tx = pool.begin().await?;
    let row: Option<Row> = query_as(
        "SELECT u.id, lower(u.email::text), u.disabled, c.code_hash, c.expires_at, \
                k.recovery_bundle_enc, k.version, k.ed25519_pub \
         FROM users u JOIN recovery_codes c ON c.user_id = u.id \
         JOIN account_keys k ON k.user_id = u.id \
         WHERE u.email = $1::citext FOR UPDATE OF c",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, email, disabled, stored, expires_at, bundle, version, ed_pub)) = row else {
        return Ok(None);
    };
    let matches = bool::from(stored.as_slice().ct_eq(&code_hash[..]));
    if !matches || expires_at <= now || disabled {
        query("UPDATE recovery_codes SET attempts = attempts + 1 WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        query(
            "DELETE FROM recovery_codes WHERE user_id = $1 \
             AND (attempts >= $2 OR expires_at <= $3)",
        )
        .bind(user_id)
        .bind(RECOVERY_CODE_MAX_ATTEMPTS)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    tx.commit().await?;
    Ok(Some(RecoveryInfo {
        user_id,
        email,
        recovery_bundle_enc: bundle,
        version,
        ed25519_pub: ed_pub,
    }))
}

pub(super) async fn finish_recovery(
    pool: &PgPool,
    user: Uuid,
    code_hash: &[u8; 32],
    new: &NewCredentials,
    now: OffsetDateTime,
) -> Res<Vec<Uuid>> {
    let mut tx = pool.begin().await?;
    let consumed: Option<OffsetDateTime> = query_scalar(
        "DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 RETURNING expires_at",
    )
    .bind(user)
    .bind(&code_hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    if !consumed.is_some_and(|exp| exp > now) {
        return Err(ApiError::AuthRequired(RECOVERY_CODE_INVALID_MESSAGE.into()));
    }
    replace_credentials(&mut tx, user, new).await?;
    query("DELETE FROM auth_tokens WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    let revoked: Vec<Uuid> = query_scalar(
        "UPDATE devices SET revoked_at = $2 \
         WHERE user_id = $1 AND revoked_at IS NULL RETURNING id",
    )
    .bind(user)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    query("DELETE FROM reauth_tokens WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(revoked)
}

pub(super) async fn totp_state(pool: &PgPool, user: Uuid) -> Res<TotpState> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> =
        query_as("SELECT totp_secret_enc, totp_pending_enc FROM users WHERE id = $1")
            .bind(user)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .map(|(secret_enc, pending_enc)| TotpState {
            secret_enc,
            pending_enc,
        })
        .unwrap_or_default())
}

pub(super) async fn set_totp_pending(pool: &PgPool, user: Uuid, sealed: &[u8]) -> Res<()> {
    query("UPDATE users SET totp_pending_enc = $2 WHERE id = $1")
        .bind(user)
        .bind(sealed)
        .execute(pool)
        .await?;
    Ok(())
}

pub(super) async fn confirm_totp(
    pool: &PgPool,
    user: Uuid,
    secret_enc: &[u8],
    step: i64,
) -> Res<bool> {
    let n = query(
        "UPDATE users SET totp_secret_enc = $2, totp_pending_enc = NULL, totp_last_step = $3 \
         WHERE id = $1 AND totp_secret_enc IS NULL AND totp_pending_enc IS NOT NULL",
    )
    .bind(user)
    .bind(secret_enc)
    .bind(step)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub(super) async fn disable_totp(pool: &PgPool, user: Uuid) -> Res<()> {
    query("UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await?;
    Ok(())
}

pub(super) async fn delete_account(
    pool: &PgPool,
    user: Uuid,
    reauth: &TokenHash,
    now: OffsetDateTime,
) -> Res<Vec<Uuid>> {
    let mut tx = pool.begin().await?;
    consume_reauth(&mut tx, user, reauth, now).await?;
    let active: Vec<Uuid> = query_scalar(
        "SELECT id FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY id",
    )
    .bind(user)
    .fetch_all(&mut *tx)
    .await?;
    let personal = "SELECT id FROM vaults WHERE kind = 'personal' AND owner_user_id = $1";
    for stmt in [
        format!("DELETE FROM items WHERE vault_id IN ({personal})"),
        format!("DELETE FROM items_rotation_staging WHERE vault_id IN ({personal})"),
        format!("DELETE FROM vault_members WHERE vault_id IN ({personal})"),
        "DELETE FROM vaults WHERE kind = 'personal' AND owner_user_id = $1".to_owned(),
        // Memberships in team vaults go; the vaults and their items stay.
        "DELETE FROM vault_members WHERE user_id = $1".to_owned(),
        "DELETE FROM org_members WHERE user_id = $1".to_owned(),
        "DELETE FROM auth_tokens WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)"
            .to_owned(),
        "DELETE FROM login_states WHERE user_id = $1".to_owned(),
        "DELETE FROM reauth_tokens WHERE user_id = $1".to_owned(),
        "DELETE FROM recovery_codes WHERE user_id = $1".to_owned(),
        "DELETE FROM devices WHERE user_id = $1".to_owned(),
        "DELETE FROM account_keys WHERE user_id = $1".to_owned(),
        "DELETE FROM users WHERE id = $1".to_owned(),
    ] {
        query(&stmt).bind(user).execute(&mut *tx).await?;
    }
    audit_in(
        &mut tx,
        Some(user),
        "account.deleted",
        Some(user),
        serde_json::json!({}),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(active)
}

pub(super) async fn account_keys(pool: &PgPool, user: Uuid) -> Res<Option<AccountKeysRow>> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, i32)> = query_as(
        "SELECT x25519_pub, ed25519_pub, private_bundle_enc, recovery_bundle_enc, version \
         FROM account_keys WHERE user_id = $1",
    )
    .bind(user)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| AccountKeysRow {
        x25519_pub: r.0,
        ed25519_pub: r.1,
        private_bundle_enc: r.2,
        recovery_bundle_enc: r.3,
        version: r.4,
    }))
}

pub(super) async fn get_secret(pool: &PgPool, name: &str) -> Res<Option<Vec<u8>>> {
    Ok(
        query_scalar("SELECT value_enc FROM server_secrets WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?,
    )
}

pub(super) async fn all_secrets(pool: &PgPool) -> Res<Vec<(String, Vec<u8>)>> {
    Ok(
        query_as("SELECT name, value_enc FROM server_secrets ORDER BY name")
            .fetch_all(pool)
            .await?,
    )
}

pub(super) async fn insert_secret_if_absent(pool: &PgPool, name: &str, value: &[u8]) -> Res<()> {
    query(
        "INSERT INTO server_secrets (name, value_enc) VALUES ($1, $2) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn setting(pool: &PgPool, key: &str) -> Res<Option<String>> {
    Ok(query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?)
}

pub(super) async fn set_setting(
    pool: &PgPool,
    key: &str,
    value: &str,
    now: OffsetDateTime,
) -> Res<()> {
    query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, $3) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn user_count(pool: &PgPool) -> Res<u64> {
    let n: i64 = query_scalar("SELECT count(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(u64::try_from(n).unwrap_or(0))
}

pub(super) async fn insert_invite(pool: &PgPool, i: &NewInvite) -> Res<()> {
    query(
        "INSERT INTO invites (id, org_id, email, role, token_hash, created_by, created_at, \
                              expires_at, accepted_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)",
    )
    .bind(i.id)
    .bind(i.org_id)
    .bind(&i.email)
    .bind(&i.role)
    .bind(&i.token_hash[..])
    .bind(i.created_by)
    .bind(i.created_at)
    .bind(i.expires_at)
    .execute(pool)
    .await
    .map_err(|e| match unique_violation(&e) {
        Some(_) => ApiError::Conflict("invite token already exists".into()),
        None => e.into(),
    })?;
    Ok(())
}
