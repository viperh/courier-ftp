//! In-memory backend of [`super::Store`].
//!
//! A model of the PostgreSQL schema for tests that run without a database: same
//! tables (as maps), same checks, same outcomes. Each method holds the one lock
//! for its whole (synchronous) body, validates first and mutates last, so it is
//! atomic like the SQL transactions. The lock is never held across an `.await`.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

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
    IssuedTokens, LAST_SEEN_THROTTLE, RECOVERY_CODE_MAX_ATTEMPTS, TokenHash, TokenKind,
};
use crate::auth::totp;
use crate::error::ApiError;
use crate::registration::{
    self, EMAIL_TAKEN_MESSAGE, InviteFacts, PolicyFacts, RegistrationMode, VAULT_TAKEN_MESSAGE,
};
use crate::settings_kv;

type Res<T> = Result<T, ApiError>;

/// Expired login states deleted per `put_login_state`.
const LOGIN_STATE_SWEEP: usize = 100;

/// A `users` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemUser {
    /// Normalized email.
    pub email: String,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Instance admin.
    pub is_instance_admin: bool,
    /// OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Sealed TOTP secret.
    pub totp_secret_enc: Option<Vec<u8>>,
    /// Sealed pending TOTP secret.
    pub totp_pending_enc: Option<Vec<u8>>,
    /// Last accepted TOTP step.
    pub totp_last_step: Option<i64>,
    /// Disabled.
    pub disabled: bool,
}

/// A `devices` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemDevice {
    /// Owner.
    pub user_id: Uuid,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Last seen.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

/// An `auth_tokens` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemToken {
    /// Device.
    pub device_id: Uuid,
    /// Kind.
    pub kind: TokenKind,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Rotation family.
    pub family: Uuid,
    /// Set when a refresh token is rotated.
    pub used_at: Option<OffsetDateTime>,
}

/// A `vaults` row (the columns T84 and T85 need).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemVault {
    /// `personal` (true) or `team`.
    pub personal: bool,
    /// Owner of a personal vault.
    pub owner_user_id: Option<Uuid>,
    /// Org of a team vault.
    pub org_id: Option<Uuid>,
    /// Creator.
    pub created_by: Uuid,
    /// Key version.
    pub key_version: i32,
    /// Highest assigned revision.
    pub head_revision: i64,
    /// Sealed name.
    pub name_enc: Vec<u8>,
    /// Created.
    pub created_at: OffsetDateTime,
}

/// A `vault_members` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemMember {
    /// Vault.
    pub vault_id: Uuid,
    /// Member.
    pub user_id: Uuid,
    /// `read` | `write` | `manage`.
    pub permission: String,
    /// Key version.
    pub key_version: i32,
    /// Wrapped vault key.
    pub wrapped_vault_key: Vec<u8>,
    /// Granter.
    pub wrapped_by: Uuid,
    /// Signature.
    pub signature: Vec<u8>,
}

/// An `items` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemItem {
    /// Revision.
    pub revision: i64,
    /// Key version.
    pub key_version: i32,
    /// Sealed envelope.
    pub envelope: Vec<u8>,
    /// Tombstone.
    pub deleted: bool,
    /// Last write.
    pub updated_at: OffsetDateTime,
}

/// An `invites` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemInvite {
    /// Id.
    pub id: Uuid,
    /// Org (`None`: instance invite).
    pub org_id: Option<Uuid>,
    /// Bound email (normalized).
    pub email: Option<String>,
    /// Org role.
    pub role: Option<String>,
    /// Token hash.
    pub token_hash: [u8; 32],
    /// Creator.
    pub created_by: Option<Uuid>,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Accepted.
    pub accepted_at: Option<OffsetDateTime>,
}

/// A `recovery_codes` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRecoveryCode {
    /// SHA-256 of the code bytes.
    pub code_hash: [u8; 32],
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Wrong attempts.
    pub attempts: i32,
}

/// An `audit_events` row.
#[derive(Debug, Clone, PartialEq)]
pub struct MemAudit {
    /// Org (`None`: instance-level).
    pub org_id: Option<Uuid>,
    /// Actor.
    pub actor_user_id: Option<Uuid>,
    /// Kind, e.g. `account.deleted`.
    pub kind: String,
    /// Target.
    pub target: Option<Uuid>,
    /// Time.
    pub at: OffsetDateTime,
    /// Metadata (never secrets or emails).
    pub meta: serde_json::Value,
}

/// All tables.
#[derive(Debug)]
pub struct MemData {
    /// `users`.
    pub users: BTreeMap<Uuid, MemUser>,
    /// `account_keys`.
    pub account_keys: BTreeMap<Uuid, AccountKeysRow>,
    /// `devices`.
    pub devices: BTreeMap<Uuid, MemDevice>,
    /// `auth_tokens` by hash.
    pub tokens: BTreeMap<TokenHash, MemToken>,
    /// `login_states`.
    pub login_states: BTreeMap<Uuid, LoginStateRow>,
    /// `reauth_tokens`: hash → (user, expiry).
    pub reauth: BTreeMap<TokenHash, (Uuid, OffsetDateTime)>,
    /// `recovery_codes` by user.
    pub recovery_codes: BTreeMap<Uuid, MemRecoveryCode>,
    /// `server_secrets` (sealed values).
    pub secrets: BTreeMap<String, Vec<u8>>,
    /// `settings`.
    pub settings: BTreeMap<String, String>,
    /// `invites`.
    pub invites: Vec<MemInvite>,
    /// `orgs`: id → name.
    pub orgs: BTreeMap<Uuid, String>,
    /// `org_members`: (org, user) → role.
    pub org_members: BTreeMap<(Uuid, Uuid), String>,
    /// `vaults`.
    pub vaults: BTreeMap<Uuid, MemVault>,
    /// `vault_members`.
    pub vault_members: Vec<MemMember>,
    /// `items` by `(vault, item)`.
    pub items: BTreeMap<(Uuid, Uuid), MemItem>,
    /// `items_rotation_staging` by `(vault, item)`: `(key_version, envelope)`.
    pub rotation_staging: BTreeMap<(Uuid, Uuid), (i32, Vec<u8>)>,
    /// `audit_events`.
    pub audit: Vec<MemAudit>,
}

impl Default for MemData {
    fn default() -> Self {
        Self {
            users: BTreeMap::new(),
            account_keys: BTreeMap::new(),
            devices: BTreeMap::new(),
            tokens: BTreeMap::new(),
            login_states: BTreeMap::new(),
            reauth: BTreeMap::new(),
            recovery_codes: BTreeMap::new(),
            secrets: BTreeMap::new(),
            // As after migration 0001.
            settings: BTreeMap::from([(
                settings_kv::REGISTRATION_MODE.to_owned(),
                RegistrationMode::InviteOnly.as_str().to_owned(),
            )]),
            invites: Vec::new(),
            orgs: BTreeMap::new(),
            org_members: BTreeMap::new(),
            vaults: BTreeMap::new(),
            vault_members: Vec::new(),
            items: BTreeMap::new(),
            rotation_staging: BTreeMap::new(),
            audit: Vec::new(),
        }
    }
}

impl MemData {
    fn user_id_by_email(&self, email: &str) -> Option<Uuid> {
        self.users
            .iter()
            .find(|(_, u)| u.email == email)
            .map(|(id, _)| *id)
    }

    fn login_user(&self, id: Uuid) -> Option<LoginUser> {
        self.users.get(&id).map(|u| LoginUser {
            id,
            email: u.email.clone(),
            opaque_record: u.opaque_record.clone(),
            disabled: u.disabled,
            is_instance_admin: u.is_instance_admin,
            totp_secret_enc: u.totp_secret_enc.clone(),
        })
    }

    fn policy_facts(&self, cred: RegistrationCredential<'_>) -> PolicyFacts {
        let invite = match cred {
            RegistrationCredential::InviteToken(t) => {
                let hash = registration::hash_token(t);
                self.invites
                    .iter()
                    .find(|i| bool::from(i.token_hash.ct_eq(&hash)))
                    .map(|i| InviteFacts {
                        id: i.id,
                        org_id: i.org_id,
                        email: i.email.clone(),
                        token_hash: i.token_hash.to_vec(),
                        expires_at: i.expires_at,
                        accepted: i.accepted_at.is_some(),
                    })
            }
            _ => None,
        };
        PolicyFacts {
            mode: RegistrationMode::from_stored(
                self.settings
                    .get(settings_kv::REGISTRATION_MODE)
                    .map(String::as_str),
            ),
            no_users: self.users.is_empty(),
            setup_token_hash: self.settings.get(settings_kv::SETUP_TOKEN_HASH).cloned(),
            invite,
        }
    }

    fn insert_device(&mut self, user_id: Uuid, d: &NewDevice, now: OffsetDateTime) {
        self.devices.insert(
            d.id,
            MemDevice {
                user_id,
                name: d.name.clone(),
                platform: d.platform.clone(),
                created_at: now,
                last_seen_at: Some(now),
                revoked_at: None,
            },
        );
    }

    fn insert_tokens(&mut self, device_id: Uuid, tokens: &IssuedTokens, family: Uuid) {
        for rec in tokens.records() {
            self.tokens.insert(
                rec.hash,
                MemToken {
                    device_id,
                    kind: rec.kind,
                    expires_at: rec.expires_at,
                    family,
                    used_at: None,
                },
            );
        }
    }

    fn delete_device_tokens(&mut self, devices: &[Uuid]) {
        self.tokens.retain(|_, t| !devices.contains(&t.device_id));
    }

    fn user_devices(&self, user_id: Uuid, only_active: bool) -> Vec<Uuid> {
        self.devices
            .iter()
            .filter(|(_, d)| d.user_id == user_id && (!only_active || d.revoked_at.is_none()))
            .map(|(id, _)| *id)
            .collect()
    }

    fn active_user(&self, device_id: Uuid) -> Option<(Uuid, bool)> {
        let dev = self.devices.get(&device_id)?;
        let user = self.users.get(&dev.user_id)?;
        (dev.revoked_at.is_none() && !user.disabled)
            .then_some((dev.user_id, user.is_instance_admin))
    }

    fn check_reauth(&self, user_id: Uuid, hash: &TokenHash, now: OffsetDateTime) -> Res<()> {
        match self.reauth.get(hash) {
            Some((u, exp)) if *u == user_id && *exp > now => Ok(()),
            _ => Err(ApiError::AuthRequired(REAUTH_REQUIRED_MESSAGE.into())),
        }
    }

    fn check_version(&self, user_id: Uuid, new: &NewCredentials) -> Res<()> {
        let current = self
            .account_keys
            .get(&user_id)
            .map(|k| k.version)
            .ok_or_else(|| ApiError::NotFound("account not found".into()))?;
        if current.checked_add(1) != Some(new.version) {
            return Err(ApiError::Conflict(KEY_VERSION_CHANGED_MESSAGE.into()));
        }
        Ok(())
    }

    fn replace_credentials(&mut self, user_id: Uuid, new: &NewCredentials) {
        if let Some(u) = self.users.get_mut(&user_id) {
            u.opaque_record.clone_from(&new.opaque_record);
        }
        if let Some(k) = self.account_keys.get_mut(&user_id) {
            k.private_bundle_enc.clone_from(&new.private_bundle_enc);
            k.version = new.version;
        }
    }

    fn push_audit(
        &mut self,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
        at: OffsetDateTime,
    ) {
        self.audit.push(MemAudit {
            org_id: None,
            actor_user_id: actor,
            kind: kind.to_owned(),
            target,
            at,
            meta,
        });
    }
}

/// The in-memory store.
#[derive(Debug, Default)]
pub struct MemDb(Mutex<MemData>);

impl MemDb {
    /// Empty tables (registration mode `invite-only`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, MemData> {
        // A panic while holding the lock can only come from a failing test.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `f` on the tables (test setup and inspection; T85 and T89 extend
    /// these tables).
    pub fn with_data<R>(&self, f: impl FnOnce(&mut MemData) -> R) -> R {
        f(&mut self.lock())
    }

    pub(super) fn check_registration(
        &self,
        email: &str,
        cred: RegistrationCredential<'_>,
        now: OffsetDateTime,
    ) -> Res<()> {
        let d = self.lock();
        registration::authorize(&d.policy_facts(cred), email, cred, now)?;
        if d.user_id_by_email(email).is_some() {
            return Err(ApiError::Conflict(EMAIL_TAKEN_MESSAGE.into()));
        }
        Ok(())
    }

    pub(super) fn register(
        &self,
        a: &NewAccount,
        cred: RegistrationCredential<'_>,
        tokens: &IssuedTokens,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Res<RegisterOutcome> {
        let mut d = self.lock();
        let decision = registration::authorize(&d.policy_facts(cred), &a.email, cred, now)?;
        if d.user_id_by_email(&a.email).is_some() || d.users.contains_key(&a.user_id) {
            return Err(ApiError::Conflict(EMAIL_TAKEN_MESSAGE.into()));
        }
        if d.vaults.contains_key(&a.vault_id) {
            return Err(ApiError::Conflict(VAULT_TAKEN_MESSAGE.into()));
        }
        // Every check passed: apply all changes.
        if decision.consume_setup_token {
            d.settings.remove(settings_kv::SETUP_TOKEN_HASH);
        }
        if let Some(id) = decision.accept_invite
            && let Some(i) = d.invites.iter_mut().find(|i| i.id == id)
        {
            i.accepted_at = Some(now);
        }
        d.users.insert(
            a.user_id,
            MemUser {
                email: a.email.clone(),
                created_at: now,
                is_instance_admin: decision.consume_setup_token,
                opaque_record: a.opaque_record.clone(),
                totp_secret_enc: None,
                totp_pending_enc: None,
                totp_last_step: None,
                disabled: false,
            },
        );
        d.account_keys.insert(a.user_id, a.keys.clone());
        d.insert_device(a.user_id, &a.device, now);
        d.vaults.insert(
            a.vault_id,
            MemVault {
                personal: true,
                owner_user_id: Some(a.user_id),
                org_id: None,
                created_by: a.user_id,
                key_version: a.grant_key_version,
                head_revision: 0,
                name_enc: a.vault_name_enc.clone(),
                created_at: now,
            },
        );
        d.vault_members.push(MemMember {
            vault_id: a.vault_id,
            user_id: a.user_id,
            permission: "manage".into(),
            key_version: a.grant_key_version,
            wrapped_vault_key: a.grant_wrapped.clone(),
            wrapped_by: a.user_id,
            signature: a.grant_signature.clone(),
        });
        d.insert_tokens(a.device.id, tokens, family);
        Ok(RegisterOutcome {
            is_instance_admin: decision.consume_setup_token,
            org_invite: decision.org_invite,
        })
    }

    pub(super) fn user_by_email(&self, email: &str) -> Res<Option<LoginUser>> {
        let d = self.lock();
        Ok(d.user_id_by_email(email).and_then(|id| d.login_user(id)))
    }

    pub(super) fn user_by_id(&self, id: Uuid) -> Res<Option<LoginUser>> {
        Ok(self.lock().login_user(id))
    }

    pub(super) fn put_login_state(&self, row: &LoginStateRow, now: OffsetDateTime) -> Res<()> {
        let mut d = self.lock();
        let expired: Vec<Uuid> = d
            .login_states
            .iter()
            .filter(|(_, s)| s.expires_at <= now)
            .map(|(id, _)| *id)
            .take(LOGIN_STATE_SWEEP)
            .collect();
        for id in expired {
            d.login_states.remove(&id);
        }
        d.login_states.insert(row.id, row.clone());
        Ok(())
    }

    pub(super) fn take_login_state(
        &self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Res<Option<LoginStateRow>> {
        Ok(self
            .lock()
            .login_states
            .remove(&id)
            .filter(|s| s.expires_at > now))
    }

    pub(super) fn consume_totp_step(&self, user: Uuid, step: i64) -> Res<bool> {
        let mut d = self.lock();
        let Some(u) = d.users.get_mut(&user) else {
            return Ok(false);
        };
        if !totp::is_fresh(u.totp_last_step, step) {
            return Ok(false);
        }
        u.totp_last_step = Some(step);
        Ok(true)
    }

    pub(super) fn start_session(
        &self,
        user: Uuid,
        choice: &DeviceChoice,
        tokens: &IssuedTokens,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Res<Uuid> {
        let mut d = self.lock();
        let device_id = match choice {
            DeviceChoice::Existing(id, fallback) => {
                let resumable = d
                    .devices
                    .get(id)
                    .is_some_and(|dev| dev.user_id == user && dev.revoked_at.is_none());
                if resumable {
                    if let Some(dev) = d.devices.get_mut(id) {
                        dev.last_seen_at = Some(now);
                        dev.name.clone_from(&fallback.name);
                        dev.platform.clone_from(&fallback.platform);
                    }
                    d.delete_device_tokens(&[*id]);
                    *id
                } else {
                    d.insert_device(user, fallback, now);
                    fallback.id
                }
            }
            DeviceChoice::New(nd) => {
                d.insert_device(user, nd, now);
                nd.id
            }
        };
        d.insert_tokens(device_id, tokens, family);
        Ok(device_id)
    }

    pub(super) fn authenticate(
        &self,
        hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Res<Option<AuthCtx>> {
        let mut d = self.lock();
        let Some(t) = d.tokens.get(hash) else {
            return Ok(None);
        };
        if t.kind != TokenKind::Access || t.expires_at <= now {
            return Ok(None);
        }
        let device_id = t.device_id;
        let Some((user_id, is_instance_admin)) = d.active_user(device_id) else {
            return Ok(None);
        };
        if let Some(dev) = d.devices.get_mut(&device_id)
            && dev
                .last_seen_at
                .is_none_or(|t| t + LAST_SEEN_THROTTLE <= now)
        {
            dev.last_seen_at = Some(now);
        }
        Ok(Some(AuthCtx {
            user_id,
            device_id,
            is_instance_admin,
        }))
    }

    pub(super) fn refresh(
        &self,
        hash: &TokenHash,
        new: &IssuedTokens,
        now: OffsetDateTime,
    ) -> Res<RefreshOutcome> {
        let mut d = self.lock();
        let Some(t) = d
            .tokens
            .get(hash)
            .filter(|t| t.kind == TokenKind::Refresh)
            .cloned()
        else {
            return Ok(RefreshOutcome::Invalid);
        };
        if t.expires_at <= now {
            return Ok(RefreshOutcome::Invalid);
        }
        let Some((user_id, _)) = d.active_user(t.device_id) else {
            return Ok(RefreshOutcome::Invalid);
        };
        if t.used_at.is_some() {
            d.tokens.retain(|_, x| x.family != t.family);
            d.push_audit(
                Some(user_id),
                "auth.refresh_token_reuse",
                Some(t.device_id),
                serde_json::json!({
                    "user_id": user_id,
                    "device_id": t.device_id,
                    "family": t.family,
                }),
                now,
            );
            return Ok(RefreshOutcome::Reused {
                device_id: t.device_id,
                user_id,
                family: t.family,
            });
        }
        if let Some(old) = d.tokens.get_mut(hash) {
            old.used_at = Some(now);
        }
        d.tokens
            .retain(|_, x| !(x.family == t.family && x.kind == TokenKind::Access));
        d.insert_tokens(t.device_id, new, t.family);
        if let Some(dev) = d.devices.get_mut(&t.device_id) {
            dev.last_seen_at = Some(now);
        }
        Ok(RefreshOutcome::Rotated {
            device_id: t.device_id,
        })
    }

    pub(super) fn logout(&self, device: Uuid, now: OffsetDateTime) -> Res<()> {
        let mut d = self.lock();
        d.delete_device_tokens(&[device]);
        if let Some(dev) = d.devices.get_mut(&device) {
            dev.revoked_at.get_or_insert(now);
        }
        Ok(())
    }

    pub(super) fn list_devices(&self, user: Uuid) -> Res<Vec<DeviceRow>> {
        let d = self.lock();
        let mut rows: Vec<DeviceRow> = d
            .devices
            .iter()
            .filter(|(_, dev)| dev.user_id == user)
            .map(|(id, dev)| DeviceRow {
                id: *id,
                name: dev.name.clone(),
                platform: dev.platform.clone(),
                created_at: dev.created_at,
                last_seen_at: dev.last_seen_at,
                revoked_at: dev.revoked_at,
            })
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse((r.created_at, r.id)));
        Ok(rows)
    }

    pub(super) fn revoke_device(&self, user: Uuid, device: Uuid, now: OffsetDateTime) -> Res<bool> {
        let mut d = self.lock();
        match d.devices.get_mut(&device) {
            Some(dev) if dev.user_id == user && dev.revoked_at.is_none() => {
                dev.revoked_at = Some(now);
            }
            _ => return Ok(false),
        }
        d.delete_device_tokens(&[device]);
        Ok(true)
    }

    pub(super) fn insert_reauth(
        &self,
        hash: &TokenHash,
        user: Uuid,
        expires: OffsetDateTime,
    ) -> Res<()> {
        self.lock().reauth.insert(*hash, (user, expires));
        Ok(())
    }

    pub(super) fn change_password(
        &self,
        ctx: AuthCtx,
        reauth: &TokenHash,
        new: &NewCredentials,
        now: OffsetDateTime,
    ) -> Res<Vec<Uuid>> {
        let mut d = self.lock();
        // Like the SQL transaction: a failed version check rolls the reauth
        // consumption back, so check everything first.
        d.check_reauth(ctx.user_id, reauth, now)?;
        d.check_version(ctx.user_id, new)?;
        d.reauth.remove(reauth);
        d.replace_credentials(ctx.user_id, new);
        let others: Vec<Uuid> = d
            .user_devices(ctx.user_id, true)
            .into_iter()
            .filter(|id| *id != ctx.device_id)
            .collect();
        d.delete_device_tokens(&others);
        Ok(others)
    }

    pub(super) fn issue_recovery_code(
        &self,
        email: &str,
        code_hash: &[u8; 32],
        expires: OffsetDateTime,
    ) -> Res<Option<Uuid>> {
        let mut d = self.lock();
        let Some(user_id) = d.user_id_by_email(email) else {
            return Ok(None);
        };
        d.recovery_codes.insert(
            user_id,
            MemRecoveryCode {
                code_hash: *code_hash,
                expires_at: expires,
                attempts: 0,
            },
        );
        Ok(Some(user_id))
    }

    pub(super) fn check_recovery_code(
        &self,
        email: &str,
        code_hash: &[u8; 32],
        now: OffsetDateTime,
    ) -> Res<Option<RecoveryInfo>> {
        let mut d = self.lock();
        let Some(user_id) = d.user_id_by_email(email) else {
            return Ok(None);
        };
        let (Some(user), Some(keys)) = (d.users.get(&user_id), d.account_keys.get(&user_id)) else {
            return Ok(None);
        };
        let info = RecoveryInfo {
            user_id,
            email: user.email.clone(),
            recovery_bundle_enc: keys.recovery_bundle_enc.clone(),
            version: keys.version,
            ed25519_pub: keys.ed25519_pub.clone(),
        };
        let disabled = user.disabled;
        let Some(code) = d.recovery_codes.get_mut(&user_id) else {
            return Ok(None);
        };
        let matches = bool::from(code.code_hash.ct_eq(code_hash));
        if matches && code.expires_at > now && !disabled {
            return Ok(Some(info));
        }
        code.attempts += 1;
        if code.attempts >= RECOVERY_CODE_MAX_ATTEMPTS || code.expires_at <= now {
            d.recovery_codes.remove(&user_id);
        }
        Ok(None)
    }

    pub(super) fn finish_recovery(
        &self,
        user: Uuid,
        code_hash: &[u8; 32],
        new: &NewCredentials,
        now: OffsetDateTime,
    ) -> Res<Vec<Uuid>> {
        let mut d = self.lock();
        let valid = d
            .recovery_codes
            .get(&user)
            .is_some_and(|c| bool::from(c.code_hash.ct_eq(code_hash)) && c.expires_at > now);
        if !valid {
            return Err(ApiError::AuthRequired(RECOVERY_CODE_INVALID_MESSAGE.into()));
        }
        d.check_version(user, new)?;
        d.recovery_codes.remove(&user);
        d.replace_credentials(user, new);
        let revoked = d.user_devices(user, true);
        let all = d.user_devices(user, false);
        d.delete_device_tokens(&all);
        for id in &revoked {
            if let Some(dev) = d.devices.get_mut(id) {
                dev.revoked_at = Some(now);
            }
        }
        d.reauth.retain(|_, (u, _)| *u != user);
        Ok(revoked)
    }

    pub(super) fn totp_state(&self, user: Uuid) -> Res<TotpState> {
        Ok(self
            .lock()
            .users
            .get(&user)
            .map(|u| TotpState {
                secret_enc: u.totp_secret_enc.clone(),
                pending_enc: u.totp_pending_enc.clone(),
            })
            .unwrap_or_default())
    }

    pub(super) fn set_totp_pending(&self, user: Uuid, sealed: &[u8]) -> Res<()> {
        if let Some(u) = self.lock().users.get_mut(&user) {
            u.totp_pending_enc = Some(sealed.to_vec());
        }
        Ok(())
    }

    pub(super) fn confirm_totp(&self, user: Uuid, secret_enc: &[u8], step: i64) -> Res<bool> {
        let mut d = self.lock();
        let Some(u) = d.users.get_mut(&user) else {
            return Ok(false);
        };
        if u.totp_secret_enc.is_some() || u.totp_pending_enc.is_none() {
            return Ok(false);
        }
        u.totp_secret_enc = Some(secret_enc.to_vec());
        u.totp_pending_enc = None;
        u.totp_last_step = Some(step);
        Ok(true)
    }

    pub(super) fn disable_totp(&self, user: Uuid) -> Res<()> {
        if let Some(u) = self.lock().users.get_mut(&user) {
            u.totp_secret_enc = None;
            u.totp_pending_enc = None;
        }
        Ok(())
    }

    pub(super) fn delete_account(
        &self,
        user: Uuid,
        reauth: &TokenHash,
        now: OffsetDateTime,
    ) -> Res<Vec<Uuid>> {
        let mut d = self.lock();
        d.check_reauth(user, reauth, now)?;
        let personal: Vec<Uuid> = d
            .vaults
            .iter()
            .filter(|(_, v)| v.personal && v.owner_user_id == Some(user))
            .map(|(id, _)| *id)
            .collect();
        d.items.retain(|(v, _), _| !personal.contains(v));
        d.rotation_staging.retain(|(v, _), _| !personal.contains(v));
        d.vault_members
            .retain(|m| !personal.contains(&m.vault_id) && m.user_id != user);
        d.vaults.retain(|id, _| !personal.contains(id));
        d.org_members.retain(|(_, u), _| *u != user);
        let active = d.user_devices(user, true);
        let all = d.user_devices(user, false);
        d.delete_device_tokens(&all);
        d.login_states.retain(|_, s| s.user_id != Some(user));
        d.reauth.retain(|_, (u, _)| *u != user);
        d.recovery_codes.remove(&user);
        d.devices.retain(|_, dev| dev.user_id != user);
        d.account_keys.remove(&user);
        d.users.remove(&user);
        d.push_audit(
            Some(user),
            "account.deleted",
            Some(user),
            serde_json::json!({}),
            now,
        );
        Ok(active)
    }

    pub(super) fn account_keys(&self, user: Uuid) -> Res<Option<AccountKeysRow>> {
        Ok(self.lock().account_keys.get(&user).cloned())
    }

    pub(super) fn get_secret(&self, name: &str) -> Res<Option<Vec<u8>>> {
        Ok(self.lock().secrets.get(name).cloned())
    }

    pub(super) fn all_secrets(&self) -> Res<Vec<(String, Vec<u8>)>> {
        Ok(self
            .lock()
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    pub(super) fn insert_secret_if_absent(&self, name: &str, value: &[u8]) -> Res<()> {
        self.lock()
            .secrets
            .entry(name.to_owned())
            .or_insert_with(|| value.to_vec());
        Ok(())
    }

    pub(super) fn setting(&self, key: &str) -> Res<Option<String>> {
        Ok(self.lock().settings.get(key).cloned())
    }

    pub(super) fn set_setting(&self, key: &str, value: &str, _now: OffsetDateTime) -> Res<()> {
        self.lock()
            .settings
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    pub(super) fn user_count(&self) -> Res<u64> {
        Ok(u64::try_from(self.lock().users.len()).unwrap_or(u64::MAX))
    }

    pub(super) fn insert_invite(&self, i: &NewInvite) -> Res<()> {
        let mut d = self.lock();
        if d.invites.iter().any(|x| x.token_hash == i.token_hash) {
            return Err(ApiError::Conflict("invite token already exists".into()));
        }
        d.invites.push(MemInvite {
            id: i.id,
            org_id: i.org_id,
            email: i.email.clone(),
            role: i.role.clone(),
            token_hash: i.token_hash,
            created_by: i.created_by,
            created_at: i.created_at,
            expires_at: i.expires_at,
            accepted_at: None,
        });
        Ok(())
    }
}
