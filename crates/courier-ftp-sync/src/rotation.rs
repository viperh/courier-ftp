//! The client side of a vault key rotation (T89 §5).
//!
//! [`Teams::rotate`](crate::teams::Teams::rotate) runs the protocol for one
//! team vault:
//!
//! 1. `begin` with `new_key_version = key_version + 1` (pushes of every
//!    member now get `409 rotating`, pulls keep working);
//! 2. a fresh **VK′** is generated and, before anything is uploaded, kept in
//!    `meta` (`rotation:<vault>`, sealed under the LMK) together with the ids
//!    uploaded so far, so a crash **resumes** instead of restarting;
//! 3. every item on the server (tombstones included) is pulled from
//!    revision 0, opened with the current VK and re-sealed under VK′ with the
//!    same item id and the new key version in the AAD;
//! 4. the envelopes go up in chunks of at most 500 items / 8 MiB; after each
//!    chunk the uploaded ids are persisted;
//! 5. `commit` with VK′ wrapped and signed for every remaining member; the
//!    server checks full coverage atomically. A member whose key **changed**
//!    (or can't be fetched) blocks the commit
//!    ([`RotationError::UntrustedMembers`]): the rotation stays open (pushes
//!    stay paused) until the key is accepted and the rotation resumed, or it
//!    is abandoned after 15 minutes. A member is never silently dropped from
//!    the vault because of a key change. Org admins that never held a grant
//!    are optional: an untrusted one is skipped.
//!
//! Resuming: `begin` by the same user and device answers `resumed` and keeps
//! the server's staging; the persisted VK′ and ids skip the work done. A
//! rotation abandoned by another client (15 minutes) is replaced: the server
//! discards its staging and this client starts afresh (so does `admin gc`).
//!
//! This device's own store is not touched here: the sync engine installs VK′
//! from the new grant like every other member (`vault_access rotated`),
//! re-seals the local items still under the old key, and re-pulls the
//! rotated items.
//!
//! The revoked user keeps what they already synced; rotation only protects
//! **future** changes.
//!
//! Adapted from sverb's `sverb-sync/src/rotation.rs` (D13).

use std::collections::{BTreeSet, HashSet};

use courier_ftp_core::model::item::VaultId;
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::envelope::{open_item, seal_item};
use courier_ftp_crypto::grant::{grant_vault_key, self_grant};
use courier_ftp_crypto::keys::{os_rng, random_key32};
use courier_ftp_crypto::wrap::WrapPurpose;
use courier_ftp_proto::ErrorCode;
use courier_ftp_proto::limits::{MAX_PULL_LIMIT, MAX_PUSH_BYTES, MAX_ROTATION_CHUNK};
use courier_ftp_proto::orgs::Role;
use courier_ftp_proto::rotation::{RotateRequest, RotateResponse, RotatedItem, RotationGrant};
use courier_ftp_proto::sync::RemoteItem;
use courier_ftp_proto::vaults::VaultMembersView;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SyncError;
use crate::teams::{TeamError, Teams};
use crate::trust::TrustError;

/// `meta` key prefix of a rotation's persisted progress (`rotation:<uuid>`).
pub const META_ROTATION_PREFIX: &str = "rotation:";

/// Where a rotation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPhase {
    /// `begin`.
    Starting,
    /// Pulling and re-encrypting the items.
    Encrypting,
    /// Uploading the re-encrypted items.
    Uploading,
    /// Wrapping the new key for the members and committing.
    Committing,
    /// Done.
    Done,
}

impl RotationPhase {
    /// A short label for progress dialogs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Encrypting => "Re-encrypting items",
            Self::Uploading => "Uploading",
            Self::Committing => "Committing",
            Self::Done => "Done",
        }
    }
}

/// A progress report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationProgress {
    /// The vault.
    pub vault: VaultId,
    /// Phase.
    pub phase: RotationPhase,
    /// Items done in this phase.
    pub done: usize,
    /// Items in this phase.
    pub total: usize,
}

/// A remaining member whose key is not trusted (blocks the commit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedMember {
    /// The user.
    pub user: Uuid,
    /// Their email, when known.
    pub email: Option<String>,
    /// Why.
    pub reason: String,
}

/// Why a rotation failed. The rotation stays open on the server (pushes
/// stay paused) and can be resumed with
/// [`Teams::rotate`](crate::teams::Teams::rotate).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotationError {
    /// A team operation failed (no key, not signed in, a request, …).
    #[error(transparent)]
    Team(#[from] TeamError),
    /// Remaining members whose keys are not trusted: the commit is blocked
    /// until their new keys are accepted (Settings → Teams), then resume.
    #[error(
        "the key rotation is blocked: {} member key(s) changed or could not be verified \
         ({}); compare safety numbers and accept the new keys in Settings → Teams, then \
         resume the rotation",
        .0.len(),
        .0.iter().map(|m| m.email.clone().unwrap_or_else(|| m.user.to_string())).collect::<Vec<_>>().join(", ")
    )]
    UntrustedMembers(Vec<UntrustedMember>),
    /// Items on the server don't open with this device's vault key.
    #[error("{0} item(s) of the vault could not be decrypted; the rotation can't continue")]
    Undecryptable(usize),
    /// This device's vault key is not the server's current one: sync first.
    #[error("this device has key version {local} but the vault is at {server}; sync first")]
    Stale {
        /// Local key version.
        local: u32,
        /// The server's.
        server: u32,
    },
    /// Stopped by [`RotationOptions::stop_after_chunks`] (test hook).
    #[error("rotation interrupted")]
    Interrupted,
}

impl RotationError {
    /// Whether another client's rotation is running (`409 rotating` on
    /// `begin`).
    #[must_use]
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Team(TeamError::Account(crate::AccountError::Sync(e))) if e.code() == Some(ErrorCode::Rotating))
    }
}

impl From<SyncError> for RotationError {
    fn from(e: SyncError) -> Self {
        Self::Team(e.into())
    }
}

impl From<TrustError> for RotationError {
    fn from(e: TrustError) -> Self {
        Self::Team(TeamError::Trust(e))
    }
}

impl From<courier_ftp_crypto::CryptoError> for RotationError {
    fn from(e: courier_ftp_crypto::CryptoError) -> Self {
        Self::Team(e.into())
    }
}

impl From<courier_ftp_core::vault::VaultError> for RotationError {
    fn from(e: courier_ftp_core::vault::VaultError) -> Self {
        Self::Team(e.into())
    }
}

/// What a finished rotation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationReport {
    /// The new key version.
    pub key_version: u32,
    /// The vault's head revision after the commit.
    pub head_revision: u64,
    /// Items re-encrypted (tombstones included).
    pub items: usize,
    /// Items uploaded by this run (fewer than `items` after a resume).
    pub uploaded: usize,
    /// Members the new key was wrapped for (this account included).
    pub members: usize,
    /// The server resumed this client's earlier attempt.
    pub resumed: bool,
    /// An abandoned rotation of another client was discarded first.
    pub replaced_abandoned: bool,
    /// Org admins without a grant that were skipped (untrusted key).
    pub skipped_admins: usize,
}

/// Knobs (defaults: the protocol limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationOptions {
    /// Items per upload (≤ 500).
    pub chunk_items: usize,
    /// Test hook: stop with [`RotationError::Interrupted`] after this many
    /// uploaded chunks (simulates a crash mid-upload).
    #[doc(hidden)]
    pub stop_after_chunks: Option<usize>,
}

impl Default for RotationOptions {
    fn default() -> Self {
        Self {
            chunk_items: MAX_ROTATION_CHUNK,
            stop_after_chunks: None,
        }
    }
}

/// The persisted progress (`meta` `rotation:<vault>`, JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Progress {
    new_key_version: u32,
    /// VK′ sealed under the LMK (purpose `VaultKey(vault)`), base64url.
    key: String,
    uploaded: BTreeSet<Uuid>,
}

fn meta_key(vault: VaultId) -> String {
    format!("{META_ROTATION_PREFIX}{}", vault.uuid())
}

type Res<T> = Result<T, RotationError>;

fn invalid(m: impl Into<String>) -> RotationError {
    RotationError::Team(TeamError::Invalid(m.into()))
}

/// Splits re-encrypted items into upload chunks (≤ `max` items, ≤ 8 MiB).
fn chunks(items: Vec<RotatedItem>, max: usize) -> Vec<Vec<RotatedItem>> {
    let max = max.clamp(1, MAX_ROTATION_CHUNK);
    let mut out = Vec::new();
    let mut cur: Vec<RotatedItem> = Vec::new();
    let mut bytes = 0usize;
    for i in items {
        let len = i.envelope.len();
        if !cur.is_empty() && (cur.len() >= max || bytes + len > MAX_PUSH_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        bytes += len;
        cur.push(i);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

impl Teams {
    async fn load_progress(&self, vault: VaultId) -> Option<Progress> {
        let bytes = self.store().meta().get(&meta_key(vault)).await.ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    async fn save_progress(&self, vault: VaultId, p: &Progress) -> Res<()> {
        let bytes =
            serde_json::to_vec(p).map_err(|e| invalid(format!("rotation progress: {e}")))?;
        self.store()
            .meta()
            .set(&meta_key(vault), bytes)
            .await
            .map_err(TeamError::from)?;
        Ok(())
    }

    async fn clear_progress(&self, vault: VaultId) {
        if let Err(e) = self.store().meta().delete(&meta_key(vault)).await {
            tracing::warn!(vault = %vault.short(), error = %e, "rotation progress not cleared");
        }
    }

    /// Whether this device has an unfinished rotation of `vault`.
    pub async fn has_pending_rotation(&self, vault: VaultId) -> bool {
        self.load_progress(vault).await.is_some()
    }

    async fn rotate_call(&self, vault: VaultId, req: RotateRequest) -> Res<RotateResponse> {
        let (id, req) = (vault.uuid(), &req);
        Ok(self
            .call(|api, t| async move { api.rotate(&t, id, req).await })
            .await?)
    }

    /// [`Self::rotate`] with [`RotationOptions`].
    ///
    /// # Errors
    /// See [`Self::rotate`].
    #[allow(clippy::too_many_lines)]
    pub async fn rotate_with(
        &self,
        vault: VaultId,
        opts: RotationOptions,
        progress: &(dyn Fn(RotationProgress) + Send + Sync),
    ) -> Res<RotationReport> {
        let report = |phase, done, total| {
            progress(RotationProgress {
                vault,
                phase,
                done,
                total,
            });
        };
        report(RotationPhase::Starting, 0, 0);
        let (kv, vk) = self.local_key(vault).await?;
        let members = self.vault_members(vault).await?;
        if members.key_version != kv {
            return Err(RotationError::Stale {
                local: kv,
                server: members.key_version,
            });
        }
        let nkv = kv + 1;
        let engine = self.session.vault();

        // 1. begin (or resume).
        let begun = self
            .rotate_call(
                vault,
                RotateRequest::Begin {
                    new_key_version: nkv,
                },
            )
            .await?;
        let saved = self
            .load_progress(vault)
            .await
            .filter(|p| p.new_key_version == nkv);
        let resumed = begun.resumed && saved.is_some();
        let purpose = WrapPurpose::VaultKey(*vault.as_bytes());
        let (vk2, mut done) = match saved.filter(|_| begun.resumed) {
            Some(p) => {
                let sealed = courier_ftp_proto::b64::decode(&p.key)
                    .map_err(|e| invalid(format!("rotation progress: {e}")))?;
                let plain = engine.lmk_open(purpose, &sealed).await?;
                let k = Key32::from_slice(&plain)
                    .map_err(|_| invalid("rotation progress: bad key length"))?;
                tracing::info!(vault = %vault.short(), uploaded = p.uploaded.len(), "resuming the key rotation");
                (k, p)
            }
            None => {
                // 2. a fresh VK′, persisted before anything is uploaded.
                let k = random_key32(&mut os_rng());
                let sealed = engine.lmk_seal(purpose, k.expose_secret()).await?;
                let p = Progress {
                    new_key_version: nkv,
                    key: courier_ftp_proto::b64::encode(&sealed),
                    uploaded: BTreeSet::new(),
                };
                self.save_progress(vault, &p).await?;
                (k, p)
            }
        };

        // 3. pull everything and re-encrypt under VK′.
        let all = self.pull_all(vault).await?;
        let total = all.len();
        let mut bad = 0usize;
        let mut todo = Vec::new();
        let mut ids = HashSet::with_capacity(total);
        for (n, item) in all.iter().enumerate() {
            ids.insert(item.id);
            if done.uploaded.contains(&item.id) {
                continue;
            }
            let lookup = |v: u32| (v == kv).then_some(&vk);
            let Ok(plain) = open_item(lookup, vault.as_bytes(), item.id.as_bytes(), &item.envelope)
            else {
                tracing::warn!(vault = %vault.short(), item = %item.id, key_version = item.key_version, "item does not open; rotation stops");
                bad += 1;
                continue;
            };
            let envelope = seal_item(
                &vk2,
                vault.as_bytes(),
                item.id.as_bytes(),
                nkv,
                &plain,
                &mut os_rng(),
            )?;
            todo.push(RotatedItem {
                id: item.id,
                envelope,
            });
            if n % 100 == 0 {
                report(RotationPhase::Encrypting, n, total);
            }
        }
        if bad > 0 {
            return Err(RotationError::Undecryptable(bad));
        }
        report(RotationPhase::Encrypting, total, total);

        // 4. upload in chunks, persisting the ids after each.
        let to_upload = todo.len();
        let mut uploaded = 0usize;
        report(RotationPhase::Uploading, total - to_upload, total);
        for (k, chunk) in chunks(todo, opts.chunk_items).into_iter().enumerate() {
            if opts.stop_after_chunks.is_some_and(|n| k >= n) {
                return Err(RotationError::Interrupted);
            }
            let chunk_ids: Vec<Uuid> = chunk.iter().map(|i| i.id).collect();
            self.rotate_call(vault, RotateRequest::Upload { items: chunk })
                .await?;
            uploaded += chunk_ids.len();
            done.uploaded.extend(chunk_ids);
            self.save_progress(vault, &done).await?;
            report(
                RotationPhase::Uploading,
                total - to_upload + uploaded,
                total,
            );
        }

        // 5. wrap VK′ for every remaining member and commit.
        report(RotationPhase::Committing, 0, 0);
        let members = self.vault_members(vault).await?;
        let (wrapped_keys, skipped_admins) =
            self.wrap_for_members(vault, &vk2, nkv, &members).await?;
        let n_members = wrapped_keys.len();
        let committed = self
            .rotate_call(vault, RotateRequest::Commit { wrapped_keys })
            .await?;
        self.clear_progress(vault).await;
        // This device switches to VK′ right away (other devices of the
        // account pick it up from the new grant).
        if let Err(e) = crate::shared::install_rotated(engine, vault, nkv, &vk, &vk2).await {
            tracing::warn!(vault = %vault.short(), error = %e, "rotated key not installed locally; the next sync does it");
        }
        report(RotationPhase::Done, total, total);
        tracing::info!(vault = %vault.short(), key_version = committed.key_version, items = total, members = n_members, "vault key rotated");
        Ok(RotationReport {
            key_version: committed.key_version,
            head_revision: committed.head_revision,
            items: total,
            uploaded,
            members: n_members,
            resumed,
            replaced_abandoned: begun.replaced_abandoned,
            skipped_admins,
        })
    }

    /// Every item of `vault` on the server, from revision 0.
    async fn pull_all(&self, vault: VaultId) -> Res<Vec<RemoteItem>> {
        let id = vault.uuid();
        let mut since = 0u64;
        let mut out = Vec::new();
        loop {
            let page = self
                .call(|api, t| async move { api.pull(&t, id, since, MAX_PULL_LIMIT).await })
                .await?;
            let next = page.next_cursor(since);
            let more = page.more && !page.items.is_empty() && next > since;
            out.extend(page.items);
            if !more {
                return Ok(out);
            }
            since = next;
        }
    }

    /// VK′ wrapped and signed for the remaining members of `members` (grant
    /// holders, plus org admins whose key is trusted).
    async fn wrap_for_members(
        &self,
        vault: VaultId,
        vk2: &Key32,
        nkv: u32,
        members: &VaultMembersView,
    ) -> Res<(Vec<RotationGrant>, usize)> {
        let me = self.me();
        let dir = self.directory();
        let mut out = Vec::new();
        let mut blocked = Vec::new();
        let mut skipped = 0usize;
        let mut rng = os_rng();
        // The committer always keeps the key.
        let g = self_grant(
            vk2,
            vault.as_bytes(),
            nkv,
            me.as_bytes(),
            &self.keys,
            &mut rng,
        )?;
        out.push(RotationGrant {
            user: me,
            wrapped: g.wrapped,
            signature: g.signature.to_vec(),
        });
        for m in &members.members {
            if m.user_id == me {
                continue;
            }
            let required = m.permission.is_some();
            if !required && m.org_role < Role::Admin {
                continue;
            }
            match self.trust.keys_for_grant(&dir, m.user_id).await {
                Ok(keys) => {
                    let g = grant_vault_key(
                        vk2,
                        vault.as_bytes(),
                        nkv,
                        m.user_id.as_bytes(),
                        &keys.x25519,
                        self.keys.ed25519_signing_key(),
                        &mut rng,
                    )?;
                    out.push(RotationGrant {
                        user: m.user_id,
                        wrapped: g.wrapped,
                        signature: g.signature.to_vec(),
                    });
                }
                Err(e) if required => {
                    tracing::warn!(vault = %vault.short(), user = %m.user_id, error = %e, "REFUSING to wrap the rotated key: the member's key is not trusted");
                    blocked.push(UntrustedMember {
                        user: m.user_id,
                        email: m.email.clone(),
                        reason: e.to_string(),
                    });
                }
                Err(e) => {
                    tracing::warn!(vault = %vault.short(), user = %m.user_id, error = %e, "org admin skipped in the key rotation (key not trusted)");
                    skipped += 1;
                }
            }
        }
        if !blocked.is_empty() {
            return Err(RotationError::UntrustedMembers(blocked));
        }
        Ok((out, skipped))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn chunking() {
        let items: Vec<RotatedItem> = (0..1203u128)
            .map(|i| RotatedItem {
                id: Uuid::from_u128(i),
                envelope: vec![0; 10],
            })
            .collect();
        let c = chunks(items.clone(), 500);
        assert_eq!(
            c.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![500, 500, 203]
        );
        assert_eq!(chunks(items, 2000).len(), 3, "capped at 500");
        let big: Vec<RotatedItem> = (0..10u128)
            .map(|i| RotatedItem {
                id: Uuid::from_u128(i),
                envelope: vec![0; 1024 * 1024],
            })
            .collect();
        assert!(
            chunks(big, 500)
                .iter()
                .all(|c| c.iter().map(|i| i.envelope.len()).sum::<usize>() <= MAX_PUSH_BYTES)
        );
    }

    #[test]
    fn untrusted_message_names_members() {
        let e = RotationError::UntrustedMembers(vec![UntrustedMember {
            user: Uuid::nil(),
            email: Some("bob@example.test".into()),
            reason: "changed".into(),
        }]);
        let s = e.to_string();
        assert!(
            s.contains("bob@example.test") && s.contains("Settings → Teams"),
            "{s}"
        );
    }
}
