# T89 — Teams and shared vaults

**Phase:** H Sync · **Milestone:** M8 · **Depends on:** T80, T85, T87, T88 · **Crate(s):** `courier-ftp-server` (orgs, team vaults, rotation), `courier-ftp-sync` (`trust`, `account::teams`, `account::vaults`, `rotation`), `courier-ftp-store` (pin trust queries on T82's `pinned_keys`), `courier-ftp-core` (vault permission, reference rules, transfers, credential overrides) · **Decisions:** D14 · **FEATURES.md:** §2 (shared Site Manager entries)
**Related (integrates with, not blocking):** T90, T91
**Reference:** sverb `crates/sverb-server/src/{orgs/*,routes/{orgs,shared_vaults,rotate}.rs,sync/{shared,rotation}.rs}`, `crates/sverb-sync/src/{trust,rotation}.rs`, `src/account/{teams,vaults,grants}.rs`, `crates/sverb-crypto/src/{grant,fingerprint}.rs`, `migrations/client/0003_pinned_keys.sql`, `tests/{orgs,shared_vaults,rotation,trust}.rs`, `docs/threat-model.md` (Teams); SPEC §13.

## Goal

Share Site Manager entries with other people through organisation ("team") vaults,
end-to-end encrypted: create an org, invite people, create team vaults, grant `read`,
`write` or `manage` access, verify members' keys with safety numbers, and rotate a vault's
key when someone loses access. Each member can keep their own login for a shared site
(credential override). A malicious server cannot read shared data or slip in a key
without the client noticing.

## Context

- **Before:** T80 grants (`grant_vault_key`, `self_grant`, `verify_grant`,
  `verify_and_open_grant`) and fingerprints/safety numbers; T84 schema (`orgs`,
  `org_members`, `invites`, `vaults`, `vault_members`, `items_rotation_staging`,
  `audit_events`) and registration with invite tokens; T85 push/pull, the vault row lock,
  `BusEvent::VaultAccess`; T87 `ApiClient`, `LoginSession` (skips team grants until now),
  local account keys; T88 engine with the `VaultKeySource` hook, `rotating` handling and the
  vault list refresh.
- **After:** T90 renders the team screens (orgs, members, safety numbers, key-change modal,
  vaults, invites, audit) and the Site Manager vault roots, read-only lock and move/copy;
  T91 verifies the trust rules (§10) and lists the residual risks.

## Technical specification

### Types and APIs

Server (`courier-ftp-server`): `src/orgs/{mod,mem,pg}.rs`, `src/routes/{orgs,team_vaults,rotate,users}.rs`,
`src/sync/{team,rotation}.rs`, `migrations/0003_teams.sql`.

```rust
impl Store {
    pub async fn create_org(&self, user: Uuid, name: &str, now: OffsetDateTime) -> Result<OrgView, ApiError>;
    pub async fn orgs_of(&self, user: Uuid) -> Result<Vec<OrgView>, ApiError>;
    pub async fn org_members(&self, caller: Uuid, org: Uuid) -> Result<Vec<MemberView>, ApiError>;
    pub async fn set_role(&self, caller: Uuid, org: Uuid, user: Uuid, role: Role, now: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn remove_member(&self, caller: Uuid, org: Uuid, user: Uuid, now: OffsetDateTime) -> Result<Vec<Uuid> /*vaults revoked*/, ApiError>;
    pub async fn create_invite(&self, caller: Uuid, org: Uuid, req: &CreateInviteRequest, token_hash: [u8; 32], now: OffsetDateTime) -> Result<InviteRow, ApiError>;
    pub async fn accept_invite(&self, caller: Uuid, caller_email: &str, token_hash: [u8; 32], now: OffsetDateTime) -> Result<InviteAccepted, ApiError>;
    pub async fn audit_page(&self, caller: Uuid, org: Uuid, before: Option<i64>, limit: u32) -> Result<AuditPage, ApiError>;
    pub async fn public_keys(&self, caller: Uuid, user: Uuid) -> Result<UserPublicKeys, ApiError>;
    pub async fn create_team_vault(&self, ctx: AuthCtx, req: &CreateVaultRequest, now: OffsetDateTime) -> Result<VaultView, ApiError>;
    pub async fn vault_members(&self, caller: Uuid, vault: Uuid) -> Result<VaultMembersView, ApiError>;
    pub async fn org_vaults(&self, caller: Uuid, org: Uuid) -> Result<Vec<OrgVaultView>, ApiError>;
    pub async fn grant(&self, caller: Uuid, vault: Uuid, member: Uuid, req: &GrantRequest, now: OffsetDateTime) -> Result<bool /*new member*/, ApiError>;
    pub async fn revoke(&self, caller: Uuid, vault: Uuid, member: Uuid, now: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn rotate(&self, ctx: AuthCtx, vault: Uuid, req: &RotateRequest, now: OffsetDateTime) -> Result<RotateResponse, ApiError>;
}
```

Client (`courier-ftp-sync`):

```rust
// src/trust.rs
pub struct PinnedKey { pub user_id: Uuid, pub label: Option<String>, pub fingerprint: [u8; 32],
    pub x25519_pub: [u8; 32], pub ed25519_pub: [u8; 32], pub first_seen_at: OffsetDateTime,
    pub verified: bool, pub verified_at: Option<OffsetDateTime>, pub is_self: bool,
    pub changed: Option<ChangedKey> }
pub struct ChangedKey { pub fingerprint: [u8; 32], pub x25519_pub: [u8; 32], pub ed25519_pub: [u8; 32], pub seen_at: OffsetDateTime }
pub enum Observed { FirstSight, Same, Changed }
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("{0}'s key changed; compare safety numbers and accept the new key first")] KeyChanged(String),
    #[error("{0} is not pinned on this device")] NotPinned(String),
    #[error("grant signature does not verify")] BadSignature,
    #[error("the granter may not grant this vault")] GranterNotAllowed,
    #[error("personal vault keys must be self-grants")] NotSelfGrant,
    #[error(transparent)] Sync(#[from] SyncError),
}
pub struct Trust { /* store, me, api, tokens */ }
impl Trust {
    pub async fn pin_self(&self, keys: &AccountPublicKeys) -> Result<(), TrustError>;
    pub async fn observe(&self, keys: &UserPublicKeys) -> Result<Observed, TrustError>;
    pub async fn fetch(&self, user: Uuid) -> Result<(UserPublicKeys, Observed), TrustError>;   // GET public-keys + observe
    pub async fn keys_for_grant(&self, user: Uuid) -> Result<AccountPublicKeys, TrustError>;   // refuses Changed
    pub async fn safety_number(&self, user: Uuid) -> Result<String, TrustError>;              // 60 digits, 12 groups
    pub async fn mark_verified(&self, user: Uuid) -> Result<(), TrustError>;
    pub async fn accept_new_key(&self, user: Uuid, verified: bool) -> Result<(), TrustError>;
    pub async fn pins(&self) -> Result<Vec<PinnedKey>, TrustError>;
}
pub struct VaultMembership { pub created_by: Option<Uuid>, pub managers: HashSet<Uuid> } // from VaultMembersView (untrusted)
pub struct GrantToVerify<'a> { pub vault: Uuid, pub kind: VaultKind, pub member: Uuid, pub key_version: u32,
                               pub wrapped: &'a [u8], pub signature: &'a [u8], pub wrapped_by: Uuid }
/// T91 §10 rules; returns the granter's pinned Ed25519 key on success.
pub fn verify_grant(g: &GrantToVerify<'_>, me: Uuid, pins: &PinSet, membership: Option<&VaultMembership>) -> Result<(), TrustError>;
/// VaultKeySource for the engine (T88) enforcing verify_grant.
pub struct TrustedKeySource;

// src/account/vaults.rs
pub struct VaultAdmin { /* api, tokens, trust, store, lmk, account keys */ }
impl VaultAdmin {
    pub async fn create(&self, org: Uuid, name: &str) -> Result<VaultId, SyncError>;
    pub async fn grant(&self, vault: VaultId, user: Uuid, permission: Permission) -> Result<(), SyncError>;
    pub async fn revoke_and_rotate(&self, vault: VaultId, user: Uuid, progress: impl Fn(RotationProgress)) -> Result<RotationReport, RotationError>;
    pub async fn reconcile_admins(&self, vault: VaultId) -> Result<Vec<Uuid> /*granted*/, SyncError>;
}
// src/account/teams.rs — thin wrappers for orgs, members, invites, audit (UI uses them)
pub async fn create_org(..) / list_orgs / members / set_role / remove_member (→ rotations) / invite / accept_invite(link_or_token) / audit_page

// src/rotation.rs
pub enum RotationPhase { Begin, Download { done: u64, total: u64 }, Upload { done: u64, total: u64 }, Commit, Done }
pub struct RotationProgress { pub vault: VaultId, pub phase: RotationPhase }
pub struct UntrustedMember { pub user: Uuid, pub label: Option<String>, pub reason: String }
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("another key rotation is running for this vault")] Busy,
    #[error("rotation blocked: {0:?} have changed or unverifiable keys")] UntrustedMembers(Vec<UntrustedMember>),
    #[error(transparent)] Sync(#[from] SyncError),
}
pub struct RotationReport { pub vault: VaultId, pub new_key_version: u32, pub items: u64, pub resumed: bool }
pub async fn rotate(admin: &VaultAdmin, vault: VaultId, progress: impl Fn(RotationProgress)) -> Result<RotationReport, RotationError>;
```

Core (`courier-ftp-core`):

Sync-facing `VaultEngine` methods with signatures fixed in T30; this task implements the
bodies (read-only check and cross-vault reference check included):

```rust
impl VaultEngine {
    pub fn vault_permission(&self, vault: VaultId) -> VaultPermission;   // Personal → Manage
    pub fn vaults(&self) -> Result<Vec<VaultInfo>, VaultError>;          // id, kind, permission (+ name, org from meta)
    /// Read-only check: put/put_many/delete/transfer-out on a `Read` vault →
    /// `VaultError::ReadOnlyVault(id)`. Cross-vault reference check: put/put_many/transfer
    /// of a team-vault item referencing an item in another vault →
    /// `VaultError::CrossVaultReference("A shared site can't use an item from your personal
    /// vault; add a credential override instead")` (→ `Error::InvalidInput`).
    pub async fn transfer(&self, plan: TransferPlan) -> Result<Vec<ItemId>, VaultError>;   // copy or move, one tx
}
pub enum TransferMode { Copy, Move }
pub struct TransferPlan { pub mode: TransferMode, pub items: Vec<ItemId>, pub target: VaultId,
                          pub target_folder: Option<ItemId>, pub include_refs: bool }
/// Effective logon for a site in a team vault: override fields replace the site's.
pub fn effective_logon(site: &Site, overrides: &[CredentialOverride]) -> Logon;
```

### Behaviour

#### Roles and permissions

| Action | member | admin | owner |
|---|---|---|---|
| see org, members, vaults with a grant | ✔ | ✔ | ✔ |
| create team vault | — | ✔ | ✔ |
| implicit `manage` on every org vault | — | ✔ | ✔ |
| invite (role ≤ own role; only owners invite owners) | — | ✔ | ✔ |
| change roles member ↔ admin | — | ✔ | ✔ |
| make/demote owners | — | — | ✔ |
| remove members/admins | — | ✔ | ✔ |
| remove owners | — | — | ✔ |
| read audit log | — | ✔ | ✔ |
| leave org | ✔ | ✔ | ✔ (not the last owner) |

Vault permissions: `read` (pull), `write` (pull, push), `manage` (push, grant, revoke, rotate).

#### Endpoints (server)

| Method | Path | Caller must | Success | Errors |
|---|---|---|---|---|
| POST | `/v1/orgs` | any user | 201 `OrgView` (caller = owner; audit `org.created`) | 400 name (1–100 chars) |
| GET | `/v1/orgs` | — | 200 `Vec<OrgView>` | — |
| GET | `/v1/orgs/{id}/members` | member | 200 `Vec<MemberView>` (by email) | 404 |
| PATCH | `/v1/orgs/{id}/members/{user}` | admin (owner for owner changes) | 204, audit `member.role_changed` | 403; 404; 400 `"an org needs at least one owner"` |
| DELETE | `/v1/orgs/{id}/members/{user}` | admin/owner per table, or the user themself | 204; deletes the user's grants on every org vault; publishes `VaultAccess{revoked}` per vault; audit `member.removed` | 403; 404; 400 last owner |
| GET | `/v1/orgs/{id}/vaults` | member | 200 `Vec<OrgVaultView>` (vaults with a grant; all for admin/owner) | 404 |
| POST | `/v1/orgs/{id}/invites` | admin (owner to invite owners) | 201 `InviteCreated` (link unless mailed); audit `invite.sent` | 403; 404; 400 email |
| POST | `/v1/invites/{token}/accept` | Bearer; email matches if bound | 200 `InviteAccepted` (existing higher role kept); audit `invite.accepted`, `member.added` | 404 `"invalid or expired invite"`; 403 `"this invite is for another account"` |
| GET | `/v1/orgs/{id}/audit?before&limit` | admin | 200 `AuditPage` newest first (limit default 50, max 200) | 403; 404 |
| GET | `/v1/users/{id}/public-keys` | shares an org with the user, or self | 200 `UserPublicKeys` | 404 |
| POST | `/v1/vaults` | org admin/owner | 201 `VaultView`; self-grant `manage` at key version 1; audit `vault.created`; `VaultAccess{granted}` to caller | 400 (self-grant signature by caller's key, `name_enc` 1–4096 B, key_version 1); 403; 404 org; 409 `"vault id already exists"` |
| GET | `/v1/vaults/{id}/members` | grant on the vault or org admin | 200 `VaultMembersView` (all org members) | 404 |
| PUT | `/v1/vaults/{id}/members/{user}` | `manage` (explicit or admin/owner) | 204; row for the current key version replaced; audit `vault.member_granted` `{permission}`; `VaultAccess{granted}` if new | 400 `"not an org member"`, `"key_version_stale…"`, signature does not verify with the caller's stored key, sizes; 403; 404; 409 rotating |
| DELETE | `/v1/vaults/{id}/members/{user}` | `manage`, or the member themself | 204; all key versions' rows removed; audit `vault.member_revoked`; `VaultAccess{revoked}` | 403; 404; 409 rotating |
| POST | `/v1/vaults/{id}/rotate` | `manage` | 200 `RotateResponse` | below |

Registration with an org invite (T84 `RegisterOutcome::org_invite`): in the same
registration transaction, `org_members` gets the invite's role and the invite is accepted
(audit `invite.accepted`, `member.added`).

Push audit: every accepted push to a team vault writes one `vault.items_pushed` event
`{"vault_id", "item_ids":[…]}` (ids only).

#### Key rotation protocol (§13.2)

Server, all under the vault row lock:

| Action | Preconditions | Effect / response |
|---|---|---|
| `begin{new_key_version}` | `manage`; team vault (personal → 400 `"personal vaults are not rotated"`); `new_key_version == key_version + 1` | no rotation → set `rotation = {by, device, new_key_version, started_at: now}`; same user+device already rotating to that version → **resume** (staging kept, `started_at = now`, `resumed: true`); other client's rotation not abandoned → 409 rotating; abandoned (> 15 min) → delete its staging, start fresh (`replaced_abandoned: true`) |
| `upload{items}` | rotating user+device; ≤ 500 items / 8 MiB; each id exists in `items`; envelope ≤ 1 MiB and header key version == `new_key_version` | upsert into `items_rotation_staging`; `staged` = count |
| `commit{wrapped_keys}` | rotating user+device; every item of the vault (live and tombstones) is staged (else 400 `"staging misses N items"`, nothing applied); one grant per user who held a grant and is still an org member (else 400 `"missing grant for member <uuid>"`); org admins/owners without a grant may be included; others → 400; each signature verifies with the committer's stored Ed25519 key | items replaced by staged envelopes with fresh revisions `head+1 ..= head+n` in old revision order; `key_version = new`; all `vault_members` rows replaced by the new ones (permission from the grant); `rotation = NULL`; staging deleted; audit `vault.rotated {key_version, members}`; after commit `VaultChanged` + `VaultAccess{rotated}` to every member |

While `rotation` is set, pushes get 409 `rotating`, grants/revokes get 409; pulls continue
(items under the old key). `GET /v1/vaults` shows `rotation.abandoned` after 15 minutes;
T85's GC clears abandoned rotations.

Client (`rotation::rotate`, run by the `manage` client that removed a member, or the next
`manage` client prompted after abandonment):
1. If `meta.rotation:<vault>` exists (crash), load it; else generate **VK′** and persist
   `{new_key_version, vk_new (wrap(LMK, VaultKey(vault)) with new version in AAD),
   uploaded: [], started_at}` **before** the first request.
2. `begin` (resume accepted).
3. Pull every item from revision 0 (tombstones included), open with the current VK,
   re-seal under VK′ with the same item id and `new_key_version`.
4. Upload chunks (≤ 500 items / 8 MiB) skipping ids already in `uploaded`; after each chunk
   append its ids to `meta.rotation:<vault>` (one SQLite write).
5. Members: `GET /v1/vaults/{id}/members`; for every member that must get a grant fetch
   public keys and `Trust::observe`; `Changed` or fetch failure → `RotationError::
   UntrustedMembers` (rotation stays open, pushes stay paused; resumed after the key is
   accepted in Settings → Team, or abandoned after 15 min). Org admins without an existing
   grant and with untrusted keys are skipped (reconciled later).
6. `commit` with `RotationGrant{user, HPKE(VK′ → member x25519), signature, permission}` for
   each (including self).
7. Delete `meta.rotation:<vault>`. If the process crashed after commit but before step 7,
   the next start sees `vaults.key_version == saved new_key_version` on the server and
   deletes the state without calling `begin`.
8. Every device (this one included) switches keys through the engine's vault list refresh:
   new grant verified → key stored → local items still under the old version re-sealed →
   rotated items pulled.
Revoked members keep whatever they downloaded before (residual risk, T91 §9).

#### Trust (§13.3, T91 §10)

- **Pins** are device-local (store `pinned_keys`), never synced. Every user's keys are
  pinned on first sight (granting, listing members, verifying grants, fetching keys); the own
  account's keys are pinned with `is_self = 1` at login/registration.
- **Changed key:** the pin is **not** replaced; the new key goes to `changed_*`, `verified`
  is cleared, `SyncEvent::Toast{Warn}` + a red modal (T90). Grants **to** that user are
  refused (`keys_for_grant` → `KeyChanged`), grants **from** that user are not trusted, and a
  rotation that must include them is blocked, until the user compares safety numbers and
  accepts the new key (`accept_new_key`, optionally marking it verified).
- **Safety number:** T80 `safety_number(fpr(a), fpr(b))` — 60 digits in 12 groups of 5,
  symmetric; marking verified stores `verified = 1` (✔ in UI).
- **`verify_grant` rules** (a vault key is used only if all hold):
  1. signature verifies over T80's canonical grant with the **pinned, unchanged** Ed25519
     key of `wrapped_by`;
  2. personal vault: `wrapped_by == member == me` (self-grant signed by our own key);
  3. team vault: `wrapped_by` has `manage` per the vault membership list, or is an org
     owner/admin, or is `created_by` (the creator's self-grant, TOFU on the creator);
  4. a self-grant claimed for another user (`wrapped_by == member != me`) is rejected unless
     that user is `created_by`.
  Failures → the vault is not adopted / the new key not used; status "access to N team
  vaults could not be verified"; toast once per vault.

#### Adoption, revocation, read-only

- **New vault** (vault list shows a team vault not stored locally, or `vault_access
  granted`): fetch `VaultMembersView`, pin granter (first sight), `verify_grant`, open VK,
  store the vault (`VK` wrapped under LMK, `sync_cursor = 0`), `meta.vault_name_enc/<id>`,
  `meta.vault_permission/<id>`; emit `VaultAdded`; pull.
- **Revoked** (`vault_access revoked`, or the vault disappears from the list, or 404 on
  pull): delete the local vault, its items and outbox rows; toast "You no longer have access to
  <name>" plus "N unsynced changes were discarded" when N > 0.
- **Permission change:** `meta.vault_permission/<id>` updated on every vault list refresh.
  `read` → `VaultEngine::put/delete` refuse with `VaultError::ReadOnlyVault(id)`; items dirty before
  the downgrade are blocked `ReadOnly` (T88) and the UI offers "Revert to server version"
  (drop local changes, re-pull) or "Copy to personal vault".
- **Admin reconcile:** on each vault list refresh, a client with `manage` grants `manage`
  (current key version) to org admins/owners without a key whose keys are pinned and
  unchanged.

#### Credentials in shared vaults (§13.4)

- A `site` (or `bookmark`, `site-folder`) in a team vault may only reference items in the
  same vault; `VaultEngine::put` enforces it (error text above).
- `credential-override` item in the **personal** vault: fields `shared_site_id` (ItemId),
  `user`, `password`, `account`, `key_id` (ssh-key in the personal vault), `key_passphrase`;
  at most one per `shared_site_id` (newest `hlc` wins if two exist). On connect,
  `effective_logon` replaces the site's logon fields with every non-empty override field.
  Overrides never leave the personal vault.

#### Move / copy between vaults

`VaultEngine::transfer` in one local transaction: copy = new item id in the target vault,
fields copied with fresh stamps, `parent` set to `target_folder` (or root); with
`include_refs = true` referenced items not in the target (ssh-key, proxy-credential) are
copied too and references remapped, otherwise the transfer is refused if references would
cross vaults (team target) or the reference is cleared (personal target, user confirmed);
the site's bookmarks are copied with it. Move = copy + tombstone of the source items.
Read-only source vault: copy allowed, move refused. Device-local rows follow the new ids.

#### Leaving / disabling sync

Leaving an org (`DELETE …/members/{me}`) or logging out (T87) removes that org's vaults from
the device; the personal vault stays.

#### Quotas

Team vaults: 1 GiB each (T85 `TEAM_VAULT_CAP_BYTES`), not counted against users.

### Data formats and configuration

Server `migrations/0003_teams.sql`:

```sql
CREATE INDEX vaults_org_id ON vaults (org_id) WHERE kind = 'team';
CREATE INDEX invites_org ON invites (org_id) WHERE accepted_at IS NULL;
-- At least one owner per org is enforced in the transaction (count check), not by a constraint.
```

Client pins use T82's full `pinned_keys` table (sverb's: `user_id`, `label`,
`fingerprint` = SHA-256(`"courier-ftp/fpr/v1"`‖x25519‖ed25519), `x25519_pub`,
`ed25519_pub`, `first_seen_at`, `verified`, `verified_at`, `is_self`,
`changed_fingerprint`, `changed_x25519_pub`, `changed_ed25519_pub`, `changed_at`). No client
migration is added by this task.

Local meta keys: `vault_name_enc/<uuid>`, `vault_permission/<uuid>` (`read|write|manage`),
`rotation:<uuid>` (CBOR `{new_key_version, vk_new_wrapped, uploaded: [16-byte ids],
started_at}` sealed with `wrap(LMK, WrapPurpose::VaultKey(vault))`).

Invite link format: `<public_url>/invite/<43-char token>`; the client accepts either the
full link or the bare token.

No new settings keys.

### Errors

- Server: `ApiError` variants as in the tables.
- Client: `TrustError`, `RotationError` (above), `SyncError` (T87); core:
  `VaultError::ReadOnlyVault(id)` (→ `Error::Vault(..)`), `VaultError::CrossVaultReference`
  (→ `Error::InvalidInput(..)`), `VaultError::Locked` (→ `Error::VaultLocked`).
  UI texts in T90.

### Security and logging

- The server stores org names and member emails in plaintext (needed for invites and member
  lists) — listed in "What the sync server sees" (T85); vault names are sealed under the VK.
- Never logged: vault keys, wrapped keys (beyond length), safety numbers, override secrets.
  Info logs carry org/vault/user ids only; member emails are not logged at info+.
- Audit events contain ids, roles and counts only — never item contents or names.
- `UserPublicKeys.email` and every membership list are untrusted on the client; they only
  narrow trust (T91 §10).
- Residual risks (documented in `docs/threat-model.md`): revoked members keep old data; first
  sight TOFU; server-asserted membership; per-device pins; accepting a changed key without
  comparing.

## Implementation steps

1. Server orgs: tables already exist; `orgs` store (mem + Pg), routes for orgs, members,
   invites, accept, audit, public keys; registration org-invite hook.
2. Server team vaults: create, members listing, org vaults, grant, revoke, push audit, admin
   implicit `manage` in vault list/push permission checks.
3. Server rotation (begin/upload/commit, resume, abandonment) + tests incl. crash/abandon.
4. Pin queries on T82's `pinned_keys`; `trust.rs` (pins, observe, safety numbers,
   `verify_grant`, `TrustedKeySource`); wire into T87 login and T88 engine.
5. Client `VaultAdmin` create/grant/revoke, adoption/revocation in the engine, admin reconcile.
6. Client `rotation.rs` with persisted state and resume.
7. Core: vault permissions, read-only enforcement, cross-vault reference rule,
   `credential-override` + `effective_logon`, `transfer`.
8. Multi-user scenarios and e2e.

## Acceptance criteria

- [ ] AC1 Owner creates an org and a team vault, invites a member by link; the member accepts,
  is granted `write`, and sees the vault's sites after one sync cycle.
- [ ] AC2 A `read` member can connect with a shared site but every edit is refused locally
  (`ReadOnly`) and a forced push gets 403.
- [ ] AC3 Removing a member rotates the vault key: the server's `key_version` increases, all
  items carry the new version, the removed member's pulls get 404, and an item edited after
  rotation does not open with the old VK.
- [ ] AC4 A member whose public key changes on the server: grants to them are refused with
  `KeyChanged`, their grants are not trusted, and a rotation that must include them stops with
  `UntrustedMembers` until the key is accepted.
- [ ] AC5 A rotation killed after uploading 2 of 4 chunks resumes on the same device without
  re-uploading those chunks and commits; a crash after commit cleans up without a new `begin`.
- [ ] AC6 A rotation abandoned for > 15 min is replaced by another `manage` client's `begin`,
  which completes it.
- [ ] AC7 Commit with incomplete staging or a missing member grant returns 400 and changes
  nothing (items, key version, grants identical).
- [ ] AC8 A tampered grant (signature by a non-manager, or by an unpinned key) is rejected and
  the vault is not adopted.
- [ ] AC9 A credential override supplies user/password for a shared site on one member's
  device only; the team vault's site item is unchanged.
- [ ] AC10 Saving a team-vault site that references a personal `ssh-key` is refused with the
  documented message; move/copy carry referenced items with `include_refs`.
- [ ] AC11 Audit log lists `org.created`, `invite.sent`, `invite.accepted`, `member.added`,
  `vault.created`, `vault.member_granted`, `vault.member_revoked`, `vault.rotated`,
  `vault.items_pushed` for the AC1/AC3 scenario, with ids only.
- [ ] AC12 Pins never leave the device (no `pinned_keys` data in any push body; test inspects
  requests).
- [ ] AC13 CI `server-db`, `fmt`, `clippy`, `docs`, `test-os` pass.

## Tests

### Unit tests
- `trust::tests::observe_first_same_changed` — pin kept on change (AC4).
- `trust::tests::verify_grant_rules` — table: valid manager grant; signature by non-manager;
  unpinned granter; granter with pending change; personal grant not self; self-grant for
  another user; creator self-grant accepted (AC8).
- `trust::tests::safety_number_symmetric_and_format` — `^\d{5}( \d{5}){11}$`.
- `core::vault::tests::read_only_put_refused` — `vault_permission(v) == VaultPermission::Read`; `put`/`delete`/`transfer` out of `v` → `Err(VaultError::ReadOnlyVault(v))`; `vaults()?` lists `v` with `VaultPermission::Read` (AC2); `cross_vault_reference_refused` → `Err(VaultError::CrossVaultReference(_))` (AC10).
- `core::sites::tests::effective_logon_override_fields` (AC9).
- `server::sync::rotation::tests::commit_checks_table` — coverage, missing grant, extra
  non-member, wrong signature (AC7).

### Property / fuzz tests
- `props::transfer_preserves_reference_integrity` — random item graphs moved/copied between
  vaults: no reference crosses into a vault the item can't resolve.
- `props::rotation_commit_is_all_or_nothing_mem` — random staging subsets: commit succeeds
  only with full coverage; failure leaves state unchanged.
- Fuzz target `grant_open` exists in T80/T91.

### Snapshot tests
- Not a UI task (T90).

### Integration tests
Server (`tests/orgs.rs`, `tests/team_vaults.rs`, `tests/rotation.rs`, mem + Pg):
- `t01_create_and_list_orgs`, `t02_role_permissions_table`, `t03_invites_link_and_email`
  (mail via a test SMTP sink), `t04_last_owner_protected`, `t05_public_keys_visibility`,
  `t06_audit_events_and_paging` (AC11).
- `create_rules`, `grant_rules`, `revoke_publishes_vault_access`, `org_admin_implicit_manage`.
- `rotation::t01_begin_upload_commit`, `t02_push_during_rotation_409`,
  `t03_incomplete_commit_rejected` (AC7), `t04_abandoned_rotation_replaced` (AC6),
  `t05_resume_same_client`, `t06_fresh_gap_free_revisions`.
Client (`courier-ftp-sync/tests/{team_vaults,rotation,trust}.rs`, in-process server):
- `t01_create_grant_receive` (AC1), `t02_grant_refused_on_changed_key` (AC4),
  `t03_tampered_grant_refused` (AC8), `t04_read_member_cannot_push` (AC2),
  `t05_revoke_rotates_and_locks_out` (AC3), `t06_move_site_with_key` (AC10),
  `t07_credential_override` (AC9), `t08_admin_auto_grant`, `t09_three_member_scenario`,
  `rotation::t05_resume_after_crash` (crash hook after chunk 2 of 4) and
  `rotation::crash_after_commit_cleans_up` (AC5), `rotation::t07_changed_member_key_blocks_commit`
  (AC4), `trust::t07_pins_never_pushed` (AC12).

### End-to-end tests
- `courier-ftp-e2e/tests/sync_teams.rs` (`#[ignore]`, `COURIER_E2E=1`, Docker sync fixture,
  three `Headless` users): `team_invite_grant_and_shared_site_connects` (a shared SFTP site
  connects to the `sshd` fixture with the member's credential override),
  `member_removal_rotates_key`, `rotation_survives_client_kill` (kills the rotating process
  between chunks, restarts it) — T76's team scenarios (AC1, AC3, AC5).

## Out of scope

- Org-level quotas and billing; SSO/SCIM.
- Per-item ACLs inside a vault.
- Web admin pages for orgs.
- OR-set list merging.

## Open questions

- **Unsynced edits in a vault whose access was revoked** are discarded (with a toast giving the
  count), as in sverb. Alternative: move them into the personal vault as copies. Which one?

Resolved (reconciliation): T82 creates the full `pinned_keys` table (with `verified` and the
pending changed-key columns) and the meta keys `vault_name_enc/<id>`,
`vault_permission/<id>`, `rotation:<id>`; T30 fixes the signatures of `vault_permission`,
`vaults` and `transfer` and the read-only / cross-vault reference checks. This task's
`ALTER TABLE` migration is dropped.
