# T89 — Teams and shared vaults

**Phase:** H Sync · **Depends on:** T85, T87, T88 · **Crates:** `courier-ftp-server`, `courier-ftp-sync`, `courier-ftp-crypto` · **Decisions:** D14
**Reference:** sverb `crates/sverb-crypto/src/grant.rs`, `crates/sverb-sync/src/{trust,rotation}.rs`, server `routes/orgs.rs`, `sync/rotation.rs`, `docs/threat-model.md`.

## Goal

Share FTP sites with other people through team (organisation) vaults, end-to-end
encrypted, with member verification and key rotation when someone leaves.

## Scope

1. **Organisations**: roles `owner`, `admin`, `member`. Endpoints: `POST|GET /v1/orgs`,
   `/orgs/{id}/members` (list, change role, remove), `/orgs/{id}/vaults`,
   `/orgs/{id}/invites` (email invite via SMTP or copyable link),
   `/invites/{token}/accept`, `/orgs/{id}/audit` (who did what, no secrets),
   `/users/{id}/public-keys`.
2. **Team vaults**: per-vault permission `read`, `write`, `manage`. Each member gets the
   vault key through a **grant**: HPKE-sealed to the member's X25519 key and signed by
   the granter's Ed25519 key (T80 `grant`). Personal vaults use a self-grant, which is
   how new devices get the personal key.
3. **Trust**: first time a member's public keys are seen they are pinned
   (`pinned_keys`, T82). A **safety number** (60 digits) can be compared out of band
   and marked verified. A changed key for a pinned member blocks new grants until the
   user accepts it (warning dialog, T90).
4. **Read-only items**: items in vaults where the user only has `read` are shown with a
   lock icon and cannot be edited (Site Manager disables fields).
5. **Removing a member → key rotation**:
   1. `POST /vaults/{id}/rotate` begin (pushes now get `409 rotating`).
   2. The rotating client re-encrypts every item under a new VK′ (same item ids,
      `key_version + 1`).
   3. Upload in chunks of 500 to staging.
   4. Commit with new grants for remaining members; server checks full coverage atomically.
   5. A rotation abandoned for 15 minutes is discarded; a crashed rotation resumes on the same device.
   6. A changed member key blocks the commit.
   Revoked members keep whatever they already downloaded (document as residual risk).
6. **Moving / copying a site** between personal and team vaults: copy creates a new
   item in the target vault (new id); move = copy + tombstone.
7. **Quotas**: team vault cap 1 GiB.

## Acceptance criteria

- [ ] Owner creates a team, invites a member, member accepts and sees shared sites.
- [ ] Read-only member can connect but not edit.
- [ ] Removing a member rotates the key; removed member can't decrypt new changes.
- [ ] Changed member key blocks grants until accepted.
- [ ] Rotation resumes after a crash.

## Tests

- Multi-user integration tests against the in-process server.
