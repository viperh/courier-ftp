# T85 — Sync server: vaults, pull/push and live updates

**Phase:** H Sync · **Depends on:** T83, T84 · **Crate:** `courier-ftp-server` · **Decisions:** D12, D14
**Related (integrates with, not blocking):** T89
**Reference:** sverb `crates/sverb-server/src/{sync/*,ws/*,routes/vaults.rs}`, `migrations/server/*`.

## Goal

Store encrypted items per vault, hand out ordered changes, accept pushes with
optimistic concurrency, and notify connected devices.

## Scope

1. **Tables**: `vaults` (`id` client-generated, `kind` personal/team, `owner_user_id`,
   `org_id`, `key_version`, `head_revision`, `gc_floor_revision`, `rotation JSONB`,
   `name_enc`), `vault_members` (`vault_id`, `user_id`, `permission` read/write/manage,
   `key_version`, `wrapped_vault_key`, `wrapped_by`, `signature`), `items`
   (`vault_id`, `id`, `revision`, `key_version`, `envelope`, `deleted`, `updated_at`,
   `updated_by_device`, unique `(vault_id, revision)`), `items_rotation_staging`.
2. **Endpoints**:
   - `GET /v1/vaults` — vaults the user can access with their grant.
   - `POST /v1/vaults` — create (team vaults, T89).
   - `GET /v1/vaults/{id}/changes?since=<rev>&limit=500` — items with `revision > since`
     in order, in one `REPEATABLE READ, READ ONLY` transaction; `more` flag; `410 gone`
     if `since < gc_floor_revision`.
   - `POST /v1/vaults/{id}/changes` — push. Checks in order: shape (400), membership
     (404), write permission (403), rotation in progress (`409 rotating`), stale
     `key_version` (400). A change is accepted iff the stored revision equals
     `base_revision` (or the item is absent and `base_revision = 0`). New revisions come
     from `UPDATE vaults SET head_revision = head_revision + n RETURNING …` — the row
     lock serialises pushes, so revisions have no gaps. Conflicts return the current
     item.
3. **WebSocket** `GET /v1/ws`: first message `auth` within 5 s (token never in the
   URL); server pings every 30 s, closes with 4408 after 2 missed pongs; 4401 on bad
   auth. Hub sends `vault_changed` after commits, `vault_access` on grant/revoke/rotate,
   `account_changed` after password change. Multi-replica fan-out via Postgres
   `NOTIFY/LISTEN courier_events`. Notifications are hints only.
4. **Limits**: per-user storage quota (default 100 MiB, `COURIER_STORAGE_QUOTA_MIB`),
   team vault cap (1 GiB), push batch limits from T83.
5. **GC**: tombstones older than 90 days removed; `gc_floor_revision` raised; runs every
   `COURIER_GC_INTERVAL_HOURS` and via admin CLI.
6. **What the server can see** (document in `docs/security.md`): emails, OPAQUE records,
   public keys, encrypted bundles, memberships, item counts, sizes rounded to 256 bytes,
   revisions, timing and device ids. Never item kinds, names, hosts or passwords.

## Acceptance criteria

- [x] Concurrent pushes from two devices get gap-free revisions and correct conflicts.
- [x] Pull pagination returns every change exactly once.
- [x] `410` after GC below the client's cursor.
- [x] WS notification reaches another connected device within 1 s (two replicas test).
- [x] Quota enforced.

*Status: all verified against the in-memory store with an in-process server
over HTTP/WebSocket (`tests/sync.rs`, `tests/ws.rs`). The PostgreSQL twins
(`*_pg`, incl. two replicas over real `LISTEN/NOTIFY`) run in CI's
`server-db` job and were not run locally. `POST /v1/vaults` (team vault
creation), members and the rotation endpoints are T89; the `rotation`
column, `409 rotating` and `items_rotation_staging` exist already.*

## Tests

- In-memory and Postgres-backed tests; concurrency test with many parallel pushes.
