# T82 — Local store (SQLite)

**Phase:** H Sync (also used by the local vault) · **Depends on:** T80, T81 · **Crate:** new `courier-ftp-store` · **Decisions:** D4, D13
**Related (integrates with, not blocking):** T40
**Reference:** sverb `crates/sverb-store/src/{db,items,outbox,sync_state,vaults,meta,approvals,pins,device_local}.rs`, `migrations/client/*.sql`.

## Goal

The client database holding encrypted items, sync bookkeeping and device-local
data. It works the same with or without sync, so turning sync on later pushes
everything that already exists.

## Scope

1. `rusqlite` (bundled SQLite) + `rusqlite_migration` (`PRAGMA user_version`); refuse to
   open a DB with a newer schema ("database created by a newer courier-ftp").
2. Connection setup: WAL, `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout`;
   one writer behind a `tokio::sync::Mutex` using `IMMEDIATE` transactions plus a small
   pool of read-only connections; all calls in `spawn_blocking`.
3. **Schema** (`migrations/0001_init.sql`):
   ```sql
   meta(key TEXT PRIMARY KEY, value BLOB)
   vaults(id BLOB PRIMARY KEY, kind INT, org_id BLOB, key_version INT,
          wrapped_key BLOB, sync_cursor INT DEFAULT 0)
   items(id BLOB PRIMARY KEY, vault_id BLOB REFERENCES vaults(id),
         revision INT DEFAULT 0,      -- server revision, 0 = never synced
         key_version INT, envelope BLOB, deleted INT, dirty INT, updated_at INT)
   outbox(item_id BLOB PRIMARY KEY, vault_id BLOB, base_revision INT,
          queued_at INT, attempts INT)  -- one row per item, edits coalesce
   device_local(item_id BLOB PRIMARY KEY, last_connected_at INT, frecency REAL,
                local_dir_override TEXT)
   device_blobs(name TEXT PRIMARY KEY, envelope BLOB)  -- LMK-encrypted: transfer queue, tab state
   sync_state(id INT PRIMARY KEY CHECK (id = 1), server_url TEXT, device_id BLOB, tokens_enc BLOB)
   pinned_keys(user_id BLOB PRIMARY KEY, x25519_pub BLOB, ed25519_pub BLOB, pinned_at INT)
   local_approvals(item_id BLOB, field TEXT, value_sha256 BLOB, approved_at INT,
                   PRIMARY KEY (item_id, field))
   ```
4. **Every local write** marks the item `dirty` and upserts an `outbox` row in the
   same transaction — even when sync is off.
5. Decrypted search labels (site names for fuzzy search) only in a `TEMP TABLE` with
   `PRAGMA temp_store = MEMORY` — never written to disk.
6. API: typed repositories `MetaRepo`, `VaultRepo`, `ItemRepo`, `OutboxRepo`,
   `SyncStateRepo`, `DeviceLocalRepo`, `PinRepo`, `ApprovalRepo`. The queue (T40)
   uses `device_blobs`.
7. File permissions `0600` on Unix; data dir `0700`.

## Acceptance criteria

- [ ] Migrations apply on a fresh DB and refuse newer schemas.
- [ ] Concurrent writers from two processes don't corrupt or deadlock (test with two store instances).
- [ ] Item write + outbox row are atomic.
- [ ] No plaintext item data in the DB file (grep test for a canary site name).

## Tests

- Port relevant sverb-store tests.
