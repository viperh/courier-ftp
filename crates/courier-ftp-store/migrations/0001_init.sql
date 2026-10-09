-- courier-ftp client schema v1 (T82). Applied by rusqlite_migration inside one
-- transaction; `PRAGMA user_version` becomes 1.
--
-- sverb's three client migrations folded into one, plus the courier-ftp
-- additions `device_blobs`, `device_local.local_dir_override` and
-- `device_local.tree_expanded`. Released migrations are never edited: later
-- schema changes are new files `0002_*.sql`, ...
--
-- Item bodies are only ever stored as encrypted envelopes. No table defined
-- here holds decrypted data.

CREATE TABLE meta        (key TEXT PRIMARY KEY, value BLOB NOT NULL);

CREATE TABLE vaults      (id BLOB PRIMARY KEY CHECK (length(id) = 16),
                          kind INTEGER NOT NULL CHECK (kind IN (0, 1)),   -- 0 personal, 1 shared
                          org_id BLOB,
                          key_version INTEGER NOT NULL,
                          wrapped_key BLOB NOT NULL,                      -- VK wrapped under the LMK
                          sync_cursor INTEGER NOT NULL DEFAULT 0);

CREATE TABLE items       (id BLOB PRIMARY KEY CHECK (length(id) = 16),
                          vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
                          revision INTEGER NOT NULL DEFAULT 0,            -- server revision, 0 = never synced
                          key_version INTEGER NOT NULL,
                          envelope BLOB NOT NULL,                         -- encrypted ItemBody (T80)
                          deleted INTEGER NOT NULL DEFAULT 0,
                          dirty INTEGER NOT NULL DEFAULT 0,               -- pending push
                          updated_at INTEGER NOT NULL);                   -- Unix ms of the last local write

CREATE TABLE outbox      (item_id BLOB PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
                          vault_id BLOB NOT NULL,
                          base_revision INTEGER NOT NULL,
                          queued_at INTEGER NOT NULL,
                          attempts INTEGER NOT NULL DEFAULT 0);

CREATE TABLE device_local(item_id BLOB PRIMARY KEY,                       -- no FK: rows may precede the item
                          last_connected_at INTEGER,
                          frecency REAL,
                          local_dir_override TEXT,
                          tree_expanded INTEGER);

CREATE TABLE device_blobs(name TEXT PRIMARY KEY,                          -- 'transfer-queue', 'tabs'
                          blob BLOB NOT NULL,                             -- T80 device_blob format
                          updated_at INTEGER NOT NULL);

CREATE TABLE sync_state  (id INTEGER PRIMARY KEY CHECK (id = 1),
                          server_url TEXT NOT NULL,
                          device_id BLOB NOT NULL,
                          tokens_enc BLOB NOT NULL);                      -- wrapped under the LMK (SyncTokens)

CREATE TABLE local_approvals (item_id BLOB NOT NULL, field TEXT NOT NULL,
                              value_sha256 BLOB NOT NULL CHECK (length(value_sha256) = 32),
                              approved_at INTEGER NOT NULL,
                              PRIMARY KEY (item_id, field));

CREATE TABLE pinned_keys (user_id BLOB NOT NULL PRIMARY KEY, label TEXT,
                          fingerprint BLOB NOT NULL, x25519_pub BLOB NOT NULL, ed25519_pub BLOB NOT NULL,
                          first_seen_at INTEGER NOT NULL,
                          verified INTEGER NOT NULL DEFAULT 0, verified_at INTEGER,
                          is_self INTEGER NOT NULL DEFAULT 0,
                          changed_fingerprint BLOB, changed_x25519_pub BLOB, changed_ed25519_pub BLOB,
                          changed_at INTEGER);

CREATE INDEX items_vault_id  ON items(vault_id);
CREATE INDEX items_dirty     ON items(dirty) WHERE dirty = 1;
CREATE INDEX outbox_vault_id ON outbox(vault_id);
