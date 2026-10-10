-- courier-ftp client schema v1 (T82). Applied by rusqlite_migration inside one
-- transaction; `PRAGMA user_version` becomes 1.
--
-- Item bodies are only ever stored as encrypted envelopes. Decrypted data never
-- goes into a table defined here; the search labels live in a TEMP table
-- (`item_index`, created at unlock on the writer connection, temp_store = MEMORY).

-- Device-level settings and wrapped secrets (KDF params, wrapped LMK, hlc_last, ...).
CREATE TABLE meta        (key TEXT PRIMARY KEY, value BLOB NOT NULL);

-- One row per vault (personal or team). The vault key is stored wrapped.
CREATE TABLE vaults      (id BLOB PRIMARY KEY, kind INTEGER NOT NULL, org_id BLOB,
                          key_version INTEGER NOT NULL,
                          wrapped_key BLOB NOT NULL,
                          sync_cursor INTEGER NOT NULL DEFAULT 0);

CREATE TABLE items       (id BLOB PRIMARY KEY, vault_id BLOB NOT NULL REFERENCES vaults(id),
                          revision INTEGER NOT NULL DEFAULT 0,  -- server revision, 0 = never synced
                          key_version INTEGER NOT NULL,
                          envelope BLOB NOT NULL,               -- encrypted ItemBody
                          deleted INTEGER NOT NULL DEFAULT 0,
                          dirty INTEGER NOT NULL DEFAULT 0,     -- pending push
                          updated_at INTEGER NOT NULL);

-- One row per item with a pending push; edits coalesce (the first base_revision stays).
CREATE TABLE outbox      (item_id BLOB PRIMARY KEY,
                          vault_id BLOB NOT NULL,
                          base_revision INTEGER NOT NULL,     -- server revision the edit is based on
                          queued_at INTEGER NOT NULL,
                          attempts INTEGER NOT NULL DEFAULT 0);

-- Per-item data that never leaves this device.
CREATE TABLE device_local(item_id BLOB PRIMARY KEY, last_connected_at INTEGER, frecency REAL,
                          local_dir_override TEXT);

-- Device-local encrypted blobs (transfer queue, tab state), sealed by the caller.
CREATE TABLE device_blobs(name TEXT PRIMARY KEY, envelope BLOB NOT NULL);

CREATE TABLE sync_state  (id INTEGER PRIMARY KEY CHECK (id = 1),
                          server_url TEXT, device_id BLOB,
                          tokens_enc BLOB);                   -- access+refresh tokens, wrapped under the LMK

-- TOFU pins of account public keys (team vaults). The first key seen is pinned; a
-- different key seen later is parked in changed_* until the user accepts it.
-- Device-local and never synced, so the server cannot poison pins.
CREATE TABLE pinned_keys (user_id               BLOB    NOT NULL PRIMARY KEY,
                          label                 TEXT,
                          fingerprint           BLOB    NOT NULL,
                          x25519_pub            BLOB    NOT NULL,
                          ed25519_pub           BLOB    NOT NULL,
                          pinned_at             INTEGER NOT NULL,
                          verified              INTEGER NOT NULL DEFAULT 0,
                          verified_at           INTEGER,
                          is_self               INTEGER NOT NULL DEFAULT 0,
                          changed_fingerprint   BLOB,
                          changed_x25519_pub    BLOB,
                          changed_ed25519_pub   BLOB,
                          changed_at            INTEGER);

-- The device-local allowlist of values the user approved on this machine: one row per
-- (item, field) with the SHA-256 of the approved value. Never synced; holds no values.
CREATE TABLE local_approvals (item_id      BLOB    NOT NULL,
                              field        TEXT    NOT NULL,
                              value_sha256 BLOB    NOT NULL,
                              approved_at  INTEGER NOT NULL,
                              PRIMARY KEY (item_id, field));

CREATE INDEX items_vault_id  ON items(vault_id);
CREATE INDEX items_dirty     ON items(dirty) WHERE dirty = 1;
CREATE INDEX outbox_vault_id ON outbox(vault_id);
