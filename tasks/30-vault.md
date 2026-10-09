# T30 — Vault (local encrypted store and unlock)

**Phase:** D Vault & sites · **Depends on:** T80 (crypto), T81 (item model), T82 (local store) · **Crate:** `courier-ftp-core` (`vault` module) · **Decisions:** D3, D4, D13 · **FEATURES.md:** §2 (password storage, master password)
**Reference:** sverb `crates/sverb-tui/src/services/vault/engine.rs`, `crates/sverb-core/src/vault/{mod,unlock,lock,password}.rs`, `crates/sverb-core/src/secret.rs`, `crates/sverb-core/src/hardening/` — copy and adapt (D13).

## Goal

Everything sensitive (sites **with their passwords**, bookmarks, key passphrases,
trusted host keys and certificates, proxy credentials, history, the persisted
queue) lives in an encrypted local vault. The vault is unlocked with the
**master password at every TUI start** (D3 — no OS keyring). The design is the
same one sverb uses, so the vault can sync between devices (phase H) without a
format change.

## Design (from sverb)

### Storage

One SQLite database, `<data dir>/courier-ftp.db` (schema and access layer in T82).
There is no separate vault file. Each record ("item") is encrypted on its own,
which is what makes per-item sync and merging possible.

### Key hierarchy

```
master password ──Argon2id(local salt, params)──▶ KEK ──wrap(Lmk)──▶ LMK (local master key, random 256-bit)
LMK ──wrap(VaultKey(vault_id))──▶ VK (one per vault: personal vault + each team vault)
LMK ──wrap(SyncTokens)──▶ sync tokens (T88)
LMK ──wrap(Device)──▶ device-local encrypted data (queue, recent history)
VK  ──HKDF(salt = item_id, info = "courier-ftp/item/v1")──▶ per-item key
```

- **KDF**: Argon2id, default `m = 256 MiB, t = 3, p = 1`, 16-byte random salt.
  Bounds checked when loading (`m ≥ 19 MiB`, `m ≤ 4 GiB`, `t ≤ 64`, `p ≤ 16`) so a
  tampered DB can't make unlock hang or crash. Stored as a CBOR map
  `{alg, m_kib, t, p, salt}` in `meta.kdf`, so the cost can be raised later
  (re-wrap on next unlock). Tests use a cheap `Argon2Cost::TEST`.
- **Cipher**: XChaCha20-Poly1305, random 24-byte nonces.
- **Key wrap** format `nonce(24) || ciphertext || tag(16)`, with AAD binding the
  purpose (and vault id): `"courier-ftp-wrap-v1" || len-prefixed purpose [|| vault_id]`.
- **Wrong password** is detected by the AEAD failing to unwrap the LMK. No password
  verifier/hash is stored.
- **Item envelopes** are defined in T80 and are identical locally and on the sync server.

### Meta keys (`meta` table)

`kdf`, `lmk_wrapped_pw`, `unlock_failures`, `unlock_next_allowed_at`, `device_id`
(UUIDv7), `db_id`, `hlc_last`, plus sync keys added by T87.

## Scope

1. **`VaultEngine`** (core, async API, Argon2 and SQLite in `spawn_blocking`):
   - `status() -> VaultStatus { Uninitialised, Locked, Unlocked }`.
   - `initialize(password)`: check strength (below), generate LMK, salt, KEK,
     the personal vault and its VK, `device_id`, `db_id`, initial HLC; write
     everything in **one** transaction.
   - `unlock(password)`: honour backoff (below), derive KEK, unwrap LMK, unwrap every
     VK, decrypt all items, run item migrations (T81), build the in-memory index.
   - `lock()`: zeroize all keys and decrypted data, keep only ciphertext.
   - `change_password(old, new)`: re-wrap the LMK under a new KEK (and new salt).
     With sync enabled, this goes through the server flow in T87 instead.
   - Item CRUD used by T31/T33/T21/T12: `get`, `list(kind)`, `put` (stamps changed
     fields with the HLC and marks the item dirty for sync, T81/T82), `delete` (tombstone).
   - The engine **never contacts the sync server** to unlock.
2. **Master password at every start** (D3):
   - No OS keyring support at all (remove `keyring` from T01's dependency list).
   - The TUI blocks on the unlock screen (T60) before showing panes. "Continue without
     vault" is possible: quickconnect only, nothing saved.
3. **Password strength**: `zxcvbn` score ≥ 3 required on create/change, with the
   feedback text shown in the UI.
4. **Brute-force backoff** (sverb `vault/unlock.rs`): failures 1–4 no delay; from the
   5th: 1, 2, 4, 8, 16 s, capped at 30 s. Counter and next-allowed time persisted in
   `meta` and updated in one write transaction (so several processes count every
   failure). Argon2 is not run while backoff is active. Reset on success.
5. **Auto-lock** (sverb `vault/lock.rs`): `vault.auto_lock_minutes`, default **15**, 0 = off.
   Reset on every key press. Also lock on demand (`Ctrl-x Ctrl-l`, T51) and on system
   suspend/resume detection (large wall-clock jump between ticks). On lock: keys
   zeroized, open dialogs discarded, the screen shows the unlock overlay. Connections
   and running transfers keep going (setting `vault.lock_disconnects` to close them);
   transfers that need a secret wait until unlock.
6. **Memory hygiene** (sverb `secret.rs`, `hardening/`):
   - `Secret<T>`/`SecretString` wrapper: `Debug`/`Display` print `[REDACTED]`, no
     `Clone`/`Serialize`, explicit `expose()`, constant-time `ct_eq`.
   - Keys in a `Key32` type that zeroizes on drop; a live-key counter in debug builds
     so tests can prove `lock()` drops every key.
   - `harden_process()` at startup: Linux `prctl(PR_SET_DUMPABLE, 0)` and
     `RLIMIT_CORE = 0`; Windows `SetErrorMode` + `WerSetFlags(NOHEAP)`. Optional
     `mlock`/`VirtualLock` for key pages (best effort, failures logged).
   - The only `unsafe` code allowed lives in the hardening module, documented.
7. **Multiple processes**: no lock file. SQLite WAL + `busy_timeout` + `IMMEDIATE`
   transactions (T82). A busy DB error tells the user another courier-ftp may be writing.
8. **Saving connections with passwords** (requested feature): sites store the
   password, account, key passphrase and proxy passwords **inside** the encrypted site
   item (plaintext only inside the envelope). Setting `vault.store_passwords`
   (default **true**) — when off, password fields are never written.
9. **Recovery**: local-only users have **no recovery** if they forget the master
   password. The first-run screen must say so plainly. With sync, the recovery key
   (T87) covers this.
10. **Backup file** `.cftp-backup` (used by T73): JSON header with Argon2id params +
    XChaCha20-Poly1305 over `zstd(cbor(items))`, AAD `"courier-ftp-backup-v1"`,
    decompressed size capped at 1 GiB.

## Acceptance criteria

- [ ] Initialize → lock → unlock returns identical items.
- [ ] Wrong password fails without modifying any data except the failure counter.
- [ ] Backoff timings match the table (paused-time tests), shared across two engine instances on the same DB.
- [ ] Auto-lock fires after the timeout and is reset by input.
- [ ] Live-key counter is zero after `lock()`.
- [ ] Tampered `kdf` params outside bounds are rejected before running Argon2.
- [ ] Weak passwords rejected with zxcvbn feedback.
- [ ] No secret appears in `Debug` output or logs (canary-secret test, see T71).

## Tests

- Unit tests with `Argon2Cost::TEST`.
- Tamper tests on `meta.kdf`, `lmk_wrapped_pw` and item envelopes.
- Port sverb's relevant vault tests and adapt them.
