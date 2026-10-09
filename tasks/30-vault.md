# T30 — Vault

**Phase:** D Vault & sites · **Depends on:** T02 · **Crate:** `courier-ftp-core` (`vault` module) · **Decisions:** D3, D4 · **FEATURES.md:** §2 (password storage, master password)

## Goal

An encrypted store for everything sensitive: sites, passwords, key passphrases,
bookmarks, quickconnect history, trusted host keys and certificates, proxy
credentials and the persisted queue. Unlocked via the OS keyring when possible,
otherwise with a master password.

## Design

### Key hierarchy

```
master password ──Argon2id(salt, params)──▶ KEK ─┐
                                                  ├─ wraps ─▶ DEK (random 256-bit)
OS keyring entry "courier-ftp/vault" ─────────────┘           │
  (stores DEK directly, base64)                               ▼
                                         XChaCha20-Poly1305(DEK) ─▶ payload
```

- **DEK** (data encryption key): random 32 bytes, created once. Encrypts the payload.
- **KEK** from master password: Argon2id. Default params m = 64 MiB, t = 3, p = 1 (stored in the header so they can be raised later). The DEK is stored wrapped with the KEK.
- **Keyring**: if the user enables it (default when a keyring is available), the DEK itself is stored in the OS keyring via the `keyring` crate (macOS Keychain, Windows Credential Manager, Secret Service on Linux). Unlock = read DEK from keyring, no prompt.
- At least one unlock path must exist. Possible setups: master password only; keyring only; both (keyring for convenience, master password as recovery / for other machines).
- **Keyring-only risk**: if the keyring entry is lost, the vault is unrecoverable. The setup UI (T60) must say this and recommend also setting a master password.

### File format (`<data dir>/vault.cfv`)

```
magic        8 bytes  "CFTPVLT\0"
version      u16 LE   1
kdf          u8       1 = Argon2id
argon m_kib  u32 LE
argon t      u32 LE
argon p      u32 LE
salt         16 bytes
has_pw_wrap  u8
wrap_nonce   24 bytes (if has_pw_wrap)
wrapped_dek  48 bytes (32 + 16 tag) (if has_pw_wrap)
payload_nonce 24 bytes
payload_len  u64 LE
payload      ciphertext + 16-byte tag
```

- Header bytes (everything before `payload`) are passed as **AAD** to the payload encryption, so tampering with params/salt is detected.
- New random nonce on every write.
- Payload plaintext = `serde_json` (or `postcard`, decide) of `VaultData { schema_version, sites, bookmarks, history, host_keys, certificates, secrets, settings_secrets }`. Schema migrations keyed on `schema_version`.
- Queue persistence (T40) uses a **separate file** `queue.cfq` encrypted with the same DEK (same container format, different magic) so frequent queue writes don't rewrite the whole vault.

### Secrets inside the vault

- `secrets: HashMap<SecretId, SecretString>`. Sites and proxy settings reference secrets by `SecretId` (uuid) — so a site can be exported without its password (T32).

## Scope

1. `Vault::create(path, unlock: UnlockSetup)`, `Vault::open(path) -> LockedVault`, `LockedVault::unlock_with_password(pw)`, `LockedVault::unlock_with_keyring()`, `Vault::lock()` (zeroize DEK and plaintext), `Vault::save()`.
2. `change_master_password(old, new)`, `remove_master_password()` (only if keyring enabled), `enable_keyring()`, `disable_keyring()` (only if master password set), `rekey()` (new DEK, re-encrypt everything).
3. **Atomic writes**: write `vault.cfv.tmp`, `fsync`, rename over the original; keep `vault.cfv.bak` of the previous version. On open, if the main file fails to decrypt but `.bak` works, offer recovery (via an error variant the UI can act on).
4. **File permissions**: `0600` on Unix; on Windows rely on the user profile ACL.
5. **Memory hygiene**: DEK in `Zeroizing<[u8; 32]>`; passwords `SecretString`; decrypted payload buffer zeroized after deserialising.
6. **Auto-lock** (setting `vault.auto_lock_minutes`, default 0 = never): locks after inactivity; open connections stay open, but saving a site requires unlock again.
7. **Wrong password** handling: constant-time tag check (AEAD), error `Vault(WrongPassword)`; no lockout but Argon2 cost makes brute force slow.
8. **Headless Linux without Secret Service**: `keyring` returns an error → treat as "keyring unavailable", fall back to master password silently (log at info).
9. **Concurrency**: two courier-ftp instances — use an advisory lock file (`fs2`/`fd-lock`) on `vault.cfv.lock`; second instance opens read-only and warns that changes won't be saved.

## Acceptance criteria

- [ ] Create → save → reopen → unlock with password returns identical `VaultData`.
- [ ] Unlock via keyring works on macOS, Windows and Linux with Secret Service (manual checklist for each OS recorded here).
- [ ] Tampering with any header byte or payload byte fails decryption.
- [ ] Wrong password → `WrongPassword`, file unchanged.
- [ ] Changing password does not change the DEK (fast; no payload re-encryption needed beyond the header rewrite).
- [ ] Crash between temp write and rename leaves a usable vault (simulate).
- [ ] No secret appears in `Debug` output or logs.

## Tests

- Unit tests with low Argon2 params (`m = 8 KiB`) behind a test-only constructor so tests stay fast.
- Tamper tests flipping each header field.
- Mock keyring backend (`keyring` has a mock credential builder) for keyring paths.
