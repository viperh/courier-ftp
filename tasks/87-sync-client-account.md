# T87 — Sync client: account, devices and recovery

**Phase:** H Sync · **Depends on:** T30, T80–T83 · **Crate:** new `courier-ftp-sync` (client) · **Decisions:** D3, D12, D13
**Reference:** sverb `crates/sverb-sync/src/{http,tokens,keys,account/*}.rs`.

## Goal

Connect a local vault to a sync server: register, log in on more devices,
change the password, recover, and manage devices.

## Scope

1. **HTTP client**: `reqwest` with rustls, 30 s timeout, `Courier-Proto` header;
   `http://` only allowed for loopback addresses. No default server URL — the user
   always enters their own.
2. **One password, two derivations** (D3): the master password is also the account
   password.
   - Locally: Argon2id(local salt) → KEK → LMK (T30, unchanged).
   - Server: OPAQUE → `export_key` → `AKEK = HKDF(export_key, "courier-ftp/akek/v1")`
     → opens the account key bundle (X25519 + Ed25519).
   - Registration uses the **current** master password (verified by unwrapping the LMK).
     Logging in with a different password than the local one shows a warning, then
     re-wraps the LMK under the account password.
3. **Register** (`register.rs`): OPAQUE registration, generate account keys, seal the
   private bundle and the recovery bundle, upload the personal vault with a self-grant
   (the local personal vault's id is reused), device info. After success, queue every
   local item with `base_revision = 0`. Show the **recovery key** (24 words) and make
   the user re-type 3 random words before finishing.
4. **Login on another device** (`login.rs`): OPAQUE login, open the bundle and grants,
   then a **dry-run preview** if the device already has local data: duplicate sites
   are detected (same host+port+user+protocol) and the user picks *keep both* /
   *keep local* / *keep account*. Commit everything in one SQLite transaction. Local
   items moved into the account vault get new ids with references remapped
   (`merge_local.rs`).
5. **Tokens** (`tokens.rs`): stored encrypted with the LMK in `sync_state.tokens_enc`;
   refresh 60 s before expiry and after a 401; the new pair is persisted **before**
   use; single-flight mutex so only one refresh runs; rejected refresh → `NeedsLogin`
   (UI asks for the master password again).
6. **Password change**: reauth via OPAQUE (purpose `Reauth`), upload new record +
   re-sealed bundle, server revokes other devices, re-wrap LMK locally. Requires the
   server to be online; offline → clear error.
7. **Recovery**: request a recovery code (email or admin), enter code + 24 words + new
   master password → new OPAQUE record and bundle; all other devices are logged out.
8. **Devices**: list (name, platform, last seen, "this device"), revoke. Revoking this
   device = local logout (sync state wiped, local data kept).
9. **Logout / disable sync**: remove tokens and sync state; local vault stays usable.
10. **Build without sync**: cargo feature `sync` on the binary (default on);
    `--no-default-features` builds a client with no network sync code at all.

## Acceptance criteria

- [ ] Register, log in from a second device (second data dir), see the same sites.
- [ ] Duplicate preview and the three choices work.
- [ ] Password change on device A logs out device B, which can log in with the new password.
- [ ] Recovery restores access with the 24 words.
- [ ] Token refresh race (two concurrent requests on expiry) results in one refresh.
- [ ] Client builds and runs with `--no-default-features`.

## Tests

- Integration tests against an in-process server (T84/T85 in-memory store).
