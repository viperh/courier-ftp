# T87 — Sync client: account, devices and recovery

**Phase:** H Sync · **Milestone:** M7 · **Depends on:** T30, T80, T81, T82, T83, T84, T85 · **Crate(s):** new `courier-ftp-sync` (client library), `courier-ftp-core` (`vault` additions), `courier-ftp` (cargo feature `sync`) · **Decisions:** D3, D12, D13 · **FEATURES.md:** §2 (master password; saved sites on every device)
**Reference:** sverb `crates/sverb-sync/src/{http,tokens,error,info}.rs`, `src/account/{mod,local,register,login,merge_local,password,recovery,devices,logout,wizard}.rs`, `tests/account.rs`; SPEC §11.2, §11.2.1, §12.6.

## Goal

Connect a local vault to a self-hosted courier-ftp sync server with the **same master
password**: create an account from an existing local vault, log in on more devices
(merging what is already there through a duplicate preview), change the password online,
recover a forgotten password with the 24-word recovery key, list and revoke devices,
enable TOTP, log out and delete the account. Everything here is UI-agnostic library code
that T90 drives; a build without the `sync` feature contains none of it.

## Context

- **Before:** T30 `VaultEngine` (unlock with the master password, LMK, personal vault and
  its VK, `meta`, `put`/`delete` marking items dirty), T80 crypto (OPAQUE client, account
  bundles, recovery key/mnemonic, grants, envelopes, `wrap` with
  `WrapPurpose::SyncTokens`), T81 item model and typed views (`Site::from_body`), T82 store
  (`sync_state`, `vaults`, `items`, `outbox`, `meta`, `device_local`), T83 DTOs, T84/T85
  server (in-process for tests).
- **After:** T88 (`SyncEngine`) reuses `ApiClient`, `TokenManager`, `SyncError` and the
  local account state; T89 adds team vaults (grant verification, trust) on top of
  `LoginSession`/`ApiClient`; T90 renders the wizard state machines and screens; T60's
  "password changed on another device" dialog and "Forgot password? → sync recovery" call
  into this crate.

## Technical specification

### Types and APIs

Crate `crates/courier-ftp-sync` (deps: `courier-ftp-core`, `courier-ftp-crypto`,
`courier-ftp-proto`, `courier-ftp-store`, `reqwest` (rustls, `json`, no default features),
`rustls-platform-verifier` (D9), `tokio`, `tokio-util`, `tokio-tungstenite` (T88), `serde`,
`serde_json`, `ciborium`, `uuid`, `time`, `thiserror`, `tracing`, `zeroize`, `secrecy`,
`parking_lot`, `fastrand`, `gethostname`). Dev: `courier-ftp-server` (in-process server),
`courier-ftp-crypto` with `insecure-test-ksf`, `tokio` `test-util`, `tempfile`, `proptest`.

```rust
// src/lib.rs
pub mod http; pub mod tokens; pub mod error; pub mod local; pub mod account;
pub use error::SyncError; pub use http::ApiClient; pub use tokens::TokenManager;

// src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync is not set up: {0}")] NotConfigured(&'static str),
    #[error("invalid server URL: {0}")] InvalidUrl(String),
    #[error("server unreachable")] Offline(#[source] reqwest::Error),           // connect/timeout/DNS/TLS
    #[error("the server speaks an unsupported protocol version; update courier-ftp")] UnsupportedServer,
    #[error("{message}")] Api { status: u16, code: Option<ErrorCode>, message: String, retry_after_s: Option<u64> },
    #[error("sign in again")] NeedsLogin(NeedsLoginReason),
    #[error("wrong email or password")] LoginFailed,
    #[error("a TOTP code is required")] TotpRequired,
    #[error("invalid TOTP code")] TotpInvalid,
    #[error("too many attempts; try again in {0} s")] RateLimited(u64),
    #[error("the recovery key is not valid: {0}")] RecoveryKeyInvalid(String),
    #[error("password too weak: {0}")] WeakPassword(String),                    // zxcvbn feedback
    #[error("the master password is wrong")] WrongLocalPassword,
    #[error("malformed server response: {0}")] Protocol(String),
    #[error("crypto: {0}")] Crypto(#[from] courier_ftp_crypto::Error),
    #[error("local database: {0}")] Store(#[from] courier_ftp_store::StoreError),
    #[error("vault: {0}")] Vault(#[from] courier_ftp_core::Error),
    #[error("cancelled")] Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsLoginReason { PasswordChangedElsewhere, DeviceRevoked, SessionExpired }
impl SyncError { pub fn is_offline(&self) -> bool; /* Offline, 5xx/Internal, RateLimited */ pub fn is_status(&self, s: u16) -> bool; }

// src/http.rs
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Clone)]
pub struct ApiClient { /* base Url, reqwest::Client */ }
impl ApiClient {
    /// `https://` required; `http://` only for loopback hosts (127.0.0.0/8, ::1, "localhost").
    /// Trailing '/' stripped; path must be empty. No default server exists.
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, SyncError>;
    pub fn base_url(&self) -> &str;
    /// GET /healthz and check {"status":"ok"} + `Courier-Proto` response header.
    pub async fn probe(&self) -> Result<(), SyncError>;
    // One method per T83 endpoint, e.g.:
    pub async fn register_start(&self, req: &RegisterStartRequest) -> Result<RegisterStartResponse, SyncError>;
    pub async fn register_finish(&self, req: &RegisterFinishRequest) -> Result<SessionResponse, SyncError>;
    pub async fn login_start(&self, req: &LoginStartRequest) -> Result<LoginStartResponse, SyncError>;
    pub async fn login_finish(&self, req: &LoginFinishRequest) -> Result<LoginFinished, SyncError>; // Session | Reauth
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenPair, SyncError>;
    pub async fn logout(&self, access: &str) -> Result<(), SyncError>;
    pub async fn devices(&self, access: &str) -> Result<Vec<DeviceView>, SyncError>;
    pub async fn revoke_device(&self, access: &str, id: Uuid) -> Result<(), SyncError>;
    pub async fn totp(&self, access: &str, req: &TotpRequest) -> Result<TotpReply, SyncError>;
    pub async fn totp_disable(&self, access: &str, code: &str) -> Result<(), SyncError>;
    pub async fn password_start(&self, access: &str, req: &PasswordStartRequest) -> Result<PasswordStartResponse, SyncError>;
    pub async fn password_change(&self, access: &str, req: &PasswordChangeRequest) -> Result<KeyVersionResponse, SyncError>;
    pub async fn recovery_code(&self, email: &str) -> Result<(), SyncError>;
    pub async fn recovery_start(&self, req: &RecoveryStartRequest) -> Result<RecoveryStartResponse, SyncError>;
    pub async fn recovery_finish(&self, req: &RecoveryFinishRequest) -> Result<KeyVersionResponse, SyncError>;
    pub async fn delete_account(&self, access: &str, reauth: &str) -> Result<(), SyncError>;
    pub async fn list_vaults(&self, access: &str) -> Result<Vec<VaultView>, SyncError>;
    pub async fn pull(&self, access: &str, vault: Uuid, since: u64, limit: u32) -> Result<PullResponse, SyncError>;
    pub async fn push(&self, access: &str, vault: Uuid, req: &PushRequest) -> Result<PushResponse, SyncError>;
}

// src/tokens.rs
pub const REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// Access/refresh tokens, sealed under the LMK in `sync_state.tokens_enc`.
pub struct TokenManager { /* store, lmk, api, tokio::sync::Mutex<State> */ }
impl TokenManager {
    pub async fn load(store: Store, lmk: Key32, api: ApiClient) -> Result<Self, SyncError>;
    /// A valid access token; refreshes first when it expires within REFRESH_MARGIN.
    pub async fn access(&self) -> Result<Zeroizing<String>, SyncError>;
    /// After a 401 with `rejected`: refresh unless another caller already replaced it.
    pub async fn refresh_after_401(&self, rejected: &str) -> Result<(), SyncError>;
    pub async fn store_pair(&self, pair: &TokenPair, now: OffsetDateTime) -> Result<(), SyncError>;
}

// src/local.rs — the device side of an account
pub struct LocalAccount { pub user_id: Uuid, pub email: String, pub key_version: u32, pub is_instance_admin: bool }
pub async fn load_account(store: &Store) -> Result<Option<LocalAccount>, SyncError>;      // meta.account
pub async fn load_account_keys(store: &Store, lmk: &Key32) -> Result<Option<AccountKeys>, SyncError>; // meta.account_keys_enc
pub fn default_device_name() -> String;    // hostname (≤ 128 chars), else "courier-ftp"
pub fn platform() -> &'static str;         // std::env::consts::OS

// src/account/*.rs
pub const PASSWORD_ADOPT_WARNING: &str = "Your local master password will be changed to your account password.";
pub const RECOVERY_WARNING: &str = "Write these 24 words down and keep them offline. They are shown only once. \
    Without them and without a signed-in device, a forgotten password means your synced data is lost.";
pub const PERSONAL_VAULT_NAME: &str = "Personal";

pub enum RegistrationToken { None, Invite(SecretString), Setup(SecretString) }
/// Step 1: probe the server, verify the CURRENT master password locally, generate the
/// account keypairs and the recovery key. Nothing is sent to the server yet.
pub async fn prepare_registration(vault: &VaultEngine, server_url: &str, email: &str,
    password: &SecretString, token: RegistrationToken) -> Result<PreparedRegistration, SyncError>;
pub struct PreparedRegistration { /* keys, recovery key (zeroized), url, email, token */ }
impl PreparedRegistration { pub fn recovery_words(&self) -> Vec<&'static str>; }   // 24
/// Step 3 (after RecoveryConfirm succeeded): OPAQUE registration + upload + local commit.
pub async fn finish_registration(vault: &VaultEngine, prepared: PreparedRegistration,
    password: &SecretString, device_name: &str) -> Result<Registered, SyncError>;

pub struct LoginRequest { pub server_url: String, pub email: String, pub password: SecretString,
                          pub totp: Option<SecretString>, pub device_name: String }
/// OPAQUE login, open account keys and the personal grant, build the duplicate preview.
/// Changes nothing locally.
pub async fn start_login(vault: &VaultEngine, req: LoginRequest) -> Result<LoginSession, SyncError>;
pub struct LoginSession { /* tokens, keys, vault keys, downloaded items, preview */ }
impl LoginSession {
    pub fn password_differs(&self) -> bool;        // entered password does not unwrap the local LMK
    pub fn password_changed_elsewhere(&self) -> bool; // server key_version > meta.account.key_version
    pub fn will_import(&self) -> bool;
    pub fn preview(&self) -> &ImportPreview;
    pub fn preview_mut(&mut self) -> &mut ImportPreview;
    /// Everything in ONE SQLite transaction (see Behaviour), then `vault.reload()`.
    pub async fn commit(self, vault: &VaultEngine) -> Result<LoggedIn, SyncError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicateChoice { #[default] KeepBoth, KeepLocal, KeepAccount }
pub struct DuplicateRow { pub local: ItemId, pub account: ItemId, pub kind: ItemKind, pub label: String, pub key: String, pub choice: DuplicateChoice }
pub struct ImportPreview { pub rows: Vec<DuplicateRow>, pub local_items: usize, pub account_items: usize }
impl ImportPreview { pub fn set(&mut self, local: ItemId, c: DuplicateChoice) -> bool; pub fn set_all(&mut self, c: DuplicateChoice); pub fn imported_count(&self) -> usize; }
pub fn dedupe_key(body: &ItemBody) -> Option<String>;
pub fn remap_body(body: &mut ItemBody, map: &HashMap<ItemId, ItemId>) -> bool;

pub async fn change_password(vault: &VaultEngine, old: &SecretString, new: &SecretString) -> Result<u32 /*new key_version*/, SyncError>;
pub async fn request_recovery_code(server_url: &str, email: &str) -> Result<(), SyncError>;
pub struct RecoveryRequest { pub server_url: String, pub email: String, pub code: SecretString,
                             pub words: SecretString, pub new_password: SecretString }
pub async fn recover_account(req: RecoveryRequest) -> Result<Recovered, SyncError>;
pub async fn list_devices(vault: &VaultEngine) -> Result<Vec<DeviceView>, SyncError>;
pub async fn revoke_device(vault: &VaultEngine, id: Uuid) -> Result<Revoked /* Other | ThisDevice(LogoutReport) */, SyncError>;
pub async fn logout(vault: &VaultEngine) -> Result<LogoutReport, SyncError>;  // keep local data
pub async fn delete_account(vault: &VaultEngine, password: &SecretString) -> Result<LogoutReport, SyncError>;
pub async fn totp_start(vault: &VaultEngine) -> Result<TotpSetupResponse, SyncError>;
pub async fn totp_confirm(vault: &VaultEngine, code: &SecretString) -> Result<(), SyncError>;
pub async fn totp_disable(vault: &VaultEngine, code: &SecretString) -> Result<(), SyncError>;

// src/account/wizard.rs — pure reducers driven by the UI (T90)
pub const CONFIRM_WORDS: usize = 3;
pub struct RecoveryConfirm { /* 3 distinct random positions 1..=24, ascending */ }
impl RecoveryConfirm {
    pub fn with_random_positions(words: &[&str]) -> Self;
    pub fn word_numbers(&self) -> [usize; CONFIRM_WORDS];
    pub fn set_input(&mut self, slot: usize, text: &str);
    pub fn submit(&mut self) -> bool;               // trimmed, case-insensitive compare
    pub fn error(&self) -> Option<&str>;            // "Word 7 does not match"
}
pub enum RegisterStep { Server, Credentials, Token, ShowWords, ConfirmWords, Working, Done, Failed }
pub enum LoginStep { Server, Credentials, Totp, AdoptPassword, Preview, Working, Done, Failed }
pub struct RegisterWizard; pub struct LoginWizard; pub struct RecoveryWizard;
// each: fn handle(&mut self, input: WizardInput) -> Option<WizardEffect>; fn step(&self)
```

Additions to `courier-ftp-core::vault` (T30's `VaultEngine`; added by this task, not
behind a feature, no network code):

```rust
impl VaultEngine {
    /// Store handle, a clone of the LMK, the shared HLC, this DB's device id and the
    /// personal vault id. Error::Vault(Locked) when locked.
    pub fn sync_handles(&self) -> Result<SyncHandles, Error>;
    /// Runs Argon2 with meta.kdf and tries to unwrap the LMK; no state change, does not
    /// touch the backoff counters.
    pub async fn verify_password(&self, pw: &SecretString) -> Result<bool, Error>;
    /// New salt + KEK for `pw`, returns the meta rows (`kdf`, `lmk_wrapped_pw`) to write
    /// inside the caller's transaction. Keyring wrap unchanged.
    pub async fn lmk_rewrap_rows(&self, pw: &SecretString) -> Result<Vec<(String, Vec<u8>)>, Error>;
    /// Re-reads vaults and items after an external transaction (login commit, logout).
    pub async fn reload(&self) -> Result<(), Error>;
}
```

### Behaviour

#### Local account state (in `courier-ftp.db`)

| Where | Content | Protection |
|---|---|---|
| `sync_state.server_url` | base URL | plaintext (not secret) |
| `sync_state.device_id` | server-assigned device UUID | plaintext |
| `sync_state.tokens_enc` | CBOR `{access, refresh, access_expires_ms, refresh_expires_ms}` | `wrap(LMK, WrapPurpose::SyncTokens)` (T80) |
| `meta.account` | JSON `{"user_id","email","key_version","is_instance_admin"}` | plaintext (no secret; email stays local) |
| `meta.account_keys_enc` | CBOR `{x25519_sk, ed25519_sk}` | AEAD under `HKDF(LMK, info = "courier-ftp/local-account-keys/v1")`, AAD `"courier-ftp/local-account-keys/v1" || user_id` |
| `meta.vault_name_enc/<vault uuid>` | sealed vault name (T89 team vaults) | under the VK |

Vault names (`name_enc`) are sealed with the T80 item envelope format using
`item_id = vault_id` and the vault's key version; plaintext CBOR text string.

#### HTTP client

- `reqwest` + rustls with `rustls-platform-verifier` (OS trust store, D9); no OpenSSL.
  Timeout 30 s per request, connect timeout 10 s, HTTP/1.1 and HTTP/2, gzip response
  decompression. Headers: `Courier-Proto: 1`, `User-Agent: courier-ftp/<version>`,
  `x-request-id: <uuidv7>` (also logged at debug, so a user can quote it to an operator).
- URL rules: scheme `https`, or `http` with host `localhost`, `127.0.0.0/8` or `::1`; no
  path, query, fragment or userinfo. No default server URL anywhere.
- Error mapping: transport error → `Offline`; `ErrorEnvelope` → `Api{…}` (`429` →
  `RateLimited(retry_after)`); 400 with "unsupported protocol version" or a missing
  `Courier-Proto` header on `probe` → `UnsupportedServer`; non-JSON body →
  `Protocol("…")`.
- Calls with a token go through `TokenManager::access()`; a 401 triggers exactly one
  `refresh_after_401` and one retry.

#### Token lifecycle (client)

1. Tokens arrive in `SessionResponse` (register/login) and are written to
   `sync_state.tokens_enc` **in the same transaction** as the rest of the login/registration
   commit.
2. `access()`: if `access_expires_ms - now < 60 s`, refresh first.
3. Refresh is single-flight: the state mutex is held across the HTTP call; concurrent
   callers wait and then use the new pair. `refresh_after_401(rejected)` is a no-op when the
   stored access token already differs from `rejected`.
4. The new pair is **persisted before it is used** (refresh tokens are single-use with
   strict reuse detection; a crash after the response but before the write would otherwise
   log the device out).
5. A rejected refresh (401) → `NeedsLogin(reason)`; reason is
   `PasswordChangedElsewhere` if the engine saw `account_changed` with a higher key version
   (T88), `DeviceRevoked` if the 401 message says the device was revoked, else
   `SessionExpired`. Sync pauses until the user signs in again (T90 / T60 §6).

#### Register (local-only → new account, §11.2.1)

1. `prepare_registration`: `ApiClient::new` + `probe`; `normalize_email`;
   `vault.verify_password(password)` must be true (else `WrongLocalPassword`); generate
   account keys (X25519 + Ed25519) and the recovery key (T80). Holds everything in memory
   (zeroized on drop).
2. UI shows the 24 words once with `RECOVERY_WARNING`, then `RecoveryConfirm` with 3 random
   distinct positions; `finish_registration` is not callable before `submit()` returned true
   (enforced by `RegisterWizard`).
3. `finish_registration`:
   a. `register_start` (OPAQUE `RegistrationRequest`, email, token) → `user_id`, response;
   b. OPAQUE finish → `RegistrationUpload` + `export_key` → `AKEK = derive_akek(export_key)`;
   c. `private_bundle = seal_private_bundle(AKEK, user_id, version 1)`,
      `recovery_bundle = seal_recovery_bundle(recovery_key, user_id)`;
   d. personal vault: **same** vault id and VK as the local one; `self_grant(VK, vault_id,
      user_id, key_version 1, ed25519_sk)`; `name_enc` = sealed `"Personal"`;
   e. `register_finish` → `SessionResponse`;
   f. one SQLite transaction: `sync_state` (url, device id, tokens), `meta.account`,
      `meta.account_keys_enc`, every live item and tombstone of the personal vault set to
      `revision = 0`, `dirty = 1` with an outbox row `base_revision = 0` (T82 already queues
      every local write; this makes it complete), `vaults.sync_cursor = 0`,
      `vaults.key_version = 1`.
   g. The engine (T88) starts and uploads everything.
4. Crash after (e) but before (f): the account exists without a signed-in device. Logging in
   later finds the local personal vault id equals the account's personal vault id and only
   signs in (no import, no duplicates).

#### Login (another device, or re-login)

`start_login`:
1. `probe`; OPAQUE login start/finish with `purpose: login`, `device.id = sync_state.device_id`
   when the stored server URL and account match (resume), else name/platform. `TotpRequired`
   → the wizard asks for the code and the whole OPAQUE exchange is repeated with it (login
   states are single-use on the server).
2. `export_key` → AKEK → `open_private_bundle` (version from `account_keys.version`).
3. `list_vaults`; the personal vault's grant must be a self-grant (`wrapped_by == user_id`)
   whose signature verifies with the account's own Ed25519 key; open it (T80
   `verify_and_open_grant`). Team vault grants are handled by T89 (until T89 lands they are
   skipped with a debug log).
4. `password_differs = !vault.verify_password(entered)` (only if a local vault exists and is
   unlocked); `password_changed_elsewhere = server key_version > meta.account.key_version`.
5. Case selection:
   - **(A) same personal vault id** (re-login after logout/password change/crashed
     registration): no import.
   - **(B) local personal vault has no live items** (fresh install that just created an empty
     vault): the empty local vault is replaced by the account's.
   - **(C) local vault has items and a different id**: pull every item of the account's
     personal vault from revision 0 (pages of 500) into memory, decrypt, and build the
     `ImportPreview`.
6. Duplicate detection (`dedupe_key`, tombstones never match):

| Kind | Key |
|---|---|
| `site` | `site <protocol>://<user>@<host lower>:<effective port>` (from `Site::from_body`) |
| `site-folder` | `folder <full path of names, '/'-joined, case-sensitive>` |
| `bookmark` | `bookmark <name> <local_dir> <remote_dir> <site key or "global">` |
| `ssh-key` | `ssh-key <algorithm> <base64 public key>` |
| `known-host` | `known-host <host lower>:<port> <key type> <sha256 fingerprint>` |
| `trusted-cert` | `trusted-cert <host lower>:<port> <sha256 fingerprint>` |
| `proxy-credential` | `proxy <type> <host lower>:<port> <user>` |
| `credential-override`, `history-entry` | none (always imported) |

   Identical `known-host` / `trusted-cert` rows default to `KeepAccount` (same trust, no
   duplicate); all other rows default to `KeepBoth`.

`LoginSession::commit` — **one** SQLite `IMMEDIATE` transaction:
1. if `password_differs`: write `lmk_rewrap_rows(entered)` (UI showed
   `PASSWORD_ADOPT_WARNING` first, or "Your password was changed on another device" when
   `password_changed_elsewhere`);
2. insert the account's vaults (VK wrapped under the LMK, `key_version`, `sync_cursor` =
   the downloaded snapshot's `head_revision` in case C, 0 otherwise);
3. case C: insert the downloaded items (clean, their revisions); import local items:
   every live local item gets a **new** UUIDv7 id in the account vault, all references
   rewritten through the id map (`remap_body`: any 16-byte id value in any field that names
   a local item); `KeepAccount` drops the local item and maps its id to the account item;
   `KeepLocal` writes the local field values over the account item with fresh HLC stamps (so
   they win the merge) and maps the id; imported items are dirty with `base_revision = 0`;
   `device_local` rows are moved to the new ids; the old local vault and its items/outbox
   rows are deleted;
4. case B: delete the empty local vault, insert account items as in C without import;
5. write `sync_state`, `meta.account`, `meta.account_keys_enc`, tokens;
6. commit, then `vault.reload()`.
A crash before commit leaves the local DB exactly as before (test hook `crash_after_items`).

#### Password change (online)

1. Sync must be configured; `probe` must succeed — offline → `Offline` before anything
   changes ("Changing the password needs the sync server; you are offline").
2. `new` must reach zxcvbn ≥ 3 (`WeakPassword(feedback)`); `old` must unlock the LMK
   (`WrongLocalPassword`).
3. OPAQUE login with `old`, `purpose: reauth` → `reauth_token`.
4. `password_start` with a `RegistrationRequest` for `new`; finish → upload + new
   export_key → new AKEK; account keys from `meta.account_keys_enc`; `private_bundle_enc` =
   seal(new AKEK, user_id, `key_version + 1`).
5. `password_change` → `KeyVersionResponse`.
6. Local transaction: `lmk_rewrap_rows(new)`, `meta.account.key_version = v + 1`.
7. A crash between 5 and 6: the device still unlocks with the **old** password; its tokens
   remain valid (only other devices were logged out); on the next `NeedsLogin` or explicit
   re-login, the new password does not unwrap the LMK → `password_differs` path re-wraps it.

#### Password changed on another device

The local unlock keeps working with the old password (LMK wrap unchanged). Sync stops with
`NeedsLogin(PasswordChangedElsewhere)` (tokens deleted by the server; `account_changed`
seen over WS). The user signs in with the new password (case A, `password_differs = true`)
→ commit re-wraps the LMK; from then on only the new password unlocks.

#### Recovery

1. `request_recovery_code(url, email)` → 202 (code by mail, or from the operator).
2. `recover_account`: `recovery_key_from_mnemonic(words)` (24 words, checksum; error →
   `RecoveryKeyInvalid`); `new_password` zxcvbn ≥ 3; OPAQUE registration start for the new
   password → `recovery_start(email, code, request)` → `recovery_bundle_enc`,
   `user_id`, `version`; `open_recovery_bundle(recovery_key, user_id)` → account keys;
   OPAQUE finish → new AKEK; seal private bundle at `version + 1`; sign
   `recovery_proof_message(user_id, version + 1, upload, bundle)` with the Ed25519 key;
   `recovery_finish`. All devices are now logged out.
3. This device then logs in with the new password: if its local vault is unlocked (old
   password or keyring), login case A re-wraps the LMK. If it cannot unlock (no keyring),
   the UI offers "Start fresh from the account": the old DB is renamed to
   `courier-ftp.db.bak-<UTC yyyymmddThhmmss>` (never deleted, T60), a new vault is
   initialised with the new password and login case B runs.

#### Devices, logout, deletion

- `list_devices`: `GET /v1/devices`; the current one flagged by the server (`current`).
- `revoke_device(id)`: `DELETE /v1/devices/{id}`; if `id == sync_state.device_id` the local
  part of `logout` runs and `Revoked::ThisDevice` is returned.
- `logout` (disable sync, keep local data): `POST /auth/logout` with a 10 s timeout (offline:
  continue, `LogoutReport.server_revoked = false`); one transaction: delete team vaults with
  their items, outbox and `meta.vault_name_enc/*` rows (they belong to the org); personal
  vault items → `revision = 0`, dirty, outbox `base_revision = 0`, `sync_cursor = 0`; delete
  `sync_state` row, `meta.account`, `meta.account_keys_enc`, `meta.rotation:*`. Pins and
  local approvals stay. The master password is unchanged.
- `delete_account(password)`: reauth login → `DELETE /v1/account` → local `logout` part.

#### TOTP

`totp_start` → `TotpSetupResponse` (URI + base32 secret, shown once by T90);
`totp_confirm(code)` → enabled; `totp_disable(code)`. Secrets are `SecretString` in memory
and never stored locally.

#### Build without sync

The binary crate `courier-ftp` has `[features] default = ["sync"]`, `sync =
["dep:courier-ftp-sync"]`. With `--no-default-features` the dependency graph contains no
`courier-ftp-sync`, `reqwest`, `tokio-tungstenite` or `courier-ftp-proto`; every sync UI
entry is compiled out (T90).

### Data formats and configuration

- Token CBOR (inside `tokens_enc`): map with text keys `"access"`, `"refresh"` (text),
  `"access_expires_ms"`, `"refresh_expires_ms"` (u64 Unix ms, device clock).
- `meta.account` JSON example: `{"user_id":"0192…","email":"a@example.com","key_version":2,"is_instance_admin":false}`.
- Settings: none added (the server URL lives in the DB, not in the config file, so it can't
  be changed by a dotfile without the vault).

### Errors

User-facing texts (T90 shows them; tests assert the variant):

| Variant | Shown as |
|---|---|
| `Offline` | "Can't reach the sync server. Check the URL and your connection." |
| `UnsupportedServer` | "This server needs a newer courier-ftp (or is not a courier-ftp server)." |
| `LoginFailed` | "Wrong email or password." |
| `TotpRequired` / `TotpInvalid` | asks for the code / "That code is not valid." |
| `RateLimited(s)` | "Too many attempts. Try again in s s." |
| `WrongLocalPassword` | "That is not this vault's master password." |
| `WeakPassword(f)` | zxcvbn feedback |
| `RecoveryKeyInvalid` | "The recovery words are not valid (check spelling and order)." |
| `Api{403 "registration requires an invite"}` | "This server needs an invite or setup token." |
| `Api{409 "email already registered"}` | "An account with this email exists. Log in instead." |
| `NeedsLogin(_)` | sign-in dialog (T90/T60) |

### Security and logging

- Passwords, recovery words, codes, TOTP secrets and tokens are `SecretString` /
  `Zeroizing`; account private keys live in `AccountKeys` (zeroize on drop); never logged,
  never in `Debug`.
- Logs at info+: only ids (`user_id`, `device_id`, `vault_id`) and outcomes; never the
  server URL host, the email or item labels (T91 §4: no hostnames at info+). The server URL
  host may appear at debug.
- The account password never leaves the device; OPAQUE only.
- Server responses are untrusted: sizes and formats are checked by the T80 parsers (bundle,
  grant) before use; the personal grant must be a self-grant verified with the account's own
  key.
- `http://` refused for non-loopback servers (no downgrade).

## Implementation steps

1. Crate skeleton, `error.rs`, `http.rs` (URL rules, headers, error mapping) with tests
   against an in-process server.
2. `tokens.rs` with single-flight refresh and persistence; `local.rs`.
3. `VaultEngine` additions in core (`sync_handles`, `verify_password`, `lmk_rewrap_rows`,
   `reload`).
4. `account/register.rs` + `wizard.rs` (`RecoveryConfirm`, `RegisterWizard`).
5. `account/login.rs` cases A/B/C + `merge_local.rs` (preview, dedupe keys, remap).
6. `account/password.rs`, `account/recovery.rs` (+ `RecoveryWizard`).
7. `account/devices.rs`, `logout.rs`, `delete`, `totp`.
8. Binary feature `sync` wiring; CI clippy `--no-default-features` stays green.

## Acceptance criteria

- [ ] AC1 Register from a local vault with 20 sites, then log in from a second data dir: the
  second device has the same 20 sites (after the T88 engine syncs; in this task verified by
  pulling directly), with identical ids.
- [ ] AC2 Login onto a device with 3 local sites, one of them a duplicate: the preview lists
  exactly that one; KeepBoth → 2 copies, KeepLocal → one with local values, KeepAccount → one
  with account values; references (site → folder, site → ssh-key) point to the right items in
  every case.
- [ ] AC3 Password change on device A: A unlocks with the new password; B's next API call
  gets `NeedsLogin`; B still unlocks locally with the old password; B logs in with the new
  password and afterwards unlocks only with the new one.
- [ ] AC4 Recovery with the 24 words, a code and a new password: login with the new password
  works; the old one fails; all devices were logged out.
- [ ] AC5 Two concurrent API calls with an expiring token cause exactly one `/auth/refresh`
  request (counted by the in-process server); the persisted pair is the new one.
- [ ] AC6 A crash injected after the server accepted registration but before the local commit
  is followed by a successful login without duplicates; a crash during the login commit
  leaves the local DB byte-identical in content (same items, same meta).
- [ ] AC7 `cargo build -p courier-ftp --no-default-features --locked` succeeds and `cargo tree
  -p courier-ftp --no-default-features -e normal` contains no `courier-ftp-sync`, `reqwest`
  or `tokio-tungstenite`.
- [ ] AC8 `ApiClient::new` rejects `http://example.com`, `ftp://x`, `https://x/path`,
  `https://u@x` and accepts `https://x`, `http://127.0.0.1:8080`, `http://[::1]:1`.
- [ ] AC9 After a full test run at trace level, no canary password, token, recovery word or
  email appears in logs or the client DB (canary scan, T91 §5).
- [ ] AC10 CI gates `fmt`, `clippy` (both feature sets), `docs`, `test-os` (Windows/macOS run
  this crate's tests) pass.

## Tests

Test harness `tests/common/mod.rs`: starts `courier-ftp-server` in-process on
`127.0.0.1:0` with the in-memory store (T84/T85), fixed setup token, `insecure-test-ksf`,
and creates `TestDevice`s (temp data dir, vault initialised with `Argon2Cost::TEST`).

### Unit tests
- `http::tests::url_rules` (AC8).
- `http::tests::error_mapping` — envelope, 429 retry-after, non-JSON, missing proto header.
- `tokens::tests::refresh_margin_and_persist_before_use` — mock clock; the store write
  precedes the token's first use (AC5).
- `account::wizard::tests::recovery_confirm_positions_and_compare` — 3 distinct positions,
  case/whitespace-insensitive, wrong word message.
- `account::wizard::tests::register_wizard_cannot_finish_before_confirm`.
- `account::merge_local::tests::dedupe_keys_per_kind` — table above.
- `account::merge_local::tests::remap_nested_ids`.

### Property / fuzz tests
- `props::import_remap_has_no_dangling_refs` — random graphs of local items (folders, sites,
  keys, bookmarks) and random choices: after import every reference names an existing item
  in the account vault; item count = local + account − KeepAccount/KeepLocal rows (AC2).
- `props::recovery_confirm_accepts_only_the_right_words`.

### Snapshot tests
- Not a UI task (T90 snapshots the screens).

### Integration tests (`tests/account.rs`)
- `t01_register_then_second_device_sees_items` (AC1).
- `t02_register_keeps_the_master_password` — unlock with the same password after registering.
- `t03_register_requires_current_password` → `WrongLocalPassword`.
- `t04_login_adopts_the_account_password` — warning flag set; after commit only the account
  password unlocks.
- `t05_login_imports_local_items_with_preview` — three choices (AC2).
- `t06_crash_during_import_then_retry` and `t06b_crash_after_register_finish` (AC6).
- `t07_online_password_change` (AC3).
- `t08_password_change_needs_the_server` — server stopped → `Offline`, nothing changed.
- `t09_recovery_resets_the_password` (AC4).
- `t10_logout_keep_local` — team vault rows gone, personal items dirty with base 0, password
  unchanged; re-login creates no duplicates.
- `t11_token_refresh_single_flight` (AC5).
- `t12_refresh_reuse_needs_login` — replaying an old refresh token → `NeedsLogin`.
- `t13_devices_list_and_revoke_this_device_logs_out`.
- `t14_totp_enable_login_disable`.
- `t15_registration_needs_invite_on_invite_only_server`.
- `t16_delete_account`.
- `no_default_features_build` is the CI clippy step (AC7).

### End-to-end tests
- `courier-ftp-e2e/tests/sync_account.rs::register_login_recover_against_docker_server`
  (`#[ignore]`, `COURIER_E2E=1`): T76 sync fixture (server + postgres from
  `deploy/docker-compose.yml`), two `TestHome`s; register with the setup token, log in on the
  second home with a duplicate preview, change the password on the first, recover with the
  words — the T76 "Sync" scenario list (AC1–AC4 against a real deployment).
- `PtyApp` flows live in T90.

## Out of scope

- The sync engine (pull/push/WS) — T88.
- Team vaults, grants from other users, trust — T89.
- Screens — T90; headless CLI commands (`courier-ftp sync …`) — not planned (see Open
  questions).

## Open questions

- **Self-signed sync servers.** Only OS-trusted certificates are accepted. Should a
  per-account custom CA / certificate pin (e.g. `sync.ca_file` or TOFU like T12) be
  supported for servers without a public certificate?
- **Headless sync commands** (`courier-ftp sync --now|--status`, `logout`) like sverb's
  CLI: wanted for T70, or UI only?
- **`VaultEngine` additions:** this task adds `sync_handles`, `verify_password`,
  `lmk_rewrap_rows` and `reload` to T30's engine; T30 should list them when it is revised.
