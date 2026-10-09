# T84 — Sync server: accounts, login and devices

**Phase:** H Sync · **Milestone:** M7 · **Depends on:** T80, T83 · **Crate(s):** new `courier-ftp-server` (binary + lib) · **Decisions:** D12, D13 · **FEATURES.md:** — (D12 sync infrastructure)
**Reference:** sverb `crates/sverb-server/src/{app,state,error,db,secrets,registration,settings,mail,serve}.rs`, `src/auth/{mod,clock,extractor,opaque,tokens,totp}.rs`, `src/auth/store/{mod,mem,pg}.rs`, `src/routes/{auth,account,devices}.rs`, `src/middleware/{client_ip,errors,proto_version,rate_limit,request_id}.rs`, `migrations/server/0001_init.sql`, `0002_login_states.sql`, `tests/{auth,http,db,config}.rs`; SPEC §10.1–§10.5, §11.2.

## Goal

The account half of the self-hosted sync server: OPAQUE registration and login with the
master password, access/refresh/reauth tokens, a device registry with revocation,
optional TOTP, online password change, account recovery with the 24-word recovery key,
account deletion, and first-start bootstrap (setup token, registration modes). The server
never learns the master password, the account private keys or any item plaintext. Every
handler runs against an in-memory store (fast tests) and PostgreSQL (production).

## Context

- **Before:** T80 provides the OPAQUE suite (`courier_ftp_crypto::opaque`: client/server
  registration and login helpers, `credential_identifier`, `recovery_proof_message`),
  account bundles (`account::BUNDLE_LEN`), grants (`grant::verify_grant`), AEAD and HKDF.
  T83 provides every DTO, `ErrorCode`, limits and `version::negotiate`. T01 created the
  empty crate; T00 has a `server-db` CI job waiting for this task.
- **After:** T85 adds vault sync, the WebSocket hub and the event bus on top of the state,
  store and middleware defined here; T86 completes the configuration (TOML file, every
  variable), the admin CLI, ops endpoints and deployment; T87 is the client of these
  endpoints; T89 adds orgs and team vaults to the same schema and extends
  `register/finish` for org invites.

## Technical specification

### Types and APIs

Crate layout (`crates/courier-ftp-server/`):

```
Cargo.toml            [[bin]] courier-ftp-server = src/main.rs; lib = src/lib.rs
migrations/0001_init.sql            (this task)
src/lib.rs            pub mod app, state, config, error, db, secrets, events, registration,
                      settings_kv, mail, serve, auth, routes, middleware
src/main.rs           parses CLI (serve [--migrate], migrate; T86 adds the rest), calls lib
src/auth/{mod,clock,extractor,opaque,tokens,totp}.rs
src/auth/store/{mod,mem,pg}.rs
src/routes/{mod,auth,account,devices}.rs
src/middleware/{client_ip,errors,proto_version,rate_limit,request_id}.rs
tests/{common/mod.rs,auth.rs,http.rs,db.rs,config.rs}
```

Dependencies (versions as in sverb's workspace, D13): `courier-ftp-crypto`,
`courier-ftp-proto`, `tokio` (rt-multi-thread, macros, signal, time), `axum` 0.8 (`ws`),
`axum-server` (rustls), `tower`, `tower-http` (compression-gzip, cors, limit, timeout,
trace), `sqlx-core` + `sqlx-postgres` (runtime-tokio, tls-rustls, `time`, `uuid`, `json`)
— **not** the `sqlx` facade (it links `libsqlite3-sys`, which conflicts with the client's
bundled `rusqlite` in the same `Cargo.lock`), `governor`, `ipnet`, `lettre` (tokio,
rustls, smtp-transport, builder), `totp-rs`, `sha2`, `subtle`, `hex`, `base64`, `uuid`
(v7), `time`, `serde`, `serde_json`, `thiserror`, `tracing`, `tracing-subscriber` (`json`,
`env-filter`), `zeroize`, `clap` (derive; see Open questions), `toml`. Dev: `tower`
(`util`), `http-body-util`, `courier-ftp-crypto` with `insecure-test-ksf`, `tokio`
(`test-util`).

```rust
// src/state.rs
/// Shared, cheap-to-clone application state.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);
impl AppState {
    pub fn new(config: Config, store: Store, events: Arc<dyn EventSink>) -> Self;
    pub fn config(&self) -> &Config;
    pub fn store(&self) -> &Store;
    pub fn secrets(&self) -> &ServerSecrets;
    pub fn auth(&self) -> &AuthRuntime;          // clock, OPAQUE ServerSetup cache
    pub fn rate_limits(&self) -> &RateLimiters;
    pub fn events(&self) -> &Arc<dyn EventSink>;
}

// src/auth/store/mod.rs
/// One storage backend for every table; the in-memory variant models PostgreSQL's
/// transaction semantics (row locks as per-key async mutexes, all-or-nothing commits).
#[derive(Clone)]
pub enum Store { Mem(Arc<MemDb>), Pg(sqlx_postgres::PgPool) }

impl Store {
    pub async fn check_registration(&self, email: &str, cred: RegistrationCredential<'_>, now: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn register(&self, acct: &NewAccount, cred: RegistrationCredential<'_>, tokens: &IssuedTokens, family: Uuid, now: OffsetDateTime) -> Result<RegisterOutcome, ApiError>;
    pub async fn user_by_email(&self, email: &str) -> Result<Option<LoginUser>, ApiError>;
    pub async fn user_by_id(&self, id: Uuid) -> Result<Option<LoginUser>, ApiError>;
    pub async fn put_login_state(&self, row: &LoginStateRow, now: OffsetDateTime) -> Result<(), ApiError>;   // also deletes expired rows (≤ 100 per call)
    pub async fn take_login_state(&self, id: Uuid, now: OffsetDateTime) -> Result<Option<LoginStateRow>, ApiError>; // DELETE … RETURNING, unexpired only
    pub async fn consume_totp_step(&self, user: Uuid, step: i64) -> Result<bool, ApiError>;
    pub async fn start_session(&self, user: Uuid, choice: &DeviceChoice, tokens: &IssuedTokens, family: Uuid, now: OffsetDateTime) -> Result<Uuid /*device*/, ApiError>;
    pub async fn authenticate(&self, access_hash: &TokenHash, now: OffsetDateTime) -> Result<Option<AuthCtx>, ApiError>;
    pub async fn refresh(&self, refresh_hash: &TokenHash, issued: &IssuedTokens, now: OffsetDateTime) -> Result<RefreshOutcome, ApiError>;
    pub async fn logout(&self, device: Uuid, now: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn list_devices(&self, user: Uuid) -> Result<Vec<DeviceRow>, ApiError>;
    pub async fn revoke_device(&self, user: Uuid, device: Uuid, now: OffsetDateTime) -> Result<bool, ApiError>;
    pub async fn insert_reauth(&self, hash: &TokenHash, user: Uuid, expires: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn change_password(&self, ctx: AuthCtx, reauth: &TokenHash, new: &NewCredentials, now: OffsetDateTime) -> Result<Vec<Uuid> /*devices logged out*/, ApiError>;
    pub async fn issue_recovery_code(&self, email: &str, code_hash: &[u8; 32], expires: OffsetDateTime) -> Result<Option<Uuid>, ApiError>;
    pub async fn check_recovery_code(&self, email: &str, code_hash: &[u8; 32], now: OffsetDateTime) -> Result<Option<RecoveryInfo>, ApiError>;
    pub async fn finish_recovery(&self, user: Uuid, code_hash: &[u8; 32], new: &NewCredentials, now: OffsetDateTime) -> Result<Vec<Uuid>, ApiError>;
    pub async fn set_totp_pending(&self, user: Uuid, sealed: &[u8]) -> Result<(), ApiError>;
    pub async fn confirm_totp(&self, user: Uuid, step: i64) -> Result<bool, ApiError>;
    pub async fn disable_totp(&self, user: Uuid) -> Result<(), ApiError>;
    pub async fn delete_account(&self, user: Uuid, reauth: &TokenHash, now: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn account_keys(&self, user: Uuid) -> Result<Option<AccountKeysRow>, ApiError>;
    pub async fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, ApiError>;
    pub async fn insert_secret_if_absent(&self, name: &str, value: &[u8]) -> Result<(), ApiError>;
    pub async fn setting(&self, key: &str) -> Result<Option<String>, ApiError>;
    pub async fn set_setting(&self, key: &str, value: &str, now: OffsetDateTime) -> Result<(), ApiError>;
    pub async fn user_count(&self) -> Result<u64, ApiError>;
}

pub enum RegistrationCredential<'a> { None, SetupToken(&'a str), InviteToken(&'a str) }
pub struct RegisterOutcome { pub is_instance_admin: bool, pub org_invite: Option<Uuid> /* T89 */ }
pub enum DeviceChoice { New(NewDevice), Existing(Uuid, NewDevice /*fallback if revoked/foreign*/) }
pub enum RefreshOutcome { Rotated { device_id: Uuid }, Reused { device_id: Uuid, user_id: Uuid, family: Uuid }, Invalid }

// src/auth/extractor.rs
/// Handler argument that requires `Authorization: Bearer <access>`.
#[derive(Debug, Clone, Copy)]
pub struct AuthCtx { pub user_id: Uuid, pub device_id: Uuid, pub is_instance_admin: bool }

// src/auth/tokens.rs
pub const TOKEN_LEN: usize = 32;
pub const ACCESS_TTL: Duration = Duration::minutes(15);
pub const REFRESH_TTL: Duration = Duration::days(30);
pub const REAUTH_TTL: Duration = Duration::minutes(5);
pub const LOGIN_STATE_TTL: Duration = Duration::seconds(60);
pub const RECOVERY_CODE_TTL: Duration = Duration::hours(24);
pub const RECOVERY_CODE_MAX_ATTEMPTS: i32 = 5;
pub const LAST_SEEN_THROTTLE: Duration = Duration::minutes(5);
pub struct TokenHash(pub [u8; 32]);                       // SHA-256 of the 32 raw bytes
pub struct NewToken { pub wire: Zeroizing<String>, pub hash: TokenHash }
impl NewToken { pub fn generate() -> Self; }
pub fn hash_presented(wire: &str) -> Option<TokenHash>;   // None unless 43 chars base64url → 32 bytes
pub struct IssuedTokens { pub access: NewToken, pub refresh: NewToken, pub access_expires: OffsetDateTime, pub refresh_expires: OffsetDateTime }
impl IssuedTokens { pub fn issue(now: OffsetDateTime) -> Self; pub fn to_pair(&self) -> TokenPair; }

// src/auth/clock.rs
pub trait Clock: Send + Sync + 'static { fn now(&self) -> OffsetDateTime; }
pub struct SystemClock; pub struct TestClock(/* settable, advance(Duration) */);

// src/events.rs — published by T84, delivered by T85's bus/hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "e", rename_all = "snake_case")]
pub enum BusEvent {
    VaultChanged { vault_id: Uuid, head_revision: u64 },
    VaultAccess { user_id: Uuid, vault_id: Uuid, change: AccessChange },
    AccountChanged { user_id: Uuid, key_version: u32, origin_device: Option<Uuid> },
    DevicesRevoked { device_ids: Vec<Uuid> },     // ≤ 200 ids per event; split above
    UserDisabled { user_id: Uuid },
}
pub trait EventSink: Send + Sync + 'static { fn publish(&self, ev: BusEvent); }
pub struct NoopSink;                               // until T85 wires the bus

// src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")] Invalid(String),               // 400 invalid
    #[error("{0}")] AuthRequired(String),          // 401 auth_required
    #[error("{0}")] Forbidden(String),             // 403 forbidden
    #[error("{0}")] NotFound(String),              // 404 not_found
    #[error("{0}")] Conflict(String),              // 409 conflict
    #[error("{0}")] Rotating(String),              // 409 rotating (T85/T89)
    #[error("{0}")] Gone(String),                  // 410 gone (T85)
    #[error("rate limited")] RateLimited { retry_after_s: u64 }, // 429 + Retry-After
    #[error("service unavailable")] Unavailable,   // 503 internal (pool exhausted, DB down)
    #[error("internal error")] Internal(#[source] Box<dyn std::error::Error + Send + Sync>), // 500 internal
}
impl axum::response::IntoResponse for ApiError { /* ErrorEnvelope JSON; Internal logs the source at error with request_id, body says only "internal error" */ }
impl From<sqlx_core::Error> for ApiError { /* PoolTimedOut → Unavailable, else Internal */ }
```

Router assembly (`src/app.rs`), middleware outermost first (as sverb):
1. `request_id::layer` (keep a valid incoming `x-request-id`, else UUIDv7; echo it);
2. `TraceLayer` span `request{method, path, request_id}` (path template, never query
   strings);
3. `errors::layer` (bare 404/405/408/413/415/422/5xx → `ErrorEnvelope`);
4. metrics layer (T86; no-op here);
5. `proto_version::layer` (`negotiate`, echo `Courier-Proto: 1`);
6. `CompressionLayer` (gzip responses ≥ 1 KiB), `CorsLayer` (deny by default; origins from
   config, T86);
7. `client_ip::layer` (TCP peer; `X-Forwarded-For` walked right-to-left only when the peer
   is in `trusted_proxies`; first non-trusted hop is the client);
8. `RequestBodyLimitLayer(BODY_LIMIT_BYTES)` + `DefaultBodyLimit::max(BODY_LIMIT_BYTES)`,
   `TimeoutLayer(30 s → 408 invalid "request timeout")`;
9. route.

### Behaviour

#### Endpoints

All under `/v1`. "Bearer" = requires `AuthCtx`. Errors use the T83 envelope; messages in
quotes are the exact `message` strings.

| Method | Path | Auth | Request → Response | Success | Errors |
|---|---|---|---|---|---|
| POST | `/auth/register/start` | — | `RegisterStartRequest` → `RegisterStartResponse` | 200 | 400 bad email / malformed OPAQUE; 403 `"registration is closed"`, `"registration requires an invite"`, `"invalid or expired invite"`, `"invalid setup token"`; 409 `"email already registered"`; 429 |
| POST | `/auth/register/finish` | — | `RegisterFinishRequest` → `SessionResponse` | 200 | 400 field-specific (`"ids must not be nil"`, `"malformed OPAQUE registration upload"`, `"x25519_pub must be 32 bytes"`, `"private and recovery bundles must be N bytes"`, `"account key version must be 1"`, `"vault key version must be 1"`, `"grant signature must be 64 bytes"`, `"self-grant signature does not verify"`, `"invalid encrypted vault name"`); 403 as above; 409 `"email already registered"`, `"vault id already exists"` |
| POST | `/auth/login/start` | — | `LoginStartRequest` → `LoginStartResponse` | 200 (also for unknown emails) | 400 bad email / malformed KE1; 429 |
| POST | `/auth/login/finish` | — | `LoginFinishRequest` → `SessionResponse` (`purpose: login`) or `ReauthResponse` (`reauth`) | 200 | 401 `"invalid email or password"` (unknown state id, expired state, wrong password, unknown email, disabled account — identical); 401 `"totp_required: …"` / `"totp_invalid: …"` (only after a correct password); 400 bad device fields |
| POST | `/auth/refresh` | — | `RefreshRequest` → `TokenPair` | 200 | 401 `"invalid or expired refresh token"`; 401 `"refresh token reuse detected; this device must log in again"` |
| POST | `/auth/logout` | Bearer | — | 204 | 401 |
| GET | `/devices` | Bearer | → `Vec<DeviceView>` (newest `created_at` first) | 200 | 401 |
| DELETE | `/devices/{id}` | Bearer | — | 204 | 401; 404 `"device not found"` (unknown, other user's, already revoked) |
| POST | `/account/totp` | Bearer | `TotpRequest{code: None}` → `TotpSetupResponse`; `{code: Some}` → `TotpStatus{enabled:true}` | 200 | 401; 409 `"totp already enabled"`; 400 `"no pending totp setup"`; 401 `"totp_invalid: …"` |
| DELETE | `/account/totp` | Bearer | `TotpRequest{code}` | 204 | 401 `"totp_invalid: …"`; 400 `"totp is not enabled"` |
| POST | `/account/password/start` | Bearer | `PasswordStartRequest` → `PasswordStartResponse` | 200 | 400 malformed; 401 |
| POST | `/account/password` | Bearer | `PasswordChangeRequest` → `KeyVersionResponse` | 200 | 401 `"reauth required"` (missing/used/expired/foreign reauth token); 409 `"account key version changed"` (version ≠ current + 1); 400 malformed upload/bundle |
| POST | `/account/recovery/code` | — | `RecoveryCodeRequest` | 202 (always, also unknown email / no SMTP) | 400 bad email; 429 |
| POST | `/account/recovery/start` | — | `RecoveryStartRequest` → `RecoveryStartResponse` | 200 | 401 `"invalid or expired recovery code"`; 404 `"this account has no recovery bundle"`; 400; 429 |
| POST | `/account/recovery` | — | `RecoveryFinishRequest` → `KeyVersionResponse` | 200 | 401 as above; 403 `"recovery proof signature does not verify"`; 409 `"account key version changed"`; 400; 429 |
| DELETE | `/account` | Bearer | `AccountDeleteRequest` | 204 | 401 `"reauth required"`; 409 `"you are the only owner of an org with other members"` (T89 adds the org check; until then never) |

Every Bearer endpoint returns 401 `"authentication required"` for a missing/malformed
header and 401 `"invalid or expired token"` otherwise (unknown hash, expired, revoked
device, disabled user).

#### Registration and bootstrap

1. **Modes** (`settings.registration_mode`): `open` (anyone; invite optional),
   `invite-only` (default after migration; needs a valid invite or the setup token),
   `closed` (nobody; invites rejected too). The **setup token** works in every mode while
   `users` is empty.
2. **Setup token**: at `serve` start, if `user_count() == 0`, generate 32 random bytes,
   encode base64url (43 chars), store `hex(SHA-256)` in `settings.setup_token_hash`
   (replacing any previous one), and log once at **warn**:
   `setup_token=<token> "no account exists yet: register the first account with this setup token"`.
   The first successful registration with it sets `is_instance_admin = true` and deletes
   `setup_token_hash` in the same transaction. Comparison is constant-time (`subtle`).
3. **Invites** (`invites` rows): valid iff `accepted_at IS NULL AND expires_at > now`, the
   token hash matches, and the bound `email` (if any) equals the normalized email. At
   `finish` the row gets `accepted_at = now` inside the registration transaction. An
   `org_id IS NULL` row is an instance invite (from `admin invite`, T86); an org invite is
   returned in `RegisterOutcome::org_invite` for T89 to apply.
4. `register/start` runs the full policy check (fail early, no OPAQUE work for refused
   requests), then `ServerSetup::registration_start(request, credential_identifier(email))`
   and proposes `user_id = Uuid::now_v7()`.
5. `register/finish` validates (`validate_registration`): normalized email; non-nil ids;
   OPAQUE upload parses (`registration_finish` → record); keys 32 B; version 1; both
   bundles exactly `account::BUNDLE_LEN`; `name_enc` 1..=4096 B; self-grant
   `key_version == 1`, signature 64 B, wrapped key parses, and
   `grant::verify_grant(grant, vault_id, user_id, 1, ed25519_pub)` succeeds. Then **one
   transaction**: re-check policy and consume invite/setup token; insert `users`,
   `account_keys`, `devices` (new UUIDv7), `vaults` (`kind='personal'`,
   `owner_user_id`, `key_version=1`, `head_revision=0`, `created_by=user`),
   `vault_members` (`manage`, self-grant, `wrapped_by = user`), `auth_tokens` (access +
   refresh, new family). A unique violation on `users.email` → 409; on `vaults.id` → 409.
   Response `SessionResponse` with tokens.

#### OPAQUE

- `ServerSetup` is created on first need, sealed (see *Server secret*) and stored as
  `server_secrets('opaque_server_setup')` with `INSERT … ON CONFLICT DO NOTHING` followed
  by a re-read (first writer wins, so replicas agree). Cached in `AuthRuntime` after load.
- Credential identifier: `credential_identifier(normalized_email)` (T80).
- `login/start`: for a known user, `login_start(Some(record))`; for an unknown email, or a
  stored record that does not parse (logged at error with `user_id`), `login_start(None)`
  (dummy record) — same response shape. The KE2 server state is sealed with AAD
  `"courier-ftp/login-state/v1" || id(16)` and stored in `login_states` with
  `expires_at = now + 60 s` and `user_id` (NULL for unknown emails). Every `put_login_state`
  also deletes up to 100 expired rows.
- `login/finish`: `take_login_state` (DELETE … RETURNING, so a state is single-use),
  unseal, `finish(KE3)`. Failure of any kind, unknown user, or `disabled` → the generic 401.
  Then TOTP (below), then:
  - `purpose = reauth`: insert `reauth_tokens` (5 min, single use) → `ReauthResponse`; no
    device or session tokens change.
  - `purpose = login`: `start_session`: if `device.id` names an unrevoked device of this
    user, issue a new token family for it (old tokens of that device deleted) and update
    name/platform when given; otherwise create a new device. Response `SessionResponse`
    with the current `account_keys`.

#### Tokens

- Format: 32 bytes from `OsRng`, base64url no padding (43 chars). Stored only as
  `SHA-256(raw bytes)` in `auth_tokens.token_hash` / `reauth_tokens.token_hash`.
- Lifetimes: access 15 min, refresh 30 days (each rotation issues a fresh 30 days), reauth
  5 min.
- **Authenticate** (`AuthCtx` extractor): `hash_presented` → row with `kind='access'`,
  `expires_at > now`, device `revoked_at IS NULL`, user `disabled = false`. Updates
  `devices.last_seen_at` when older than 5 min (one UPDATE, failures ignored).
- **Refresh** (one transaction, `SELECT … FOR UPDATE` on the token row):
  1. no row / not `refresh` / expired / device revoked / user disabled → `Invalid`;
  2. `used_at IS NOT NULL` → **reuse**: delete every token of that `family`, write audit
     row `refresh_token_reuse` (user id, device id, family), log warn with ids → 401;
  3. else set `used_at = now`, insert a new access + refresh pair in the **same family**,
     delete the family's other access tokens → `TokenPair`.
  There is no grace window; the client must persist the new pair before using it (T87).
- **Logout**: deletes all tokens of the calling device and sets `devices.revoked_at`;
  publishes `DevicesRevoked{[device]}`.
- **Revoke device**: same for a chosen device of the caller; revoking the calling device is
  allowed (equivalent to logout).

#### TOTP

RFC 6238 via `totp-rs`: SHA-1, 6 digits, 30 s step, 160-bit secret, issuer `courier-ftp`,
account label = the email (only inside the otpauth URI sent to the user). A code is
accepted for steps `now-1..=now+1`; the matched step must be **greater** than
`users.totp_last_step` (replay protection, updated atomically). Enable: `POST` without code
stores a sealed pending secret (`totp_pending_enc`, AAD `"courier-ftp/totp-pending/v1" ||
user_id`) and returns the URI and base32 secret; `POST` with a valid code moves it to
`totp_secret_enc` (AAD `"courier-ftp/totp/v1" || user_id`). Login with TOTP enabled: no
code → 401 `"totp_required: this account requires a TOTP code"`; wrong/replayed → 401
`"totp_invalid: invalid or already used TOTP code"`. Disable requires a current code.

#### Password change (online, §11.2.1)

1. Client logs in with `purpose: reauth` → `reauth_token`.
2. `POST /account/password/start` (Bearer) → OPAQUE registration response for the new
   password (credential identifier of the account's email).
3. `POST /account/password` (Bearer + reauth token): one transaction — consume the reauth
   token (must belong to `ctx.user_id`, unexpired, unused); check `version ==
   account_keys.version + 1` (else 409); replace `users.opaque_record`,
   `account_keys.private_bundle_enc`, `account_keys.version`; delete all `auth_tokens` of
   the user's **other** devices (rows stay, not revoked: they log in again with the new
   password and resume their device id). After commit publish
   `AccountChanged{user, version, origin_device: Some(ctx.device_id)}` and
   `DevicesRevoked{other devices}` (so their WebSockets close with 4401).

#### Recovery (sverb proposal, §11.2)

- Code: 10 random bytes rendered as 16 Crockford base32 chars, shown as `XXXX-XXXX-XXXX-XXXX`
  (dashes and case ignored on input). Stored as SHA-256 in `recovery_codes` (one live code
  per user; a new one replaces the old), TTL 24 h, 5 wrong attempts delete it.
- `POST /account/recovery/code`: rate-limited; with SMTP configured and a known email,
  mails the code (subject `"Your courier-ftp recovery code"`); always 202. Without SMTP the
  operator issues codes with `admin user recovery-code` (T86).
- `recovery/start`: code check (wrong code → attempts + 1 → 401) → returns
  `recovery_bundle_enc`, an OPAQUE registration response and the current `version`.
- `recovery` (finish): code check; `version == current + 1`; Ed25519 verify of
  `recovery_proof_message(user_id, version, registration_upload, private_bundle_enc)` with
  the stored `ed25519_pub` (403 on failure); one transaction: replace record + bundle +
  version, delete the code, delete **all** tokens and set `revoked_at` on **all** devices of
  the account. `recovery_bundle_enc` is unchanged (same recovery key). Publish
  `AccountChanged{origin_device: None}` and `DevicesRevoked{all}`.

#### Account deletion

Bearer + reauth token; one transaction deletes: items, staging and members of the user's
personal vault, the vault, the user's `vault_members` rows in team vaults, `org_members`
rows, tokens, login states, reauth tokens, recovery codes, devices, `account_keys`,
`users`; inserts audit `account.deleted` (actor = user, no email). Publishes
`DevicesRevoked{all}`. T89 adds the "only owner of an org with other members → 409" check.

#### Rate limiting (`governor`, GCRA, burst = full quota)

| Limiter | Key | Quota | Applied to |
|---|---|---|---|
| `auth_email` | normalized email | 5 / min | `register/start`, `login/start`, `recovery/code`, `recovery/start`, `recovery` |
| `auth_ip` | client IP | 50 / min | same endpoints |

Both are checked (IP first); exceeding either → 429 `rate_limited`, message
`"too many attempts"`, `retry_after_s` = governor's wait rounded up, `Retry-After` header.
Keys whose state fully recovered are dropped every 60 s. Limiters are per replica.

#### Server secret

`COURIER_SERVER_SECRET` (≥ 32 bytes after hex or base64 decoding; T86 config) →
`K = HKDF-SHA256(ikm = secret, salt = none, info = "courier-ftp/server-secret/v1")`.
`ServerSecrets::seal(aad, pt)` = `nonce(24) || XChaCha20-Poly1305(K, nonce, aad, pt)`.
`server_secrets.value_enc` uses AAD = the row name. At start
`ServerSecrets::verify_or_init`: insert canary row `secret_check` (plaintext
`"courier-ftp server secret check v1"`) if absent, then decrypt **every** `server_secrets`
row; any failure → `ServeError::WrongSecret` → log error
`"cannot decrypt server_secrets row <name>: COURIER_SERVER_SECRET differs from the one this database was created with. Refusing to start."`
and exit code 2.

#### Migrations and DB access

- `db::MIGRATIONS: &[(i64, &str, &str)]` = `(version, name, include_str!(…))`; bookkeeping
  table `schema_migrations(version BIGINT PRIMARY KEY, name TEXT NOT NULL, checksum BYTEA
  NOT NULL, applied_at TIMESTAMPTZ NOT NULL)`. `migrate` takes `pg_advisory_lock(0x434F55524945)`
  and applies each missing migration in its own transaction. `serve` without `--migrate`
  refuses to start when migrations are pending; any DB row with an unknown version or a
  checksum mismatch → refuse ("database schema is newer than this binary" / "migration N
  was modified").
- Pool: `PgPoolOptions::max_connections(16)`, `acquire_timeout(5 s)`; queries are
  runtime-checked (`sqlx_core::query`), so building never needs a database.
- In-memory store (`MemDb`): one `tokio::sync::Mutex` per logical transaction scope; writes
  are applied all-or-nothing at the end of each store method.

#### Startup (`serve`)

Load config → connect → migrations check/apply → `verify_or_init` secrets → load or create
OPAQUE `ServerSetup` → setup-token bootstrap → spawn rate-limit cleanup → bind (plain or
built-in rustls when cert+key given) → serve with graceful shutdown on SIGINT/SIGTERM (10 s
grace). Exit codes: 0 normal, 2 config/secret error, 3 database/migration error, 4 bind/TLS
error.

### Data formats and configuration

`crates/courier-ftp-server/migrations/0001_init.sql` (complete base schema, also used by
T85 and T89; later changes only in new files):

```sql
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE server_secrets (name TEXT PRIMARY KEY, value_enc BYTEA NOT NULL);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
                       updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
INSERT INTO settings (key, value) VALUES ('registration_mode', 'invite-only');

CREATE TABLE users (
  id UUID PRIMARY KEY, email CITEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  is_instance_admin BOOLEAN NOT NULL DEFAULT false,
  opaque_record BYTEA NOT NULL,
  totp_secret_enc BYTEA, totp_pending_enc BYTEA, totp_last_step BIGINT,
  disabled BOOLEAN NOT NULL DEFAULT false);

CREATE TABLE account_keys (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  x25519_pub BYTEA NOT NULL, ed25519_pub BYTEA NOT NULL,
  private_bundle_enc BYTEA NOT NULL, recovery_bundle_enc BYTEA,
  version INT NOT NULL CHECK (version >= 1));

CREATE TABLE devices (
  id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, platform TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ);
CREATE INDEX devices_user_id ON devices (user_id);

CREATE TABLE auth_tokens (
  token_hash BYTEA PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
  expires_at TIMESTAMPTZ NOT NULL, family UUID NOT NULL, used_at TIMESTAMPTZ);
CREATE INDEX auth_tokens_device_id ON auth_tokens (device_id);
CREATE INDEX auth_tokens_family ON auth_tokens (family);
CREATE INDEX auth_tokens_expires_at ON auth_tokens (expires_at);

CREATE TABLE login_states (id UUID PRIMARY KEY, user_id UUID, state_enc BYTEA NOT NULL,
                           expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX login_states_expires_at ON login_states (expires_at);

CREATE TABLE reauth_tokens (token_hash BYTEA PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL);

CREATE TABLE recovery_codes (user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0);

CREATE TABLE orgs (id UUID PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE org_members (
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  joined_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (org_id, user_id));
CREATE INDEX org_members_user_id ON org_members (user_id);

CREATE TABLE invites (
  id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id) ON DELETE CASCADE, -- NULL = instance invite
  email CITEXT, role TEXT CHECK (role IN ('owner','admin','member')),
  token_hash BYTEA NOT NULL UNIQUE, created_by UUID,
  created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, accepted_at TIMESTAMPTZ);

CREATE TABLE vaults (
  id UUID PRIMARY KEY,                               -- client-generated UUIDv7
  kind TEXT NOT NULL CHECK (kind IN ('personal','team')),
  owner_user_id UUID REFERENCES users(id), org_id UUID REFERENCES orgs(id),
  created_by UUID NOT NULL,
  key_version INT NOT NULL DEFAULT 1, head_revision BIGINT NOT NULL DEFAULT 0,
  gc_floor_revision BIGINT NOT NULL DEFAULT 0,
  rotation JSONB,                                    -- {by, device, new_key_version, started_at}
  name_enc BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL AND org_id IS NULL)),
  CHECK ((kind = 'team') = (org_id IS NOT NULL)));
CREATE UNIQUE INDEX vaults_one_personal ON vaults (owner_user_id) WHERE kind = 'personal';

CREATE TABLE vault_members (
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission TEXT NOT NULL CHECK (permission IN ('read','write','manage')),
  key_version INT NOT NULL, wrapped_vault_key BYTEA NOT NULL,
  wrapped_by UUID NOT NULL, signature BYTEA NOT NULL,
  PRIMARY KEY (vault_id, user_id, key_version));
CREATE INDEX vault_members_user_id ON vault_members (user_id);

CREATE TABLE items (
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, id UUID NOT NULL,
  revision BIGINT NOT NULL, key_version INT NOT NULL, envelope BYTEA NOT NULL,
  deleted BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL, updated_by_device UUID,
  PRIMARY KEY (vault_id, id));
CREATE UNIQUE INDEX items_vault_rev ON items (vault_id, revision);

CREATE TABLE items_rotation_staging (
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, id UUID NOT NULL,
  key_version INT NOT NULL, envelope BYTEA NOT NULL, PRIMARY KEY (vault_id, id));

CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY, org_id UUID, actor_user_id UUID, kind TEXT NOT NULL,
  target UUID, at TIMESTAMPTZ NOT NULL, meta JSONB NOT NULL DEFAULT '{}'::jsonb);
CREATE INDEX audit_events_org ON audit_events (org_id, id DESC);
```

Configuration fields introduced here (T86 adds the TOML file, the remaining variables and
the documentation; environment always wins, empty = unset):

| Env | Type | Default | Used for |
|---|---|---|---|
| `DATABASE_URL` | string (redacted in `Debug`) | — (required by `serve`, `migrate`) | Postgres |
| `COURIER_BIND` | socket addr | `0.0.0.0:8080` | listener |
| `COURIER_PUBLIC_URL` | https URL, no trailing `/` | **required** | invite links (T89), mail texts |
| `COURIER_SERVER_SECRET` | hex or base64, ≥ 32 bytes | **required** | at-rest key |
| `COURIER_TLS_CERT`, `COURIER_TLS_KEY` | PEM paths | off (both or neither) | built-in TLS |
| `COURIER_TRUSTED_PROXIES` | comma list of IP/CIDR | none | client IP |
| `COURIER_REQUEST_TIMEOUT_S` | u64 1..=300 | 30 | `TimeoutLayer` |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | strings / u16 / bool | off; 587; —; —; required with host; true | recovery mail (T84), invites (T89) |

### Errors

- Server: `ApiError` → status + `ErrorEnvelope` as listed; `Internal` and `Unavailable`
  bodies say only `"internal error"` / `"service unavailable"`; details go to the log at
  error with `request_id`.
- Startup: `ServeError::{Config, Database, Migration, PendingMigrations, SchemaTooNew,
  WrongSecret, OpaqueSetup, Tls, Bind}` with the messages above, printed to stderr and the
  log, mapped to exit codes 2/3/4.
- Client-visible meaning is defined in T87 (e.g. 401 on login → "wrong email or password").

### Security and logging

- Never logged at any level: tokens, token hashes, OPAQUE messages, bundles, TOTP secrets
  and codes, recovery codes, invite/setup token values (except the one deliberate setup
  token warn line), passwords of SMTP, `DATABASE_URL` (redacted `Debug`).
- Emails are never logged at info+; where needed (debug) as `email_hash` = first 16 hex chars
  of SHA-256(normalized email). Info lines carry `user_id`, `device_id`, `request_id`.
- Logs are JSON lines on stdout (T86 makes the format configurable).
- Untrusted input: every length and format is checked before crypto (sizes from T83
  `limits`); OPAQUE and grant parsers are the fuzzed T80 functions; JSON bodies limited to
  12 MiB; device fields stripped of control characters.
- Enumeration resistance: `login/start` identical for unknown emails (dummy KE2, stored
  state); `login/finish` identical failure; `recovery/code` always 202. Registration does
  reveal whether an email exists (409) — accepted, documented in `docs/threat-model.md`.
- Constant-time comparison for setup/invite token hashes (`subtle::ConstantTimeEq`).
- Disabled accounts: tokens rejected; login fails generically (logged at warn with user id
  when the password was correct).

## Implementation steps

1. Crate skeleton, `error.rs`, `config.rs` (the variables above, `Config::from_sources(toml,
   env_lookup)` pure function), `secrets.rs`, `auth/clock.rs`, `tests/config.rs`.
2. `db.rs` migration runner + `0001_init.sql`; `tests/db.rs::migrations_apply_and_are_recorded`
   (Postgres-gated).
3. Middleware (`request_id`, `errors`, `proto_version`, `client_ip`, `rate_limit`) and
   `app.rs` router with an empty `/v1`; `tests/http.rs` for envelope, request id, version,
   client IP, body limit.
4. `Store` enum with `MemDb` and Pg implementations of the registration/login/token methods;
   `auth/tokens.rs`, `auth/opaque.rs`, `auth/extractor.rs`.
5. Routes `auth/register/*`, `login/*`, `refresh`, `logout`; `events.rs` with `NoopSink`.
6. Routes `devices`; TOTP (`auth/totp.rs`, `/account/totp`).
7. Password change, recovery (code, start, finish), `mail.rs`, account deletion.
8. `registration.rs` bootstrap + `serve.rs`/`main.rs` (`serve [--migrate]`, `migrate`),
   wrong-secret refusal; the `server-db` CI job switched on (T00).

## Acceptance criteria

- [ ] AC1 Register → login on a second device → refresh → logout works over HTTP against
  the in-memory store and against Postgres (same test body, `Harness` per backend).
- [ ] AC2 Presenting a used refresh token returns 401 and deletes every token of that family
  (the device's access token stops working on the next request).
- [ ] AC3 `login/start` for an unknown email returns 200 with the same JSON keys and value
  lengths as for a known email and stores a login state; `login/finish` with a wrong
  password and with an unknown email return identical status and body.
- [ ] AC4 Starting `serve` against a database initialised with a different
  `COURIER_SERVER_SECRET` exits with code 2 and the documented message.
- [ ] AC5 The 6th `login/start` for one email within a minute returns 429 with `Retry-After`
  ≥ 1 and `retry_after_s` in the body; the 51st from one IP likewise.
- [ ] AC6 With no users, `serve` logs exactly one warn line containing `setup_token=`; the first
  registration with it becomes instance admin; a second use returns 403.
- [ ] AC7 `invite-only` rejects registration without an invite (403), `closed` rejects with an
  invite (403), `open` accepts without one.
- [ ] AC8 Access tokens expire after 15 min, reauth tokens after 5 min, login states after
  60 s (paused-clock tests); refresh tokens after 30 days.
- [ ] AC9 Password change bumps `account_keys.version`, makes the old password fail and the
  new one succeed, deletes the other devices' tokens and publishes `AccountChanged` +
  `DevicesRevoked` (recorded by a test `EventSink`).
- [ ] AC10 Recovery with a valid code and signature replaces the record, revokes all devices;
  5 wrong codes delete the code; an invalid signature returns 403 and changes nothing.
- [ ] AC11 TOTP: enable → login without code 401 `totp_required` → with code 200 → same code
  again 401 `totp_invalid`.
- [ ] AC12 No token, OPAQUE message, TOTP secret, recovery code or email appears in the log
  output of the full test suite at `trace` (canary test; T91 §5 `canary` job).
- [ ] AC13 `cargo tree -p courier-ftp-server -e normal` contains no `libsqlite3-sys`,
  `rusqlite`, `ratatui`, `crossterm`, `courier-ftp-core`, `courier-ftp-store`,
  `courier-ftp-sync` (`layering` job).
- [ ] AC14 CI `server-db` job (Postgres 16) passes; `fmt`, `clippy`, `docs`, `deny` pass.

## Tests

Harness: `tests/common/mod.rs` builds an `AppState` + router per backend. `mem()` always;
`pg()` creates database `courier_test_<uuidv7 simple>` via `DATABASE_URL`, runs migrations,
drops it on drop. Without `DATABASE_URL` Postgres variants print
`skipping: DATABASE_URL not set` and pass — **except** when `CI=true`, where they fail
(only the `server-db` and `canary` CI jobs run this crate's tests, both with Postgres).
Every auth test is written once as `async fn tNN_name(h: &Harness)` and instantiated for both
backends by a `both!` macro (`tNN_name_mem`, `tNN_name_pg`). Clients use
`courier-ftp-crypto` with `insecure-test-ksf`. Time is a `TestClock`.

### Unit tests
- `secrets::tests::seal_open_roundtrip_and_aad_binding` — wrong AAD fails.
- `config::tests::secret_hex_and_base64_min_len` — 31 bytes rejected, 32 accepted (AC4).
- `auth::tokens::tests::hash_presented_rejects_wrong_length_and_padding`.
- `auth::totp::tests::window_and_replay` — steps −1/0/+1 accepted, ±2 rejected (AC11).
- `registration::tests::mode_parse_and_credential_precedence` (AC7).
- `routes::auth::tests::validate_registration_rejects_each_bad_field` — one case per 400
  message in the endpoint table.
- `middleware::client_ip::tests::forwarded_for_walk` — trusted chain, untrusted peer (AC5).
- `middleware::rate_limit::tests::burst_then_refill` with governor's fake clock (AC5).

### Property / fuzz tests
- `props::recovery_code_format_roundtrip` — any 10 bytes → 16 chars → same bytes; dashes and
  lower case accepted.
- OPAQUE/grant/bundle parsers are fuzzed in T80/T91; not repeated.

### Snapshot tests
- Not a UI task. `tests/http.rs::t03_error_envelope_for_every_code` uses `insta` JSON
  snapshots of one error body per `ErrorCode`.

### Integration tests (`tests/auth.rs`, `tests/http.rs`, `tests/db.rs`, `tests/config.rs`)
- `t01_register_login_refresh_logout` (AC1).
- `t02_unknown_email_indistinguishable` (AC3).
- `t03_register_is_atomic` — a failing step (duplicate vault id) leaves no user row (AC1).
- `t04_registration_modes_and_invites` (AC7).
- `t05_access_token_expiry` (AC8).
- `t06_refresh_rotation` / `t07_refresh_reuse_revokes_family` (AC2).
- `t08_logout_revokes_device` (AC1).
- `t09_devices_list_and_revoke` — foreign device id → 404; revoked device's token → 401.
- `t10_totp_enable_login_replay_disable` (AC11).
- `t11_password_change` (AC9).
- `t12_tokens_stored_hashed` — raw tokens never in `auth_tokens` (Pg: `SELECT` all bytea;
  Mem: inspect) (AC12).
- `t13_disabled_account_rejected`.
- `t14_delete_account_removes_everything` — personal vault, items, devices gone; reauth needed.
- `t15_recovery_flow` (AC10).
- `t16_login_state_ttl_and_single_use` (AC8).
- `t17_rate_limits_email_and_ip` (AC5).
- `http::t04_request_id_echo_generate_replace`, `t05_protocol_version_negotiation`,
  `t14_body_limit_maps_to_invalid`, `cors_denies_by_default`.
- `db::t02_migrations_apply_and_refuse_modified_or_newer` (Pg).
- `db::t09_wrong_server_secret_refuses_to_start` — runs `serve` logic twice with different
  secrets (AC4).
- `db::t10_bootstrap_setup_token_once` — captures logs with a test subscriber (AC6).
- `logs::canary_never_logged` — runs t01/t10/t11/t15 with a `trace` subscriber writing to a
  buffer; asserts no canary token/password/email appears (AC12).

### End-to-end tests
- Covered by T86 (`docker compose` smoke test) and the sync scenarios in T76/T87; none here.

## Out of scope

- Vault list/pull/push, WebSocket, bus fan-out (T85).
- Orgs, invites via API, team vaults, rotation (T89) — only their tables exist here.
- TOML config file, admin CLI, `/healthz` `/readyz` `/metrics`, Docker (T86).
- WebAuthn or other second factors; email verification at registration.

## Open questions

- **`clap` in the server crate.** `tasks/README.md` says the server crate never depends on
  `clap`, but the server needs a CLI (`serve`, `migrate`, `admin …`, `healthcheck`) and sverb
  uses `clap` there. Proposal: allow `clap` in `courier-ftp-server` (it is a binary, not a
  library used by the client) and change the README rule to "core, protocol, crypto, store,
  proto and sync crates". Until decided, this task uses `clap`.
- **Registration reveals existing emails** (409 `email already registered`) in `open` mode.
  Accept (as sverb does) or answer `register/start` identically and fail only at `finish`?
