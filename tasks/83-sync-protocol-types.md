# T83 — Sync protocol types

**Phase:** H Sync · **Milestone:** M7 · **Depends on:** T80 · **Crate(s):** new `courier-ftp-proto` · **Decisions:** D12, D13, D14 · **FEATURES.md:** — (infrastructure for D12 sync; no FileZilla feature)
**Related (integrates with, not blocking):** T84, T87
**Reference:** sverb `crates/sverb-proto/src/{lib,b64,error,version,auth,sync,users,orgs,vaults,rotation,ws}.rs`, SPEC §10.4, §12.2, §12.3, §13.2 (copy and adapt, D13; the terminal-share modules `share.rs`/`share_frame.rs` are **not** copied).

## Goal

One small crate that defines the complete wire format between the courier-ftp client
(T87, T88, T89) and `courier-ftp-server` (T84, T85, T86, T89): every request and response
body, the error envelope, the WebSocket messages, protocol constants and limits. Serde
only, no I/O, so client and server can never disagree about a field name or a limit, and
the JSON decoders can be fuzzed in isolation.

## Context

- **Before:** T80 provides `courier-ftp-crypto` (envelope, account bundle, grant,
  signature and fingerprint formats, with their byte lengths). T01 created the empty
  crate `crates/courier-ftp-proto` and its workspace entry.
- **After:** T84/T85/T89 implement the endpoints listed here on the server; T87/T88/T89
  call them from the client (`courier-ftp-sync`); T91 §7 adds the fuzz target
  `sync_dto_decode` whose body lives here. Any change to a DTO after T84 lands needs a
  protocol-version review (see *Versioning*).

## Technical specification

### Types and APIs

Crate layout (`crates/courier-ftp-proto/src/`):

| Module | Contents |
|---|---|
| `lib.rs` | re-exports `ErrorCode`, `ErrorBody`, `ErrorEnvelope`, `ProtoError` |
| `b64.rs` | base64url-no-padding serde adapters |
| `error.rs` | error envelope and codes |
| `version.rs` | protocol version, header names, path prefix |
| `limits.rs` | every numeric limit shared by client and server |
| `auth.rs` | registration, login, tokens, devices, TOTP, password change, recovery, account deletion |
| `sync.rs` | vault list, pull, push |
| `users.rs` | user public keys |
| `orgs.rs` | orgs, members, invites, audit log |
| `vaults.rs` | team vault creation, members, grants |
| `rotation.rs` | vault key rotation |
| `ws.rs` | `/v1/ws` messages, close codes, timing constants |
| `validate.rs` | shape checks shared by client and server (`validate_email`, `PushRequest::validate`, …) |

Common rules for every DTO:

- `#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]`; `Debug` is derived **only**
  when no field is secret. DTOs with a secret field (tokens, TOTP codes, recovery codes,
  invite/setup tokens, OPAQUE messages that carry key material) implement `Debug` by hand
  and print `[REDACTED]` for those fields (T91 §3).
- Unknown JSON fields are **ignored** on decode (no `deny_unknown_fields`), so a newer
  server can add response fields without breaking an older client. Optional fields use
  `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- Ids are `uuid::Uuid` (hyphenated lowercase strings). The client converts them to the
  T81 newtypes (`UserId`, `VaultId`, `ItemId`, `DeviceId`, `OrgId`); this crate does not
  depend on `courier-ftp-core`.
- Timestamps are `time::OffsetDateTime` serialised as RFC 3339 UTC
  (`#[serde(with = "time::serde::rfc3339")]`, `…::option` for `Option`).
- Binary fields are `Vec<u8>` with `#[serde(with = "crate::b64")]`.
- Revisions are `u64`, key versions `u32`.

#### `b64`

```rust
/// base64url without padding (RFC 4648 §5). Strict: `=` padding and the standard
/// alphabet (`+`, `/`) are rejected on decode.
pub fn encode(bytes: &[u8]) -> String;
pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError>;
pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>;
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error>;
pub mod option { /* same for Option<Vec<u8>>: null/absent <-> None */ }
```

#### `error`

```rust
/// Machine-readable error code; wire spelling in snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Conflict,      // 409 optimistic-concurrency or uniqueness conflict
    Forbidden,     // 403 authenticated but not allowed
    NotFound,      // 404 no such resource, or not visible to the caller
    RateLimited,   // 429 see retry_after_s and the Retry-After header
    Invalid,       // 400 (also 405, 413, 415, 422 bodies) malformed or unacceptable request
    Gone,          // 410 pull cursor below the GC floor
    Rotating,      // 409 vault key rotation in progress
    AuthRequired,  // 401 missing, expired or revoked credentials
    Internal,      // 500/503 unexpected server failure; clients treat it as transient
}
impl ErrorCode {
    pub const ALL: [Self; 9];
    pub const fn as_str(self) -> &'static str;
    pub const fn default_status(self) -> u16;
}

/// `{"error": {...}}` — the body of every non-2xx response.
pub struct ErrorEnvelope { pub error: ErrorBody }
pub struct ErrorBody {
    pub code: ErrorCode,
    /// Human-readable, English, never contains secrets, emails or hostnames.
    pub message: String,
    /// Seconds until a retry may succeed (only with `rate_limited`).
    pub retry_after_s: Option<u64>,
}

/// Errors of this crate's own helpers (decoding, validation).
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("malformed protocol version header")]
    MalformedVersion,
}
```

Well-known `message` values (constants, matched by clients, never translated):

| Constant | Value | Used with |
|---|---|---|
| `LOGIN_FAILED_MESSAGE` | `"invalid email or password"` | 401 from `login/finish` for unknown email, wrong password, disabled account |
| `TOTP_REQUIRED_HINT` | `"totp_required"` (prefix of the message) | 401 when TOTP is on and no code was sent |
| `TOTP_INVALID_HINT` | `"totp_invalid"` (prefix) | 401 wrong or replayed TOTP code |
| `KEY_VERSION_STALE_HINT` | `"key_version_stale"` (prefix) | 400 push/grant with an old vault key version |
| `QUOTA_EXCEEDED_MESSAGE` | `"quota exceeded"` | `PushResult.message` with `too_large` |
| `ENVELOPE_TOO_LARGE_MESSAGE` | `"envelope exceeds 1 MiB"` | `PushResult.message` with `too_large` |
| `VAULT_CAP_MESSAGE` | `"team vault size cap reached"` | `PushResult.message` with `too_large` |

#### `version`

```rust
pub const PROTO_HEADER: &str = "courier-proto";      // sent as `Courier-Proto: 1`
pub const PROTO_VERSION: u32 = 1;                    // N
pub const MIN_SUPPORTED_PROTO_VERSION: u32 = PROTO_VERSION.saturating_sub(1); // N-1
pub const REQUEST_ID_HEADER: &str = "x-request-id";
pub const API_PREFIX: &str = "/v1";
pub const USER_AGENT_PREFIX: &str = "courier-ftp/";  // client sends `courier-ftp/<semver>`

pub const fn is_supported(version: u32) -> bool;
/// Parses a `Courier-Proto` header value: ASCII decimal, 1–5 digits, no sign/space.
/// `None` (header absent) means the current version.
pub fn negotiate(header: Option<&[u8]>) -> Result<u32, ProtoError>;
```

#### `limits`

| Constant | Value | Meaning |
|---|---|---|
| `MAX_ENVELOPE_BYTES` | 1 048 576 | one item envelope (decoded bytes) |
| `MAX_BATCH_ITEMS` | 500 | changes per push |
| `MAX_BATCH_BYTES` | 8 388 608 | sum of decoded envelopes per push |
| `MAX_PULL_LIMIT` | 500 | page size cap and default |
| `MAX_ROTATION_CHUNK` | 500 | items per rotation `upload` (and ≤ `MAX_BATCH_BYTES`) |
| `ROTATION_ABANDON_SECS` | 900 | rotation counts as abandoned after 15 min |
| `BODY_LIMIT_BYTES` | 12 582 912 | HTTP request body limit (8 MiB base64 ≈ 10.7 MiB + JSON) |
| `MAX_EMAIL_LEN` | 254 | after trim |
| `MAX_DEVICE_FIELD` | 128 | device name / platform, characters |
| `MAX_NAME_ENC_BYTES` | 4 096 | sealed vault name |
| `MAX_ORG_NAME_CHARS` | 100 | org display name (1–100) |
| `MAX_AUDIT_PAGE` / `DEFAULT_AUDIT_PAGE` | 200 / 50 | audit page size |
| `INVITE_TTL_SECS` | 604 800 | org and instance invites live 7 days |
| `MAX_TOKEN_CHARS` | 64 | any opaque token string (tokens are 43 chars) |
| `RECOVERY_CODE_CHARS` | 16 | recovery code (Crockford-style base32, grouped `XXXX-XXXX-XXXX-XXXX`; 19 chars with dashes) |

#### `auth`

```rust
// POST /v1/auth/register/start
pub struct RegisterStartRequest {
    pub email: String,
    #[serde(with = "crate::b64")] pub registration_request: Vec<u8>, // OPAQUE RegistrationRequest
    pub invite_token: Option<String>,   // secret: redacted in Debug
    pub setup_token: Option<String>,    // secret: redacted in Debug
}
pub struct RegisterStartResponse {
    #[serde(with = "crate::b64")] pub registration_response: Vec<u8>,
    /// Fresh UUIDv7 proposed by the server; the client binds the bundle AAD and
    /// the self-grant signature to it and echoes it in RegisterFinishRequest.
    pub user_id: Uuid,
}
pub struct AccountKeysUpload {
    #[serde(with = "crate::b64")] pub x25519_pub: Vec<u8>,        // 32 B
    #[serde(with = "crate::b64")] pub ed25519_pub: Vec<u8>,       // 32 B
    #[serde(with = "crate::b64")] pub private_bundle_enc: Vec<u8>,  // T80 account::BUNDLE_LEN
    #[serde(with = "crate::b64")] pub recovery_bundle_enc: Vec<u8>, // T80 account::BUNDLE_LEN
    pub version: u32,                                             // 1 at registration
}
pub struct GrantUpload {
    #[serde(with = "crate::b64")] pub wrapped_vault_key: Vec<u8>, // T80 grant wire format
    #[serde(with = "crate::b64")] pub signature: Vec<u8>,         // 64 B Ed25519
    pub key_version: u32,
}
pub struct PersonalVaultUpload {
    pub id: Uuid,                                                 // the local personal vault id (kept)
    #[serde(with = "crate::b64")] pub name_enc: Vec<u8>,          // name sealed under the VK
    pub self_grant: GrantUpload,
}
pub struct DeviceInfo { pub name: String, pub platform: String }   // platform: "linux"|"macos"|"windows"|other
// POST /v1/auth/register/finish  -> SessionResponse
pub struct RegisterFinishRequest {
    pub email: String,
    pub user_id: Uuid,
    #[serde(with = "crate::b64")] pub registration_upload: Vec<u8>,
    pub account_keys: AccountKeysUpload,
    pub personal_vault: PersonalVaultUpload,
    pub device: DeviceInfo,
    pub invite_token: Option<String>,   // redacted
    pub setup_token: Option<String>,    // redacted
}

// POST /v1/auth/login/start  (same response shape for unknown emails)
pub struct LoginStartRequest { pub email: String, #[serde(with = "crate::b64")] pub credential_request: Vec<u8> }
pub struct LoginStartResponse {
    #[serde(with = "crate::b64")] pub credential_response: Vec<u8>,
    pub login_state_id: Uuid,          // server-side state, expires after 60 s
}
#[serde(rename_all = "snake_case")]
pub enum LoginPurpose { #[default] Login, Reauth }
pub struct LoginDevice {                // all optional; default = new device "unknown"
    pub id: Option<Uuid>,               // resume an existing, unrevoked device of this account
    pub name: Option<String>,
    pub platform: Option<String>,
}
// POST /v1/auth/login/finish -> SessionResponse (Login) | ReauthResponse (Reauth)
pub struct LoginFinishRequest {
    pub login_state_id: Uuid,
    #[serde(with = "crate::b64")] pub credential_finalization: Vec<u8>, // KE3
    pub totp: Option<String>,           // redacted
    #[serde(default)] pub device: LoginDevice,
    #[serde(default)] pub purpose: LoginPurpose,
}
pub struct TokenPair {                  // Debug redacts both tokens
    pub access_token: String,           // 43 chars base64url (32 random bytes)
    pub refresh_token: String,
    pub access_expires_in_s: u64,       // 900
    pub refresh_expires_in_s: u64,      // 2_592_000
}
pub struct AccountKeysView {
    #[serde(with = "crate::b64")] pub x25519_pub: Vec<u8>,
    #[serde(with = "crate::b64")] pub ed25519_pub: Vec<u8>,
    #[serde(with = "crate::b64")] pub private_bundle_enc: Vec<u8>,
    pub version: u32,
}
pub struct SessionResponse {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub tokens: TokenPair,
    pub account_keys: AccountKeysView,
    #[serde(default)] pub is_instance_admin: bool,
}
pub struct ReauthResponse { pub user_id: Uuid, pub reauth_token: String /* redacted */, pub reauth_expires_in_s: u64 /* 300 */ }
pub struct RefreshRequest { pub refresh_token: String }            // Debug: "RefreshRequest([REDACTED])"

// GET /v1/devices -> Vec<DeviceView>
pub struct DeviceView {
    pub id: Uuid,
    pub name: Option<String>,
    pub platform: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")] pub created_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")] pub last_seen_at: Option<OffsetDateTime>, // ≤ 5 min stale
    pub current: bool,
    #[serde(with = "time::serde::rfc3339::option")] pub revoked_at: Option<OffsetDateTime>,
}

// POST|DELETE /v1/account/totp
pub struct TotpRequest { pub code: Option<String> }              // redacted
pub struct TotpSetupResponse { pub otpauth_uri: String, pub secret_base32: String } // Debug redacted
pub struct TotpStatus { pub enabled: bool }

// POST /v1/account/password/start, POST /v1/account/password
pub struct PasswordStartRequest { #[serde(with = "crate::b64")] pub registration_request: Vec<u8> }
pub struct PasswordStartResponse { #[serde(with = "crate::b64")] pub registration_response: Vec<u8> }
pub struct PasswordChangeRequest {
    pub reauth_token: String,                                       // redacted
    #[serde(with = "crate::b64")] pub registration_upload: Vec<u8>,
    #[serde(with = "crate::b64")] pub private_bundle_enc: Vec<u8>,  // re-sealed under the new AKEK
    pub version: u32,                                               // current + 1
}
pub struct KeyVersionResponse { pub version: u32 }

// POST /v1/account/recovery/code, /recovery/start, /recovery
pub struct RecoveryCodeRequest { pub email: String }
pub struct RecoveryStartRequest {
    pub email: String,
    pub code: String,                                               // redacted
    #[serde(with = "crate::b64")] pub registration_request: Vec<u8>,
}
pub struct RecoveryStartResponse {
    pub user_id: Uuid,
    #[serde(with = "crate::b64")] pub recovery_bundle_enc: Vec<u8>,
    #[serde(with = "crate::b64")] pub registration_response: Vec<u8>,
    pub version: u32,                                               // current; the new one is +1
}
pub struct RecoveryFinishRequest {
    pub email: String,
    pub code: String,                                               // redacted
    #[serde(with = "crate::b64")] pub registration_upload: Vec<u8>,
    #[serde(with = "crate::b64")] pub private_bundle_enc: Vec<u8>,
    pub version: u32,
    /// Ed25519 by the account key over T80 `opaque::recovery_proof_message(
    /// user_id, version, registration_upload, private_bundle_enc)`.
    #[serde(with = "crate::b64")] pub signature: Vec<u8>,
}
// DELETE /v1/account
pub struct AccountDeleteRequest { pub reauth_token: String }      // redacted
```

#### `sync`

```rust
#[serde(rename_all = "snake_case")] pub enum VaultKind { Personal, Team }
/// Ordered: Read < Write < Manage.
#[serde(rename_all = "snake_case")] pub enum Permission { Read, Write, Manage }
impl Permission { pub const fn can_write(self) -> bool; pub const fn as_str(self) -> &'static str; pub fn parse(s: &str) -> Option<Self>; }
impl VaultKind  { pub const fn as_str(self) -> &'static str; pub fn parse(s: &str) -> Option<Self>; }

pub struct VaultGrant {
    pub key_version: u32,
    #[serde(with = "crate::b64")] pub wrapped_vault_key: Vec<u8>,
    pub wrapped_by: Uuid,
    #[serde(with = "crate::b64")] pub signature: Vec<u8>,
}
pub struct RotationView {
    pub new_key_version: u32,
    pub by: Uuid,
    #[serde(with = "time::serde::rfc3339")] pub started_at: OffsetDateTime,
    #[serde(default)] pub abandoned: bool,    // started_at older than ROTATION_ABANDON_SECS
}
// GET /v1/vaults -> Vec<VaultView>
pub struct VaultView {
    pub id: Uuid,
    pub kind: VaultKind,
    pub org_id: Option<Uuid>,                 // Some for team vaults
    #[serde(with = "crate::b64")] pub name_enc: Vec<u8>,
    pub key_version: u32,
    pub head_revision: u64,
    pub permission: Permission,               // effective permission of the caller
    pub grants: Vec<VaultGrant>,              // the caller's wraps, ascending key_version
    pub rotation: Option<RotationView>,
}
// GET /v1/vaults/{id}/changes?since=&limit=
pub struct PullQuery { #[serde(default)] pub since: u64, pub limit: Option<u32> }
pub struct RemoteItem {
    pub id: Uuid,
    pub revision: u64,
    pub key_version: u32,
    #[serde(with = "crate::b64")] pub envelope: Vec<u8>,
    #[serde(default)] pub deleted: bool,
}
pub struct PullResponse { pub items: Vec<RemoteItem>, pub head_revision: u64, pub more: bool }
// POST /v1/vaults/{id}/changes
pub struct PushChange {
    pub id: Uuid,
    pub base_revision: u64,                   // 0 = new item
    pub key_version: u32,
    #[serde(with = "crate::b64")] pub envelope: Vec<u8>,
    #[serde(default)] pub deleted: bool,
}
pub struct PushRequest { pub changes: Vec<PushChange> }
#[serde(rename_all = "snake_case")] pub enum PushStatus { Ok, Conflict, Forbidden, TooLarge }
pub struct PushResult {
    pub id: Uuid,
    pub status: PushStatus,
    pub revision: Option<u64>,                // Ok only
    pub current: Option<RemoteItem>,          // Conflict only; None = item absent on the server
    pub message: Option<String>,              // TooLarge: one of the message constants
}
pub struct PushResponse { pub results: Vec<PushResult> } // same order and length as the request
```

#### `users`

```rust
// GET /v1/users/{id}/public-keys
pub struct UserPublicKeys {
    pub user_id: Uuid,
    pub email: Option<String>,                // display only, untrusted
    #[serde(with = "crate::b64")] pub x25519_pub: Vec<u8>,
    #[serde(with = "crate::b64")] pub ed25519_pub: Vec<u8>,
}
```

#### `orgs`

```rust
/// Ordered by power: Member < Admin < Owner. Wire: lowercase.
#[serde(rename_all = "lowercase")] pub enum Role { Member, Admin, Owner }
pub struct CreateOrgRequest { pub name: String }                     // POST /v1/orgs -> OrgView
pub struct OrgView { pub id: Uuid, pub name: String, pub role: Role, #[serde(with = "time::serde::rfc3339")] pub created_at: OffsetDateTime }
pub struct MemberView { pub user_id: Uuid, pub email: String, pub role: Role }
pub struct UpdateMemberRequest { pub role: Role }                    // PATCH /v1/orgs/{id}/members/{user}
pub struct CreateInviteRequest { pub email: Option<String>, pub role: Role } // POST /v1/orgs/{id}/invites
pub struct InviteCreated {
    pub id: Uuid, pub org_id: Uuid, pub email: Option<String>, pub role: Role,
    #[serde(with = "time::serde::rfc3339")] pub expires_at: OffsetDateTime,
    pub link: Option<String>,   // `<public_url>/invite/<token>`; secret: Debug redacted
    pub emailed: bool,
}
pub struct InviteAccepted { pub org_id: Uuid, pub role: Role }       // POST /v1/invites/{token}/accept
pub struct AuditQuery { pub before: Option<i64>, pub limit: Option<u32> }
pub struct AuditEventView {
    pub id: i64, pub kind: String, pub actor: Option<Uuid>, pub target: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")] pub at: OffsetDateTime,
    pub meta: serde_json::Value,   // object with ids, roles, counts only
}
pub struct AuditPage { pub events: Vec<AuditEventView>, pub next_before: Option<i64> }
/// Audit kinds (T89 §audit): string constants in `orgs::audit_kind`.
pub mod audit_kind {
    pub const MEMBER_ADDED: &str = "member.added";
    pub const MEMBER_REMOVED: &str = "member.removed";
    pub const MEMBER_ROLE_CHANGED: &str = "member.role_changed";
    pub const INVITE_SENT: &str = "invite.sent";
    pub const INVITE_ACCEPTED: &str = "invite.accepted";
    pub const VAULT_CREATED: &str = "vault.created";
    pub const VAULT_GRANTED: &str = "vault.member_granted";
    pub const VAULT_REVOKED: &str = "vault.member_revoked";
    pub const VAULT_ROTATED: &str = "vault.rotated";
    pub const ITEMS_PUSHED: &str = "vault.items_pushed";   // meta: {"vault_id", "item_ids": [..≤500]}
    pub const DEVICE_ADDED: &str = "device.added";
    pub const DEVICE_REVOKED: &str = "device.revoked";
}
```

#### `vaults`

```rust
pub struct CreateVaultRequest {                  // POST /v1/vaults -> VaultView
    pub id: Uuid, pub org_id: Uuid,
    #[serde(with = "crate::b64")] pub name_enc: Vec<u8>,
    pub self_grant: GrantUpload,                 // creator gets `manage`
}
pub struct GrantRequest {                        // PUT /v1/vaults/{id}/members/{user}
    pub permission: Permission,
    pub key_version: u32,
    #[serde(with = "crate::b64")] pub wrapped_vault_key: Vec<u8>,
    #[serde(with = "crate::b64")] pub signature: Vec<u8>,
}
pub struct VaultMemberView {
    pub user_id: Uuid, pub email: Option<String>, pub org_role: Role,
    pub permission: Option<Permission>,          // explicit grant; None = no grant
    pub has_key: bool,                           // holds a grant for the current key_version
    pub granted_by: Option<Uuid>,
}
impl VaultMemberView { /// Explicit permission, or Manage for org owner/admin.
    pub fn effective(&self) -> Option<Permission>; }
pub struct VaultMembersView {                    // GET /v1/vaults/{id}/members (untrusted on the client)
    pub vault_id: Uuid, pub org_id: Uuid, pub key_version: u32,
    pub created_by: Option<Uuid>, pub members: Vec<VaultMemberView>,
}
pub struct OrgVaultView {                        // GET /v1/orgs/{id}/vaults
    pub id: Uuid, #[serde(with = "crate::b64")] pub name_enc: Vec<u8>,
    pub key_version: u32, pub permission: Permission, pub has_key: bool,
}
```

#### `rotation`

```rust
pub struct RotatedItem { pub id: Uuid, #[serde(with = "crate::b64")] pub envelope: Vec<u8> }
pub struct RotationGrant {
    pub user: Uuid,
    #[serde(with = "crate::b64")] pub wrapped: Vec<u8>,
    #[serde(with = "crate::b64")] pub signature: Vec<u8>,
    pub permission: Permission,                  // the member's permission, carried over
}
/// POST /v1/vaults/{id}/rotate, tagged by "action".
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RotateRequest {
    Begin { new_key_version: u32 },
    Upload { items: Vec<RotatedItem> },
    Commit { wrapped_keys: Vec<RotationGrant> },
}
pub struct RotateResponse {
    pub key_version: u32, pub new_key_version: u32, pub head_revision: u64,
    pub staged: u64,
    #[serde(default)] pub resumed: bool,
    #[serde(default)] pub replaced_abandoned: bool,
}
```

#### `ws`

```rust
pub const WS_PATH: &str = "/ws";                 // under API_PREFIX
pub const CLOSE_AUTH_REQUIRED: u16 = 4401;
pub const CLOSE_PING_TIMEOUT: u16 = 4408;
pub const CLOSE_INTERNAL: u16 = 1011;
pub const AUTH_TIMEOUT_SECS: u64 = 5;
pub const PING_INTERVAL_SECS: u64 = 30;
pub const MAX_MISSED_PONGS: u32 = 2;
pub const MAX_CLIENT_MESSAGE_BYTES: usize = 16 * 1024;

#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg { Auth { token: String }, Ping, Pong }   // Debug redacts the token
#[serde(rename_all = "snake_case")] pub enum AccessChange { Granted, Revoked, Rotated }
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    VaultChanged { vault_id: Uuid, head_revision: u64 },
    VaultAccess { vault_id: Uuid, change: AccessChange },
    AccountChanged { key_version: u32 },
    Ping,
    Pong,
    /// Any `type` this client version does not know; ignored by receivers.
    #[serde(other)] Unknown,
}
```

#### `validate`

```rust
/// Trims, lower-cases (ASCII + Unicode simple lowercase), checks 3..=254 chars,
/// exactly one '@', non-empty local and domain parts, no whitespace/control chars.
/// Returns the normalized email (also the OPAQUE credential identifier input, T80).
pub fn normalize_email(raw: &str) -> Result<String, ProtoError>;
/// Device name/platform: trimmed, ≤ MAX_DEVICE_FIELD chars, no control chars;
/// empty → "unknown".
pub fn device_field(raw: Option<&str>) -> Result<String, ProtoError>;
impl PushRequest {
    /// ≤ MAX_BATCH_ITEMS changes, Σ envelope ≤ MAX_BATCH_BYTES, no duplicate ids,
    /// no nil ids. Per-envelope size is NOT checked here (it is a per-item
    /// `too_large` result, not a request error).
    pub fn validate(&self) -> Result<(), ProtoError>;
}
impl RotateRequest { pub fn validate(&self) -> Result<(), ProtoError>; } // chunk ≤ 500 items / 8 MiB
pub fn validate_org_name(raw: &str) -> Result<String, ProtoError>;     // trimmed, 1..=100 chars
```

### Behaviour

**Endpoint index.** The full list; method/path/body types are fixed here, status codes and
semantics in the owning task.

| Method | Path | Request | 2xx response | Owner |
|---|---|---|---|---|
| POST | `/v1/auth/register/start` | `RegisterStartRequest` | 200 `RegisterStartResponse` | T84 |
| POST | `/v1/auth/register/finish` | `RegisterFinishRequest` | 200 `SessionResponse` | T84 |
| POST | `/v1/auth/login/start` | `LoginStartRequest` | 200 `LoginStartResponse` | T84 |
| POST | `/v1/auth/login/finish` | `LoginFinishRequest` | 200 `SessionResponse` / `ReauthResponse` | T84 |
| POST | `/v1/auth/refresh` | `RefreshRequest` | 200 `TokenPair` | T84 |
| POST | `/v1/auth/logout` | — | 204 | T84 |
| GET | `/v1/devices` | — | 200 `Vec<DeviceView>` | T84 |
| DELETE | `/v1/devices/{id}` | — | 204 | T84 |
| POST | `/v1/account/totp` | `TotpRequest` | 200 `TotpSetupResponse` (no code) / `TotpStatus` (code) | T84 |
| DELETE | `/v1/account/totp` | `TotpRequest` | 204 | T84 |
| POST | `/v1/account/password/start` | `PasswordStartRequest` | 200 `PasswordStartResponse` | T84 |
| POST | `/v1/account/password` | `PasswordChangeRequest` | 200 `KeyVersionResponse` | T84 |
| POST | `/v1/account/recovery/code` | `RecoveryCodeRequest` | 202 (always) | T84 |
| POST | `/v1/account/recovery/start` | `RecoveryStartRequest` | 200 `RecoveryStartResponse` | T84 |
| POST | `/v1/account/recovery` | `RecoveryFinishRequest` | 200 `KeyVersionResponse` | T84 |
| DELETE | `/v1/account` | `AccountDeleteRequest` | 204 | T84 |
| GET | `/v1/vaults` | — | 200 `Vec<VaultView>` | T85 |
| GET | `/v1/vaults/{id}/changes` | query `PullQuery` | 200 `PullResponse` | T85 |
| POST | `/v1/vaults/{id}/changes` | `PushRequest` | 200 `PushResponse` | T85 |
| GET | `/v1/ws` | WebSocket upgrade | 101 | T85 |
| GET | `/v1/users/{id}/public-keys` | — | 200 `UserPublicKeys` | T89 |
| POST / GET | `/v1/orgs` | `CreateOrgRequest` / — | 201 `OrgView` / 200 `Vec<OrgView>` | T89 |
| GET | `/v1/orgs/{id}/members` | — | 200 `Vec<MemberView>` | T89 |
| PATCH / DELETE | `/v1/orgs/{id}/members/{user}` | `UpdateMemberRequest` / — | 204 | T89 |
| GET | `/v1/orgs/{id}/vaults` | — | 200 `Vec<OrgVaultView>` | T89 |
| POST | `/v1/orgs/{id}/invites` | `CreateInviteRequest` | 201 `InviteCreated` | T89 |
| POST | `/v1/invites/{token}/accept` | — | 200 `InviteAccepted` | T89 |
| GET | `/v1/orgs/{id}/audit` | query `AuditQuery` | 200 `AuditPage` | T89 |
| POST | `/v1/vaults` | `CreateVaultRequest` | 201 `VaultView` | T89 |
| GET | `/v1/vaults/{id}/members` | — | 200 `VaultMembersView` | T89 |
| PUT / DELETE | `/v1/vaults/{id}/members/{user}` | `GrantRequest` / — | 204 | T89 |
| POST | `/v1/vaults/{id}/rotate` | `RotateRequest` | 200 `RotateResponse` | T89 |
| GET | `/healthz`, `/readyz`, `/metrics` | — | 200 / 503 | T86 |

**Conventions (normative for T84–T89):**

1. HTTPS + JSON (`Content-Type: application/json`), UTF-8. Auth: `Authorization: Bearer
   <access token>` on every `/v1` endpoint except `auth/register/*`, `auth/login/*`,
   `auth/refresh` and `account/recovery*` (invite acceptance does need a bearer token: the
   invitee must be logged in).
2. Every request carries `Courier-Proto: 1`; every response echoes `Courier-Proto: 1`.
   `negotiate`: header absent → current version; non-digit, empty, > 5 digits →
   `400 invalid` "malformed Courier-Proto header"; outside `[N-1, N]` → `400 invalid`
   "unsupported protocol version X (server supports N-1..N)". The client treats this
   400 as "update courier-ftp" (T87).
3. `x-request-id`: client may send 1–128 chars of `[A-Za-z0-9-]`; otherwise the server
   generates a UUIDv7. Always echoed in the response.
4. Every non-2xx response body is an `ErrorEnvelope` (also router-level 404/405/413/408 and
   panics → `internal`). `429` also sets `Retry-After: <retry_after_s>`.
5. Pull ordering: `items` sorted by `revision` ascending, all `> since`; when `more ==
   false` the client may set its cursor to `head_revision`, otherwise to the last item's
   revision.
6. Revisions are per-vault, gap-free, start at 1; `0` means "nothing yet".
7. WebSocket: text frames with one JSON object each; first client frame must be
   `ClientMsg::Auth` within 5 s; receivers ignore unknown `type`s (`ServerMsg::Unknown`).

**Versioning.** Adding an optional request field or any response field is compatible (no
version bump). Removing/renaming a field, changing a type, or changing semantics bumps
`PROTO_VERSION`; the server then keeps N-1 handlers for one release. Server upgrades go
first (T86 docs).

### Data formats and configuration

Exact JSON of representative DTOs (snapshots must match byte-for-byte after
`serde_json::to_string_pretty`):

```json
{"error":{"code":"rate_limited","message":"too many login attempts","retry_after_s":12}}
```
```json
{"changes":[{"id":"0192f0c4-7a10-7c3e-9a55-0f6b2c1d3e4f","base_revision":0,"key_version":1,"envelope":"AQAAAAE…","deleted":false}]}
```
```json
{"results":[{"id":"0192f0c4-…","status":"conflict","current":{"id":"0192f0c4-…","revision":7,"key_version":1,"envelope":"AQ","deleted":true}},
            {"id":"0192f0c5-…","status":"too_large","message":"quota exceeded"}]}
```
```json
{"type":"vault_changed","vault_id":"0192f0c4-…","head_revision":42}
{"type":"auth","token":"…43 chars…"}
{"action":"begin","new_key_version":3}
```

No settings keys (pure library).

### Errors

This crate only produces `ProtoError` from `negotiate`, `normalize_email`, `device_field`,
`validate_org_name`, `PushRequest::validate`, `RotateRequest::validate`. The server maps
`ProtoError::Invalid` → `400 invalid` with the error's text; the client maps it to
`SyncError::Protocol` (T87). JSON decode failures are serde errors and become `400 invalid`
on the server and `SyncError::Protocol("malformed server response")` on the client.

### Security and logging

- Secret-bearing fields (listed above with "redacted") never appear in `Debug`. A unit test
  formats every such DTO with canary values and asserts the canary is absent (T91 §3, §5).
- No `Display` impl prints a DTO.
- Decoders are total: any byte input either decodes or returns an error, never panics; the
  fuzz target `sync_dto_decode` (T91 §7) decodes the input as each request and response
  type, `ServerMsg`, `ClientMsg` and `RotateRequest`, and runs every `validate` function.
- Not applicable: logging (the crate logs nothing).

## Implementation steps

1. Crate skeleton: `Cargo.toml` (deps: `serde`, `serde_json`, `base64`, `uuid` with
   `serde`, `time` with `serde`/`formatting`/`parsing`, `thiserror`,
   `courier-ftp-crypto`; dev: `insta` with `json`, `proptest`), `#![forbid(unsafe_code)]`
   is not used (workspace lint `unsafe_code = "deny"` is inherited, T91 §2), `lib.rs`,
   `b64.rs`, `error.rs`, `version.rs`, `limits.rs` with tests.
2. `auth.rs` with manual `Debug` impls and redaction tests.
3. `sync.rs`, `users.rs`, `validate.rs` (`normalize_email`, `device_field`,
   `PushRequest::validate`).
4. `orgs.rs`, `vaults.rs`, `rotation.rs` (+ `RotateRequest::validate`,
   `validate_org_name`).
5. `ws.rs` with the `Unknown` fallback.
6. JSON snapshot tests for every DTO (`tests/snapshots.rs`), round-trip property tests,
   the fuzz body `fuzz_decode_all(data: &[u8])` (public, `#[doc(hidden)]`).
7. Layering check entry (T00 `check-layering.py`, T76 `workspace_metadata.rs`): this crate
   has no tokio/axum/reqwest/rusqlite/ratatui/crossterm/clap in its normal dependency graph.

## Acceptance criteria

- [ ] AC1 Every DTO listed above exists with the exact field names, and its JSON matches the
  committed `insta` snapshot (`cargo test -p courier-ftp-proto` passes, no pending snapshots).
- [ ] AC2 Binary fields encode as base64url without padding; padded or standard-alphabet input
  is rejected on decode.
- [ ] AC3 `negotiate` accepts absent/`1`/`0` and rejects `2`, `-1`, `01x`, `""`, `123456` with
  the documented errors.
- [ ] AC4 Every secret-bearing DTO prints no secret in `{:?}` (canary test).
- [ ] AC5 `PushRequest::validate` rejects 501 changes, 8 MiB + 1 byte total, duplicate ids and
  nil ids, and accepts exactly 500 changes / exactly 8 MiB.
- [ ] AC6 Unknown JSON fields are ignored on every response type; an unknown WS `type`
  decodes to `ServerMsg::Unknown`.
- [ ] AC7 `cargo tree -p courier-ftp-proto -e normal` contains none of `tokio`, `axum`,
  `reqwest`, `rusqlite`, `sqlx-core`, `ratatui`, `crossterm`, `clap` (checked by the
  `layering` CI job).
- [ ] AC8 `fuzz_decode_all` never panics (property test with 10 000 random inputs) and the
  `sync_dto_decode` fuzz target builds in the `fuzz` CI job.
- [ ] AC9 CI gates `fmt`, `clippy`, `docs`, `deny` pass.

## Tests

### Unit tests
- `b64::tests::no_padding_url_alphabet` — `[0xfb,0xff]` ↔ `"-_8"`; `"-_8="` and `"+/8"` fail (AC2).
- `error::tests::codes_serialize_as_spec_strings` — every `ErrorCode::ALL` ↔ `as_str()`;
  `default_status` table (AC1).
- `error::tests::retry_after_omitted_when_none` (AC1).
- `version::tests::negotiate_table` — table of header inputs → result (AC3).
- `auth::tests::login_finish_defaults` — missing `device`/`purpose`/`totp` default to
  `LoginDevice::default()`, `Login`, `None` (AC1).
- `auth::tests::secrets_redacted_in_debug` — `TokenPair`, `RefreshRequest`,
  `RegisterStartRequest`, `RegisterFinishRequest`, `LoginFinishRequest`, `ReauthResponse`,
  `TotpRequest`, `TotpSetupResponse`, `PasswordChangeRequest`, `RecoveryStartRequest`,
  `RecoveryFinishRequest`, `AccountDeleteRequest`, `InviteCreated`, `ClientMsg::Auth`
  built with `CANARY-TOKEN-…` values; `format!("{:?}")` does not contain `CANARY` (AC4).
- `validate::tests::push_limits` — 500 ok / 501 rejected, 8 MiB ok / +1 rejected,
  duplicate id, nil id (AC5).
- `validate::tests::normalize_email_cases` — `"  Alice@Example.COM "` → `"alice@example.com"`;
  rejects `""`, `"a"`, `"a@"`, `"@b"`, `"a@b@c"`, 255 chars, `"a b@c"`, `"a\u{7}@b"`.
- `validate::tests::device_field_rules` — empty → `"unknown"`, 129 chars rejected, control
  chars rejected.
- `ws::tests::unknown_type_is_ignored` — `{"type":"share_join_request",…}` →
  `ServerMsg::Unknown` (AC6).
- `sync::tests::permission_order_and_can_write` — `Read < Write < Manage`; only `Write`,
  `Manage` can write.
- `sync::tests::unknown_fields_ignored` — `VaultView` with an extra `"foo"` field decodes (AC6).

### Property / fuzz tests
- `props::dto_roundtrip` — proptest strategies for every DTO: `from_str(to_string(x)) == x` (AC1).
- `props::fuzz_body_never_panics` — 10 000 arbitrary byte strings through `fuzz_decode_all` (AC8).
- Fuzz target `fuzz/fuzz_targets/sync_dto_decode.rs` calls `fuzz_decode_all` (T91 §7) (AC8).

### Snapshot tests
- `tests/snapshots.rs::every_dto_json` — one `insta::assert_snapshot!` per DTO with fixed
  ids (`Uuid::from_u128`), fixed timestamps and short byte arrays (AC1). Not a UI task:
  no terminal snapshots.

### Integration tests
- Not applicable in this crate; T84/T85 handler tests exercise the DTOs over HTTP.
- `layering` CI job (T00) asserts AC7 via `cargo tree`.

### End-to-end tests
- Not applicable (covered by the sync scenarios in T76/T88).

## Out of scope

- HTTP client and server code (T84, T85, T87).
- Terminal-share DTOs from sverb (no such feature in courier-ftp).
- CBOR item bodies and envelopes (T80, T81): `envelope` is opaque bytes here.

## Open questions

None.
