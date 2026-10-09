# T83 — Sync protocol types

**Phase:** H Sync · **Depends on:** T80 · **Crate:** new `courier-ftp-proto` · **Decisions:** D12, D13
**Reference:** sverb `crates/sverb-proto/src/{auth,sync,vaults,orgs,rotation,ws,version,b64}.rs`.

## Goal

The wire format shared by the client (T87/T88) and the server (T84–T86): request and
response structs, error shape, limits and protocol version. Serde only, no I/O.

## Scope

1. **Conventions**: HTTPS + JSON under `/v1`; binary fields base64url without padding
   (`b64` helper with serde adapters); header `Courier-Proto: 1` (server accepts N and
   N-1); `x-request-id` echoed back.
2. **Error body**: `{"error": {"code": "conflict|forbidden|not_found|rate_limited|invalid|gone|rotating|auth_required|internal", "message": "...", "retry_after_s": 5?}}`; 429 also sets `Retry-After`.
3. **Auth DTOs**: `RegisterStartRequest/Response`, `RegisterFinishRequest { email, user_id, registration_upload, account_keys: AccountKeysUpload { x25519_pub, ed25519_pub, private_bundle_enc, recovery_bundle_enc, version }, personal_vault: PersonalVaultUpload { id, name_enc, self_grant }, device: DeviceInfo { name, platform }, invite_token?, setup_token? }`, `LoginStartRequest/Response { credential_response, login_state_id }`, `LoginFinishRequest { login_state_id, credential_finalization, totp?, device: LoginDevice, purpose: Login | Reauth }`, `TokenPair`, refresh/logout, password change, recovery code/start/finish, TOTP enable/disable.
4. **Devices**: `DeviceSummary { id, name, platform, created_at, last_seen_at, current }`.
5. **Sync DTOs**:
   - `PullResponse { items: Vec<RemoteItem { id, revision, key_version, envelope, deleted }>, head_revision, more }`.
   - `PushRequest { changes: Vec<PushChange { id, base_revision, key_version, envelope, deleted }> }` → `Vec<PushResult { id, status: ok|conflict|forbidden|too_large, revision?, current?: RemoteItem, message? }>`.
   - Limits as constants: `MAX_PULL_LIMIT = 500`, `MAX_PUSH_ITEMS = 500`, `MAX_PUSH_BYTES = 8 MiB`, `MAX_ENVELOPE = 1 MiB`.
6. **Vaults / orgs / rotation / invites** DTOs for T89.
7. **WebSocket messages** (`ws`): client `auth { token }` (first message, within 5 s); server `vault_changed { vault_id, head_revision }`, `vault_access { vault_id, change: granted|revoked|rotated }`, `account_changed { key_version }`, `ping`/`pong`; close codes 4401 (auth failed) and 4408 (ping timeout).

## Acceptance criteria

- [ ] All DTOs serialise to the documented JSON (snapshot tests with `insta`).
- [ ] Version negotiation helper rejects unsupported versions with a clear error.
- [ ] No dependency on tokio, axum or reqwest.

## Tests

- JSON snapshot tests for every DTO.
