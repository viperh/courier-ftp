# T84 — Sync server: accounts, login and devices

**Phase:** H Sync · **Depends on:** T80, T83 · **Crate:** new `courier-ftp-server` (binary) · **Decisions:** D12, D13
**Reference:** sverb `crates/sverb-server/src/{app,auth/*,routes/*,registration,secrets,middleware/rate_limit}.rs`, `migrations/server/0001*.sql`.

## Goal

The courier-ftp sync server's account side: OPAQUE registration and login, tokens,
devices, recovery, TOTP and instance setup. The server never learns the master
password or any plaintext.

## Scope

1. **Stack**: axum 0.8 (+ `ws`), axum-server (built-in rustls TLS, optional),
   tower-http (compression, CORS off by default, body limit 12 MiB, timeout, trace),
   PostgreSQL 15+ via `sqlx-core` + `sqlx-postgres` (not the `sqlx` facade, avoids a
   libsqlite3 link conflict with the client's rusqlite), migrations embedded with
   `include_str!`. In-memory store implementations for tests.
2. **Tables**: `server_secrets`, `users` (email CITEXT unique, `opaque_record`,
   `totp_secret_enc`, `disabled`, `is_instance_admin`), `account_keys` (pub keys,
   `private_bundle_enc`, `recovery_bundle_enc`, `version`), `devices`, `auth_tokens`
   (`token_hash`, `device_id`, `kind`, `expires_at`, `family`, `used_at`),
   `login_states` (AEAD-sealed, 60 s TTL — lets login start/finish hit different
   replicas), `reauth_tokens`, `recovery_codes`, `settings` (`registration_mode`,
   `setup_token_hash`), `audit_events`.
3. **Server secret**: env `COURIER_SERVER_SECRET`; `HKDF(secret, "courier-ftp/server-secret/v1")`
   encrypts the OPAQUE `ServerSetup` and TOTP seeds (row name as AAD). A canary row is
   checked at start — wrong secret ⇒ refuse to start.
4. **Endpoints** (`/v1`):
   - `POST /auth/register/start`, `/auth/register/finish`
   - `POST /auth/login/start`, `/auth/login/finish` (purpose `Login` or `Reauth` → 5-minute reauth token)
   - `POST /auth/refresh`, `/auth/logout`
   - `DELETE /account`; `POST|DELETE /account/totp`
   - `POST /account/password/start`, `/account/password` (atomically replaces OPAQUE record + re-sealed bundle, version + 1, revokes other devices' tokens, sends WS `account_changed`)
   - `POST /account/recovery/code` (emailed via SMTP or issued by admin CLI), `/account/recovery/start`, `/account/recovery` (new record + bundle signed with the account Ed25519 key; revokes all devices)
   - `GET /devices`, `DELETE /devices/{id}`
5. **OPAQUE**: suite from T80; credential id = lower-cased trimmed email; unknown emails
   get a dummy KE2 (no account enumeration).
6. **Tokens**: 32 random bytes, stored as SHA-256; access 15 min, refresh 30 days,
   single-use refresh with rotation; reuse of a used refresh token revokes the whole
   token family.
7. **Registration modes**: `open`, `invite-only` (default), `closed`. While no user
   exists, every start logs a one-time **setup token** at warn level (only its hash is
   stored); the first registration with it becomes the instance admin.
8. **Rate limiting** (`governor`): login 5/min per email and 50/min per IP;
   registration and recovery similar. Client IP from `X-Forwarded-For` only when the
   peer is in `COURIER_TRUSTED_PROXIES`.
9. **TOTP** (optional 2FA, `totp-rs`) on login.

## Acceptance criteria

- [ ] Register → login → refresh → logout works end-to-end with the in-memory and the Postgres store.
  *Status: verified against the in-memory store (in-process server over HTTP,
  `tests/auth.rs`); the Postgres variants (`*_pg`) are written and run in CI's
  `server-db` job, but could not be run locally (no PostgreSQL/Docker).*
- [x] Refresh-token reuse revokes the family.
- [x] Unknown email login is indistinguishable in shape and timing class from a wrong password.
- [x] Wrong server secret refuses to start.
- [x] Rate limits return 429 with `Retry-After`.

## Tests

- Handler tests against the in-memory store; Postgres tests behind `COURIER_SERVER_PG_TEST=1` (Docker in CI).
