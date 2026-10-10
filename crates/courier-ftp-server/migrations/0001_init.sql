-- courier-ftp-server initial schema (T84; adapted from sverb's server schema).
--
-- Never edit this file once released: sqlx checksums every migration. Later
-- changes go into new numbered files (add them to `db::MIGRATIONS`).
--
-- Accounts and login (T84):
--   * server_secrets: AEAD-sealed server-side secrets (OPAQUE ServerSetup and
--     the startup canary), key = HKDF(COURIER_SERVER_SECRET);
--   * users (email CITEXT), account_keys, devices, auth_tokens (SHA-256 of
--     the token only, rotation `family`, `used_at` for reuse detection);
--   * login_states: the OPAQUE server login state between login/start and
--     login/finish (60 s TTL), in the database so the two requests may hit
--     different replicas; `user_id` is NULL for unknown emails (dummy record);
--   * reauth_tokens (5 min proofs of a fresh login), recovery_codes (one-time
--     codes gating the recovery bundle), both SHA-256 hashes only;
--   * settings: `registration_mode` and the one-time `setup_token_hash`;
--   * invites (instance invites, `org_id IS NULL`; org invites are T89);
--   * audit_events (metadata only, never item data).
--
-- Vault tables (T85) are here too because registration already creates the
-- personal vault with its self-grant. orgs / org_members exist so that
-- shared vaults (T89) can reference them.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE server_secrets (
  name TEXT PRIMARY KEY,                  -- 'opaque_server_setup', 'secret_check'
  value_enc BYTEA NOT NULL                -- nonce || XChaCha20-Poly1305, AAD = name
);

CREATE TABLE users (
  id UUID PRIMARY KEY,
  email CITEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  is_instance_admin BOOLEAN NOT NULL DEFAULT false,
  opaque_record BYTEA NOT NULL,           -- OPAQUE registration record
  totp_secret_enc BYTEA,                  -- sealed with the server-secret key
  totp_pending_enc BYTEA,                 -- TOTP secret awaiting its confirmation code
  totp_last_step BIGINT,                  -- last accepted TOTP step (replay protection)
  disabled BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE account_keys (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  x25519_pub BYTEA NOT NULL,
  ed25519_pub BYTEA NOT NULL,
  private_bundle_enc BYTEA NOT NULL,      -- sealed under the AKEK (client side)
  recovery_bundle_enc BYTEA,              -- sealed under the recovery key
  version INT NOT NULL
);

CREATE TABLE devices (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  name TEXT,
  platform TEXT,
  created_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX devices_user_id ON devices (user_id);

CREATE TABLE auth_tokens (
  token_hash BYTEA PRIMARY KEY,           -- SHA-256 of the 256-bit random token
  device_id UUID REFERENCES devices(id),
  kind TEXT CHECK (kind IN ('access','refresh')),
  expires_at TIMESTAMPTZ NOT NULL,
  family UUID NOT NULL,                   -- refresh-token rotation family
  used_at TIMESTAMPTZ                     -- set when a refresh token is rotated
);
CREATE INDEX auth_tokens_device_id ON auth_tokens (device_id);
CREATE INDEX auth_tokens_family ON auth_tokens (family);

CREATE TABLE login_states (
  id UUID PRIMARY KEY,
  user_id UUID,
  state_enc BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX login_states_expires_at ON login_states (expires_at);

CREATE TABLE reauth_tokens (
  token_hash BYTEA PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE recovery_codes (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0
);

CREATE TABLE orgs (id UUID PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ);
CREATE TABLE org_members (
  org_id UUID REFERENCES orgs(id),
  user_id UUID REFERENCES users(id),
  role TEXT CHECK (role IN ('owner','admin','member')),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE vaults (
  id UUID PRIMARY KEY,                    -- client-generated (UUIDv7): local ids survive upload
  kind TEXT CHECK (kind IN ('personal','shared')) NOT NULL,
  owner_user_id UUID,
  org_id UUID REFERENCES orgs(id),
  key_version INT NOT NULL DEFAULT 1,
  head_revision BIGINT NOT NULL DEFAULT 0,
  gc_floor_revision BIGINT NOT NULL DEFAULT 0,  -- tombstones at or below this were purged
  rotation JSONB,                         -- non-NULL while a key rotation is in progress
  name_enc BYTEA NOT NULL,                -- vault name sealed under the vault key
  CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL AND org_id IS NULL))
);

CREATE TABLE vault_members (
  vault_id UUID REFERENCES vaults(id),
  user_id UUID REFERENCES users(id),
  permission TEXT CHECK (permission IN ('read','write','manage')),
  key_version INT NOT NULL,
  wrapped_vault_key BYTEA NOT NULL,       -- HPKE to the member's X25519 key
  wrapped_by UUID NOT NULL,               -- granting user (signature verification)
  signature BYTEA NOT NULL,               -- Ed25519 by the granter (canon::sig_grant)
  PRIMARY KEY (vault_id, user_id, key_version)
);
CREATE INDEX vault_members_user_id ON vault_members (user_id);

CREATE TABLE items (
  vault_id UUID REFERENCES vaults(id),
  id UUID NOT NULL,
  revision BIGINT NOT NULL,
  key_version INT NOT NULL,
  envelope BYTEA NOT NULL,                -- always present; tombstones carry the delete stamp
  deleted BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL,
  updated_by_device UUID,
  PRIMARY KEY (vault_id, id)
);
CREATE UNIQUE INDEX items_vault_rev ON items (vault_id, revision);

CREATE TABLE items_rotation_staging (     -- re-encrypted items uploaded during a key rotation
  vault_id UUID,
  id UUID,
  key_version INT,
  envelope BYTEA NOT NULL,
  PRIMARY KEY (vault_id, id)
);

CREATE TABLE invites (
  id UUID PRIMARY KEY,
  org_id UUID,                            -- NULL: instance invite (registration)
  email CITEXT,
  role TEXT,
  token_hash BYTEA,
  created_by UUID,
  expires_at TIMESTAMPTZ,
  accepted_at TIMESTAMPTZ
);

CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY,
  org_id UUID,
  actor_user_id UUID,
  kind TEXT,
  target UUID,
  at TIMESTAMPTZ NOT NULL,
  meta JSONB                              -- never contains plaintext item data
);

--   registration_mode  'open' | 'invite-only' | 'closed'
--   setup_token_hash   hex SHA-256 of the one-time setup token; present only
--                      until the first account registers with it.
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO settings (key, value) VALUES ('registration_mode', 'invite-only');
