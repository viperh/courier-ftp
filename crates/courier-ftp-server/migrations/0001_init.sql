-- courier-ftp-server base schema (T84; also used by T85 and T89).
--
-- Never edit this file once released: the migration runner stores its SHA-256
-- and refuses to start when it changes. Later changes go into new numbered files.

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
