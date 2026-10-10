# T86 — Sync server: configuration, admin CLI and deployment

**Phase:** H Sync · **Depends on:** T84, T85 · **Crate:** `courier-ftp-server` · **Decisions:** D12
**Related (integrates with, not blocking):** T00
**Reference:** sverb `crates/sverb-server/src/config.rs`, `deploy/`, `docs/self-hosting.md`.

## Goal

Make the server easy to self-host and operate.

## Scope

1. **Config**: `courier-ftp-server.toml` plus env vars (env wins): `DATABASE_URL`,
   `COURIER_BIND` (default `0.0.0.0:8080`), `COURIER_PUBLIC_URL`,
   `COURIER_SERVER_SECRET`, `COURIER_TLS_CERT` / `COURIER_TLS_KEY` (optional built-in
   TLS), `SMTP_*` (invites, recovery codes), `COURIER_STORAGE_QUOTA_MIB`,
   `COURIER_TRUSTED_PROXIES`, `COURIER_METRICS_TOKEN` / `COURIER_METRICS_BIND`,
   `COURIER_GC_INTERVAL_HOURS`. Validation with clear errors at startup.
2. **Admin CLI** (same binary): `serve [--migrate]`, `migrate`,
   `admin user list|create|disable|recovery-code`, `admin invite`,
   `admin registration open|invite-only|closed`, `admin gc`, `healthcheck`.
3. **Ops endpoints** (outside `/v1`): `/healthz` (process up), `/readyz` (DB reachable),
   `/metrics` (Prometheus, token-protected or separate bind).
4. **Deployment**:
   - `deploy/Dockerfile.server`: static musl build, distroless non-root image.
   - `deploy/docker-compose.yml`: `postgres:16` + server with `serve --migrate`.
   - Image published to `ghcr.io/viperh/courier-ftp-server` (amd64 + arm64) by the CD workflow; static Linux binaries attached to releases.
5. **Docs** `docs/self-hosting.md`: quick start, setup-token bootstrap, config table,
   TLS behind Caddy/nginx (with WebSocket upgrade) or built-in, multiple replicas,
   backups ("back up the database **and** `COURIER_SERVER_SECRET`"), upgrades.
6. Logging: structured JSON logs; never log tokens, emails at info level only hashed.

## Acceptance criteria

- [ ] `docker compose up` gives a working server; setup token appears in logs.
- [ ] `healthcheck` subcommand usable as Docker HEALTHCHECK.
- [ ] Image builds for amd64 and arm64 in CI.
- [ ] Self-hosting doc followed from scratch works (manual check recorded).

*Status: everything here is written but none of the Docker parts could be run
locally (no Docker daemon access). Verified locally: config parsing
(`tests/config.rs`), the CLI grammar (`cli` unit tests), `healthcheck` as a
subcommand of the real binary against an in-process server
(`tests/ops.rs`), `/metrics`, `/healthz`, `/readyz` (503 without a database).
Unverified until CI runs: `deploy/Dockerfile.server` and the compose stack
(CI job `server-docker`: build, compose up, `/healthz`, `/readyz`, setup token
in the logs, healthcheck in the container, non-root user), the amd64 + arm64
image (CD job `image`, smoke-tested per architecture, pushed only on tags),
the static server binaries in the release archives, and the admin
operations on PostgreSQL (`admin_operations_pg`, CI `server-db`). The
from-scratch walk-through with a real client needs T87/T88.*

## Tests

- Config parsing tests; container smoke test in CI.
