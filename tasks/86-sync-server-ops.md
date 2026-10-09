# T86 — Sync server: configuration, admin CLI and deployment

**Phase:** H Sync · **Milestone:** M7 · **Depends on:** T84, T85 · **Crate(s):** `courier-ftp-server`, `deploy/`, `docs/`, `.github/workflows/` · **Decisions:** D12, D15 · **FEATURES.md:** — (D12 sync infrastructure)
**Related (integrates with, not blocking):** T00
**Reference:** sverb `crates/sverb-server/src/{config,cli,serve,healthcheck,logging,metrics}.rs`, `src/routes/ops.rs`, `src/admin/{mod,user,invite,gc}.rs`, `deploy/{Dockerfile.server,Dockerfile.server.release,docker-compose.yml}`, `docs/self-hosting.md`, `tests/{config,db,http}.rs`; SPEC §10.6, §10.7, §18.

## Goal

Make `courier-ftp-server` easy to self-host and operate: one validated configuration
(environment variables or a TOML file), an admin CLI in the same binary, health, readiness
and Prometheus endpoints, structured logs, a static binary and a distroless multi-arch
Docker image, a `docker compose` quick start, and a self-hosting guide that a new operator
can follow from scratch.

## Context

- **Before:** T84 has `Config::from_sources` with the core variables, `serve [--migrate]`,
  `migrate`, the setup-token bootstrap, migrations and the secret check. T85 has
  `sync::gc::run` + background job, the bus with `healthy()`, and records metrics through
  the `metrics` macros (no exporter yet). T00 defined the `server-db` and `server-docker`
  CI jobs and the server parts of `cd.yml` as stubs.
- **After:** T76's sync fixture uses `deploy/docker-compose.yml`/the image; T77 links the
  self-hosting guide from the README and publishes the image and binaries in releases;
  T89 adds org invites that reuse `admin invite`'s link format.

## Technical specification

### Types and APIs

```rust
// src/config.rs (completes T84's Config)
pub const DEFAULT_BIND: &str = "0.0.0.0:8080";
pub const SECRET_MIN_LEN: usize = 32;
pub const METRICS_TOKEN_MIN_LEN: usize = 16;
pub const CONFIG_PATH_ENV: &str = "COURIER_SERVER_CONFIG";
pub const DEFAULT_CONFIG_FILE: &str = "courier-ftp-server.toml";

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: Option<Sensitive<String>>,
    pub bind: SocketAddr,
    pub public_url: Url,                     // https://… or http://localhost…, no trailing '/'
    pub server_secret: ServerSecret,         // zeroized, Debug "[REDACTED]"
    pub tls: Option<TlsFiles>,
    pub smtp: Option<SmtpConfig>,
    pub limits: Limits,                      // storage_quota_mib, tombstone_horizon_days, gc_interval_hours
    pub metrics_token: Option<Sensitive<String>>,
    pub metrics_bind: Option<SocketAddr>,
    pub log_format: LogFormat,               // Json | Pretty
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub cors_allowed_origins: Vec<String>,
    pub request_timeout: std::time::Duration,
    pub db_max_connections: u32,
}
impl Config {
    /// File: --config FILE, else $COURIER_SERVER_CONFIG, else ./courier-ftp-server.toml if it exists.
    pub fn load(cli_path: Option<&Path>) -> Result<Self, ConfigError>;
    /// Pure: TOML text (+ its path for messages) and an env lookup.
    pub fn from_sources(file: Option<(&str, &Path)>, env: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError>;
}
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    MissingSecret, SecretTooShort { len: usize }, SecretEncoding,
    Missing(&'static str),
    Invalid { name: &'static str, reason: String },
    ReadFile { path: PathBuf, source: std::io::Error },
    ParseFile { path: PathBuf, message: String },   // includes unknown keys
}

// src/cli.rs (clap derive)
pub struct Cli { #[arg(long, global = true)] pub config: Option<PathBuf>, #[command(subcommand)] pub command: Command }
pub enum Command {
    Serve { #[arg(long)] migrate: bool },
    Migrate,
    Admin { #[command(subcommand)] command: AdminCommand },
    Healthcheck { #[arg(long)] addr: Option<SocketAddr> },
}
pub enum AdminCommand {
    User { #[command(subcommand)] command: UserCommand },
    Invite { email: String, #[arg(long)] no_email: bool },
    Registration { mode: RegistrationMode },          // open | invite-only | closed
    Gc,
}
pub enum UserCommand {
    List,
    Create { email: String },                          // = invite (OPAQUE: no server-side password)
    Disable { email: String },
    Enable { email: String },
    RecoveryCode { email: String },
}
pub async fn run(cli: Cli) -> std::process::ExitCode;

// src/admin/*.rs — return data, CLI prints (so tests call them directly)
pub async fn list_users(store: &Store) -> Result<Vec<UserSummary>, AdminError>;   // email, created_at, disabled, admin, devices
pub async fn create_invite(store: &Store, cfg: &Config, email: &str, now: OffsetDateTime) -> Result<CreatedInvite, AdminError>; // link + expiry; Debug redacts link
pub async fn disable_user(store: &Store, email: &str) -> Result<DisableReport, AdminError>;     // tokens revoked, publishes UserDisabled
pub async fn enable_user(store: &Store, email: &str) -> Result<(), AdminError>;
pub async fn recovery_code(store: &Store, email: &str, now: OffsetDateTime) -> Result<Zeroizing<String>, AdminError>;
pub async fn set_registration(store: &Store, mode: RegistrationMode) -> Result<(), AdminError>;
// gc: crate::sync::gc::run (T85)

// src/routes/ops.rs
pub fn router(state: &AppState) -> Router<AppState>;  // /healthz, /readyz, /metrics (if token set)
pub fn metrics_router(state: AppState) -> Router;      // for COURIER_METRICS_BIND

// src/readiness.rs
pub struct Readiness;                                  // named degraded components, e.g. "ws_listener"
impl Readiness { pub fn set_degraded(&self, c: &'static str, since: Instant); pub fn clear(&self, c: &'static str); pub fn degraded(&self) -> Vec<&'static str>; }
```

### Behaviour

#### Configuration

Sources, lowest to highest precedence: built-in defaults → TOML file → environment. Empty
environment variables count as unset. Unknown TOML keys are an error. Validation runs at
start; any error prints one line naming the variable and exits with code 2.

| Env | TOML key | Type / range | Default | Meaning |
|---|---|---|---|---|
| `DATABASE_URL` | `database_url` | postgres URL | — (required by `serve`, `migrate`, `admin`) | database |
| `COURIER_BIND` | `bind` | socket address | `0.0.0.0:8080` | listener |
| `COURIER_PUBLIC_URL` | `public_url` | `https://…`; `http://` only for `localhost`/loopback | **required** | invite links, mails |
| `COURIER_SERVER_SECRET` | `server_secret` | hex (even length, only hex digits) or base64 (std/url, padded or not), ≥ 32 bytes | **required** | at-rest key (T84) |
| `COURIER_TLS_CERT`, `COURIER_TLS_KEY` | `tls_cert`, `tls_key` | PEM files | off (both or neither) | built-in TLS (rustls, TLS 1.2+1.3) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | `[smtp]` `host`, `port`, `user`, `password`, `from`, `starttls` | — / 1..=65535 / — / — / RFC 5322 mailbox / bool | off; 587; —; —; required with host; `true` | mail for recovery codes and invites; `starttls = false` = implicit TLS (465) |
| `COURIER_STORAGE_QUOTA_MIB` | `storage_quota_mib` | 1..=1 048 576 | 100 | personal vault quota |
| `COURIER_TOMBSTONE_HORIZON_DAYS` | `tombstone_horizon_days` | 1..=3650 | 90 | tombstone purge age |
| `COURIER_GC_INTERVAL_HOURS` | `gc_interval_hours` | 0..=720 | 24 | background GC; 0 = off |
| `COURIER_METRICS_TOKEN` | `metrics_token` | ≥ 16 chars | off | bearer for `/metrics` on the main port |
| `COURIER_METRICS_BIND` | `metrics_bind` | socket address | off | separate listener serving only `/metrics` |
| `COURIER_LOG_FORMAT` | `log_format` | `json` \| `pretty` | `json` | log line format |
| `COURIER_SERVER_LOG` / `RUST_LOG` | — | tracing filter | `info` | log level |
| `COURIER_TRUSTED_PROXIES` | `trusted_proxies` | comma list / array of IP or CIDR | none | trust `X-Forwarded-For` from these peers |
| `COURIER_CORS_ORIGINS` | `cors_allowed_origins` | comma list / array of origins | none (deny) | CORS |
| `COURIER_REQUEST_TIMEOUT_S` | `request_timeout_s` | 1..=300 | 30 | per-request timeout |
| `COURIER_DB_MAX_CONNECTIONS` | `db_max_connections` | 2..=200 | 16 | pool size |
| `COURIER_SERVER_CONFIG` | — | path | `./courier-ftp-server.toml` if present | config file |

`metrics_token` and `metrics_bind` may both be set (then the separate listener also
requires the token). `DATABASE_URL`, `server_secret`, `smtp.password`, `metrics_token` are
`Sensitive` (redacted in `Debug`).

#### Admin CLI (same binary)

```text
courier-ftp-server [--config FILE] serve [--migrate]
courier-ftp-server [--config FILE] migrate
courier-ftp-server [--config FILE] admin user list
courier-ftp-server [--config FILE] admin user create <EMAIL>
courier-ftp-server [--config FILE] admin user disable <EMAIL>
courier-ftp-server [--config FILE] admin user enable <EMAIL>
courier-ftp-server [--config FILE] admin user recovery-code <EMAIL>
courier-ftp-server [--config FILE] admin invite <EMAIL> [--no-email]
courier-ftp-server [--config FILE] admin registration open|invite-only|closed
courier-ftp-server [--config FILE] admin gc
courier-ftp-server healthcheck [--addr HOST:PORT]
```

| Command | Effect | Output (stdout) | Exit |
|---|---|---|---|
| `serve` | T84 startup + ops routes + metrics listener + GC job | logs only | 0 / 2 config / 3 DB / 4 bind |
| `migrate` | applies pending migrations | `migrations applied: <n> (now at <v>)` | 0 / 3 |
| `admin user list` | table: email, created (RFC 3339), disabled, admin, active devices | one line per user | 0 / 3 |
| `admin user create <email>` | instance invite bound to the email (same as `admin invite`) | link + expiry | 0 / 1 already registered / 3 |
| `admin user disable <email>` | `disabled = true`, all tokens deleted, `UserDisabled` published | `disabled <email>; revoked <n> token(s)` | 0 / 1 unknown email |
| `admin user enable <email>` | `disabled = false` | `enabled <email>` | 0 / 1 |
| `admin user recovery-code <email>` | one-time code, 24 h, replaces any previous; mailed too with SMTP | the code on its own line | 0 / 1 |
| `admin invite <email> [--no-email]` | `invites` row, `org_id NULL`, role NULL, 7 days; link `<public_url>/invite/<token>`; mailed with SMTP unless `--no-email` | link, expiry, `mailed to …` / `no mail sent` | 0 / 1 |
| `admin registration <mode>` | sets `settings.registration_mode` | `registration mode set to <mode>` | 0 |
| `admin gc` | `sync::gc::run` once | the `GcReport` counts | 0 / 3 |
| `healthcheck` | `GET http://<addr>/healthz` with a 5 s timeout (built-in TLS: TCP connect only); default addr from `COURIER_BIND` with `0.0.0.0`/`::` → loopback | nothing | 0 healthy / 1 otherwise |

Error messages go to stderr prefixed `courier-ftp-server: `. `admin` commands need
`DATABASE_URL` and the server secret (the recovery-code and invite paths do not need the
secret, but the config is validated uniformly). `healthcheck` reads only `COURIER_BIND`
and the TLS variables and works without `DATABASE_URL`.

#### Ops endpoints (outside `/v1`, no `Courier-Proto` requirement)

| Path | Response |
|---|---|
| `GET /healthz` | 200 `{"status":"ok"}` always while the process serves |
| `GET /readyz` | 200 `{"status":"ready","database":"ok","migrations":"current"}`; 503 with `"status":"not_ready"` and `database: "unreachable"` (query `SELECT 1` fails within 2 s), `migrations: "pending"` (+ `"pending":[3]`) or `"mismatch"`, or `"degraded":["ws_listener"]` (listener down > 30 s, T85) |
| `GET /metrics` | Prometheus text 0.0.4. Main port: only when `COURIER_METRICS_TOKEN` is set, requires `Authorization: Bearer <token>` (constant-time compare; 401 otherwise). `COURIER_METRICS_BIND`: served there (token still required if set). Neither set → 404 |

Metrics (exporter `metrics-exporter-prometheus`, recorder installed once):

| Name | Kind | Labels | Source |
|---|---|---|---|
| `http_requests_total` | counter | `method`, `route` (template), `status` | middleware |
| `http_request_duration_seconds` | histogram (buckets 5 ms … 10 s) | `method`, `route` | middleware |
| `courier_ws_connections_active` | gauge | — | T85 hub |
| `courier_sync_push_items_total` | counter | `result` (`ok`,`conflict`,`too_large`) | T85 push |
| `courier_sync_push_bytes_total` | counter | — | T85 push |
| `courier_sync_pull_items_total`, `courier_sync_pull_bytes_total` | counter | — | T85 pull |
| `courier_gc_tombstones_purged_total` | counter | — | T85 GC |
| `courier_auth_login_total` | counter | `result` (`ok`,`failed`,`totp_required`) | T84 |
| `courier_rate_limited_total` | counter | `limiter` | T84 |

#### Logging

`tracing-subscriber` to stdout: JSON lines (`timestamp`, `level`, `target`, `message`,
fields, span `request_id`) or pretty. Rules (T91 §4): tokens, secrets and OPAQUE material
never logged; emails never at info+ (debug only as `email_hash`); the listen address and
public URL at info at start; the setup token at warn (the one deliberate exception).

#### Deployment

- `deploy/Dockerfile.server` (build from source): stage `rust:1-alpine` with `musl-dev`,
  `RUSTFLAGS=-C target-feature=+crt-static`, `cargo build --locked --release -p
  courier-ftp-server --target $(uname -m)-unknown-linux-musl` with cache mounts; final stage
  `gcr.io/distroless/static-debian12:nonroot`, `USER nonroot:nonroot`,
  `ENV COURIER_BIND=0.0.0.0:8080 COURIER_LOG_FORMAT=json`, `EXPOSE 8080`,
  `HEALTHCHECK --interval=10s --timeout=6s --start-period=20s --retries=3 CMD
  ["/usr/local/bin/courier-ftp-server","healthcheck"]`, `ENTRYPOINT
  ["/usr/local/bin/courier-ftp-server"]`, `CMD ["serve"]`. `.dockerignore` excludes
  `target/`, `.git/`, fixtures.
- `deploy/Dockerfile.server.release`: same final stage, `COPY --chmod=0755
  dist/courier-ftp-server-${TARGETARCH}`, OCI labels (title, description, licenses,
  version) — the CD workflow builds it from the static release binaries for
  `linux/amd64,linux/arm64` and pushes `ghcr.io/viperh/courier-ftp-server:<version>` and
  `:latest`.
- `deploy/docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_USER: courier
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-courier}
      POSTGRES_DB: courier
    volumes: [ "pgdata:/var/lib/postgresql/data" ]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U courier -d courier"]
      interval: 5s
      timeout: 5s
      retries: 20
  courier-ftp-server:
    build: { context: .., dockerfile: deploy/Dockerfile.server }
    image: courier-ftp-server:local
    restart: unless-stopped
    command: ["serve", "--migrate"]
    depends_on: { postgres: { condition: service_healthy } }
    environment:
      DATABASE_URL: postgres://courier:${POSTGRES_PASSWORD:-courier}@postgres:5432/courier
      COURIER_BIND: 0.0.0.0:8080
      COURIER_PUBLIC_URL: ${COURIER_PUBLIC_URL:-http://localhost:8080}
      COURIER_SERVER_SECRET: ${COURIER_SERVER_SECRET:?set COURIER_SERVER_SECRET (openssl rand -base64 48) and back it up with the database}
      COURIER_METRICS_TOKEN: ${COURIER_METRICS_TOKEN:-}
      COURIER_LOG_FORMAT: json
      SMTP_HOST: ${SMTP_HOST:-}
      SMTP_PORT: ${SMTP_PORT:-587}
      SMTP_USER: ${SMTP_USER:-}
      SMTP_PASSWORD: ${SMTP_PASSWORD:-}
      SMTP_FROM: ${SMTP_FROM:-}
    ports: [ "8080:8080" ]
volumes:
  pgdata:   # back up together with COURIER_SERVER_SECRET
```

- CI (switch on T00 stubs): `server-db` (from T84), `server-docker`: `docker compose -f
  deploy/docker-compose.yml config --quiet`; `up -d --build` with a generated secret; poll
  `/healthz` up to 60 s; `/readyz` 200; `docker compose logs courier-ftp-server | grep -q
  setup_token`; `docker inspect` user is `nonroot` / uid 65532; tear down with `-v`.
  `cd.yml`: static musl `courier-ftp-server` for x86_64 and aarch64 (`cross`), `file` reports
  "statically linked", archives `courier-ftp-server-<v>-linux-{x86_64,aarch64}.tar.gz` in
  `SHA256SUMS`; image build from `Dockerfile.server.release` with `docker/build-push-action`,
  smoke test per arch (`docker run --rm --platform … image healthcheck --help`), push.

#### `docs/self-hosting.md` (sections, all required)

1. What the server stores (link to threat model "What the sync server sees"), requirements
   (PostgreSQL 15+, x86_64/aarch64 Linux or Docker), and the **backup warning**: back up the
   database **and** `COURIER_SERVER_SECRET` together.
2. Quick start with Docker Compose (export secret + public URL, `up -d --build`, curl
   `/healthz`), first account via setup token (`logs … | grep setup_token`), registration
   modes and invites.
3. Using the published image (pin a version).
4. Running the static binary (`migrate`, `serve`, systemd unit example with
   `EnvironmentFile=`, `User=courier`, `Restart=on-failure`).
5. Configuration table (the one above) and an example `courier-ftp-server.toml`.
6. TLS: built-in, or Caddy (2-line `reverse_proxy`) / nginx (WebSocket upgrade headers,
   `client_max_body_size 13m`, `proxy_read_timeout 120s` > the 30 s ping) with
   `COURIER_TRUSTED_PROXIES`.
7. Several replicas: same DB and same secret, any load balancing (no sticky sessions
   needed: WS fan-out via `LISTEN/NOTIFY`), rate limits are per replica.
8. Operations: endpoints table, metrics list, logs and `x-request-id`.
9. Admin CLI reference and the recovery-code procedure (verify the person out of band).
10. Backups (pg_dump + secret, restore test), upgrades (server first, then clients;
    `serve --migrate` or `migrate`; no downgrades — restore the backup), GC and the
    tombstone horizon (devices offline longer resync fully).

### Data formats and configuration

Example `courier-ftp-server.toml` (shipped as `deploy/courier-ftp-server.toml.example`):

```toml
public_url = "https://sync.example.com"
database_url = "postgres://courier:secret@localhost/courier"
# server_secret = "…"   # better: only in the environment
trusted_proxies = ["127.0.0.1"]
storage_quota_mib = 100
log_format = "json"

[smtp]
host = "smtp.example.com"
user = "courier"
password = "…"
from = "courier-ftp <courier@example.com>"
```

### Errors

`ConfigError` messages (exact text tested):
- `COURIER_SERVER_SECRET is required (at least 32 random bytes, hex or base64); generate one with: openssl rand -base64 48`
- `COURIER_SERVER_SECRET is too short: N bytes after decoding, at least 32 required`
- `COURIER_SERVER_SECRET must be hex or base64 encoded`
- `COURIER_PUBLIC_URL is required`
- `invalid COURIER_PUBLIC_URL: must be https:// (http:// only for localhost)`
- `invalid COURIER_TLS_CERT/COURIER_TLS_KEY: set both or neither`
- `SMTP_FROM is required when SMTP_HOST is set`
- `invalid <VAR>: <reason>` for ranges and parse errors; `cannot read <path>: …`;
  `invalid config file <path>: unknown key `x``.
`AdminError::{UnknownEmail, AlreadyRegistered, Database, Mail}` → exit codes in the CLI
table. `/readyz` failures are logged at warn once per state change.

### Security and logging

- The image runs as uid 65532 (`nonroot`) on a distroless base (no shell, no package
  manager); the binary is static (musl + rustls, no OpenSSL).
- `/metrics` is never public by default; token compared in constant time.
- Admin CLI output contains recovery codes and invite links by design (stdout of an
  operator's terminal), never written to logs.
- Config `Debug` redacts all `Sensitive` fields (unit test with canaries).

## Implementation steps

1. Complete `config.rs` (TOML + all variables + validation) and `tests/config.rs`.
2. `logging.rs` (JSON/pretty, filter), `metrics.rs` (recorder, middleware, names), ops routes
   + `readiness.rs`; wire T85's listener health.
3. `cli.rs` with clap; `admin/{user,invite}.rs`; `admin gc` → `sync::gc::run`;
   `healthcheck.rs`.
4. `deploy/Dockerfile.server`, `.dockerignore`, `deploy/docker-compose.yml`,
   `deploy/courier-ftp-server.toml.example`; switch on CI `server-docker`.
5. `deploy/Dockerfile.server.release` + `cd.yml` server steps (binaries, image, smoke test).
6. `docs/self-hosting.md`; manual walk-through recorded in the PR description.

## Acceptance criteria

- [ ] AC1 `COURIER_SERVER_SECRET=$(openssl rand -base64 48) docker compose -f
  deploy/docker-compose.yml up -d --build` gives `/healthz` 200 within 60 s, `/readyz` 200,
  and a `setup_token=` line in the server log (CI `server-docker`).
- [ ] AC2 The image's `HEALTHCHECK` (`healthcheck` subcommand) reports healthy; the container
  user is uid 65532.
- [ ] AC3 The CD dry run builds static `courier-ftp-server` binaries for x86_64 and aarch64
  (`file` says statically linked) and a multi-arch image (amd64 + arm64) that passes the
  smoke test on both architectures.
- [ ] AC4 Every row of the configuration table is covered by a parse test (default, valid
  value, out-of-range value with the documented message); env overrides TOML; unknown TOML
  keys are rejected.
- [ ] AC5 `admin user list|create|disable|enable|recovery-code`, `admin invite`, `admin
  registration`, `admin gc` work against Postgres with the documented output and exit codes.
- [ ] AC6 `/metrics` returns 404 without token/bind, 401 with a wrong token, 200 with the token,
  and contains `http_requests_total` after one request.
- [ ] AC7 `/readyz` returns 503 with `migrations: "pending"` when started with a pending
  migration and `serve` without `--migrate` refuses to start.
- [ ] AC8 Manual check (recorded in the PR): a person who has not seen the project follows
  `docs/self-hosting.md` sections 2 and 6 (Caddy) on a fresh VM and connects a courier-ftp
  client.
- [ ] AC9 CI `server-db`, `server-docker`, `fmt`, `clippy`, `docs`, `deny` pass.

## Tests

### Unit tests
- `config::tests::defaults_and_every_variable` — table-driven over the configuration table
  (AC4).
- `config::tests::secret_encodings` — hex, base64 std/url, padded/unpadded, 31 bytes rejected.
- `config::tests::sensitive_fields_redacted_in_debug` — canary values absent from `{:?}`.
- `cli::tests::cli_surface_parses` — every command line in the CLI block parses; bad mode
  rejected.
- `routes::ops::tests::metrics_token_constant_time_and_401`.

### Property / fuzz tests
- Not applicable.

### Snapshot tests
- Not a UI task. `cli::tests::help_text_snapshot` — `insta` snapshot of `--help` and
  `admin --help` (catches accidental CLI changes).

### Integration tests
- `tests/config.rs::toml_file_with_env_overrides`, `unknown_keys_rejected`,
  `invalid_values_are_rejected` (AC4).
- `tests/db.rs::t12_admin_user_list_disable_enable_recovery` (Pg) — outputs and token
  revocation (AC5).
- `tests/db.rs::t13_admin_invite_link_registers_once` — invite from the CLI function, register
  with it via HTTP, second use 403 (AC5).
- `tests/db.rs::t14_admin_gc_report` (AC5).
- `tests/db.rs::t02_pending_migration_readyz_503_and_serve_refuses` (AC7).
- `tests/http.rs::t08_metrics_requires_token`, `metrics_not_exposed_without_token_or_bind`,
  `healthz_ok_and_readyz_503_without_database` (AC6, AC7).
- `tests/http.rs::healthcheck_probe_accepts_the_real_server` — `healthcheck --addr` against
  a server on an ephemeral port → exit 0; against a closed port → 1 (AC2).
- `tests/binary.rs::refuses_to_start_without_secret` — runs the built binary, exit 2 and the
  message.

### End-to-end tests
- CI job `server-docker` (AC1, AC2) and `cd.yml` dry run (AC3).
- `courier-ftp-e2e` sync fixture (T76) starts the same compose stack; `sync_server.rs::
  compose_stack_is_ready` (`#[ignore]`, `COURIER_E2E=1`) asserts `/readyz` and the setup
  token extraction helper used by every sync scenario.

## Out of scope

- A web admin UI or web vault viewer.
- Kubernetes manifests / Helm chart (the compose file and docs cover single host and
  replicas behind a proxy).
- Automatic ACME in the server (use Caddy or nginx + certbot).

## Open questions

None.

Resolved (reconciliation): the server crate may use `clap` for its CLI (README rule and T00
layering updated), so `cli.rs` uses clap derive.
