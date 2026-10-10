# Self-hosting courier-ftp-server

`courier-ftp-server` is the optional sync server for courier-ftp (D12). It
stores only end-to-end encrypted data: it never sees host names, user names,
passwords or keys in plaintext (see [security.md](security.md)). It needs
**PostgreSQL 15+** and ships as one static binary or a distroless Docker image.
courier-ftp works fully offline without it.

> **Back up the database and `COURIER_SERVER_SECRET` together.**
> The secret encrypts the OPAQUE server setup kept in the database (and TOTP
> secrets). Losing either one, or restoring a database with a different
> secret, invalidates every login: the server refuses to start with
> `cannot decrypt server_secrets row … Refusing to start.` Vault data stays
> safe (it is end-to-end encrypted and still on every device), but every user
> would have to set up sync again.

## 1. Quick start (Docker Compose)

```sh
git clone https://github.com/viperh/courier-ftp && cd courier-ftp
export COURIER_SERVER_SECRET="$(openssl rand -base64 48)"   # store this in a password manager
export COURIER_PUBLIC_URL=https://sync.example.com          # the URL clients will use
docker compose -f deploy/docker-compose.yml up -d --build
curl -fsS http://localhost:8080/healthz
```

The compose file starts `postgres:16` (data in the `pgdata` volume) and
`courier-ftp-server serve --migrate` on port 8080 once Postgres is healthy.
The image runs as the unprivileged `nonroot` user and has a built-in
`HEALTHCHECK` (`courier-ftp-server healthcheck`).

### First account (setup token)

While no account exists, every start logs a one-time **setup token** at
`warn` level:

```sh
docker compose -f deploy/docker-compose.yml logs courier-ftp-server | grep setup_token
```

Set up sync in courier-ftp against this server and enter that token when
asked. That account becomes the **instance admin** and the token stops
working. Until someone registers, each restart logs a fresh token (only its
hash is stored; the previous one is replaced).

Registration starts as `invite-only`: new users need an invite token
(`courier-ftp-server admin invite <email>`) unless you switch to `open`.

### Using the published image

Releases publish `ghcr.io/viperh/courier-ftp-server:<version>` and `:latest`
(linux/amd64 and linux/arm64, distroless, non-root), built from the same static
binaries as the release archives (`deploy/Dockerfile.server.release`). To use
it, replace the `build:` block of the `courier-ftp-server` service in
`deploy/docker-compose.yml` with

```yaml
    image: ghcr.io/viperh/courier-ftp-server:1.0.0   # pin a version; :latest follows releases
```

and start with `docker compose -f deploy/docker-compose.yml up -d`. The release
archives `courier-ftp-server-<version>-linux-{x86_64,aarch64}.tar.gz` hold the
same static binary for running without Docker; check them against
`SHA256SUMS`.

## 2. Running the binary directly

```sh
export DATABASE_URL=postgres://courier:…@db.internal:5432/courier
export COURIER_SERVER_SECRET=…   COURIER_PUBLIC_URL=https://sync.example.com
courier-ftp-server migrate        # apply schema migrations
courier-ftp-server serve          # refuses to start while migrations are pending
```

`serve --migrate` applies pending migrations at startup instead of refusing.
The binary is static (musl, rustls, no OpenSSL) and runs on any x86_64 or
aarch64 Linux.

## 3. Configuration

Settings come from environment variables or a TOML file (`--config FILE`,
else `$COURIER_SERVER_CONFIG`, else `./courier-ftp-server.toml`).
**Environment variables win.** Empty variables count as unset. Invalid values
stop the server at startup with a message naming the variable.

| Environment | TOML key | Default | Meaning |
|---|---|---|---|
| `DATABASE_URL` | `database_url` | — | Postgres URL (needed by `serve`, `migrate`, `admin`) |
| `COURIER_BIND` | `bind` | `0.0.0.0:8080` | Listen address |
| `COURIER_PUBLIC_URL` | `public_url` | **required** | The URL clients use (logged with the setup token, printed with invites) |
| `COURIER_SERVER_SECRET` | `server_secret` | **required** | ≥ 32 random bytes, hex or base64 |
| `COURIER_TLS_CERT`, `COURIER_TLS_KEY` | `tls_cert`, `tls_key` | off | PEM files for built-in TLS (both or neither) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | `[smtp]` `host`, `port`, `user`, `password`, `from`, `starttls` | off; `587`, `true` | Mail for invites and recovery codes. Without SMTP, invites are copy-paste tokens and recovery codes come from the admin CLI. `starttls = false` means implicit TLS (port 465). |
| `COURIER_STORAGE_QUOTA_MIB` | `storage_quota_mib` | `100` | Per-user quota (encrypted bytes in the personal vault; team vaults are capped at 1 GiB each) |
| `COURIER_TOMBSTONE_HORIZON_DAYS` | `tombstone_horizon_days` | `90` | Deleted items are purged by GC after this |
| `COURIER_GC_INTERVAL_HOURS` | `gc_interval_hours` | `24` | Hours between in-process GC runs; `0` disables them |
| `COURIER_METRICS_TOKEN` | `metrics_token` | off | Bearer token for `/metrics` on the main port (≥ 16 chars) |
| `COURIER_METRICS_BIND` | `metrics_bind` | off | Separate address that serves only `/metrics` |
| `COURIER_LOG_FORMAT` | `log_format` | `json` | `json` or `pretty` |
| `COURIER_TRUSTED_PROXIES` | `trusted_proxies` | none | Comma list of proxy IPs/CIDRs whose `X-Forwarded-For` is trusted |
| `COURIER_CORS_ORIGINS` | `cors_allowed_origins` | none | Origins allowed by CORS (deny by default) |
| `COURIER_REQUEST_TIMEOUT_S` | `request_timeout_s` | `30` | Per-request timeout |
| `COURIER_LOG` / `RUST_LOG` | — | `info` | Log filter (`tracing` syntax) |

Example `courier-ftp-server.toml`:

```toml
public_url = "https://sync.example.com"
database_url = "postgres://courier:secret@localhost/courier"
server_secret = "…"        # or keep it only in the environment
trusted_proxies = ["127.0.0.1"]

[smtp]
host = "smtp.example.com"
user = "courier"
password = "…"
from = "courier-ftp sync <sync@example.com>"
```

Request bodies are limited to 12 MiB (a push carries up to 500 items and
8 MiB of encrypted items, 1 MiB per item, base64-encoded). Login,
registration and recovery are limited to 5 attempts per minute per email and
50 per minute per client IP; over the limit the server answers `429` with
`Retry-After`.

## 4. TLS

**Built in:** set `COURIER_TLS_CERT` and `COURIER_TLS_KEY` (PEM); rustls serves
HTTPS on `COURIER_BIND`. Restart the server after renewing certificates.

**Reverse proxy (recommended for ACME):** terminate TLS in the proxy, keep
the server on plain HTTP on a private address, and set
`COURIER_TRUSTED_PROXIES` to the proxy's address so rate limits see real
client IPs. The proxy must pass WebSocket upgrades on `/v1/ws`.

Caddy (proxies WebSockets and sets `X-Forwarded-For` by default):

```caddyfile
sync.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

server {
    listen 443 ssl http2;
    server_name sync.example.com;
    ssl_certificate     /etc/letsencrypt/live/sync.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sync.example.com/privkey.pem;

    client_max_body_size 12m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;   # > the 30 s WebSocket ping interval
    }
}
```

## 5. Several replicas

The server keeps no state outside PostgreSQL except open WebSockets. OPAQUE
login states live in the database (login start and finish may hit different
replicas), and change notifications fan out between replicas through Postgres
`LISTEN/NOTIFY` (channel `courier_events`), so any load-balancing works, no
sticky sessions needed. All replicas must share the same database **and** the
same `COURIER_SERVER_SECRET`. Every replica may run the background GC; the
per-vault lock makes concurrent runs harmless.

## 6. Operations

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Process alive (always 200) |
| `GET /readyz` | 200 when the database is reachable, migrations are current and the `LISTEN` connection is up; 503 otherwise (JSON says why) |
| `GET /metrics` | Prometheus metrics; needs `Authorization: Bearer $COURIER_METRICS_TOKEN`, or is served only on `COURIER_METRICS_BIND`. Disabled when neither is set. |

Metrics: `http_requests_total{method,route,status}`,
`http_request_duration_seconds`, `courier_ws_connections_active`,
`courier_ws_messages_sent_total`, `courier_sync_push_*` and
`courier_sync_pull_*` (items and bytes). Labels never contain user data.

Logs are JSON lines on stdout with a `request_id` per request. Clients may
send `x-request-id`; it is echoed in every response. Tokens are never logged
(only the one-time setup token, by design) and emails are not logged at
`info`; accounts appear by user id. Every error response has the form
`{"error": {"code": "…", "message": "…"}}`.

## 7. Admin CLI

Run these where the server's environment is available, e.g.
`docker compose -f deploy/docker-compose.yml exec courier-ftp-server courier-ftp-server admin user list`.

```text
courier-ftp-server serve [--migrate]                 run the server
courier-ftp-server migrate                           apply database migrations
courier-ftp-server admin user list                   email, created, disabled, admin, device count
courier-ftp-server admin user create <email>         create a registration invite (prints server URL + token)
courier-ftp-server admin user disable <email>        disable the account, revoke its tokens, close its sockets
courier-ftp-server admin user recovery-code <email>  one-time account-recovery code (24 h; mailed with SMTP)
courier-ftp-server admin invite <email> [--no-email] invite token (also mailed when SMTP is set)
courier-ftp-server admin registration open|invite-only|closed
courier-ftp-server admin gc                          purge expired tokens, invites and old tombstones
courier-ftp-server healthcheck [--addr HOST:PORT]    probe /healthz (the Docker HEALTHCHECK)
```

Passwords are never set on the server: courier-ftp uses OPAQUE with the
master password, chosen on the client. `user create` and `invite` hand out a
single-use, email-bound token valid for 7 days. `closed` blocks every
registration, invites included.

Forgotten master password: a user with their 24-word recovery key needs a
one-time recovery code. With SMTP configured, courier-ftp requests it by
mail; otherwise verify the person out of band and run
`admin user recovery-code <email>`. The code is useless without the
recovery key, and five wrong attempts discard it. A recovery logs out every
device of the account.

GC runs every `COURIER_GC_INTERVAL_HOURS` (default daily); with `0`, run
`admin gc` from cron. Purging tombstones makes devices that were offline
longer than `COURIER_TOMBSTONE_HORIZON_DAYS` do a full resync.

## 8. Backups and upgrades

- **Backup:** `pg_dump` (or volume snapshots) **plus** a copy of
  `COURIER_SERVER_SECRET`, stored together. Test restores with the same secret.
- **Upgrade:** back up, pull or build the new image, then either let
  `serve --migrate` apply migrations or run `courier-ftp-server migrate`
  first. Without `--migrate`, a newer binary refuses to start on an older
  schema and `/readyz` reports pending migrations.
- **Downgrade:** not supported once a newer migration is applied (the older
  binary refuses to start on the unknown migration); restore the backup.
- Clients send `Courier-Proto`; the server accepts the current protocol
  version and the previous one, so upgrade the server first, clients after.

## 9. Manual check

The steps above (quick start, setup-token registration, invite, healthcheck)
are exercised by CI's `server-docker` job (build, compose up, `/healthz`,
`/readyz`, setup token in the logs, non-root user). A full walk-through with
a real client needs the sync client (T87/T88).
