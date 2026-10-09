# T76 — Integration test harness

**Phase:** G App-level (start early, alongside phase B/C) · **Depends on:** T03, T06 · **Crates:** all (workspace `tests/` or a dedicated `crates/courier-ftp-it`)

## Goal

Run every backend against real servers in Docker, locally and in CI.

## Scope

1. **Servers** (`docker-compose.yml` under `tests/servers/`):
   - `vsftpd` — plain FTP, explicit FTPS with `require_ssl_reuse=YES`, implicit FTPS on 990, passive port range exposed.
   - `proftpd` — MLSD, mod_tls, `SITE CHMOD`.
   - `pure-ftpd` — TLS, unusual LIST output.
   - FileZilla Server isn't available on Linux Docker — skip; note it.
   - `openssh-server` — password, keyboard-interactive (PAM with 2 prompts), pubkey (ed25519, RSA, ECDSA), agent (test spins up `ssh-agent`).
   - Optional: `squid` (HTTP CONNECT) and `dante` (SOCKS5) for proxy tests.
   - Fixed test credentials and test-only keys committed under `tests/fixtures/` (clearly marked as test-only).
2. **Test runner**: Rust integration tests gated by env `COURIER_FTP_IT=1` (skipped otherwise so `cargo test` works without Docker). Each server exposes a known port on localhost.
3. **Backend conformance suite** (from T06) run against: LocalBackend, FTP (plain, FTPES, FTPS implicit) × each FTP server, SFTP × each auth method.
4. **Scenario tests**: queue of 50 mixed-size files up/down with checksum verification; resume after killing the connection mid-transfer (use `toxiproxy` or close socket from server side); speed limit; recursive delete; listing parsers against real server output (snapshot).
5. **CI**: a separate GitHub Actions job (`integration`) on `ubuntu-latest` that runs `docker compose up -d`, waits for health checks, runs the tests with `COURIER_FTP_IT=1`. Allowed to be slower; required to pass before merge.
6. `scripts/it.sh` to run the same locally.

## Acceptance criteria

- [ ] `scripts/it.sh` brings servers up and runs the suite green locally.
- [ ] CI integration job green.
- [ ] Without Docker, `cargo test` skips integration tests cleanly.

## Tests

- This task *is* tests.
