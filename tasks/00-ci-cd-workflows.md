# T00 — CI/CD workflows (sverb parity)

**Phase:** A Foundation (first task; extended as features land) · **Depends on:** — · **Files:** `.github/workflows/{ci,cd,fuzz,bench}.yml`, `scripts/`, `deny.toml`, `supply-chain/`, `rust-toolchain.toml`, `rustfmt.toml`, workspace lints
**Related (integrates with, not blocking):** T76, T91, T41b, T84, T85, T86
**Reference:** sverb `.github/workflows/ci.yml`, `cd.yml`, `fuzz.yml`, `bench.yml`, `scripts/*`, `deny.toml`, `supply-chain/`, `rust-toolchain.toml`, `rustfmt.toml`, `Cargo.toml` `[workspace.lints]`.

## Goal

The same CI/CD setup as sverb, adapted to courier-ftp's crates: every check
runs on each pull request, nightly fuzzing and benchmarks, and a reproducible,
signed release pipeline for the client and the sync server.

## Scope

This is the **first task**. Set up the jobs that can run on the template right away (fmt, clippy, docs, test, deny, unsafe-check, msrv, the reproducible-packaging check) and stubs for the rest. Jobs that need later work are switched on by the task that makes them possible: `e2e` and `layering` (T76), `canary` and `vet` crypto check (T91), `server-db` and `server-docker` (T84–T86), `fuzz` (first target in T91), `bench` gates (T41b and others), release pipeline parts for the server (T86).


### 1. Repository-wide settings (copy from sverb)
- `rust-toolchain.toml`: `channel = "stable"`, components `rustfmt`, `clippy`. MSRV only in
  `[workspace.package] rust-version`.
- `rustfmt.toml`: `edition = "2024"`, `imports_granularity = "Crate"`,
  `group_imports = "StdExternalCrate"` (applied by nightly rustfmt, ignored by stable).
- `[workspace.lints.rust]`: `unsafe_code = "deny"`, `missing_debug_implementations = "warn"`,
  `unreachable_pub = "warn"`. `[workspace.lints.clippy]`: `all = warn`, `dbg_macro = deny`,
  `todo = warn`, `unwrap_used = warn`, `expect_used = warn`, `await_holding_lock = deny`,
  `large_futures = warn`. Every crate has `[lints] workspace = true`.
- `.github/dependabot.yml` (cargo + github-actions, weekly) and `.gitleaks.toml` /
  `secret_scanning.yml` like sverb.

### 2. `ci.yml` — on push to `master`, pull requests, manual
Common: `concurrency: ci-${{ github.ref }}` with cancel-in-progress, `permissions: contents: read`,
`CARGO_TERM_COLOR=always`, `RUST_BACKTRACE=1`, `CARGO_INCREMENTAL=0`, `Swatinem/rust-cache@v2`,
`fetch-depth: 0` where vergen-gix needs git history.

| Job | What it runs |
|---|---|
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, then the local-only build: `cargo clippy -p courier-ftp --all-targets --no-default-features --locked -- -D warnings` |
| `docs` | `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --document-private-items --all-features --workspace --locked` |
| `test-local-only` | `cargo test --workspace --no-default-features --locked --exclude courier-ftp-sync --exclude courier-ftp-server --exclude courier-ftp-e2e` with `COURIER_FTP_HOME` in `runner.temp` |
| `test-os` *(our addition — sverb has no Windows/macOS test job, but our local filesystem backend, paths and terminal suspend are OS-specific)* | matrix `windows-latest`, `macos-latest`: `cargo test --workspace --locked --exclude courier-ftp-server --exclude courier-ftp-e2e` |
| `e2e` | Docker e2e suite (T76): build the fixture images with `docker/build-push-action` + GHA layer cache, validate every server profile (`--check`), build the binary, `cargo test -p courier-ftp-e2e --locked --no-fail-fast -- --ignored --test-threads=4` with `COURIER_E2E=1`; on failure `docker ps -a`. Required check. |
| `server-db` | Postgres 16 service; `DATABASE_URL` set; `cargo test -p courier-ftp-server --locked` (each DB test creates and drops its own database) |
| `server-docker` | `docker compose -f deploy/docker-compose.yml config --quiet`, `up -d --build`, wait for `/healthz` (60 s), check `/readyz` and that a `setup_token` was logged, check the image user is not root, tear down |
| `bench-build` | `cargo bench --workspace --no-run --locked`; `python3 scripts/bench-gate.py self-test` |
| `deny` | `EmbarkStudios/cargo-deny-action@v2`: `check advisories bans licenses sources --all-features --locked` |
| `vet` | `cargo vet --locked`; `python3 scripts/check-vet-crypto.py` (warns while crypto crates are exempted) |
| `msrv` | read `rust-version` via `cargo metadata` (fail if crates disagree), install that toolchain, `cargo +MSRV check --workspace --all-features --locked` |
| `layering` | `cargo test -p courier-ftp-e2e --test workspace_metadata --locked` plus `python3 scripts/check-layering.py` (independent second implementation) |
| `unsafe-check` | `python3 scripts/check-unsafe.py` |
| `canary` | Postgres service; `COURIER_FTP_LOG_LEVEL=trace`, `COURIER_FTP_KEYRING=off`; `scripts/canary-scan.sh --self-test`; run the whole suite with `TMPDIR` and `COURIER_FTP_HOME` under one root; `pg_dumpall` of the server DB; `scripts/canary-scan.sh --require-files target/tmp <roots>` |
| `fuzz` | nightly toolchain + `cargo-fuzz`; `fuzz/seed-corpus.sh`; build all targets; run each 30 s (`-rss_limit_mb=2048 -timeout=10`); upload crashes |
| `nix` *(optional, if we add a flake)* | `nix flake check --no-build`, `nix build .#courier-ftp`, run `--version`, man page and completions present |
| `packaging` | `scripts/update-packaging.py --self-test`; syntax of AUR PKGBUILDs, Homebrew formula, Scoop JSON; **archives are reproducible** (package twice, `cmp`, `sha256sum -c`); `cargo package --workspace --exclude courier-ftp-e2e --locked` |

### 3. `fuzz.yml` — nightly (cron `17 3 * * *`) and manual (input: seconds per target, default 600)
Matrix over every fuzz target from T91 §7, `fail-fast: false`, 30 min timeout; restore
corpus cache, seed, run, `cargo fuzz cmin` on success, upload crashes on failure.

### 4. `bench.yml` — nightly and manual
- Restore the `main` criterion baseline from cache, `cargo bench --workspace --locked --bench '*' -- --save-baseline ci --noplot`.
- `scripts/bench-gate.py gate --baseline ci` against thresholds in `scripts/bench-gates.toml`
  (listing parser throughput, file-list render time for 100k entries, envelope seal/open,
  merge, Argon2 unlock, transfer engine scheduling — and the transfer benchmarks of T41b
  that can run without network).
- `compare --old main --new ci --threshold 15` (fail on > 15 % regressions).
- Startup gate: time from launch to the unlocked file panes with 1 000 sites (keyring
  unlock, test hook), e.g. < 200 ms.
- On `master`: promote and save the baseline.

### 5. `cd.yml` — on version tags (`v1.2.3`) and manual dry run
- **Release metadata**: version, publish flag, `SOURCE_DATE_EPOCH` from the tag commit.
- **Assets**: man page + shell completions generated by the binary (`courier-ftp generate man|completions`).
- **Linux** x86_64 + aarch64 **musl static** (aarch64 via `cross`) for `courier-ftp` and
  `courier-ftp-server`; check binaries are static; **reproducibility check** (rebuild in a
  second target dir and `cmp`).
- **macOS universal** (`lipo` of x86_64 + arm64), sign and notarize when the secrets exist.
- **Windows** x86_64 (CRLF conversion disabled for packaging).
- **Server image** `ghcr.io/viperh/courier-ftp-server` amd64 + arm64 from
  `deploy/Dockerfile.server.release`, smoke test each architecture, push.
- **GitHub release**: CycloneDX SBOM, `SHA256SUMS`, notes extracted from `CHANGELOG.md`;
  dry runs keep artifacts instead of publishing.
- **Package channels**: AUR (`courier-ftp`, `courier-ftp-bin`), Homebrew tap, Scoop bucket
  updated from the release checksums (`scripts/update-packaging.py`).
- `scripts/release-package.sh` builds deterministic archives (fixed mtimes/owners/order).
- This replaces the template's current `cd.yml` (which builds glibc Linux, macOS x86_64/arm64
  separately, Windows, and i686). Drop i686 unless you ask for it.

### 6. Scripts (adapted copies)
`scripts/canary-scan.sh`, `check-unsafe.py`, `check-layering.py` (rules: UI crates on top;
core/crypto/store/proto/protocol crates never depend on ratatui/crossterm/clap; server never
depends on client UI crates; crypto has no I/O deps), `check-vet-crypto.py`, `bench-gate.py`
+ `bench-gates.toml`, `release-package.sh`, `update-packaging.py`, `fuzz/seed-corpus.sh`.

### 7. Branch protection (document in `CONTRIBUTING.md`)
Required checks: fmt, clippy, docs, test-local-only, test-os, e2e, server-db, deny,
unsafe-check, layering, canary, fuzz. `CONTRIBUTING.md` sections like sverb's: logging rules,
canary secrets (prefixes and where to keep test homes), `unsafe`, fuzzing, generated docs
(`COURIER_FTP_BLESS=1` to refresh), releases.

## Acceptance criteria

- [ ] All `ci.yml` jobs exist and pass on a PR.
- [ ] Nightly fuzz and bench workflows run (manual dispatch tested).
- [ ] A `workflow_dispatch` dry run of `cd.yml` produces all artifacts, SBOM and checksums, and the reproducibility checks pass.
- [ ] Scripts have self-tests that run in CI.
- [x] `CONTRIBUTING.md` documents every check and how to run it locally.

## Tests

- The workflows themselves; each script's `--self-test`.
