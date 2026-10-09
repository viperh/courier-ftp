# T00 — CI/CD workflows (sverb parity)

**Phase:** A Foundation (first task; extended as features land) · **Milestone:** M1 · **Depends on:** — · **Crate(s):** none (repo-wide: `.github/`, `scripts/`, `fuzz/`, root config files) · **Decisions:** D9, D13, D15 · **FEATURES.md:** — (infrastructure)
**Related (integrates with, not blocking):** T76, T91, T41b, T84, T85, T86
**Reference:** sverb `.github/workflows/{ci,cd,fuzz,bench}.yml`, `.github/{dependabot.yml,secret_scanning.yml}`, `.gitleaks.toml`, `scripts/*`, `deny.toml`, `supply-chain/`, `rust-toolchain.toml`, `rustfmt.toml`, `Cargo.toml` `[workspace.lints]`, `fuzz/{Cargo.toml,seed-corpus.sh}`, `CONTRIBUTING.md`, `docs/release.md`, SPEC §17, §19, §20.

## Goal

courier-ftp gets the same CI/CD setup as sverb, adapted to its own crates. Every pull
request runs formatting, lints, docs, tests on Linux/Windows/macOS, the Docker e2e suite,
supply-chain checks, layering and `unsafe` checks, the canary scan and a short fuzz run.
Nightly workflows run long fuzzing and benchmark gates. A tag push builds reproducible,
static release archives for the client and the sync server, the server image, an SBOM
and checksums, and updates the package channels.

## Context

**Before this task** (template state after `setup.sh`):

- `.github/workflows/ci.yml` triggers on pushes to `main` (the default branch is `master`)
  and runs four jobs (`test`, `rustfmt`, `clippy`, `docs`) without `--locked` on clippy/docs.
- `.github/workflows/cd.yml` triggers on `[v]?X.Y.Z` tags and builds **glibc** binaries for
  macOS x86_64 + arm64 (separately), Linux x86_64/aarch64/i686 and Windows; no checksums
  file, no SBOM, no reproducibility check.
- No `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `supply-chain/`, `scripts/`,
  `fuzz/`, `[workspace.lints]`; `rust-version = "1.85"` (too low for the pinned
  `vergen-gix 10.0.1`).
- Two crates: `courier-ftp` (binary) and `courier-ftp-core`.

**After this task**, later tasks rely on:

- The job names below as required checks (every task's acceptance criteria say "the T00
  CI gates pass").
- `scripts/check-layering.py` and `scripts/check-unsafe.py` already knowing every planned
  crate (T01 creates them; T76 adds the second layering implementation).
- `scripts/canary-scan.sh` (T91), `scripts/bench-gate.py` + `bench-gates.toml` (T41b,
  T13, T53, T30, T80 add gates), `fuzz/` (first target from T91/T13), the `cd.yml`
  release pipeline (T77, T86 add the server parts).
- The `detect` job, which switches jobs on automatically when the files they need exist
  (no workflow edits are needed when a later task lands).

## Technical specification

### Types and APIs

Not Rust APIs: the "interfaces" of this task are files, job names and script command lines.

**File layout created by this task**

```
rust-toolchain.toml
rustfmt.toml
deny.toml
.gitleaks.toml
.github/
  dependabot.yml
  secret_scanning.yml
  workflows/{ci,cd,fuzz,bench}.yml
supply-chain/{config.toml,audits.toml,imports.lock}
scripts/
  canary-scan.sh          check-layering.py      check-unsafe.py
  check-vet-crypto.py     bench-gate.py          bench-gates.toml
  release-package.sh      update-packaging.py
fuzz/
  Cargo.toml              (own workspace, crate `courier-ftp-fuzz`, publish = false)
  seed-corpus.sh
  fuzz_targets/           (empty until T91/T13 add the first target)
packaging/
  aur/courier-ftp/PKGBUILD          aur/courier-ftp-bin/PKGBUILD
  homebrew/courier-ftp.rb           scoop/courier-ftp.json
CONTRIBUTING.md
```

**Script command lines** (all scripts use only the Python 3.11+ standard library or bash
+ coreutils; every script prints usage on bad arguments and exits 2):

| Script | Usage | Exit codes |
|---|---|---|
| `scripts/check-unsafe.py` | `[--root DIR]` | 0 clean, 1 violation |
| `scripts/check-layering.py` | `[--manifest-path Cargo.toml]` | 0 clean, 1 violation, 2 `cargo metadata` failed |
| `scripts/check-vet-crypto.py` | `[supply-chain/config.toml]`; env `VET_CRYPTO_STRICT=1` makes warnings fatal | 0 ok/warn, 1 strict failure |
| `scripts/canary-scan.sh` | `--self-test` \| `[--require-files] [DIR…]`; env `COURIER_FTP_CANARY_DIRS` (colon-separated extra dirs) | 0 clean, 1 canary found, 2 usage / nothing scanned with `--require-files` |
| `scripts/bench-gate.py` | `gate [--local] [--dir target/criterion] [--baseline ci]` \| `compare --old main --new ci [--threshold 15]` \| `self-test` | 0 ok, 1 gate/regression failed, 2 missing data |
| `scripts/release-package.sh` | `<courier-ftp\|courier-ftp-server> <version> <label> <binary> <out-dir> [assets-dir]` | 0 ok, 2 usage |
| `scripts/update-packaging.py` | `<version> <SHA256SUMS> [--source-sha256 HEX] [--out DIR]` \| `--self-test` | 0 ok, 1 error |
| `fuzz/seed-corpus.sh` | `[corpus-dir]` (default `fuzz/corpus`) | 0 |

### Behaviour

#### 1. Repository-wide settings

- `rust-toolchain.toml`: `[toolchain] channel = "stable"`, `components = ["rustfmt", "clippy"]`.
  The MSRV lives only in `[workspace.package] rust-version`.
- `rust-version = "1.95"` (sverb's value for the same pinned dependency set:
  `rusqlite_migration 2.6`, `vergen-gix 10.0.1`). The `msrv` job proves it.
- `rustfmt.toml`: `edition = "2024"`, `imports_granularity = "Crate"`,
  `group_imports = "StdExternalCrate"` (nightly rustfmt applies the last two, stable ignores
  them with a warning).
- Root `Cargo.toml`:
  ```toml
  [workspace]
  resolver = "3"
  members = ["crates/*"]
  exclude = ["fuzz"]

  [workspace.lints.rust]
  unsafe_code = "deny"            # not forbid: hardening/ needs an inner allow (T91)
  missing_debug_implementations = "warn"
  unreachable_pub = "warn"

  [workspace.lints.clippy]
  all = { level = "warn", priority = -1 }
  dbg_macro = "deny"
  todo = "warn"
  unwrap_used = "warn"
  expect_used = "warn"
  await_holding_lock = "deny"
  large_futures = "warn"
  ```
  Every crate's `Cargo.toml` has `[lints] workspace = true` (added to the two existing
  crates here). With `-D warnings` in CI, `unwrap_used`/`expect_used` are effectively
  denied in non-test code; test modules and integration tests put
  `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top.
- `[profile.release]`: `codegen-units = 1`, `lto = true`, `opt-level = 3` (was `"s"`;
  T41b throughput and T53 render targets matter more than size), `panic = "unwind"`
  (the panic hook relies on unwinding to restore the terminal), `strip = true`.
- `.github/dependabot.yml`: `cargo` and `github-actions`, weekly, `open-pull-requests-limit: 10`,
  cargo patch updates grouped (`cargo-patch`), all actions grouped (`actions`).
- `.gitleaks.toml` (`[extend] useDefault = true`, allowlist paths
  `^tests/fixtures/sshd/keys/`, `^tests/fixtures/tls/`, `^tests/fixtures/keys/`) and
  `.github/secret_scanning.yml` (`paths-ignore` with the same three globs). These
  directories hold TEST-ONLY keys (T76).

#### 2. `ci.yml`

Triggers: `push` to `master`, `pull_request`, `workflow_dispatch`.
Top level: `concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }`,
`permissions: contents: read`, `env: CARGO_TERM_COLOR=always, RUST_BACKTRACE=1, CARGO_INCREMENTAL=0`.
Every job: `actions/checkout@v4` (`fetch-depth: 0` wherever the binary is built, because
`vergen-gix` in `crates/courier-ftp/build.rs` reads history and tags),
`dtolnay/rust-toolchain@stable` (or `@nightly` / `@master` where stated),
`Swatinem/rust-cache@v2`. Every job's `name:` equals its id (that is the check name used
by branch protection; matrix jobs appear as `test-os (windows-latest)` etc.).

**`detect` job** (runs first, ~5 s, no Rust): `actions/checkout@v4`, then one shell step
writes these outputs (`true`/`false`) with `test -f`:

| Output | True when this file exists | Switched on by |
|---|---|---|
| `e2e` | `crates/courier-ftp-e2e/Cargo.toml` | T76 |
| `server_crate` | `crates/courier-ftp-server/Cargo.toml` | T01 (gates `server-db`; its DB tests appear with T84) |
| `server` | `deploy/docker-compose.yml` | T86 (gates `server-docker`) |
| `fuzz_targets` | at least one `fuzz/fuzz_targets/*.rs` | T91 / T13 |
| `vet` | `supply-chain/config.toml` | T00 (always true after this task) |
| `generate` | `crates/courier-ftp/src/cli/generate.rs` (the `generate` subcommand, T77) | T77 |

Jobs that need one of them declare `needs: detect` and
`if: needs.detect.outputs.<x> == 'true'`. A job skipped by its `if` reports success, so
it can be a required check from day one and starts running the day its files land.

**Jobs:**

| Job | Runner | Steps (commands exactly as run) |
|---|---|---|
| `fmt` | ubuntu-latest | toolchain with `rustfmt`; `cargo fmt --all --check` |
| `clippy` | ubuntu-latest | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`; then the local-only build: `cargo clippy -p courier-ftp --all-targets --no-default-features --locked -- -D warnings` |
| `docs` | ubuntu-latest | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --locked` |
| `test` | ubuntu-latest | `cargo test --workspace --all-features --locked` (includes the e2e crate's Docker-free harness self-tests; its container tests are `#[ignore]`d) with `COURIER_FTP_HOME=${{ runner.temp }}/courier-ftp-home`, `COURIER_FTP_KEYRING=off`. Server DB tests skip without `DATABASE_URL` (they run in `server-db`). |
| `test-os` | matrix `windows-latest`, `macos-latest`, `fail-fast: false` | `cargo test --workspace --all-features --locked --exclude courier-ftp-server --exclude courier-ftp-e2e` (same env, `shell: bash`). Our addition: sverb has no such job, but the local backend (T06), paths, keyring and terminal suspend are OS-specific. |
| `test-local-only` | ubuntu-latest | `cargo test --workspace --no-default-features --locked --exclude courier-ftp-sync --exclude courier-ftp-server --exclude courier-ftp-e2e` (same env). Proves the client works without the `sync` feature (project rule). `--exclude` of a not-yet-existing crate only prints a warning. |
| `e2e` | ubuntu-latest, `timeout-minutes: 45`, `needs: detect`, `if: e2e` | env `COURIER_E2E=1`, `COURIER_E2E_SSHD_IMAGE=courier-ftp-e2e-sshd:ci`, `COURIER_E2E_FTPD_IMAGE=courier-ftp-e2e-ftpd:ci`, `COURIER_E2E_PROXY_IMAGE=courier-ftp-e2e-proxy:ci`; `docker info`; `docker/setup-buildx-action@v3`; one `docker/build-push-action@v6` per fixture dir (`tests/fixtures/{sshd,ftpd,proxy}`, `load: true`, `cache-from/to: type=gha,scope=courier-ftp-e2e-<name>`, `mode=max`); validate every profile: for each image `for p in $(docker run --rm "$IMAGE" --list); do docker run --rm -e <SSHD|FTPD|PROXY>_PROFILE="$p" "$IMAGE" --check; done` (`--list` prints the image's profile names, one per line, T76); when `deploy/Dockerfile.server` exists also build `courier-ftp-server:e2e` from it (env `COURIER_E2E_SERVER_IMAGE`); `cargo build -p courier-ftp --locked`; `cargo test -p courier-ftp-e2e --locked --no-fail-fast -- --ignored --test-threads=4`; `if: always()`: `scripts/canary-scan.sh target/tmp` (homes the scenarios kept, T76/T91); on `failure()`: `docker ps -a`. |
| `server-db` | ubuntu-latest, `needs: detect`, `if: server_crate`, service `postgres:16` (`POSTGRES_USER/PASSWORD/DB=courier`, port 5432, `--health-cmd "pg_isready -U courier" --health-interval 5s --health-timeout 5s --health-retries 10`) | env `DATABASE_URL=postgres://courier:courier@localhost:5432/courier`; `cargo test -p courier-ftp-server --locked`. Each DB test creates and drops its own database. |
| `server-docker` | ubuntu-latest, `needs: detect`, `if: server` | env `COURIER_SERVER_SECRET=c1c1c1c1000102030405060708090a0b0c0d0e0f101112131415161718191a1b` (CI-only test value), `COURIER_PUBLIC_URL=http://localhost:8080`; `docker compose -f deploy/docker-compose.yml config --quiet`; `up -d --build`; poll `curl -fsS http://localhost:8080/healthz` once per second for 60 s (on timeout print compose logs, fail); `curl -fsS http://localhost:8080/readyz`; `docker compose … logs courier-ftp-server \| grep -q setup_token`; `docker inspect --format '{{.Config.User}}' courier-ftp-server:local` must not be empty, `root`, `0`, `0:0`, `root:root`; `if: always()` `down -v`. |
| `bench-build` | ubuntu-latest | `cargo bench --workspace --no-run --locked`; `python3 scripts/bench-gate.py self-test` |
| `deny` | ubuntu-latest | `EmbarkStudios/cargo-deny-action@v2` with `command: check advisories bans licenses sources`, `arguments: --all-features --locked` |
| `vet` | ubuntu-latest | `taiki-e/install-action@v2` (`tool: cargo-vet`); `cargo vet --locked`; `python3 scripts/check-vet-crypto.py` |
| `msrv` | ubuntu-latest | read the MSRV: `cargo metadata --no-deps --format-version 1 --locked \| jq -r '[.packages[].rust_version // empty] \| unique \| if length == 1 then .[0] else error("workspace crates disagree on rust-version: \(.)") end'`; install it with `dtolnay/rust-toolchain@master` (`toolchain: <msrv>`); rust-cache `key: msrv-<msrv>`; `cargo +<msrv> check --workspace --all-features --locked` |
| `layering` | ubuntu-latest | `python3 scripts/check-layering.py`; when `crates/courier-ftp-e2e` exists (T76) also `cargo test -p courier-ftp-e2e --test workspace_metadata --test forbid_unsafe --locked` |
| `unsafe-check` | ubuntu-latest | `python3 scripts/check-unsafe.py` |
| `canary` | ubuntu-latest, service `postgres:16` (as `server-db`) | env `COURIER_FTP_LOG_LEVEL=trace`, `COURIER_FTP_KEYRING=off`, `DATABASE_URL=…`; `scripts/canary-scan.sh --self-test`; `mkdir -p "$RUNNER_TEMP/canary/tmp" "$RUNNER_TEMP/canary/home"`; `TMPDIR=$RUNNER_TEMP/canary/tmp COURIER_FTP_HOME=$RUNNER_TEMP/canary/home cargo test --workspace --all-features --locked --no-fail-fast`; `if: always()`: `PGPASSWORD=courier pg_dumpall -h localhost -U courier > "$RUNNER_TEMP/canary/tmp/server-dump.sql" \|\| echo "pg_dumpall unavailable"`; `if: always()`: `scripts/canary-scan.sh --require-files target/tmp "$RUNNER_TEMP/canary/tmp" "$RUNNER_TEMP/canary/home"`. Until T91 lands the binary canary fixture, `--require-files` is passed only when `crates/courier-ftp/tests/canary.rs` exists (shell `test -f` in the step). |
| `fuzz` | ubuntu-latest, `needs: detect`, `if: fuzz_targets` | nightly toolchain; `cargo-fuzz` via `taiki-e/install-action@v2`; rust-cache `workspaces: fuzz`; `fuzz/seed-corpus.sh`; `cargo +nightly fuzz build --target x86_64-unknown-linux-gnu`; for each target of `cargo +nightly fuzz list`: `cargo +nightly fuzz run --target x86_64-unknown-linux-gnu "$t" "fuzz/corpus/$t" -- -max_total_time=30 -rss_limit_mb=2048 -timeout=10` (collect status, `::error::` per crashing target, fail at the end); on failure upload `fuzz/artifacts` as `fuzz-crashes` (`if-no-files-found: ignore`). |
| `packaging` | ubuntu-latest, `needs: detect` | `python3 scripts/update-packaging.py --self-test`; syntax: `bash -n packaging/aur/courier-ftp/PKGBUILD`, `bash -n packaging/aur/courier-ftp-bin/PKGBUILD`, `ruby -c packaging/homebrew/courier-ftp.rb`, `jq -e . packaging/scoop/courier-ftp.json`; **no test-only features in the shipped graphs**: `cargo tree -p courier-ftp -p courier-ftp-server -e no-dev,features --locked > tree.txt` and fail if it matches `insecure-test-ksf\|test-hooks\|test-util`; **reproducible archives** (only `if: generate`, i.e. once T77 adds `courier-ftp generate`): `cargo build --locked -p courier-ftp`, `target/debug/courier-ftp generate man --out-dir assets/man`, `… generate completions bash > assets/completions/courier-ftp.bash`, run `scripts/release-package.sh courier-ftp 0.0.0 linux-x86_64 target/debug/courier-ftp out$i assets` for `i` in 1 2, `cmp out1/courier-ftp-0.0.0-linux-x86_64.tar.gz out2/…`, `(cd out1 && sha256sum -c ./*.sha256)`; `cargo package --workspace --exclude courier-ftp-e2e --locked` (packages every publishable crate in dependency order through cargo's temporary local registry; needs the `version` on every internal `[workspace.dependencies]` entry, T01). |

No `nix` job: courier-ftp ships no Nix flake in v1 (see Open questions).

**Required checks** (branch protection on `master`, documented in `CONTRIBUTING.md`):
every job above, i.e. `detect`, `fmt`, `clippy`, `docs`, `test`, `test-os (windows-latest)`,
`test-os (macos-latest)`, `test-local-only`, `e2e`, `server-db`, `server-docker`,
`bench-build`, `deny`, `vet`, `msrv`, `layering`, `unsafe-check`, `canary`, `fuzz`, `packaging`.
Admins are included; force pushes to `master` are blocked.

#### 3. `fuzz.yml` (nightly)

- Triggers: `schedule: cron "17 3 * * *"`, `workflow_dispatch` with input `seconds`
  (default `"600"`).
- Job `list`: checkout, nightly, `cargo-fuzz`, output
  `targets=$(cargo +nightly fuzz list | jq -R . | jq -cs .)`; when the list is empty the
  `fuzz` job is skipped (`if: needs.list.outputs.targets != '[]'`).
- Job `fuzz`: `strategy: { fail-fast: false, matrix: { target: ${{ fromJSON(needs.list.outputs.targets) }} } }`,
  `timeout-minutes: 30`. Steps: restore corpus with `actions/cache@v4`
  (`path: fuzz/corpus/<t>`, `key: fuzz-corpus-<t>-${{ github.run_id }}`,
  `restore-keys: fuzz-corpus-<t>-`); `fuzz/seed-corpus.sh`;
  `cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <t> fuzz/corpus/<t> -- -max_total_time=${SECONDS_PER_TARGET} -rss_limit_mb=2048 -timeout=10`;
  on success `cargo +nightly fuzz cmin --target x86_64-unknown-linux-gnu <t> fuzz/corpus/<t>`;
  on failure upload `fuzz/artifacts/<t>` as `fuzz-crashes-<t>`.
- The target list is dynamic (sverb hard-codes it), so adding `fuzz/fuzz_targets/<name>.rs`
  plus its `[[bin]]` is enough; the planned targets are listed in T91.

#### 4. `bench.yml` (nightly)

- Triggers: `schedule: cron "17 3 * * *"`, `workflow_dispatch`. `timeout-minutes: 60`.
- Steps:
  1. Restore `target/criterion` with `actions/cache/restore@v4`
     (`key: criterion-main-${{ github.run_id }}`, `restore-keys: criterion-main-`).
  2. `cargo bench --workspace --locked --bench '*' -- --save-baseline ci --noplot`.
  3. `python3 scripts/bench-gate.py gate --baseline ci` (CI thresholds, see below).
  4. If `target/criterion/*/*/main/estimates.json` exists:
     `python3 scripts/bench-gate.py compare --old main --new ci --threshold 15`
     (fail on a median > 15 % slower), else print "No main baseline yet".
  5. Startup gate (once T60 + T31 exist, i.e. `crates/courier-ftp/tests/startup.rs` exists):
     `COURIER_FTP_STARTUP_GATE_MS=200 cargo test --release --locked -p courier-ftp --features test-hooks --test startup -- --ignored --nocapture`.
     The test (owned by T76) creates a home with 1 000 sites and keyring unlock through a
     file-backed test keyring, then measures launch → file panes drawn; median of 20 runs
     must be < 200 ms.
  6. On `refs/heads/master` only: copy every `…/ci` to `…/main` and save the cache
     (`actions/cache/save@v4`, same key).
- `scripts/bench-gates.toml` starts with **no** `[[gate]]` entries; `gate` with an empty
  file prints "no gates" and exits 0 (adapted from sverb, which exits 2 on a missing
  `target/criterion`). Each task adds its gate when its bench exists. Planned gates (spec
  value = reference machine, `--local`; CI value = 2× time / ½ throughput):

  | `bench` (criterion `group/function`) | Spec | CI | Added by |
  |---|---|---|---|
  | `listing_parse/unix_10k_lines` | `max_ms = 10` | `ci_max_ms = 20` | T13 |
  | `listing_parse/mlsd_10k_lines` | `max_ms = 10` | `ci_max_ms = 20` | T13 |
  | `file_list/sort_100k` | `max_ms = 50` | `ci_max_ms = 100` | T53 |
  | `file_list/render_100k_160x48` | `max_ms = 2` | `ci_max_ms = 4` | T53 |
  | `index_build_10k/decrypt_and_index` | `max_ms = 75` | `ci_max_ms = 150` | T30 |
  | `transfer_schedule/plan_10k_files` | `max_ms = 20` | `ci_max_ms = 40` | T41b |
  | `ascii_convert/crlf_8MiB` | `min_mb_s = 500` | `ci_min_mb_s = 250` | T11 |

  Informational benches without a gate (regressions still caught by `compare`):
  `envelope/seal_open_1k`, `merge/1k_items`, `argon2/unlock_default`.

#### 5. `cd.yml` (release)

Header comment lists the published artifacts and the optional secrets, as sverb's does.
Triggers: `push: tags: ['v[0-9]+.[0-9]+.[0-9]+*']`, `workflow_dispatch` (always a dry run).
`permissions: contents: read` at top level; jobs elevate only what they need.

| Job | Needs | Does |
|---|---|---|
| `meta` | — | reads `workspace.package.version` with `python3 -c 'import tomllib; …'`; on a tag requires `GITHUB_REF_NAME == "v$version"` (else `::error::` + exit 1) and sets `publish=true`; manual runs set `publish=false`; outputs `version`, `publish`, `source-date-epoch=$(git log -1 --format=%ct)` |
| `assets` | meta | `if: generate` file exists (T77); with `COURIER_FTP_HOME=$RUNNER_TEMP/h COURIER_FTP_KEYRING=off`: `cargo build --locked -p courier-ftp`, `courier-ftp generate man --out-dir assets/man`, `generate completions {bash,zsh,fish,powershell,elvish}` → `assets/completions/{courier-ftp.bash,_courier-ftp,courier-ftp.fish,_courier-ftp.ps1,courier-ftp.elv}` (the five shells of T70); `bash -n` on the bash file; `groff -man -ww -z assets/man/courier-ftp.1`; upload `courier-ftp-assets` |
| `linux` | meta, assets | matrix `x86_64-unknown-linux-musl` (`musl-tools`, native) and `aarch64-unknown-linux-musl` (`cross`); `RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols --remap-path-prefix=$GITHUB_WORKSPACE=/build/courier-ftp --remap-path-prefix=$HOME/.cargo=/cargo"`, `SOURCE_DATE_EPOCH` from `meta`; `cargo build --locked --release -p courier-ftp -p courier-ftp-server --target <t>`; **static check**: `file <bin> \| grep -Eq 'statically linked\|static-pie linked'`; **reproducibility** (x86_64 only): `git worktree add --detach $RUNNER_TEMP/rebuild HEAD`, rebuild there with its own remap prefix and `CARGO_TARGET_DIR=$RUNNER_TEMP/rebuild-target`, `cmp` both binaries; package both with `scripts/release-package.sh`; copy the server binary to `image/courier-ftp-server-{amd64,arm64}`; upload `dist-linux-<arch>` and `image-linux-<arch>` |
| `macos` | meta, assets | `macos-14`; build `x86_64-apple-darwin` and `aarch64-apple-darwin` with the same remap flags; `lipo -create` → `universal/courier-ftp`; `lipo -info` must list `x86_64` and `arm64`; sign + notarize when `APPLE_CERTIFICATE_P12` and `APPLE_SIGNING_IDENTITY` are set (keychain import, `codesign --force --options runtime --timestamp`, `xcrun notarytool submit --wait` when `APPLE_NOTARY_KEY` is set), otherwise `::notice::` unsigned; package `macos-universal` (`gnu-tar` via brew) |
| `windows` | meta, assets | `git config --global core.autocrlf false` **before** checkout; `cargo build --locked --release -p courier-ftp --target x86_64-pc-windows-msvc`; package `windows-x86_64` (zip) |
| `image` | meta, linux | `packages: write`; context `ctx/` = `deploy/Dockerfile.server.release` + both server binaries; `docker/setup-qemu-action@v3`, `setup-buildx-action@v3`; per arch (`amd64`, `arm64`): `buildx build --platform linux/<a> --load -t courier-ftp-server:local`, `docker run --rm courier-ftp-server:local --version \| grep -F "$VERSION"`, compose up with a `platform:` override file, wait up to 240 s (120 × 2 s) for `State.Health.Status == healthy`, print diagnostics and fail otherwise, `down -v`; when `publish`: login to `ghcr.io` with `GITHUB_TOKEN`, push `ghcr.io/${{ github.repository_owner }}/courier-ftp-server:<v>` and `:latest` for `linux/amd64,linux/arm64` with label `org.opencontainers.image.source` |
| `release` | meta, linux, macos, windows, image | `contents: write`; download `dist-*`; `cargo-cyclonedx` (install `continue-on-error`) → `courier-ftp-<v>.cdx.json` into `dist/`; `cat ./*.sha256 \| sort -k2 > SHA256SUMS`; `sha256sum -c SHA256SUMS`; notes = the `## [<v>]` section of `CHANGELOG.md` (awk, as sverb), fallback "See CHANGELOG.md."; `publish`: `softprops/action-gh-release@v2` with `tag_name: v<v>`, `body_path: notes.md`, `files: dist/*`; dry run: upload `dist` + `notes.md` as `release-dry-run` |
| `channels` | meta, release; `if: publish` | download `SHA256SUMS` with `gh release download`, source tarball sha256, `python3 scripts/update-packaging.py <v> release/SHA256SUMS --source-sha256 … --out out`; AUR `courier-ftp` + `courier-ftp-bin` (`KSXGitHub/github-actions-deploy-aur@v3`, only if `AUR_SSH_PRIVATE_KEY`), Homebrew tap `<owner>/homebrew-courier-ftp` (`HOMEBREW_TAP_TOKEN`), Scoop bucket `<owner>/scoop-courier-ftp` (`SCOOP_BUCKET_TOKEN`); each channel is skipped when its secret is missing |

Release artifacts: `courier-ftp-<v>-linux-{x86_64,aarch64}.tar.gz`,
`courier-ftp-<v>-macos-universal.tar.gz`, `courier-ftp-<v>-windows-x86_64.zip`,
`courier-ftp-server-<v>-linux-{x86_64,aarch64}.tar.gz`, one `.sha256` per archive,
`SHA256SUMS`, `courier-ftp-<v>.cdx.json`. The template's glibc builds, separate macOS
archives and the **i686** target are dropped (see Open questions).

Until T77 adds `generate` and T86 adds `deploy/`, the `assets` and `image` jobs are skipped
by `if:` (the `meta` job outputs `has-generate` / `has-server-image` from `test -f`) and
`release` drops them from `needs` via `if: always() && !failure() && !cancelled()`.

#### 6. Scripts (adapted from sverb)

- **`check-unsafe.py`**: `ALLOWED = ("crates/courier-ftp-core/src/hardening/",)`. Fails
  when an attribute lifts `unsafe_code` (`allow|expect|warn(…unsafe_code…)`, also inside
  `cfg_attr`; string literals and `//` comments stripped first) in any `crates/**/*.rs`
  outside `ALLOWED`; when a crate manifest lacks `[lints] workspace = true` or sets
  `unsafe_code` in its own `[lints.rust]`; when the workspace level is not `deny`/`forbid`.
  Skips `target/`.
- **`check-layering.py`**: same algorithm as sverb (direct internal deps against an allow
  list; transitive closure of *normal* deps, all targets, against a forbidden set; run for
  `--all-features` and `--no-default-features`; every workspace member must have a rule).
  `INTERNAL_PREFIX = "courier-ftp"`, `UI = {"ratatui", "crossterm"}`. Rules:

  | Crate | Allowed direct internal deps | Forbidden anywhere in the closure |
  |---|---|---|
  | `courier-ftp-crypto` | none | UI, `clap`, `tokio`, `mio`, `hyper`, `reqwest`, `rusqlite`, `sqlx-core`, `russh` |
  | `courier-ftp-proto` | `courier-ftp-crypto` | UI, `clap`, `rusqlite`, `russh` |
  | `courier-ftp-core` | `courier-ftp-crypto`, `courier-ftp-proto` | UI, `clap`, `russh`, `courier-ftp-store` |
  | `courier-ftp-store` | `courier-ftp-core`, `courier-ftp-crypto` | UI, `clap`, `russh` |
  | `courier-ftp-proto-ftp` | `courier-ftp-core` | UI, `clap`, `russh`, `rusqlite` |
  | `courier-ftp-proto-sftp` | `courier-ftp-core` | UI, `clap`, `rusqlite` |
  | `courier-ftp-sync` | `courier-ftp-core`, `courier-ftp-store`, `courier-ftp-proto`, `courier-ftp-crypto` | UI, `clap`, `russh` |
  | `courier-ftp-server` | `courier-ftp-proto`, `courier-ftp-crypto` | UI, `russh`, `rusqlite`, `courier-ftp-core`, `courier-ftp-store`, `courier-ftp-proto-ftp`, `courier-ftp-proto-sftp`, `courier-ftp-sync`, `courier-ftp` |
  | `courier-ftp` | any | `courier-ftp-server` |
  | `courier-ftp-e2e` | any | — |

  Plus: `courier-ftp-sync` may be a dependency of `courier-ftp` (and dev-dependency of
  `courier-ftp-e2e`) only with `optional = true`, and the `--no-default-features` closure of
  `courier-ftp` must not contain `courier-ftp-sync`.
- **`check-vet-crypto.py`**: `CRYPTO = {chacha20poly1305, argon2, hkdf, sha2, hpke,
  opaque-ke, x25519-dalek, ed25519-dalek, rand_core, zeroize, secrecy, bip39, zxcvbn,
  rustls, ring, russh}`; exempted members are reported as `::warning::`; fatal with
  `VET_CRYPTO_STRICT=1`.
- **`canary-scan.sh`**: sverb's scanner with courier-ftp artifact classes:

  | Class | Matches (path relative to the scanned dir) |
  |---|---|
  | `crash` | `*/crash/*` |
  | `edit` | `*/edit/*` (T63 temp copies of edited remote files) |
  | `backup` | `*.cftp-backup` (T30/T73) |
  | `db` | `*.db`, `*.db-wal`, `*.db-shm`, `*.db-journal`, `*.sqlite*` |
  | `dump` | `*.sql`, `*.dump`, `*.pgdump` |
  | `log` | `*.log`, `*.log.*`, `courier-ftp.*.log`, `session*.log*` (T71 session log) |

  Rules: a secret canary (case-insensitive `canary-[a-z0-9_]` that is not
  `canary-host-…`) must not appear in any classified file; a host canary
  (`canary-host-`) must not appear on `INFO`/`WARN`/`ERROR` lines of `log` files (line
  format `<RFC3339 ts> +<LEVEL> …`, continuation lines inherit the level) nor anywhere in
  `crash`, `edit`, `backup`, `db`, `dump` files. **Exception:** the T71 session log
  (`session*.log*`) is a user-requested transcript and may contain host canaries, never
  secret canaries. Default dirs: `target/tmp` plus `$COURIER_FTP_CANARY_DIRS`.
  `--self-test` builds a clean tree (must pass) and one dirty tree per case
  (`info-secret`, `debug-secret`, `info-host`, `crash-host`, `db-secret`, `wal-host`,
  `backup-secret`, `edit-secret`, `session-log-secret`), each of which must be detected.
- **`bench-gate.py`**: sverb's script, plus: an empty gate file → exit 0; the self-test
  also covers the empty file.
- **`release-package.sh`**: sverb's script with names `courier-ftp` / `courier-ftp-server`;
  temp dir prefix `courier-ftp-release.`; `courier-ftp` archives need the assets dir and
  contain `man/courier-ftp.1` and `completions/*`; archive = one top-level dir
  `<name>-<v>-<label>/` with the binary, `LICENSE`, `README.md`, `CHANGELOG.md`; entries
  sorted, owner `0:0`, mtime `SOURCE_DATE_EPOCH` (default: last commit time, else 0),
  `gzip -n -9`; Windows labels produce a `.zip` (`zip -X`, sorted). Writes
  `<file>.sha256` (`<hex>  <file>`).
- **`update-packaging.py`**: rewrites version and checksums in the four `packaging/` files
  (in place or under `--out`), refuses non-SemVer versions, errors when an archive is
  missing from `SHA256SUMS`; `--self-test` checks the rewriting offline.
- **`fuzz/seed-corpus.sh`**: copies fixtures into `fuzz/corpus/<target>/fixture-<dir>-<file>`
  (idempotent, keeps existing entries) and writes hand-made seeds with `printf`. Seed
  sources are listed per target in T91.

#### 7. `CONTRIBUTING.md`

Sections (sverb's structure): **Checks** (every CI job with the local command, and
`act`-free alternatives), **Logging** (T91 rules, link to `docs/threat-model.md`),
**Canary secrets** (prefixes `CANARY-PW-`, `CANARY-PASS-`, `CANARY-KEY-`, `CANARY-TOKEN-`,
`CANARY-TOTP-`, `CANARY-WORDS-`, hostnames `canary-host-….example`; keep scanned test homes
under `CARGO_TARGET_TMPDIR`; FileZilla XML exports in tests must not use canary passwords
because exports are plaintext by design), **`unsafe`**, **Fuzzing** (how to add a target),
**E2E tests** (T76: `COURIER_E2E=1`, Linux Docker host), **Generated docs**
(`COURIER_FTP_BLESS=1` to refresh, T77), **Releases** (conventional commits, link to
`docs/release.md`, T77), **Branch protection** (the required checks list above).

### Data formats and configuration

- **`deny.toml`** (copy of sverb's, adapted):
  - `[graph] all-features = true`; `[output] feature-depth = 1`.
  - `[advisories] version = 2`, `unmaintained = "workspace"`, `yanked = "deny"`,
    `ignore = [{ id = "RUSTSEC-2023-0071", reason = "Marvin timing side channel in rsa via russh; no patched release; RSA keys are opt-in, Ed25519 is the default" }]`.
  - `[licenses] version = 2`, `allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0", "CC0-1.0", "0BSD", "MPL-2.0"]`,
    `confidence-threshold = 0.9`, `unused-allowed-license = "allow"`,
    `exceptions = [{ allow = ["CDLA-Permissive-2.0"], crate = "webpki-roots" }]`,
    `[licenses.private] ignore = true`.
  - `[bans] multiple-versions = "warn"`, `wildcards = "allow"`, `highlight = "all"`,
    `deny = [openssl, openssl-sys, native-tls (D9: rustls only),
    { crate = "ratatui", wrappers = ["courier-ftp"] },
    { crate = "crossterm", wrappers = ["courier-ftp", "ratatui", "ratatui-crossterm"] },
    { crate = "courier-ftp-sync", wrappers = ["courier-ftp", "courier-ftp-e2e"] }]`,
    each with a `reason`.
  - `[sources] unknown-registry = "deny"`, `unknown-git = "deny"`,
    `allow-registry = ["https://github.com/rust-lang/crates.io-index"]`, `allow-git = []`.
- **`supply-chain/config.toml`**: `[cargo-vet] version = "0.10"`, imports
  `bytecode-alliance`, `google`, `isrg`, `mozilla`, `zcash`, `zcashfoundation` (same URLs
  as sverb); `[[exemptions.<crate>]]` generated with `cargo vet regenerate exemptions`
  (`criteria = "safe-to-deploy"`). A PR that adds or bumps a dependency must keep
  `cargo vet --locked` green (import an audit, certify, or add an exemption in the same PR).
- **Workflow env vars used by tests**: `COURIER_FTP_HOME` (T01), `COURIER_FTP_KEYRING=off`
  (T91: disables the OS keyring), `COURIER_FTP_LOG_LEVEL` (existing), `COURIER_E2E`,
  `COURIER_E2E_{SSHD,FTPD,PROXY,SERVER}_IMAGE` (T76), `DATABASE_URL` (T84),
  `COURIER_FTP_STARTUP_GATE_MS` (T76), `COURIER_FTP_CANARY_DIRS` (scanner).
- **Secrets** (cd.yml only; all optional except the automatic `GITHUB_TOKEN`):
  `AUR_SSH_PRIVATE_KEY`, `HOMEBREW_TAP_TOKEN`, `SCOOP_BUCKET_TOKEN`,
  `APPLE_CERTIFICATE_P12`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`,
  `APPLE_NOTARY_KEY`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER`.

### Errors

Not applicable to Rust code. Failure reporting rules for workflows and scripts:
- Scripts print one line per violation to stderr, prefixed with the file/crate, and use the
  exit codes in the table above; GitHub annotations use `::error::` / `::warning::`.
- A job never swallows a failing command (`set -euo pipefail` in every multi-line bash
  step; loops collect a status and `exit $status` at the end).
- On CI (`CI=true`) a missing Docker daemon in `e2e` is a failure, not a skip (T76).

### Security and logging

- `permissions: contents: read` everywhere; only `cd.yml` jobs `image` (`packages: write`)
  and `release` (`contents: write`) elevate. No `pull_request_target` triggers. Secrets are
  only referenced in `cd.yml`, never in `ci.yml` (PRs from forks get none).
- Third-party actions are pinned to a major version tag as in sverb (`@v4`, `@v2` …);
  Dependabot keeps them current.
- The CI-only `COURIER_SERVER_SECRET` value is a public, test-only constant and is
  commented as such.
- The `canary` job runs the entire suite at `trace` level so that any secret or hostname
  logged anywhere is found (rules in T91).
- Release builds: `--locked`, `SOURCE_DATE_EPOCH`, `-C strip=symbols`,
  `--remap-path-prefix` (checkout → `/build/courier-ftp`, cargo home → `/cargo`), so
  binaries do not leak the runner's paths and can be rebuilt bit for bit.

## Implementation steps

1. Root config: `rust-toolchain.toml`, `rustfmt.toml`, `[workspace.lints]`,
   `rust-version = "1.95"`, `exclude = ["fuzz"]`, release profile; `[lints] workspace = true`
   in both crates; fix the lints this turns up in the template code (`unwrap_used` etc.).
2. Replace `ci.yml` with `detect`, `fmt`, `clippy`, `docs`, `test`, `test-os`,
   `test-local-only`, `msrv` (trigger `master`).
3. `deny.toml` + `deny` job; `supply-chain/` (`cargo vet init`, imports, regenerate
   exemptions) + `check-vet-crypto.py` + `vet` job.
4. `check-unsafe.py`, `check-layering.py` (+ `layering`, `unsafe-check` jobs).
5. `canary-scan.sh` with self-test + `canary` job (service Postgres already declared).
6. `bench-gate.py`, empty `bench-gates.toml`, `bench-build` job, `bench.yml`.
7. `fuzz/` workspace skeleton, `seed-corpus.sh`, `fuzz` job and `fuzz.yml` (both skip
   while no target exists).
8. `e2e`, `server-db`, `server-docker` jobs (skipped until T76/T84/T86 files exist).
9. `release-package.sh`, `update-packaging.py`, `packaging/` channel files, `packaging` job.
10. New `cd.yml` (replaces the template's); dry run via `workflow_dispatch`.
11. `dependabot.yml`, `.gitleaks.toml`, `secret_scanning.yml`, `CONTRIBUTING.md`, README
    "Checks" and "Releases" sections updated to the new commands; configure branch
    protection on GitHub (manual step, recorded in `CONTRIBUTING.md`).

## Acceptance criteria

- [ ] AC1 Every `ci.yml` job listed in §2 exists with the exact name, and a PR against `master` shows all of them green (jobs whose prerequisites are missing show "skipped").
- [ ] AC2 `ci.yml` triggers on pushes to `master` (not `main`), PRs and `workflow_dispatch`; a push to `master` runs it.
- [ ] AC3 `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, the `docs` command and `cargo test --workspace --all-features --locked` pass locally on the template with the new lints.
- [ ] AC4 The `msrv` job installs the toolchain read from `rust-version` (1.95) and `cargo check` passes; making one crate declare a different `rust-version` makes the job fail with "workspace crates disagree".
- [ ] AC5 `python3 scripts/check-unsafe.py` exits 0 on the tree, and exits 1 when a scratch file `crates/courier-ftp-core/src/x.rs` contains `#![allow(unsafe_code)]` or a crate drops `[lints] workspace = true`.
- [ ] AC6 `python3 scripts/check-layering.py` exits 0; adding `ratatui` to `courier-ftp-core` makes it exit 1 with the dependency path in the message.
- [ ] AC7 `scripts/canary-scan.sh --self-test` passes (clean tree accepted, all nine dirty cases detected).
- [ ] AC8 `python3 scripts/bench-gate.py self-test`, `python3 scripts/update-packaging.py --self-test` pass; `bench-gate.py gate` exits 0 with the empty gates file.
- [ ] AC9 `cargo deny --all-features check advisories bans licenses sources` and `cargo vet --locked` pass.
- [ ] AC10 `fuzz.yml` and `bench.yml` complete successfully on a manual `workflow_dispatch` (fuzz: the matrix is empty and the job is skipped until T91; bench: no gates).
- [ ] AC11 A `workflow_dispatch` dry run of `cd.yml` produces `dist-linux-x86_64`, `dist-linux-aarch64`, `dist-macos-universal`, `dist-windows-x86_64` and `release-dry-run` (with `SHA256SUMS` and `notes.md`); the static check and the x86_64 reproducibility `cmp` pass; nothing is published.
- [ ] AC12 Pushing a tag whose version differs from `workspace.package.version` fails `meta` with the mismatch error.
- [ ] AC13 `CONTRIBUTING.md` documents every job with its local command, the canary prefixes, the `unsafe` rule, fuzzing, e2e and the required-checks list; README "Checks" matches the CI commands.
- [ ] AC14 Branch protection on `master` requires the checks listed in §2 (screenshot or `gh api repos/:owner/:repo/branches/master/protection` output recorded in the PR).

## Tests

### Unit tests
- `scripts/canary-scan.sh --self-test` — the nine dirty cases and the clean case (AC7).
- `scripts/bench-gate.py self-test` — 5 % passes, 20 % flagged, CI vs local gates, empty gates file (AC8).
- `scripts/update-packaging.py --self-test` — version and checksum rewriting of all four channel files (AC8).
- Manual negative checks for `check-unsafe.py` and `check-layering.py` recorded in the PR description (AC5, AC6); T76's `workspace_metadata.rs` / `forbid_unsafe.rs` later make them automatic.

### Property / fuzz tests
Not applicable in this task (the fuzz harness is set up; targets come with T91/T13).

### Snapshot tests
Not applicable.

### Integration tests
- The workflows themselves: AC1, AC2, AC4, AC9, AC10 are verified by the CI runs of the PR that adds them (links in the PR description).

### End-to-end tests
- `cd.yml` dry run (AC11) and a mismatching test tag pushed to a fork (AC12).

## Out of scope

- The jobs' content that belongs to later tasks: the e2e harness and fixtures (T76),
  hardening/canary fixtures and fuzz targets (T91), server compose/Dockerfiles (T86),
  `courier-ftp generate` (T77), benches (T13, T30, T41b, T53).
- crates.io publishing automation (manual, T77).
- A Nix flake and the `nix` job.

## Open questions

- **i686 Linux builds**: the template builds `i686-unknown-linux-gnu`; sverb parity drops it. Keep dropped? (Assumed: dropped.)
- **Nix flake**: sverb ships `flake.nix` and a `nix` CI job; courier-ftp has no flake planned. Add one for parity?
- **Package channel names**: the Homebrew tap `<owner>/homebrew-courier-ftp` and Scoop bucket `<owner>/scoop-courier-ftp` repositories must be created by the owner before the first release.
- Inconsistency (not owned here): the project rule in `tasks/README.md` lists the server crate among crates that never depend on `clap`, but T86's admin CLI (`serve`, `admin …`) needs an argument parser and sverb-server uses `clap`. The layering rules above allow `clap` in `courier-ftp-server`; the README rule should be updated, or T86 must parse arguments by hand.
