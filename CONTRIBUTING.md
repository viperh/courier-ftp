# Contributing to courier-ftp

- Read [`FEATURES.md`](FEATURES.md) for what courier-ftp is meant to do and
  [`tasks/README.md`](tasks/README.md) for the plan, the agreed decisions (D1–D15) and
  the build order.
- Run the checks below before sending a change. A task is done when its acceptance
  criteria are ticked and every required CI check passes.

## Checks

Every job of `.github/workflows/ci.yml` and the command that reproduces it locally.
No `act` needed: each job is a few plain commands. Jobs marked *(gated)* are skipped by
the `detect` job until the files they need exist; a skipped job counts as passed.

| CI job | Local command |
|---|---|
| `detect` | — (sets the `e2e`, `server_crate`, `server`, `fuzz_targets`, `vet`, `generate` flags with `test -f`) |
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and `cargo clippy -p courier-ftp --all-targets --no-default-features --locked -- -D warnings` |
| `docs` | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --locked` |
| `test` | `COURIER_FTP_KEYRING=off cargo test --workspace --all-features --locked` |
| `test-os (windows-latest)`, `test-os (macos-latest)` | `cargo test --workspace --all-features --locked --exclude courier-ftp-server --exclude courier-ftp-e2e` (on that OS) |
| `test-local-only` | `cargo test --workspace --no-default-features --locked --exclude courier-ftp-sync --exclude courier-ftp-server --exclude courier-ftp-e2e` |
| `e2e` *(gated: T76)* | `COURIER_E2E=1 cargo test -p courier-ftp-e2e --locked -- --ignored` (Linux Docker host, see "E2E tests") |
| `server-db` *(gated: server crate)* | `DATABASE_URL=postgres://courier:courier@localhost:5432/courier cargo test -p courier-ftp-server --locked` (a local `postgres:16`) |
| `server-docker` *(gated: T86)* | `docker compose -f deploy/docker-compose.yml up -d --build`, then `curl -fsS http://localhost:8080/healthz` |
| `bench-build` | `cargo bench --workspace --no-run --locked` and `python3 scripts/bench-gate.py self-test` |
| `deny` | `cargo deny --all-features --locked check advisories bans licenses sources` |
| `vet` | `cargo vet --locked` and `python3 scripts/check-vet-crypto.py` |
| `msrv` | `cargo +1.95 check --workspace --all-features --locked` (the version is `rust-version` in `Cargo.toml`) |
| `layering` | `python3 scripts/check-layering.py` (plus, with T76, `cargo test -p courier-ftp-e2e --test workspace_metadata --test forbid_unsafe --locked`) |
| `unsafe-check` | `python3 scripts/check-unsafe.py` |
| `canary` | `scripts/canary-scan.sh --self-test`; `COURIER_FTP_LOG_LEVEL=trace cargo test --workspace --all-features --locked --no-fail-fast`; `scripts/canary-scan.sh` |
| `fuzz` *(gated: a fuzz target)* | `fuzz/seed-corpus.sh` and `cargo +nightly fuzz run <target> fuzz/corpus/<target> -- -max_total_time=30` |
| `packaging` | `python3 scripts/update-packaging.py --self-test`; `bash -n packaging/aur/*/PKGBUILD`; `ruby -c packaging/homebrew/courier-ftp.rb`; `jq -e . packaging/scoop/courier-ftp.json`; `cargo package --workspace --exclude courier-ftp-e2e --locked --no-verify` |

Install the extra tools once with `cargo install --locked cargo-deny cargo-vet cargo-fuzz`.
`Cargo.lock` is committed and CI builds with `--locked`. A PR that adds or bumps a
dependency keeps `cargo vet --locked` green: import an audit, certify one
(`cargo vet certify`) or add an exemption in the same PR.

Nightly workflows: `fuzz.yml` (every fuzz target for 10 minutes) and `bench.yml`
(benchmarks, spec gates from `scripts/bench-gates.toml`, regression check against the
last `master` baseline, startup gate). Both can be started by hand (`workflow_dispatch`).

## Logging

No hostnames, addresses, usernames, paths, commands or item labels at `info` and
above, and secrets never, at any level (T91). Read `docs/threat-model.md` (T91) before
adding a `tracing` call. The session log (T71, `session*.log`) is a transcript the user
asked for and may name hosts, never secrets.

## Canary secrets

Tests that handle secrets or hostnames plant **canary values**, so a leak anywhere is
found by a plain text search:

| Kind | Form | Rule |
|---|---|---|
| Passwords, passphrases, keys, tokens, TOTP seeds, recovery words | `CANARY-PW-…`, `CANARY-PASS-…`, `CANARY-KEY-…`, `CANARY-TOKEN-…`, `CANARY-TOTP-…`, `CANARY-WORDS-…` (any `CANARY-…` that is not a host) | never in a log file at any level (session log included), a crash report, an edit temp copy, a SQLite file (`*.db`, `-wal`, `-shm`, `-journal`), a backup (`*.cftp-backup`) or a server database dump |
| Hostnames | `canary-host-….example` | never at `info`, `warn` or `error` in logs, never in crash reports, edit copies, DB files, backups or dumps; `debug`/`trace` lines and the session log may contain them |

Matching is case-insensitive. `scripts/canary-scan.sh [--require-files] [DIR…]` checks
those files under the given directories (default `target/tmp` plus
`$COURIER_FTP_CANARY_DIRS`) and exits 1 on a leak; `scripts/canary-scan.sh --self-test`
checks the scanner itself. The CI job `canary` runs the whole suite with
`COURIER_FTP_LOG_LEVEL=trace`, `TMPDIR` and `COURIER_FTP_HOME` under one root, dumps the
server database, and scans everything.

To keep the scan meaningful, give planted secrets one of these prefixes, and keep test
homes you want scanned under `CARGO_TARGET_TMPDIR`. FileZilla XML exports in tests must
not use canary passwords: exports are plaintext by design (T32).

## `unsafe`

The workspace lint is `unsafe_code = "deny"` and every crate has `[lints] workspace =
true`. Only `crates/courier-ftp-core/src/hardening/` (T91) may lift it, with a `SAFETY`
comment on every block; `python3 scripts/check-unsafe.py` (CI job `unsafe-check`)
enforces this. Test modules and integration tests put
`#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top; non-test code may not
use `unwrap`/`expect`.

## Fuzzing

`fuzz/` is a cargo-fuzz workspace (nightly), excluded from the root one:

```sh
cargo +nightly fuzz list
fuzz/seed-corpus.sh            # seeds from tests/fixtures and crate fixtures
cargo +nightly fuzz run <target> fuzz/corpus/<target> -- -max_total_time=60
```

A new parser of untrusted input gets a target: add `fuzz/fuzz_targets/<name>.rs`
(`fuzz_target!(|data: &[u8]| body(data));`, where `body` is a `#[doc(hidden)] pub fn
fuzz_…` of the owning crate that a property test also runs), a `[[bin]]` in
`fuzz/Cargo.toml` and seeds in `fuzz/seed-corpus.sh`. Nothing else: the PR job and the
nightly matrix list the targets with `cargo fuzz list`. The planned targets are in T91.

## E2E tests

The Docker e2e suite lives in `crates/courier-ftp-e2e` (T76). Its container tests are
`#[ignore]`d and run only with `COURIER_E2E=1` on a Linux host with Docker:

```sh
COURIER_E2E=1 cargo test -p courier-ftp-e2e --locked -- --ignored --test-threads=4
```

On CI (`CI=true`) a missing Docker daemon is a failure, not a skip. The fixture images
come from `tests/fixtures/{sshd,ftpd,proxy}`; their keys and certificates are TEST-ONLY
(`.gitleaks.toml`, `.github/secret_scanning.yml`).

## Generated docs

Some docs are generated, and a test fails when they are stale; refresh them with
`COURIER_FTP_BLESS=1 cargo test …` (T77). The man page and shell completions come from
`courier-ftp generate` (T77).

## Releases

- Use [conventional commits](https://www.conventionalcommits.org) (`feat:`, `fix:`,
  `sec:`, `perf:`, `refactor:`, `docs:`, `ci:`); they make the changelog easy to write.
  The release flow is in `docs/release.md` (T77).
- A tag `vX.Y.Z` matching `workspace.package.version` runs `.github/workflows/cd.yml`:
  static musl Linux archives (x86_64, aarch64) for the client and the sync server, a
  universal macOS archive, a Windows zip, the server image on ghcr.io, `SHA256SUMS`, a
  CycloneDX SBOM, and the AUR / Homebrew / Scoop updates. Running `cd.yml` by hand
  (`workflow_dispatch`) is a dry run that publishes nothing.

## Branch protection

`master` is protected (Settings → Branches; admins included, force pushes blocked).
Required status checks, i.e. every `ci.yml` job:

`detect`, `fmt`, `clippy`, `docs`, `test`, `test-os (windows-latest)`,
`test-os (macos-latest)`, `test-local-only`, `e2e`, `server-db`, `server-docker`,
`bench-build`, `deny`, `vet`, `msrv`, `layering`, `unsafe-check`, `canary`, `fuzz`,
`packaging`.

Applied with:

```sh
gh api -X PUT repos/viperh/courier-ftp/branches/master/protection --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["detect", "fmt", "clippy", "docs", "test",
                 "test-os (windows-latest)", "test-os (macos-latest)", "test-local-only",
                 "e2e", "server-db", "server-docker", "bench-build", "deny", "vet",
                 "msrv", "layering", "unsafe-check", "canary", "fuzz", "packaging"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```
