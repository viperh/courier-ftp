# Contributing to courier-ftp

- [`FEATURES.md`](FEATURES.md) lists what courier-ftp is meant to do, and
  [`tasks/`](tasks/README.md) is the plan: one file per task, the agreed decisions
  (D1–D15) and the build order. Pick a task whose hard dependencies are done, and
  tick its acceptance criteria as they are met.
- Run the checks below before sending a change. CI runs all of them.

## Checks

| CI job | Run locally |
|---|---|
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and the local-only build: `cargo clippy -p courier-ftp --all-targets --no-default-features --locked -- -D warnings` |
| `docs` | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --locked` |
| `test-local-only` | `cargo test --workspace --no-default-features --locked --exclude courier-ftp-sync --exclude courier-ftp-server --exclude courier-ftp-e2e` |
| `test-os` | the same suite on Windows and macOS: `cargo test --workspace --locked --exclude courier-ftp-server --exclude courier-ftp-e2e` |
| `bench-build` | `cargo bench --workspace --no-run --locked` and `python3 scripts/bench-gate.py self-test` |
| `deny` | `cargo deny --all-features check advisories bans licenses sources` (install with `cargo install --locked cargo-deny`) |
| `msrv` | `cargo +1.96 check --workspace --all-features --locked` (the version is `rust-version` in `Cargo.toml`) |
| `layering` | `cargo test -p courier-ftp-e2e --test workspace_metadata` and `python3 scripts/check-layering.py` |
| `e2e` | `COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --include-ignored` (needs Docker; container tests skip without `COURIER_E2E=1`) |
| `unsafe-check` | `python3 scripts/check-unsafe.py` |
| `canary` | `scripts/canary-scan.sh --self-test`, then the suite with `COURIER_FTP_LOG_LEVEL=trace` and `scripts/canary-scan.sh` |
| `packaging` | `python3 scripts/update-packaging.py --self-test`, then build twice with `scripts/release-package.sh` and `cmp` the archives (see `ci.yml`) |

Jobs that are switched on by later tasks: `server-db` (T84),
`server-docker` (T86), `vet` (T91) and `fuzz` (T91). `.github/workflows/ci.yml`
lists them at the top.

Tests that need a config or data directory must not touch the real user
directories: set `COURIER_FTP_HOME` to a temporary directory (config goes to
`<home>/config`, data to `<home>/data`).

### Branch protection

Required checks on `master`: fmt, clippy, docs, test-local-only, test-os, deny,
unsafe-check, layering, canary, packaging, e2e. Add server-db and fuzz when they
are switched on.

## Crate layering

`scripts/check-layering.py` enforces the dependency direction (rules in
[`tasks/README.md`](tasks/README.md), "Project-wide rules"):

- only the `courier-ftp` binary may depend on `ratatui`, `crossterm` or `clap`;
- `courier-ftp-crypto` stays pure: no async runtime, storage or network crates;
- the protocol crates depend on `courier-ftp-core` and nothing above it;
- `courier-ftp-server` never links client crates;
- `courier-ftp-sync` is an optional dependency of the binary (feature `sync`),
  and the local-only build (`--no-default-features`) never contains it.

`deny.toml` repeats the UI and sync rules as a second line of defence.

## Logging and secrets

Secrets (passwords, key passphrases, the vault key) are wrapped in
`secrecy`/`zeroize` types and are never logged, at any level. FTP `PASS` lines
are masked (`PASS ****`). Hostnames and user names may appear at `debug` and
`trace` only.

## Canary secrets

Tests that handle secrets or hostnames plant **canary values**, so a leak anywhere
is found by a plain text search:

| Kind | Form | Rule |
|---|---|---|
| Passwords, passphrases, keys, tokens | `CANARY-PW-…`, `CANARY-PASS-…`, `CANARY-KEY-…`, `CANARY-TOKEN-…` (any `CANARY-…` that is not a host) | never in a log file at any level, a crash report, a SQLite file (`*.db`, `-wal`, `-shm`), a backup or a server database dump |
| Hostnames | `canary-host-….example` (`CANARY-HOST-…`) | never at `info`, `warn` or `error` in logs, never in crash reports, DB files, backups or dumps; `debug`/`trace` lines may contain them |

Matching is case-insensitive. `scripts/canary-scan.sh [DIR…]` checks those files
under the given directories (default `target/tmp`) and exits 1 on a leak;
`scripts/canary-scan.sh --self-test` checks the scanner itself. Keep test homes
you want scanned under `CARGO_TARGET_TMPDIR`.

## `unsafe`

The workspace lint is `unsafe_code = "deny"`. Only
`crates/courier-ftp-core/src/hardening/` (T91) may lift it, with a `SAFETY` comment
on every block; `python3 scripts/check-unsafe.py` enforces this.

## Fuzzing

`fuzz/` will be a cargo-fuzz workspace (nightly), added with the first parser of
untrusted input (T13, T91). Every target calls a public parser that a property test
in its crate also runs, so the bodies stay compiled on stable. `fuzz.yml` reads the
target list from `fuzz/Cargo.toml`, runs each for 10 minutes every night and
uploads crashes.

## Releases

- Use [conventional commits](https://www.conventionalcommits.org) (`feat:`, `fix:`,
  `sec:`, `perf:`, `refactor:`, `docs:`); they make `CHANGELOG.md` easy to write.
- Bump `workspace.package.version` and the internal crate versions in
  `Cargo.toml`, add a `## [x.y.z]` section to `CHANGELOG.md`, then push the tag
  `vx.y.z`. `cd.yml` builds static Linux (musl), universal macOS and Windows
  archives, checks they are reproducible, writes `SHA256SUMS` and an SBOM, creates
  the GitHub release and updates the AUR, Homebrew and Scoop channels.
- A manual run of `cd.yml` (Actions → CD → Run workflow) is a dry run: it builds
  everything and keeps the artifacts, but publishes nothing.
- The man page and shell completions come from `courier-ftp generate man` and
  `courier-ftp generate completions <shell>`.
