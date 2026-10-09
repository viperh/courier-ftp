# courier-ftp

[![CI](https://github.com/viperh/courier-ftp/workflows/CI/badge.svg)](https://github.com/viperh/courier-ftp/actions)

A terminal FTP, FTPS and SFTP client: a TUI replacement for the FileZilla
client, built on [ratatui](https://ratatui.rs) and [tokio](https://tokio.rs).
Work in progress; see [`FEATURES.md`](FEATURES.md) and [`tasks/`](tasks/).

## Layout

The workspace deliberately splits the UI from everything else:

```
Cargo.toml              workspace manifest — all dependency versions live here
.envrc                  direnv: keep config/data/logs inside the repo
crates/
  courier-ftp/            A terminal FTP, FTPS and SFTP client (the binary: terminal,
                          rendering, input, config, logging, directory resolution)
    build.rs              vergen — stamps git/build info into the version string
    config/config.json    default keybindings and styles, baked into the binary
    src/
      main.rs             entry point
      app.rs              event loop, mode handling, component dispatch
      action.rs           the Action enum every component speaks
      components.rs       the Component trait
      components/
        home.rs           default screen — copy this shape for new components
      cli.rs              clap argument parsing
      config.rs           layered config, keybinding and style parsing
      errors.rs           panic hooks, color-eyre, human-panic
      logging.rs          tracing subscriber writing to a log file
      paths.rs            AppPaths: config, data and cache directories
      tui.rs              terminal setup/teardown and the crossterm event stream
  courier-ftp-core/       Domain logic for courier-ftp, independent of any user interface
  courier-ftp-proto-ftp/  FTP and FTPS client for courier-ftp
  courier-ftp-proto-sftp/ SFTP client for courier-ftp, built on russh
  courier-ftp-crypto/     Cryptography for the courier-ftp vault and sync (no I/O)
  courier-ftp-store/      SQLite store for courier-ftp's encrypted items
  courier-ftp-proto/      Wire types of the courier-ftp sync protocol
  courier-ftp-sync/       Sync client for courier-ftp (optional: the binary's `sync`
                          feature, on by default)
  courier-ftp-server/     Self-hosted sync server for courier-ftp (binary)
```

Dependency direction (`a ← b`: `b` depends on `a`):

```
crypto ← store ← core
crypto ← proto ← core
core ← {proto-ftp, proto-sftp} ← sync ← courier-ftp
server ← {proto, crypto}
```

That is, core → store → crypto, and the store never depends on core. The server
never depends on a client crate, so its heavy dependencies stay out of the client
build. Only the `courier-ftp` binary may use `ratatui`, `crossterm` or `clap` (the
server may use `clap` for its admin CLI): the core, the protocol crates, crypto,
store, proto and sync stay UI-free and testable without a TTY.
`scripts/check-layering.py` (CI job `layering`) enforces all of this.

## Running

```sh
cargo run -p courier-ftp
```

`q`, `Ctrl-c` and `Ctrl-d` quit; `Ctrl-z` suspends. Rebind in
`crates/courier-ftp/config/config.json`.

```sh
cargo run -p courier-ftp -- --tick-rate 4 --frame-rate 60
cargo run -p courier-ftp -- --version    # prints git info and the resolved directories
```

## Configuration

Defaults are compiled in from `crates/courier-ftp/config/config.json`. At startup the
app also looks in the config directory (printed by `--version`) for `config.json5`,
`config.json`, `config.yaml`, `config.toml` or `config.ini`, and layers whatever it
finds on top.

courier-ftp uses three directories: **config** (configuration files), **data** (vault,
logs, crash reports) and **cache** (disposable files such as edit copies). These
environment variables move them:

| Variable | Effect |
|---|---|
| `COURIER_FTP_HOME=P` | Everything under one root: `P/config`, `P/data`, `P/cache` (tests and CI use this). |
| `COURIER_FTP_CONFIG=D` | The config directory is `D` (wins over `COURIER_FTP_HOME`). |
| `COURIER_FTP_DATA=D` | The data directory is `D` (wins over `COURIER_FTP_HOME`). |

Precedence, per directory (first match wins): command-line flag (`--config-dir` /
`--data-dir`, planned) > `COURIER_FTP_CONFIG` / `COURIER_FTP_DATA` >
`COURIER_FTP_HOME` > the platform's per-user directories (XDG on Linux,
`~/Library/Application Support` and `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on
Windows). The cache directory has no variable of its own. Empty values count as unset;
relative paths are made absolute against the current directory. If none applies (for
example no `HOME`), courier-ftp exits with an error asking you to set
`COURIER_FTP_HOME` instead of writing into the current directory. Missing directories
are created (mode `0700` on Unix) when the TUI starts; `--version` creates nothing.

Keybindings are keyed by mode, then by key sequence: `"<Ctrl-a>"` for a single
chord, `"<g><g>"` for a sequence. Every value must name an `Action` variant.

## Logging

Logs go to `<data dir>/courier-ftp.log`. Set `COURIER_FTP_LOG_LEVEL` (or `RUST_LOG`) to change
the filter, and `COURIER_FTP_DATA` to change the directory.

## Checks

The main gates CI runs on every pull request (`.github/workflows/ci.yml`; the full job
list with local commands is in [CONTRIBUTING.md](CONTRIBUTING.md#checks)):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy -p courier-ftp --all-targets --no-default-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --locked
cargo test --workspace --all-features --locked
cargo deny --all-features --locked check advisories bans licenses sources
cargo vet --locked
python3 scripts/check-layering.py
python3 scripts/check-unsafe.py
scripts/canary-scan.sh --self-test
```

`Cargo.lock` is committed on purpose — CI builds with `--locked`. The minimum
supported Rust version is `rust-version` in `Cargo.toml` (1.95).

## Releases

Pushing a tag `vX.Y.Z` that matches `workspace.package.version` runs
`.github/workflows/cd.yml`: reproducible, static (musl) archives for Linux x86_64 and
aarch64, a universal macOS archive and a Windows zip, plus `SHA256SUMS`, one `.sha256`
per archive and a CycloneDX SBOM, attached to the GitHub release. Running the workflow
by hand is a dry run that publishes nothing. See [CONTRIBUTING.md](CONTRIBUTING.md#releases).

## License

MIT — see [LICENSE](LICENSE).
