# courier-ftp

[![CI](https://github.com/viperh/courier-ftp/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/viperh/courier-ftp/actions/workflows/ci.yml)

A terminal FTP, FTPS and SFTP client: a keyboard-driven replacement for the
FileZilla client, built in Rust on [ratatui](https://ratatui.rs) and
[tokio](https://tokio.rs).

> **Status: early development.** The foundation is being built (milestone M1 in
> [`tasks/`](tasks/README.md)): the domain model, settings, event bus, filters,
> the `Backend` trait, the local filesystem backend and the main screen exist. There is no usable client yet: no connections,
> no transfers.

## What it will do

The full list is in [`FEATURES.md`](FEATURES.md). In short:

- **Protocols:** FTP, FTPS (explicit and implicit) and SFTP, with IPv6, HTTP/SOCKS
  and FTP proxies, active/passive mode, keep-alive, and automatic reconnect.
- **Two-pane browsing:** local and remote file lists with directory trees, a
  message log, a transfer queue and a status bar.
- **Keyboard first:** Midnight Commander F-keys (F5 copy, F6 move, F7 mkdir, F8
  delete, Tab switch pane) together with vim motions (`j/k/h/l`, `gg/G`, `/`), all
  rebindable.
- **Transfers:** a persistent queue, resume (including files over 4 GB), "file
  exists" rules, speed limits, parallel transfers, and large files split across
  several connections.
- **Sites in an encrypted vault:** a Site Manager whose sites and passwords live
  in a vault (Argon2id + XChaCha20-Poly1305) unlocked by a master password. OS
  keyring unlock is optional. Sites can be imported from FileZilla.
- **Power features:** bookmarks, connection tabs, directory comparison,
  synchronized browsing, remote and local search, filename filters, and editing
  remote files in your external editor.
- **Optional sync:** sites, bookmarks and trusted keys sync end-to-end encrypted
  between your devices and team vaults, through your own self-hosted
  `courier-ftp-server`. Everything works offline without an account.

## Layout

```
Cargo.toml                 workspace manifest: all dependency versions and lints live here
crates/
  courier-ftp/             the binary: terminal, rendering, input, CLI, config, logging
    config/default.json    default keybindings and styles, baked into the binary
  courier-ftp-core/        domain model, Backend trait, settings, queue, filters, vault (no UI)
  courier-ftp-proto-ftp/   FTP and FTPS client written from scratch on tokio (D1)
  courier-ftp-proto-sftp/  SFTP client on russh + russh-sftp (D2)
  courier-ftp-crypto/      key derivation, encryption, signing; pure, no I/O
  courier-ftp-store/       encrypted SQLite item store
  courier-ftp-proto/       sync wire types shared by client and server
  courier-ftp-sync/        sync client (optional, cargo feature `sync`, on by default)
  courier-ftp-server/      self-hosted, end-to-end encrypted sync server
tasks/                     the implementation plan, one file per task
scripts/                   CI helpers: layering, unsafe, canary scan, bench gates, packaging
packaging/                 AUR, Homebrew and Scoop files, updated on each release
```

Only the `courier-ftp` binary may depend on `ratatui`, `crossterm` or `clap`;
`scripts/check-layering.py` (CI job `layering`) enforces the dependency direction.
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rules.

## Running

Requires Rust 1.96 or newer.

```sh
cargo run -p courier-ftp
cargo run -p courier-ftp -- --version     # prints git info and the resolved directories
cargo run -p courier-ftp --no-default-features   # local-only build, without sync
```

`F1` lists the keys. `Tab` switches between the local and remote pane, `Ctrl-l`,
`Ctrl-j` and `Ctrl-e` toggle the log, queue and directory trees, `Ctrl-q` or
`F10` quits and `Ctrl-z` suspends. The full keymap arrives with T51.

## Configuration

Defaults are compiled in from `crates/courier-ftp/config/default.json`. At startup
the app also looks in the per-user config directory (printed by `--version`) for
`config.json5`, `config.json`, `config.yaml`, `config.toml` or `config.ini`, and
layers whatever it finds on top.

Keybindings are keyed by mode, then by key sequence: `"<Ctrl-a>"` for a single
chord, `"<g><g>"` for a sequence. Every value must name an `Action` variant.

| Variable | Effect |
|---|---|
| `COURIER_FTP_HOME` | One directory for everything: config in `<home>/config`, data in `<home>/data` |
| `COURIER_FTP_CONFIG` | Config directory (wins over `COURIER_FTP_HOME`) |
| `COURIER_FTP_DATA` | Data directory, where the log file goes (wins over `COURIER_FTP_HOME`) |
| `COURIER_FTP_LOG_LEVEL` | Log filter, e.g. `debug` (`RUST_LOG` also works) |

The repo's `.envrc` ([direnv](https://direnv.net)) keeps config, data and logs
inside the checkout while developing.

## Logging

Logs go to `<data dir>/courier-ftp.log`. Passwords and other secrets are never
logged, at any level.

## Checks

The main gates CI runs (the full list is in [`CONTRIBUTING.md`](CONTRIBUTING.md)):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --locked
python3 scripts/check-layering.py
python3 scripts/check-unsafe.py
```

`Cargo.lock` is committed on purpose: CI builds with `--locked`.

## Releases

Pushing a tag `vX.Y.Z` that matches the workspace version builds static Linux
(x86_64, aarch64; musl), universal macOS and Windows archives, each with the man
page and shell completions. The workflow checks that the builds are
reproducible, then publishes them with `SHA256SUMS` and an SBOM to the GitHub
release and updates the AUR, Homebrew and Scoop packages. A manual run of the CD
workflow is a dry run.

## License

MIT. See [LICENSE](LICENSE).
