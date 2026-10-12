# courier-ftp

[![CI](https://github.com/viperh/courier-ftp/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/viperh/courier-ftp/actions/workflows/ci.yml)

A terminal FTP, FTPS and SFTP client: a keyboard-driven replacement for the
FileZilla client, built in Rust on [ratatui](https://ratatui.rs) and
[tokio](https://tokio.rs).

> **Status: early development.** The foundation is being built (milestone M1 in
> [`tasks/`](tasks/README.md)): the domain model, settings, event bus, filters,
> the `Backend` trait, the local filesystem backend and the main screen with a
> working local file browser exist. There is no usable client yet: no connections,
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
`F10` quits and `Ctrl-z` suspends. All keys are in
[`docs/keybindings.md`](docs/keybindings.md).

Each connection can have its own tab: `Ctrl-t` opens one, `Ctrl-w` closes it,
`Alt-1`…`Alt-9` or `Ctrl-PgUp`/`Ctrl-PgDn` switch, `Ctrl-x R` renames and
`Ctrl-x T` duplicates. Connecting while the tab is connected asks whether to
open a new tab or replace the connection (`interface.connect_in_tab`). The queue
is shared by all tabs. With `interface.restore_tabs` the tabs (their sites or
servers and directories, never passwords) are kept in the vault and reopened
after the next unlock.

### Command line

```sh
courier-ftp sftp://alice@example.com:2222/var/www   # connect at start (also ftp://, ftps://, ftpes://)
courier-ftp ftp://host-a sftp://bob@host-b          # one tab per URL
courier-ftp --site Work/Production/web01            # a Site Manager entry by its path
courier-ftp ~/projects/site                         # start the local pane here
courier-ftp -l ~/projects/site sftp://alice@host    # local directory and a connection
```

| Option | Effect |
|---|---|
| `URL_OR_PATH…` | Server URLs to connect to (one tab each), or one local directory to start in |
| `-s, --site <PATH>` | Connect to a saved site (`Work/Production/web01`; repeatable). An unknown path lists close matches |
| `-l, --local <DIR>` | Local start directory, also used for the URL and site connections |
| `--logontype <ask\|interactive>` | Log in to the URLs given by asking for the password / for every server prompt |
| `--config-dir <DIR>`, `--data-dir <DIR>` | Override the config and data directories (win over the variables below) |
| `--no-vault` | Run without the vault: quickconnect only, nothing saved |
| `--no-keyring` | Don't unlock the vault with the system keyring this run; ask for the master password |
| `--debug`, `--debug-level <0-4>`, `--log-file <FILE>` | Logging for this run (see [Logging](#logging)) |
| `--no-update-check` | No release check this run |
| `-t, --tick-rate`, `-f, --frame-rate` | Event loop rates |
| `-V, --version` | Version, directories and the vault's path |
| `generate man\|completions <shell>` | Man page and shell completions (bash, zsh, fish, powershell), for packaging |

Connections given on the command line start once the vault is unlocked (URLs
also when it's skipped; sites need it). The first goes into the current tab,
the others into new tabs, and the saved tabs aren't restored on such a start.
A password in a URL (`sftp://user:pass@host`) works but is visible in your
shell history and the process list; courier-ftp warns about it. Leave it out to
be asked when connecting.

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
| `COURIER_FTP_NO_UPDATE_CHECK` | Set to `1` to turn the update check off (same as `--no-update-check`; for packagers) |

The repo's `.envrc` ([direnv](https://direnv.net)) keeps config, data and logs
inside the checkout while developing.

## Logging

- **Application log** (for developers): `<data dir>/courier-ftp.<YYYY-MM-DD>.log`, one
  file per day, the last 7 kept, readable by you only. Level from `COURIER_FTP_LOG_LEVEL`
  (default `info`); `--debug` switches to `debug`, which may contain hostnames, user names
  and paths. At `info` and above it never does.
- **Session log** (the message log as a file, for diagnosing connections): turn on
  `logging.log_to_file`; written to `logging.log_file` (default `<data dir>/session.log`),
  rotated at `logging.log_file_max_mib`, `logging.log_file_keep` old files kept. It names
  servers, users and paths; passwords show as `PASS ****`.
- `--debug-level 0-4` sets the message log's detail for one run; level 3 and up add raw
  directory listings and TLS/SSH negotiation details (`logging.show_raw_listing` adds the
  listings alone). `--log-file <FILE>` writes the session log to FILE for one run.
  `<Ctrl-x><s>` shows the raw listing of the current directory; in the
  message log `Y` copies and `S` saves the whole log.

Passwords and other secrets are never logged, at any level, in either log.

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

The client looks for a newer release at startup, at most once a week
(`interface.check_updates`, on by default; `interface.check_prereleases` counts
betas and release candidates). It sends one anonymous request to the GitHub
releases API, in the background, and shows "Update available" in the status bar,
the message log and Help (`F1`). It never downloads or installs anything. Turn it
off with the setting, `--no-update-check` or `COURIER_FTP_NO_UPDATE_CHECK=1`.

## License

MIT. See [LICENSE](LICENSE).
