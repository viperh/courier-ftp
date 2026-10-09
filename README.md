# courier-ftp

[![CI](https://github.com/viperh/courier-ftp/workflows/CI/badge.svg)](https://github.com/viperh/courier-ftp/actions)

A terminal FTP, FTPS and SFTP client: a TUI replacement for the FileZilla
client, built on [ratatui](https://ratatui.rs) and [tokio](https://tokio.rs).
Work in progress; see [`FEATURES.md`](FEATURES.md) and [`tasks/`](tasks/).

## Layout

The workspace deliberately splits the UI from everything else:

```
Cargo.toml              workspace manifest — all dependency versions live here
.config/config.json     default keybindings and styles, baked into the binary
.envrc                  direnv: keep config/data/logs inside the repo
crates/
  courier-ftp/          the binary: terminal, rendering, input, config, logging
    build.rs            vergen — stamps git/build info into the version string
    src/
      main.rs           entry point
      app.rs            event loop, mode handling, component dispatch
      action.rs         the Action enum every component speaks
      components.rs     the Component trait
      components/
        home.rs         default screen — copy this shape for new components
      cli.rs            clap argument parsing
      config.rs         layered config, keybinding and style parsing
      errors.rs         panic hooks, color-eyre, human-panic
      logging.rs        tracing subscriber writing to a log file
      tui.rs            terminal setup/teardown and the crossterm event stream
  courier-ftp-core/     domain logic: model, Backend trait, settings, vault, sites,
                        queue and transfer engine, filters, compare, search, paths
  courier-ftp-proto-ftp/  own FTP/FTPS client on tokio + rustls (Backend impl)
  courier-ftp-proto-sftp/ SFTP client on russh + russh-sftp (Backend impl)
  courier-ftp-crypto/   key hierarchy, item envelopes, HPKE, OPAQUE; pure, no I/O
  courier-ftp-store/    local SQLite store of individually encrypted items
  courier-ftp-proto/    sync wire types shared by the sync client and server
  courier-ftp-sync/     sync client: account, devices, pull/push, live updates
                        (optional: the binary's `sync` feature, on by default)
  courier-ftp-server/   self-hosted, end-to-end encrypted sync server (binary)
```

`courier-ftp-core`, the protocol crates, crypto, store, proto, sync and server
never depend on `ratatui`, `crossterm` or `clap`. Keeping the domain there means
it can be unit tested without a TTY. The server never depends on the client
crates, so its heavy dependencies stay out of the client build.

## Running

```sh
cargo run -p courier-ftp
```

`q`, `Ctrl-c` and `Ctrl-d` quit; `Ctrl-z` suspends. Rebind in
`.config/config.json`.

```sh
cargo run -p courier-ftp -- --tick-rate 4 --frame-rate 60
cargo run -p courier-ftp -- --version    # prints git info and the resolved directories
```

## Configuration

Defaults are compiled in from `.config/config.json`. At startup the app also
looks in the per-user config directory (printed by `--version`) for
`config.json5`, `config.json`, `config.yaml`, `config.toml` or `config.ini`,
and layers whatever it finds on top. Set `COURIER_FTP_CONFIG` to override that
directory outright.

`COURIER_FTP_HOME=P` moves everything under one root: the config directory
becomes `P/config` and the data directory `P/data` (tests and CI use this).
`COURIER_FTP_CONFIG` and `COURIER_FTP_DATA` still win over it.

Keybindings are keyed by mode, then by key sequence: `"<Ctrl-a>"` for a single
chord, `"<g><g>"` for a sequence. Every value must name an `Action` variant.

## Logging

Logs go to `<data dir>/courier-ftp.log`. Set `COURIER_FTP_LOG_LEVEL` (or `RUST_LOG`) to change
the filter, and `COURIER_FTP_DATA` to change the directory.

## Checks

The same four gates CI runs:

```sh
cargo test --locked --all-features --workspace
cargo fmt --all --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace
```

`Cargo.lock` is committed on purpose — CI builds with `--locked`.

## Releases

Pushing a tag matching `v1.2.3` or `1.2.3` builds the binary for macOS
(x86_64/arm64), Linux (x86_64/arm64/i686) and Windows, then attaches tarballs
and SHA-256 sums to the GitHub release.

## License

MIT — see [LICENSE](LICENSE).
