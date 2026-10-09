# rust-tui-template

[![CI](https://github.com/qviperh/rust-tui-template/workflows/CI/badge.svg)](https://github.com/qviperh/rust-tui-template/actions)

A starting point for terminal user interfaces in Rust, built on
[ratatui](https://ratatui.rs) with an async [tokio](https://tokio.rs) event
loop, layered configuration, file logging and cross-platform release builds.

## Layout

The workspace deliberately splits the UI from everything else:

```
Cargo.toml              workspace manifest — all dependency versions live here
.config/config.json     default keybindings and styles, baked into the binary
.envrc                  direnv: keep config/data/logs inside the repo
crates/
  app/                  the binary: terminal, rendering, input, config, logging
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
  app-core/             domain logic, no terminal dependencies
    src/lib.rs
```

`app-core` must never depend on `ratatui`, `crossterm` or `clap`. Keeping the
domain there means it can be unit tested without a TTY, and it stays reusable
if you later add a second front end (a CLI, a daemon, a web UI).

## Using the template

1. Rename the crates. `app` and `app-core` appear in:
   - `crates/app/` and `crates/app-core/` (directory names)
   - the `name` field of both `crates/*/Cargo.toml`
   - `app-core = { path = ... }` in the root `Cargo.toml`
   - `use app_core::Core;` in `crates/app/src/app.rs`
   - `BINARY_NAME` in `.github/workflows/cd.yml`
2. Rename the environment variables in `.envrc`. The prefix is the crate name
   upper-cased — `config::PROJECT_NAME` derives it from `CARGO_CRATE_NAME`, so
   renaming the crate to `foo` means `FOO_CONFIG`, `FOO_DATA`, `FOO_LOG_LEVEL`.
3. Set `APP_QUALIFIER` and `APP_ORGANIZATION` in `crates/app/src/config.rs`.
   They decide where per-user config and data land on each platform.
4. Update `authors`, `repository` and `license` in the root `Cargo.toml`, and
   the copyright line in `LICENSE`. `repository` is read at compile time by
   `errors.rs` for the panic message, so it cannot be removed.
5. Replace `Core` and `Error` in `crates/app-core/src/lib.rs` with your model.
6. Rewrite `crates/app/src/components/home.rs`, and add modes to
   `app::Mode` plus matching sections in `.config/config.json`.

## Running

```sh
cargo run -p app
```

`q`, `Ctrl-c` and `Ctrl-d` quit; `Ctrl-z` suspends. Rebind in
`.config/config.json`.

```sh
cargo run -p app -- --tick-rate 4 --frame-rate 60
cargo run -p app -- --version    # prints git info and the resolved directories
```

## Configuration

Defaults are compiled in from `.config/config.json`. At startup the app also
looks in the per-user config directory (printed by `--version`) for
`config.json5`, `config.json`, `config.yaml`, `config.toml` or `config.ini`,
and layers whatever it finds on top. Set `APP_CONFIG` to override that
directory outright.

Keybindings are keyed by mode, then by key sequence: `"<Ctrl-a>"` for a single
chord, `"<g><g>"` for a sequence. Every value must name an `Action` variant.

## Logging

Logs go to `<data dir>/app.log`. Set `APP_LOG_LEVEL` (or `RUST_LOG`) to change
the filter, and `APP_DATA` to change the directory.

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
