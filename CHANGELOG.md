# Changelog

All notable changes to courier-ftp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org). `cd.yml` takes the release notes from
the section matching the tag.

## [Unreleased]

### Added
- CI/CD with the same job set as sverb (T00): fmt, clippy (with and without the
  `sync` feature), docs, tests (Linux, Windows, macOS), cargo-deny, MSRV, crate
  layering, `unsafe` confinement, canary scan, reproducible packaging; nightly
  fuzz and benchmark workflows; a reproducible, multi-platform release pipeline.
- Workspace layout for the protocol, crypto, store, sync and server crates (T01).
- `courier-ftp generate man|completions <shell>`.
- `COURIER_FTP_HOME` redirects the config and data directories.
- Core domain model (T02): `RemotePath`, `LocalPath`, entries, permissions,
  timestamps with precision, protocols, server URLs, credentials, charsets and
  the crate-wide `Error`.
- Typed settings with FileZilla's defaults (T05), loaded leniently and saved as
  a minimal diff; the defaults are listed in `config/default.json`.
- Event and log bus (T04): log levels, command masking, coalesced transfer
  progress, prompts.
- Filename filter engine with FileZilla's built-in filters (T47).
- `Backend` trait, `SessionHandle` with keep-alive and reconnect-once, and an
  in-memory mock backend for tests (T03).
- Local filesystem backend with Windows drive/UNC path mapping, a file name
  sanitizer and a backend conformance suite (T06).
- Main screen (T50): Classic, Explorer and Widescreen layouts, a single-pane
  mode for small terminals, focus handling, a modal stack with a help overlay
  generated from the keymap, `NO_COLOR` support; the local pane lists the home
  directory in the background.
- Directory listing cache shared across tabs, patched by our own changes, with
  LRU eviction (T46).
- Full default keymap mixing Midnight Commander F-keys with vim motions (T51):
  context modes, sequences with a 1 s timeout shown in the status bar, bad
  bindings and conflicts reported instead of aborting, `docs/keybindings.md`
  generated from the keymap.
- Dialog and form framework (T52): text, password, number and path fields,
  checkboxes, dropdowns, radio groups, lists, tabbed forms, standard dialogs
  and a progress dialog; bracketed paste; core password and
  keyboard-interactive prompts now open real dialogs.
- Status bar (T57): security, transfer type, speed limit, filters, sync and
  compare, vault and queue indicators, pending keys and transient messages,
  key hints, ASCII fallback; server info dialog (`Ctrl-x i`).
- `courier-ftp-e2e` test harness, first stage (T76): Docker opt-in and CI
  enforcement, polling helpers, failure diagnostics, temporary homes, workspace
  layering and `unsafe` policy tests; CI `e2e` job.
- Message log pane (T55): coloured prefixes, optional timestamps, a capped ring
  buffer, follow/pause with a new-lines counter, search with highlighting,
  line and range copy (OSC 52), wrap, errors-only and per-tab views.
- File list pane (T53): columns that drop on narrow terminals, natural sort,
  directories first, navigation with cursor memory and history, selection
  (toggle, range, all, invert, by pattern), quick filter, filters, hidden
  files, address bar with completion, column menu, inline errors. Renders
  100 000 entries in under 5 ms.
- Network layer (T07): IPv6 preference with Happy Eyeballs fallback, timeouts
  and cancellation on DNS, connect and proxy handshake, TCP
  keep-alive/NODELAY, and HTTP CONNECT, SOCKS4/4a and SOCKS5 proxies with
  authentication.
- Trust prompts (T69) for SSH host keys (unknown and changed, SHA-256/MD5
  fingerprints) and TLS certificates (summary, chain details,
  changed-certificate warning), plus a prompt queue with a status badge and
  <Ctrl-x><p> to open the next prompt.
