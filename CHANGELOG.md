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
- FTP directory listing parsers (T13): MLSD/MLST, Unix ls -l (shared with
  SFTP), DOS/IIS, EPLF, VMS, MVS/z/OS, IBM i and NetWare, with year inference,
  server time-zone offset and per-line charset fallback; listing fuzz target.
- Crypto crate (T80, courier-ftp-crypto): XChaCha20-Poly1305 item envelopes,
  Argon2id KDF with CBOR parameters, key wrapping, OPAQUE, account and
  recovery keys (BIP39), HPKE vault-key grants, Ed25519 signing and safety
  numbers, adapted from sverb.
- SSH connection and authentication via russh (T20): password,
  ask-for-password, keyboard-interactive/2FA, OpenSSH/PEM/PKCS#8/PuTTY PPK
  v2/v3 key files with passphrase prompts, SSH agent and Pageant, through the
  generic proxy, with a pluggable host key verifier.
- SFTP host key verification (T21): unknown keys ask (Trust once / Always
  trust / Cancel), changed keys raise a warning with old and new fingerprints,
  trusted keys are remembered, and OpenSSH known_hosts (including hashed
  entries and @revoked) is honoured read-only.
- SFTP backend (T22): every file operation over russh-sftp, owner/group names
  from longname, symlink targets resolved (links to directories can be
  entered), pipelined resumable transfers (64 requests of up to 255 KiB in
  flight, 90–120 % of OpenSSH sftp throughput), SftpBackendFactory and
  scripts/bench-sftp.sh.
- Item model (T81): UUIDv7 ids, nine item kinds with typed views, HLC-stamped
  CBOR bodies, field-level last-writer-wins merge with tombstones and
  clock-skew warnings, read-time schema migrations.
- Local store (T82, courier-ftp-store): SQLite with WAL, one writer plus a
  reader pool, migrations that refuse newer schemas, an outbox entry on every
  write, device-local data and blobs, key pins, local approvals, in-memory
  search labels, 0700/0600 permissions.
- Quickconnect bar (T58): connect to SFTP servers from host, user, password
  and port fields or a pasted URL (sftp://user@host:port/path); browse the
  remote pane, disconnect (Ctrl-x d), reconnect (Ctrl-x r, password asked
  again), confirm before replacing a connection; host key and password prompts
  open automatically; new setting interface.show_quickconnect.
- Encrypted local vault (T30): master-password unlock with Argon2id and
  persisted brute-force backoff, optional per-device OS keyring unlock with
  keyring-based password recovery, auto-lock (idle and suspend), password
  change, store-passwords setting, vault-backed trusted host keys, and the
  .cftp-backup format.
- Vault unlock UI (T60): first-run master password setup with strength meter
  and optional keyring unlock, unlock view with backoff countdown, silent
  keyring unlock with password fallback, "Forgot password?" (keyring reset, or
  a new empty vault with the old database moved aside), lock overlay with
  <Ctrl-x><v> and auto-lock, "Continue without vault", and a database-busy
  retry screen.
