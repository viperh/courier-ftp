# T74 — Update check and splash screen

**Phase:** G App-level · **Depends on:** T07, T50 · **Crate:** `courier-ftp` · **FEATURES.md:** §10 (automatic update check, optional splash screen)

## Goal

Tell users when a new release exists, and optionally show a splash on start.

## Scope

1. **Update check** (`interface.check_updates`, default on; interval 7 days, last-check timestamp stored in data dir):
   - GET `https://api.github.com/repos/viperh/courier-ftp/releases/latest` (via the net layer with TLS — needs a minimal HTTP client; use `reqwest` with rustls **or** hand-rolled HTTP/1.1 over `tokio-rustls`; decide by binary size impact).
   - Compare `tag_name` (semver, strip leading `v`) with `CARGO_PKG_VERSION`; ignore prereleases unless setting `check_prereleases`.
   - Non-blocking, background; failure silent (debug log).
   - Notification: status bar message + entry in Help overlay "Update available: v1.3.0 — <release URL>". No auto-download/install (users install via package managers / releases).
   - Respect `--no-update-check` flag and env `COURIER_FTP_NO_UPDATE_CHECK` (for packagers).
2. **Splash screen** (`interface.show_splash`, default **off**): ASCII-art logo + version + "loading…", shown until config/vault init completes or 1 s, any key skips.

## Acceptance criteria

- [x] Update check respects interval and opt-out.
- [x] Version comparison unit-tested (`v1.2.3` vs `1.10.0`, prereleases).
- [x] No network access when disabled (test with a mock that panics if called).

## Tests

- Unit tests for version comparison and scheduling; mock HTTP.

## Status

Done. `reqwest` (rustls/ring, OS trust store) was chosen over hand-rolled HTTP: the
default build already links it through `courier-ftp-sync`, so it adds nothing there;
the local-only build gains hyper/reqwest. The request goes direct (no configured
or environment proxy). The splash stays at least 1 s and until the vault has
opened, at most 5 s; config loads before the terminal is set up, so there is
nothing else to wait for.
