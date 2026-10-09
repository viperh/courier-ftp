# T77 — Documentation and release

**Phase:** G App-level · **Depends on:** most others · **Crate:** repo-wide

## Goal

User-facing docs and a release pipeline good enough for a 1.0.

## Scope

1. **README** rewrite: what courier-ftp is, screenshot (asciinema/VHS gif via `charmbracelet/vhs` tape committed in `docs/`), install (cargo, releases, package managers later), quick start, feature list (link FEATURES.md with ✔/✘ status per item), security model summary (vault, keyring, host keys), FileZilla migration (site import).
2. `docs/keybindings.md` generated from the default keymap (T51) — a small `xtask` or test that fails if the doc is out of date.
3. `docs/configuration.md`: every setting (generated from T05 doc comments if feasible), config file locations per OS, env vars.
4. `docs/security.md`: vault format (T30), threat model, what is and isn't encrypted, reporting vulnerabilities (`SECURITY.md`).
5. Man page via `clap_mangen` (`courier-ftp.1`) included in release archives.
6. `CHANGELOG.md` (Keep a Changelog format) maintained per release.
7. **Release workflow** (existing `cd.yml`): verify it still builds all targets after the new deps (russh, rustls, keyring — keyring on Linux needs D-Bus: use the `sync-secret-service` + `crypto-rust` features to avoid OpenSSL/libdbus build deps, or vendored dbus; verify for each target incl. i686 and arm64 cross builds).
8. Packaging follow-ups (separate later tasks): crates.io publish order (core → proto crates → binary), Homebrew tap, AUR, Scoop/winget.

## Acceptance criteria

- [ ] Docs exist and are linked from README.
- [ ] Generated docs checked in CI.
- [ ] A tagged release produces binaries for all targets in `cd.yml`.

## Tests

- CI doc-freshness checks.
