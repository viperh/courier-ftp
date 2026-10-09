# T77 — Documentation and release

**Phase:** G App-level · **Milestone:** M9 · **Depends on:** T00, T05, T51, T70, T86, T91 · **Crate(s):** repo-wide (`README.md`, `CHANGELOG.md`, `docs/`, `packaging/`, `scripts/`, `.github/workflows/{ci,cd}.yml`); doc generators in `courier-ftp` and `courier-ftp-core` · **Decisions:** D3, D8, D12, D15 · **FEATURES.md:** §1–§10 (status), §10 (app-level)
**Reference:** sverb `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md` ("Releases and documentation"), `docs/{release,faq,keybindings,config,self-hosting,threat-model}.md`, `.github/workflows/cd.yml`, `scripts/{release-package.sh,update-packaging.py}`, `packaging/`, SPEC §20.

## Goal

courier-ftp is ready for a 1.0 release: a README that explains what it is and how to
install, start and migrate from FileZilla; user documentation for keybindings,
configuration, security and self-hosting that cannot drift from the code (generated parts
are checked in CI); a changelog that feeds the release notes; and a release pipeline that
has been run end to end, producing signed-when-possible, reproducible archives for every
target, the server image and the package-channel updates.

## Context

**Before this task:**
- T00: `ci.yml` (`docs`, `packaging` jobs), `cd.yml` (meta, assets, linux, macos,
  windows, image, release, channels), `scripts/release-package.sh`,
  `scripts/update-packaging.py`, `packaging/` channel files, `CONTRIBUTING.md`.
- T05: `Settings::json_schema()` and `docs/settings.schema.json` (staleness test,
  `COURIER_FTP_BLESS=1 cargo test -p courier-ftp-core settings_schema`).
- T51: the default keymap table that also renders the help overlay.
- T70: `courier-ftp generate man [--out-dir DIR]` and `generate completions <shell>`
  (bash, elvish, fish, powershell, zsh), with a man-page snapshot test; `--help` text.
- T86: `deploy/` (Dockerfiles, compose) and `docs/self-hosting.md`.
- T91: `docs/threat-model.md`, `SECURITY.md`.
- The README is still the template's ("A starting point for terminal user interfaces…").

**After:** releases are cut by tag only, following `docs/release.md`.

## Technical specification

### Types and APIs

**Doc generators** (tests that compare the committed file with freshly generated text;
`COURIER_FTP_BLESS=1` rewrites the file instead of failing):

```rust
// crates/courier-ftp/src/docs_gen.rs  (#[cfg(test)] module tree only, nothing shipped)
/// Markdown for docs/keybindings.md from the default keymap (T51): one table per mode
/// (Normal, file panes, dialogs, …) with columns Keys | Action | Description, keys in
/// the notation of `.config/config.json` ("<F5>", "<Ctrl-x><Ctrl-l>", "<g><g>").
fn render_keybindings_md(keymap: &KeyMap) -> String;

// crates/courier-ftp-core/tests/configuration_doc.rs
/// The generated block of docs/configuration.md from `Settings::json_schema()` (T05):
/// one `###` heading per section (`connection`, `ftp`, …), a table Key | Type | Default |
/// Description per section; keys as full dotted paths (`transfers.max_concurrent`).
fn render_settings_md(schema: &serde_json::Value) -> String;
```

The generated text replaces only the region between
`<!-- BEGIN GENERATED: <name> -->` and `<!-- END GENERATED: <name> -->`; hand-written text
outside the markers is kept. `KeyMap` stands for T51's default keymap type (use its real
name).

**Scripts**

| Script | Usage | Behaviour | Exit |
|---|---|---|---|
| `scripts/check-doc-links.py` | `[--root DIR]` \| `--self-test` | For `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/**/*.md`: every relative link (`[x](path)`, `[x](path#anchor)`) resolves to an existing file, and `#anchor` matches a heading (GitHub slug rules: lowercase, spaces → `-`, punctuation dropped). External `http(s)` links are not fetched. | 0 ok, 1 broken links (one line each: `file:line: target`), 2 usage |
| `scripts/release-notes.sh` | `<version> [CHANGELOG.md]` \| `--self-test` | Prints the body of the `## [<version>] - YYYY-MM-DD` section (up to the next `## [`); fails when the section is missing or empty | 0 ok, 1 missing/empty, 2 usage |

### Behaviour

#### 1. README (`README.md`, rewritten)

Sections, in order (exact headings):
1. `# courier-ftp` + one paragraph: "A terminal FTP, FTPS and SFTP client: a keyboard-driven
   replacement for FileZilla, with an encrypted vault for your sites and optional
   end-to-end-encrypted sync between your devices." CI badge.
2. Demo: `docs/demo.gif` (≤ 2 MiB, 120×36), rendered from the committed VHS tape
   `docs/demo.tape` (`charmbracelet/vhs`): start against a local SFTP test server, unlock,
   browse, upload with `F5`, watch the queue. The tape uses only `example.org`-style or
   local fixture data.
3. `## Features` — a table per FEATURES.md section (§1–§10) with one row per feature
   group and a status: ✔ (in 1.0), ✘ (dropped, D8: Kerberos/GSS, OS drag and drop,
   sound/sleep/shutdown actions), or "later" with the reason; link to `FEATURES.md`.
4. `## Install` — `cargo install courier-ftp --locked` (and `--no-default-features` for a
   build without sync); release archives (list of the five archive names from T00 and how
   to verify `SHA256SUMS`); AUR `courier-ftp` / `courier-ftp-bin`; Homebrew tap; Scoop
   bucket; the server image `ghcr.io/<owner>/courier-ftp-server`.
5. `## Quick start` — first run (create the master password; local-only users have no
   recovery unless keyring unlock is enabled), quickconnect, Site Manager, the core keys
   (Tab, F5–F8, `/`, `?` help), quitting.
6. `## Migrating from FileZilla` — where FileZilla keeps `sitemanager.xml` per OS, the
   import action (T32), what is imported (folders, passwords, protocols, logon types,
   charset, transfer mode), what is not.
7. `## Security` — five bullets (vault encryption, master password and optional keyring,
   end-to-end-encrypted sync, host-key/certificate trust, logging policy) and links to
   `docs/security.md`, `docs/threat-model.md`, `SECURITY.md`.
8. `## Sync` — what it does, that it is optional, link to `docs/self-hosting.md`.
9. `## Documentation` — links: keybindings, configuration, security, threat model,
   self-hosting, FAQ, release process, CONTRIBUTING.
10. `## Building and checks` — the commands from `CONTRIBUTING.md` (short form).
11. `## License` — MIT.

#### 2. `docs/keybindings.md`
Hand-written intro (notation, rebinding in `config.json`, terminal caveats from T51:
keys some terminals don't send, tmux settings) + the generated region `keybindings`.
Stale file → `docs_gen::tests::keybindings_doc_is_current` fails with
`docs/keybindings.md is stale; run COURIER_FTP_BLESS=1 cargo test -p courier-ftp docs_gen`.

#### 3. `docs/configuration.md`
Hand-written parts: config file locations per OS (table from T01/T70: Linux
`~/.config/courier-ftp/`, macOS `~/Library/Application Support/com.viperh.courier-ftp/`,
Windows `%APPDATA%\viperh\courier-ftp\config\`, plus data and cache dirs), layering of
`config.json5|json|yaml|toml|ini` (D10), the environment-variable table (`COURIER_FTP_HOME`,
`COURIER_FTP_CONFIG`, `COURIER_FTP_DATA`, `COURIER_FTP_LOG_LEVEL`, `COURIER_FTP_KEYRING`,
`COURIER_FTP_NO_UPDATE_CHECK`, `RUST_LOG`; each with meaning and default), and a pointer
to `docs/settings.schema.json`. Generated region `settings` from the schema.
`configuration_doc_is_current` and `every_settings_key_documented` guard it.

#### 4. `docs/security.md` (user-facing; the threat model stays the detailed reference)
Sections: *What is encrypted and where* (table: sites/passwords/keys/bookmarks/trusted
keys and certificates/history → vault items; transfer queue and tabs → device blobs; logs
→ plain text without secrets; session log → plain text, opt-in), *The vault* (Argon2id
`m = 256 MiB, t = 3, p = 1` by default, XChaCha20-Poly1305 per-item envelopes, T30/T80),
*Master password, keyring unlock and recovery* (exactly the D3 rules), *Sync* (what the
server sees: ciphertext, sizes rounded to 256 bytes, item counts, timestamps; OPAQUE),
*Host keys and certificates* (prompts, changed keys blocked), *Approvals* (T91 §8),
*Logs* (what each level contains, `--debug` warning, session log), *Plain FTP* (unencrypted,
how the UI shows it), *Reporting a vulnerability* (→ `SECURITY.md`).

#### 5. `docs/faq.md`
At least: macOS Gatekeeper with an unsigned binary (referenced by `cd.yml`'s notice);
"I forgot my master password" (sync: recovery key; local-only: keyring path or data
loss); keyring unavailable on headless Linux; function keys not working in a terminal or
tmux; where the logs are and what to attach to a bug report (and what not).

#### 6. `docs/release.md` (adapted from sverb)
1. *Flow*: conventional commits; bump `workspace.package.version` **and** every internal
   `[workspace.dependencies]` `version`; add `## [X.Y.Z] - YYYY-MM-DD` to `CHANGELOG.md`;
   `cargo test` (updates the man-page snapshot); dry run (**Actions → CD → Run workflow**);
   manual checks; `git tag vX.Y.Z && git push origin vX.Y.Z`.
2. *What cd.yml produces and checks* (the T00 job table).
3. *Secrets* table (T00).
4. *crates.io publishing* (manual, in dependency order): `courier-ftp-crypto` →
   `courier-ftp-proto` → `courier-ftp-core` → `courier-ftp-store` →
   `courier-ftp-proto-ftp` → `courier-ftp-proto-sftp` → `courier-ftp-sync` →
   `courier-ftp`; then `courier-ftp-server`. `courier-ftp-e2e` is never published.
5. *Manual checks* per channel (checkbox list, results recorded with the release commit):
   `cargo install` (default and `--no-default-features`), Linux tarballs on a distro without
   Rust (`--version`, `man ./man/courier-ftp.1`), AUR both packages in a clean Arch
   container, Homebrew macOS Intel + Apple silicon + Linux, Scoop on Windows 11 in Windows
   Terminal, macOS universal Gatekeeper behaviour, server image `--version` + compose quick
   start on amd64 and arm64, one SFTP and one FTPS session against public test servers or
   the e2e fixtures, one sync round trip between two devices against the released server.
6. *Protocol versioning*: the sync API version (`/v1`) changes only for incompatible wire
   changes; the server serves N and N−1 (T83/T85).

#### 7. `CHANGELOG.md`
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) format, SemVer:
`## [Unreleased]` on top, released sections `## [X.Y.Z] - YYYY-MM-DD` with subsections
`### Added`, `### Changed`, `### Fixed`, `### Security`, `### Removed` (only those that
apply), link references at the bottom. `build:`/`ci:`/`chore:`/`test:` commits are not
listed. The first release section is `## [1.0.0]`; pre-1.0 history is summarised in one
paragraph.

#### 8. Release pipeline changes (on top of T00)
- `cd.yml` `release` job: notes come from `scripts/release-notes.sh "$VERSION"`. On a tag
  a missing or empty section **fails** the job (T00's "See CHANGELOG.md." fallback stays
  for dry runs only).
- `cd.yml` `assets` job runs (T70's `generate` exists); every client archive contains
  `man/courier-ftp.1` and `completions/{courier-ftp.bash,_courier-ftp,courier-ftp.fish,_courier-ftp.ps1,courier-ftp.elv}`.
- `ci.yml` `docs` job gains `python3 scripts/check-doc-links.py` and
  `scripts/release-notes.sh --self-test`.
- `packaging/` files get real metadata: description "A terminal FTP, FTPS and SFTP client",
  homepage `https://github.com/viperh/courier-ftp`, license MIT, the man page and
  completions installed to the standard locations (AUR `usr/share/man/man1`,
  `usr/share/bash-completion/completions`, `usr/share/zsh/site-functions`,
  `usr/share/fish/vendor_completions.d`; Homebrew `man1.install`, `bash_completion.install`
  etc.; Scoop `bin` only), and a `test` block in the Homebrew formula
  (`assert_match version.to_s, shell_output("#{bin}/courier-ftp --version")`).
- Build verification with the real dependency set (russh, rustls/ring, bundled SQLite,
  zstd): the dry run must pass on all targets; any target-specific build fix (e.g. a C
  toolchain for `aarch64-unknown-linux-musl` under `cross`) goes into `Cross.toml` and is
  documented in `docs/release.md`.

### Data formats and configuration

- New files: `docs/{keybindings,configuration,security,faq,release}.md`,
  `docs/demo.tape`, `docs/demo.gif`, `CHANGELOG.md`, `scripts/check-doc-links.py`,
  `scripts/release-notes.sh`, optionally `Cross.toml`.
- No new settings. Env `COURIER_FTP_BLESS=1` (tests only) rewrites generated docs.
- Generated-region markers: `<!-- BEGIN GENERATED: keybindings -->`,
  `<!-- BEGIN GENERATED: settings -->` and matching `END` lines.

### Errors

Not applicable to runtime code. Failure messages: stale docs name the bless command;
`check-doc-links.py` prints `file:line: broken link <target>`; `release-notes.sh` prints
`no CHANGELOG.md section for <version>`.

### Security and logging

- Docs and the demo use reserved example names (`example.org`, `203.0.113.0/24`) and the
  TEST-ONLY fixtures; no real hostnames, users or keys.
- `docs/security.md` must not promise more than the threat model: every statement links to
  the threat-model row or task that implements it; residual risks are repeated in short.
- Release secrets are only used in `cd.yml` (T00); `docs/release.md` lists them without
  values.
- `SECURITY.md` (T91) is linked from README, `docs/security.md` and the GitHub repository
  security policy.

## Implementation steps

1. `scripts/check-doc-links.py` (+ self-test) and `scripts/release-notes.sh` (+ self-test);
   add both to the `docs` CI job.
2. `docs_gen.rs` + `docs/keybindings.md` (generated region and intro).
3. `configuration_doc.rs` + `docs/configuration.md`.
4. `docs/security.md`, `docs/faq.md`, `docs/release.md`.
5. `CHANGELOG.md` with `[Unreleased]` filled from the git history.
6. README rewrite; `docs/demo.tape` + `docs/demo.gif`.
7. `cd.yml`: notes via `release-notes.sh`, fail on tag without notes; `packaging/` metadata
   and install paths; `Cross.toml` if needed.
8. Full `cd.yml` dry run on the release-candidate commit; manual checks; tag `v1.0.0`.

## Acceptance criteria

- [ ] AC1 README has the eleven sections of §1 in order; `python3 scripts/check-doc-links.py` exits 0 on the repository and its `--self-test` passes.
- [ ] AC2 `docs/keybindings.md` matches the default keymap: `cargo test -p courier-ftp docs_gen` passes; changing one default binding makes it fail with the bless hint; `COURIER_FTP_BLESS=1` rewrites only the generated region.
- [ ] AC3 `docs/configuration.md` lists every key of `Settings` with type and default: `cargo test -p courier-ftp-core --test configuration_doc` passes and fails when a setting is added without regenerating.
- [ ] AC4 `docs/security.md`, `docs/faq.md`, `docs/release.md`, `docs/self-hosting.md` (T86), `docs/threat-model.md` and `SECURITY.md` (T91) exist and are linked from README `## Documentation`.
- [ ] AC5 `CHANGELOG.md` follows Keep a Changelog; `scripts/release-notes.sh 1.0.0` prints a non-empty section; a test tag on a fork without a section fails the `release` job.
- [ ] AC6 A `cd.yml` dry run on the release candidate produces all archives of T00 §5 plus SBOM and `SHA256SUMS`; `tar tzf` / `unzip -l` of each client archive lists `man/courier-ftp.1` and the five completion files; static, `lipo` and reproducibility checks pass; both server image architectures become healthy.
- [ ] AC7 `cargo install --path crates/courier-ftp --locked` and the same with `--no-default-features` succeed on a clean machine; `cargo package --workspace --exclude courier-ftp-e2e --locked` passes (T00 `packaging`).
- [ ] AC8 The manual checks of `docs/release.md` §5 are recorded (date, version, result per channel) for v1.0.0.
- [ ] AC9 All T00 CI gates pass, including the extended `docs` job.

## Tests

### Unit tests
- `crates/courier-ftp/src/docs_gen.rs::tests::keybindings_doc_is_current` — renders and compares with `docs/keybindings.md` (generated region only) (AC2).
- `crates/courier-ftp/src/docs_gen.rs::tests::bless_replaces_only_generated_region` — in a temp copy: text outside the markers is unchanged after blessing (AC2).
- `crates/courier-ftp/src/docs_gen.rs::tests::every_default_binding_appears` — each action with a default key appears in the rendered table (AC2).
- `scripts/check-doc-links.py --self-test` — good link, missing file, missing anchor, link inside a code block ignored (AC1).
- `scripts/release-notes.sh --self-test` — present section, missing section, empty section, last section in file (AC5).

### Property / fuzz tests
Not applicable.

### Snapshot tests
- The man page snapshot is T70's `man_page_snapshot`; this task only ships the file (AC6).

### Integration tests
- `crates/courier-ftp-core/tests/configuration_doc.rs::configuration_doc_is_current` and `::every_settings_key_documented` — walks the schema's properties recursively and checks each dotted key appears in the generated region (AC3).
- CI `docs` job (link check, notes self-test) and `packaging` job (AC1, AC7, AC9).

### End-to-end tests
- `cd.yml` dry run on the release candidate (AC6) and the fork tag test (AC5).
- Manual release checks (AC8), recorded in `docs/release.md`.

## Out of scope

- Translations of the documentation (T75 covers UI strings only).
- A documentation website (mdBook / GitHub Pages).
- winget and other channels not set up by T00 (see Open questions).
- crates.io publish automation (manual per `docs/release.md`).

## Open questions

- **winget / Debian / Fedora packages:** add more channels after 1.0, or before?
- **Demo GIF:** is a VHS GIF in the README wanted, or a static screenshot only (smaller repository)?
- **1.0 scope statement:** which FEATURES.md items may ship as "later" in 1.0 (the README status table needs the owner's list)?
- **Dependency change (reported):** T70 added to **Depends on** because the man page and completions in the release archives come from T70's `generate` subcommand (this task originally generated the man page itself).
