# T70 — Command-line arguments

**Phase:** G App-level · **Depends on:** T02, T31, T60, T61 · **Crate:** `courier-ftp` (`cli.rs`) · **FEATURES.md:** §2 (command-line start)
**Related (integrates with, not blocking):** T71, T91

## Goal

Start courier-ftp straight into a connection or directory, mirroring FileZilla's
command-line options.

## Scope

1. Positional `[URL_OR_PATH]`:
   - URL (`sftp://user@host:port/path`, `ftp://`, `ftps://`, `ftpes://`) → quickconnect on start; password from URL (`user:pass@`) accepted but a warning is printed that it's visible in shell history/process list.
   - Local path → local pane starts there.
2. `-s, --site <PATH>`: connect to a Site Manager entry by path (`"Work/Production/web01"`, T31 lookup); with `0/` prefix compatibility not needed. Requires vault unlock (prompt in TUI).
3. `-l, --local <DIR>`: initial local dir (combine with URL/site).
4. `--logontype <ask|interactive>` override (FileZilla has this) — optional.
5. `--config-dir`, `--data-dir`: override dirs (sets the same env vars used by `config.rs`).
6. `--debug-level <0-4>`, `--log-file <PATH>` (T71).
7. `--no-vault` (skip the unlock screen: session without vault, nothing persisted) and `--no-keyring` (ignore keyring unlock for this start, ask for the password).
7b. `--debug`: debug log level, prints a warning that debug logs may contain hostnames (T91 §4).
8. Existing `--tick-rate`, `--frame-rate`, `--version` keep working; `--version` output adds vault path.
9. Shell completions: hidden subcommand `completions <shell>` via `clap_complete`.
10. Error for unknown site path lists close matches (fuzzy).

## Acceptance criteria

- [ ] Each flag documented in `--help` and README.
- [ ] URL/site/local combos start in the right state (integration test via `App` constructor, no real terminal).
- [ ] Password-in-URL warning printed to stderr before TUI starts.

## Tests

- `clap` parse tests; app-init tests.
