# T70 — Command-line arguments

**Phase:** G App-level · **Milestone:** M9 · **Depends on:** T02, T31, T60, T61 · **Crate(s):** `courier-ftp` (`cli/` module, `main.rs`, `paths.rs`) · **Decisions:** D3, D10 · **FEATURES.md:** §2 (command-line start), §9 (debug level)
**Related (integrates with, not blocking):** T71, T91
**Reference:** sverb `crates/sverb/src/cli/{mod,exit,generate}.rs`, `crates/sverb/src/main.rs`, `crates/sverb/tests/cli.rs`

## Goal

Start courier-ftp straight into a connection, a saved site or a local directory, with
FileZilla-compatible long option names (`--site`, `--local`, `--logontype`). Every
flag is documented in `--help` and in a generated man page, shells get completion
scripts, and the process returns documented exit codes. Developers get a pure,
testable `Cli` → `LaunchIntent` conversion that needs no terminal.

## Context

- The template `cli.rs` has only `--tick-rate`/`--frame-rate` and a `--version` text that
  prints the config and data directories resolved from env vars (`COURIER_FTP_CONFIG`,
  `COURIER_FTP_DATA`, and `COURIER_FTP_HOME` from T01).
- T02 provides `ServerAddress` URL parsing (`ftp://`, `ftps://`, `ftpes://`, `sftp://`),
  `LogonType`, `RemotePath`, `LocalPath` and `courier_ftp_core::Error`.
- T31 provides site lookup by path string (`"Work/Production/web01"`).
- T60 starts the TUI locked and runs command-line launch intents after unlock (or after
  "Continue without vault").
- T61 provides tabs; a launch intent opens in a tab.
- T00's `cd.yml` and `nix` job call `courier-ftp generate man` and
  `courier-ftp generate completions <shell>`; T77 ships the man page.
- Later in M9: T71 consumes `--debug`, `--debug-level`, `--log-file`; T74 consumes
  `--no-update-check`; T75 adds `--lang`.

## Technical specification

### Types and APIs

Module layout (replaces `src/cli.rs`):

```
crates/courier-ftp/src/cli/mod.rs        Cli, parse, version text, dispatch
crates/courier-ftp/src/cli/exit.rs       exit codes, CliError, HELP text
crates/courier-ftp/src/cli/intent.rs     LaunchIntent, LaunchTarget, conversion from Cli
crates/courier-ftp/src/cli/generate.rs   `generate man | completions`
crates/courier-ftp/src/paths.rs          AppPaths (config/data dir resolution)
```

```rust
/// courier-ftp: a terminal FTP, FTPS and SFTP client.
#[derive(clap::Parser, Debug, PartialEq)]
#[command(name = "courier-ftp", author, about, disable_version_flag = true,
          args_conflicts_with_subcommands = true, after_long_help = exit::HELP)]
pub(crate) struct Cli {
    /// URL to connect to (ftp://, ftps://, ftpes://, sftp://) or a local directory to open
    #[arg(value_name = "URL_OR_PATH")]
    pub target: Option<String>,
    /// Connect to a Site Manager entry by its path, e.g. "Work/Production/web01"
    #[arg(short = 's', long, value_name = "PATH", conflicts_with = "target")]
    pub site: Option<String>,
    /// Start the local pane in this directory
    #[arg(short = 'l', long, value_name = "DIR")]
    pub local: Option<PathBuf>,
    /// Logon type for a URL: ask for the password, or use keyboard-interactive
    #[arg(long, value_enum, value_name = "TYPE", requires = "target", conflicts_with = "site")]
    pub logontype: Option<LogonTypeArg>,
    /// Use this config directory
    #[arg(long, value_name = "DIR", env = "COURIER_FTP_CONFIG")]
    pub config_dir: Option<PathBuf>,
    /// Use this data directory (vault database, logs, crash reports)
    #[arg(long, value_name = "DIR", env = "COURIER_FTP_DATA")]
    pub data_dir: Option<PathBuf>,
    /// Message log debug level for this run: 0 none, 1 warning, 2 info, 3 verbose, 4 debug
    #[arg(long, value_name = "0-4", value_parser = clap::value_parser!(u8).range(0..=4))]
    pub debug_level: Option<u8>,
    /// Also write the message log to this file for this run
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,
    /// Write the application log at debug level (log files may then contain hostnames)
    #[arg(long)]
    pub debug: bool,
    /// Start without the vault: quickconnect only, nothing is saved
    #[arg(long, conflicts_with_all = ["site", "no_keyring"])]
    pub no_vault: bool,
    /// Do not use keyring unlock for this start; ask for the master password
    #[arg(long)]
    pub no_keyring: bool,
    /// Do not check for a new release on this start
    #[arg(long, env = "COURIER_FTP_NO_UPDATE_CHECK", value_parser = clap::builder::FalseyValueParser::new())]
    pub no_update_check: bool,
    /// UI ticks per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 4.0, value_parser = tick_rate)]
    pub tick_rate: f64,
    /// Frames per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 60.0, value_parser = frame_rate)]
    pub frame_rate: f64,
    /// Print version, build information and the directories in use
    #[arg(short = 'V', long)]
    pub version: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(clap::Subcommand, Debug, PartialEq)]
pub(crate) enum Command {
    /// Generate the man page or shell completions (for packagers)
    #[command(hide = true)]
    Generate(generate::GenerateArgs),
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogonTypeArg { Ask, Interactive }

impl Cli {
    /// Parses `args` (including argv[0]). Pure: no env access besides clap's `env = …`.
    pub(crate) fn try_parse_from_args<I, T>(args: I) -> Result<Self, clap::Error>
    where I: IntoIterator<Item = T>, T: Into<std::ffi::OsString> + Clone;
    /// Whether this invocation starts the TUI (false for `generate` and `--version`).
    pub(crate) fn launches_tui(&self) -> bool;
}

/// The resolved directories. Built once in `main` and passed explicitly
/// (replaces the template's `LazyLock` env statics in `config.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppPaths { pub config_dir: PathBuf, pub data_dir: PathBuf }

impl AppPaths {
    /// Precedence per directory: CLI flag > `COURIER_FTP_CONFIG`/`COURIER_FTP_DATA`
    /// (clap already folds these into the flag) > `COURIER_FTP_HOME`/{config,data} > OS default.
    pub(crate) fn resolve(cli_config: Option<&Path>, cli_data: Option<&Path>, env: &dyn Env) -> Self;
    pub(crate) fn vault_db(&self) -> PathBuf;   // <data>/courier-ftp.db (T30)
    pub(crate) fn log_dir(&self) -> PathBuf;    // <data>/logs (T71)
    pub(crate) fn crash_dir(&self) -> PathBuf;  // <data>/crash (T71)
}

/// What the TUI does once the vault is unlocked (or skipped). Built from `Cli`.
#[derive(Debug, PartialEq)]
pub struct LaunchIntent {
    pub target: LaunchTarget,
    /// From `--local` or a positional local path; overrides a site's default local dir.
    pub local_dir: Option<LocalPath>,
    /// Entry to select in the local pane (positional path pointed at a file).
    pub select_local: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum LaunchTarget {
    None,
    /// Quickconnect. `password` is never logged; `Debug` prints `[REDACTED]`.
    Url { address: ServerAddress, password: Option<SecretString>, remote_dir: Option<RemotePath>,
          logon: Option<LogonTypeArg> },
    /// Site Manager path, resolved after unlock (T31).
    Site(String),
}

/// Per-run overrides that are never written to the config file.
#[derive(Debug, Clone, PartialEq)]
pub struct RunOptions {
    pub tick_rate: f64, pub frame_rate: f64,
    pub debug: bool, pub debug_level: Option<u8>, pub session_log_file: Option<PathBuf>,
    pub no_vault: bool, pub no_keyring: bool, pub no_update_check: bool,
}

/// Converts a parsed command line. Checks local paths on disk (through `fs`).
pub(crate) fn launch_from_cli(cli: &Cli, fs: &dyn LocalFs) -> Result<(LaunchIntent, RunOptions, Vec<Warning>), CliError>;

/// Splits a launch URL into address, password and path (wraps T02 `ServerAddress::from_str`).
pub(crate) fn parse_launch_url(s: &str) -> Result<LaunchTarget, CliError>;

/// Site lookup failure with suggestions (used by the TUI after unlock).
pub fn site_suggestions(tree: &SiteTree, wanted: &str) -> Vec<String>;
```

`exit.rs` (codes are stable and listed in `--help`):

```rust
pub(crate) const OK: u8 = 0;        // success
pub(crate) const FAILURE: u8 = 1;   // runtime failure, no terminal, internal error
pub(crate) const USAGE: u8 = 2;     // bad command line (clap uses 2 as well)
pub(crate) const NOT_FOUND: u8 = 4; // --local / positional local path does not exist
// 3 is reserved for "vault locked" (sverb), 101 is a crash (panic, T71).

#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")] Usage(String),
    #[error("{0}")] NotFound(String),
    #[error("courier-ftp needs an interactive terminal (stdout is not a TTY)")] NoTty,
    #[error("{0}")] Failure(String),
}
impl CliError { pub(crate) fn exit_code(&self) -> u8; }
```

`generate.rs`:

```rust
#[derive(clap::Args, Debug, PartialEq)]
pub(crate) struct GenerateArgs { #[command(subcommand)] pub what: GenerateCmd }
#[derive(clap::Subcommand, Debug, PartialEq)]
pub(crate) enum GenerateCmd {
    /// The man page (roff) to stdout, or `<DIR>/courier-ftp.1`
    Man { #[arg(long, value_name = "DIR")] out_dir: Option<PathBuf> },
    /// A completion script to stdout
    Completions { shell: clap_complete::Shell },   // bash, elvish, fish, powershell, zsh
}
```

### Behaviour

**Startup order in `main`** (sverb order, adapted): install panic hook (T71) →
`harden_process()` (T91) → parse CLI → resolve `AppPaths` → `--version` / `generate`
(print, exit 0, no logging, no terminal) → logging init (T71, uses `--debug`) →
load config (T05) and apply `RunOptions` → TTY check → build the tokio runtime →
run the app with the `LaunchIntent`. The CLI is parsed **before** paths, because
`--config-dir`/`--data-dir` change them; that is why clap's automatic version flag is
disabled and `-V/--version` is handled after parsing.

**Positional `URL_OR_PATH`:**

| Input | Meaning |
|---|---|
| starts with `ftp://`, `ftps://`, `ftpes://`, `sftp://` (scheme case-insensitive) | URL → `LaunchTarget::Url` |
| any other `<scheme>://` | usage error (exit 2): `unsupported URL scheme "http"; use ftp, ftps, ftpes or sftp` |
| anything else | local path. Existing dir → `local_dir`. Existing file → parent dir + `select_local = file name`. Missing → exit 4 `no such file or directory: <path>` |

A bare `host` or `host:port` is **not** treated as a URL (ambiguous with a relative
path); `--help` says to write `ftp://host`. A local directory literally named `generate`
must be written `./generate` (subcommand names win).

**URL parsing** (`parse_launch_url`): the password (`user:pass@`) is removed from the
string and moved into a `SecretString` before the rest goes to T02's
`ServerAddress::from_str`. The path part (percent-decoded) becomes `remote_dir`
(`RemotePath`, normalised; empty or `/` → `None` = server's home dir). Port defaults
follow T02 (21/990/22). Parse errors from T02 (`Error::InvalidInput`) become
`CliError::Usage` (exit 2).

**Option combinations** (enforced by clap attributes, plus `launch_from_cli` for the
path rules):

| Combination | Result |
|---|---|
| URL + `--local` | connect; local pane at `--local` |
| URL + `--logontype ask` | prompt for the password on connect (`LogonType::AskForPassword`); a URL that also contains a password → usage error |
| URL + `--logontype interactive` | `LogonType::Interactive` (keyboard-interactive for SFTP; FTP: password prompt per reply 331) |
| `--site` + `--local` | connect to site; local pane at `--local` (overrides the site's `default_local_dir`) |
| `--site` + positional | usage error (clap `conflicts_with`) |
| positional local path + `--local` | usage error: `give the local directory once (positional or --local)` |
| `--site` + `--no-vault` | usage error: sites live in the vault |
| `--no-vault` + `--no-keyring` | usage error (redundant/conflicting) |
| `--logontype` without a URL | usage error |
| `--local <missing dir>` | exit 4 |

**Per-run overrides** (`RunOptions`, never saved by `Settings::save_user`):
- `--debug-level N` replaces `logging.level` for this process (T04 source filter, T71).
  Changing the level in Settings during the run still works and is saved normally.
- `--log-file PATH` turns on the session log file for this run at `PATH`
  (`logging.log_to_file = true`, `logging.log_file = PATH` in memory only). The parent
  directory must exist, else exit 4.
- `--debug`: application log default level `debug` (T71). Before the TUI starts,
  stderr gets `warning: debug logging is on: log files may contain hostnames and usernames`
  (T91 §4); the TUI also shows it once as a status message.
- `--no-vault`: the unlock screen is skipped as if "Continue without vault" was chosen
  (T60): quickconnect only, nothing persisted, status bar `🔐 locked`.
- `--no-keyring`: keyring unlock is not attempted on this start even if enabled (T30); the
  master password screen is shown. The keyring setting is unchanged.
- `--no-update-check` or `COURIER_FTP_NO_UPDATE_CHECK` set to a truthy value: T74 makes no
  network request on this run. Falsey values (`0`, `false`, `no`, `off`, empty) are ignored.
- `--tick-rate` must be in `0.1..=60.0`; `--frame-rate` in `1.0..=240.0`; else exit 2.

**Running a launch intent (in the TUI):**
1. The app starts as T60 describes. The intent is stored in `App` and runs on the first
   transition to *unlocked* or *continue without vault* (immediately with `--no-vault`).
2. With `interface.restore_tabs` (T61) on, restored tabs open first; the intent then
   opens in a **new** tab, which becomes active. Otherwise it uses tab 1.
3. `Url` → the quickconnect path of T58 with the fields filled (host, user, port,
   protocol, password); `remote_dir` is entered after login (failure to enter it is an
   `Error:` log line, the session stays at the home dir).
4. `Site(path)` → T31 lookup by path. Matching: exact (case-sensitive) first; if none, a
   case-insensitive match is accepted when it is unique. Not found → error dialog
   `No site "Work/web1". Did you mean: Work/web01, Work/web02?` listing up to 5 site
   paths with `strsim::jaro_winkler(lowercase) ≥ 0.80`, best first; the app continues
   to the normal screen. When the user chose "Continue without vault", the dialog says
   `"--site" needs the vault; unlock it to connect` with an Unlock button.
5. If the site has synced local-acting fields that are not approved on this device
   (T91 §8), the normal approval prompt appears before connecting.
6. `local_dir` and `select_local` are applied to the new tab's local pane before connecting.

**TTY check:** when stdout is not a terminal and the TUI would start, print the
`NoTty` message and exit 1 before touching terminal modes (no escape bytes reach a pipe).
Warnings (password-in-URL, `--debug`) are printed **before** this check.

**`--version` text** (exit 0):

```
courier-ftp 1.2.0-v1.2.0-3-gabc1234 (2026-10-09) features: sync

Authors: qviperh <…>

Config directory: /home/alice/.config/courier-ftp
Data directory:   /home/alice/.local/share/courier-ftp
Vault database:   /home/alice/.local/share/courier-ftp/courier-ftp.db
Log directory:    /home/alice/.local/share/courier-ftp/logs
COURIER_FTP_HOME: not set
```

`features:` lists enabled cargo features of the binary (`sync`, `update-check`), or `none`.

**`--help`** (`after_long_help` = `exit::HELP`, also in the man page):

```
Examples:
  courier-ftp                                  open the local home directory
  courier-ftp ~/projects/site                  open a local directory
  courier-ftp sftp://alice@example.com/var/www connect, then open /var/www
  courier-ftp --site "Work/Production/web01" --local ~/projects/web01

Environment:
  COURIER_FTP_HOME             base directory for config/ and data/ (tests, portable use)
  COURIER_FTP_CONFIG           config directory (same as --config-dir)
  COURIER_FTP_DATA             data directory (same as --data-dir)
  COURIER_FTP_LOG_LEVEL        application log filter, e.g. "debug" or "courier_ftp_proto_ftp=trace"
  COURIER_FTP_NO_UPDATE_CHECK  set to 1 to disable the update check
  NO_COLOR                     disable colours

Exit codes:
  0    success
  1    failure (including: no interactive terminal)
  2    usage error
  4    local path not found
  101  crash (a crash report was written, see the log directory)
```

**Completions and man page:** `clap_complete::generate` for bash, elvish, fish,
powershell and zsh, and `clap_mangen::Man::new(Cli::command()).render` (no date, so the
output is deterministic and reproducible, T00 §5). Hidden subcommands and hidden flags
are excluded. `generate man --out-dir DIR` creates `DIR` and writes `DIR/courier-ftp.1`.
Neither command touches the config, data dir, logging or terminal.

### Data formats and configuration

No new settings keys. Flags override (in memory only): `logging.level` (`--debug-level`),
`logging.log_to_file` + `logging.log_file` (`--log-file`), `interface.check_updates`
(`--no-update-check`). Workspace `clap` gains the `env` feature; new workspace deps
`clap_complete`, `clap_mangen`, `strsim` (pin current versions, T01 rules).

### Errors

| Situation | Error | User sees | Exit |
|---|---|---|---|
| clap parse error, conflict, range | `clap::Error` | clap message + usage | 2 |
| unsupported scheme, bad URL (T02 `Error::InvalidInput`) | `CliError::Usage` | `error: invalid URL: <reason>` (password masked) | 2 |
| missing local path / `--log-file` parent | `CliError::NotFound` | `error: no such directory: <path>` | 4 |
| stdout not a TTY | `CliError::NoTty` | message above | 1 |
| `generate` write failure | `CliError::Failure` | `error: cannot write <file>: <io error>` | 1 |
| site not found after unlock | (TUI) | error dialog with suggestions | n/a |

Errors print as `error: …` on stderr with `writeln!` (not `eprintln!`, which panics when
stderr is closed). Nothing is printed to stdout except `--help`, `--version` and `generate`.

### Security and logging

- A password in the URL is moved into `SecretString` at parse time; the `String` holding
  the original argument is zeroized (`zeroize::Zeroize`) after splitting. The process
  argument list itself cannot be scrubbed portably, so before the TUI starts stderr gets:
  `warning: the password in the URL is visible in your shell history and the process list; use --logontype ask or a saved site instead`.
- `LaunchTarget`'s `Debug` prints `[REDACTED]` for the password (test).
- Logging: `info!` lines name only the intent kind (`launch intent: url` / `site` /
  `local`) — no host, user, site path or local path (T91 §4). `debug!` may log the URL
  with the password replaced by `****` and the site path.
- Site paths, URLs and paths shown in dialogs pass through the control-character
  stripping helper (T91, T53/T55) — they come from argv, which may contain escape bytes.

## Implementation steps

1. Add `paths.rs` with `AppPaths::resolve` (flag > env > `COURIER_FTP_HOME` > OS default)
   and switch `config.rs`, `logging.rs` and `version()` to take `AppPaths`; remove the
   `LazyLock` env statics. Unit tests for precedence.
2. Replace `cli.rs` with the `cli/` module: `Cli` with all flags, `exit.rs`, manual
   `-V/--version`, `after_long_help`. Parse tests.
3. `intent.rs`: `parse_launch_url`, `launch_from_cli` with the combination rules and
   local path checks (through a `LocalFs` trait for tests). Unit tests.
4. Rework `main.rs` into the startup order above with `CliError` → exit code mapping,
   stderr warnings and the TTY check.
5. App integration: `App::new` takes `LaunchIntent` + `RunOptions`; run the intent after
   unlock / continue-without-vault (T60), in a tab per T61, connect via T58/T31; site
   suggestions dialog.
6. `generate` subcommand (man + completions) with snapshot tests; wire into T00's
   `cd.yml`/`packaging` assets if not already done.
7. README "Usage" section and `docs/configuration.md` env-var table (T77) updated from the
   help text.

## Acceptance criteria

- [ ] AC1 Every flag in the `Cli` struct appears in `courier-ftp --help` and the man page;
  the long help contains the Examples, Environment and Exit codes sections (snapshot test).
- [ ] AC2 Each row of the option-combination table produces the stated result or exit
  code (parse/intent tests and binary tests).
- [ ] AC3 URL, site and local-path launches start in the right state: correct tab, local
  dir, selected file and connect call, verified through `App` with a mock backend factory
  and no terminal.
- [ ] AC4 A password in the URL produces the warning on stderr before the TUI starts,
  never appears in `Debug` output, the app log or the session log (canary test).
- [ ] AC5 Unknown `--site` path shows the error dialog with up to 5 suggestions, best first.
- [ ] AC6 `courier-ftp generate man` and `generate completions <shell>` for all five shells
  exit 0, are byte-identical across two runs, and need no config/data dir
  (`COURIER_FTP_HOME` pointing to a non-existent dir is not created).
- [ ] AC7 `--version` lists config dir, data dir, vault DB path, log dir and features, and
  reflects `--config-dir`/`--data-dir` given on the same command line.
- [ ] AC8 Exit codes 0, 1, 2, 4 occur exactly in the documented cases; piping stdout
  makes the TUI exit 1 without writing escape sequences.
- [ ] AC9 `--no-vault`, `--no-keyring`, `--debug-level`, `--log-file`, `--no-update-check`
  take effect for the run and are not written to the user config.
- [ ] AC10 CI gates from T00 pass: `fmt`, `clippy` (both feature sets), `docs`,
  `test-local-only`, `test-os`, `layering` (core still has no `clap` dependency).

## Tests

### Unit tests
- `paths_flag_wins_over_env_and_home`, `paths_env_wins_over_home`, `paths_home_sets_both`, `paths_default_uses_project_dirs` — AppPaths precedence (AC7).
- `parse_no_args_is_plain_launch`, `parse_url_positional`, `parse_site_short_and_long`, `parse_local_short_and_long` — field mapping (AC2).
- `parse_rejects_site_with_positional`, `parse_rejects_no_vault_with_site`, `parse_rejects_no_vault_with_no_keyring`, `parse_rejects_logontype_without_url` — clap conflicts return `ErrorKind::ArgumentConflict`/`MissingRequiredArgument`, exit code 2 (AC2, AC8).
- `parse_debug_level_range` — `5` and `-1` rejected, `0..=4` accepted (AC2).
- `parse_tick_and_frame_rate_ranges` — bounds inclusive, `0` rejected (AC2).
- `no_update_check_env_truthy_and_falsey` — `1`/`true` set it, `0`/`false`/empty do not (AC9).
- `url_with_password_is_split_and_redacted` — password in `SecretString`, `format!("{:?}")` contains `[REDACTED]` and not the password (AC4).
- `url_path_becomes_remote_dir` — `sftp://a@h/var/www%20x` → `/var/www x`; `/` → `None` (AC3).
- `url_unknown_scheme_is_usage_error`, `bare_host_is_local_path` (AC2).
- `local_file_selects_entry_in_parent`, `missing_local_path_is_not_found_exit_4` (AC2, AC8).
- `logontype_ask_with_password_is_usage_error` (AC2).
- `site_suggestions_ranked_and_capped_at_5`, `site_lookup_unique_case_insensitive_match` (AC5).
- `help_mentions_every_visible_flag` — iterates `Cli::command().get_arguments()` and checks each long name is in the rendered help (AC1).

### Snapshot tests
- `help_long_snapshot` — `Cli::command().term_width(100).render_long_help()` with insta (AC1).
- `man_page_snapshot` — rendered man page (AC1, AC6).
- `version_text_snapshot` — with fixed paths and a fixed version string injected (AC7).
- `site_not_found_dialog_80x24`, `site_not_found_dialog_160x48` — TestBackend + insta (AC5).

### Integration tests
- `app_launch_url_connects_in_tab_1` — `App` built with a `LaunchIntent::Url`, mock `BackendFactory` records the `ConnectInfo` (host, port, user, protocol, password present) after simulated "continue without vault" (AC3).
- `app_launch_site_after_unlock` — test vault (cheap Argon2) with a nested unicode site path; intent runs only after unlock (AC3).
- `app_launch_with_restore_tabs_opens_new_tab` (AC3).
- `app_launch_local_dir_and_selection` (AC3).
- `run_options_not_saved` — `--debug-level 4 --log-file x` then Settings save: user config has no `logging.level`/`log_file` (AC9).
- Binary tests (`std::process::Command` with `CARGO_BIN_EXE_courier-ftp`, temp `COURIER_FTP_HOME`):
  - `bin_generate_completions_all_shells_deterministic`, `bin_generate_man_out_dir` (AC6).
  - `bin_version_reflects_dir_flags` (AC7).
  - `bin_piped_stdout_exits_1_without_escapes` — stdout captured, empty of `\x1b` (AC8).
  - `bin_password_url_warns_on_stderr` — stderr contains the warning, exit 1 (no TTY) (AC4, AC8).
  - `bin_missing_local_exits_4`, `bin_bad_flag_exits_2` (AC8).

### End-to-end tests
- `e2e_cli_sftp_url_connects` (`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`): `PtyApp` runs `courier-ftp --no-vault sftp://test@<sshd>:<port>/upload`, accepts the host key prompt, enters the password at the prompt, waits for `/upload` in the remote pane title (AC3).
- `e2e_cli_site_connects_after_unlock`: `TestHome` with a site `Fixtures/ftp-plain`, run with `--site Fixtures/ftp-plain`, unlock, wait for the remote listing (AC3).

## Out of scope

- Headless subcommands (list, get, put, sync, backup) — courier-ftp is a TUI; sverb-style
  headless commands can be a later task.
- FileZilla's `0/`/`1/` site-path prefixes, `--site-manager`, `--close`, and short options
  `-c`/`-a` (FileZilla's) — long names match FileZilla, short options are ours.
- Opening a URL in an already running instance (single-instance IPC).
- Translating `--help` and CLI error messages (T75 keeps the CLI English).

## Open questions

None.
