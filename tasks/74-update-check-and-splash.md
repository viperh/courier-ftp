# T74 — Update check and splash screen

**Phase:** G App-level · **Milestone:** M9 · **Depends on:** T07, T50 · **Crate(s):** `courier-ftp-core` (`net::http`, `update` modules), `courier-ftp` (`components/splash.rs`, update notice) · **Decisions:** D9, D10 · **FEATURES.md:** §10 (automatic update check, optional splash screen)

## Goal

Tell users when a newer courier-ftp release exists — at most once a week, in the
background, without downloading or installing anything — and let users and packagers
turn it off completely. Optionally show a splash screen while the app starts.

## Context

- T07 provides `connect_tcp(&HostPort, &NetOpts, CancellationToken, &SessionLog) ->
  Result<NetStream>` with timeouts, IPv6 preference and HTTP/SOCKS proxies, and
  `NetOpts::from_settings`. T12 brings `tokio-rustls` and `rustls-platform-verifier` (D9)
  into the workspace.
- T05 registers `interface.check_updates` (true), `interface.show_splash` (false) and
  `interface.check_prereleases` (false).
- T50 provides the main screen, the status bar slot for transient messages (T57) and the
  help overlay (F1).
- T70 (same milestone, earlier) passes `RunOptions::no_update_check` from
  `--no-update-check` / `COURIER_FTP_NO_UPDATE_CHECK`.
- sverb never phones home (its SPEC §1.1 and `tests/network_silence.rs`); courier-ftp has
  the update check because FEATURES §10 asks for it, so it gets strict opt-outs and a
  silence test of its own.
- T72 can use the HTTPS client from this task for `https://` IP lookup URLs.

## Technical specification

### Types and APIs

**Minimal HTTP client** — `courier_ftp_core::net::http`. Decision: a small hand-written
HTTP/1.1 GET client over T07's `connect_tcp` + `tokio-rustls`, not `reqwest`: it honours
the user's generic proxy settings through T07 for free, adds no dependency to builds
without the `sync` feature (where `reqwest` is absent), and the code is ~300 lines.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: url::Url,                       // http or https only
    pub headers: Vec<(String, String)>,      // validated: no CR/LF
    pub max_body: usize,                     // bytes; larger → Error::Protocol
    pub timeout: Duration,                   // whole request (connect + TLS + response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }

/// GET with `Connection: close`, `Accept-Encoding: identity`. Follows no redirects.
/// Dials with `connect_tcp(&HostPort { host, port }, net, cancel.child_token(), log)` (T07).
pub async fn get(req: &HttpRequest, net: &NetOpts, log: &SessionLog, cancel: CancellationToken)
    -> Result<HttpResponse, Error>;
```

**Update check** — `courier_ftp_core::update`:

```rust
pub const RELEASES_API: &str = "https://api.github.com/repos/viperh/courier-ftp/releases";
pub const RELEASE_URL_PREFIX: &str = "https://github.com/viperh/courier-ftp/releases/";
pub const CHECK_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600);
pub const RETRY_AFTER_ERROR: Duration = Duration::from_secs(24 * 3600);
pub const STARTUP_DELAY: Duration = Duration::from_secs(10);
pub const STATE_FILE: &str = "update-check.json";        // in the data dir

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo { pub version: semver::Version, pub url: String, pub published_at: Option<String> }

/// Persisted state (non-secret JSON in the data dir).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    pub last_check: Option<String>,      // RFC 3339 UTC of the last attempt
    pub last_error: Option<String>,      // RFC 3339 UTC of the last failed attempt
    pub etag: Option<String>,
    pub latest: Option<StoredRelease>,   // newest release seen (any version)
    pub dismissed: Option<String>,       // version the user dismissed
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateConfig {
    pub enabled: bool,              // interface.check_updates && !RunOptions::no_update_check && feature on
    pub include_prereleases: bool,  // interface.check_prereleases
    pub current: semver::Version,   // CARGO_PKG_VERSION
}

/// Pure decision: should a request be made now?
pub fn is_due(state: &UpdateState, now: OffsetDateTime) -> bool;
/// Pure: the newest acceptable release from an API response body.
pub fn pick_release(body: &[u8], include_prereleases: bool) -> Result<Option<ReleaseInfo>, Error>;
/// Pure: what to show, if anything.
pub fn notice(state: &UpdateState, cfg: &UpdateConfig) -> Option<ReleaseInfo>;
/// Strips a leading `v`/`V` and parses semver. Invalid → None.
pub fn parse_tag(tag: &str) -> Option<semver::Version>;

/// Abstraction over the network for tests (the mock panics when called in silence tests).
pub trait ReleaseSource: Send + Sync + std::fmt::Debug {
    fn fetch<'a>(&'a self, include_prereleases: bool, etag: Option<&'a str>, cancel: CancellationToken)
        -> BoxFuture<'a, Result<FetchResult, Error>>;
}
pub enum FetchResult { NotModified, Body { body: Vec<u8>, etag: Option<String> } }

/// Background task: waits STARTUP_DELAY, checks if due, updates the state file, and
/// returns the notice to show. Returns immediately (no I/O at all) when `!cfg.enabled`.
/// `Clock` is T71's injectable time source; this task moves it to
/// `courier_ftp_core::clock::Clock` and re-exports it from `session_log`.
pub async fn run_check(cfg: UpdateConfig, data_dir: PathBuf, source: Arc<dyn ReleaseSource>,
    clock: Arc<dyn Clock>, cancel: CancellationToken) -> Option<ReleaseInfo>;
```

**UI**: `Action::UpdateAvailable(ReleaseInfo)`, `Action::DismissUpdate` (default key
`Ctrl-x u`, T51's `Ctrl-x` prefix table, owner T74); `components/splash.rs` with
`Splash { shown_at: Instant, init_done: bool }`.

**Cargo feature**: `update-check` on the `courier-ftp` binary, **default on**. With it
off, `run_check` is not compiled in, the setting is hidden in T68, and `--version` does
not list it — for distributions that forbid update checks.

### Behaviour

**When a check runs** (`enabled` must be true; otherwise nothing below happens, not even
reading the state file):
1. 10 s after startup (`STARTUP_DELAY`, not blocking anything; the vault does not need
   to be unlocked), load `<data dir>/update-check.json` (missing or invalid → default).
2. `is_due`: true when `last_check` is missing, or `now - last_check ≥ 7 days`, or
   `last_check` is more than 1 day in the future (clock was wrong); and, when
   `last_error` is set, `now - last_error ≥ 24 h`.
3. If not due: use the stored `latest` for the notice. If due: fetch, update the state,
   write it atomically (temp + rename, `0600`), then compute the notice.
4. At most one request per run; the task is cancelled on quit.

**Request** (`ReleaseSource` production impl via `net::http::get`):
- Stable only: `GET /repos/viperh/courier-ftp/releases/latest` (GitHub excludes drafts and
  prereleases). With prereleases: `GET /repos/viperh/courier-ftp/releases?per_page=10`.
- Headers: `User-Agent: courier-ftp/<version>`, `Accept: application/vnd.github+json`,
  `X-GitHub-Api-Version: 2022-11-28`, `If-None-Match: <etag>` when stored.
- Timeout 30 s total; body limit 1 MiB; proxy per settings (`NetOpts` from `Settings`).
- `200` → parse; `304` → `NotModified` (keep `latest`, update `last_check`); `404` (no
  releases yet) → no notice, `last_check` updated; `403`/`429`/`5xx`/network error →
  `last_error = now`, previous state kept. All failures are silent: `debug!` only.

**Parsing** (`pick_release`, serde_json, unknown fields ignored):
- Object (latest) or array (list). Use `tag_name`, `html_url`, `draft`, `prerelease`,
  `published_at`. Skip drafts. Skip prereleases (flag or semver pre-release part) unless
  `include_prereleases`. Pick the highest semver among the rest.
- `parse_tag`: trim, strip one leading `v`/`V`, `semver::Version::parse`; invalid → skipped.
  Build metadata is ignored in comparisons (semver precedence).
- `html_url` must start with `RELEASE_URL_PREFIX` and be ≤ 200 chars of
  `[A-Za-z0-9._~/:%-]`; otherwise the URL shown is `RELEASE_URL_PREFIX + "latest"`.

**Notice** (`notice`): `latest.version > current` (semver precedence: `1.10.0 > 1.9.3`,
`1.3.0 > 1.3.0-rc.1`, a running `1.3.0-rc.1` sees `1.3.0`), and `latest.version !=
dismissed`, and `enabled`. Then:
- Status bar transient message (T57) for 10 s: `Update available: v1.3.0 (F1 for details,
  Ctrl-x u to dismiss)`.
- Help overlay (F1) top line: `Update available: v1.3.0 — https://github.com/viperh/courier-ftp/releases/tag/v1.3.0`
  with the hint `Ctrl-x u: don't remind me about this version`. `Ctrl-x u`
  (`DismissUpdate`, works from anywhere while a notice exists; otherwise a no-op with
  the status message "No update notice") → `dismissed = "1.3.0"`, state written. A
  newer version shows again.
- No download, no install, no browser launch. Users update through their package
  manager or the releases page.

**Opt-outs** (any one disables all network activity for updates):

| Mechanism | Scope |
|---|---|
| `interface.check_updates = false` (Settings → Interface, T68) | persistent; also hides a stored notice |
| `--no-update-check` (T70) | this run |
| `COURIER_FTP_NO_UPDATE_CHECK=1` (truthy) | process; for packagers' wrapper scripts and CI |
| cargo feature `update-check` off | build |

**Splash screen** (`interface.show_splash`, default **off**):
- Drawn on the first frame, before the unlock screen (T60), centred: ASCII logo
  (≤ 6 lines × 40 columns, ASCII only), `courier-ftp <version>`, and `Loading…` with a
  spinner. Below 44 columns or 10 rows only the name/version line is drawn.
- Stays until both (a) startup init is done (config loaded, store opened, keyring unlock
  attempt finished) and (b) 1 s has passed since it appeared. Init finishing late keeps it
  up longer (with the spinner). Any key dismisses it immediately; that key is consumed.
- `NO_COLOR` honoured; no animation besides the spinner (tick rate).

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `interface.check_updates` | bool | `true` | Settings help: "Once a week, ask api.github.com for the latest release. Sends your IP address and courier-ftp version to GitHub." |
| `interface.check_prereleases` | bool | `false` | registered in T05 |
| `interface.show_splash` | bool | `false` | |
| env `COURIER_FTP_NO_UPDATE_CHECK` | truthy | unset | see T70 |

`<data dir>/update-check.json`:

```json
{
  "last_check": "2026-10-09T12:00:00Z",
  "last_error": null,
  "etag": "W/\"6f1c…\"",
  "latest": { "version": "1.3.0", "url": "https://github.com/viperh/courier-ftp/releases/tag/v1.3.0", "published_at": "2026-10-01T08:00:00Z" },
  "dismissed": null
}
```

Unknown fields are ignored; a corrupt file is replaced on the next successful write
(debug log).

### Errors

All update-check errors are swallowed after a `debug!` line: `Error::Connection`,
`Error::Timeout`, `Error::Tls`, `Error::Protocol` (bad status line, body > 1 MiB, bad
chunked encoding), JSON errors, state file I/O (`Error::Io`). The user never sees an error
from the update check. The HTTP client returns `Error::InvalidInput` for non-http(s) URLs
or header values with CR/LF, and `Error::Cancelled` on cancel.

### Security and logging

- TLS via rustls with the platform verifier (D9); no certificate prompts or overrides —
  any certificate problem is a silent failure.
- The response is untrusted: 1 MiB cap, strict JSON parsing, URL allow-list prefix,
  version strings parsed by `semver`, tag text never rendered raw (only the parsed
  version and the validated URL).
- HTTP client: chunked decoding with a 1 MiB cap on the sum and on each chunk-size line
  (≤ 16 hex digits), header section ≤ 64 KiB, no redirects followed (a `3xx` is a failure),
  no cookies, no auth headers.
- Privacy: only `api.github.com` is contacted, at most once per 7 days (24 h after a
  failure), with no identifiers besides the version in `User-Agent`. Documented in
  `docs/configuration.md` (T77) and the setting's help text.
- Logging: `debug!` only (`update check: up to date`, `update check failed: <error kind>`);
  `info!` once when a newer version is found (`update available: 1.3.0` — no personal data).

## Implementation steps

1. `net::http`: request writer, status/header parser, `Content-Length` and chunked bodies,
   TLS via `tokio-rustls` + platform verifier, timeout/cancel. Tests against an in-process
   HTTP server (plain) and a test-CA TLS server.
2. `update` module: `parse_tag`, `pick_release`, `is_due`, `notice`, state file
   read/write; unit tests.
3. `ReleaseSource` production impl and `run_check` with injected clock; `update-check`
   cargo feature.
4. UI: spawn `run_check` from `App` when enabled; status message, help overlay entry,
   `DismissUpdate` on `Ctrl-x u`; Settings entries (T68) for both update keys.
5. Splash component, init-done signal from startup, key-skip; snapshot tests.
6. Network-silence test for the binary.

## Acceptance criteria

- [ ] AC1 With the check due, exactly one request is made; within 7 days of a successful
  check none is made; 24 h after a failed check one is made again (fake clock).
- [ ] AC2 Each opt-out (setting off, `--no-update-check`, `COURIER_FTP_NO_UPDATE_CHECK=1`,
  feature off) results in zero calls to `ReleaseSource` (mock that panics) and no state
  file read or write.
- [ ] AC3 Version comparison table passes: `v1.2.3` vs `1.10.0` → newer; `1.3.0-rc.1` vs
  `1.2.9` with prereleases off → ignored, on → newer; running `1.3.0-rc.1` vs `1.3.0` →
  newer; `v1.2.3+build5` equals `1.2.3`; `latest`, `vfoo`, `1.2` → skipped.
- [ ] AC4 A newer release shows the status message once per start and the help overlay
  entry; `Ctrl-x u` dismisses it until a newer version appears.
- [ ] AC5 Untrusted response handling: body > 1 MiB, malformed JSON, foreign `html_url`,
  redirect status → no notice (or the safe default URL), no panic.
- [ ] AC6 A local-only run with the update check disabled makes no `AF_INET`/`AF_INET6`
  connection (strace test on Linux, sverb `network_silence` pattern).
- [ ] AC7 The splash is shown only with `interface.show_splash`, stays ≥ 1 s and until init
  is done, and any key dismisses it without reaching the app.
- [ ] AC8 Snapshot tests for the splash (full and narrow) and the help overlay with an
  update entry at 80×24 and 160×48.
- [ ] AC9 T00 gates pass (`fmt`, `clippy` both feature sets, `docs`, `test-local-only`,
  `test-os`, `deny` with no new license/advisory issues).

## Tests

### Unit tests
- `parse_tag_table` — `v1.2.3`, `V1.2.3`, `1.10.0`, `1.3.0-rc.1`, `1.2.3+build5`, invalid tags (AC3).
- `newer_version_table` — the comparisons of AC3 via `notice` (AC3).
- `pick_release_latest_object`, `pick_release_list_skips_drafts_and_prereleases`, `pick_release_list_with_prereleases` (AC3).
- `html_url_validation_falls_back_to_latest` (AC5).
- `is_due_matrix` — no state, 6 d 23 h, 7 d, future timestamp, error 23 h / 24 h ago (AC1).
- `dismissed_version_hidden_newer_shown` (AC4).
- `ctrl_x_u_dispatches_dismiss_update` — keymap `Ctrl-x u` → `DismissUpdate`, state file gets `dismissed` (AC4).
- `state_file_corrupt_is_default_and_rewritten` (AC1).
- `run_check_disabled_never_touches_source_or_disk` — `PanicSource` + read-only temp dir (AC2).
- `http_parses_content_length_and_chunked`, `http_rejects_oversized_body_and_chunk_line`, `http_rejects_crlf_in_headers`, `http_3xx_is_error`, `http_timeout_and_cancel` (AC5).
- `splash_min_duration_and_init_wait`, `splash_key_consumed` — paused time (AC7).

### Property / fuzz tests
- `prop_http_response_parser_never_panics` — arbitrary bytes into the response parser (AC5).
- `prop_pick_release_never_panics` — arbitrary JSON values (AC5).

### Snapshot tests
- `splash_80x24`, `splash_160x48`, `splash_narrow_40x10` (AC8).
- `help_overlay_update_available_80x24`, `help_overlay_update_available_160x48` (AC8).
- `status_bar_update_message_80` (AC4).

### Integration tests
- `update_check_against_local_https_server` — test CA, in-process server returning a releases JSON with an ETag; second run after 7 days sends `If-None-Match` and handles `304` (AC1).
- `update_check_through_http_connect_proxy` — in-process proxy from T07 tests (AC1).
- `app_shows_notice_from_stored_state` — state file with a newer version, check not due: notice shown without any request (AC4).
- `bin_env_opt_out_makes_no_request` — binary started with `COURIER_FTP_NO_UPDATE_CHECK=1` and a test hook pointing `RELEASES_API` at a local server (debug builds only, `COURIER_FTP_TEST_RELEASES_URL`); the server sees no request within 15 s (AC2).
- `network_silence_local_only_run` (Linux, `strace`; skipped with a note when unavailable): `PtyApp` with update check off and keyring off, unlock, browse local files for 12 s, quit; no `AF_INET`/`AF_INET6` in `connect`/`sendto`/`sendmsg` (AC6).

### End-to-end tests
Not applicable (no Docker fixture needed; the integration tests use in-process servers).

## Out of scope

- Downloading, verifying or installing updates; opening a browser.
- Release notes display beyond the version and URL.
- The "connect on start" part of FEATURES §10: covered by T61 (`interface.restore_tabs`)
  and T70 (`--site`, URL argument).

## Open questions

- **Default of `interface.check_updates`**: T05 sets it to `true` (FileZilla behaviour),
  while sverb's policy is that the client never phones home. Keep the default `true`, or
  make it `false` / ask on first run? (Current spec: `true`, with the opt-outs above.)
