# T58 — Quickconnect bar

**Phase:** F TUI · **Milestone:** M2 · **Depends on:** T03, T22, T52, T53, T69 · **Crate(s):** `courier-ftp` (`components/quickconnect.rs`, `backend_factory.rs`) · **Decisions:** D5, D6, D7 · **FEATURES.md:** §2 (quickconnect bar with history, reconnect to the last server)
**Related (integrates with, not blocking):** T14, T33, T61

## Goal

Connect to a server without creating a site: a one-line bar with host, user, password,
port, `[Connect]` and a history dropdown, reachable with `Ctrl-k`. The host field also
accepts URLs (`sftp://alice@host:2222/var/www`). This task also wires the binary's
`BackendFactory`, so it is the first place where a real SFTP connection is opened from
the UI.

## Context

- **Before:** T03 (`ConnectInfo` incl. `try_agent_first`, `BackendFactory::create(Arc<ConnectInfo>,
  BackendContext) -> Result<Box<dyn Backend>>`, `BackendContext`, `SessionHandle`), T22
  (`SftpBackend::new(Arc<ConnectInfo>, BackendContext, verifier, agent)`), T21 (`TrustVerifier`, `SwitchableHostKeyStore`, `SessionTrust`,
  `OpenSshKnownHosts`, via T22), T20 (`SystemAgent`), T52 (`TextInput` incl. masked,
  `Button`, `ListView`, `confirm`), T53 (remote file list pane: shows the listing after
  connecting, "Not connected" hint mentions `Ctrl-k`), T69 (the host-key and password
  prompts that every first SFTP connect needs), T50 (layout row for the bar, focus
  regions, `Mode::Input`), T02 (`ServerAddress::from_str`, `Protocol { Ftp, Sftp }`,
  `FtpEncryption { PlainOnly, ExplicitIfAvailable, RequireExplicit, RequireImplicit }`
  — part of `ServerAddress`, `LogonType`), T05 (`interface.show_quickconnect`,
  `interface.connect_target: ConnectTarget`).
- **After:** T14 adds the FTP/FTPS arm to `AppBackendFactory`. T33 supplies the
  vault-backed `QuickconnectHistory` and the recent-servers list (until then the history
  button is hidden and "reconnect" uses the in-memory last connection). T59 handles
  `Action::OpenSiteManagerWithDraft` ("Save as site"). T61 adds "open in new tab /
  replace current connection" to the busy-tab confirmation.

## Technical specification

### Types and APIs

```rust
// crates/courier-ftp/src/components/quickconnect.rs
pub struct QuickconnectBar {
    host: TextInput, user: TextInput, pass: TextInput /* masked */, port: TextInput /* digits, max 5 */,
    focus: QcFocus,
    history: Option<HistoryPopup>,
    error: Option<(QcField, String)>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QcFocus { Host, User, Pass, Port, Connect, History }
pub enum QcField { Host, User, Pass, Port }

impl QuickconnectBar {
    pub fn focus_host(&mut self);                         // ctrl-k (FocusQuickconnect)
    pub fn handle_key(&mut self, key: KeyEvent, ctx: &QcContext) -> Option<Action>;
    pub fn handle_paste(&mut self, text: &str);
    pub fn render(&mut self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme);
    /// Fill the fields from a history entry (no connect).
    pub fn fill(&mut self, entry: &QuickconnectEntry);
    /// Parse and validate the fields; on success the fields are rewritten with the
    /// parsed values (URL parts moved into user/pass/port).
    pub fn build(&mut self, settings: &Settings) -> Result<QuickconnectRequest, (QcField, String)>;
}

/// What the bar produces.
pub struct QuickconnectRequest {
    pub info: Arc<ConnectInfo>,            // T03; shared by every session to this server
    pub initial_remote_dir: Option<RemotePath>,
    pub entry: QuickconnectEntry,          // for history
}

/// A history row (no secret unless the vault stores passwords).
pub struct QuickconnectEntry {
    pub address: ServerAddress,            // protocol, FTP encryption, host, port, user (T02)
    pub password: Option<SecretString>,    // only with vault unlocked ∧ vault.store_passwords
    pub initial_dir: Option<RemotePath>,
}

/// History source; T33 provides the vault implementation.
pub trait QuickconnectHistory: Send + Sync {
    /// `None` → history unavailable (vault locked or not implemented): button hidden.
    fn entries(&self) -> Option<Vec<QuickconnectEntry>>;     // most recent first, ≤ 10
    fn record(&self, entry: &QuickconnectEntry);             // after a successful connect
    fn clear(&self);
}
pub struct NoHistory; // returns None; used until T33

/// Popup list under the host field.
struct HistoryPopup { list: ListView, entries: Vec<QuickconnectEntry> }

/// The same fields as a dialog (bar hidden, or terminal narrower than 64 columns).
pub struct QuickconnectDialog;

// crates/courier-ftp/src/backend_factory.rs
pub struct AppBackendFactory {
    settings: Arc<RwLock<Settings>>,
    host_keys: Arc<SwitchableHostKeyStore>,   // T21; T30 swaps in the vault store
    session_trust: Arc<SessionTrust>,         // T21
    openssh_known_hosts: Arc<OpenSshKnownHosts>,
    agent: Arc<dyn AgentConnector>,           // T20 SystemAgent
    next_session: AtomicU64,
}
impl BackendFactory for AppBackendFactory {
    /// `Protocol::Sftp` → `SftpBackend`; `Protocol::Ftp` (any `FtpEncryption`) →
    /// `UnsupportedBackend` until T14. Errors: `InvalidInput` from `ConnectInfo::validate`.
    fn create(&self, info: Arc<ConnectInfo>, ctx: BackendContext) -> Result<Box<dyn Backend>>;
}
/// Backend whose `connect` fails with `Error::Unsupported("FTP and FTPS are not available yet")`.
pub struct UnsupportedBackend;
```

Actions (names and default keys from T51's table):

| Action | Default key | Effect |
|---|---|---|
| `FocusQuickconnect` | `ctrl-k` (also `ctrl-x 1` = `FocusRegion1`) | focus Host field (or open the dialog) |
| `QuickconnectConnect(QuickconnectRequest)` | Enter in the bar | connect (internal, `#[serde(skip)]`) |
| `ReconnectLast` | `ctrl-x r` | reconnect (active tab's server, else the last server) |
| `SaveAsSite` | `ctrl-x S` | emit `OpenSiteManagerWithDraft(SiteDraft)` (handled by T59) |
| `ToggleQuickconnect` | `ctrl-x q` | show/hide the bar (`interface.show_quickconnect`, persisted) |

### Behaviour

**Layout.** The bar is T50's top row block (3 rows: border, fields, border; title
`Quickconnect`). Field widths from the inner width `I = W − 2`:
`rem = I − 54` (leading space 1, four labels 24, port 5, `[Connect]` 9, `[▾]` 3, gaps 12); `host = clamp(rem/2, 12, 48)`,
`user = clamp(rem/4, 6, 24)`, `pass = clamp(rem/4, 6, 24)`, `port = 5`; leftover
columns stay blank on the right. Inputs are drawn in the `input` style (focused field:
`input_focused` + cursor); text longer than the field scrolls horizontally to keep the
cursor visible, unfocused fields show the start. The password shows one `•` (ASCII
`*`) per character up to the field width.

80×24 (inner 78: host 12, user 6, pass 6):
```
┌ Quickconnect ────────────────────────────────────────────────────────────────┐
│ Host: example.com   User: alice   Pass: ••••••  Port: 22     [Connect]  [▾]  │
└──────────────────────────────────────────────────────────────────────────────┘
```
160×48 (inner 158: host 48, user 24, pass 24):
```
┌ Quickconnect ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Host: web01.example.com                                 User: alice                     Pass: ••••••••                  Port: 22     [Connect]  [▾]          │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
- `[▾]` is hidden (and its 5 columns go to the host field) when
  `QuickconnectHistory::entries()` is `None`.
- Terminal narrower than 64 columns: the bar shows only `│ Quickconnect: Ctrl-k │` and
  `ctrl-k` opens `QuickconnectDialog`. With `interface.show_quickconnect = false` the
  row is not drawn and `ctrl-k` opens the dialog too:

```
┌ Quickconnect ────────────────────────────────────────┐
│ Host:      [                                    ]    │
│ Username:  [                        ]                │
│ Password:  [                        ]                │
│ Port:      [     ]                                   │
│                                                      │
│      [ Connect ]   [ History ▾ ]   [ Cancel ]        │
└──────────────────────────────────────────────────────┘
```

**Keys** (bar focused → app `Mode::Input`, so single-letter global bindings don't fire):

| Key | Effect |
|---|---|
| `ctrl-k` (global) | focus Host, cursor at end |
| `Tab` / `Shift-Tab` | Host → User → Pass → Port → Connect → History → Host (History skipped when hidden) |
| `Enter` | in a field or on `[Connect]`: connect; on `[▾]`: open history |
| `↓` in a field | open history (if available) |
| `Esc` | leave the bar; focus returns to the pane focused before; field contents kept |
| text editing | T52 `TextInput` keys (Home/End, Ctrl-←/→, Ctrl-w, bracketed paste) |
| Port field | digits only; other keys ignored |

History popup (below the Host field, width `max(host field, 50)`, ≤ 10 rows + separator
+ `Clear history`):
```
┌ History ───────────────────────────────────────┐
│ sftp://alice@web01.example.com                 │
│ ftp://bob@ftp.example.org                      │
│ ftpes://deploy@files.example.net:2121          │
│ ────────────────────────────────────────────── │
│ Clear history                                  │
└────────────────────────────────────────────────┘
```
Rows are `ServerAddress` `Display` (never a password). `↑`/`↓`/`j`/`k` move, `Enter` on
an entry fills the fields and connects, `Enter` on `Clear history` asks
`confirm("Clear history", "Remove all 3 quickconnect entries?", default No)` then calls
`clear()`; `Esc` closes.

**Parsing** (`build`, on Connect only — not on every keystroke):

1. Trim all fields. Host empty → error on Host: "Enter a host name or URL".
2. Host field parsed with T02 `ServerAddress::from_str` (schemes `sftp`, `ftp`, `ftps`,
   `ftpes`, bare `host`, `host:port`, `[v6]:port`, percent-decoding) plus the path.
3. URL parts override the separate fields and are written back into them: user →
   User, `user:password@` → Pass (and removed from the Host text), port → Port, path →
   initial remote dir. The Host field keeps `scheme://host` (no user/password).
4. Protocol and port:

| Host field | Port field | Protocol / encryption | Port |
|---|---|---|---|
| `sftp://h` | any | `Sftp` | URL port, else field, else 22 |
| `ftp://h` | any | `Ftp` + `ExplicitIfAvailable` | URL, field, 21 |
| `ftpes://h` | any | `Ftp` + `RequireExplicit` | URL, field, 21 |
| `ftps://h` | any | `Ftp` + `RequireImplicit` | URL, field, 990 |
| `h` or `h:p` | `22` (or `p` = 22) | `Sftp` | 22 |
| `h` or `h:p` | `990` (or `p` = 990) | `Ftp` + `RequireImplicit` | 990 |
| `h` or `h:p` | other / empty | `Ftp` + `ExplicitIfAvailable` (FileZilla default) | `p`, field, 21 |

   A port outside 1–65535 → error on Port: "Port must be 1–65535".
5. Logon type (`LogonType`, T02):

| Protocol | User | Password | Logon |
|---|---|---|---|
| FTP/FTPS | empty | any | `Anonymous` |
| FTP/FTPS | set | set | `Normal` |
| FTP/FTPS | set | empty | `AskForPassword` |
| SFTP | empty | — | error on User: "Enter a user name for SFTP" |
| SFTP | set | set | `Normal { password: Some(..) }`, `ConnectInfo.try_agent_first = false` |
| SFTP | set | empty | `Interactive`, `ConnectInfo.try_agent_first = true` (agent keys, then keyboard-interactive, then a password prompt — T20 chain) |

   Values typed into the quickconnect bar count as approved on this device (T91 §8).
6. `ConnectInfo` gets the global defaults from `Settings` (charset Auto, server type
   Auto, timezone offset 0, transfer mode default, generic proxy per settings, no
   connection limit); `can_save` for prompts = false (not a saved site).

**Connect flow:**

1. `build()`; on error: field drawn in the `error` style, focus moves to it, the
   status bar shows the message for 5 s (T57); nothing else happens.
2. Current tab has a connected or connecting session → behaviour follows
   `interface.connect_target` (T05 `ConnectTarget`: `ask` default, `new_tab`, `replace`;
   T61 implements `new_tab`). Before T61, `ask` shows this confirm dialog (default
   button `Connect`):
```
┌ Replace connection? ─────────────────────────────────────────┐
│ This tab is connected to sftp://alice@web01.example.com.     │
│ Disconnect it and connect to ftp://bob@ftp.example.org?      │
│ Transfers already in the queue keep running.                 │
│                                                              │
│               [ Connect ]        [ Cancel ]                  │
└──────────────────────────────────────────────────────────────┘
```
   (T61 later adds `[ New tab ]`.) Cancel → nothing changes.
3. Old session (if any) is disconnected; a new `SessionHandle` (T03) is created from
   `AppBackendFactory::create(info.clone(), ctx)` (`info: Arc<ConnectInfo>`; no secret is
   copied); `connect` runs as a spawned task (T50 rule: the UI
   never awaits network I/O); the remote pane title shows the spinner; T69 prompts
   appear as foreground prompts.
4. Success → remote pane lists `initial_remote_dir` if given, else `home_dir()`; on
   `NotFound`/`PermissionDenied` for the initial dir, it falls back to the home dir and
   logs `Error: …`. The entry is recorded with `QuickconnectHistory::record` (password
   included only if vault unlocked ∧ `vault.store_passwords`) and the `Arc<ConnectInfo>`
   is kept in memory as `last_connection` (with the typed password as `SecretString`)
   for `ReconnectLast`.
   Focus moves to the remote file list.
5. Failure → the error is in the message log (T55) and the status bar; fields keep
   their values; focus stays in the bar.
6. The password field keeps its value after connecting (FileZilla behaviour); it is
   zeroized when the field is cleared or the app exits.

**Reconnect** (`ReconnectLast`): uses T33's recent server #0 when available, else
`last_connection`; nothing → status message "No previous connection". Same busy-tab
confirmation as Connect.

**Save as site** (`SaveAsSite`, `ctrl-x S`): builds `SiteDraft` from the current fields
(including the typed password as `SecretString`, `save_password` default =
`vault.store_passwords`) and emits `Action::OpenSiteManagerWithDraft(draft)`; T59
handles it. Vault locked → T60's unlock prompt first (T59 rule).

**Backend factory:** `create` validates `info`, then matches `info.address.protocol`:
`Protocol::Sftp` → `SftpBackend::new(info, ctx, verifier, Some(agent))` with
`verifier = TrustVerifier::new(host_keys, session_trust, openssh_known_hosts)`
(`OpenSshKnownHosts::disabled()` when `sftp.use_openssh_known_hosts` is false);
`Protocol::Ftp` → `UnsupportedBackend` until T14 (which dispatches on
`address.encryption`). Callers allocate `ctx.session` from one process-wide counter, so
session ids are unique per process.

### Data formats and configuration

| Key | Type | Default | Use |
|---|---|---|---|
| `interface.show_quickconnect` | bool | `true` | T05; draw the bar (toggled by `ToggleQuickconnect`, persisted with `save_user`) |
| `interface.connect_target` | `ask` \| `new_tab` \| `replace` | `ask` | T05 `ConnectTarget`; busy-tab behaviour (T61) |
| `vault.store_passwords` | bool | `true` (T30) | password in history / save-as-site default |
| `sftp.use_openssh_known_hosts` | bool | `true` (T21) | factory verifier |

Keybinding config (`crates/courier-ftp/config/config.json`, T51 format, mode `Normal`):
`"ctrl-k": "FocusQuickconnect"`, `"ctrl-x r": "ReconnectLast"`, `"ctrl-x S": "SaveAsSite"`,
`"ctrl-x q": "ToggleQuickconnect"`.

### Errors

| Situation | What the user sees |
|---|---|
| Empty host / bad port / SFTP without user / unparsable URL | field in error style + status message ("Enter a host name or URL", "Port must be 1–65535", "Enter a user name for SFTP", "Not a valid address: <reason from T02>") |
| FTP/FTPS before T14 | `Error::Unsupported` → log + status "FTP and FTPS are not available yet" |
| Connection errors (T20/T21/T22: `Connection`, `Timeout`, `Auth`, `HostKey`, `Cancelled`) | message log `Error:` line + status bar message; `Cancelled` is shown as a Status line only |
| Initial dir missing | log `Error: /path: No such file`, home dir shown |

### Security and logging

- The password is a masked `TextInput` holding a `SecretString`; it is never rendered,
  never part of `ServerAddress` `Display`, never in history unless the vault stores
  passwords, never in `tracing` at any level, and `Debug` prints `[REDACTED]`.
- A password typed inside a URL is moved to the Pass field before anything else
  happens and removed from the Host text (so it is not shown, and not in history rows).
- `tracing` at info logs only `SessionId` and the outcome of a connect; host and user
  only at debug (T91 §4). The session log (T55) shows host and user, as FileZilla does.
- History rows contain host names; they live only in the vault (T33) and are hidden
  while it is locked.

## Implementation steps

1. `AppBackendFactory` + `UnsupportedBackend`; construct shared trust objects in `App`;
   unit test with a fake `SftpBackend` constructor seam.
2. `QuickconnectBar` fields, layout rules and rendering (snapshots), `ctrl-k`, focus/keys.
3. `build()` parsing/validation with table tests.
4. Connect flow: busy-tab confirm, spawned connect, pane update, error display.
5. `QuickconnectHistory` trait, `NoHistory`, history popup (tested with a fake provider).
6. `ReconnectLast`, `SaveAsSite`, `ToggleQuickconnect`, narrow/dialog mode;
   `interface.show_quickconnect` setting.
7. e2e PTY test against the `sshd` fixture.

## Acceptance criteria

- [ ] AC1 Every row of the protocol/port table and the logon table produces the expected `ConnectInfo` (protocol, encryption, host, port, user, logon, `try_agent_first`) and initial dir; fields are rewritten as specified (e.g. `sftp://bob:s3cret@h:2222/www` → Host `sftp://h`, User `bob`, Pass masked, Port `2222`, dir `/www`).
- [ ] AC2 Validation errors (empty host, port 0 / 70000 / non-digit, SFTP without user, malformed URL) show the error style and message and never start a connection.
- [ ] AC3 Snapshot tests at 80×24 and 160×48: empty bar, filled bar unfocused, Host focused with cursor, Pass focused (masked), history open, history hidden (`NoHistory`), validation error, busy-tab confirm; plus 60×20 hint mode and the dialog variant.
- [ ] AC4 Field widths follow the formula at widths 64, 80, 120, 160, 200 (unit test on the layout function).
- [ ] AC5 With a fake history provider, selecting an entry fills the fields and starts a connect; "Clear history" asks and then calls `clear()`; with `NoHistory` the `[▾]` button is absent.
- [ ] AC6 Busy tab: connecting while connected shows the confirm; Cancel keeps the old session; Connect disconnects it first.
- [ ] AC7 Connecting through `AppBackendFactory` to T22's `SftpTestServer` (unknown host key answered by a scripted prompt responder) lists the home directory in the remote pane; FTP URLs return the "not available yet" error until T14.
- [ ] AC8 The typed password never appears in rendered buffers, `Debug` output, history rows, `ServerAddress` displays or logs (canary test over snapshots, trace log and session log).
- [ ] AC9 `ReconnectLast` reconnects with the same `ConnectInfo` (incl. the typed password) without asking for the password again; with no previous connection it shows "No previous connection".
- [ ] AC10 `SaveAsSite` (`ctrl-x S`) emits `OpenSiteManagerWithDraft` with host, port, protocol, user and the password.
- [ ] AC11 `ToggleQuickconnect` (`ctrl-x q`) hides/shows the bar and persists `interface.show_quickconnect`; with the bar hidden `ctrl-k` opens the dialog.
- [ ] AC12 e2e: PTY run, `ctrl-k`, type `sftp://test@<sshd>:<port>`, password `test`, Enter, trust the host key → the remote pane shows the home directory listing.
- [ ] AC13 T00 gates pass.

## Tests

### Unit tests
- `quickconnect::tests::protocol_port_table` — AC1.
- `quickconnect::tests::logon_table` — AC1.
- `quickconnect::tests::url_parts_rewrite_fields_and_strip_password` — AC1, AC8.
- `quickconnect::tests::ipv6_literal_with_port` — AC1.
- `quickconnect::tests::validation_errors` — AC2.
- `quickconnect::tests::field_widths_formula` — AC4.
- `quickconnect::tests::tab_order_skips_hidden_history` — keys.
- `quickconnect::tests::esc_restores_previous_focus` — keys.
- `quickconnect::tests::port_accepts_digits_only` — keys.
- `backend_factory::tests::sftp_creates_sftp_backend_ftp_unsupported` — `create(Arc<ConnectInfo>, ctx)` for `Protocol::Sftp` and for `Protocol::Ftp` with each `FtpEncryption` — AC7.
- `quickconnect::tests::default_keys_reach_actions` — `AppHarness`: `ctrl-x r`, `ctrl-x S`, `ctrl-x q`, `ctrl-k` produce `ReconnectLast`, `SaveAsSite`, `ToggleQuickconnect`, `FocusQuickconnect` — AC9, AC10, AC11.
- `quickconnect::tests::debug_redacts_password` — AC8.

### Property / fuzz tests
- `quickconnect::props::build_never_panics` (proptest over arbitrary host/user/port strings) — AC2.

### Snapshot tests
`crates/courier-ftp/tests/snapshots/quickconnect__*.snap` (ratatui `TestBackend` +
`insta`, full main screen at 80×24 and 160×48): `empty`, `filled_unfocused`,
`host_focused`, `pass_focused_masked`, `history_open`, `history_hidden`,
`port_error`, `busy_confirm`; plus `hint_60x20` and `dialog_80x24` — AC3, AC8.

### Integration tests
`crates/courier-ftp/tests/quickconnect_flow.rs` (App driven by synthetic keys, T22
`SftpTestServer`, scripted prompt answers):
- `connect_lists_home_dir` — AC7.
- `history_select_connects` (fake provider) — AC5.
- `busy_tab_confirm_cancel_and_connect` — AC6.
- `reconnect_last_reuses_password` — AC9.
- `save_as_site_emits_draft` — AC10.
- `toggle_bar_persists_setting` — AC11.
- `no_password_in_logs_or_buffers` (canary) — AC8.

### End-to-end tests
`crates/courier-ftp-e2e/tests/quickconnect.rs`, `#[ignore]`, `require_docker!`, T76
`PtyApp` + `sshd` `password` profile:
- `pty_quickconnect_sftp_password` — AC12.

## Out of scope

- FTP/FTPS backends (T14 adds the factory arm); history storage and recent servers
  (T33); the Site Manager dialog (T59); tab choice on connect (T61); CLI URL start (T70).

## Open questions

1. **SFTP without a user name:** this task requires a user name (error). Should it
   default to the local OS user name like `ssh` does?

(Resolved by the coordinator: the factory takes `Arc<ConnectInfo>` and `BackendContext`,
so no secret-copying `duplicate()` is needed. T69 stays in **Depends on** because no SFTP
connection can complete without the host-key prompt UI; T69 is earlier in M2.)
