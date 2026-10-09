# T57 — Status bar

**Phase:** F TUI · **Milestone:** M1 · **Depends on:** T50, T52 · **Crate(s):** `courier-ftp` (`components/status_bar.rs`, `components/server_info.rs`, `ui/symbols.rs`) · **Decisions:** D6, D7 · **FEATURES.md:** §3 (status bar: queue size, speed-limit toggle, transfer type, encryption lock/info), §6 (speed limit toggle), §8 (filter indicator)
**Related (integrates with, not blocking):** T44, T66, T69

## Goal

A one-line bottom bar that always tells the user how secure the current connection
is, whether limits, filters, synchronized browsing or comparison are active, what
the queue is doing and which keys are pending — and that degrades predictably on
narrow terminals. It also provides the server information dialog, the transfer
type and speed-limit toggles and transient messages. It adds the status-bar glyphs to
T50's shared `Symbols` (T50 owns `Symbols`, `TermEnv`, `UnicodeSymbols` and the
`auto` detection).

## Context

**Before this task:** T50 provides the main screen (the status bar is its last row),
`Theme` with `NO_COLOR` handling, focus, the modal stack, `ui::text::sanitize` and
`ui::symbols::{Symbols, TermEnv, UnicodeSymbols}` with `Symbols::resolve`. T03 provides
`Backend::security_info() -> SessionSecurityInfo` (also on `SessionHandle`). T69 provides
`PromptQueue::badge(unicode) -> Option<String>`. T51 provides the
keymap, the pending-key sequence (showcmd) and key-name rendering. T52 provides
dialogs (`TabbedForm`-free plain dialog, buttons, scrollable content). In M1 there
is no remote protocol, queue or vault yet: every segment is fed from an optional
data source and is hidden while its source does not exist.

**Later tasks feed it:** T12/T20 (connection security details), T40/T41 (queue
summary), T44 (effective speed limits), T47/T53/T67 (filters active), T60 (vault
locked), T66 (sync browsing / comparison), T69 (pending prompts badge), T90 (sync
status).

## Technical specification

### Types and APIs

```rust
// crates/courier-ftp/src/ui/symbols.rs — owned by T50. This task only adds these
// status-bar fields to T50's `Symbols` (both the Unicode and the ASCII set); it defines
// no `UnicodeSymbols`, `TermEnv` or selection logic of its own.
pub struct Symbols {
    // … T50 base set and fields added by other tasks …
    pub lock: &'static str,          // "🔒"  | "[TLS]" style handled per segment
    pub unlock: &'static str,        // "🔓"
    pub vault_locked: &'static str,  // "🔐"
    pub sep: &'static str,           // " │ " | " | "
    pub speed: &'static str,         // "⇅"  | "lim"
    pub filter: &'static str,        // "⚑"  | "[F]"
    pub sync: &'static str,          // "⇄"  | "<>"
    pub compare: &'static str,       // "≠"  | "!="
    pub sync_status: &'static str,   // "⟳"  | "sync"
    pub dash: &'static str,          // "–"  | "-"
    pub rate_down: &'static str, pub rate_up: &'static str, // "↓" "↑" | "v" "^"
}

// crates/courier-ftp/src/components/status_bar.rs
/// Everything the bar shows, rebuilt by `App` before each draw (cheap: no I/O,
/// borrowed strings). `None` = the source does not exist yet → segment hidden.
#[derive(Debug, Default)]
pub struct StatusInfo<'a> {
    pub security: SecurityIndicator,
    pub vault: Option<VaultIndicator>,          // T60
    pub prompts_badge: Option<String>,          // T69 `PromptQueue::badge(sym.unicode)`
    pub transfer_type: Option<TransferTypeChoice>, // T05 file_types.default_type
    pub speed: Option<SpeedLimitIndicator>,     // T44
    pub filters_active: bool,                   // T47/T53
    pub sync_browsing: bool, pub comparison: bool, // T66
    pub sync: Option<SyncIndicator>,            // T90
    pub queue: Option<QueueSummary>,            // T40/T41
    pub pending_keys: &'a str,                  // T51 showcmd
    pub message: Option<&'a TransientMessage>,
    pub hints: &'a [KeyHint],                   // from the keymap of the focused mode
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SecurityIndicator {
    #[default] NotConnected,
    Local,                                  // tab without remote session (M1)
    Plain,                                  // FTP without TLS (incl. ExplicitIfAvailable that fell back)
    Tls { version: String },                // "TLS 1.3"
    Ssh,
    Connecting,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultIndicator { Locked, NoVault }   // nothing shown when unlocked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedLimitIndicator { pub enabled: bool, pub down_kib: u32, pub up_kib: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncIndicator { Synced, Syncing, Offline { pending: u32 }, Error, LoginNeeded }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueSummary { pub files: u64, pub bytes: u64, pub down_bps: u64, pub up_bps: u64, pub eta_secs: Option<u64> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHint { pub keys: String, pub label: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransientMessage { pub text: String, pub level: MessageLevel, pub until: Instant }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageLevel { Info, Success, Warning, Error }

/// A segment with its long and short form, after formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment { pub kind: SegmentKind, pub long: String, pub short: String, pub style: StyleKey }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SegmentKind { Security, Vault, Prompts, TransferType, SpeedLimit, Filters,
                       SyncCompare, SyncStatus, Queue, PendingKeys, Message, Hints }

/// Pure layout: which form of which segment is drawn at `width`.
pub fn fit_segments(width: u16, segments: &[Segment], hints: &[KeyHint], sym: &Symbols) -> FittedBar;

pub struct StatusBar { message: Option<TransientMessage> /* … */ }
impl Component for StatusBar { /* update: StatusMessage, Tick; draw */ }

// crates/courier-ftp/src/components/server_info.rs
/// View model of the server information dialog (sanitised strings only).
#[derive(Debug, Clone, Default)]
pub struct ServerInfoView {
    pub title: String,                 // "Server information · Tab 1 · <site>"
    pub rows: Vec<(String, String)>,   // label, value; empty label = blank line
    pub has_details: bool,             // TLS: certificate chain details (T69 renderer)
}
impl ServerInfoView {
    pub fn from_session(info: &SessionSecurityInfo, addr: &ServerAddress, tab_label: &str) -> Self;
    pub fn not_connected() -> Self;
}
```

`SessionSecurityInfo` (T03) comes from `SessionHandle::security_info()` /
`Backend::security_info()` of the tab's browsing session: `encrypted`, `summary`
(`"TLS 1.3"`, `"SSH"`, `"plain"`, `"local"`), `peer_addr`, `server_software`, `tls:
Option<TlsSessionInfo>` (T04 type: version, cipher suite, key exchange, data-channel
protection, certificate chain, host-name match, trust source), `host_key:
Option<HostKeyInfo>` (T04 type: key type and bits, SHA-256 fingerprint, trust state) and
`details` (label/value rows: FEAT summary, SSH kex/cipher/MAC/compression, auth
method). The dialog rows are built only from these fields plus `ServerAddress`; fields
that are `None` are omitted. The security segment is derived from `encrypted` and
`summary` (`encrypted == false` with an FTP address → `Plain`).

Actions (T51 names and keys): `ServerInfo` (`ctrl-x i`), `CycleTransferType`
(`ctrl-x a`), `ToggleSpeedLimit` (`ctrl-x k`), and the non-key `Action::StatusMessage(TransientMessage)`
any component may send. Handling `ToggleSpeedLimit` sends T41's
`EngineCommand::SettingsChanged` after updating `Settings`.

### Behaviour

#### Segments (left group, then right group)

| Kind | Long form (Unicode) | Short form | ASCII long / short | Priority | Shown when |
|---|---|---|---|---|---|
| Security | `🔒 TLS 1.3`, `🔒 SSH`, `🔓 plain FTP`, `– not connected`, `local`, `◌ connecting` | `🔒TLS`, `🔒SSH`, `🔓FTP`, `–`, `local`, `◌` | `[TLS 1.3]` / `[TLS]`, `[SSH]`, `[PLAIN FTP]` / `[FTP!]`, `[not connected]` / `[-]` | 8 | always |
| Vault | `🔐 vault locked`, `no vault` | `🔐`, `novault` | `[vault locked]` / `[L]`, `[no vault]` / `[NV]` | 10 | vault locked or "continue without vault" (T60) |
| Prompts | `PromptQueue::badge` text: `⚠ 2 prompts` (ASCII `! 2 prompts`) | `⚠2` / `!2` | `! 2 prompts` / `!2` | 10 | `prompts_badge` is `Some` (T69) |
| Transfer type | `Type: Auto` / `Binary` / `ASCII` | `Auto` … | same | 2 | source exists |
| Speed limit | `⇅ off`, `⇅ ↓500 KiB/s ↑100 KiB/s` (`↓∞` for 0) | `⇅off`, `⇅↓500K↑100K` | `lim off`, `lim D:500K U:100K` / `L:off`, `L:500K/100K` | 6 | source exists |
| Filters | `⚑ filters` | `⚑` | `[filters]` / `[F]` | 5 | any side filtered |
| Sync/compare | `⇄ sync`, `≠ compare`, `⇄ sync ≠ compare` | `⇄`, `≠`, `⇄≠` | `<> sync != compare` / `<>!=` | 4 | either on |
| Sync status | `⟳ synced`, `⟳ syncing`, `⟳ offline (3)`, `⟳ error`, `⟳ login needed` | `⟳`, `⟳3`, `⟳!` | `sync ok`… / `S` | 3 | T90 |
| Queue | `Queue: 12 files, 30.2 MiB, ↓1.20 MiB/s, ~00:00:25` (rates only when > 0, ETA when known), `Queue: empty` | `Q: 12, 30.2 MiB`, `Q: 0` | `v`/`^` for arrows | 7 | source exists |
| Pending keys | `g`, `s`, `Ctrl-x` (T51 `pending_display()`, modifiers title-cased for display) | same | same | 10 | sequence pending |
| Message | text (prefixed `Error: ` for errors) | text cut with `…` | same | 9 | message active |
| Hints | `F1 help  F5 copy  F6 move  F7 mkdir  F8 delete  F10 quit` | dropped one by one from the right | same | 1 | no message active |

Left group: Security, Vault, Prompts, Transfer type, Speed limit, Filters,
Sync/compare, Sync status, Queue — joined with `Symbols::sep`. Right group (right
aligned): Pending keys, then Message or Hints. One space margin at both ends, at least
two spaces between the groups.

#### Fitting algorithm (`fit_segments`, pure, deterministic)

1. Start with every visible segment in its long form and all hints.
2. While too wide: remove the rightmost hint.
3. For priority p = 1, 2, …, 8 (ascending): while too wide, switch all segments of
   priority p to their short form.
4. For priority p = 1, 2, …, 8: while too wide, drop all segments of priority p.
   Priority ≥ 9 segments (Message, Pending keys, Vault, Prompts) are never dropped.
5. Re-expand: for segments in descending priority, switch a short form back to long
   when the bar still fits.
6. If still too wide, cut the Message with the ellipsis; then cut the left group at the
   right edge. Never panic for any width ≥ 0.

Hints are generated from the effective keymap of the focused mode (T51), listing these
actions in this order when bound: `Help`, `Transfer`, `Move`, `Mkdir`, `Delete`, `Quit`.
Keys shown with T51's display names (`f5`, `ctrl-q`, rendered `F5`, `Ctrl-q` in hints).

#### Mock-ups

Row 24 of an 80×24 screen and row 48 of a 160×48 screen (the bar is always 1 row).
State A: FTPS connection, limits on, filters, sync + compare, queue running.

160 columns:
```
 🔒 TLS 1.3 │ Type: Auto │ ⇅ ↓500 KiB/s ↑100 KiB/s │ ⚑ filters │ ⇄ sync ≠ compare │ Queue: 12 files, 30.2 MiB, ↓1.20 MiB/s, ~00:00:25          F1 help  F5 copy 
```
80 columns:
```
 🔒 TLS 1.3 │ Auto │ ⇅ ↓500 KiB/s ↑100 KiB/s │ ⚑ filters │ ⇄≠ │ Q: 12, 30.2 MiB 
```
60 and 40 columns (single-pane mode below 80×24, T50):
```
 🔒 TLS 1.3 │ Auto │ ⇅↓500K↑100K │ ⚑ │ ⇄≠ │ Q: 12, 30.2 MiB 
 🔒TLS │ ⇅↓500K↑100K │ Q: 12, 30.2 MiB  
```
State A in ASCII mode (160, 80, 40):
```
 [TLS 1.3] | Type: Auto | lim D:500K U:100K | [filters] | <> sync != compare | Queue: 12 files, 30.2 MiB, v1.20 MiB/s, ~00:00:25      F1 help  F5 copy  F6 move 
 [TLS 1.3] | Auto | lim D:500K U:100K | [filters] | <>!= | Q: 12, 30.2 MiB      
 [TLS] | L:500K/100K | Q: 12, 30.2 MiB  
```
State B: plain FTP (fell back from "explicit TLS if available"), limits off, empty
queue, `ctrl-x` pending (160, 80, 40):
```
 🔓 plain FTP │ Type: Binary │ ⇅ off │ Queue: empty                                           Ctrl-x │ F1 help  F5 copy  F6 move  F7 mkdir  F8 delete  F10 quit 
 🔓 plain FTP │ Type: Binary │ ⇅ off │ Queue: empty   Ctrl-x │ F1 help  F5 copy 
 🔓FTP │ Binary │ ⇅ off │ Q: 0   Ctrl-x 
```
State C: vault locked, 2 prompts waiting, transient message (160, 80, 40):
```
 – not connected │ 🔐 vault locked │ ⚠ 2 prompts │ Type: Auto │ ⇅ off │ Queue: 3 files, 1.21 GiB, ↓8.40 MiB/s, ~00:02:27                Copied URL to clipboard 
 – │ 🔐 │ ⚠ 2 prompts │ Auto │ ⇅ off │ Q: 3, 1.21 GiB   Copied URL to clipboard 
 – │ 🔐 │ ⚠2    Copied URL to clipboard 
```

#### Styles and colour rules

| Element | Style key | Colour default | `NO_COLOR` |
|---|---|---|---|
| bar background | `status.bar` | dark grey bg | reverse off, plain |
| TLS/SSH | `status.secure` | green | plain (text says it) |
| plain FTP | `status.insecure` | black on yellow | reverse + bold |
| not connected / local | `status.dim` | dark grey | dim |
| vault locked, prompts | `status.attention` | black on cyan | reverse |
| active toggles (filters, sync, compare, limits on) | `status.active` | yellow | bold |
| message info / success / warning / error | `status.msg_info`, `…_ok`, `…_warn`, `…_error` | default / green / yellow / red bold | plain / plain / bold / bold + `Error:` prefix |
| hints keys / labels | `status.hint_key`, `status.hint` | bold / dim | bold / dim |

No state is shown by colour only: every segment carries text.

#### Transient messages

- `Action::StatusMessage` replaces the current message. Duration: Info/Success 3 s,
  Warning 5 s, Error 8 s, measured from arrival; `Tick` (T50, 4 Hz default) removes
  expired messages. Any key press removes an Info/Success message older than 1 s.
- Messages are sanitised (`ui::text::sanitize`) and limited to 200 characters.

#### Toggles

- `CycleTransferType`: `Auto → Binary → ASCII → Auto` on `file_types.default_type`;
  saved with `Settings::save_user`; applies to transfers queued afterwards; message
  `Transfer type: Binary`.
- `ToggleSpeedLimit`: flips `transfers.speed_limit_enabled`, saves, sends
  `SettingsChanged` to the engine (T44 applies it within one chunk). If both limits are 0,
  the toggle is refused with Warning `No speed limits set (Settings → Transfers)`.
  Before T44 exists the action shows `Speed limits are not available yet`.

#### Server information dialog

`ctrl-x i` (`ServerInfo`) opens a T52 dialog for the focused tab. Size: width `clamp(W − 4, 40, 100)`, height
content + 2 capped at `H − 2` (content scrolls with `j`/`k`), centred. Buttons
`[ Details ]` (TLS only: opens the certificate chain view built by T69) and `[ Close ]`
(`Esc`, `Enter`). Not connected: the dialog says `Not connected to any server.`
All values are sanitised; fingerprints are wrapped at byte boundaries.

80×24 (FTPS; dialog 76×21 at x=2, y=1):
```
┌ Server information · Tab 1 ──────────────────────────────────────────────┐
│ Protocol        FTP over TLS (explicit, required)                        │
│ Server          ftp.example.com:21 (203.0.113.5)                         │
│ Software        220 (vsFTPd 3.0.5)                                       │
│ System          UNIX Type: L8                                            │
│ Features        MLSD MLST SIZE MDTM REST STREAM UTF8 EPSV                │
│                                                                          │
│ TLS version     TLS 1.3                                                  │
│ Cipher suite    TLS_AES_256_GCM_SHA384                                   │
│ Key exchange    X25519                                                   │
│ Data channel    TLS, session resumed                                     │
│                                                                          │
│ Subject         CN=ftp.example.com                                       │
│ Issuer          CN=R11, O=Let's Encrypt, C=US                            │
│ Valid           2026-08-01 → 2026-10-30 (21 days left)                   │
│ Host name       ✓ matches                                                │
│ SHA-256         4F:A2:19:03:7C:DE:55:1B:0A:93:E2:47:8D:C1:6B:2F:90:3E:A5 │
│                 :7D:12:CC:48:B6:E9:01:5A:F3:27:8E:64:9C                  │
│ Trust           system trust roots                                       │
│                                                                          │
│ [ Details ]  [ Close ]                                                   │
```
160×48 (SFTP; dialog 100×14 at x=30, y=17):
```

┌ Server information · Tab 2 · web01 ──────────────────────────────────────────────────────────────┐
│ Protocol        SFTP (SSH-2, SFTP version 3)                                                     │
│ Server          web01.example.com:22 (198.51.100.7)                                              │
│ Software        SSH-2.0-OpenSSH_9.6                                                              │
│                                                                                                  │
│ Key exchange    curve25519-sha256                                                                │
│ Host key        ssh-ed25519 256                                                                  │
│ Fingerprint     SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM                               │
│ Host key trust  trusted (stored 2026-09-01)                                                      │
│ Cipher          chacha20-poly1305@openssh.com                                                    │
│ MAC             implicit (AEAD cipher)                                                           │
│ Compression     none                                                                             │
│                                                                                                  │
```

#### Glyph set selection

`interface.unicode_symbols` (`auto` | `always` | `never`) is resolved by T50's
`Symbols::resolve(setting, &TermEnv)`; the bar uses whichever set T50 selected and
never inspects the environment itself.

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `interface.unicode_symbols` | `auto` \| `always` \| `never` | `auto` | T05; resolved by T50 |
| `file_types.default_type` | `auto` \| `ascii` \| `binary` | `auto` | T05, toggled here |
| `transfers.speed_limit_enabled` | bool | `false` | T05, toggled here |
| `transfers.download_limit_kib` / `upload_limit_kib` | u32 | 0 | T05, displayed |

Style keys listed above live in the `styles` config (T50 `Theme`).

### Errors

`Settings::save_user` failure after a toggle: the in-memory value still changes;
Error message `Could not save settings: <io error>`; logged at `warn` without paths.
No other fallible operations; rendering never fails.

### Security and logging

- The plain-FTP warning must be impossible to miss: distinct style plus the words
  `plain FTP`, never only a colour (T91 mitigation "plain FTP warnings", with T12).
- `ExplicitIfAvailable` FTP that ended without TLS is shown as `plain FTP`, never as
  secure: the indicator is driven by the negotiated state, not the configured mode.
- The server info dialog shows host names and IPs (user-facing, allowed); nothing from
  it is written to `tracing` at `info`+.
- The bar never shows passwords; messages from other components are sanitised.

## Implementation steps

1. Add the status-bar glyph fields to T50's `Symbols` (Unicode and ASCII sets) with a test that every new ASCII glyph is ASCII.
2. Segment formatting functions (one per kind) + `fit_segments` with unit/property tests.
3. `StatusBar` component, `StatusInfo` assembly in `App` (security = `NotConnected`/`Local` in M1), styles, snapshot tests.
4. Transient messages (`Action::StatusMessage`, expiry on `Tick`).
5. Toggles `CycleTransferType` (`ctrl-x a`), `ToggleSpeedLimit` (`ctrl-x k`) (engine message once T41/T44 exist).
6. Server info dialog (`ctrl-x i`) with `ServerInfoView` built from `security_info()`; prompts badge from `PromptQueue::badge()`.

## Acceptance criteria

- [ ] AC1 Snapshot tests of the bar at widths 40, 60, 80, 120, 160 for states A, B, C (Unicode and ASCII), and full-screen snapshots at 80×24 and 160×48 including the bar.
- [ ] AC2 `fit_segments` output equals the mock-ups above for the given states and widths, never exceeds the width, and never drops Vault, Prompts, Pending keys or Message.
- [ ] AC3 A plain FTP session (including `ExplicitIfAvailable` without TLS) renders `plain FTP` with style `status.insecure`; under `NO_COLOR` it is reverse + bold.
- [ ] AC4 Indicators update within one frame of the state change (filters toggled, sync on, vault lock, speed limit toggle, queue event).
- [ ] AC5 Transient messages expire after 3/5/8 s (paused-time test) and Info messages clear on the next key after 1 s.
- [ ] AC6 `CycleTransferType` and `ToggleSpeedLimit` change the settings, persist them, and the toggle is refused when both limits are 0.
- [ ] AC7 Server info dialog shows the correct rows for FTP, FTPS and SFTP sessions (rows filled from `SessionSecurityInfo` fixtures) and the not-connected text.
- [ ] AC8 The status-bar glyphs exist in both T50 sets; with `interface.unicode_symbols = never` the bar uses only the ASCII forms; `ctrl-x i`, `ctrl-x a` and `ctrl-x k` reach `ServerInfo`, `CycleTransferType` and `ToggleSpeedLimit` with the default keymap.
- [ ] AC9 In ASCII mode every cell of the bar and dialog is ASCII (test iterates the buffer).
- [ ] AC10 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `status_glyphs_ascii_set_is_ascii` (AC8, AC9).
- `status_bar_default_keys` — `AppHarness`: `ctrl-x i` opens the server info dialog, `ctrl-x a` cycles the type, `ctrl-x k` toggles limits (AC6, AC8).
- `security_segment_from_security_info` — `SessionSecurityInfo { encrypted: false, summary: "plain" }` on an FTP address → `🔓 plain FTP`; `encrypted: true, summary: "TLS 1.3"` → `🔒 TLS 1.3` (AC3).
- `prompts_segment_uses_badge_text` — `Some("⚠ 2 prompts")` shown verbatim; `None` hides the segment.
- `fit_drops_hints_first_then_shortens_by_priority` (AC2).
- `fit_never_drops_priority_nine_or_more` (AC2).
- `fit_reexpands_highest_priority_first` (AC2).
- `fit_matches_mockups_state_a_b_c` — exact strings from this file (AC2).
- `security_indicator_plain_when_tls_not_negotiated` (AC3).
- `speed_segment_formats_zero_as_unlimited`.
- `queue_segment_omits_zero_rates_and_unknown_eta`.
- `message_expiry_by_level` (paused time, AC5), `info_message_cleared_by_key_after_one_second` (AC5).
- `cycle_transfer_type_order_and_persist`, `toggle_speed_limit_refused_without_limits` (AC6).
- `server_info_rows_ftp_ftps_sftp`, `server_info_not_connected` (AC7).

### Property / fuzz tests
- `prop_fit_width_never_exceeded` — random segment sets, widths 0–300 (AC2).
- `prop_ascii_mode_renders_only_ascii` (AC9).

### Snapshot tests
`TestBackend` + `insta`: `status_bar_state_{a,b,c}_{40,60,80,120,160}` (Unicode),
`status_bar_state_a_ascii_{40,80,160}`, `server_info_ftps_80x24`, `server_info_sftp_160x48`,
`server_info_not_connected_80x24`, plus `NO_COLOR` style assertions for the insecure and
attention styles (AC1, AC3, AC7).

### Integration tests
- `indicators_follow_app_state` — drive `App` with actions (filters toggled, `CoreEvent::Connected`, queue progress events from a mock engine) and assert the next frame's bar (AC4).

### End-to-end tests
- T76 PtyApp scenario `plain_ftp_warning_visible` against the `vsftpd-plain` profile asserts `plain FTP` in the last row; `tls_indicator_after_explicit_tls` against `vsftpd-explicit-tls` asserts `TLS 1.`.

## Out of scope

- Mouse clicks on segments (D7).
- The certificate details view itself (T69) and the sync panel (T90).
- Sound or desktop notifications (T45, D8).

## Open questions

None. (Resolved by the coordinator: `Backend::security_info()` provides the data; the
keys are `ctrl-x i`, `ctrl-x a`, `ctrl-x k`; T50 owns `Symbols`.)
