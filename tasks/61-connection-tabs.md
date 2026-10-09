# T61 — Connection tabs

**Phase:** F TUI · **Milestone:** M5 · **Depends on:** T50, T53, T58, T59 · **Crate(s):** `courier-ftp` (`tabs.rs`, `components/tab_bar.rs`) · **Decisions:** D4, D6, D7 · **FEATURES.md:** §2 (tabs: several connections open at once, each with its own panes)

## Goal

Several connections open at once, each in its own tab with its own local and remote
panes, trees, message log view, synchronized-browsing and comparison state. Tabs are
created, closed, switched, renamed, duplicated and reordered from the keyboard; the
transfer queue stays global. Optionally, tabs are restored at the next start.

## Context

**Before this task:** T50 has one implicit tab (`TabId(0)`) holding the panes; T53
provides `FileListState`, `PaneId { tab, side }`; T55 the `LogStore`
with per-tab rings (`set_tab_route`, `remove_tab`) and creates `crate::tabs::TabId`;
T58 connects the current tab from quickconnect (with "replace current connection"
confirm) and implements `BackendFactory`; T59 connects from the Site Manager;
T03 provides `ConnectInfo`, `SessionHandle`; T04 `SessionId`, `CoreEvent::Connected` /
`Disconnected`. T82 provides `device_blobs` (LMK-encrypted, device-local) for tab state.

**Later tasks need from it:** T66 (per-tab sync base and comparison flags), T64 (apply a
bookmark to the active tab), T45 (Disconnect action disconnects every tab), T70
(launch intents open in the first tab), T57 (security of the active tab).

## Technical specification

### Types and APIs

```rust
// crates/courier-ftp/src/tabs.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TabId(pub u32);                     // created in T55; ids never reused in a run

/// Connection state of a tab's browsing session.
#[derive(Debug)]
pub enum TabConnection {
    None,
    Connecting { session: SessionId, cancel: CancellationToken, label: String },
    Connected { session: SessionId, handle: Arc<SessionHandle>, address: ServerAddress },
    Failed { message: String },                // last attempt failed; shows `!`
}

/// Where a connection came from (for title, reconnect, duplicate and restore).
#[derive(Debug, Clone)]
pub enum ConnectOrigin { Site(SiteId), Quickconnect(ServerAddress), Url(ServerAddress) }

#[derive(Debug)]
pub struct Tab {
    pub id: TabId,
    pub custom_title: Option<String>,
    pub connection: TabConnection,
    pub origin: Option<ConnectOrigin>,
    /// Kept in memory only (contains secrets); used by reconnect and duplicate.
    connect_info: Option<Arc<ConnectInfo>>,
    pub site_color: Option<SiteColor>,
    pub local: FileListState,
    pub remote: FileListState,
    pub local_tree: Option<DirTreeState>,      // field added when T54 (M6) lands
    pub remote_tree: Option<DirTreeState>,
    pub focus: TabFocus,                       // which region was focused (restored on switch)
    pub sync_browsing: Option<SyncBase>,       // T66 (local base, remote base)
    pub comparison: bool,                      // T66
}

#[derive(Debug)]
pub struct Tabs {
    tabs: Vec<Tab>,                            // display order
    active: usize,
    next_id: u32,
    bar_scroll: usize,                         // first visible tab in the bar
}

pub const MAX_TABS: usize = 32;

impl Tabs {
    pub fn new(first: Tab) -> Self;
    pub fn active(&self) -> &Tab;
    pub fn active_mut(&mut self) -> &mut Tab;
    pub fn get(&self, id: TabId) -> Option<&Tab>;
    pub fn by_session(&self, session: SessionId) -> Option<TabId>;
    pub fn open(&mut self, template: NewTab) -> Result<TabId, TabError>; // TabError::Limit
    pub fn close(&mut self, id: TabId) -> ClosedTab;           // never leaves zero tabs
    pub fn activate(&mut self, index: usize);
    pub fn next(&mut self); pub fn prev(&mut self);
    pub fn move_left(&mut self); pub fn move_right(&mut self);
    pub fn rename(&mut self, id: TabId, title: Option<String>);
    pub fn title(&self, id: TabId) -> String;                  // rules below
    pub fn snapshot(&self) -> TabsSnapshot;                    // for restore
}

#[derive(Debug, Clone)]
pub enum NewTab { Empty { local_dir: LocalPath }, Duplicate(TabId), Restored(TabSnapshot) }

/// What `close` hands back so the app can disconnect and clean up.
#[derive(Debug)]
pub struct ClosedTab { pub id: TabId, pub session: Option<SessionId>, pub replaced_last: bool }

/// Where a connect request should open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectTarget { Ask, NewTab, Replace }

/// A connect request from quickconnect (T58), Site Manager (T59), bookmarks (T64),
/// history/recent servers (T33) or the command line (T70).
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub info: Arc<ConnectInfo>,
    pub origin: ConnectOrigin,
    pub target: Option<ConnectTarget>,         // Some(NewTab) for "Connect in new tab"
    pub initial_remote_dir: Option<RemotePath>,
    pub initial_local_dir: Option<LocalPath>,
}
```

Component `TabBar` (implements `Component`, draws one row; no focus of its own).
Actions (T51 names): `NewTab` (`Ctrl-t`), `CloseTab` (`Ctrl-w`), `NextTab` (`gt`,
`Ctrl-PageDown`), `PrevTab` (`gT`, `Ctrl-PageUp`), `GoToTab(n)` (`Alt-1`…`Alt-9`),
`RenameTab` (`Ctrl-x t`), `DuplicateTab` (`Ctrl-x T`), `MoveTabLeft` (`Ctrl-x <`),
`MoveTabRight` (`Ctrl-x >`), `Disconnect` (`Ctrl-x d`), `Reconnect` (`Ctrl-x r`, T58).
Non-key: `Action::Connect(ConnectRequest)` (`#[serde(skip)]`, redacted `Debug`).

### Behaviour

#### Tab lifecycle

| Operation | Rules |
|---|---|
| New (`Ctrl-t`) | new tab after the active one, disconnected, local dir = active tab's local dir, remote pane `NotConnected`; becomes active; `MAX_TABS` reached → Warning `Maximum of 32 tabs reached` |
| Close (`Ctrl-w`) | connected or connecting → confirm dialog (default `Close tab`); disconnects only this tab's browsing session (`SessionHandle` dropped, `Backend::disconnect` with a 5 s timeout, then dropped); queued and running transfers continue on their own sessions (T41); `LogStore::remove_tab`; the next tab to the right (else left) becomes active |
| Close last tab | the tab is replaced by a new empty tab (same local dir); never zero tabs |
| Switch | `GoToTab(n)` (1-based; beyond count → ignored), next/prev wrap around; restores the tab's focused region |
| Rename (`Ctrl-x t`) | T52 `prompt_text` prefilled with the current title; empty → back to the automatic title; max 40 chars |
| Duplicate (`Ctrl-x T`) | new tab after the source with the same local dir; if the source has `connect_info`, connects a **new** session with it and opens the source's current remote dir; else an empty tab |
| Move (`Ctrl-x <`/`>`) | swaps with the neighbour; numbers follow the display order |
| Disconnect (`Ctrl-x d`) | active tab's browsing session closed; remote pane `NotConnected`; tab stays |
| Reconnect (`Ctrl-x r`) | active tab's `connect_info` (or T58's last-server logic when none) reconnects in the same tab |

#### Connecting (adds the choice to T58 and T59)

1. Every connect goes through `Action::Connect(ConnectRequest)`.
2. Target: `request.target` if set (Site Manager's `Connect in new tab` sets `NewTab`;
   its `Connect` leaves it `None`); else if the active tab is `None`/`Failed` → this tab;
   else `interface.connect_target`.
3. `Ask` → dialog with `[ New tab ]` (default), `[ Replace current connection ]`,
   `[ Cancel ]` and `[ ] Remember my choice`; remembering writes
   `interface.connect_target` (`new_tab` / `replace`) via `Settings::save_user`.
4. `Replace` disconnects the tab's current session first (its panes keep the local
   side); `NewTab` opens a tab (limit applies).
5. The tab becomes `Connecting` (marker `◌`), the `BackendFactory` (T58) builds the
   backend, `SessionHandle` connects with the tab's `SessionId`; T55 routing is set with
   `set_tab_route`. `Esc` in the remote pane or `Ctrl-x d` cancels the connect.
6. `CoreEvent::Connected` → `Connected`, remote pane lists `initial_remote_dir` or the
   home dir; site settings applied (default dirs, sync browsing, comparison — T59/T66).
7. Failure → `Failed { message }` (marker `!`), remote pane shows the error (T53).
   A later `CoreEvent::Disconnected { reason }` (after T03's single reconnect attempt) →
   `None`, remote pane `NotConnected` with `Connection lost: <reason>. Ctrl-x r reconnects.`
8. Events for background tabs update their state and panes; only the bar marker shows it.

#### Titles

Custom title if set; else site name (origin `Site`); else `user@host` (quickconnect/URL;
port appended when not default); else `Local`. The bar cuts titles (see below); the
full title appears in the remote pane border (T53).

#### Tab bar layout

One row: ` [n title ●] [n title ○] …`, one space between labels. State markers:
`●` connected, `○` not connected, `◌` connecting, `!` failed (ASCII `*`, `o`, `.`, `!`).
Active tab: style `tabs.active` (reverse + bold; monochrome the same). The number of a
tab whose site has a `background_color` (T31) is drawn on that colour (`tabs.site_<colour>`);
monochrome: no colour, the remote pane title still names the site.

Fitting (pure `fit_tab_bar(width, labels, active)`):
1. Try title limits 20, 16, 12, 10, 8, 6 characters (cut with `…`) — first that fits.
2. Otherwise keep limit 6 and show a window of consecutive tabs that contains the
   active tab, growing to the right first, then left; hidden tabs are indicated by
   `«` (left) / `»` (right) (ASCII `<<` / `>>`).
3. Width < 20: show `n/N` + title cut to the rest (e.g. `3/5 deplo…`).

#### Mock-ups

Five tabs (active 1). 160 columns (row 2 of a 160×48 screen):
```
 [1 web01 ●] [2 backup.example.org ○] [3 deploy@ftp.example.… ◌] [4 db01 (prod) !] [5 Local ○]                                                                  
```
80 columns (row 2 of an 80×24 screen):
```
 [1 web01 ●] [2 backup.ex… ○] [3 deploy@ft… ◌] [4 db01 (pro… !] [5 Local ○]     
```
40 columns (single-pane mode):
```
 [1 web01 ●] [2 backu… ○] »             
```
Twelve tabs, active 9 (`reports`) — 160, 80, 40 columns:
```
 [1 web01 ●] [2 web02 ●] [3 backup ○] [4 db01 !] [5 ftp-leg… ◌] [6 staging ●] [7 cdn-ori… ●] [8 logs ○] [9 reports ●] [10 archive ○] [11 media ●] [12 Local ○]  
 « [7 cdn-o… ●] [8 logs ○] [9 repor… ●] [10 archi… ○] [11 media ●] [12 Local ○] 
 « [9 repor… ●] [10 archi… ○] »         
```
Connect choice and close confirmation (both 64×8 / 64×7, centred; identical at 80×24 and
160×48 — at 80×24 the connect dialog is at x=8, y=8; at 160×48 at x=48, y=20):
```
┌ Connect to web01 ────────────────────────────────────────────┐
│ Tab 2 is connected to backup.example.org.                    │
│ Where should the new connection open?                        │
│                                                              │
│ [ ] Remember my choice                                       │
│                                                              │
│  [ New tab ]   [ Replace current connection ]   [ Cancel ]   │
└──────────────────────────────────────────────────────────────┘

┌ Close tab ───────────────────────────────────────────────────┐
│ Tab 1 is connected to web01.                                 │
│ Close the tab and disconnect its browsing session?           │
│ Queued transfers keep running.                               │
│                                                              │
│  [ Close tab ]   [ Cancel ]                                  │
└──────────────────────────────────────────────────────────────┘
```

#### Session restore (`interface.restore_tabs`)

- Saved to `device_blobs` row `tabs` (T82; LMK-encrypted, device-local, never synced)
  on quit and debounced 2 s after tab changes, only while the vault is unlocked.
- Format: CBOR map `{v: 1, active: u8, tabs: [{origin: {site: uuid} | {quick: url-without-password}, custom_title?, local_dir, remote_dir?, sync_browsing: bool, comparison: bool}]}`; at most 32 entries.
- Restore runs after unlock (T60), before the launch intent (T70; a launch intent then
  opens per the connect-target rules). At most 3 connects run at once; the rest wait
  as `Connecting`. Site origins whose site was deleted → tab opens disconnected with a
  Warning. Quickconnect origins reconnect with `AskForPassword` unless the history
  entry has a stored password (T33).
- Vault locked or "continue without vault": nothing restored or saved.
- Unknown `v` → ignored with a Warning, overwritten on next save.

#### Performance

Switching tabs swaps references only (≤ 1 ms, no relisting; panes keep their listings).
32 tabs × 2 panes with 100 000 entries each are allowed; memory is the listings
themselves (T46 cache shares `Arc<Listing>` between tabs on the same server).

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `interface.restore_tabs` | bool | `false` | added here (T05 §1c) |
| `interface.connect_target` | `ask` \| `new_tab` \| `replace` | `ask` | added here |
| `device_blobs['tabs']` | CBOR, see above | — | T82 table |

Style keys: `tabs.bar`, `tabs.active`, `tabs.inactive`, `tabs.marker_connected`
(green), `tabs.marker_failed` (red; monochrome bold), `tabs.site_red` … `tabs.site_magenta`,
`tabs.scroll`.

### Errors

| Situation | User sees |
|---|---|
| Connect failure (`Error::Connection`, `Auth`, `Tls`, `HostKey`, `Timeout`) | tab `!`, remote pane error text (T53 mapping), log lines (T55) |
| Tab limit | Warning message |
| Restore blob unreadable (decrypt/CBOR error) | Warning `Saved tabs could not be restored`; blob replaced on next save |
| Disconnect timeout (5 s) | session dropped anyway; `debug` log |

### Security and logging

- `ConnectInfo` (with secrets) lives only in memory in the tab and is dropped on close,
  disconnect-and-replace and vault lock when `vault.lock_disconnects` is on; it is never
  serialised. The restore blob holds no passwords (quickconnect URLs without password).
- Tab titles and hosts are user-facing; `tracing` at `info`+ logs only
  `tab=<id> state=<state>`, never hosts or titles.
- Titles are sanitised (T55) — a site name or custom title cannot inject escapes.

## Implementation steps

1. `Tabs`/`Tab` model moving T50's single-tab state into `Tabs`; `TabId` routing for pane actions; unit tests.
2. Tab bar component with `fit_tab_bar`; snapshots.
3. Actions: new, close (confirm), switch, rename, duplicate, move, disconnect, reconnect.
4. `Action::Connect` pipeline with target rules and the Ask dialog; update T58/T59 call sites.
5. Per-tab log routing (T55), per-tab panes/trees/focus; background tab events.
6. Session restore in `device_blobs` with debounce; restore after unlock.
7. UI-flow tests with two mock backends.

## Acceptance criteria

- [ ] AC1 Two tabs connected to different `MockBackend` servers browse independently (listings, cursor, log views).
- [ ] AC2 Closing a connected tab disconnects only that tab's browsing session; a running transfer to the same server continues (engine with mock backend).
- [ ] AC3 Closing the last tab leaves exactly one empty tab.
- [ ] AC4 Connect target rules: disconnected tab reused; `ask` shows the dialog; `remember` persists; Site Manager's `Connect in new tab` always opens a new tab.
- [ ] AC5 `fit_tab_bar` matches the mock-ups for 5 and 12 tabs at 160/80/40 columns and always shows the active tab.
- [ ] AC6 Snapshot tests at 80×24 and 160×48 (full screen) for: one tab, five tabs with all states, overflow, the connect dialog, the close dialog; `NO_COLOR` + ASCII variants all ASCII.
- [ ] AC7 With `interface.restore_tabs`, quit and restart (same temp home, test vault) reopen the same tabs, dirs and titles; the blob contains no password (canary).
- [ ] AC8 32-tab limit enforced; switching between two tabs with 100 000-entry listings triggers no backend call.
- [ ] AC9 CI gates `fmt`, `clippy`, `test-local-only`, `test-os`, `canary` pass.

## Tests

### Unit tests
- `open_close_never_zero_tabs` (AC3), `close_activates_right_then_left`.
- `tab_limit_32` (AC8).
- `title_rules_custom_site_userhost_local`.
- `fit_tab_bar_cut_steps_and_window` — the mock-up cases (AC5), `fit_tab_bar_tiny_width`.
- `connect_target_rules` — table over (tab state × setting × request target) (AC4).
- `move_left_right_renumbers`.
- `restore_blob_roundtrip_without_secrets` (AC7), `restore_unknown_version_ignored`.

### Property / fuzz tests
- `prop_active_tab_always_visible_in_bar` — random tab counts/titles/widths (AC5).
- `prop_tabs_ops_keep_invariants` — random op sequences: ≥ 1 tab, ≤ 32, active index valid, ids unique.

### Snapshot tests
Full-screen `TestBackend` at 80×24 and 160×48: `tabs_single`, `tabs_five_states`,
`tabs_overflow_twelve`, `tabs_connect_dialog`, `tabs_close_dialog`; each also `*_mono_ascii` (AC6).

### Integration tests
- `two_tabs_browse_independently` (AC1) — two `MockBackend` instances via a test `BackendFactory`.
- `close_tab_keeps_transfer_running` (AC2) — T41 engine + mock backend with latency.
- `switch_tabs_no_relist` (AC8) — call counter.
- `restore_tabs_after_unlock` (AC7) — real `VaultEngine` with `Argon2Cost::TEST`, `device_blobs`.
- `background_tab_disconnect_updates_marker`.

### End-to-end tests
- T76 PtyApp `two_tabs_two_servers` — `sshd` (password profile) and vsftpd (`plain`): connect each in its own tab, list, close one, the other still lists.

## Out of scope

- Split panes inside a tab, tab groups, mouse (D7).
- Per-tab filter sets (filters stay global as in FileZilla; the quick filter is per pane, T53).
- Remote-to-remote transfers between tabs.

## Open questions

1. T51 binds `Alt-1..9` to tabs, while T50 suggests `Alt-1..5` for focus regions. This task keeps `Alt-1..9` for tabs; T50/T51 need another binding for focus regions.
2. Should tab state restore also reconnect automatically (current design), or open the tabs disconnected and let the user press `Ctrl-x r`? Automatic reconnects to many servers at startup may be unwanted.
