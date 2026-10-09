# T59 — Site Manager screen

**Phase:** F TUI · **Milestone:** M5 · **Depends on:** T31, T32, T33, T52, T58, T60 · **Crate(s):** `courier-ftp` (`components/site_manager/`) · **Decisions:** D4, D6, D7, D8 · **FEATURES.md:** §2 (Site Manager: folder tree, General/Advanced/Transfer settings/Charset tabs, background colour, import/export, bookmarks, password storage)
**Related (integrates with, not blocking):** T64, T70

## Goal

A full-screen Site Manager: the folder tree of saved sites on the left, a tabbed
site editor on the right, and Connect / Connect in new tab / Save / Import / Export
at the bottom. Fields appear only when they apply to the chosen protocol and logon
type, passwords are stored encrypted in the vault, unsaved changes are never lost
silently, and a fuzzy site picker connects to a known site in a few keystrokes.

## Context

**Before this task:** T31 provides `SiteNode`, `Site` (all fields), tree operations
(add, rename, delete, move, duplicate, sort), lookup, validation and
`Site::to_connect_info()`; sites and folders are `site` / `site-folder` items written
through `VaultEngine::put` (T30). T32 provides FileZilla XML import, courier-ftp
export/import (with/without passwords) and the import report. T33 provides site
bookmarks and `device_local` recents (frecency). T52 provides `TabbedForm`,
`TextInput` (masked), `NumberInput`, `Checkbox`, `Select`, `RadioGroup`, `PathInput`,
`confirm`, `prompt_password`, `ProgressDialog`. T58 provides the quickconnect path and
"Save as site" prefill. T60 provides `request_unlock()`, `vault_available()` and the
lock behaviour (dialogs discarded, `DISCARDED_FORMS`). T64 (Related; built just before this task in
M5) provides the bookmark editor dialog used by the Bookmarks tab — until it exists the tab
is a read-only list. T82 provides `ApprovalRepo`
(`local_approvals`) and `DeviceLocalRepo`.

**Later tasks need from it:** T61 (Connect / Connect in new tab produce a
`ConnectRequest`), T70 (`--site` uses the same lookup and connect path), T90 (vault
roots, read-only team items, copy/move to vault).

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/site_manager/` (`mod.rs`, `tree.rs`,
`editor.rs`, `fields.rs` (visibility), `picker.rs`, `import_export.rs`).

```rust
/// UI protocol choice (General tab). Mapped to T02/T31 fields by `ProtocolChoice::apply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolChoice { Ftp, Sftp }

/// Every editable field of the editor (one variant per form control).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SiteField {
    // General
    Protocol, Encryption, Host, Port, LogonType, User, Password, Account,
    KeySource, KeyFile, VaultKey, KeyPassphrase, TryAgentFirst, Colour, Comments,
    // Advanced
    ServerType, BypassProxy, DefaultLocalDir, DefaultRemoteDir, SyncBrowsing,
    DirectoryComparison, TimezoneHours, TimezoneMinutes,
    // Transfer settings
    TransferMode, LimitConnections, MaxConnections,
    // Charset
    CharsetMode, CustomEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldState { Hidden, Editable, Disabled { reason: &'static str } }

/// Pure visibility rule (the table below). `store_passwords` = `vault.store_passwords`.
pub fn field_state(field: SiteField, draft: &SiteDraft, store_passwords: bool, read_only: bool) -> FieldState;

/// Logon types offered for a protocol, in display order.
pub fn logon_types_for(p: ProtocolChoice) -> &'static [LogonKind];

/// `LogonType` without its data (T02 variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonKind { Anonymous, Normal, AskForPassword, Interactive, Account, KeyFile, Agent }

/// Where an SFTP key comes from (T31 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource { File, Vault }

/// The editor's working copy. Secrets are `SecretString`; `Debug` is redacted.
#[derive(Debug, Clone)]
pub struct SiteDraft {
    pub site: Site,                 // T31 type, edited in place
    pub original: Arc<Site>,        // for dirty detection (field-wise compare, secrets via ct_eq)
    pub errors: HashMap<SiteField, String>,
    pub warnings: HashMap<SiteField, String>,
}
impl SiteDraft {
    pub fn is_dirty(&self) -> bool;
    pub fn validate(&mut self) -> bool;                 // T31 rules + UI rules below
    pub fn set_protocol(&mut self, p: ProtocolChoice, enc: FtpEncryption);
    pub fn set_logon_kind(&mut self, k: LogonKind);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EditorTab { #[default] General, Advanced, Transfer, Charset, Bookmarks }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmFocus { Tree, Editor, Buttons }

pub struct SiteManager {
    tree: SiteTreeView,             // flattened rows over the T31 tree, expansion, cursor, filter
    editor: Option<SiteEditor>,     // TabbedForm over a SiteDraft (site selected) or folder name
    focus: SmFocus,
    cut: Option<ItemId>,            // marked for move
    pending: Option<PendingSwitch>, // selection change waiting for Save/Discard/Cancel
}
impl Component for SiteManager { /* … */ }

/// Fuzzy picker (`Ctrl-x s`).
pub struct SitePicker { query: String, results: Vec<PickerHit>, cursor: usize }
pub fn fuzzy_score(query: &str, name: &str, path: &str) -> Option<i32>;
```

Actions (T51 names): `SiteManager` (`Ctrl-s`, global), `SitePicker` (`Ctrl-x s`,
global), and in mode `SiteManager`: `SmNewSite`, `SmNewFolder`, `SmDuplicate`,
`SmRename`, `SmDelete`, `SmMark`, `SmPaste`, `SmFind`, `SmConnect`,
`SmConnectNewTab`, `SmSave`, `SmImport`, `SmExport`, `SmClose`, `SmNextTab`,
`SmPrevTab`. Emitted: `Action::Connect(ConnectRequest)` (T61),
`Action::StatusMessage` (T57).

### Behaviour

#### Opening and the vault

- `Ctrl-s` opens the Site Manager as a full-screen view (everything except the
  status bar; T50 modal layer). The cursor starts on the site of the active tab, else
  on the last selected site of this run, else the first row.
- Vault locked (T60 "continue without vault" or after lock): `request_unlock()`; on
  success the Site Manager opens; on cancel nothing opens and Info
  `Unlock the vault to view sites` is shown.
- When the vault locks while the Site Manager is open, it closes (T60 discards dialogs;
  a dirty draft sets `DISCARDED_FORMS`).
- From T58 "Save as site": opens with a new site prefilled (protocol, host, port, user,
  password if `vault.store_passwords`) in the root folder, dirty, editor focused.

#### Layout

| Region | 80×24 | 160×48 | Rule |
|---|---|---|---|
| Tree column | 28 columns | 44 columns | 30 % of width, min 24, max 44 |
| Editor column | rest | rest | min 44; label column 13 (≤ 100 wide) or 18 |
| Key hints | last 3 rows of the tree column | last 4 rows | hidden when the tree has < 10 rows |
| Buttons row | 1 row above the bottom border | same | buttons cut to short labels below 100 columns (`[New tab]`, `[Import…]`) |
| Narrow (< 72 columns or < 20 rows) | one column: tree **or** editor; `Tab` switches | — | title shows `Sites` or the site name |

Editor tab headers: `[General] Advanced Transfer Charset Bookmarks` (active in
brackets and `sm.tab_active`); ≥ 100 columns the third is `Transfer settings`.
`[` / `]` or `Ctrl-PageUp` / `Ctrl-PageDown` switch tabs (T52 `TabbedForm`).
The editor title shows the site name and ` *` when dirty. Hidden fields take no rows;
the field order is fixed (as in the tables).

#### Mock-up: 80×24, General tab, SFTP with key file (cursor on `web01`, draft dirty)

```
┌ Site Manager ─────────────┬ web01 * ─────────────────────────────────────────┐
│ ▾ Personal                │ [General] Advanced Transfer Charset Bookmarks    │
│   ▾ Work                  │                                                  │
│     ▾ Production          │ Protocol     SFTP ▾                              │
│       ● web01             │ Host         web01.example.com                   │
│       ● db01              │ Port         22 (default)                        │
│     ▸ Staging             │ Logon type   Key file ▾                          │
│   ▸ Clients               │ User         deploy                              │
│     ftp.example.com       │ Key          File ▾                              │
│     legacy-ftp            │ Key file     ~/.ssh/id_ed25519                   │
│                           │ Passphrase   ••••••••••                          │
│                           │ [x] Try SSH agent first                          │
│                           │ Colour       Red ▾                               │
│                           │ Comments     Production web server,              │
│                           │              deploy user only                    │
│                           │                                                  │
│                           │                                                  │
│ n new  f folder  d dup    │                                                  │
│ r rename  x delete        │ Saved in vault: Personal                         │
│ m move  p paste  / find   │ Ctrl-s save · [ ] tabs · Tab fields              │
├───────────────────────────┴──────────────────────────────────────────────────┤
│ [Connect]  [New tab]  [Save]  [Import…]  [Export…]  [Close]                  │
└──────────────────────────────────────────────────────────────────────────────┘
 🔒 SSH │ Type: Auto │ ⇅ off │ Queue: empty                                     
```

#### Mock-up: 160×48, General tab, FTP with Account logon and a validation error

```
┌ Site Manager ─────────────────────────────┬ ftp.example.com ─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ▾ Personal                                │ [General]  Advanced  Transfer settings  Charset  Bookmarks                                                       │
│   ▾ Work                                  │                                                                                                                  │
│     ▾ Production                          │ Protocol          FTP ▾                                                                                          │
│       ● web01                             │ Encryption        Require explicit FTP over TLS ▾                                                                │
│       ● db01                              │ Host              ftp.example.com                                Port   0                                        │
│       ● cdn-origin                        │                                                                  Port must be between 1 and 65535                │
│     ▸ Staging                             │ Logon type        Account ▾                                                                                      │
│   ▸ Clients                               │ User              alice                                                                                          │
│     ftp.example.com                       │ Password          ••••••••••••          stored encrypted in the vault                                            │
│     legacy-ftp                            │ Account           acct-42                                                                                        │
│     ● backup.example.org                  │                                                                                                                  │
│                                           │ Background colour None ▾                                                                                         │
│                                           │ Comments          Customer FTP; passive mode only.                                                               │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│                                           │                                                                                                                  │
│ n new site   f new folder   d duplicate   │                                                                                                                  │
│ r/F2 rename   x/Del delete                │                                                                                                                  │
│ m mark to move   p paste here             │ Saved in vault: Personal · last connected 2026-10-08 18:22                                                       │
│ / find   Enter connect   e edit           │ Ctrl-s save · [ / ] switch tabs · Tab next field · Esc back to tree                                              │
├───────────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [ Connect ]   [ Connect in new tab ]   [ Save ]   [ Import… ]   [ Export… ]   [ Close ]                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 🔒 SSH │ Type: Auto │ ⇅ off │ Queue: empty                                                                                                                     
```

#### Mock-ups: 80×24 Advanced, Transfer settings and Charset tabs

```
┌ Site Manager ─────────────┬ web01 ───────────────────────────────────────────┐
│ ▾ Personal                │ General [Advanced] Transfer Charset Bookmarks    │
│   ▾ Work                  │                                                  │
│     ▾ Production          │ Server type  Default (detect) ▾                  │
│       ● web01             │ [ ] Bypass proxy                                 │
│       ● db01              │ Local dir    ~/projects/site                     │
│     ▸ Staging             │ Remote dir   /var/www/html                       │
│   ▸ Clients               │ [x] Use synchronized browsing                    │
│     ftp.example.com       │ [ ] Directory comparison                         │
│     legacy-ftp            │ Time zone    +0 h  00 min                        │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│ n new  f folder  d dup    │                                                  │
│ r rename  x delete        │ Saved in vault: Personal                         │
│ m move  p paste  / find   │ Ctrl-s save · [ ] tabs · Tab fields              │
├───────────────────────────┴──────────────────────────────────────────────────┤
│ [Connect]  [New tab]  [Save]  [Import…]  [Export…]  [Close]                  │
└──────────────────────────────────────────────────────────────────────────────┘
 🔒 SSH │ Type: Auto │ ⇅ off │ Queue: empty                                     
```
```
┌ Site Manager ─────────────┬ legacy-ftp ──────────────────────────────────────┐
│ ▾ Personal                │ General Advanced [Transfer] Charset Bookmarks    │
│   ▾ Work                  │                                                  │
│     ▾ Production          │ Transfer mode  Default ▾                         │
│       ● web01             │ [x] Limit number of simultaneous                 │
│       ● db01              │     connections                                  │
│     ▸ Staging             │ Maximum        2                                 │
│   ▸ Clients               │                                                  │
│     ftp.example.com       │                                                  │
│     legacy-ftp            │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│ n new  f folder  d dup    │                                                  │
│ r rename  x delete        │ Saved in vault: Personal                         │
│ m move  p paste  / find   │ Ctrl-s save · [ ] tabs · Tab fields              │
├───────────────────────────┴──────────────────────────────────────────────────┤
│ [Connect]  [New tab]  [Save]  [Import…]  [Export…]  [Close]                  │
└──────────────────────────────────────────────────────────────────────────────┘
 🔒 SSH │ Type: Auto │ ⇅ off │ Queue: empty                                     
```
```
┌ Site Manager ─────────────┬ legacy-ftp ──────────────────────────────────────┐
│ ▾ Personal                │ General Advanced Transfer [Charset] Bookm…       │
│   ▾ Work                  │                                                  │
│     ▾ Production          │ (•) Autodetect                                   │
│       ● web01             │ ( ) Force UTF-8                                  │
│       ● db01              │ ( ) Use custom charset                           │
│     ▸ Staging             │     Encoding   windows-1252 ▾                    │
│   ▸ Clients               │                                                  │
│     ftp.example.com       │                                                  │
│     legacy-ftp            │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│                           │                                                  │
│ n new  f folder  d dup    │                                                  │
│ r rename  x delete        │ Saved in vault: Personal                         │
│ m move  p paste  / find   │ Ctrl-s save · [ ] tabs · Tab fields              │
├───────────────────────────┴──────────────────────────────────────────────────┤
│ [Connect]  [New tab]  [Save]  [Import…]  [Export…]  [Close]                  │
└──────────────────────────────────────────────────────────────────────────────┘
 🔒 SSH │ Type: Auto │ ⇅ off │ Queue: empty                                     
```

#### Field visibility by protocol and logon type (General tab)

`E` editable, `–` hidden, `D` disabled (shown with the reason). Read-only items
(team vault without write permission, T89/T90) make every field `D`.

| Field | FTP · Anonymous | FTP · Normal | FTP · Ask for password | FTP · Interactive | FTP · Account | SFTP · Normal | SFTP · Ask for password | SFTP · Interactive | SFTP · Key file | SFTP · Agent |
|---|---|---|---|---|---|---|---|---|---|---|
| Protocol | E | E | E | E | E | E | E | E | E | E |
| Encryption | E | E | E | E | E | – | – | – | – | – |
| Host, Port | E | E | E | E | E | E | E | E | E | E |
| Logon type | E | E | E | E | E | E | E | E | E | E |
| User | – (sent as `anonymous`) | E | E | E | E | E | E | E | E | E |
| Password | – | E¹ | – | – | E¹ | E¹ | – | – | – | – |
| Account | – | – | – | – | E | – | – | – | – | – |
| Key source (File / Vault key) | – | – | – | – | – | – | – | – | E | – |
| Key file (path) | – | – | – | – | – | – | – | – | E (source File) | – |
| Vault key (picker of `ssh-key` items) | – | – | – | – | – | – | – | – | E (source Vault) | – |
| Key passphrase | – | – | – | – | – | – | – | – | E¹ (optional) | – |
| Try SSH agent first | – | – | – | – | – | E | E | E | E | – |
| Background colour | E | E | E | E | E | E | E | E | E | E |
| Comments | E | E | E | E | E | E | E | E | E | E |

¹ `D` with reason `Passwords are not saved (Settings → Security → Store passwords)` when
`vault.store_passwords = false`; the logon then behaves like Ask for password (T31 §6).

Logon types offered: FTP — Anonymous, Normal, Ask for password, Interactive, Account;
SFTP — Normal, Ask for password, Interactive (keyboard-interactive), Key file, Agent.
Kerberos/GSS is not offered (D8).

#### Field visibility on the other tabs

| Field | FTP | SFTP |
|---|---|---|
| Server type (Default/Unix/DOS/VMS/MVS/…, T31 `ServerTypeOverride`) | E | – |
| Bypass proxy | E | E |
| Default local dir (device-local, T31 §4) | E | E |
| Default remote dir | E | E |
| Use synchronized browsing | E | E |
| Directory comparison | E | E |
| Time zone offset (hours −24…+24, minutes 0…59) | E | E |
| Transfer mode (Default / Active / Passive) | E | – |
| Limit number of simultaneous connections | E | E |
| Maximum (1–10) | E when the limit is ticked, else D | same |
| Charset: Autodetect / Force UTF-8 / Custom | E | D `SFTP always uses UTF-8` |
| Custom encoding (`encoding_rs` labels, type-to-jump) | E when Custom | – |
| Bookmarks tab (list of site bookmarks; `a` add, `e` edit, `x` delete via T64 dialogs) | E | E |

#### Protocol and logon changes

- `ProtocolChoice::apply` mapping to T31 `protocol` + `encryption`:
  SFTP → (`Sftp`, none); FTP + Only use plain FTP → (`Ftp`, `PlainOnly`);
  FTP + Use explicit FTP over TLS if available (default) → (`Ftp`, `ExplicitIfAvailable`);
  FTP + Require explicit FTP over TLS → (`FtpsExplicit`, `RequireExplicit`);
  FTP + Require implicit FTP over TLS → (`FtpsImplicit`, `RequireImplicit`).
- Port: `None` shows `21 (default)` / `990 (default)` / `22 (default)`; an explicit port
  equal to the old protocol's default becomes `None` when the protocol changes.
- A logon type invalid for the new protocol becomes `Normal` (user and password kept;
  account, key fields cleared from the draft).
- Switching to a logon type without a password while the saved site has one shows the
  warning `The saved password will be removed when you save` (T31 §5).
- "Only use plain FTP" shows the warning `Plain FTP sends passwords unencrypted`.

#### Tree

Rows: folders with `▾`/`▸` (ASCII `-`/`+`), sites with a colour dot `●` (ASCII `*`)
when `background_color` is set (style `sm.colour_<name>`; monochrome: dot without
colour). Children sorted folders first, then name (T31; no manual order). Root label
`Personal` (T90 adds team vault roots).

| Key | Action |
|---|---|
| `j` `k` `↓` `↑`, `gg` `G` | move |
| `l` `→` / `h` `←` | expand / collapse (or parent) |
| `Enter` | site: connect (target rules of T61); folder: toggle |
| `e`, `Tab` | focus the editor (`Tab` cycles tree → editor → buttons) |
| `n` / `f` | new site / new folder in the cursor's folder (name prompt inline, default `New site`/`New folder`, made unique with ` (2)` …) |
| `d` | duplicate (T31 deep copy, ` (copy)`) |
| `r` `F2` | rename inline (Enter apply, Esc cancel; `/` rejected with an inline error) |
| `x` `Delete` | delete with confirm; folders: `Delete folder "Work" with 12 sites and 3 folders?` (default Cancel) |
| `m` / `p` | mark for move / move the marked item into the cursor's folder (moving into its own descendant → error from T31) |
| `/` | filter: substring on names (case-insensitive), shows matches with ancestors |
| `c` / `C` | connect / connect in new tab |
| `Ctrl-s` | save the draft |
| `i` / `E` | import / export |
| `Esc` `q` | close (unsaved-changes guard) |

`Ctrl-x` and `Ctrl-v` are not used for cut/paste because `Ctrl-x` is the global prefix (T51).

#### Editor keys

`Tab`/`Shift-Tab` move between fields (T52 form traversal), `Enter` in a single-line
field moves to the next field (in Comments it inserts a newline; `Ctrl-s` saves),
`Space` toggles checkboxes, `Enter`/`Space` opens selects, `[`/`]` switch editor tabs,
`Esc` returns focus to the tree (does not discard). The masked password shows `•`
(capped at 32); `Ctrl-r` in a password field reveals it until the field loses focus
(sverb §8.6).

#### Dirty tracking and saving

- The draft is dirty when any field differs from `original` (secrets compared in
  constant time). Title ` *`.
- Moving the tree cursor to another item, closing, connecting another site, or
  pressing `Esc` twice with a dirty draft opens `Unsaved changes`:
  `[ Save ]` (default) / `[ Discard ]` / `[ Cancel ]`.
- Save: `validate()`; errors are shown under the field (style `sm.error`) and the
  focus jumps to the first invalid field; otherwise `VaultEngine::put` via T31; values
  of local-acting fields typed on this device (key file path, Agent / try agent first,
  T91 §8) are recorded as approved in `local_approvals`; Success `Site saved`.
- Validation (T31 §8 plus UI): host non-empty (`Host is required`), port 1–65535,
  time zone within ±24 h, max connections 1–10, key file exists (warning only:
  `File not found on this device`), custom encoding is a known label.

#### Connecting

`Connect` / `Connect in new tab` (`c`/`C`, buttons, `Enter` on a site): if dirty, save
first (validation must pass); then `Site::to_connect_info()` and
`Action::Connect(ConnectRequest { origin: Site(id), target: None | Some(NewTab),
initial_remote_dir, initial_local_dir })` (T61 applies default dirs, synchronized
browsing and comparison after connect). The Site Manager closes; the site's
`last_connected_at` is updated by T33 on success.

#### Import and export

- **Import…** (`i`): choose *FileZilla* (path prefilled with the existing default:
  Linux/macOS `~/.config/filezilla/sitemanager.xml`, Windows
  `%APPDATA%\FileZilla\sitemanager.xml`) or *courier-ftp export file*; `PathInput` with
  completion. Encrypted courier-ftp exports ask the passphrase (`prompt_password`);
  FileZilla `crypt` passwords ask for the FileZilla master password (empty = skip those
  passwords). Runs in a `ProgressDialog` (cancellable), then shows T32's report:

```
┌ Import from FileZilla ───────────────────────────────────────┐
│ Imported into folder "Imported from FileZilla 2026-10-09":   │
│                                                              │
│  23 sites in 4 folders                                       │
│  19 passwords                                                │
│  6 bookmarks                                                 │
│                                                              │
│  2 skipped:                                                  │
│    old-kerberos: Kerberos logon is not supported (D8)        │
│    vms-box: protocol 5 (unknown)                             │
│                                                              │
│ [ OK ]                                                       │
└──────────────────────────────────────────────────────────────┘
```

- **Export…** (`E`): scope (*cursor site* / *cursor folder* / *all sites*), checkbox
  *Include passwords* (default off); when on, passphrase + confirm (zxcvbn score ≥ 3,
  same meter as T60) and the file is T32's encrypted export; target path
  (`PathInput`, default `~/courier-ftp-sites-YYYYMMDD.json`); existing file → confirm
  overwrite. Success message names the file.

#### Fuzzy site picker (`Ctrl-x s`)

A 60-column popup (T52 `ListView`, up to 12 rows) over the current screen:

```
┌ Connect to site ─────────────────────────────────────────┐
│ > w0▏                                                    │
│                                                          │
│  web01               Personal/Work/Production            │
│  web02               Personal/Work/Staging               │
│                                                          │
│ Enter connect · Ctrl-t new tab · Esc close               │
└──────────────────────────────────────────────────────────┘
```

- Empty query: sites ordered by `device_local.frecency` (T33/T82), then name.
- Scoring (`fuzzy_score`): query chars must appear in order in the name (or in
  `folder/…/name` when the query contains `/`); +100 prefix match, +40 per match at a
  word start (after start, space, `-`, `_`, `.`, `/`), +10 per consecutive match, −1 per
  skipped char; ties → frecency → name. Case-insensitive.
- `Enter` connects the top/cursor site (T61 target rules), `Ctrl-t` connects in a new
  tab, `↑`/`↓` move, `Esc` closes. Vault locked → `request_unlock()` first.

#### Performance

Tree with 5 000 sites in 500 folders: opening ≤ 50 ms, filter keystroke ≤ 10 ms,
picker keystroke ≤ 10 ms (bench `site_picker_5000`). Rendering is virtualised like T53.

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `vault.store_passwords` | bool | `true` | T30/T31; disables password fields when false |
| `interface.connect_target` | enum | `ask` | T61 |

No new settings. Items written: `site`, `site-folder` (T31), `bookmark` (T64);
device-local: `device_local.local_dir_override` for the default local dir,
`local_approvals` rows for local-acting fields typed here.

Style keys: `sm.border`, `sm.border_focused`, `sm.tab_active`, `sm.label`, `sm.field`,
`sm.field_focused`, `sm.disabled` (dim), `sm.error` (red; monochrome bold),
`sm.warning` (yellow; monochrome bold), `sm.colour_red` … `sm.colour_magenta`,
`sm.cursor` (reverse), `sm.cut` (italic + `[move]` suffix text).

### Errors

| Source | User sees |
|---|---|
| Validation | inline message under the field; Save/Connect blocked |
| `VaultEngine::put` failure (`Error::Vault`, SQLite busy) | Error dialog `Could not save the site: <reason>`; draft stays dirty |
| Tree operation rejected by T31 (move into own descendant, name with `/`) | inline error in the tree row / prompt |
| Import parse errors (T32) | error dialog with file name and line/column when available |
| Wrong export passphrase on import | `Wrong passphrase or damaged file` |
| Vault locked | unlock request (see above) |

### Security and logging

- Passwords, account strings and key passphrases are `SecretString` in the draft; the
  masked inputs never render the text (reveal only on explicit `Ctrl-r` in the focused
  field). `SiteDraft`'s `Debug` is redacted; drafts are dropped (zeroized) on close and lock.
- Local-acting synced fields (T91 §8): fields synced from another device and not yet
  approved show `needs approval on this device` next to the value; approval happens at
  connect time (T91 prompt), not silently on open.
- Imported data is untrusted: names and comments are sanitised for display (T55);
  `Name` with `/` is rejected/renamed by T31/T32.
- Export with passwords is always encrypted (T32); plain export strips secrets.
- `tracing` at `info`+ logs only item ids and counts (`site saved id=<uuid>`,
  `import sites=<n> skipped=<n>`), never names, hosts or users.

## Implementation steps

1. `fields.rs`: `field_state`, `logon_types_for`, protocol mapping; exhaustive unit tests from the tables.
2. Tree view over T31 (flatten, expansion, filter, keys, inline rename, new/duplicate/delete/move).
3. Editor: `SiteDraft`, `TabbedForm` with the four tabs + Bookmarks, validation, dirty tracking, save via T31, approvals.
4. Layout and rendering (two columns, narrow single column), snapshot tests.
5. Unsaved-changes guard, close, lock behaviour.
6. Connect / Connect in new tab through `Action::Connect` (T61 integration when it lands; before T61, connect replaces the current tab via T58's path).
7. Import and export flows (T32) with progress and report.
8. Fuzzy site picker with scoring and frecency; bench.

## Acceptance criteria

- [ ] AC1 Every T31 field is editable where the tables say `E`, persisted through the vault, and reloaded identically (round-trip test for each protocol × logon type).
- [ ] AC2 `field_state` matches both visibility tables for all 10 protocol/logon combinations and both protocols (table-driven test generated from this file's tables).
- [ ] AC3 Leaving a dirty site (cursor move, close, connect another site) always shows Save / Discard / Cancel; each choice behaves as specified.
- [ ] AC4 Validation errors block Save and Connect and focus the first invalid field.
- [ ] AC5 FileZilla import (T32 fixture) and courier-ftp export → import round-trip (with and without passwords) work end-to-end through the UI flow; the report lists skipped entries.
- [ ] AC6 Fuzzy picker: with the 20-site fixture, `Ctrl-x s`, `w`, `0`, `Enter` connects to `web01`; empty query + `Enter` connects to the most recent site.
- [ ] AC7 Snapshot tests at 80×24 and 160×48 for each editor tab, SFTP key-file and FTP account variants, a validation error, the narrow single-column mode, the unsaved-changes dialog, the import report and the picker; `NO_COLOR` + ASCII variants all ASCII.
- [ ] AC8 With `vault.store_passwords = false`, password fields are disabled with the reason and no password is written (item inspected).
- [ ] AC9 Opening the Site Manager while the vault is locked asks to unlock; cancelling shows the message and opens nothing; a lock while open closes it and shows the discard toast if dirty.
- [ ] AC10 No password or passphrase appears in `Debug` output, snapshots or logs (canary).
- [ ] AC11 CI gates `fmt`, `clippy`, `test-local-only`, `test-os`, `canary` pass.

## Tests

### Unit tests
- `field_state_matches_general_table` (AC2), `field_state_matches_other_tabs_table` (AC2).
- `logon_types_per_protocol`.
- `protocol_mapping_to_t31_fields` — five UI choices → (`Protocol`, `FtpEncryption`).
- `port_default_follows_protocol_change`, `invalid_logon_falls_back_to_normal`.
- `password_removal_warning_on_logon_change`.
- `dirty_detection_including_secrets` (AC3).
- `validation_rules_host_port_timezone_maxconn_encoding` (AC4).
- `fuzzy_score_prefix_word_start_consecutive` (AC6), `picker_empty_query_orders_by_frecency` (AC6).
- `tree_delete_folder_confirm_counts`, `move_into_descendant_rejected`.
- `site_draft_debug_is_redacted` (AC10).

### Property / fuzz tests
- `prop_field_state_never_editable_for_read_only`.
- `prop_site_manager_render_never_panics` — random trees/drafts, sizes 0–200 × 0–60.

### Snapshot tests
`sm_general_sftp_keyfile_80x24`, `sm_general_ftp_account_error_160x48` (and the other size
for each), `sm_advanced_{80x24,160x48}`, `sm_transfer_{80x24,160x48}`, `sm_charset_ftp_80x24`,
`sm_charset_sftp_disabled_80x24`, `sm_bookmarks_tab_80x24`, `sm_narrow_70x20`,
`sm_unsaved_dialog_80x24`, `sm_import_report_80x24`, `sm_picker_{80x24,160x48}`,
each colour snapshot also `*_mono_ascii` (AC7).

### Integration tests
UI-flow tests with a real `VaultEngine` (`Argon2Cost::TEST`) and a mock backend factory:
- `create_edit_save_reopen_site_each_logon_type` (AC1).
- `unsaved_changes_guard_save_discard_cancel` (AC3).
- `connect_and_connect_new_tab_emit_requests` — `ConnectRequest` contents (T61).
- `import_filezilla_fixture_flow`, `export_import_roundtrip_flow` (AC5).
- `store_passwords_off_writes_no_password` (AC8).
- `locked_vault_open_and_lock_while_open` (AC9).
- `canary_password_not_logged` (AC10).
- Bench `site_picker_5000`.

### End-to-end tests
- T76 PtyApp `first_run_add_site_quit_unlock_connect` (T76 scenario list): create vault, add an SFTP site with password in the Site Manager, quit, start, unlock, `Ctrl-x s` + name + `Enter` connects without a password prompt.

## Out of scope

- Drag and drop of sites (D7); "import from other clients" beyond FileZilla (T32 scope).
- Vault roots, read-only team items, copy/move between vaults (T90).
- The bookmark editor dialog itself (T64).

## Open questions

1. T31 stores both `protocol` (`Ftp`/`FtpsExplicit`/`FtpsImplicit`/`Sftp`) and `encryption` (FTP only), which can disagree; this task writes them with the canonical mapping above. Should T31 drop one of the two?
2. Default local dir is device-local (T31 §4), so on a second device the field is empty. Should the editor show the value from the device that created the site as a hint?
