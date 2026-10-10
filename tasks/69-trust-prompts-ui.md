# T69 — Trust prompts (host keys and certificates)

**Phase:** F TUI · **Milestone:** M2 · **Depends on:** T04, T52 · **Crate(s):** `courier-ftp` (`components/prompts/`) · **Decisions:** D3, D7 · **FEATURES.md:** §1 (host key confirmation on first connect, TLS certificate trust dialog), §5 (file-exists actions)
**Related (integrates with, not blocking):** T12, T21, T42
**Reference:** sverb `crates/sverb-tui/src/views/dialogs/host_key.rs` (unknown/changed host key dialogs, typed-hostname confirmation).

## Goal

Clear, safe dialogs for every question the core asks the user while connecting or
transferring: unknown and changed SSH host keys, untrusted and changed TLS certificates,
passwords and key passphrases, keyboard-interactive (2FA) challenges, and "target file
already exists". Prompts from background transfers queue up and never steal keystrokes;
a changed key or certificate can never be accepted by pressing Enter.

## Context

- **Before:** T04 delivers `CoreEvent::Prompt(PromptRequest { id, session, kind })`
  with `respond(PromptResponse) -> bool` and `is_withdrawn()` (a dropped reply means
  cancel), all prompt payload types (`HostKeyPrompt`, `CertPromptDetails`,
  `PasswordPrompt`, `PassphrasePrompt`, `KbdInteractivePrompt`, `FileExistsPrompt`,
  `MessagePrompt`), the answers (`PromptResponse`, `TrustAnswer`, `ApplyTo`) and
  `CoreEvent::CredentialAccepted { session, prompt_id }`. T52 gives
  the modal stack, `TextInput` (incl. `masked`), `Checkbox`, `RadioGroup`, `Button`
  rows, `Form` focus traversal, scrolling for tall dialogs and "terminal too small".
  T50 routes core events to the UI and owns `Mode`, `ui::text::sanitize` and
  `ui::symbols::Symbols`. T51 binds `OpenNextPrompt` to `ctrl-x p`.
- **Producers** (each dialog is built when its producer's payload type exists, as
  `tasks/README.md` notes): T20 (password, passphrase, keyboard-interactive) and T21
  (host keys) in M2; T12 (certificates) in M3; T42 (file exists) in M4. The queue,
  secret cache and focus rules come first.
- **After:** T57 shows the pending-prompt badge from `PromptQueue::badge()`. T57's
  server-info dialog reuses `render_host_key_details` / `render_certificate_details`.
  T58/T59 connects produce foreground prompts.

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/prompts/`:

```rust
// mod.rs
/// Where a prompt comes from, decided by the app when the event arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOrigin {
    /// The browsing session of the active tab (the user just asked to connect/list).
    Foreground,
    /// Transfer sessions (T41), other tabs, anything else.
    Background,
}

/// Queue of core prompts; at most one is visible.
#[derive(Debug, Default)]
pub struct PromptQueue { /* VecDeque<Queued>, visible: Option<ActiveDialog>, last_key: Instant */ }

impl PromptQueue {
    pub fn push(&mut self, req: PromptRequest, origin: PromptOrigin, now: Instant);
    /// Called every tick (T50, 4 Hz minimum) and after every key: drops withdrawn prompts
    /// (reply sender closed), applies the auto-open rules, returns what changed.
    pub fn tick(&mut self, now: Instant, ui: &UiFocusState) -> PromptTick;
    /// `Action::OpenNextPrompt` (`ctrl-x p`, T51).
    pub fn open_next(&mut self, now: Instant);
    /// Status-bar badge text: "⚠ 2 prompts" (ASCII: "! 2 prompts"); None if nothing waits.
    pub fn badge(&self, unicode: bool) -> Option<String>;
    pub fn handle_key(&mut self, key: KeyEvent, now: Instant) -> Option<PromptAnswered>;
    pub fn handle_paste(&mut self, text: &str);
    /// Vault locked: hide the visible dialog (re-queued at the front) and stop opening.
    pub fn set_suspended(&mut self, suspended: bool);
    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme);
}

pub struct UiFocusState { pub mode: Mode /* T50 */, pub other_dialog_open: bool, pub vault_locked: bool, pub unicode: bool }
pub enum PromptTick { Unchanged, Opened(PromptId), Withdrawn(PromptId), BadgeChanged }

/// "Remember for this session" secrets (process memory only; cleared on vault lock and exit).
#[derive(Default)]
pub struct SecretCache { /* HashMap<SecretCacheKey, SecretString> */ }
impl SecretCache {
    pub fn get(&self, key: &SecretCacheKey) -> Option<&SecretString>;
    pub fn insert(&mut self, key: SecretCacheKey, value: SecretString);
    pub fn clear(&mut self);   // zeroizes every value
}

/// Typed secrets waiting for `CoreEvent::CredentialAccepted` (T20) before they are
/// cached / saved. Dropped (zeroized) on failure, disconnect or after 5 minutes.
pub struct PendingCredentials { /* HashMap<PromptId, Pending { value, remember, save, target, since }> */ }
impl PendingCredentials {
    pub fn on_accepted(&mut self, id: PromptId, cache: &mut SecretCache) -> Option<SaveRequest>;
    pub fn on_session_ended(&mut self, session: SessionId);
}
/// Emitted as `Action::SaveCredential(SaveRequest)`; T31 writes it into the site item.
pub struct SaveRequest { pub site: SiteRef, pub field: CredentialField /* Password | KeyPassphrase */, pub value: SecretString }

// one file per dialog
pub struct HostKeyDialog;      // host_key.rs: unknown + changed variants
pub struct CertificateDialog;  // certificate.rs: unknown + changed + details view
pub struct SecretDialog;       // secret.rs: password + key passphrase
pub struct KbdDialog;          // keyboard_interactive.rs
pub struct FileExistsDialog;   // file_exists.rs

/// Shared detail renderers (also used by T57's server info dialog).
pub fn render_host_key_details(p: &HostKeyPrompt) -> Vec<Line<'static>>;
pub fn render_certificate_details(c: &CertificateDetails, now: OffsetDateTime) -> Vec<Line<'static>>;
```

Payloads consumed — exactly the T04 types (produced by T20, T21, T12, T42):

| `PromptKind` | Payload fields used |
|---|---|
| `TrustHostKey(HostKeyPrompt)` (T21) | `host`, `port`, `key_type`, `bits`, `fingerprint_sha256`, `fingerprint_md5`, `changed: Option<Vec<OldKey { fingerprint_sha256, source }>>`, `other_known_types`, `can_save` |
| `TrustCertificate(Box<CertPromptDetails>)` (T12) | `host`, `port`, `session: TlsSessionInfo { protocol, cipher_suite, chain: Vec<CertificateDetails>, .. }`, `problems: Vec<CertProblem>`, `hostname_matches`, `previous: Option<PreviousCert { sha256, subject, not_after, added_at }>`, `can_save` |
| `Password(PasswordPrompt)` (T07/T10/T15/T20) | `purpose`, `target`, `retry`, `attempt`, `max_attempts`, `cache_key`, `can_save` |
| `KeyPassphrase(PassphrasePrompt)` (T20) | `key_label`, `retry`, `attempt`, `max_attempts`, `cache_key`, `can_save` |
| `KeyboardInteractive(KbdInteractivePrompt)` (T20) | `host`, `name`, `instructions`, `prompts: Vec<KbdField { text, echo }>` |
| `FileExists(Box<FileExistsPrompt>)` (T42) | `direction`, `source_path`, `source: Entry`, `target_path`, `target: Entry`, `can_resume`, `suggested_name` |
| `Message(MessagePrompt)` | `level`, `title`, `text` → T52 message dialog, answered `Ack` |

Answers sent back (T04 `PromptResponse`): `HostKey(TrustAnswer)`,
`Certificate(TrustAnswer)` with `TrustAnswer { TrustOnce, AlwaysTrust, Reject }`,
`Secret { value: SecretString, remember_session: bool, save_in_vault: bool }`,
`Answers(Vec<SecretString>)`, `FileExists { action: ExistsAction, apply_to: ApplyTo,
new_name: Option<String> }` with `ApplyTo { Once, AllInQueue, AllForDirection }`, `Ack`,
`Cancel`.

Actions: `OpenNextPrompt` (bindable, T51 default `ctrl-x p`) and
`Action::SaveCredential(SaveRequest)` (internal, no key).

### Behaviour

**Queue and focus rules** (the decision the original task left open):

1. Every `CoreEvent::Prompt` goes into `PromptQueue::push` with its origin:
   `Foreground` if `PromptRequest.session` is the browsing session of the active tab,
   else `Background`.
2. **Secret cache first:** a `Password`/`KeyPassphrase` prompt with `retry == false`
   whose `cache_key` is in `SecretCache` is answered immediately with the cached value
   (`remember_session: false, save_in_vault: false`) and never shown. Retry prompts
   always show.
3. Order: foreground prompts before background ones; FIFO within each class.
4. **Auto-open:** at most one prompt dialog is visible. A queued prompt opens when no
   other modal dialog is open and the queue is not suspended, and
   - foreground: immediately (next tick);
   - background: only if `mode == Normal` (not `Input`, `Filter`, `Dialog`) and no key
     was pressed for ≥ 2 s.
   Otherwise the status bar shows the badge (`⚠ N prompts` / `! N prompts`, N = queued
   count). `ctrl-x p` opens the next prompt at once (or, if a non-prompt dialog is open,
   right after it closes).
5. **Input guard:** for 500 ms after a prompt dialog becomes visible, key presses are
   ignored (buttons drawn with the `dim` style), so an Enter typed for something else
   cannot answer it.
6. **Withdrawn prompts:** when `PromptRequest::is_withdrawn()` (the core gave up: connect cancelled,
   server closed the connection), the prompt is removed within one tick; a visible
   dialog closes and the status bar shows "Prompt withdrawn: the connection was closed"
   for 3 s.
7. **Vault lock** (T30/T60): `set_suspended(true)` hides the visible dialog (re-queued
   at the front, typed text discarded) and stops auto-open; `SecretCache::clear()`.
   After unlock the queue resumes. Prompts are not cancelled by locking.
8. Answering sends the response on the `reply` sender and closes the dialog; the next
   prompt may open on the next tick (rule 4).
9. Typed passwords/passphrases with "Remember for this session" or "Save in the vault"
   go to `PendingCredentials`; only `CoreEvent::CredentialAccepted { prompt_id }` moves
   them to `SecretCache` and/or emits `Action::SaveCredential`; a failed connection
   (`Disconnected`/connect error for that session) drops them.

**Layout rules (all dialogs):** width = `min(76, terminal_width − 4)`, centred; height =
content (≤ 21 rows, fits 80×24); taller than `terminal_height − 2` → body scrolls (T52);
label column 12 chars; values wrap at the dialog edge; server- or file-provided text
(names, prompts, certificate fields, file names) is stripped of control characters
before rendering (defence in depth on top of T20's sanitising). Snapshot sizes: 80×24
and 160×48 (the dialog is 76 wide in both, centred over the dimmed main screen).

**1. Unknown host key** (`HostKeyPrompt.changed == None`):

```
┌ Unknown host key ────────────────────────────────────────────────────────┐
│ The server's host key is not known. You have no guarantee that the       │
│ server is the computer you think it is.                                  │
│                                                                          │
│ Host:       web01.example.com:22                                         │
│ Key type:   ssh-ed25519 (256 bits)                                       │
│ SHA-256:    SHA256:uYxmMoF3aflKiV/iuu80yFQwZt3pbSCXEaovtc9SyY8           │
│ MD5:        MD5:9a:52:0e:7c:1f:33:a8:0d:4b:6e:21:c5:90:fe:12:ab          │
│                                                                          │
│ [x] Always trust this host and save the key in the vault                 │
│                                                                          │
│                    [ Trust ]        [ Cancel ]                           │
└──────────────────────────────────────────────────────────────────────────┘
```

- `other_known_types` non-empty → extra line `Note:       This server also has a trusted ssh-rsa key.`
- `can_save == false` → checkbox unchecked, disabled, text `Always trust this host (unlock the vault to save keys)`.
- Checkbox default: checked when `can_save`.
- Focus order: checkbox → `Trust` → `Cancel`; initial focus `Trust`; default button `Trust`.
- Keys: `Enter` = focused button (on the checkbox: default button); `Space` toggles the
  checkbox; `t`/`Alt-t` Trust; `a`/`Alt-a` toggle; `c`/`Alt-c`/`Esc` Cancel; `Tab`/`Shift-Tab` move.
- Answer: Trust + checked → `AlwaysTrust`; Trust + unchecked → `TrustOnce`; Cancel → `Reject`.

**2. Changed host key** (`changed == Some(old_keys)`; the `Trusted:` line lists each
`OldKey`, with "saved in the vault on <date>" or "from ~/.ssh/known_hosts line N"), border and title in the `error` style,
title text bold so it reads without colour (`NO_COLOR`):

```
┌ WARNING: HOST KEY CHANGED ───────────────────────────────────────────────┐
│ The host key of web01.example.com:22 is not the one you trusted.         │
│ Someone could be intercepting your connection (man-in-the-middle         │
│ attack), or the server was reinstalled or its key was replaced.          │
│                                                                          │
│ Key type:   ssh-ed25519 (256 bits)                                       │
│ Trusted:    SHA256:Xq3vR0ZQh2m1bN8kPj4tLw6yUe9sDc7fGa5iHo2KlMn           │
│             saved in the vault on 2026-03-01                             │
│ New key:    SHA256:uYxmMoF3aflKiV/iuu80yFQwZt3pbSCXEaovtc9SyY8           │
│                                                                          │
│ Continue only if you know why the key changed. Type the host name        │
│ to enable the trust buttons:                                             │
│ Host name:  [                                        ]                   │
│                                                                          │
│      [ Cancel ]      [ Trust once ]      [ Replace trusted key ]         │
└──────────────────────────────────────────────────────────────────────────┘
```

- One `Trusted:` line per old key; source line `saved in the vault on <date>` or
  `from ~/.ssh/known_hosts line 12`.
- Initial focus and default button: `Cancel`. `Trust once` and `Replace trusted key`
  are disabled (dim, skipped by Tab) until the typed text equals the host
  (ASCII case-insensitive, surrounding spaces ignored).
- `Enter` in the host-name field never answers: if the text matches, focus moves to
  `Trust once`; otherwise the field shows `does not match` in the error style.
- `Enter` on `Cancel` or `Esc` anywhere → `Reject`. `Alt-o` Trust once and `Alt-r`
  Replace only when enabled. No single-letter shortcuts (the field takes text).
- `can_save == false` → `Replace trusted key` hidden; note line `The vault is locked:
  the new key can only be trusted for this session.`
- Answer: Trust once → `TrustOnce`; Replace → `AlwaysTrust`; Cancel → `Reject`.

**3. Certificate** (T12 payload). Unknown/invalid certificate (summary of the leaf
certificate; problems listed with `✘`, ASCII `x`):

```
┌ Unknown certificate ─────────────────────────────────────────────────────┐
│ The server's certificate could not be verified:                          │
│   ✘ self-signed certificate                                              │
│   ✘ host name does not match (certificate is for www.example.com)        │
│                                                                          │
│ Host:       ftp.example.com:21                                           │
│ Subject:    CN=www.example.com, O=Example Ltd                            │
│ Issuer:     CN=www.example.com, O=Example Ltd                            │
│ Valid:      2026-01-01 00:00 → 2027-01-01 00:00 UTC                      │
│ SHA-256:    3F:9A:0C:11:7E:52:D4:8B:A1:6C:2E:90:44:BD:73:05              │
│             E8:12:FA:39:C7:60:5B:DE:81:24:9F:0A:B3:76:CE:58              │
│ SHA-1:      9C:41:7D:02:E5:B8:33:6A:F1:0E:84:C9:27:5D:A6:1B:70:3E:D2:48  │
│ Session:    TLS 1.3, TLS_AES_256_GCM_SHA384                              │
│ Chain:      1 certificate          [ Details… ]                          │
│                                                                          │
│ [x] Always trust this certificate and save it in the vault               │
│                                                                          │
│                    [ Trust ]        [ Cancel ]                           │
└──────────────────────────────────────────────────────────────────────────┘
```

- Expired / not-yet-valid dates and a hostname mismatch are drawn in the `error` style
  and also marked in text (`(expired 12 days ago)`, `✘`), valid ones `✔` (ASCII `ok`).
- SHA-256 is split into two lines of 16 bytes; SHA-1 is one line.
- Keys: as the unknown host key dialog, plus `d`/`Alt-d` or `Enter` on `Details…` opens
  the details view.
- **Details view** (replaces the body; one certificate at a time, leaf = 1):

```
┌ Certificate 1 of 2: server ──────────────────────────────────────────────┐
│ Subject:    CN=ftp.example.com, O=Example Ltd, C=DE                      │
│ Issuer:     CN=Example Intermediate CA 1, O=Example Ltd                  │
│ Serial:     04:A3:9F:11:0C:7E                                            │
│ Not before: 2025-01-01 00:00 UTC                                         │
│ Not after:  2025-12-31 23:59 UTC  (expired 282 days ago)                 │
│ Alt. names: DNS:ftp.example.com                                          │
│             DNS:www.example.com                                          │
│ Public key: ECDSA P-256 (256 bits)                                       │
│ Signature:  ecdsa-with-SHA256                                            │
│ SHA-256:    3F:9A:0C:11:7E:52:D4:8B:A1:6C:2E:90:44:BD:73:05              │
│             E8:12:FA:39:C7:60:5B:DE:81:24:9F:0A:B3:76:CE:58              │
│ SHA-1:      9C:41:7D:02:E5:B8:33:6A:F1:0E:84:C9:27:5D:A6:1B:70:3E:D2:48  │
│                                                                          │
│ j/k scroll   [ ] previous/next certificate   Esc back                    │
└──────────────────────────────────────────────────────────────────────────┘
```

  Keys: `j`/`k`/`↑`/`↓` line, `PgUp`/`PgDn` page, `g`/`G` top/bottom, `[`/`]` or
  `←`/`→` previous/next certificate, `Esc`/`d` back to the summary. More than 20 SANs
  are listed in full (scrolling).
- **Changed certificate** (`previous == Some(prev)`): same safety rules and button row as
  the changed host key (title `WARNING: CERTIFICATE CHANGED`, `Trusted:` = `prev.sha256`
  + `prev.added_at` date + `prev.subject`, `New:` = new SHA-256 on two lines, typed host name, default `Cancel`).
- Answers map like the host-key dialogs to `Certificate(TrustOnce | AlwaysTrust | Reject)`.

**4. Password / key passphrase** (T20 secret prompts):

```
┌ Password required ───────────────────────────────────────────────────────┐
│ Password for alice@web01.example.com:22                                  │
│ Permission denied, please try again (attempt 2 of 3).                    │
│                                                                          │
│ Password:  [••••••••                                              ]      │
│                                                                          │
│ [ ] Remember for this session                                            │
│ [ ] Save in the vault                                                    │
│                                                                          │
│                     [ OK ]          [ Cancel ]                           │
└──────────────────────────────────────────────────────────────────────────┘
```

- Passphrase variant: title `Key passphrase required`, first line `Passphrase for key
  <label>`, retry line `Wrong passphrase, please try again (attempt 2 of 3).`
- The retry line appears only when `retry` (error style). `Save in the vault` appears
  only when `can_save`. Both checkboxes default unchecked.
- Input: T52 masked `TextInput`, one `•` (ASCII `*`) per character, max 1 024 chars,
  bracketed paste allowed (newlines stripped). Empty input is allowed.
- Focus: field → checkboxes → `OK` → `Cancel`; initial focus the field; `Enter` in the
  field = OK; `Esc` = Cancel → `PromptResponse::Cancel` (T20 aborts the connect).
- The typed text lives in a `SecretString`; the widget's buffer is zeroized when the
  dialog closes.

**5. Keyboard-interactive** (T20):

```
┌ Authentication: web01.example.com:22 ────────────────────────────────────┐
│ Duo two-factor login                                                     │
│ Enter your password, then the 6-digit code from your authenticator       │
│ app.                                                                     │
│                                                                          │
│ Password:          [••••••••                                         ]   │
│ Verification code: [123456                                           ]   │
│                                                                          │
│                     [ OK ]          [ Cancel ]                           │
└──────────────────────────────────────────────────────────────────────────┘
```

- Name line (bold) only if non-empty; instructions wrapped, at most 8 lines visible,
  more → `PgUp`/`PgDn` scroll the instruction area with a `▼` marker.
- One row per prompt: label column = longest label, capped at 28 chars (longer labels
  are truncated with `…`); input fills the rest (min 20 chars); `echo == false` →
  masked, `echo == true` → plain.
- `Enter` in a field that is not the last → next field; in the last field → OK.
  `Esc` → `Cancel`. Answers are `SecretString`s in prompt order.

**6. File exists** (T42):

```
┌ Target file already exists ──────────────────────────────────────────────┐
│ Download  /var/www/index.html                                            │
│       to  ~/projects/site/index.html                                     │
│                                                                          │
│             Size          Modified                                       │
│ Source:     4.0 KiB       2026-10-02 10:00                               │
│ Target:     3.1 KiB       2026-09-30 09:12                               │
│                                                                          │
│ (•) Overwrite                                                            │
│ ( ) Overwrite if the source is newer                                     │
│ ( ) Overwrite if the size differs                                        │
│ ( ) Overwrite if newer or the size differs                               │
│ ( ) Resume                                                               │
│ ( ) Rename to: [index (1).html                    ]                      │
│ ( ) Skip                                                                 │
│                                                                          │
│ [ ] Use this action for all remaining conflicts in this queue            │
│     [ ] Only for downloads                                               │
│                                                                          │
│                     [ OK ]          [ Cancel ]                           │
└──────────────────────────────────────────────────────────────────────────┘
```

- Paths middle-truncated with `…` to fit; sizes per `interface.size_format`, dates per
  `interface.date_format`/`time_format` and the entry's precision (day-only dates show
  no time); unknown values show `?`.
- `Resume` is disabled (dim, skipped) when `can_resume == false`. The rename field
  is enabled only when `Rename` is selected; prefilled with `suggested_name`; validated
  inline (non-empty, no `/` or `\`, not equal to the target's name).
- "Only for downloads" (`uploads` for an upload) is enabled only when the first checkbox is set.
- Keys: `↑`/`↓`/`j`/`k` move the radio selection; mnemonics `o` Overwrite, `n` if
  newer, `z` if size differs, `b` newer or size, `r` Resume, `m` Rename (focuses the
  name field), `s` Skip, `a` toggle "all remaining", `d` toggle "only for …";
  `Enter` = OK (in the name field: OK if valid); `Esc` = Cancel.
- Answer: `ExistsAction` from the radio; `apply_to` = `Once` (first checkbox off),
  `AllInQueue` (on, second off), `AllForDirection` (both on); `new_name` only for
  Rename. Cancel → `PromptResponse::Cancel` (T42 decides: skip this item).

### Data formats and configuration

| Key | Type | Default | Use |
|---|---|---|---|
| `interface.unicode_symbols` (T05; resolved by T50 `Symbols`) | `auto` \| `always` \| `never` | `auto` | `•`/`*`, `✔`/`ok`, `✘`/`x`, `⚠`/`!` |
| `interface.size_format`, `date_format`, `time_format` (T05) | — | — | file-exists dialog |

Constants: input guard 500 ms; background auto-open idle 2 s; withdrawn-message 3 s;
pending-credential expiry 5 minutes; dialog width 76; label column 12; kbd label cap 28;
instruction area 8 lines; secret input max 1 024 chars.

No new settings; nothing is persisted by this task (saving goes through
`Action::SaveCredential` → T31, trust decisions through T21/T12 stores).

### Errors

This task raises no core errors. Edge cases: the reply sender already closed when the
user answers → the answer is dropped silently and the status bar shows "Prompt
withdrawn: the connection was closed". A `SaveCredential` that fails (vault busy) is
reported by T31 as an error dialog; the connection is unaffected.

### Security and logging

- Masked fields never render their content, including in snapshots and the T50 help
  overlay; the `Debug` of every dialog prints `[REDACTED]` for typed secrets.
- Secrets are held in `SecretString` from keystroke to reply; widget buffers are
  zeroized on close; `SecretCache` and `PendingCredentials` zeroize on clear/drop; a
  drop-counter test proves it (pattern from sverb `Answers`).
- Nothing in this module logs typed values; `tracing` at debug may log the prompt kind
  and id only (no host, user, path at info+, T91).
- Dangerous defaults are impossible: changed host keys and certificates require typing
  the host name; the input guard prevents accidental confirmation; background prompts
  never take focus from a text field.
- All displayed external text is control-character-free (no terminal escapes).

## Implementation steps

1. `PromptQueue` (push, ordering, withdrawn pruning, badge, suspend, input guard,
   auto-open rules) with unit tests over synthetic `PromptRequest`s; `Action::OpenNextPrompt`.
2. `SecretCache` + `PendingCredentials` + `CredentialAccepted` handling + `SaveCredential` action.
3. `SecretDialog` (password/passphrase) and `KbdDialog` — snapshots and key tests (M2).
4. `HostKeyDialog` unknown + changed variants, `render_host_key_details` (M2).
5. Wire into `MainScreen` (T50): core event bridge pushes prompts; status-bar badge hook for T57.
6. `CertificateDialog` with details view (after T12, M3).
7. `FileExistsDialog` (after T42, M4).

## Acceptance criteria

- [x] AC1 Snapshot tests exist at 80×24 and 160×48 for: unknown host key (vault unlocked, locked, other key type note), changed host key (empty field, matching text), password (first, retry, with/without save), passphrase, keyboard-interactive (1 and 2 prompts, long instructions), unknown certificate (summary, details page 1 and 2, expired), changed certificate, file exists (download, upload, resume disabled, rename invalid), badge in the status bar.
- [x] AC2 Changed host key / certificate: with an empty or wrong host name, `Enter` on every focusable element and `Esc` answer `Reject`; `Trust once`/`Replace` are unreachable by Tab until the host name matches; `Enter` in the field never answers.
- [x] AC3 Keys pressed within 500 ms after a prompt opens have no effect (paused-time test).
- [x] AC4 Three prompts pushed at once (one foreground, two background) are shown one at a time, foreground first, then FIFO; answering one shows the next on the following tick.
- [x] AC5 A background prompt arriving while `mode == Input` only shows the badge; it opens after `ctrl-x p`, or automatically after 2 s without keys in `Normal` mode.
- [x] AC6 Closing the reply sender removes the prompt (and closes the visible dialog) within one tick and shows the withdrawn message.
- [x] AC7 Typed passwords never appear in any rendered buffer or `Debug` output (snapshot buffers searched for the typed canary string).
- [x] AC8 "Remember for this session" answers the next non-retry prompt with the same `cache_key` without opening a dialog; retry prompts always open; vault lock clears the cache.
- [x] AC9 "Save in the vault" emits `Action::SaveCredential` only after `CredentialAccepted`; a failed connect emits nothing and drops the pending secret (drop counter = typed secrets).
- [x] AC10 Keyboard-interactive: echo flags respected (masked vs plain in snapshots); `Enter` advances fields and submits on the last one; answers arrive in prompt order.
- [x] AC11 File exists: every radio × checkbox combination maps to the documented `ExistsAction`/`apply_to`/`new_name`; Resume can't be selected when `can_resume` is false; invalid rename names block OK with an inline message.
- [x] AC12 Vault lock while a prompt is visible hides it; after unlock it is shown again with its original content; "Always trust"/"Save in the vault" follow `can_save`.
- [x] AC13 At 60×20 dialogs scroll instead of clipping buttons; below T52's minimum the "terminal too small" message shows and no answer is sent.
- [x] AC14 T00 gates pass (`fmt`, `clippy -D warnings`, `docs`, tests).

## Tests

### Unit tests
- `prompts::queue::tests::foreground_before_background_fifo` — AC4.
- `prompts::queue::tests::background_waits_for_normal_mode_and_idle` (paused time) — AC5.
- `prompts::queue::tests::ctrl_x_p_opens_next` — AC5.
- `prompts::queue::tests::withdrawn_prompt_removed_within_one_tick` — AC6.
- `prompts::queue::tests::input_guard_500ms` — AC3.
- `prompts::queue::tests::suspend_requeues_visible_at_front` — AC12.
- `prompts::queue::tests::badge_text_unicode_and_ascii`.
- `prompts::secrets::tests::cache_answers_non_retry_only` — AC8.
- `prompts::secrets::tests::cache_cleared_on_lock` — AC8.
- `prompts::secrets::tests::save_only_after_credential_accepted` — AC9.
- `prompts::secrets::tests::pending_dropped_on_failure_drop_counter` — AC9.
- `prompts::host_key::tests::changed_enter_everywhere_rejects` — AC2.
- `prompts::host_key::tests::changed_buttons_enabled_after_matching_host` — AC2.
- `prompts::host_key::tests::unknown_answers_trust_once_always_reject` — AC1 behaviour.
- `prompts::certificate::tests::details_navigation_and_back` — AC1.
- `prompts::kbd::tests::enter_advances_then_submits_in_order` — AC10.
- `prompts::file_exists::tests::answer_mapping_table` — AC11.
- `prompts::file_exists::tests::resume_disabled_and_rename_validation` — AC11.
- `prompts::tests::debug_redacts_typed_secrets` — AC7.

### Property / fuzz tests
- `prompts::props::rendering_never_panics` (proptest: random terminal sizes 1×1–300×100, random payload strings incl. control chars; asserts no panic and no control chars in the buffer) — AC13.

### Snapshot tests
`crates/courier-ftp/tests/snapshots/prompts__*.snap`, ratatui `TestBackend` + `insta`,
each at 80×24 and 160×48 over a fixed main screen, input guard elapsed:
`host_key_unknown`, `host_key_unknown_vault_locked`, `host_key_unknown_other_type_note`,
`host_key_changed_empty`, `host_key_changed_matching`, `password_first`,
`password_retry_with_save`, `passphrase`, `kbd_two_prompts`, `kbd_long_instructions`,
`certificate_unknown`, `certificate_details_page_1`, `certificate_details_page_2`,
`certificate_expired`, `certificate_changed`, `file_exists_download`,
`file_exists_upload_resume_disabled`, `file_exists_rename_invalid`,
`status_badge_two_prompts`; plus `password_60x20_scrolls` — AC1, AC7, AC13.

### Integration tests
UI-flow tests in `crates/courier-ftp/tests/prompts_flow.rs` driving `App` with
synthetic key events and a fake core event channel:
- `three_concurrent_prompts_flow` — AC4.
- `background_prompt_during_quickconnect_typing` — AC5.
- `lock_unlock_restores_prompt` — AC12.
- `password_remember_then_second_connection_silent` — AC8 (with T20's in-process server once available).

### End-to-end tests
In `courier-ftp-e2e` (T76 `PtyApp`, `#[ignore]`, `COURIER_E2E=1`), once T58 exists:
- `pty_unknown_host_key_trust_then_silent` — SFTP connect via quickconnect, answer the
  prompt with `t`, reconnect without a prompt.
- `pty_changed_host_key_enter_rejects` — AC2 against a regenerated host key.

## Out of scope

- Producing prompts (T12, T20, T21, T42) and storing trust decisions (T21, T12, T30).
- Settings screens for stored keys/certificates (T68) and the server info dialog (T57).
- Mouse interaction (D7).

## Open questions

1. **File-exists "remember":** FileZilla can also turn the chosen action into the new
   default setting, and has an "apply to current queue only" scope. T04's `ApplyTo` has
   only `Once`, `AllInQueue` and `AllForDirection` (this queue run), so the dialog offers
   no session-wide or default-changing scope. Should T04 add a session scope, or the
   dialog offer "Make this the default for downloads/uploads" (writes the T05 exists
   setting)?
2. **"Always trust" pre-checked:** the unknown host key and certificate dialogs
   pre-check "Always trust" when the vault is unlocked. Keep, or default to trust-once?

(Resolved by the coordinator: payloads and answers are T04's final types listed above.)

## Implementation notes

- **Files.** `components/prompts.rs` (the `PromptDialog` trait, `Step`, `PromptEnv`,
  `build_dialog`, `answer_from_cache`) and `components/prompts/`: `queue.rs`
  (`PromptQueue`, `PromptOrigin`, `UiFocusState`, `PromptTick`, `PromptAnswered`),
  `secrets.rs` (`SecretCache`, `PendingCredentials`, `Pending`, `SaveRequest`,
  `CredentialField`), `layout.rs` (rows, scrolling, frame, key classification shared by
  the dialogs), one file per dialog (`host_key.rs`, `certificate.rs`, `secret.rs`,
  `kbd.rs` — named for the spec's test path `prompts::kbd::tests` —, `file_exists.rs`,
  `message.rs`). All payload types exist in T04, so every dialog (certificates and
  file exists included) is built now.
- **Where the dialog lives.** The queue owns the visible prompt dialog (not the
  `ModalStack`): it is drawn after every modal, takes every key while visible
  (`App::mode()` is `Dialog` then) and opens only while no other modal is open. Prompt
  dialogs build their content as rows at the dialog width (`layout::Body`); the shared
  renderer scrolls them (keeping the focused row visible, `▲`/`▼` markers) and draws
  text fields with T52's `TextInput`/`SecretInput`. Below 30×8 (or when the body does
  not fit at all) T52's "Terminal too small" text shows and keys are ignored, so
  nothing can be answered unseen.
- **Opening is done by the tick** (`App::run_prompt_tick`, every `Tick` and after every
  key), not when the event arrives, so prompts arriving together open foreground first
  (AC4). `PromptQueue::tick` returns `Vec<PromptTick>` (several things can change in one
  tick); `Withdrawn` is reported for the visible prompt only (status message), a
  withdrawn queued prompt gives `BadgeChanged`. `PromptTick::Unchanged` is not needed.
- **Background idle rule.** "`mode == Normal`" is read as "not a text or dialog mode":
  background prompts open in `Normal`, `FileList`, `Tree`, `Log` and `Queue`, never in
  `Input`, `Filter`, `Dialog` or `SiteManager` (with the literal rule they would never
  open while a file list has the focus). Keys answered inside a prompt dialog do not
  reset the 2 s idle timer (`note_key` is called only for keys routed elsewhere), so the
  next prompt can open on the following tick (AC4).
- **Origin.** Until T61 there is one tab: a prompt is `Foreground` when its session was
  opened with `SessionPurpose::Browse` (or the app has not seen it open), `Background`
  for `Transfer`/`Search`/`Other` sessions (`App` tracks `SessionOpened`/`SessionClosed`).
  T61 must narrow this to the active tab's browsing session.
- **`SaveRequest`** has no `SiteRef` (T31 does not exist): it carries `session`, the
  prompt's `key: SecretCacheKey`, `field` and `value: Arc<SecretString>` (`Arc` because
  `Action` is `Clone`). `Action::SaveCredential` currently shows "Saving credentials in
  the vault is not available yet"; T31 replaces that arm in `App::dispatch`.
  `PendingCredentials` drops a secret on `Disconnected`/`SessionClosed` of its session,
  after 5 minutes (checked every tick), or when the answer could not be delivered.
- **Vault lock.** `App::set_vault_locked(bool)` (for T60) suspends the queue, clears the
  `SecretCache` and re-queues the visible prompt at the front (rebuilt from its payload
  when reopened). There is no lock event yet, so nothing calls it outside tests.
- **`PromptQueue::push`/`open_next`** take `now` as specified but do not need it;
  formats and the certificate clock come from `PromptQueue::set_env(PromptEnv)` (set from
  the interface settings at start and on every interface change; tests fix "now").
- **Changed key/certificate.** The typed-host-name part is `host_key::ChangedConfirm`,
  shared by both dialogs. Focus order: field → (`Details…`) → `Cancel` → `Trust once` →
  `Replace…`; `Alt-c` also cancels; `Left`/`Right` move between enabled buttons. The
  certificate variant's button reads `Replace trusted certificate`.
- **Certificate details.** `certificate::DetailsView` is shared by the prompt and the new
  `CertificateChainDialog` (a T52 `Dialog`), which T57's `[ Details ]` now opens through
  the internal `Action::CertificateChain` (T57's test was updated). Problem texts and the
  `✔`/`✘` (`ok`/`x`) marks follow the mock-ups; the role in the details title is
  `server`, `intermediate` or `root` (last certificate that is a CA or self-signed).
  `render_host_key_details` / `render_certificate_details` return unwrapped lines; the
  dialogs wrap at their width.
- **Messages and unknown kinds.** `PromptKind::Message` gets a small `OK` dialog (`Ack`
  on Enter/Esc); a future `PromptKind` variant shows "This question is not supported…"
  and answers `Cancel`.
- **Style keys** `prompt.danger` (bold red; bold in monochrome) and `prompt.ok` (green)
  were added to `config/config.json` and the theme.
- **Tests.** Unit tests as named (`prompts::queue::tests::*`, `prompts::secrets::tests::*`,
  …). The UI-flow tests are in `components/prompts/app_tests.rs` (the binary crate has
  no library a `tests/prompts_flow.rs` could import); snapshots are in
  `components/prompts/snapshots/` (crate convention) with the style legend appended, and
  include `kbd_one_prompt`. The secret-cache flow uses a fake core (no T20 server).
  `tests::Prompter` produces real `PromptRequest`s through `EventSender::prompt_with_cancel`
  on helper threads. `uuid` is a new dev-dependency (vault item ids in fixtures; already
  in the lock file).
- **Not done here:** the PTY tests `pty_unknown_host_key_trust_then_silent` and
  `pty_changed_host_key_enter_rejects` need T58's quickconnect (no way to connect from
  the TUI yet).

