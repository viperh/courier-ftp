# T04 — Event and log bus

**Phase:** A Foundation · **Milestone:** M1 · **Depends on:** T02, T05 · **Crate(s):** `courier-ftp-core` (`events` module) · **Decisions:** D3 · **FEATURES.md:** §3 (message log), §9 (debug levels)
**Related (integrates with, not blocking):** T42

## Goal

A single channel through which backends, the transfer engine, the vault and the sync engine
report what is happening, so the UI can show FileZilla's message log, progress and
prompts (trust a host key? enter a password? overwrite a file?) without core knowing
about the UI. Progress updates are coalesced so a fast transfer cannot flood memory, and
prompts are request/response pairs that cancel cleanly.

## Context

- Before: T02 (ids, `Entry`, `ServerAddress`, `ServerIdentity`, `Direction`, `RemotePath`,
  `SecretString`, `Error`) and T05 (`DebugLevel`, `ExistsAction`, `logging.level`).
- After: T03 (`SessionHandle` emits connection events, `BackendContext` carries an
  `EventSender`), T07/T10–T15/T20–T22 (session log lines, prompts), T41–T45 (progress,
  queue events, file-exists prompt), T46 (`ListingUpdated`), T50 (bridge into `Action`s),
  T55 (message log), T69 (prompt dialogs), T71 (log file), T88 (sync status, toasts).

## Technical specification

### Types and APIs

Module `courier_ftp_core::events` (`events/{mod,ids,log,prompt,channel,mask}.rs`).

```rust
/// One connection/session (a tab's browsing session, a transfer worker, a search session).
/// Process-local, never persisted. 0 = the application itself (vault, config, sync).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);
impl SessionId {
    pub const APP: SessionId = SessionId(0);
    /// Next id from a process-wide AtomicU64 starting at 1.
    pub fn next() -> Self;
    pub fn get(self) -> u64;
}
/// Queue item id. Assigned by the queue (T40), which reuses this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TransferId(pub u64);
/// Long-running non-transfer operation (recursive delete/chmod, search, import).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(pub u64);       // OperationId::next() like SessionId
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PromptId(u64);

// ---- message log ----
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogKind {
    Status, Command, Response, Error,
    /// Raw listing line (only produced when logging.show_raw_listing, T71).
    ListingRaw,
    /// FileZilla "Trace" lines; level 1..=4 (= DebugLevel Warning..=Debug as u8).
    Debug(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogMessage {
    pub time: OffsetDateTime,       // UTC; the UI formats it in local time
    pub session: SessionId,
    pub kind: LogKind,
    /// One line, sanitised (see Behaviour), ≤ 4096 chars.
    pub text: String,
}

// ---- events ----
#[derive(Debug)]
#[non_exhaustive]
pub enum CoreEvent {
    Log(LogMessage),
    /// A session was created (T03); `label` = site name or "user@host" for the UI.
    SessionOpened { session: SessionId, purpose: SessionPurpose, label: String },
    SessionClosed { session: SessionId },
    Connecting { session: SessionId },
    Connected { session: SessionId, address: ServerAddress },
    Disconnected { session: SessionId, reason: DisconnectReason },
    /// Backend capabilities changed (e.g. SITE CHMOD rejected, T14) — UI re-reads them.
    CapabilitiesChanged { session: SessionId },
    /// A cached listing changed (T46). `server` None = local filesystem.
    ListingUpdated { server: Option<ServerIdentity>, dir: RemotePath },
    /// Coalesced: at most one pending per TransferId (see Behaviour).
    TransferProgress(TransferProgress),
    /// Queue item state changed; the UI reads the new state from the queue (T40).
    TransferStateChanged { id: TransferId },
    /// Items added/removed/reordered (T40).
    QueueChanged,
    /// The queue ran and is now empty of queued and active items (T41/T45).
    QueueFinished { stats: QueueStats },
    OperationProgress { id: OperationId, text: String, done: u64, total: Option<u64> },
    OperationFinished { id: OperationId, error: Option<String> },
    /// Transient user-facing notice (toast / status-bar message): connection limit lowered,
    /// sync clock skew, resurrected item (T41, T88).
    Notice { level: NoticeLevel, text: String },
    Prompt(PromptRequest),
    // T88 adds `Sync(SyncStatus)`; the enum is non_exhaustive for that reason.
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPurpose { Browse, Transfer, Search, Other }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// disconnect() was called (user, tab closed, queue finished with Disconnect).
    Requested,
    /// The connection dropped; message = Error Display text.
    Lost(String),
    /// Connecting failed (after retries).
    Failed(String),
}
#[derive(Clone, Debug, PartialEq)]
pub struct TransferProgress {
    pub id: TransferId,
    pub bytes_done: u64,
    pub total: Option<u64>,
    /// Exponential moving average (T41), bytes per second.
    pub speed_bps: u64,
    pub eta: Option<Duration>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueStats { pub files_ok: u64, pub files_failed: u64, pub bytes: u64, pub duration: Duration }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeLevel { Info, Warning, Error }

// ---- prompts ----
/// A question to the user. The requester awaits the answer; dropping the requester
/// withdraws the prompt (the UI sees `is_withdrawn()` and closes the dialog).
pub struct PromptRequest { pub id: PromptId, pub session: SessionId, pub kind: PromptKind, /* reply: oneshot::Sender<PromptResponse> */ }
impl PromptRequest {
    /// Send the answer. Returns false when the requester is gone.
    pub fn respond(self, response: PromptResponse) -> bool;
    /// The requester gave up (operation cancelled, connection closed).
    pub fn is_withdrawn(&self) -> bool;
}
impl fmt::Debug for PromptRequest;   // id, session, kind (kinds hold no secrets)

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum PromptKind {
    TrustHostKey(HostKeyPrompt),                 // T21
    TrustCertificate(Box<CertificatePrompt>),    // T12
    Password(PasswordPrompt),                    // T15, T20, T07, T10
    KeyPassphrase(PassphrasePrompt),             // T20
    KeyboardInteractive(KbdInteractivePrompt),   // T20
    FileExists(Box<FileExistsPrompt>),           // T42
    Message(MessagePrompt),                      // informational, answered with Ack
}
#[derive(Clone, Debug, PartialEq)]
pub struct HostKeyPrompt {
    pub host: String, pub port: u16,
    pub key_type: String,                 // "ssh-ed25519"
    pub key_bits: Option<u32>,
    pub fingerprint_sha256: String,       // "SHA256:<base64, no padding>"
    pub fingerprint_md5: String,          // "MD5:aa:bb:…"
    /// Set when a different key of the same type is stored: the changed-key warning (T69).
    pub known: Option<KnownHostKey>,
    /// false when the vault is locked: "Always trust" is disabled (T21 §4).
    pub can_store: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub struct KnownHostKey { pub key_type: String, pub fingerprint_sha256: String }
#[derive(Clone, Debug, PartialEq)]
pub struct CertificatePrompt {
    pub host: String, pub port: u16,
    pub chain: Vec<CertificateInfo>,      // leaf first
    pub tls_version: String,              // "TLS 1.3"
    pub cipher_suite: String,
    pub hostname_matches: bool,
    /// Human-readable verification problems: "expired", "self-signed", "unknown issuer", …
    pub problems: Vec<String>,
    /// SHA-256 of a previously "always trusted" certificate for this host:port (changed-cert warning).
    pub previously_trusted_sha256: Option<String>,
    pub can_store: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateInfo {
    pub subject: String, pub issuer: String,
    pub not_before: OffsetDateTime, pub not_after: OffsetDateTime,
    pub serial_hex: String,
    pub sha256: String, pub sha1: String,  // "AB:CD:…"
    pub subject_alt_names: Vec<String>,
    pub key_algorithm: String, pub key_bits: Option<u32>,
    pub signature_algorithm: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordPrompt {
    pub purpose: PasswordPurpose,
    /// "user@host:port" or the proxy "host:port" (shown in the dialog).
    pub target: String,
    pub can_remember: bool,               // "Remember for this session"
    pub can_save: bool,                   // "Save in vault" (vault unlocked and store_passwords)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordPurpose { Login, Account, Proxy, FtpProxy }
#[derive(Clone, Debug, PartialEq)]
pub struct PassphrasePrompt { pub key: String /* path or "vault key <name>" */, pub attempt: u8 /* 1..=3 */, pub can_save: bool }
#[derive(Clone, Debug, PartialEq)]
pub struct KbdInteractivePrompt { pub name: String, pub instructions: String, pub fields: Vec<KbdField> }
#[derive(Clone, Debug, PartialEq)]
pub struct KbdField { pub text: String, pub echo: bool }
#[derive(Clone, Debug, PartialEq)]
pub struct FileExistsPrompt {
    pub direction: Direction,
    pub source_path: String, pub source: Entry,
    pub target_path: String, pub target: Entry,
    pub can_resume: bool,                 // backend capability + binary type (T42)
}
#[derive(Clone, Debug, PartialEq)]
pub struct MessagePrompt { pub level: NoticeLevel, pub title: String, pub text: String }

/// The user's answer. Must match the prompt kind (see Behaviour).
#[non_exhaustive]
pub enum PromptResponse {
    Trust(TrustDecision),                                      // TrustHostKey, TrustCertificate
    Secret { value: SecretString, remember: Remember },        // Password, KeyPassphrase
    KeyboardInteractive(Vec<SecretString>),                    // one per field, same order
    FileExists { action: ExistsAction, apply_to: ApplyTo, new_name: Option<String> },
    Ack,                                                       // Message
    Cancel,                                                    // any kind
}
impl fmt::Debug for PromptResponse;   // secrets as [REDACTED]
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum TrustDecision { Once, Always, Reject }
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Remember { No, Session, Vault }
/// Scope of a file-exists answer (T42).
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ApplyTo { Once, AllInQueue, AllForDirection }

// ---- channel ----
pub fn channel(level: DebugLevel) -> (EventSender, EventReceiver);

#[derive(Clone)]
pub struct EventSender { /* Arc<Shared> */ }
impl EventSender {
    /// Never blocks and never fails; events are discarded when the receiver is gone.
    pub fn send(&self, event: CoreEvent);
    /// Applies the level filter, splits on '\n', sanitises, truncates, timestamps.
    pub fn log(&self, session: SessionId, kind: LogKind, text: impl AsRef<str>);
    /// `log(Command, mask_command(cmd))`.
    pub fn log_command(&self, session: SessionId, cmd: &str);
    /// Cheap check before formatting expensive debug text.
    pub fn enabled(&self, level: u8) -> bool;           // same rule as Debug(level)
    pub fn set_level(&self, level: DebugLevel);      // runtime change (T68, T71)
    pub fn level(&self) -> DebugLevel;
    pub fn progress(&self, p: TransferProgress);     // coalescing slot
    /// Sends TransferStateChanged and discards pending progress for `id`.
    pub fn transfer_state(&self, id: TransferId);
    /// Ask the UI. Errors: Cancelled (no UI, withdrawn, or user cancelled),
    /// Internal (response kind does not match the prompt kind).
    pub async fn prompt(&self, session: SessionId, kind: PromptKind) -> Result<PromptResponse>;
    /// As `prompt`, but also returns Cancelled as soon as `cancel` fires.
    pub async fn prompt_with_cancel(&self, session: SessionId, kind: PromptKind,
                                    cancel: &CancellationToken) -> Result<PromptResponse>;
    pub fn is_closed(&self) -> bool;
}
pub struct EventReceiver { /* … */ }
impl EventReceiver {
    /// Next event; None when every EventSender is dropped and nothing is pending.
    pub async fn recv(&mut self) -> Option<CoreEvent>;
    pub fn try_recv(&mut self) -> Option<CoreEvent>;
}

/// Convenience for code that logs for one session (backends, net layer).
#[derive(Clone)]
pub struct SessionLog { pub events: EventSender, pub session: SessionId }
impl SessionLog {
    pub fn status(&self, t: impl AsRef<str>); pub fn error(&self, t: impl AsRef<str>);
    pub fn command(&self, cmd: &str);         // masked
    pub fn response(&self, t: impl AsRef<str>);
    pub fn listing(&self, t: impl AsRef<str>);
    pub fn debug(&self, level: u8, t: impl AsRef<str>);   // 1..=4
    pub fn enabled(&self, level: u8) -> bool;           // same rule as Debug(level)
}

// ---- masking (events::mask) ----
/// "PASS hunter2" → "PASS ****"; "ACCT x" → "ACCT ****";
/// "Proxy-Authorization: Basic …" → "Proxy-Authorization: ****". Otherwise unchanged.
pub fn mask_command(line: &str) -> Cow<'_, str>;
/// Replace every occurrence of `secret` (if non-empty) with "****" (T15 custom proxy scripts).
pub fn mask_secret<'a>(text: &'a str, secret: &str) -> Cow<'a, str>;
```

All public types are `Send + 'static`; `EventSender` and `SessionLog` are `Sync`.

### Behaviour

**Log levels** (FileZilla semantics): `Status`, `Command`, `Response`, `Error` and
`ListingRaw` lines are always delivered. `Debug(l)` lines are delivered only when
`l ≤ current level as u8` (so level 0 = `None` delivers none); `Debug(0)` and values > 4
are clamped to 1 and 4. Filtered lines are dropped inside `EventSender::log` before any
allocation of the `LogMessage`. The level is an `AtomicU8` shared by all clones;
`set_level` takes effect for the next call.

**Warnings:** there is no separate warning kind (FileZilla has none either). User-visible
warnings (plain-text fallback T12, charset switch T10, …) are logged as `Status` with the
text prefixed `Warning: `; T55 may colour lines with that prefix.

**Sanitising** (in `log`, so the UI, the session log file (T71) and copies are safe):
1. Split the text on `'\n'`; strip one trailing `'\r'` per line; each line becomes its own
   `LogMessage` with the same kind and time. Empty trailing line is dropped.
2. Replace control characters: C0 (U+0000–U+001F except TAB) and DEL become caret notation
   (`ESC` → `^[`, NUL → `^@`, DEL → `^?`); C1 (U+0080–U+009F) becomes `\u{9b}` style escapes;
   TAB stays.
3. Truncate to 4096 characters, appending `…` when cut.

**Masking:** `mask_command` looks at the first whitespace-delimited token, compared
ASCII-case-insensitively: `PASS` and `ACCT` → `<token as written> ****` (also when the
argument is empty); `PASV`, `PASSWD`-like other tokens are untouched. A line starting with
`Proxy-Authorization:` (case-insensitive) → `Proxy-Authorization: ****`. Leading
whitespace is preserved. Producers that send secrets inside other commands (T15 custom
scripts, `SITE` commands with `%p`) must call `mask_secret` with the secret.

**Progress coalescing:** `progress()` stores the value in a per-`TransferId` slot
(`Mutex<BTreeMap<TransferId, TransferProgress>>`), replacing any pending value, and wakes
the receiver. `recv()` returns queued normal events first (FIFO); when none are queued it
returns one pending progress value (lowest id first) and removes it from the map. So memory
is bounded by the number of distinct active transfers. `transfer_state(id)` removes the
pending progress for `id` before queuing `TransferStateChanged`, so no stale progress
follows a state change. Producers rate-limit to 10 Hz per transfer (T41); the bus does not.

**Log flood protection:** at most 10 000 `Log` events may be queued. Further log lines are
counted and dropped; the first log line accepted after the queue drains below 10 000 is
preceded by `Status: <n> log messages dropped (message log could not keep up)`. Non-log
events are never dropped (they are low-rate by design).

**Prompts:**
1. `prompt()` creates a oneshot, assigns a `PromptId`, sends `CoreEvent::Prompt` and awaits.
2. No receiver (headless without an auto-responder) → `Err(Cancelled)` immediately.
3. The UI drops the request or answers `Cancel` → `Err(Cancelled)`.
4. Dropping the `prompt()` future (the operation was cancelled, see T03 cancellation rules)
   closes the oneshot; `PromptRequest::is_withdrawn()` becomes true and the UI removes the
   dialog (T69). `prompt_with_cancel` does the same when the token fires.
5. No timeout: the user may be away.
6. Answer/kind compatibility: `Trust` ↔ TrustHostKey/TrustCertificate; `Secret` ↔
   Password/KeyPassphrase; `KeyboardInteractive` ↔ KeyboardInteractive with exactly
   `fields.len()` values; `FileExists` ↔ FileExists with `action ≠ Ask` and `new_name`
   present iff `action = Rename`; `Ack` ↔ Message; `Cancel` ↔ any. Anything else →
   `Err(Internal)` and an `error!` trace.
7. Ordering and one-at-a-time display are the UI's job (T69); the bus delivers in send order.

**Bridge:** the binary's main loop (T50) owns the `EventReceiver` and `select!`s on it; this
task only provides the receiver. Headless users (T76) drain it in a task and answer prompts
with a scripted responder.

### Data formats and configuration

- Settings read: `logging.level` (initial `DebugLevel` passed to `channel`; T68/T71 call
  `set_level`).
- No persisted formats. `LogMessage` is written to a file only by T71, which defines that format.

### Errors

- `prompt()`: `Error::Cancelled` (see above), `Error::Internal` for mismatched responses.
- `send`/`log`/`progress` never fail.

### Security and logging

- `LogMessage.text` passes through `mask_command` for commands; secrets must never be passed
  to `log` (T91 canary tests scan the session log file, T71).
- `PromptKind` carries no secrets; `PromptResponse` holds them only as `SecretString`, and
  its `Debug` is redacted. The UI zeroizes its input buffers (T52/T69).
- Server-supplied strings (`KbdInteractivePrompt` texts, certificate fields, replies) are
  untrusted: log lines are sanitised here; prompt texts are sanitised by the UI at render (T69).
- This module emits no `tracing` events at info+ (session log lines can contain hostnames,
  which are fine in the user-facing message log but not in the app log, T91 §4).

## Implementation steps

1. `events::ids` (`SessionId`, `TransferId`, `OperationId`, `PromptId`) and `events::mask`
   with tests.
2. `LogKind`, `LogMessage`, sanitising helper with tests.
3. `CoreEvent` and the prompt types (`PromptKind`, responses, `PromptRequest`).
4. `channel()`: `EventSender`/`EventReceiver` with level filter, flood protection and
   progress coalescing; `SessionLog`.
5. `prompt()` / `prompt_with_cancel()` with compatibility checks.
6. Compile-time `Send + 'static` assertions and rustdoc.

## Acceptance criteria

- [ ] AC1 All types exist with rustdoc and are `Send + 'static` (compile-time assertion test).
- [ ] AC2 `mask_command` covers `PASS`, `ACCT` (any case), empty arguments and
  `Proxy-Authorization`, and leaves `PASV`, `PWD`, `USER` untouched; `mask_secret` masks every
  occurrence.
- [ ] AC3 With level 2, `Debug(3)` and `Debug(4)` lines are not delivered and
  `Debug(1)`/`Debug(2)` are; level 0 delivers no debug lines; Status/Command/Response/
  Error always delivered.
- [ ] AC4 10 000 progress updates for 3 transfers without a consumer leave at most 3 pending
  progress values; the consumer then receives exactly the latest value per transfer.
- [ ] AC5 After `transfer_state(id)` the receiver gets no older progress for `id`.
- [ ] AC6 20 000 log lines without a consumer keep ≤ 10 000 queued and produce one
  "messages dropped" Status line once drained.
- [ ] AC7 Prompt answered → caller receives the answer; dropped request, `Cancel`, no receiver,
  and a fired token each give `Error::Cancelled`; withdrawing makes `is_withdrawn()` true
  within one scheduler tick.
- [ ] AC8 Control characters in log text are rendered in caret notation; multi-line text
  becomes one message per line; lines are capped at 4096 chars.
- [ ] AC9 `format!("{:?}", PromptResponse::Secret{..})` does not contain the secret.
- [ ] AC10 T00 CI gates pass.

## Tests

### Unit tests
- `mask_command_masks_pass_and_acct` — `"PASS hunter2"`→`"PASS ****"`, `"pass x"`→`"pass ****"`, `"ACCT 123"`→`"ACCT ****"`, `"PASS"`→`"PASS ****"`. (AC2)
- `mask_command_leaves_other_commands` — `PASV`, `PWD`, `USER alice`, `SITE CHMOD 644 PASS` unchanged. (AC2)
- `mask_command_masks_proxy_authorization`. (AC2)
- `mask_secret_replaces_all_occurrences` and `mask_secret_empty_secret_noop`. (AC2)
- `log_level_filter_table` — levels 0..=4 × LogKind (incl. `Debug(0)`/`Debug(9)` clamping). (AC3)
- `set_level_applies_to_clones`. (AC3)
- `sanitise_control_chars_caret_notation` — `"a\x1b[31mb"` → `"a^[[31mb"`, `"\u{9b}"` → `"\u{9b}"` escape text, TAB kept. (AC8)
- `multiline_text_splits_into_messages` — `"a\r\nb\n"` → two messages. (AC8)
- `long_line_truncated_to_4096_chars`. (AC8)
- `prompt_response_debug_redacted`. (AC9)
- `events_types_are_send_static` — `fn assert_send_static<T: Send + 'static>()` for each public type. (AC1)

### Property / fuzz tests
- `prop_sanitised_text_has_no_control_chars` — random strings → output has no C0/C1 except TAB, length ≤ 4097 chars. (AC8)

### Snapshot tests
Not applicable.

### Integration tests
(in-crate async tests with `#[tokio::test(start_paused = true)]`)
- `progress_coalescing_bounds_memory` — 10 000 updates × 3 ids, then drain: 3 progress events with the last values. (AC4)
- `transfer_state_discards_stale_progress`. (AC5)
- `log_flood_is_bounded_and_reported`. (AC6)
- `prompt_roundtrip_answer` — a responder task answers `Trust(Always)`. (AC7)
- `prompt_dropped_request_is_cancelled`, `prompt_cancel_response_is_cancelled`, `prompt_without_receiver_is_cancelled`, `prompt_with_cancel_token_fires`. (AC7)
- `dropping_prompt_future_withdraws_request` — `is_withdrawn()` true after the requester future is dropped. (AC7)
- `prompt_mismatched_response_is_internal_error`. (AC7)
- `receiver_returns_none_after_all_senders_dropped`. (AC1)

### End-to-end tests
Not applicable (T76 Headless exercises the bus with real backends).

## Out of scope

- Rendering of log lines and prompts (T55, T69), the session log file (T71).
- Sync status types (T88 adds a `CoreEvent::Sync` variant).
- Converting events into UI `Action`s (T50).

## Open questions

None.
