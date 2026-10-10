# T04 — Event and log bus

**Phase:** A Foundation · **Depends on:** T02, T05 · **Crate:** `courier-ftp-core` (`events` module) · **FEATURES.md:** §3 message log, §9
**Related (integrates with, not blocking):** T42

## Goal

A single channel through which backends, the transfer engine and the vault
report what is happening, so the UI can show FileZilla's message log, progress,
and prompts (trust a certificate? overwrite a file?) without the core knowing about the UI.

## Scope

1. **`LogMessage`**
   ```rust
   pub struct LogMessage {
       pub time: OffsetDateTime,
       pub session: SessionId,     // which tab/connection
       pub kind: LogKind,          // Status, Command, Response, Error, ListingRaw, Debug(u8 /*1-4*/)
       pub text: String,
   }
   ```
   - `Command` text has passwords masked (`PASS ****`, SFTP never logs secrets).
   - Debug levels 0–4 mirror FileZilla: 0 none, 1 warning, 2 info, 3 verbose, 4 debug. Messages above the configured level (T05) are dropped at the source to avoid flooding the channel.
2. **`CoreEvent`** enum (core → UI):
   - `Log(LogMessage)`
   - `Connected { session, address }`, `Disconnected { session, reason }`
   - `ListingUpdated { session, dir }`
   - `TransferProgress { id, bytes_done, total, speed_bps, eta }`
   - `TransferStateChanged { id, state }`
   - `QueueFinished { stats }`
   - `Prompt(PromptRequest)` — see below
3. **Prompts (core asks the UI and waits for an answer)**
   - `PromptRequest { id, kind, reply: oneshot::Sender<PromptResponse> }`
   - Kinds: `TrustHostKey { host, key_type, fingerprint_sha256, known: Option<old fingerprint> }`, `TrustCertificate { details }`, `Password { for_ }`, `KeyPassphrase { path }`, `KeyboardInteractive { name, instructions, prompts: Vec<(String, echo: bool)> }`, `FileExists { .. }` (T42), `Message(String)`.
   - If the UI drops the sender, the core treats it as "cancel".
   - Timeout: none (user may be away), but the operation's `CancellationToken` cancels the wait.
4. **`EventSender`/`EventReceiver`**: `tokio::sync::mpsc` unbounded for prompts/state, plus **coalescing** for `TransferProgress` (only the latest value per transfer per UI frame matters — use a `watch` channel or a dedup map so a fast transfer cannot fill memory).
5. Bridge to the binary: the app's main loop selects on the event receiver and converts events into `Action`s (done in T50; here only provide the receiver).

## Acceptance criteria

- [x] Types exist, documented, `Send + 'static`.
- [x] Password masking helper `mask_command(&str) -> Cow<str>` covers `PASS`, `ACCT`, and proxy `USER`/`PASS` variants used by T15.
- [x] Progress coalescing proven: 10 000 progress updates without a consumer keep memory bounded.
- [x] Prompt round-trip works; dropped sender → `Error::Cancelled`.

## Tests

- `mask_command("PASS hunter2") == "PASS ****"`, case-insensitive, leaves `PASV` alone.
- Prompt answered → caller receives answer; prompt cancelled via token → `Cancelled`.
- Log level filter drops debug messages when level = 2.
