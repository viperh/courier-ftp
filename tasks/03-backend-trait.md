# T03 — Backend trait

**Phase:** A Foundation · **Depends on:** T02, T04, T05 · **Crate:** `courier-ftp-core` (`backend` module) · **Decisions:** D5
**Related (integrates with, not blocking):** T31

## Goal

One async trait that FTP, SFTP and the local filesystem all implement, so the
UI, transfer engine, search and comparison code never care which protocol is in use.

## Scope

1. **Trait** (object-safe so we can hold `Box<dyn Backend>`):
   ```rust
   #[async_trait] // or native async fn + boxing helper, decide in implementation
   pub trait Backend: Send + Sync {
       fn capabilities(&self) -> Capabilities;
       fn address(&self) -> Option<&ServerAddress>;      // None for local
       async fn connect(&mut self, cancel: CancellationToken) -> Result<()>;
       async fn disconnect(&mut self) -> Result<()>;
       fn is_connected(&self) -> bool;

       async fn home_dir(&mut self) -> Result<RemotePath>;   // PWD / realpath(".")
       async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing>;
       async fn stat(&mut self, path: &RemotePath) -> Result<Entry>;

       async fn mkdir(&mut self, path: &RemotePath) -> Result<()>;
       async fn rmdir(&mut self, path: &RemotePath) -> Result<()>;
       async fn remove_file(&mut self, path: &RemotePath) -> Result<()>;
       async fn rename(&mut self, from: &RemotePath, to: &RemotePath) -> Result<()>;
       async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()>;
       async fn set_mtime(&mut self, path: &RemotePath, t: OffsetDateTime) -> Result<()>;

       async fn open_read(&mut self, path: &RemotePath, offset: u64, opts: &TransferOpts)
           -> Result<Box<dyn AsyncRead + Send + Unpin>>;
       async fn open_write(&mut self, path: &RemotePath, mode: WriteMode, opts: &TransferOpts)
           -> Result<Box<dyn AsyncWrite + Send + Unpin>>;
       async fn finish_transfer(&mut self) -> Result<()>;    // FTP: read 226 reply

       async fn raw_command(&mut self, cmd: &str) -> Result<String>;  // §4 custom command
       async fn keepalive(&mut self) -> Result<()>;
   }
   ```
   - `WriteMode { Create, Truncate, Append, ResumeAt(u64) }`.
   - `TransferOpts { transfer_type: TransferType (Ascii/Binary), preallocate_hint: Option<u64> }`.
   - `Listing { dir: RemotePath, entries: Vec<Entry>, fetched_at: Instant, raw: Option<String> }`.
2. **`Capabilities`** bitflags/struct: `chmod`, `set_mtime`, `resume_download`, `resume_upload`, `append`, `raw_commands`, `symlinks`, `server_side_rename_across_dirs`, `ascii_mode`, `parallel_connections_allowed`.
   UI greys out actions a backend can't do.
3. **One connection = one operation at a time.** A `Backend` instance is a single session. The transfer engine (T41) opens extra instances for parallel transfers. Document this.
4. **`ConnectInfo`** (defined here, not in the Site Manager): everything needed to open a session — `ServerAddress`, `Credentials`, encryption mode, charset, server type override, timezone offset, transfer mode, proxy choice (generic / FTP proxy / bypass), connection limit, key file or vault key. Quickconnect builds it directly; the Site Manager (T31) converts a saved site into it.
   **`BackendFactory`** trait in core: `fn create(&self, info: &ConnectInfo, events: EventSender) -> Box<dyn Backend>`. The binary crate implements it, matching on `Protocol` to construct the FTP or SFTP backend. Core never names the protocol crates.
5. **`SessionHandle`**: a wrapper owning a `Backend` behind a `tokio::sync::Mutex` plus a task that sends `keepalive()` every N seconds when idle (setting from T05), and transparently **reconnects** once on `Error::Connection` before failing the call (FileZilla behaviour). Re-issues `cwd` to the last directory after reconnect.

## Design notes

- Prefer native `async fn` in traits where possible; for `dyn Backend` we need boxed futures, so `async-trait` is acceptable. Pick one and document why in the module docs.
- `Backend` methods take `&mut self` because protocol sessions are stateful (current dir, data connection).
- Errors map to `core::Error` variants from T02; protocol-specific detail goes into the message.

## Acceptance criteria

- [ ] Trait, `Capabilities`, `Listing`, `WriteMode`, `TransferOpts`, `BackendFactory`, `SessionHandle` exist and are documented.
- [ ] A `MockBackend` (in-memory tree, behind `#[cfg(any(test, feature = "test-util"))]`) implements the trait; used by later tasks' tests.
- [ ] `SessionHandle` reconnect-once logic tested with the mock (simulate dropped connection).
- [ ] Keep-alive task stops when the handle is dropped (no leaked tasks).

## Tests

- MockBackend: mkdir/list/rename/remove round-trips.
- SessionHandle: first call fails with `Connection`, reconnect succeeds, call retried; second consecutive failure surfaces the error.
- Keep-alive fires after idle interval (use `tokio::time::pause`).
