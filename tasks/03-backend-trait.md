# T03 — Backend trait

**Phase:** A Foundation · **Milestone:** M1 · **Depends on:** T02, T04, T05 · **Crate(s):** `courier-ftp-core` (`backend` module) · **Decisions:** D5, D11 · **FEATURES.md:** §1 (keep-alive, reconnect, retries), §4
**Related (integrates with, not blocking):** T31
**Reference:** sverb `crates/sverb-conn/src/transport.rs` (async-trait object-safe trait, connector), `crates/sverb-conn/src/mock.rs` (`test-util` mock)

## Goal

One async trait that FTP/FTPS, SFTP and the local filesystem all implement, so the UI,
transfer engine, search, comparison and recursive operations never care which protocol is
in use. Around it: `ConnectInfo` (everything needed to open a session), `BackendFactory`
(protocol choice lives in the binary, D5), `SessionHandle` (keep-alive, reconnect-once,
retries, cancellation), an in-memory `MockServer`/`MockBackend`, and a reusable backend
conformance suite.

## Context

- Before: T02 (paths, `Entry`, `ServerAddress`, `LogonType`, `Charset`, `Error`), T04
  (`EventSender`, `SessionId`, `CoreEvent`, prompts), T05 (`SharedSettings`,
  `connection.*` keys).
- After: T06 (`LocalBackend`), T14 (`FtpBackend`), T22 (`SftpBackend`) implement `Backend`;
  T58 implements `BackendFactory` in the binary (SFTP arm), T14 adds the FTP arm; T31
  builds `ConnectInfo` from a saved site; T41/T41b create backends through the factory and
  pool `Box<dyn Backend>` directly (their own retry/limit logic); browsing, search and
  recursive operations (T43/T46/T48/T49/T53/T62) use `SessionHandle`; T76 runs the conformance
  suite against every real server profile.

## Technical specification

### Types and APIs

Module `courier_ftp_core::backend` (`backend/{mod,types,connect_info,factory,session,mock,conformance}.rs`).

**Async style:** `#[async_trait::async_trait]`. Native `async fn` in traits (stable since
1.75) is not dyn-compatible, and we need `Box<dyn Backend>` chosen at runtime; the boxed
future per call is negligible next to network I/O. sverb uses the same approach.

**Cancellation convention (applies to all of core):** the two long-running methods,
`connect` (may wait for user prompts) and `list` (large directories), take a
`CancellationToken` and must return `Error::Cancelled` within 100 ms of it firing. All other
methods are cancelled by dropping their future. Top-level entry points (`SessionHandle`
methods, engine tasks) take `&CancellationToken`, pass child tokens to `connect`/`list`, and
`select!` on the token for the rest. Every backend must stay consistent when a future is
dropped at any `.await`: afterwards it is either usable or reports
`is_connected() == false` (the `SessionHandle` then reconnects).
Every network wait inside a backend is bounded by `connection.timeout_secs` of inactivity
(FileZilla semantics: no data for N seconds), so nothing hangs forever even without a token.

```rust
pub type ReadStream = Box<dyn AsyncRead + Send + Unpin>;
pub type WriteStream = Box<dyn AsyncWrite + Send + Unpin>;

/// One session (one control connection / SSH connection / local handle).
/// One operation at a time (`&mut self`); parallel work uses several instances (T41).
#[async_trait]
pub trait Backend: Send {
    /// Current capabilities. Valid after `connect`; may shrink during a session
    /// (e.g. SITE CHMOD rejected → chmod = false and CoreEvent::CapabilitiesChanged).
    fn capabilities(&self) -> Capabilities;
    /// None for the local backend.
    fn address(&self) -> Option<&ServerAddress>;
    fn is_connected(&self) -> bool;
    /// For the status-bar lock and the server info dialog (T57). Before connect:
    /// `SessionSecurityInfo::default()`.
    fn security_info(&self) -> SessionSecurityInfo;

    /// Open the session: TCP/proxy (T07), TLS/SSH, host-key/cert trust and login prompts (T04).
    async fn connect(&mut self, cancel: CancellationToken) -> Result<()>;
    /// Polite close (FTP QUIT with 2 s wait, SSH disconnect). Never fails because the peer is gone.
    async fn disconnect(&mut self) -> Result<()>;

    /// Initial directory after login (FTP PWD, SFTP realpath("."), local home).
    async fn home_dir(&mut self) -> Result<RemotePath>;
    /// List `dir`. NotFound / PermissionDenied when the server says so.
    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing>;
    /// Metadata of one path. Does NOT follow a final symlink, but fills `target_kind`.
    async fn stat(&mut self, path: &RemotePath) -> Result<Entry>;

    /// Create one directory (parent must exist). AlreadyExists if present.
    async fn mkdir(&mut self, path: &RemotePath) -> Result<()>;
    /// Remove one empty directory.
    async fn rmdir(&mut self, path: &RemotePath) -> Result<()>;
    /// Remove a file or a symlink (never its target).
    async fn remove_file(&mut self, path: &RemotePath) -> Result<()>;
    /// `replace = false`: AlreadyExists if `to` exists (checked with stat where the protocol
    /// has no atomic no-replace rename). `replace = true`: an existing file at `to` is replaced.
    async fn rename(&mut self, from: &RemotePath, to: &RemotePath, replace: bool) -> Result<()>;
    /// `mode` & 0o7777. Unsupported unless capabilities().chmod.
    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()>;
    /// Unsupported unless capabilities().set_mtime.
    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()>;

    /// Start reading at `offset` (offset > 0 needs capabilities().resume_download).
    async fn open_read(&mut self, path: &RemotePath, offset: u64, opts: &TransferOpts) -> Result<ReadStream>;
    async fn open_write(&mut self, path: &RemotePath, mode: WriteMode, opts: &TransferOpts) -> Result<WriteStream>;
    /// End the open transfer (see "Transfer protocol"). FTP reads the 226 / does ABOR.
    async fn finish_transfer(&mut self, end: TransferEnd) -> Result<()>;

    /// Custom command (§4, FTP only). Returns the reply lines joined with '\n'.
    async fn raw_command(&mut self, cmd: &str) -> Result<String>;
    /// Keep an idle connection alive (FTP T10 random command, SFTP no-op/realpath).
    async fn keepalive(&mut self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferEnd { Complete, Abort }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteMode {
    /// Target does not exist (decided by T42). Local/SFTP: exclusive create (AlreadyExists
    /// if it appeared meanwhile). FTP has no exclusive create and behaves like Truncate.
    Create,
    /// Create or truncate to 0.
    Truncate,
    /// Append at the end (needs capabilities().append).
    Append,
    /// Truncate to `n` bytes, then write from `n` (needs resume_upload). Error InvalidInput
    /// if the existing file is shorter than `n` (local/SFTP/mock; FTP cannot check).
    ResumeAt(u64),
    /// Write from `n` without truncating; creates the file if missing (needs positional_writes;
    /// used for segmented uploads/downloads, T41b).
    WriteAt(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferOpts {
    pub transfer_type: TransferType,      // Ascii only matters for FTP (T11)
    /// Writes: reserve this many bytes up front (local backend, T06). None = don't.
    pub preallocate_hint: Option<u64>,
    /// Reads: stop after this many bytes (EOF). Used by segmented downloads (T41b).
    pub range_len: Option<u64>,
}
impl Default for TransferOpts; // Binary, None, None

#[derive(Clone, Debug, PartialEq)]
pub struct Listing {
    pub dir: RemotePath,
    /// Unsorted. Never contains "."/".."; every name satisfies Entry::is_valid_name;
    /// no duplicate names (first one kept).
    pub entries: Vec<Entry>,
    pub fetched_at: tokio::time::Instant,
    /// Raw server text (FTP LIST/MLSD, SFTP longnames) for T71; None for local.
    pub raw: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub chmod: bool,
    pub set_mtime: bool,
    /// open_read with offset > 0 (FTP REST STREAM; SFTP, local always). Also "ranged reads" (T41b).
    pub resume_download: bool,
    /// WriteMode::ResumeAt.
    pub resume_upload: bool,
    pub append: bool,
    pub raw_commands: bool,
    pub symlinks: bool,
    pub server_side_rename_across_dirs: bool,
    /// The backend converts line endings for TransferType::Ascii (FTP only).
    pub ascii_mode: bool,
    pub parallel_connections_allowed: bool,
    /// WriteMode::WriteAt.
    pub positional_writes: bool,
    /// Names differing only in case are the same file (local Windows/macOS, DOS-style FTP). T48.
    pub case_insensitive_names: bool,
    pub path_style: PathStyle,
}
impl Capabilities { pub const NONE: Capabilities; /* all false, Unix */ }

/// What the status-bar lock and the server info dialog (T57) show for a session.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SessionSecurityInfo {
    /// Control/SSH channel encrypted.
    pub encrypted: bool,
    /// Short label: "TLS 1.3", "SSH", "plain", "local".
    pub summary: String,
    /// The connected peer (server, or the proxy when proxied, T07). None for local.
    pub peer_addr: Option<SocketAddr>,
    /// FTP greeting / SYST, SSH version string (sanitised).
    pub server_software: Option<String>,
    /// FTPS: negotiated TLS session incl. certificate chain (T12; T04 type).
    pub tls: Option<TlsSessionInfo>,
    /// SFTP: host key summary (T21; T04 type).
    pub host_key: Option<HostKeyInfo>,
    /// Other label/value rows in display order: FEAT summary, SSH kex/cipher/MAC/compression,
    /// data-channel protection, auth method.
    pub details: Vec<(String, String)>,
}
```

**ConnectInfo** (defined here, not in the Site Manager; T58 builds it from quickconnect,
T31 from a saved site, T70 from the command line):

```rust
/// Everything needed to open sessions to one server. Shared as Arc<ConnectInfo> by every
/// session to that server (browsing + transfer workers). Holds secrets → no Clone/Serialize.
pub struct ConnectInfo {
    pub address: ServerAddress,          // includes user and FTP encryption
    pub logon: LogonType,                // KeySource::VaultItem must already be resolved to Inline
    /// Tab/log title: site name or "user@host".
    pub label: String,
    /// The vault item of the saved site; None for quickconnect/CLI.
    pub site_id: Option<uuid::Uuid>,
    pub charset: Charset,
    pub server_type: ServerTypeOverride,
    /// Server time zone offset for LIST times, −1440..=1440 (T13).
    pub timezone_offset_minutes: i32,
    pub transfer_mode: TransferModeOverride,   // FTP
    pub proxy: ProxyChoice,
    /// Generic proxy password from the vault (proxy.generic.password_ref), if any.
    pub proxy_password: Option<SecretString>,
    /// FTP proxy password (proxy.ftp_proxy.password_ref), if any (T15).
    pub ftp_proxy_password: Option<SecretString>,
    /// Per-site connection limit, 1..=10 (T31, T41). None = global limits only.
    pub limit_connections: Option<u8>,
    /// CWD after login (site default remote dir, URL path, bookmark).
    pub initial_remote_dir: Option<RemotePath>,
    pub try_agent_first: bool,           // SFTP, T20
}
impl ConnectInfo {
    /// Defaults for everything except address and logon (quickconnect).
    pub fn quick(address: ServerAddress, logon: LogonType) -> Self;
    /// InvalidInput: logon not valid for protocol, unresolved KeySource::VaultItem,
    /// limit_connections 0 or > 10, offset out of range.
    pub fn validate(&self) -> Result<()>;
}
impl fmt::Debug for ConnectInfo;        // secrets as [REDACTED]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferModeOverride { #[default] Default, Active, Passive }
/// Site "Bypass proxy" (T31). Default = use settings.proxy (generic or FTP proxy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyChoice { #[default] Default, Bypass }
```

**Factory:**

```rust
/// What every backend instance gets from its creator.
#[derive(Clone)]
pub struct BackendContext {
    pub session: SessionId,
    pub events: EventSender,
    pub settings: SharedSettings,       // read once at connect for network settings
}
impl BackendContext { pub fn log(&self) -> SessionLog; }

/// Implemented by the binary (T58: SFTP, T14: FTP), matching on address.protocol.
/// Core never names the protocol crates. Trust stores (T12/T21) are owned by the factory.
pub trait BackendFactory: Send + Sync {
    /// Construct (not connect). Errors: InvalidInput (ConnectInfo::validate),
    /// Unsupported (protocol not available in this build).
    fn create(&self, info: Arc<ConnectInfo>, ctx: BackendContext) -> Result<Box<dyn Backend>>;
}
```

**SessionHandle:**

```rust
#[derive(Clone, Copy, Debug)]
pub struct SessionOptions {
    pub purpose: SessionPurpose,
    /// Reconnect once when an operation fails with is_connection_lost(). Default true.
    pub reconnect: bool,
    /// Run the keep-alive task (also requires settings connection.keepalive). Default true.
    pub keepalive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState { Disconnected, Connecting, Connected, Reconnecting, Failed(String) }

/// A Backend behind a tokio Mutex, plus keep-alive and reconnect logic. Clone = same session.
#[derive(Clone)]
pub struct SessionHandle { /* Arc<Inner> */ }
impl SessionHandle {
    /// Emits SessionOpened; spawns the keep-alive task. Does not connect.
    pub fn new(backend: Box<dyn Backend>, ctx: BackendContext, opts: SessionOptions, label: String) -> Self;
    pub fn id(&self) -> SessionId;
    pub fn state(&self) -> SessionState;
    pub fn watch_state(&self) -> tokio::sync::watch::Receiver<SessionState>;
    /// Copy refreshed after every operation.
    pub fn capabilities(&self) -> Capabilities;
    pub fn security_info(&self) -> SessionSecurityInfo;

    /// Connect with retries (see Behaviour).
    pub async fn connect(&self, cancel: &CancellationToken) -> Result<()>;
    pub async fn disconnect(&self) -> Result<()>;

    pub async fn home_dir(&self, cancel: &CancellationToken) -> Result<RemotePath>;
    pub async fn list(&self, dir: &RemotePath, cancel: &CancellationToken) -> Result<Listing>;
    pub async fn stat(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<Entry>;
    pub async fn mkdir(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()>;
    pub async fn rmdir(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()>;
    pub async fn remove_file(&self, path: &RemotePath, cancel: &CancellationToken) -> Result<()>;
    pub async fn rename(&self, from: &RemotePath, to: &RemotePath, replace: bool, cancel: &CancellationToken) -> Result<()>;
    pub async fn chmod(&self, path: &RemotePath, mode: u32, cancel: &CancellationToken) -> Result<()>;
    pub async fn set_mtime(&self, path: &RemotePath, time: OffsetDateTime, cancel: &CancellationToken) -> Result<()>;
    pub async fn raw_command(&self, cmd: &str, cancel: &CancellationToken) -> Result<String>;

    /// Exclusive access for multi-step work (e.g. a transfer started from the pane, T63
    /// view/edit download). Connects / reconnects first if needed; no automatic retry
    /// while the guard is held.
    pub async fn lock(&self, cancel: &CancellationToken) -> Result<BackendGuard>;
}
/// Owned guard (tokio OwnedMutexGuard); DerefMut to dyn Backend; marks activity on drop.
pub struct BackendGuard { /* … */ }
```

**Mock and conformance** (behind `#[cfg(any(test, feature = "test-util"))]`; the
`test-util` cargo feature of `courier-ftp-core` is used as a dev-dependency feature by
other crates and never enabled in release builds):

```rust
pub mod mock {
    /// An in-memory "server": a file tree shared by every MockBackend it creates.
    #[derive(Clone)] pub struct MockServer { /* Arc<Mutex<MockState>> */ }
    impl MockServer {
        pub fn new() -> Self;                                  // "/" and home "/home/test"
        pub fn with_capabilities(self, caps: Capabilities) -> Self; // default: all true except
                                                               // raw_commands, ascii_mode; Unix
        pub fn add_dir(&self, path: &str);                     // mkdir -p
        pub fn add_file(&self, path: &str, data: impl Into<bytes::Bytes>);
        /// File of `len` zero bytes stored sparsely (> 4 GiB without memory).
        pub fn add_sparse_file(&self, path: &str, len: u64);
        pub fn add_symlink(&self, path: &str, target: &str);
        pub fn set_meta(&self, path: &str, mode: Option<u32>, mtime: Option<Timestamp>);
        pub fn read_file(&self, path: &str) -> Option<Vec<u8>>;   // for assertions (≤ 64 MiB)
        pub fn file_len(&self, path: &str) -> Option<u64>;
        pub fn backend(&self, ctx: BackendContext) -> MockBackend; // a new session
        /// Delay before every operation (tokio::time::sleep; works with paused time).
        pub fn set_latency(&self, d: Duration);
        /// Per-connection stream throughput limit in bytes/s (None = unlimited).
        pub fn set_bandwidth(&self, bytes_per_sec: Option<u64>);
        /// connect() beyond `n` simultaneous sessions → Error::ConnectionLimit.
        pub fn set_max_connections(&self, n: Option<usize>);
        /// Queue a failure for the next call of `op` (FIFO, any session).
        pub fn fail_next(&self, op: MockOp, make: fn() -> Error);
        /// Every connected session loses its connection: next op → Error::Connection,
        /// is_connected() = false until connect().
        pub fn drop_connections(&self);
        /// connect() raises this prompt via ctx.events and fails with Cancelled on Cancel.
        pub fn set_connect_prompt(&self, kind: Option<PromptKind>);
        pub fn calls(&self, op: MockOp) -> usize;
        pub fn connections(&self) -> usize;          // currently connected
        pub fn peak_connections(&self) -> usize;     // max observed (T41 limit tests)
    }
    impl BackendFactory for MockServer;              // create() = backend(ctx)
    #[derive(Debug)] pub struct MockBackend { /* … */ }
    impl Backend for MockBackend;
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum MockOp { Connect, Disconnect, HomeDir, List, Stat, Mkdir, Rmdir, RemoveFile,
                      Rename, Chmod, SetMtime, OpenRead, OpenWrite, FinishTransfer, RawCommand, Keepalive }
}

pub mod conformance {
    /// What a conformance run needs from the backend under test.
    pub struct ConformanceEnv {
        /// An existing, empty, writable directory on the target.
        pub scratch: RemotePath,
        /// Creates a new, not yet connected backend for the same target.
        pub make: Box<dyn Fn() -> Result<Box<dyn Backend>> + Send + Sync>,
        /// Run `large_offset_*` cases (needs sparse files on the target).
        pub large_files: bool,
        /// Case names to skip, with the reason printed (e.g. a server quirk).
        pub skip: Vec<(&'static str, &'static str)>,
    }
    pub const CASES: &[&str];                     // every case name, listed in Tests
    pub async fn run_case(name: &str, env: &ConformanceEnv) -> Result<()>;
}
/// Expands to one #[tokio::test] per case, each calling `$env()` to build a ConformanceEnv.
/// `backend_conformance_tests!(ignored, env_fn)` adds #[ignore] (Docker targets, T76).
#[macro_export] macro_rules! backend_conformance_tests { … }
```

### Behaviour

**Transfer protocol** (all backends):
1. At most one open stream per backend. While a stream is open, every method except
   `finish_transfer`, `capabilities`, `address`, `is_connected` and `security_info` returns
   `Error::Internal("transfer in progress")`.
2. Read: read until `Ok(0)` (EOF, also after `range_len` bytes), drop the stream, call
   `finish_transfer(Complete)`. Stopping early: drop the stream, `finish_transfer(Abort)`.
3. Write: write everything, `shutdown().await`, drop, `finish_transfer(Complete)`. The
   upload counts as successful only when `finish_transfer` returns Ok (FTP 226, SFTP close OK).
4. If a stream is dropped and `finish_transfer` is never called (task cancelled), the next
   method call performs the `Abort` cleanup first.
5. `opts.transfer_type = Ascii` on a backend without `ascii_mode` is treated as Binary.

**Listing hygiene:** backends drop entries whose names fail `Entry::is_valid_name`
(including "." and ".."), keep the first of duplicate names, and log one Status line per
listing with the number dropped (`Ignored 2 entries with invalid names`). This protects
recursion and downloads from hostile names (T91).

**SessionHandle connect** (`connect`, also used for reconnects):
- State `Connecting` (or `Reconnecting`), event `Connecting`.
- Up to `1 + connection.retries` attempts. An attempt that fails with `is_transient()`
  (and not `ConnectionLimit`) waits `connection.retry_delay_secs` (cancellable) and retries;
  Status lines like FileZilla: `Connection attempt failed with "<error>".` and
  `Waiting to retry... (2 attempts left)`. `Auth`, `HostKey`, `Tls`, `Proxy`, `Cancelled`,
  `InvalidInput`, `ConnectionLimit` are not retried.
- Success → state `Connected`, event `Connected { address }` (local: no event), cached
  capabilities refreshed. Failure → state `Failed(msg)`, event `Disconnected { Failed(msg) }`.

**Operations with reconnect-once:**
1. If the state is not `Connected`, connect first (this counts as the one reconnect).
2. Run the operation under the mutex, racing `cancel`. Cancelled → drop the future, return
   `Cancelled` (if the backend now reports disconnected, state → `Disconnected`).
3. Error with `is_connection_lost()` and `opts.reconnect` and no reconnect done yet in this
   call → event `Disconnected { Lost }`, Status `Connection lost, reconnecting`, `connect`
   (with its retries), then run the operation once more. A second failure is returned as is.
4. Idempotency on the retried run: `mkdir` returning `AlreadyExists` and `remove_file`/`rmdir`
   returning `NotFound` are treated as success (the first attempt probably succeeded before
   the connection dropped); logged at `Debug(Info)`.
5. No explicit "CWD to the last directory" is needed after reconnect: every method takes an
   absolute path and backends change directory themselves (T14 tracks its cwd).
6. After each operation: update `last_activity`, refresh cached capabilities and send
   `CapabilitiesChanged` if they differ.

**Keep-alive task:** spawned by `new` when `opts.keepalive`. Ticks every
`connection.keepalive_interval_secs` (re-read from `SharedSettings` each tick). When
`connection.keepalive` is true, the state is `Connected`, and the session has been idle at
least one interval, it `try_lock`s the backend (skips the tick if busy) and calls
`keepalive()` under `connection.timeout_secs`. If that fails with `is_connection_lost()`:
state `Disconnected`, event `Disconnected { Lost }`, Status `Connection lost`; no automatic
reconnect (the next operation reconnects lazily, like FileZilla). The task holds only a
`Weak` reference and a child `CancellationToken` cancelled by a `DropGuard` in the shared
state, so it ends when the last `SessionHandle` clone is dropped. On that drop, the backend is
moved into a detached task that calls `disconnect()` with a 2 s timeout (only if a tokio
runtime is current), and `SessionClosed` is emitted.

**MockBackend semantics** match the trait docs exactly (it is the reference implementation
for the conformance suite): exclusive create, AlreadyExists, NotFound for missing parents,
`rmdir` of a non-empty dir → `Protocol { code: None, message: "directory not empty" }`,
symlinks resolved for `target_kind`, names case-sensitive unless
`case_insensitive_names`. Data is stored as a sparse chunk map, so `add_sparse_file` and
`ResumeAt`/`WriteAt` beyond 4 GiB cost no memory.

**Conformance cases** run in a fresh subdirectory `<scratch>/<case>-<8 hex>` and remove it
afterwards (best effort). Cases whose capability is false are skipped and reported as
skipped, not passed.

### Data formats and configuration

Settings read (T05): `connection.timeout_secs`, `connection.retries`,
`connection.retry_delay_secs`, `connection.keepalive`, `connection.keepalive_interval_secs`.
No files or wire formats. New dependencies: `async-trait`, `tokio-util` (CancellationToken),
`bytes` (mock), `futures`.

### Errors

- Trait methods return the `Error` variants listed in T02 with the mapping rules there;
  unsupported operations return `Unsupported("<operation> is not supported by <protocol>")`.
- `SessionHandle`: `Cancelled` on token; the backend's error otherwise. `lock()` fails with
  the connect error if (re)connecting fails.
- Factory: `InvalidInput` for an invalid `ConnectInfo`, `Unsupported` for unavailable protocols.
- Messages shown to the user come from `Error`'s Display (T52 error dialog, T55 log).

### Security and logging

- `ConnectInfo` holds secrets only as `SecretString`; its `Debug` is redacted; it is shared
  via `Arc` (no copies) and dropped (zeroized) with the last session.
- Session log lines (Status) come from `SessionHandle` as described; `tracing` events at
  info+ carry only `session = id` and `error = err.code()` (no hostnames/paths, T91 §4);
  hostnames only at debug.
- `raw_command` input is passed to the backend unchanged; CR/LF rejection is the FTP
  backend's job (T10).

## Implementation steps

1. `backend::types`: `Backend` trait, `ReadStream`/`WriteStream`, `TransferEnd`,
   `WriteMode`, `TransferOpts`, `Listing`, `Capabilities`, `SessionSecurityInfo`; module docs with
   the async-trait and cancellation conventions.
2. `backend::connect_info` and `backend::factory`: `ConnectInfo` (+ validate, redacted
   Debug), `TransferModeOverride`, `ProxyChoice`, `BackendContext`, `BackendFactory`.
3. `backend::mock`: `MockServer`, `MockBackend`, `MockOp` (sparse data, latency, bandwidth,
   failure injection, connection limits, counters); `test-util` feature.
4. `backend::conformance` + `backend_conformance_tests!`; run it against `MockBackend`.
5. `backend::session`: `SessionHandle` with connect retries and reconnect-once.
6. Keep-alive task, drop behaviour, events; paused-time tests.

## Acceptance criteria

- [ ] AC1 Trait, `Capabilities`, `Listing`, `WriteMode`, `TransferOpts`, `TransferEnd`,
  `SessionSecurityInfo`, `ConnectInfo`, `BackendContext`, `BackendFactory`, `SessionHandle`,
  `SessionState`, `MockServer`, `MockBackend`, conformance module exist with rustdoc; the
  module docs state the async-trait choice and the cancellation convention.
- [ ] AC2 `Box<dyn Backend>` compiles and `MockBackend` passes every conformance case
  (`cargo test -p courier-ftp-core --features test-util conformance`).
- [ ] AC3 Reconnect-once: an operation failing with `Error::Connection` reconnects and
  succeeds; a second consecutive loss is returned to the caller; with `reconnect = false`
  the first error is returned.
- [ ] AC4 `connect` makes exactly `1 + retries` attempts `retry_delay_secs` apart for
  transient errors and one attempt for `Auth`/`HostKey`/`ConnectionLimit` (paused time).
- [ ] AC5 A cancelled operation returns `Cancelled` within 50 ms of `cancel()` even when the
  mock latency is 10 s (paused time), and the next operation works.
- [ ] AC6 Keep-alive fires after an idle interval, never while the backend is locked, and its
  task has finished within one tick after the last `SessionHandle` is dropped.
- [ ] AC7 `format!("{:?}", connect_info)` contains no password text.
- [ ] AC8 The events `SessionOpened`, `Connecting`, `Connected`, `Disconnected{Lost|Failed}`,
  `SessionClosed` are emitted in the documented situations.
- [ ] AC9 T00 CI gates pass (fmt, clippy, docs, test-local-only, test-os, layering).

## Tests

### Unit tests
- `capabilities_none_is_all_false`. (AC1)
- `connect_info_validate_table` — Agent+FTP, Anonymous+SFTP, unresolved VaultItem key, limit 0/11, offset 1441 → InvalidInput; quick() defaults valid. (AC1)
- `connect_info_debug_redacted` — Normal password, proxy passwords. (AC7)
- `transfer_opts_default_is_binary`. (AC1)
- `dyn_backend_is_object_safe` — `let _: Box<dyn Backend> = Box::new(mock)`. (AC2)

### Property / fuzz tests
- `prop_mock_write_read_roundtrip` — random sequences of WriteAt/ResumeAt/Append chunks vs a `Vec<u8>` model; contents equal. (AC2)

### Snapshot tests
Not applicable.

### Integration tests
Conformance cases (each a test via `backend_conformance_tests!` for `MockBackend`; T06 runs
them for `LocalBackend`, T14/T22 via T76 for real servers) — all cover AC2:
`home_dir_is_absolute`, `scratch_starts_empty`, `mkdir_then_list_shows_dir`,
`mkdir_existing_is_already_exists`, `mkdir_missing_parent_fails`,
`write_then_read_roundtrip_1mib`, `write_empty_file`, `stat_file_reports_size_and_kind`,
`stat_missing_is_not_found`, `list_missing_dir_is_not_found`,
`names_with_spaces_unicode_and_leading_dash` (`" a"`, `"b "`, `"ü ñ 日本"`, `"-rf"`, `"#x"`, `"a;b"`),
`dotfile_is_hidden`, `rename_in_same_dir`, `rename_across_dirs`,
`rename_without_replace_fails_if_target_exists`, `rename_with_replace_overwrites`,
`remove_file_then_stat_not_found`, `remove_symlink_keeps_target`, `rmdir_empty_dir`,
`rmdir_non_empty_fails`, `read_from_offset`, `read_range_len_stops_at_length`,
`abort_read_midway_leaves_session_usable`, `resume_write_at_offset`, `append_write`,
`write_at_offset_keeps_existing_bytes`, `ops_rejected_while_stream_open`,
`chmod_roundtrip`, `set_mtime_roundtrip`, `large_offset_resume_beyond_4gib`
(`large_files` only), `second_session_sees_changes`, `keepalive_ok`,
`disconnect_then_connect_again`.

SessionHandle tests (`#[tokio::test(start_paused = true)]`, MockServer):
- `reconnect_once_on_connection_lost` — `drop_connections()`, then `list` succeeds; `calls(Connect) == 2`. (AC3)
- `second_consecutive_loss_surfaces` — `fail_next(List, Connection)` twice → error returned. (AC3)
- `no_reconnect_when_disabled`. (AC3)
- `retried_mkdir_already_exists_is_success` and `retried_remove_not_found_is_success`. (AC3)
- `connect_retries_transient_errors_with_delay` — retries = 2, three Connection failures → 3 attempts at t = 0, 5 s, 10 s. (AC4)
- `connect_does_not_retry_auth_or_limit`. (AC4)
- `cancel_interrupts_slow_operation` — latency 10 s, cancel at 1 s → Cancelled by 1.05 s; next `list` Ok. (AC5)
- `keepalive_fires_after_idle_interval` — interval 30 s: no call at 29 s, one call by 31 s. (AC6)
- `keepalive_skipped_while_locked` — guard held across two ticks → 0 calls. (AC6)
- `keepalive_task_stops_when_handle_dropped` — weak count 0 and task JoinHandle finished within one tick. (AC6)
- `keepalive_failure_marks_disconnected_and_next_op_reconnects`. (AC6, AC8)
- `session_events_sequence` — collects events from a receiver for connect, loss, reconnect, drop. (AC8)
- `connect_limit_reported_as_connection_limit` — `set_max_connections(1)`, second session → `ConnectionLimit`. (AC4)

### End-to-end tests
Not applicable here; T76 runs the conformance macro (`ignored` variant) against Docker servers.

## Out of scope

- Concrete protocol backends (T06, T14, T22) and the binary's factory (T58, T14).
- Connection pooling and per-server limits (T41).
- Listing cache (T46).

## Open questions

None.
