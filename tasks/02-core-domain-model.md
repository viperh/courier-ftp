# T02 — Core domain model

**Phase:** A Foundation · **Milestone:** M1 · **Depends on:** T01 · **Crate(s):** `courier-ftp-core` (`model`, `secret`, `error` modules) · **Decisions:** D3, D4, D5 · **FEATURES.md:** §1, §2, §3, §4
**Reference:** sverb `crates/sverb-core/src/secret.rs` (copy, D13), `crates/sverb-core/src/model/ids.rs` (id conventions)

## Goal

Define the shared vocabulary every other task uses: remote and local paths, directory
entries, timestamps with precision, permissions, protocols and server addresses (with URL
parsing), logon types with their secrets, charsets, the secret wrapper and the crate-wide
`Error`. After this task, protocol crates, the transfer engine and the UI can exchange
data without inventing their own types.

## Context

- Before: T01 replaced the template `Core { ticks }` with empty module declarations in
  `courier-ftp-core` (`model`, `backend`, `events`, `settings`, …) and added the workspace
  dependencies. `Error` is still the placeholder `Error::InvalidState`.
- After: T03 (Backend trait, `ConnectInfo`), T04 (events), T05 (settings), T06/T13/T14/T22
  (listings), T31 (sites), T40 (queue), T42 (file-exists decisions), T46 (cache keys),
  T48 (comparison), T58/T70 (URL parsing) all use these types by the names below.
- T30/T91 extend the `secret` module (`Key32`, `Locked<T>`, hardening); this task only
  creates `Secret<T>`, `SecretString`, `SecretBytes`.
- T81 adds `model::ids` (`ItemId`, `VaultId`, …) and `model::item`. This task refers to
  vault items by raw `uuid::Uuid` where it must (`KeySource::VaultItem`), because T81 comes
  later; T81's `ItemId` wraps the same `Uuid`.

## Technical specification

### Types and APIs

Module layout (all re-exported from `courier_ftp_core::model` unless noted):

```
courier-ftp-core/src/
  error.rs            Error, Result                    (re-exported at crate root)
  secret.rs           Secret<T>, SecretString, SecretBytes, REDACTED
  model/mod.rs
  model/path.rs       RemotePath, LocalPath, PathStyle, ServerTypeOverride
  model/entry.rs      Entry, EntryKind, SymlinkTarget, Timestamp, Precision, Permissions
  model/server.rs     Protocol, FtpEncryption, ServerAddress, ServerIdentity, ParsedUrl, UrlOptions
  model/logon.rs      LogonType, LogonKind, KeySource
  model/charset.rs    Charset
  model/transfer.rs   Direction, TransferType
```

#### Secrets (`courier_ftp_core::secret`)

Copied from sverb `secret.rs` (D13) with the crate name changed:

```rust
pub const REDACTED: &str = "[REDACTED]";
/// Heap secret: zeroized on drop; Debug/Display print "[REDACTED]";
/// no Clone, PartialEq, Serialize or Deserialize.
pub struct Secret<T: Zeroize + ?Sized>(secrecy::SecretBox<T>);
pub type SecretString = Secret<str>;
pub type SecretBytes = Secret<[u8]>;
impl<T: Zeroize + ?Sized> Secret<T> {
    pub fn from_box(value: Box<T>) -> Self;
    /// The only way to read the value; grep-able in review (`expose(`).
    pub fn expose(&self) -> &T;
    /// Constant-time comparison (`subtle`).
    pub fn ct_eq(&self, other: &Self) -> bool where T: AsRef<[u8]>;
}
impl From<String> for SecretString; impl From<&str> for SecretString;
impl From<Vec<u8>> for SecretBytes; impl From<&[u8]> for SecretBytes;
```

To copy a secret, call sites write `SecretString::from(s.expose())` (sverb convention).
This is the project rule's "`secrecy::SecretString`": our type wraps `secrecy`.

#### Paths (`model::path`)

```rust
/// An absolute, normalised, '/'-separated path on a server (or on the local side when it
/// goes through the Backend trait, see T06).
///
/// Invariants (enforced by every constructor):
/// - starts with '/'; no empty components; no "." or ".." components;
/// - no trailing '/' except the root "/";
/// - components never contain '/' or NUL; any other character is allowed, including
///   spaces (leading/trailing), '\\', ':', control characters and non-ASCII.
///
/// Servers with other path syntaxes (VMS `DISK:[DIR]FILE`, MVS datasets, DOS `C:\`) are
/// still represented in this Unix form; the FTP crate translates when it sends commands
/// (T14) using the session's `PathStyle`.
/// Callers rendering a RemotePath in the terminal must escape control characters (T53/T55).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RemotePath(String);

impl RemotePath {
    pub fn root() -> Self;                                   // "/"
    /// Parse an absolute path and normalise it. Errors: InvalidInput for "", relative input, NUL.
    pub fn parse(s: &str) -> Result<Self>;
    /// Resolve `input` (absolute or relative to self, may contain "." and "..") — address bar, CWD.
    pub fn resolve(&self, input: &str) -> Result<Self>;
    /// Append one component. Errors: InvalidInput if `name` is empty, ".", "..", or contains '/' or NUL.
    pub fn join(&self, name: &str) -> Result<Self>;
    /// Append several components (each validated like `join`).
    pub fn join_all<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Result<Self>;
    pub fn parent(&self) -> Option<Self>;                    // None for root
    pub fn file_name(&self) -> Option<&str>;                 // None for root
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> + '_;
    pub fn depth(&self) -> usize;                            // root = 0
    pub fn is_root(&self) -> bool;
    /// Component-wise prefix test ("/ab" does not start with "/a").
    pub fn starts_with(&self, base: &RemotePath) -> bool;
    /// Components of self below `base`, or None if self is not under base (T49, T66).
    pub fn strip_prefix(&self, base: &RemotePath) -> Option<Vec<&str>>;
    pub fn as_str(&self) -> &str;
}
impl fmt::Display for RemotePath;   // the raw string
impl fmt::Debug for RemotePath;     // "RemotePath(\"/a/b\")"
impl FromStr for RemotePath;        // = parse
impl TryFrom<String> for RemotePath; impl From<RemotePath> for String;

/// A local filesystem path. A newtype so local and remote paths cannot be mixed up.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalPath(PathBuf);
impl LocalPath {
    pub fn new(p: impl Into<PathBuf>) -> Self;
    pub fn as_path(&self) -> &Path;
    pub fn into_path_buf(self) -> PathBuf;
    /// Append one component; same rejection rules as RemotePath::join plus '\\' on Windows.
    pub fn join(&self, name: &str) -> Result<Self>;
    pub fn parent(&self) -> Option<Self>;
    pub fn file_name(&self) -> Option<&OsStr>;
    /// Native separators; the home directory prefix shown as "~" ("~/projects", "~\\Desktop").
    pub fn to_display(&self) -> String;                       // uses directories::BaseDirs
    pub fn display_with_home(&self, home: Option<&Path>) -> String; // testable variant
}

/// How a server spells paths. Detected by the FTP crate (SYST + listing), forced by
/// `ServerTypeOverride`. SFTP and local backends are always `Unix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PathStyle { #[default] Unix, Dos, Vms, Mvs }

/// Site Manager "Server type" (T31 Advanced tab).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ServerTypeOverride { #[default] Auto, Unix, Dos, Vms, Mvs }
impl ServerTypeOverride { pub fn path_style(self) -> Option<PathStyle>; } // None for Auto
```

#### Entries (`model::entry`)

```rust
/// One directory entry as reported by a backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// File name only (one valid RemotePath component: non-empty, not "."/"..", no '/', no NUL).
    pub name: String,
    pub kind: EntryKind,
    /// Bytes. None when the server does not say (MVS, some VMS, directories on most servers).
    pub size: Option<u64>,
    pub modified: Option<Timestamp>,
    pub permissions: Option<Permissions>,
    /// Owner/group names (or numeric ids as text when names are unknown).
    pub owner: Option<String>,
    pub group: Option<String>,
    /// Dotfile on Unix-like sides, FILE_ATTRIBUTE_HIDDEN locally on Windows, or server-flagged.
    pub hidden: bool,
}
impl Entry {
    pub fn new(name: impl Into<String>, kind: EntryKind) -> Self; // other fields None/false
    pub fn is_dir(&self) -> bool;          // kind == Dir
    /// Dir, or a symlink whose target is a directory (can be entered).
    pub fn is_dir_like(&self) -> bool;
    /// True if `name` is acceptable as an Entry name (see field doc).
    pub fn is_valid_name(name: &str) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink { target: Option<String>, target_kind: Option<SymlinkTarget> },
    /// Devices, sockets, FIFOs, MVS datasets that are neither.
    Other,
}
/// What a symlink points to, when resolved. None in `target_kind` = not resolved yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymlinkTarget { File, Dir, Other, Broken }
impl EntryKind { pub fn type_char(&self) -> char; } // 'd', 'l', '-', '?' (for "drwxr-xr-x")

/// A point in time (always stored in UTC) plus how precise the source was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub precision: Precision,
}
/// Ordered coarse → fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Precision { Day, Minute, Second, Millis }
impl Timestamp {
    /// Converts to UTC and truncates to `precision`.
    pub fn new(time: OffsetDateTime, precision: Precision) -> Self;
    /// Truncate to a (coarser) precision; finer requests return self unchanged.
    pub fn truncated(self, p: Precision) -> Self;
    /// Compare at the coarser precision of the two (T42 "newer", T48 comparison).
    pub fn cmp_coarse(&self, other: &Timestamp) -> Ordering;
    /// |self - other| after truncating both to the coarser precision.
    pub fn abs_diff_coarse(&self, other: &Timestamp) -> Duration;
}

/// Permissions as far as the server reports them.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permissions {
    /// Unix mode bits, masked to 0o7777 (setuid 0o4000, setgid 0o2000, sticky 0o1000).
    pub mode: Option<u32>,
    /// Text for servers with non-Unix permissions (MLSD `perm=` facts, Windows "R"), shown as-is.
    pub raw: Option<String>,
}
impl Permissions {
    pub fn from_mode(mode: u32) -> Self;                         // masks to 0o7777
    pub fn from_raw(raw: impl Into<String>) -> Self;
    /// 9 chars, e.g. "rwxr-xr-x", "rwsr-sr-t", "rwSr--r-T". None without a mode.
    pub fn to_rwx_string(&self) -> Option<String>;
    /// 10 chars with the type char: `perms.ls_string(&kind)` → "drwxr-xr-x".
    pub fn ls_string(&self, kind: &EntryKind) -> Option<String>;
    /// Accepts 9 chars, or 10 (first = type char, ignored), optionally followed by one
    /// ACL marker '+', '.', '@'. Errors: InvalidInput.
    pub fn from_rwx_string(s: &str) -> Result<Self>;
    /// "644", or 4 digits ("4755") when any of setuid/setgid/sticky is set. None without mode.
    pub fn to_octal_string(&self) -> Option<String>;
    /// Parse 3 or 4 octal digits ("644", "0644", "4755"). Errors: InvalidInput.
    pub fn parse_octal(s: &str) -> Result<u32>;
}
```

#### Servers and URLs (`model::server`)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol { Ftp, Sftp }

/// FileZilla's four FTP encryption modes (§1). Ignored for SFTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FtpEncryption { PlainOnly, #[default] ExplicitIfAvailable, RequireExplicit, RequireImplicit }

/// Where to connect. No secrets: passwords live in LogonType.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerAddress {
    pub protocol: Protocol,
    /// Always `ExplicitIfAvailable` when protocol is Sftp (normalised by `new`).
    pub encryption: FtpEncryption,
    /// Hostname, IPv4 or IPv6 literal, stored WITHOUT brackets.
    pub host: String,
    /// None = protocol default (see `effective_port`). Never Some(0).
    pub port: Option<u16>,
    /// None = not given (anonymous FTP, or asked later).
    pub user: Option<String>,
}
impl ServerAddress {
    /// Validates host (non-empty, ≤ 253 bytes, no whitespace, control chars, '/', '@', or
    /// '[' ']' — brackets are stripped by the URL parser before this) and port != 0;
    /// normalises encryption for SFTP. Errors: InvalidInput.
    pub fn new(protocol: Protocol, encryption: FtpEncryption, host: impl Into<String>,
               port: Option<u16>, user: Option<String>) -> Result<Self>;
    /// 22 for SFTP, 990 for RequireImplicit, otherwise 21.
    pub fn default_port(&self) -> u16;
    pub fn effective_port(&self) -> u16;
    /// "scheme://[user@]host[:port]" — see URL rules below. Never contains a password.
    pub fn to_url(&self, opts: &UrlOptions<'_>) -> String;
    /// Key for caches, history dedup and connection pools (T33, T41, T46).
    pub fn identity(&self) -> ServerIdentity;
    /// Scheme for this address: "sftp", "ftp", "ftpes", "ftps".
    pub fn scheme(&self) -> &'static str;
}
/// Display = to_url(&UrlOptions::default()), e.g. "sftp://alice@example.com:2222".
impl fmt::Display for ServerAddress;
/// FromStr = ParsedUrl::parse, rejecting input that carries a password (InvalidInput)
/// and dropping the path.
impl FromStr for ServerAddress;

/// protocol + lowercase host + effective port + user. Encryption is NOT part of it
/// (plain and TLS sessions to one server see the same files).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerIdentity { pub protocol: Protocol, pub host: String, pub port: u16, pub user: String }

#[derive(Default)]
pub struct UrlOptions<'a> {
    pub password: Option<&'a SecretString>,  // T62 "copy URL with password"
    pub path: Option<&'a RemotePath>,
    /// Include the port even when `port` is None (prints the default port).
    pub force_port: bool,
}

/// Result of parsing a URL or bare host typed by the user (T58 quickconnect, T70 CLI).
pub struct ParsedUrl {
    pub address: ServerAddress,
    pub password: Option<SecretString>,   // T70 warns when present
    pub path: Option<RemotePath>,         // initial remote dir
}
impl ParsedUrl { pub fn parse(input: &str) -> Result<Self>; }
impl fmt::Debug for ParsedUrl;            // password printed as [REDACTED]
```

#### Logon types (`model::logon`)

The user name lives in `ServerAddress.user`; `LogonType` carries only the method and its
secrets. There is no separate `Credentials` type: "credentials" in other tasks means
`ServerAddress.user` + `LogonType`.

```rust
/// FileZilla's logon types (§2) with their secrets. No Clone/Serialize (secrets);
/// persisted through T31's item mapping, not serde.
pub enum LogonType {
    /// FTP only: USER anonymous / PASS anonymous@example.com.
    Anonymous,
    /// Password stored; None = not stored (vault.store_passwords off) → asked at connect.
    Normal { password: Option<SecretString> },
    /// Asked on every connect (Prompt::Password, T04).
    AskForPassword,
    /// Keyboard-interactive (SFTP) / password asked in a dialog (FTP).
    Interactive,
    /// SFTP public key.
    KeyFile { key: KeySource, passphrase: Option<SecretString> },
    /// FTP with ACCT.
    Account { password: Option<SecretString>, account: Option<SecretString> },
    /// SFTP via ssh-agent / Pageant.
    Agent,
}
impl LogonType {
    pub fn kind(&self) -> LogonKind;
    /// Deep copy (re-wraps secrets). Explicit instead of Clone so copies are visible in review.
    pub fn duplicate(&self) -> Self;
    /// Valid for this protocol? Anonymous/Account: FTP only; KeyFile/Agent: SFTP only.
    pub fn is_valid_for(&self, protocol: Protocol) -> bool;
}
impl fmt::Debug for LogonType; // secrets as [REDACTED], e.g. Normal { password: Some([REDACTED]) }

/// Field-less discriminant for settings, the UI and T70 `--logontype`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogonKind { Anonymous, Normal, AskForPassword, Interactive, KeyFile, Account, Agent }

/// Where an SSH private key comes from (T31 §7).
pub enum KeySource {
    /// A key file on this device (device-local value, T91 §8 approval applies when synced).
    Path(LocalPath),
    /// An `ssh-key` item in the vault (T81); resolved to `Inline` when building ConnectInfo.
    VaultItem(uuid::Uuid),
    /// Key text (OpenSSH/PEM/PPK) already loaded from the vault.
    Inline(SecretString),
}
impl fmt::Debug for KeySource; // Inline → Inline([REDACTED])
```

#### Charset (`model::charset`)

```rust
/// Filename/command encoding per server (§1, Site Manager Charset tab).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Charset {
    /// UTF-8 if valid, else Windows-1252 per line (T10 switches to Utf8 on FEAT UTF8).
    #[default] Auto,
    Utf8,
    /// Any ASCII-compatible encoding_rs encoding (not UTF-16, not "replacement").
    Custom(&'static encoding_rs::Encoding),
}
impl Charset {
    /// Errors: InvalidInput for unknown labels or non-ASCII-compatible encodings.
    pub fn from_label(label: &str) -> Result<Self>;     // "auto", "utf-8", "windows-1252", …
    pub fn label(&self) -> &'static str;
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Cow<'a, str>;  // lossy (U+FFFD)
    /// Errors: InvalidInput if `text` has characters the encoding cannot represent.
    pub fn encode<'a>(&self, text: &'a str) -> Result<Cow<'a, [u8]>>;
}
/// Serialised as its label string: "auto" | "utf-8" | an encoding_rs label.
impl Serialize for Charset; impl<'de> Deserialize<'de> for Charset;
```

#### Transfer basics (`model::transfer`)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction { Download, Upload }       // used by T04 prompts, T40 queue, T42

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferType { Ascii, Binary }       // resolved type; the Auto choice is T05's TransferTypeChoice
```

#### Errors (`courier_ftp_core::Error`)

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Could not connect, or the connection was lost (incl. FTP 421). SessionHandle reconnects (T03).
    #[error("connection error: {0}")]            Connection(String),
    /// Server accepted no more connections from us: FTP 421/530 replies whose text says
    /// "too many connections" (T10), SSH disconnect reason 12 TOO_MANY_CONNECTIONS (T20).
    /// T41 lowers the per-server connection limit.
    #[error("too many connections: {0}")]        ConnectionLimit(String),
    /// No data for `connection.timeout_secs`.
    #[error("timed out")]                        Timeout,
    #[error("cancelled")]                        Cancelled,
    #[error("authentication failed: {0}")]       Auth(String),
    #[error("TLS error: {0}")]                   Tls(String),
    /// Host key rejected (revoked, or the user refused a changed key).
    #[error("host key rejected: {0}")]           HostKey(String),
    /// HTTP/SOCKS/FTP proxy refused or failed the handshake (T07, T15).
    #[error("proxy error: {0}")]                 Proxy(String),
    #[error("not found: {0}")]                   NotFound(RemotePath),
    /// Message is the server text or the path.
    #[error("permission denied: {0}")]           PermissionDenied(String),
    #[error("already exists: {0}")]              AlreadyExists(RemotePath),
    /// A server reply that is not one of the cases above. `code` = FTP reply code, SFTP status code.
    #[error("{}", protocol_message(*code, message))] Protocol { code: Option<u16>, message: String },
    #[error("not supported: {0}")]               Unsupported(String),
    /// Local I/O.
    #[error("I/O error: {0}")]                   Io(#[from] std::io::Error),
    /// The vault is locked and the operation needs a secret or a vault write.
    #[error("the vault is locked")]              VaultLocked,
    /// Other vault failures (T30 may add structured variants).
    #[error("vault error: {0}")]                 Vault(String),
    /// User input or untrusted data failed validation.
    #[error("invalid input: {0}")]               InvalidInput(String),
    /// A bug (state that should be impossible). Logged at error level.
    #[error("internal error: {0}")]              Internal(String),
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Retry with backoff is worthwhile (T41): Connection, ConnectionLimit, Timeout,
    /// Protocol with code 400..=499, Io with kind ConnectionReset, ConnectionAborted,
    /// BrokenPipe, TimedOut, UnexpectedEof, Interrupted. Everything else: false.
    pub fn is_transient(&self) -> bool;
    /// The session is unusable and must reconnect (T03 SessionHandle): Connection, Timeout,
    /// and Io with ConnectionReset/ConnectionAborted/BrokenPipe/UnexpectedEof.
    pub fn is_connection_lost(&self) -> bool;
    /// Stable short code for logs at info+ (no hostnames, paths or server text, T91 §4):
    /// "connection", "connection-limit", "timeout", "cancelled", "auth", "tls", "host-key",
    /// "proxy", "not-found", "permission-denied", "already-exists", "protocol",
    /// "unsupported", "io", "vault-locked", "vault", "invalid-input", "internal".
    pub fn code(&self) -> &'static str;
}
```

`Error` is not `Clone` (it holds `io::Error`). Code that must keep or broadcast an error
(queue failed list T40, events T04) stores `err.to_string()` and `err.code()`.

### Behaviour

**RemotePath normalisation** (`parse`, `resolve`): split on '/', drop empty and "."
components, ".." pops one component (at root it is ignored: `/a/../..` → `/`), join with
'/', prefix '/'. Input containing NUL → `InvalidInput("path contains NUL")`. `parse("")` and
relative input → `InvalidInput`. Length limit 4096 bytes after normalisation (`InvalidInput`).
`resolve("")` returns self. Backslashes are ordinary characters.

**LocalPath::join** additionally rejects names containing the platform separator
(`std::path::is_separator`) and, on Windows, names with a drive prefix (`C:`). This makes
`join` safe for names received from servers (path traversal, T91).

**Timestamp precision:** `new` truncates (Day → 00:00:00 UTC, Minute → seconds = 0, Second →
nanos = 0, Millis → nanos rounded down to ms). `cmp_coarse` truncates both to
`min(self.precision, other.precision)` before comparing. Day-precision values are dates; the
listing parser (T13) does **not** apply the server time-zone offset to them.

**Permissions strings:** bit order owner/group/other `rwx`; setuid shows `s` on owner x
(`S` if x unset), setgid on group x, sticky `t`/`T` on other x. Round-trip
`from_rwx_string(to_rwx_string(m)) == m` for all 4096 modes.

**URL parsing** (`ParsedUrl::parse`), applied after trimming ASCII whitespace:

| Input | protocol / encryption | Port default |
|---|---|---|
| `sftp://…` | Sftp | 22 |
| `ftp://…` | Ftp / ExplicitIfAvailable | 21 |
| `ftpes://…` | Ftp / RequireExplicit | 21 |
| `ftps://…` | Ftp / RequireImplicit | 990 |
| no scheme, port 22 | Sftp | — |
| no scheme, other/no port | Ftp / ExplicitIfAvailable (FileZilla quickconnect default) | — |

Scheme is case-insensitive; any other scheme → `InvalidInput("unsupported scheme")`.
Grammar: `[scheme://][userinfo@]host[:port][/path]`. `userinfo` is split at the **last** '@'
before the host (so `a@b.com@host` gives user `a@b.com`); user and password are split at the
first ':' of userinfo. User, password and path are percent-decoded (`%40` → '@'; invalid
escapes or decoding to invalid UTF-8 → `InvalidInput`); the host is not. IPv6 literals must
be bracketed (`[::1]:2222`); a bare `::1` without scheme is accepted as host `::1` with no
port. Port must be 1–65535. Path: everything from the first '/' after the authority, parsed
with `RemotePath::parse` (`sftp://h` → None, `sftp://h/` → Some("/")). Empty user (`@host`)
→ `None`. Maximum input length 2048 bytes.

**URL printing** (`to_url`): scheme from the table (PlainOnly also prints `ftp://`; it is
the one value that does not round-trip and parses back as ExplicitIfAvailable — documented),
user percent-encoded for `%`, `@`, `:`, `/`, '?', '#', space and non-printable characters,
`:password@` only when `UrlOptions.password` is given (also percent-encoded), host bracketed
when it contains ':', `:port` when `port` is Some or `force_port`, then the path with each
component percent-encoded for `%`, `?`, `#`, space and control characters. Round-trip rule:
`ParsedUrl::parse(&a.to_url(&opts))` reproduces `a` (and password/path) for every address
whose encryption is not PlainOnly.

**Charset:** `Auto.decode` = UTF-8 when the bytes are valid UTF-8, otherwise Windows-1252
(encoding_rs label "windows-1252", what FileZilla calls ISO-8859-1). `Auto.encode` = UTF-8.
`Custom(e).encode` uses `e.encode` and fails on unmappable characters instead of producing
HTML entities.

**Error mapping guidance** for later tasks: backends set `NotFound`/`PermissionDenied`/
`AlreadyExists` when the protocol says so (T14, T22, T06), `Protocol` for everything else
from the server, `Io` only for local I/O.

### Data formats and configuration

- Serde (JSON, used by settings T05, queue persistence/export T40, history T33):
  `RemotePath` as a string (validated on deserialize), `LocalPath` as a string,
  `Timestamp` as `{"time":"2024-01-31T12:00:00Z","precision":"minute"}`, `EntryKind` as
  `{"type":"symlink","target":"/x","target_kind":"dir"}`, enums kebab-case,
  `Charset` as label string, `ServerAddress` as an object with the field names above.
- `LogonType`, `KeySource`, `ParsedUrl` and `Secret<T>` implement **no** serde traits.
- Dependencies added to `courier-ftp-core`: `time` (features `serde-well-known`,
  `formatting`, `parsing`, `macros`), `secrecy`, `zeroize`, `subtle`, `encoding_rs`,
  `percent-encoding`, `uuid` (`serde`), `directories`. No settings keys in this task.

### Errors

This task defines the variants above. Constructors in this task return
`Error::InvalidInput` with a message that names the problem but never echoes a password.
`RemotePath` errors include the offending path text escaped with `escape_debug` (control
characters cannot reach the terminal through an error message).

### Security and logging

- Every type holding a secret (`Secret<T>`, `LogonType`, `KeySource`, `ParsedUrl`) has a
  hand-written `Debug` that prints `[REDACTED]`; none implements `Clone`, `Serialize` or
  `Display` of the secret.
- `ServerAddress::Display` never includes a password; `to_url` includes one only when the
  caller passes it explicitly.
- No logging in this module.
- Untrusted input: URL and path parsers are total (never panic) on arbitrary input; a
  property test feeds random strings (T91 fuzz list gets `url_parse` in this task).

## Implementation steps

1. Add the dependencies; create `secret.rs` by copying sverb `secret.rs` and its tests;
   create `error.rs` with `Error`, `Result`, `is_transient`, `is_connection_lost`, `code`;
   remove the placeholder `Error::InvalidState` and `Core` leftovers if T01 left any.
2. `model/path.rs`: `RemotePath` (parse/resolve/join/parent/…), `LocalPath`, `PathStyle`,
   `ServerTypeOverride`, with table tests.
3. `model/entry.rs`: `Entry`, `EntryKind`, `SymlinkTarget`, `Timestamp`, `Precision`,
   `Permissions` with tests.
4. `model/transfer.rs` and `model/charset.rs` with tests.
5. `model/server.rs` (`Protocol`, `FtpEncryption`, `ServerAddress`, `ServerIdentity`,
   `ParsedUrl`, `UrlOptions`) and `model/logon.rs` (`LogonType`, `LogonKind`, `KeySource`)
   with URL and redaction tests.
6. Property tests (`proptest` dev-dependency) and the `url_parse` fuzz body; rustdoc on
   every public item; `cargo doc` without warnings.

## Acceptance criteria

- [ ] AC1 All types and functions in "Types and APIs" exist with the given names and
  rustdoc on every public item; `cargo doc -p courier-ftp-core --no-deps` with
  `RUSTDOCFLAGS="-D warnings"` passes.
- [ ] AC2 `RemotePath` normalisation, `join`, `parent`, `starts_with`, `strip_prefix`,
  `resolve` match the rules above (table test, ≥ 25 rows).
- [ ] AC3 `RemotePath::join` and `LocalPath::join` reject `""`, `"."`, `".."`, names with
  '/', NUL (and '\\'/drive prefixes for LocalPath on Windows).
- [ ] AC4 `Permissions` rwx ↔ mode round-trips for all modes 0..=0o7777; octal parsing and
  printing per the rules.
- [ ] AC5 `Timestamp::cmp_coarse` returns `Equal` for `12:00` (Minute) vs `12:00:59` (Second)
  and `Less` for `12:00` vs `12:01:00`.
- [ ] AC6 URL parsing table (all four schemes, bare host, `host:port`, IPv6, percent-encoded
  user with '@', password, path, invalid inputs) passes, and parse(to_url(x)) == x for every
  non-PlainOnly address in a property test (1 000 cases).
- [ ] AC7 `format!("{:?}")` of `LogonType::Normal`, `Account`, `KeyFile` with an inline key,
  `ParsedUrl` with a password, and `SecretString` never contains the secret text and
  contains `[REDACTED]`.
- [ ] AC8 `Error::is_transient` / `is_connection_lost` / `code` table-tested for every variant.
- [ ] AC9 Parsers never panic: proptest on random strings for `RemotePath::parse`,
  `ParsedUrl::parse`, `Permissions::from_rwx_string` (10 000 cases each).
- [ ] AC10 CI gates from T00 pass: fmt, clippy (`-D warnings`), docs, test-local-only,
  test-os (Windows/macOS for `LocalPath`), layering (core has no ratatui/crossterm/clap).

## Tests

### Unit tests
- `remote_path_normalisation_table` — rows: `"/"`→`/`, `"//a//b/"`→`/a/b`, `"/a/./b/../c"`→`/a/c`,
  `"/a/../.."`→`/`, `"/ ä b /c "`→`/ ä b /c ` (spaces kept), `"/-x"` kept, `""`→error,
  `"a/b"`→error, `"/a\0b"`→error, 4097-byte path→error. (AC2)
- `remote_path_join_rejects_traversal_names` — `""`, `"."`, `".."`, `"a/b"`, `"a\0"` → InvalidInput; `"..."`, `" "`, `"a\\b"` accepted. (AC3)
- `remote_path_parent_and_file_name` — root has none; `/a/b` → `/a`, `b`. (AC2)
- `remote_path_starts_with_is_component_wise` — `/ab` vs `/a` false; `/a/b` vs `/a` true; strip_prefix gives `["b"]`. (AC2)
- `remote_path_resolve_relative_and_absolute` — `/a`.resolve(`../b/./c`) = `/b/c`; resolve(`/x`) = `/x`. (AC2)
- `remote_path_serde_rejects_invalid` — deserialising `"rel"` fails. (AC2)
- `local_path_join_rejects_separators` (+ `#[cfg(windows)] local_path_join_rejects_drive_prefix`). (AC3)
- `local_path_display_uses_tilde` — `display_with_home(Some("/home/u"))` of `/home/u/x` = `~/x`; `/home/user2` not shortened. (AC1)
- `permissions_rwx_roundtrip_all_modes` — loop 0..=0o7777. (AC4)
- `permissions_special_bits_render` — 0o4755 → `rwsr-xr-x`, 0o2644 → `rw-r-Sr--`, 0o1777 → `rwxrwxrwt`, 0o1776 → `rwxrwxrwT`. (AC4)
- `permissions_octal_strings` — 0o644 → "644", 0o4755 → "4755"; parse "0644" = 0o644; "8" → error. (AC4)
- `permissions_from_rwx_accepts_type_char_and_acl` — `"drwxr-xr-x+"` → 0o755. (AC4)
- `timestamp_cmp_coarse_minute_vs_second` and `timestamp_day_precision_truncates_to_midnight`. (AC5)
- `charset_auto_falls_back_to_windows_1252`, `charset_custom_encode_unmappable_fails`, `charset_rejects_utf16_label`, `charset_serde_label_roundtrip`. (AC1)
- `url_parse_table` — `sftp://[::1]:2222` (host `::1`, port 2222), `ftp://a%40b.com@h` (user `a@b.com`), `ftps://h` (RequireImplicit, effective port 990), `ftpes://u:p%3Aw@h/x%20y` (password `p:w`, path `/x y`), `h:22` → Sftp, `h` → Ftp/ExplicitIfAvailable, `http://h` → error, `ftp://h:0` → error, `ftp://h:65536` → error. (AC6)
- `server_address_display_never_contains_password`. (AC7)
- `server_identity_ignores_encryption_and_host_case`. (AC1)
- `logon_debug_is_redacted`, `secret_string_debug_and_display_redacted`, `parsed_url_debug_redacted`. (AC7)
- `logon_type_valid_for_protocol` — Anonymous+Sftp false, Agent+Ftp false. (AC1)
- `error_classification_table` — each variant → is_transient, is_connection_lost, code. (AC8)

### Property / fuzz tests
- `prop_remote_path_parse_never_panics_and_is_normalised` — random strings; when Ok, `parse(p.as_str()) == p` and invariants hold. (AC9, AC2)
- `prop_url_roundtrip` — generated addresses (random user incl. `@:/%`, IPv4/IPv6/hostnames, ports, encryption ≠ PlainOnly, optional password and path). (AC6)
- `prop_url_parse_never_panics` — random strings; body shared with fuzz target `url_parse` (T91 §7). (AC9)
- `prop_rwx_parse_never_panics`. (AC9)

### Snapshot tests
Not applicable (no UI).

### Integration tests
Not applicable (pure types).

### End-to-end tests
Not applicable.

## Out of scope

- Vault item ids and item bodies (T81), site model (T31), queue ids (T40).
- Listing parsing (T13) and path translation for VMS/MVS (T14).
- Key material types `Key32`/`Locked<T>` and process hardening (T30, T91).
- IDN/punycode conversion of hostnames (hostnames are passed to the resolver as typed).

## Open questions

- `FtpEncryption::PlainOnly` has no URL scheme (FileZilla has none either), so a copied URL
  of a plain-only site reopens as "explicit TLS if available". Is that acceptable, or do you
  want a courier-ftp-specific scheme (e.g. `ftp+plain://`)?
