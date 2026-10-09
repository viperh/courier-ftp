# T10 — FTP control connection

**Phase:** B FTP · **Milestone:** M3 · **Depends on:** T02, T04, T05, T07 · **Crate(s):** `courier-ftp-proto-ftp` (`control`, `reply`, `command`, `features`, `login`, `testing` modules) · **Decisions:** D1 (own client), D5 · **FEATURES.md:** §1 (FTP, keep-alive, timeouts, charset), §4 (custom command)
**Related (integrates with, not blocking):** T12, T13
**Reference:** sverb `fuzz/fuzz_targets/http_connect_response.rs` and `crates/sverb-conn/src/proxy/http_connect.rs` (pattern for a bounded, fuzzed, incremental response parser; `fuzz_*` body shared with a property test), `crates/sverb-conn/src/connlog.rs` (connection log lines).

## Goal

The FTP command channel of our own FTP client (D1): open the TCP connection, read and
parse replies exactly as RFC 959 defines them, send commands safely (no injection, secrets
masked), log in (normal, anonymous, account, interactive and scripted logins), negotiate
features (RFC 2389 `FEAT`, RFC 2640 `UTF8`, RFC 3659 `MLST` facts) and keep the connection
alive. Every later FTP task (data connections, TLS, listings, the backend, proxies, the
network wizard) is built on the `ControlConnection` and the scripted fake server delivered here.

## Context

**Exists before this task:**
- T02: `RemotePath`, `ServerAddress` (incl. `user`), `LogonType` (with `SecretString`
  passwords; "credentials" = `ServerAddress.user` + `LogonType`), `Charset`, `Protocol` +
  `FtpEncryption`, `courier_ftp_core::Error` (`Connection`, `ConnectionLimit`, `Timeout`,
  `Cancelled`, `Auth`, `Protocol { code, message }`, `Unsupported`, `InvalidInput`, `Io`…)
  and `Error::is_transient()`.
- T04: `EventSender`, `SessionLog`, `LogMessage`/`LogKind` (`Status`, `Command`, `Response`,
  `Error`, `ListingRaw`, `Debug(u8)`; no warning kind — warnings are `Status` lines prefixed
  `Warning: `), `mask_command`, `PromptKind::Password(PasswordPrompt)` with
  `PasswordPurpose::{Login, Account}`, `EventSender::prompt_tracked` /
  `credential_accepted` (`CoreEvent::CredentialAccepted`).
- T05: `Settings` (`connection.timeout_secs` = 20, `connection.keepalive_interval_secs` = 30,
  `ftp.send_keepalive_command: KeepaliveCommand` = `noop`).
- T07: `net::connect_tcp(&HostPort, &NetOpts, CancellationToken, &SessionLog) -> Result<NetStream>`
  (DNS, IPv6 preference, Happy Eyeballs, timeout, HTTP/SOCKS proxies), `local_addr_for`.

**Later tasks need from this one:**
- T11: `ControlConnection::send`/`read_reply`, `Features` (`epsv`, `eprt`, `rest_stream`),
  peer/local addresses, the "transfer in progress" guard, and the fake server's data steps.
- T12: `ControlConnection::upgrade_stream` (swap the plain stream for a TLS stream in place),
  the greeting/login hooks for `AUTH TLS`, `PBSZ`, `PROT`.
- T13: nothing at compile time; T14 passes `syst()` and `Features` hints to the parsers.
- T14: everything here, plus `raw_command`, `keepalive`, `quit`, `pwd`.
- T15: `LoginScript` (proxy login sequences are just other scripts).
- T72: connect + login + `PASV`/`PORT` via T11.
- T76/T91: the reply-parser fuzz target and the `FakeServer` harness.

## Technical specification

### Types and APIs

Module paths are inside `courier_ftp_proto_ftp`.

```rust
// reply.rs ------------------------------------------------------------------------------
/// A three-digit FTP reply code (RFC 959 §4.2). Always 100..=599 with first digit 1–5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyCode(u16);

/// First digit of a reply code (RFC 959 §4.2.1).
pub enum ReplyClass { Preliminary /*1yz*/, Completion /*2yz*/, Intermediate /*3yz*/,
                      TransientNegative /*4yz*/, PermanentNegative /*5yz*/ }

/// One complete (single- or multi-line) reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: ReplyCode,
    /// Every line exactly as received (decoded, CR/LF stripped, control chars replaced
    /// with U+FFFD), including the `NNN-`/`NNN ` prefixes. Used for the message log.
    pub lines: Vec<String>,
}
impl Reply {
    pub fn class(&self) -> ReplyClass;
    pub fn is_preliminary(&self) -> bool;     // 1xx
    pub fn is_ok(&self) -> bool;              // 2xx
    pub fn is_intermediate(&self) -> bool;    // 3xx
    pub fn is_transient_err(&self) -> bool;   // 4xx
    pub fn is_permanent_err(&self) -> bool;   // 5xx
    /// Text without code prefixes; continuation lines joined with '\n'.
    pub fn text(&self) -> String;
}

/// Incremental, allocation-bounded reply parser. Feed it bytes in any chunking; it yields
/// complete replies. Pure (no I/O) so it is property-tested and fuzzed.
pub struct ReplyParser { /* state: Idle | InMultiline { code, lines }, partial line buffer */ }
impl ReplyParser {
    pub fn new(decoder: LineDecoder) -> Self;
    /// Append bytes; returns replies completed by this chunk (usually 0 or 1).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Reply>, ReplyError>;
    /// True if a partial line or an unterminated multi-line reply is buffered.
    pub fn has_partial(&self) -> bool;
}
pub enum ReplyError { LineTooLong, ReplyTooLarge, Malformed(String) }

/// Fuzz/property entry point (T91 §7): feeds `data` split at boundaries derived from
/// the first byte; must never panic or allocate beyond the limits below.
pub fn fuzz_reply_parser(data: &[u8]);

// command.rs ----------------------------------------------------------------------------
/// A command ready to be written. `Debug` masks secret arguments.
pub struct Command { verb: &'static str, arg: Option<CommandArg> }
pub enum CommandArg { Plain(String), Secret(SecretString) }
impl Command {
    pub fn new(verb: &'static str) -> Self;              // verb is ASCII upper-case
    pub fn arg(self, arg: impl Into<String>) -> Result<Self>;   // rejects CR, LF, NUL
    pub fn secret(self, arg: SecretString) -> Result<Self>;     // PASS/ACCT; same checks
    /// Line for the message log (`PASS ****`, `ACCT ****`).
    pub fn log_text(&self) -> String;
    /// Wire bytes: `VERB[ SP arg] CRLF`, arg encoded with the session charset, 0xFF
    /// doubled (Telnet IAC escape, RFC 959 §4.1 / RFC 2640 §3.1). Zeroized on drop.
    pub(crate) fn encode(&self, enc: &SessionEncoding) -> Result<Zeroizing<Vec<u8>>>;
}

// features.rs ---------------------------------------------------------------------------
/// Parsed `FEAT` reply (RFC 2389). Unknown lines kept in `raw`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Features {
    pub feat_supported: bool,        // false when FEAT got 500/502 (defaults below apply)
    pub mlst: Option<Vec<MlstFact>>, // RFC 3659 `MLST size*;modify*;type*;` (`*` = enabled)
    pub mlsd: bool,                  // = mlst.is_some() || explicit "MLSD" line
    pub size: bool, pub mdtm: bool, pub mfmt: bool, pub mff: bool,
    pub rest_stream: bool,           // "REST STREAM"
    pub utf8: bool,                  // "UTF8" (RFC 2640)
    pub epsv: bool, pub eprt: bool,  // RFC 2428 (often not listed — see T11)
    pub tvfs: bool, pub clnt: bool, pub mode_z: bool, pub host: bool,
    pub auth: Vec<String>,           // "AUTH TLS;SSL" → ["TLS", "SSL"]
    pub pbsz: bool, pub prot: bool, pub ccc: bool,
    pub hash: Option<Vec<String>>,   // "HASH SHA-256*;SHA-1;MD5" (draft-bryan-ftpext-hash, T41b)
    pub site: Vec<String>,           // "SITE CHMOD;UTIME" style lists (upper-cased)
    pub lang: Option<String>,
    pub raw: Vec<String>,
}
pub struct MlstFact { pub name: String /* lower-case */, pub enabled: bool }
pub fn parse_feat(reply: &Reply) -> Features;

// control.rs ----------------------------------------------------------------------------
/// Any byte stream the control connection runs over (TCP, TLS-over-TCP, test duplex).
pub trait ControlIo: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
pub type BoxedIo = Box<dyn ControlIo>;

/// Everything needed to open one control connection.
pub struct ControlParams {
    pub target: HostPort,             // host + port actually dialled (proxy host for T15)
    pub server_name: String,          // name used for TLS verification and log lines
    pub net: NetOpts,                 // from T07 (timeouts, proxy, prefer_ipv6)
    pub charset: Charset,             // T02
    pub timeout: Duration,            // connection.timeout_secs
    /// `courier_ftp_core::settings::KeepaliveCommand` (T05: `Noop`* | `Random`),
    /// from `ftp.send_keepalive_command`. Not redefined here.
    pub keepalive_command: KeepaliveCommand,
    pub log: SessionLog,              // T04: session id + EventSender
}

pub enum ControlState { Greeting, LoggingIn, Ready, Busy, TransferOpen, Broken, Closed }

pub struct ControlConnection { /* io: Option<BoxedIo>, parser, encoding, features, syst,
                                  state, current_type, timeout, log, peer/local addrs */ }
impl ControlConnection {
    /// TCP connect (T07) and read the greeting. Implicit FTPS (T12) passes a hook that
    /// wraps the stream in TLS before the greeting is read.
    pub async fn connect(p: ControlParams, pre_greeting: Option<&dyn StreamUpgrade>,
                         cancel: &CancellationToken) -> Result<(Self, Reply /*greeting*/)>;
    /// Same, over an existing stream (tests, T15 proxies through T07).
    pub async fn from_stream(io: BoxedIo, p: ControlParams, cancel: &CancellationToken)
        -> Result<(Self, Reply)>;
    /// Runs a login script (default or T15 proxy script).
    pub async fn login(&mut self, script: LoginScript, cancel: &CancellationToken) -> Result<()>;
    /// SYST, FEAT, OPTS UTF8 ON, OPTS MLST; fills `features()`/`syst()`.
    pub async fn negotiate(&mut self, cancel: &CancellationToken) -> Result<()>;
    /// Send one command, return its final reply (skips up to 8 unexpected 1xx replies
    /// for non-transfer commands). Never fails on 4xx/5xx — the caller interprets the code.
    pub async fn send(&mut self, cmd: Command, cancel: &CancellationToken) -> Result<Reply>;
    /// `send` + check: a code not in `expected` becomes `Error::Protocol { code, text }`
    /// (or the mapping in "Errors").
    pub async fn send_expect(&mut self, cmd: Command, expected: &[u16],
                             cancel: &CancellationToken) -> Result<Reply>;
    /// Send without waiting (used by T11 for RETR/STOR and ABOR) / read next reply.
    pub async fn write_command(&mut self, cmd: Command) -> Result<()>;
    pub async fn read_reply(&mut self, cancel: &CancellationToken) -> Result<Reply>;
    /// PWD → server path string as returned (T14 converts to `RemotePath`).
    pub async fn pwd(&mut self, cancel: &CancellationToken) -> Result<String>;
    pub async fn keepalive(&mut self, cancel: &CancellationToken) -> Result<()>;
    /// User-entered custom command (FEATURES §4). Returns the whole reply.
    pub async fn raw_command(&mut self, line: &str, cancel: &CancellationToken) -> Result<Reply>;
    /// QUIT, wait ≤ 2 s for any reply, TLS close_notify (T12), close. Never fails.
    pub async fn quit(self);
    /// TLS upgrade (T12): takes the stream out, gives it back wrapped. Only in `Ready`/
    /// `Greeting` with no buffered unread bytes (else `Error::Protocol`).
    pub async fn upgrade_stream<F, Fut>(&mut self, f: F) -> Result<()>
        where F: FnOnce(BoxedIo) -> Fut, Fut: Future<Output = Result<BoxedIo>>;

    pub fn features(&self) -> &Features;
    pub fn syst(&self) -> Option<&str>;
    pub fn greeting(&self) -> &Reply;
    pub fn peer_addr(&self) -> Option<SocketAddr>;   // None over a test duplex
    pub fn local_addr(&self) -> Option<SocketAddr>;
    pub fn current_type(&self) -> Option<TransferType>;   // tracked TYPE (T11 uses it)
    pub fn set_current_type(&mut self, t: Option<TransferType>);
    pub fn encoding(&self) -> &SessionEncoding;
    pub fn state(&self) -> ControlState;
    pub(crate) fn mark_transfer_open(&mut self, open: bool);    // T11 guard
    pub(crate) fn mark_broken(&mut self);
}

/// Hook to wrap a raw stream before the greeting (implicit FTPS, T12).
#[async_trait]
pub trait StreamUpgrade: Send + Sync { async fn upgrade(&self, io: BoxedIo) -> Result<BoxedIo>; }

// encoding.rs ---------------------------------------------------------------------------
/// The session's charset decision (RFC 2640 + `Charset` from T02).
pub struct SessionEncoding { /* encoding: &'static Encoding, mode: Auto|Fixed, switched: bool */ }
impl SessionEncoding {
    pub fn decode_line(&mut self, bytes: &[u8]) -> String;   // may switch Auto → fallback
    pub fn encode(&self, s: &str) -> Result<Vec<u8>>;        // unmappable → InvalidInput
    pub fn name(&self) -> &'static str;
}
/// Reply-line decoding with `encoding_rs` (same rules as T13's `TextDecoder`; T14
/// configures the listing decoder from this `SessionEncoding`, so replies and listings
/// always agree). If T13 has landed, use its `TextDecoder` instead of duplicating it.
pub struct LineDecoder;

// login.rs ------------------------------------------------------------------------------
/// An ordered login sequence. The default is built from `ServerAddress.user` + `LogonType`
/// (T02); T15 builds proxy scripts. Secrets are resolved lazily so a prompt only appears
/// when the server asks.
pub struct LoginScript { pub steps: Vec<LoginStep> }
pub struct LoginStep {
    pub kind: StepKind,                 // User | Pass | Acct | Other
    pub value: StepValue,               // the argument
    /// Log text with secrets already replaced by `****` (T15 custom lines).
    pub log_text: String,
    /// Which login this step belongs to (proxy or target), for error messages.
    pub target: LoginTarget,            // Proxy | Server
}
pub enum StepKind { User, Pass, Acct, Other(&'static str) }
pub enum StepValue { Plain(String), Secret(SecretString), AskPassword, AskAccount, Line(SecretString) }
pub enum LoginTarget { Proxy, Server }
/// Prompt metadata for AskPassword/AskAccount steps (filled by T14 from ConnectInfo).
pub struct LoginPromptInfo {
    pub target: String,                 // PasswordPrompt.target, "user@host:port"
    pub cache_key: SecretCacheKey,      // T04 Password { protocol: Ftp, host, port, user }
    /// T04 `can_save`: saved site (`ConnectInfo.site_id.is_some()`) and
    /// `vault.store_passwords`; T69 also disables it while the vault is locked.
    pub can_save: bool,
}
impl LoginScript {
    /// USER/PASS[/ACCT] for `ServerAddress.user` + `LogonType` (T02). `user` None with a
    /// non-anonymous logon → `Error::InvalidInput("user name required")`.
    /// KeyFile/Agent → `Error::InvalidInput` ("key-based logon is SFTP only").
    pub fn for_logon(user: Option<&str>, logon: &LogonType, prompt: LoginPromptInfo) -> Result<Self>;
}

// testing.rs (feature `test-util`, also used by T11–T15, T72, T76) -----------------------
pub struct FakeServer { /* script, duplex end or TcpListener */ }
pub enum Step {
    Reply(&'static str),                 // write "<text>\r\n" (multi-line: embed \r\n)
    RawBytes(Vec<u8>),                   // exact bytes, for split/garbage tests
    Expect(&'static str),                // next client line must equal this
    ExpectPrefix(&'static str),          // e.g. "PASS " (value checked separately)
    ExpectSecret { verb: &'static str, value: &'static str },
    Delay(Duration),                     // with tokio::time::pause
    Close,
    // T11 adds: PasvListen, EpsvListen, ExpectPortThenConnect, SendData, RecvData, CloseData…
    // T12 adds: StartTls { config }, RequireResumedDataTls …
}
impl FakeServer {
    pub fn duplex(script: Vec<Step>) -> (Self, BoxedIo);
    pub async fn tcp(script: Vec<Step>) -> (Self, SocketAddr);
    /// Panics with "expected X, got Y" + the transcript on mismatch; asserts the script
    /// was consumed completely.
    pub async fn finish(self) -> Transcript;
}
```

### Behaviour

**1. Reply grammar (RFC 959 §4.2).**

```
reply        = single-line / multi-line
single-line  = code SP text CRLF  /  code CRLF                 ; bare code accepted
multi-line   = code "-" text CRLF *( line CRLF ) code SP text CRLF   ; same code
code         = %x31-35 2DIGIT                                   ; 1yz … 5yz
```

- Line terminator: CRLF; a bare LF is also accepted (CR stripped if present). A bare CR
  inside a line is kept as data (then replaced by U+FFFD when sanitising).
- A multi-line reply ends at the first line that starts with the **same** code followed by
  a space, or is exactly the code. Continuation lines may start with anything: indented text,
  `NNN-` with the same code (ProFTPD prefixes every line), or a **different** code followed
  by space (RFC 959 example: `123-First line / Second line / 234 A line beginning with numbers
  / 123 The last line`) — none of those end the reply.
- First line of a reply that is not `code[ -]…` or `code` → `ReplyError::Malformed`.
- Limits: one line ≤ **64 KiB** (`LineTooLong`); one reply ≤ **10 000 lines** and
  ≤ **4 MiB** total (`ReplyTooLarge`). Any `ReplyError` → `Error::Protocol { code: None, .. }`
  and the connection becomes `Broken`.
- Telnet (RFC 854) on the control channel: `IAC IAC` (0xFF 0xFF) decodes to one 0xFF;
  `IAC WILL/WONT/DO/DONT x` (3 bytes) and other `IAC x` (2 bytes) are dropped and never
  answered. Implemented in the parser before line splitting.
- Decoded line text: bytes decoded by `SessionEncoding` (below); then every C0 control
  (except TAB) and C1 control is replaced with U+FFFD (T91: no terminal escapes from the
  server reach logs or the UI).
- **Unsolicited replies:** before writing a command, any complete reply already buffered
  (or readable without blocking) is consumed: `421` → connection closes, `Error::Connection`;
  anything else is logged (`LogKind::Response` + `Debug(3)` "unexpected reply discarded")
  and dropped.

**2. Reply code reference** (meaning used by this crate; T11/T12/T14 rely on it).

| Code | Meaning | Where expected |
|---|---|---|
| 110 | Restart marker | never sent by us (MODE B unused) — skipped |
| 120 | Service ready in nnn minutes | greeting, before 220 |
| 125 / 150 | Data connection open / about to open | transfer commands (T11) |
| 200 | OK | TYPE, PORT, EPRT, PBSZ, PROT, OPTS, NOOP |
| 202 | Not implemented, superfluous | ACCT, some OPTS |
| 211 / 212 / 213 | System / dir / file status | FEAT (211), SIZE/MDTM/MFMT (213) |
| 214 / 215 | Help / system type | HELP, SYST |
| 220 / 221 | Ready / closing control | greeting / QUIT |
| 225 / 226 | Data conn open, no transfer / closing data conn, success | ABOR, transfer end |
| 227 / 229 | Entering passive / extended passive | PASV, EPSV (T11) |
| 230 / 232 | Logged in / logged in after security exchange (RFC 2228) | USER, PASS, ACCT |
| 234 | AUTH accepted (RFC 2228/4217) | AUTH TLS (T12) |
| 250 / 257 | Action OK / path created or PWD | CWD, DELE, RMD, RNTO, MLST / MKD, PWD |
| 331 / 332 | Need password / need account | USER, PASS |
| 350 | Pending further info | REST, RNFR |
| 421 | Service not available, closing | anywhere |
| 425 / 426 | Can't open data conn / transfer aborted | T11 |
| 430 / 434 | Invalid user or password / host unavailable (RFC 7151) | login |
| 450 / 451 / 452 | File busy / local error / insufficient storage | T14 |
| 500 / 501 / 502 / 503 / 504 | Syntax / args / not implemented / bad sequence / param not implemented | anywhere |
| 522 | Network protocol not supported (EPRT, RFC 2428) | T11 |
| 530 / 532 | Not logged in / need account for storing | login, STOR |
| 533 / 534 / 535 / 536 | Protection denied / policy denied / security check failed / PROT level not supported (RFC 2228) | T12 |
| 550–553 | File unavailable / page type / storage exceeded / name not allowed | T14 |
| 631–633 | Protected replies (RFC 2228 MIC/CONF/ENC) | not supported → `Error::Protocol` |

**3. Command writer.**
- One outstanding command at a time; no pipelining (exception: `ABOR` while a transfer is
  open, T11).
- Arguments containing CR, LF or NUL → `Error::InvalidInput("… contains a line break or
  NUL")` **before** anything is written (command-injection protection for file names and
  user input). Verbs are compile-time constants.
- Encoding: the argument is encoded with the session encoding; an unmappable character in
  a fixed custom charset → `Error::InvalidInput` (never substitute `?`, which could address
  a different file). Bytes 0xFF are doubled.
- Logging: every command → `LogKind::Command` with `Command::log_text()` (secrets
  `****`; T04 `mask_command` is applied on top as a second guard). Every reply line →
  `LogKind::Response`.
- The wire buffer holding a secret is `Zeroizing<Vec<u8>>`; `SecretString::expose()`
  happens only inside `Command::encode`.

**4. Charset (`SessionEncoding`, RFC 2640).**

| Site `Charset` | Server FEAT has `UTF8` | Session encoding |
|---|---|---|
| `Utf8` | any | UTF-8; send `OPTS UTF8 ON` if advertised; invalid bytes → U+FFFD + `Debug(1)` warning |
| `Custom(enc)` | any | `enc` both directions; `OPTS UTF8 ON` never sent |
| `Auto` | yes | UTF-8, `OPTS UTF8 ON` sent (failure ignored) |
| `Auto` | no / FEAT unsupported | UTF-8 tentatively; on the **first** line (reply or listing, T13) that is not valid UTF-8, switch the session to `windows-1252` (`encoding_rs::WINDOWS_1252`, the WHATWG mapping for "ISO-8859-1") for both directions, log Status "Server does not use UTF-8, switching to windows-1252" and re-decode that line. Never switches back. |

**5. Session start sequence** (each step logs a `Status` line, e.g. `Connecting to …`,
`Connection established, waiting for welcome message...`, `Logged in`).

```
Disconnected ─connect_tcp─▶ [implicit TLS hook, T12] ─▶ Greeting
Greeting: read reply
   120            → log "server busy, ready in N min", keep reading (≤ 5 × 120 accepted)
   220            → continue
   421            → Error::ConnectionLimit(text) if the text matches the "too many" pattern
                    (§6), else Error::Connection(text); T41 lowers the limit on ConnectionLimit
   other          → Error::Connection("unexpected greeting: <text>")
[explicit TLS, T12: AUTH TLS → 234 → handshake]
LoggingIn: run LoginScript (below)
Negotiate: SYST → FEAT → [OPTS UTF8 ON] → [OPTS MLST …] → [T12: PBSZ 0, PROT P] → PWD
Ready ⇄ Busy (one command) ⇄ TransferOpen (T11)  ─421/timeout/EOF/protocol error─▶ Broken
Ready ─quit()─▶ Closed
```

- `SYST`: `215 <text>` stored (`UNIX Type: L8`, `Windows_NT`, `VMS …`, `MVS is the operating
  system…`, `OS/400 …`); 500/502 → `None`.
- `FEAT` (RFC 2389): `211-` reply; each feature line begins with exactly one space;
  feature names are case-insensitive; text after the first space are parameters. Example:
  ```
  211-Features:
   EPRT
   EPSV
   MDTM
   MLST type*;size*;modify*;perm*;unix.mode*;
   REST STREAM
   SIZE
   UTF8
   AUTH TLS
  211 End
  ```
  `500`/`502` → `Features { feat_supported: false, .. }` with all flags false (T11/T14 then
  probe). `MLSD` support is **implied by `MLST`** (RFC 3659 §7.8); an explicit `MLSD` line
  also sets `mlsd`. FEAT is sent after login (some servers advertise more after login).
- `OPTS UTF8 ON`: rules in §4; any reply accepted.
- `OPTS MLST type;size;modify;perm;unix.mode;unix.owner;unix.group;unix.ownername;unix.groupname;`
  (intersection with advertised facts, in that order, `;`-terminated) when `mlst` is
  advertised; reply ignored (failure just means default facts).
- `PWD` → `257 "<path>" <comment>`: path is between the first `"` and the next `"` that is
  not doubled; `""` inside is a literal `"` (RFC 959 Appendix II). No quotes → first
  whitespace-separated token after the code. Empty → `Error::Protocol`.
- `CLNT` and `HOST` (RFC 7151) are **not** sent (no benefit, `CLNT` discloses the client).

**6. Login state machine** (RFC 959 §6 USER/PASS/ACCT diagram, generalised for scripts).

| Step sent | Reply | Next |
|---|---|---|
| `USER x` | 230, 232 | logged in for this target; skip the directly following `PASS`/`ACCT` steps of the same target |
| | 331 | next step must be `PASS` (missing → resolve via prompt, see below) |
| | 332 | send `ACCT` (step, credentials account, or prompt) |
| `PASS x` | 230, 202, 232 | logged in for this target |
| | 332 | send `ACCT` |
| `ACCT x` | 230, 202 | logged in |
| any | 421 + text matching `/too many\|maximum\|connections\|limit/i` | `Error::ConnectionLimit(text)` (T41 lowers the limit; not retried by T03) |
| any | other 421 | `Error::Connection(text)` |
| any | 530 + text matching the same pattern | `Error::ConnectionLimit(text)` (not a credential error) |
| any | 530, 430 | `Error::Auth(server text)` |
| any | other 4xx | `Error::Protocol` (transient) |
| any | other 5xx | `Error::Auth(server text)` |
| `Other` (T15 `SITE`/`OPEN`) | 2xx, 3xx | next step; 4xx/5xx → `Error::Proxy("FTP proxy could not connect to the server: …")` |
| step with `LoginTarget::Proxy` | 530, 430, other 5xx | `Error::Proxy("FTP proxy login failed: …")` (T15) |

- After the last step the last reply must be 2xx (`230`/`202`), otherwise
  `Error::Auth("login incomplete: <text>")`.
- `LoginScript::for_logon` (user from `ServerAddress.user`):
  - `Anonymous` → `USER anonymous`, `PASS anonymous@example.com`.
  - `Normal { password: Some(p) }` / `Account { password: Some(p), account }` → `USER`,
    `PASS`, `ACCT` (only when 332 is received; `account` None → `AskAccount`).
  - `Normal { password: None }` (not stored), `AskForPassword`, `Interactive`, `Account
    { password: None, .. }` → `PASS` value `AskPassword`: a
    `PromptKind::Password(PasswordPrompt { purpose: Login, target, retry: false, attempt: 1,
    max_attempts: 1, cache_key, can_save })` (T04) is sent via `prompt_tracked` **only when
    331 arrives**; `AskAccount` uses `purpose: Account` and `SecretCacheKey::Account`. The
    inactivity timer is paused while waiting; a cancelled/dropped prompt → `Error::Cancelled`.
    When the login reaches 230/202, the crate calls `credential_accepted(session, prompt_id)`
    for every prompt answered during this login (T69 then caches/saves the value).
    `AskForPassword` keeps the answer for this backend instance (T14); `Interactive` asks
    on every login.
  - `KeyFile` / `Agent` → `Error::InvalidInput`.
- No reply to a step within the timeout → `Error::Timeout`.

**7. Keep-alive.** `keepalive()` is called by `SessionHandle` (T03) after
`connection.keepalive_interval_secs` (30 s) idle. Command from `ftp.send_keepalive_command`:
`noop` (default) → `NOOP`; `random` → a uniform choice of `NOOP`, `PWD` or `TYPE`
(re-sends the current type, `TYPE I` if unknown) each time, like FileZilla, to defeat
servers that ignore `NOOP` for idle detection. If a transfer is open, `keepalive()` returns `Ok(())`
without sending. Any reply is accepted; 421/timeout → `Error::Connection`/`Timeout`.

**8. Raw command (FEATURES §4).** Verb = first token, upper-cased. Refused with
`Error::InvalidInput("use the normal UI for <VERB>")` without sending: `LIST NLST MLSD RETR
STOR STOU APPE REST PORT EPRT LPRT PASV EPSV LPSV ABOR AUTH PBSZ PROT CCC REIN USER PASS ACCT
QUIT`. Allowed commands are sent verbatim (CR/LF/NUL check, charset encoding). After a raw
`CWD`/`CDUP`/`TYPE` the tracked cwd/type are set to unknown so T14 re-issues them. Returns
the whole reply (any code is a success at this level; T14 joins `lines` with `\n`).

**9. Disconnect.** `quit()`: write `QUIT`, wait ≤ **2 s** for any reply (221 expected),
TLS `close_notify` if TLS (T12), shut down and drop the socket. Errors are logged at
`Debug(3)` and swallowed.

**10. Timeouts and cancellation.**

| What | Limit | Result |
|---|---|---|
| TCP connect (per address, T07) | `connection.timeout_secs` (20 s) | `Error::Timeout` |
| Greeting, each reply | **inactivity**: no byte received for `timeout_secs` (FileZilla semantics; any received byte resets the timer) | `Error::Timeout`, state `Broken` |
| Waiting for a user prompt | timer paused, no limit; `CancellationToken` aborts | `Error::Cancelled` |
| `QUIT` | 2 s total | ignored |
| Write of a command | `timeout_secs` | `Error::Timeout` |

Every await is wrapped in `tokio::select!` with the operation's `CancellationToken`;
cancellation mid-reply marks the connection `Broken` (reply state unknown) and returns
`Error::Cancelled`. Commands on a `Broken` or `Closed` connection return
`Error::Connection("connection lost")` immediately so `SessionHandle` reconnects.

### Data formats and configuration

Settings read (all from T05, none added here):

| Key | Type | Default | Use |
|---|---|---|---|
| `connection.timeout_secs` | u32 | 20 | inactivity timeout |
| `connection.keepalive` / `keepalive_interval_secs` | bool / u32 | true / 30 | `SessionHandle` schedule |
| `ftp.send_keepalive_command` | `KeepaliveCommand` (`noop`\|`random`, snake_case) | `noop` | §7; invalid values are reset by T05 |
| `logging.level` | u8 0–4 | 2 | `Debug(n)` lines dropped above it (T04) |

Wire formats: RFC 959 commands `VERB SP arg CRLF`; replies per §1. Status-line texts used
in the log (FileZilla wording): `Resolving address of {host}`, `Connecting to {addr}...`,
`Connection established, waiting for welcome message...`, `Logged in`,
`Server does not support non-ASCII characters.` (no UTF8 and Auto), `Disconnected from server`.

### Errors

| Situation | `courier_ftp_core::Error` | User sees (message log / error line) |
|---|---|---|
| TCP/DNS failure | from T07 (`Connection`, `Timeout`) | "Could not connect to server" + detail |
| Inactivity timeout | `Timeout` | "Connection timed out after 20 seconds of inactivity" |
| EOF / reset while waiting | `Connection("connection closed by server")` | same |
| 421 after login | `Connection(text)` | server text; `SessionHandle` reconnects once |
| "too many connections" 421/530 at greeting/login | `ConnectionLimit(text)` | server text; T41 lowers the per-server limit |
| other 421 at greeting/login | `Connection(text)` | server text |
| Bad credentials | `Auth(text)` | "Authentication failed: <text>" |
| Malformed / oversized reply | `Protocol { code: None, message }` | "Invalid reply from server" |
| CR/LF/NUL in argument, refused raw command, unmappable char | `InvalidInput(..)` | the message |
| Prompt cancelled / token cancelled | `Cancelled` | nothing (status "Cancelled") |
| Other 4xx / 5xx from `send_expect` | `Protocol { code, message }` | "<code> <text>" |

### Security and logging

- Secrets: passwords/accounts only as `SecretString`; exposed once into a
  `Zeroizing<Vec<u8>>` write buffer; `Command`/`LoginStep` `Debug` print `****`. The
  message log shows `PASS ****` / `ACCT ****` (T04 `mask_command` as second guard).
- Untrusted input: every reply is bounded (64 KiB line, 10 000 lines, 4 MiB), Telnet
  sequences stripped, control characters replaced before logging or putting server text
  into an `Error` message. The parser is fuzzed (`fuzz/fuzz_targets/ftp_reply.rs`, T91 §7).
- `tracing` (application log, T91 §4): `info` only with the session id and outcome
  (`ftp session {id} connected`), never host, user, path, command or reply text; `debug`
  may contain the host and command verbs, never arguments of `PASS`/`ACCT`. The session
  message log (T04/T55) is the user-facing place for commands and replies.
- No `unwrap`/`expect` outside tests; no `unsafe`.

## Implementation steps

1. Crate skeleton modules, `ReplyCode`/`ReplyClass`/`Reply`, `ReplyParser` with limits,
   Telnet stripping and sanitising; table tests + chunk-split property test.
2. `fuzz_reply_parser` and `fuzz/fuzz_targets/ftp_reply.rs` (+ seed corpus file
   `fuzz/corpus/ftp_reply/` from the test fixtures, `fuzz/seed-corpus.sh` entry).
3. `SessionEncoding`/`LineDecoder` (UTF-8, Auto fallback to windows-1252, custom).
4. `Command` (validation, encoding, IAC doubling, masked `log_text`, zeroizing buffer).
5. `FakeServer` (`testing` module, `test-util` feature) with the control steps.
6. `ControlConnection::from_stream` + greeting state machine + inactivity timeout +
   cancellation + unsolicited-reply handling.
7. `connect` via `net::connect_tcp`, peer/local addresses, `StreamUpgrade` hook.
8. `LoginScript` + login state machine + password/account prompts.
9. `parse_feat`, `negotiate` (SYST, FEAT, OPTS UTF8, OPTS MLST), `pwd` parsing.
10. `keepalive`, `raw_command` guard list, `quit`.
11. Docker e2e login/feature tests in `courier-ftp-e2e` (T76 profiles).

## Acceptance criteria

- [ ] AC1 Multi-line replies parse correctly for: the RFC 959 example (continuation line
  starting with a different code + space), ProFTPD style (`NNN-` on every line), indented
  continuation lines, a bare `NNN` terminator, and LF-only line endings.
- [ ] AC2 Parsing result is identical for every possible split of the input into two and
  three chunks (property test, ≥ 1 000 cases).
- [ ] AC3 Oversized line (> 64 KiB), > 10 000 lines, > 4 MiB, and a first line without a
  code each yield `Error::Protocol` and mark the connection `Broken`; the parser never
  panics (fuzz target runs 30 s in CI without findings).
- [ ] AC4 Login works for: normal (331→230), anonymous, `230` straight after `USER`, `332`
  account required after `PASS`, ask-for-password (prompt only after 331; no prompt when
  `USER` gets 230), and cancelled prompt → `Error::Cancelled`.
- [ ] AC5 530 → `Error::Auth`; "421 Too many connections" at greeting and "530 too many
  connections" → `Error::ConnectionLimit`; any other 421 at greeting and 421 after login →
  `Error::Connection`.
- [ ] AC6 `FEAT` parsed into `Features` (MLST facts with `*`, `REST STREAM`, `AUTH TLS;SSL`,
  `UTF8`, `HASH`); `500` reply to FEAT leaves all flags false and login still succeeds.
- [ ] AC7 Charset: `OPTS UTF8 ON` sent only for Auto/Utf8 with `UTF8` advertised; Auto
  switches to windows-1252 on the first invalid UTF-8 line; custom charset with an
  unmappable character → `Error::InvalidInput` and nothing written.
- [ ] AC8 CR, LF and NUL in any argument (including user and password) are rejected before
  writing; 0xFF bytes are doubled on the wire.
- [ ] AC9 Message log shows `PASS ****` and `ACCT ****`; a canary password never appears in
  `LogMessage`s, `Debug` output or `tracing` output (test captures all three).
- [ ] AC10 Inactivity timeout: server that stops sending for 20 s (paused time) →
  `Error::Timeout`; a server trickling one byte every 15 s does **not** time out.
- [ ] AC11 Cancellation during a reply wait returns `Error::Cancelled` within 100 ms and the
  next command returns `Error::Connection`.
- [ ] AC12 `PWD` parsing: `257 "/a ""b"" c" created` → `/a "b" c`; unquoted fallback works.
- [ ] AC13 `raw_command` refuses every verb in the list without sending; `SITE HELP` is sent
  verbatim and returns all reply lines.
- [ ] AC14 Keep-alive: `noop` sends `NOOP`; `random` sends only `NOOP`, `PWD` or `TYPE`
  (restoring the current type), all three seen over 100 seeded calls; nothing is sent
  while a transfer is open.
- [ ] AC15 Docker e2e: login + negotiate succeed against vsftpd `plain` and `anonymous`,
  proftpd and pure-ftpd profiles (T76); FEAT of proftpd/pure-ftpd shows `mlsd = true`,
  vsftpd `mlsd = false`.
- [ ] AC16 CI gates (T00): `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`,
  `layering` (`cargo tree -p courier-ftp-proto-ftp -i ratatui` empty), `fuzz` pass.

## Tests

### Unit tests
- `reply_single_line_parses_code_and_text` — `220 Ready\r\n` → code 220, text "Ready". AC1.
- `reply_multiline_rfc959_example` — the RFC example incl. `234 A line beginning with
  numbers` inside a `123-` reply → one reply, 4 lines. AC1.
- `reply_multiline_proftpd_prefixed_lines` — `211-` on every line, `211 End`. AC1.
- `reply_multiline_indented_continuation` / `reply_bare_code_terminates` /
  `reply_lf_only_line_endings`. AC1.
- `reply_first_line_without_code_is_malformed`, `reply_line_over_64k_rejected`,
  `reply_more_than_10000_lines_rejected`, `reply_over_4mib_rejected`. AC3.
- `reply_telnet_iac_sequences_stripped` — `IAC WILL 1` dropped, `IAC IAC` → 0xFF. AC3.
- `reply_control_chars_replaced` — ESC `[31m` in text becomes U+FFFD. Security.
- `command_rejects_cr_lf_nul_in_arg` (table over `\r`, `\n`, `\0` in path/user/password). AC8.
- `command_doubles_iac_byte` — windows-1252 `ÿ` (0xFF) → `0xFF 0xFF`. AC8.
- `command_debug_and_log_text_mask_secret` — `PASS`/`ACCT`. AC9.
- `feat_parses_vsftpd_proftpd_pureftpd_samples` — three recorded FEAT replies → expected
  `Features` (snapshot with `insta`). AC6.
- `feat_mlst_implies_mlsd` / `feat_auth_list_split`. AC6.
- `pwd_parses_doubled_quotes`, `pwd_unquoted_fallback`, `pwd_empty_is_error`. AC12.
- `encoding_auto_switches_to_windows1252_on_invalid_utf8`,
  `encoding_custom_unmappable_is_invalid_input`. AC7.
- `raw_command_refused_verbs_table` — every refused verb, case-insensitive. AC13.

### Property / fuzz tests
- `prop_reply_parse_is_chunking_invariant` — random valid replies (1–20 lines, random
  codes, random continuation styles) serialised, split at 1–3 random points → same
  `Vec<Reply>` as unsplit. AC2.
- `prop_reply_parser_never_panics` — random bytes ≤ 128 KiB (same body as the fuzz target). AC3.
- `prop_command_encode_never_contains_crlf_inside` — any accepted argument encodes to bytes
  whose only CRLF is the terminator. AC8.
- Fuzz target `ftp_reply` → `courier_ftp_proto_ftp::reply::fuzz_reply_parser` (also parses
  each reply with `parse_feat` and the PWD parser). AC3.

### Snapshot tests
- `insta` snapshots of parsed `Features` for the FEAT samples (above). No UI in this task.

### Integration tests (`FakeServer`, `tokio::time::pause`)
- `login_normal_331_230`, `login_anonymous_sends_default_password`,
  `login_230_after_user_skips_pass`, `login_332_sends_acct`,
  `login_ask_password_prompts_only_after_331`, `login_prompt_cancelled_returns_cancelled`. AC4.
- `login_530_is_auth_error`, `greeting_421_too_many_is_connection_limit`,
  `greeting_421_other_text_is_connection`, `login_530_too_many_connections_is_connection_limit`,
  `reply_421_after_login_is_connection`. AC5.
- `login_prompt_accepted_emits_credential_accepted` — ask-for-password login → 230 →
  `CoreEvent::CredentialAccepted` with the prompt's id; a 530 emits none. AC4.
- `greeting_120_then_220_succeeds`. 
- `negotiate_without_feat_uses_defaults`, `negotiate_sends_opts_utf8_only_when_advertised`,
  `negotiate_sends_opts_mlst_with_advertised_facts`. AC6, AC7.
- `inactivity_timeout_fires_after_20s`, `trickling_server_does_not_time_out`. AC10.
- `cancel_during_reply_returns_cancelled_and_breaks_connection`. AC11.
- `unsolicited_421_before_command_is_connection_error`.
- `keepalive_variants_send_expected_commands`, `keepalive_skipped_during_transfer`. AC14.
- `canary_password_never_logged` — runs a login with password `CANARY-PW-…`, collects
  `LogMessage`s, `format!("{:?}")` of all public structs and a `tracing` test subscriber
  at `trace`; asserts the canary is absent. AC9.
- `quit_waits_at_most_2s` (server never answers QUIT).

### End-to-end tests (`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`, T76)
- `ftp_control_login_vsftpd_plain`, `ftp_control_login_vsftpd_anonymous`,
  `ftp_control_login_proftpd`, `ftp_control_login_pureftpd` — connect, login, negotiate,
  `PWD`, `NOOP`, `QUIT`; assert `Features` per server (vsftpd: no MLSD; proftpd and
  pure-ftpd: MLSD + MFMT). AC15.
- `ftp_control_wrong_password_is_auth_error` (vsftpd `plain`). AC5.

## Out of scope

- Data connections, transfer commands, `TYPE` decisions (T11); TLS (T12); listings (T13);
  `Backend` methods and path translation (T14); proxy scripts (T15).
- Kerberos/GSS (`AUTH GSSAPI`, `ADAT`, `MIC`/`ENC`/`CONF`, 63x replies) — dropped (D8).
- `HOST` (RFC 7151), `CLNT`, `LANG` (RFC 2640 §4), `MODE Z`, `MODE B`/restart markers.
- Telnet option negotiation (we never answer `DO`/`WILL`).

## Open questions

- T05 keeps `ftp.send_keepalive_command` default `noop`. FileZilla rotates `NOOP`/`PWD`/
  `TYPE` because some servers don't count `NOOP` as activity. Should the default be
  `random`? (Setting owner: T05.)
- Resolved: warnings are `Status` lines prefixed `Warning: ` (T04 has no `LogKind::Warning`);
  "too many connections" maps to `Error::ConnectionLimit` (T02).
