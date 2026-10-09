# T11 — FTP data connections and transfer modes

**Phase:** B FTP · **Milestone:** M3 · **Depends on:** T10 · **Crate(s):** `courier-ftp-proto-ftp` (`data`, `passive`, `active`, `ascii`, `transfer` modules), uses `courier-ftp-core` `settings::decide_transfer_type` (T05) · **Decisions:** D1, D11 · **FEATURES.md:** §1 (active/passive, fallback to active, external IP, port range, IP lookup), §5 (resume, > 4 GB), §6 (ASCII/binary, file type list)
**Related (integrates with, not blocking):** T76
**Reference:** sverb `fuzz/fuzz_targets/socks5_request.rs` (fuzz body shared with a property test).

## Goal

Open FTP data connections in passive (`EPSV`/`PASV`) or active (`EPRT`/`PORT`) mode
exactly as RFC 959 and RFC 2428 define them, move bytes in ASCII or binary type, resume
with `REST`, and abort cleanly with `ABOR` so the control connection stays usable. The
result is a streaming `DataStream` (read for downloads/listings, write for uploads) that
T12 wraps in TLS, T13 parses, T14 returns from `open_read`/`open_write` and T41 copies.

## Context

**Exists before this task:** T10's `ControlConnection` (`send`, `write_command`,
`read_reply`, `features()`, `peer_addr()`/`local_addr()`, `current_type()`,
`mark_transfer_open`, `FakeServer`), T07's `net::connect_tcp` and `local_addr_for`,
T05's `ftp.*` and `file_types.*` settings and `decide_transfer_type`, T02 errors and
`TransferType` (`Ascii`/`Binary`), T03 `WriteMode` and `TransferOpts` (incl. `range_len`).

**Later tasks need from this one:**
- T12: a hook to wrap every data socket in TLS after it is connected/accepted
  (`DataTlsHook`), and the ordering "TLS handshake after the 1xx reply".
- T13/T14: `open_listing(cmd)` returning the full listing bytes.
- T14: `open_download`, `open_upload`, `finish`, `abort`, `ensure_type`.
- T41/T41b: cancellation semantics (drop the stream, then `finish_transfer` aborts),
  `u64` offsets, socket buffer sizes (T41b raises them).
- T72: `PassiveProbe`/`ActiveProbe` (connect, `PASV`/`EPSV` + `LIST`, `PORT`/`EPRT` + `LIST`).

## Technical specification

### Types and APIs

```rust
// Uses T05's courier_ftp_core::settings::decide_transfer_type(file_name, choice, ft)
// (not redefined here); T14 calls it per file and passes the result to `open`.

// courier_ftp_proto_ftp::data -----------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataMode { Passive, Active }

/// Per-session data-connection policy, built from `Settings` + `ConnectInfo` (T14).
pub struct DataConfig {
    pub mode: DataMode,                        // ftp.transfer_mode / site override
    pub fallback_to_active: bool,              // ftp.fallback_to_active (true)
    pub ignore_unroutable_pasv_ip: bool,       // ftp.passive_ignore_unroutable_ip (true)
    pub external_ip: ActiveExternalIp,         // ftp.active_external_ip (Auto)
    /// ftp.active_no_external_ip_on_local (true): local server → advertise the local IP.
    pub no_external_ip_on_local: bool,
    pub port_range: Option<(u16, u16)>,        // ftp.active_port_range (None)
    /// `!net.proxy.allows_inbound()` (T07): active mode impossible.
    pub through_generic_proxy: bool,
    pub net: NetOpts,                          // T07 options for data dials (Purpose::Data)
    pub control_host: String,                  // host name dialled (used with proxies)
    pub timeout: Duration,                     // connection.timeout_secs
    pub socket_buffer: usize,                  // 256 KiB here; T41b raises to 4 MiB
}

/// Per-session learned state ("remember the choice for the session").
#[derive(Debug, Default)]
pub struct DataState {
    pub epsv_failed: bool, pub pasv_failed: bool, pub eprt_failed: bool,
    pub use_active: bool,            // set after a successful passive→active fallback
    pub rest_supported: Option<bool>,// None = unknown (no FEAT), learned from 350/5xx
    pub external_ip_cache: Option<IpAddr>,
}

/// A connected data socket before TLS: dialled through T07 (passive; may be proxied) or
/// accepted from our listener (active). Implements AsyncRead + AsyncWrite + Unpin + Send.
pub enum RawData { Dialed(NetStream), Accepted(tokio::net::TcpStream) }

/// Wraps a freshly connected data socket (TLS, T12). Plain FTP passes `None`.
#[async_trait]
pub trait DataTlsHook: Send + Sync {
    async fn wrap(&self, raw: RawData) -> Result<DataIo>;
}
pub enum DataIo { Plain(RawData), Tls(Box<tokio_rustls::client::TlsStream<RawData>>) }

/// What the transfer command is.
pub enum TransferCommand {
    List { args: Option<String> },  // LIST [-a]       (T14/T13)
    Mlsd,                           // MLSD            (T14/T13)
    /// `range_len` = `TransferOpts.range_len` (T03): stop after this many bytes.
    Retr { path: String, offset: u64, range_len: Option<u64> },
    Stor { path: String, offset: u64 },   // offset > 0 → REST n + STOR
    Appe { path: String },
}

/// An open transfer. Exactly one may exist per control connection.
pub struct DataStream { /* io: DataIo (+ ascii adapter), bytes: u64, direction, idle timer */ }
impl AsyncRead for DataStream {}   // downloads, listings
impl AsyncWrite for DataStream {}  // uploads
impl DataStream { pub fn bytes_transferred(&self) -> u64; }

/// Session-level operations used by T14 (a short-lived borrow bundle).
pub struct FtpData<'a> {
    pub ctrl: &'a mut ControlConnection,
    pub cfg: &'a DataConfig,
    pub state: &'a mut DataState,
}
impl FtpData<'_> {
    /// Send `TYPE A`/`TYPE I` only when it differs from `ctrl.current_type()`.
    pub async fn ensure_type(&mut self, t: TransferType, cancel: &CancellationToken) -> Result<()>;
    /// Opens the data connection, sends REST (if offset>0) and the command, waits for
    /// 125/150, applies TLS hook. Returns the stream; the control stays `TransferOpen`.
    pub async fn open(&mut self, cmd: TransferCommand, ty: TransferType,
                      tls: Option<&dyn DataTlsHook>, cancel: &CancellationToken)
                      -> Result<DataStream>;
    /// After the stream reached EOF (download) or was shut down (upload): read the final
    /// 226/250 reply. If the stream was dropped early → `abort` instead.
    pub async fn finish(&mut self, stream: Option<DataStream>, cancel: &CancellationToken)
        -> Result<()>;
    /// ABOR sequence + resync (§8). Leaves the control `Ready` or `Broken`.
    pub async fn abort(&mut self, stream: Option<DataStream>) -> Result<()>;
    /// Whole listing in memory (cap 64 MiB), for T13.
    pub async fn read_listing(&mut self, cmd: TransferCommand, tls: Option<&dyn DataTlsHook>,
                              cancel: &CancellationToken) -> Result<Vec<u8>>;
}

// passive.rs / active.rs (pure parsers, fuzzed) -----------------------------------------
pub fn parse_pasv(text: &str) -> Result<SocketAddrV4, AddrParseError>;     // 227
pub fn parse_epsv(text: &str) -> Result<u16, AddrParseError>;              // 229
pub fn format_port(addr: SocketAddrV4) -> String;                          // "h1,h2,h3,h4,p1,p2"
pub fn format_eprt(addr: SocketAddr) -> String;                            // "|1|ip|port|" / "|2|ip|port|"
pub fn parse_eprt(arg: &str) -> Result<SocketAddr, AddrParseError>;        // for tests/fake server
pub fn is_unroutable(ip: IpAddr) -> bool;
/// Fuzz entry (T91 §7 "PASV/EPSV parser").
pub fn fuzz_pasv_epsv(data: &[u8]);

// ascii.rs ------------------------------------------------------------------------------
/// Streaming network-ASCII → local text (download). CRLF → LF on Unix/macOS; identity on
/// Windows. Handles a CR at the end of one chunk followed by LF at the start of the next.
pub struct AsciiDecode<R> { /* inner, pending_cr: bool */ }
/// Local text → network ASCII (upload). Bare LF → CRLF on Unix/macOS (existing CRLF kept);
/// identity on Windows.
pub struct AsciiEncode<W> { /* inner, last_was_cr: bool, pending output */ }
```

### Behaviour

**1. Mode selection per transfer.**

```
mode = Active if DataConfig.mode == Active or DataState.use_active, else Passive
Passive:
  family = control peer address family (IPv6 → EPSV is mandatory, PASV can't carry IPv6)
  if IPv6 or (features.epsv and !epsv_failed): try EPSV
      EPSV reply 500/501/502/504 → epsv_failed = true; IPv4 → try PASV; IPv6 → error
  else: PASV  (if !features.feat_supported and !epsv_failed, EPSV is tried first anyway —
               many servers support EPSV without listing it)
  data connect fails (refused / timeout) and fallback_to_active and !through_generic_proxy
      → retry the same transfer once in Active; on success use_active = true (log Status
        "Passive mode failed, using active mode for this session")
Active: §3
```

**2. Passive mode.**

- `EPSV` (RFC 2428 §3) reply: `229 Entering Extended Passive Mode (|||6446|)`. Parse:
  find `(`, then four delimiter characters `d` (the same printable ASCII 33–126 char, `|`
  by convention), port between the 3rd and 4th: `(<d><d><d><port><d>)`. Port 1–65535,
  decimal, ≤ 5 digits; otherwise `Error::Protocol { code: Some(229), "invalid EPSV reply" }`.
  Connect to the **control connection's peer address** (RFC 2428) — with a generic proxy,
  to `control_host` through the proxy.
- `PASV` (RFC 959) reply: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`. Servers vary
  (`227 =h1,h2,…`, no brackets, spaces after commas), so: scan for the first run of six
  comma-separated decimal numbers (optional spaces), each 0–255; port = `p1*256 + p2`, must
  be ≠ 0. Fewer than six numbers, a value > 255 or port 0 → `Error::Protocol { code: Some(227) }`.
- **Address choice for PASV** (anti-bounce/SSRF, T91 "PASV bounce"):

  | PASV IP | Control peer | Generic proxy | Connect to |
  |---|---|---|---|
  | any | any | yes | `control_host:port` through the proxy |
  | equal to peer | – | no | PASV IP |
  | unroutable (`is_unroutable`) and peer routable, `ignore_unroutable_pasv_ip` | – | no | peer IP (Status: "Server sent passive reply with unroutable address. Using server address instead.") |
  | unroutable, setting off | – | no | PASV IP |
  | routable but **different** from peer | – | no | **peer IP** (Status: "Server sent a passive reply with a different address. Using server address instead.") |

  `is_unroutable`: `0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`,
  `192.168/16`, `198.18/15`, `240/4`, IPv6 `::`, `::1`, `fc00::/7`, `fe80::/10`.
- The data socket is opened with `net::connect_tcp` (T07: proxy, timeout, cancellation),
  `TCP_NODELAY` off, `SO_RCVBUF`/`SO_SNDBUF` = `socket_buffer`.
- Ordering: data TCP connect **before** sending the transfer command (some servers only
  accept the connection for a short time and some only send 150 once connected).

**3. Active mode.**

- Through a generic proxy (T07, `ProxyConfig::allows_inbound() == false`) →
  `Error::Unsupported("active mode FTP does not work through an HTTP or SOCKS proxy; use
  passive mode")`, logged as an Error line; no fallback attempt.
- Listener: bind on the control connection's **local IP** (same family). Port:
  `port_range = Some((lo, hi))` → start at a random port in `lo..=hi`, try each port in the
  range once (wrapping), first successful bind wins; none free →
  `Error::Connection("no free port in active mode port range lo–hi")`. `None` → port 0
  (ephemeral). Backlog 1.
- Advertised address:
  - `no_external_ip_on_local` (`ftp.active_no_external_ip_on_local`, default true) and the
    control peer IP is private, loopback, link-local or unspecified (`is_unroutable`) → the
    listener's local IP, whatever `external_ip` says (FileZilla "Don't use external IP
    address on local connections"); no URL lookup is made.
  - `Auto` → the listener's local IP.
  - `Fixed(ip)` → `ip` if same family as the control connection, else local IP (Status
    warning).
  - `FromUrl(url)` → GET once per session (cached in `DataState.external_ip_cache`) via
    T07 `net::http_get_small(url, &opts, log, 1024)` (direct, 10 s timeout, body ≤ 1 KiB),
    trimmed, parsed as `IpAddr` of the control family; any failure → local IP + Status
    `Warning: Failed to retrieve external IP address, using local address`. T07's helper
    supports `http://` only; an `https://` URL fails the same way (logged) until T74's
    HTTP client exists (same rule as T72).
- Command:
  - IPv4: `PORT h1,h2,h3,h4,p1,p2` → 200. Reply 500/501/502 → try
    `EPRT |1|a.b.c.d|port|` (unless `eprt_failed`); that failing too → `eprt_failed = true`
    and `Error::Unsupported("server refused active mode")`.
  - IPv6: `EPRT |2|addr|port|` (RFC 2428 §2; address in RFC 5952 text form) → 200;
    `522` (network protocol not supported) or 500/502 → `Error::Unsupported("server does
    not support active mode over IPv6")`.
- After 200, send the transfer command, then concurrently wait for the 1xx reply and
  `accept()` (bounded by `timeout`). Accepted peer IP must equal the control peer IP;
  otherwise the socket is closed, a Status line `Warning: rejected data connection from
  unexpected address` logged, and accepting continues until the timeout. With an FTP proxy (T15)
  the control peer is the proxy, so the rule is unchanged. The listener is closed after the
  first accepted connection.
- Accept timeout → `Error::Connection("server did not connect to the data port")`, then the
  ABOR resync (§8).

**4. Transfer sequence (both modes).**

```
ensure_type(t)                         # TYPE A | TYPE I, only if changed; 200 expected
[passive: PASV/EPSV + TCP connect]   [active: listen + PORT/EPRT]
if offset > 0: REST <offset>           # 350 expected (§6)
<cmd> <path>                           # RETR/STOR/APPE/LIST/MLSD
reply:  125 | 150 → transfer starts   (mark_transfer_open(true))
        226 | 250 without 1xx → empty transfer (listing of an empty dir on some servers)
        425 | 426 → Error::Protocol (transient) — passive fallback rule applies to 425
        4xx/5xx → mapped error (T14 table), data socket closed, control stays Ready
[active: accept]
TLS hook (T12): handshake AFTER the 1xx reply
stream bytes (download: until EOF; upload: until caller shutdown())
finish(): upload → TLS close_notify (T12) + TCP shutdown(Write); read final reply
          226 | 250 → Ok;  426/451/4xx → Error::Protocol (transient); 5xx → mapped
```

- A final `226` that arrives on the control connection **before** the data socket hits
  EOF is normal (server finished writing, bytes still in flight): `finish` drains/awaits
  data EOF first and only then evaluates the already-buffered reply.
- MODE and STRU are never sent (defaults `S`, `F`). `TYPE A` means `TYPE A N`.
- **Ranged reads** (`Retr { range_len: Some(n) }`, T41b segments): the `DataStream`
  returns EOF after exactly `n` bytes (fewer only if the server ends the data first).
  If the server's data has not ended at that point, `finish` runs the abort sequence (§8)
  but treats the transfer's `426`/`451`/`226` reply as success (the requested range was
  delivered); the bytes counted are `n`. If the data ended exactly at `n`, the normal
  `226` path applies.

**5. Transfer type and ASCII conversion.**

- The type per file is decided by T05's `decide_transfer_type(file_name, choice,
  &settings.file_types)` (rules owned and tested there); T14 passes the result to `open`,
  which calls `ensure_type`.
- Listings are read in whatever type is current (no extra `TYPE` round trip; T13 accepts
  CRLF and LF).
- `AsciiDecode` (download, Unix/macOS): `CR LF` → `LF`; lone `CR` passes through; a `CR`
  that ends a chunk is held until the next byte (or EOF, when it is emitted). Windows:
  identity (network ASCII already is CRLF).
- `AsciiEncode` (upload, Unix/macOS): `LF` not preceded by `CR` → `CR LF`; existing `CR LF`
  unchanged (state survives chunk boundaries). Windows: identity.
- Resume is refused for ASCII transfers (offsets differ between the two representations):
  `offset > 0` with `Ascii` → `Error::Unsupported("resume is not possible in ASCII mode")`
  and a Status line; T42 then restarts from 0 or asks.

**6. REST (RFC 3659 §5).** `REST <n>` with `n: u64` in decimal (offsets > 4 GiB valid).
`350` → continue. `500/501/502/504` → `rest_supported = Some(false)` and
`Error::Unsupported("server does not support resuming")`. `features.rest_stream` →
`rest_supported = Some(true)` from the start. `STOR` with `REST` (upload resume) is used
only when `rest_supported != Some(false)`; T14 falls back to `APPE` (T14 `open_write`).

**7. Inactivity on data.** While the caller is waiting in a read/write on the data
socket, no progress for `timeout` (20 s) → `Error::Timeout` and the abort sequence. Time
the caller spends elsewhere (speed limiter, T44) is not counted (timer armed only while a
poll is pending).

**8. Abort and resync (RFC 959 §4.1.3).** Triggered by `abort()`, by `finish()` with a
stream that was dropped before EOF, or by a data error.
1. Close the data socket immediately (no TLS `close_notify` — we are discarding).
2. Write `ABOR` (plain; the Telnet IP/Synch urgent sequence is not sent — it can't be sent
   inside TLS and modern servers don't need it).
3. Read replies with a 2 s grace per reply, at most 3: the transfer's own reply (`426`,
   `451`, or `226` if it had already completed) and the reply to `ABOR` (`225`/`226`, or
   `500`/`502` on servers without ABOR).
4. **Resync:** send `NOOP` and read replies until a `200` arrives (max 8 replies, total
   `timeout`); every reply skipped is logged at `Debug(3)`. No `200` → connection `Broken`
   (`SessionHandle` reconnects on the next call).
5. Target: control usable again ≤ 1 s after the abort on a responsive server (T41 AC).

**9. Limits.** One `DataStream` per control connection (`open` while one is open →
`Error::InvalidInput("a transfer is already in progress")`). Listings capped at **64 MiB**
(`Error::Protocol { code: None, "directory listing too large" }`, then abort). Sizes and
offsets are `u64` everywhere.

### Data formats and configuration

| Command / reply | Format |
|---|---|
| `PASV` → `227` | `227 Entering Passive Mode (192,0,2,10,195,149)` → 192.0.2.10:50069 |
| `EPSV` → `229` | `229 Entering Extended Passive Mode (|||50069|)` |
| `PORT` | `PORT 192,0,2,7,195,149` |
| `EPRT` | `EPRT |1|192.0.2.7|50069|`, `EPRT |2|2001:db8::7|50069|` |
| `REST` | `REST 5368709120` → `350 Restarting at 5368709120` |
| `TYPE` | `TYPE I` / `TYPE A` → `200` |

Settings (T05, none added): `ftp.transfer_mode` (`Passive`), `ftp.fallback_to_active`
(true), `ftp.active_external_ip` (`Auto` \| `Fixed(IpAddr)` \| `FromUrl(String)`),
`ftp.active_no_external_ip_on_local` (true), `ftp.active_port_range` (`None`; validated
`1024 ≤ lo ≤ hi ≤ 65535` in T05),
`ftp.passive_ignore_unroutable_ip` (true), `file_types.default_type` (`Auto`),
`file_types.ascii_extensions`, `file_types.dotfiles_ascii` (true),
`file_types.no_extension_ascii` (true), `connection.timeout_secs` (20). Site override:
`ConnectInfo` transfer mode (`Default`/`Active`/`Passive`, T31/T03).

### Errors

| Situation | Error | Message |
|---|---|---|
| Bad 227/229 | `Protocol { code: Some(227/229) }` | "Invalid passive mode reply" |
| Data connect refused/timeout (no fallback) | `Connection` / `Timeout` | "Failed to open data connection" |
| Active through generic proxy | `Unsupported` | as above |
| No free port in range | `Connection` | "no free port in active mode port range" |
| Server never connects (active) | `Connection` | "server did not connect to the data port" |
| REST unsupported / ASCII resume | `Unsupported` | as above |
| 425 / 426 / 451 | `Protocol { code }` (transient → T41 retries) | server text |
| Data inactivity | `Timeout` | "Data connection timed out" |
| Listing > 64 MiB | `Protocol { code: None }` | "directory listing too large" |
| Second open | `InvalidInput` | "a transfer is already in progress" |
| Cancelled | `Cancelled` | (abort sequence runs; control stays usable) |

### Security and logging

- PASV/EPSV address rules above prevent a hostile server from making the client connect to
  third-party or internal hosts; accepted active connections are checked against the control
  peer IP (anti-bounce). Both parsers are fuzzed (`fuzz/fuzz_targets/ftp_pasv.rs`).
- Message log: `Command`/`Response` lines for every command; Status lines for mode
  fallback, address substitution and external-IP lookup failures. `Debug(3)`: chosen data
  address, bytes transferred, abort/resync details.
- `tracing` at `info`: only session id + "data connection failed/fell back" with no
  addresses; addresses and paths only at `debug` (T91 §4).
- The external-IP URL response is untrusted: size-capped, must parse as an IP.

## Implementation steps

1. `ensure_type` (TYPE only on change, using T05's `decide_transfer_type` result).
2. `parse_pasv`, `parse_epsv`, `format_port`, `format_eprt`, `parse_eprt`, `is_unroutable`
   + property tests + `fuzz/fuzz_targets/ftp_pasv.rs`.
3. `AsciiDecode`/`AsciiEncode` with chunk-boundary handling and property tests.
4. `FakeServer` data steps (`PasvListen`, `EpsvListen`, `ExpectPortThenConnect`,
   `SendData`, `RecvData`, `CloseData`, `ExpectAbor`) over loopback TCP.
5. Passive open (`EPSV`→`PASV`, address rules, ordering) + `finish` + listing reader.
6. Active open (listener, port range, external IP sources incl.
   `active_no_external_ip_on_local`, `PORT`/`EPRT`, accept check).
7. Fallback passive → active and `DataState` memory.
8. `REST` handling, `range_len` ranged reads, upload shutdown, `226`-before-EOF race.
9. Abort + resync; inactivity timer.
10. Docker e2e against vsftpd profiles.

## Acceptance criteria

- [ ] AC1 `parse_pasv` accepts the format variants in the test table and rejects > 255
  values, < 6 numbers and port 0; `parse_epsv` accepts any repeated delimiter and rejects
  mismatched delimiters and ports > 65535.
- [ ] AC2 EPSV, PASV, EPRT (IPv4 + IPv6) and PORT each complete a `RETR` against the fake
  server; an IPv6 data channel works against `[::1]`.
- [ ] AC3 PASV address rules: unroutable address replaced by the peer when the setting is
  on (kept when off); a different routable address is always replaced; Status line logged.
- [ ] AC4 Passive failure with `fallback_to_active` retries once in active mode, succeeds,
  and the next transfer uses active mode without trying passive.
- [ ] AC5 Active mode honours the port range (bound port within range) and rejects a data
  connection from an unexpected IP; through a generic proxy it fails with `Unsupported`;
  with `active_no_external_ip_on_local` on and a loopback/private control peer, `PORT`/`EPRT`
  carries the local IP even when `external_ip` is `Fixed`/`FromUrl` (no URL request made),
  and with it off the external IP is sent.
- [ ] AC6 `AsciiDecode`/`AsciiEncode` output is independent of chunking (CR at chunk end)
  and `decode(encode(x)) == x` for LF-only text.
- [ ] AC7 Resume via `REST` produces byte-identical files for download and upload, including
  an offset > 4 GiB (fake server, sparse data) — `REST 5368709120` on the wire.
- [ ] AC8 Cancelling a transfer mid-stream runs ABOR + resync and the next `PWD` succeeds
  within 1 s (paused time) for each server reply variant (426+226, 226 only, 225, 500).
- [ ] AC9 A `226` received before the data EOF does not cause an error or data loss.
- [ ] AC10 `ensure_type` sends `TYPE A`/`TYPE I` only when the requested type differs from
  the tracked type; a `Retr` with `range_len: Some(n)` yields exactly `n` bytes, then the
  abort sequence leaves the control usable and `finish` returns Ok.
- [ ] AC11 Docker e2e: passive and active downloads/uploads (SHA-256 verified) against
  vsftpd `plain`, `active-only` and `passive-unroutable` profiles.
- [ ] AC12 CI gates (T00) pass, including the `ftp_pasv` fuzz target (30 s).

## Tests

### Unit tests
- `pasv_parses_standard_reply`, `pasv_parses_without_brackets`,
  `pasv_parses_with_spaces_and_equals_sign`, `pasv_rejects_value_over_255`,
  `pasv_rejects_port_zero`, `pasv_rejects_five_numbers`. AC1.
- `epsv_parses_pipe_delimiter`, `epsv_parses_other_delimiter`,
  `epsv_rejects_mixed_delimiters`, `epsv_rejects_port_65536`. AC1.
- `eprt_formats_ipv4_and_ipv6`, `port_formats_high_port`. AC2.
- `unroutable_ranges_table` (every listed range + public examples). AC3.
- `ensure_type_sends_type_only_on_change`. AC10.
- `ascii_decode_cr_at_chunk_end`, `ascii_decode_lone_cr_kept`,
  `ascii_encode_existing_crlf_kept`, `ascii_windows_is_identity` (`#[cfg(windows)]`). AC6.
- `ascii_resume_refused`.

### Property / fuzz tests
- `prop_pasv_format_parse_roundtrip` — any `SocketAddrV4` with port ≠ 0 →
  `parse_pasv(format)` == addr, with random surrounding text. AC1.
- `prop_eprt_roundtrip` (IPv4 and IPv6). AC2.
- `prop_ascii_chunking_invariant` — random bytes, random chunk sizes 1–64 → identical
  output to single-chunk conversion. AC6.
- `prop_ascii_roundtrip_lf_text`. AC6.
- Fuzz target `ftp_pasv` → `fuzz_pasv_epsv` (both parsers; must not panic). AC12.

### Snapshot tests
Not applicable (no UI, no corpus).

### Integration tests (`FakeServer` over loopback TCP, `tokio::time::pause` where timing matters)
- `retr_via_epsv`, `retr_via_pasv_when_epsv_rejected`, `retr_via_port`,
  `retr_via_eprt_ipv6_loopback`. AC2.
- `pasv_unroutable_ip_replaced_by_peer`, `pasv_unroutable_kept_when_setting_off`,
  `pasv_foreign_routable_ip_replaced`. AC3.
- `passive_failure_falls_back_to_active_and_remembers`. AC4.
- `active_port_range_respected`, `active_rejects_foreign_peer`,
  `active_through_proxy_unsupported`, `active_external_ip_from_url_cached_once`,
  `active_external_ip_url_failure_uses_local`,
  `active_local_peer_uses_local_ip_when_setting_on` (Fixed 203.0.113.5, loopback server →
  `PORT 127,0,0,1,…`; setting off → `203,0,113,5`). AC5.
- `retr_range_len_stops_after_n_bytes_and_aborts` (server sends 1 MiB, range 100 KiB →
  100 KiB read, ABOR + resync, `finish` Ok, next `PWD` works),
  `retr_range_len_reaching_file_end_reads_226`. AC10.
- `rest_resume_download_over_4gib_offset`, `rest_resume_upload_byte_identical`,
  `rest_unsupported_reports_unsupported`. AC7.
- `abort_variants_leave_control_usable` (table over 426+226 / 226 / 225 / 500),
  `abort_without_200_marks_broken`. AC8.
- `final_226_before_data_eof_is_ok`. AC9.
- `listing_over_64mib_rejected`, `second_open_rejected`, `data_inactivity_timeout`.

### End-to-end tests (`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`, T76)
- `ftp_data_passive_roundtrip_vsftpd` — upload + download 10 MiB, SHA-256 equal. AC11.
- `ftp_data_active_roundtrip_vsftpd_active_only`. AC11.
- `ftp_data_passive_unroutable_profile_uses_peer`. AC3, AC11.
- `ftp_data_resume_after_cut_slow_profile` — cancel mid-download on `slow`, resume, hash
  equal. AC7, AC8.

## Out of scope

- TLS on data connections (T12), listing parsing (T13), choosing `STOR` vs `APPE` and
  `SIZE` checks (T14), segmented transfers and socket-buffer tuning (T41b), speed limits
  (T44).
- `MODE Z`/`MODE B`, `STOU`, `LPRT`/`LPSV`, `EPSV ALL`, Telnet IP/Synch on `ABOR`, FXP
  (server-to-server).

## Open questions

- PASV replies naming a **different public IP** than the control peer are always replaced
  with the peer address (safe default, same as curl). FileZilla connects to such addresses
  unless they are unroutable. Do we need a setting (e.g. `ftp.trust_pasv_address`, off by
  default) for server farms that really hand out another host?
