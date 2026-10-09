# T07 — Network layer: sockets, IPv6, generic proxies

**Phase:** A Foundation · **Milestone:** M2 · **Depends on:** T02, T04, T05 · **Crate(s):** `courier-ftp-core` (`net` module) · **Decisions:** D1, D2 · **FEATURES.md:** §1 (IPv6, HTTP/1.1 CONNECT and SOCKS4/5 proxies, timeouts)
**Related (integrates with, not blocking):** T11, T31
**Reference:** sverb `crates/sverb-conn/src/ssh/tcp.rs` (DNS, Happy Eyeballs, `STAGGER`), `crates/sverb-conn/src/proxy/{mod,http_connect,socks5}.rs` (HTTP CONNECT in-house with `PrefixedStream`, SOCKS5 via `tokio-socks`, readable error messages)

## Goal

One function every protocol uses to open a TCP connection: DNS, IPv4/IPv6 with Happy
Eyeballs, an inactivity-based timeout, cancellation by drop, socket options, and HTTP/1.1
CONNECT, SOCKS4/4a and SOCKS5 proxies — with FileZilla-style Status lines in the message
log and no secret ever logged.

## Context

- Before: T02 (`Error`, `SecretString`, `ServerAddress` host rules), T04 (`SessionLog`,
  prompts for a proxy password), T05 (`connection.*`, `proxy.generic.*` settings).
- After: T10 (FTP control connection, implicit TLS on top), T11 (FTP data connections,
  active mode refusal through proxies, external-IP lookup), T20 (SSH transport via
  `russh::client::connect_stream`), T72 (network wizard). T03's `ConnectInfo.proxy` /
  `proxy_password` are turned into a `ProxyConfig` here. T41b sets data-socket buffer sizes.

## Technical specification

### Types and APIs

Module `courier_ftp_core::net` (`net/{mod,dial,happy,proxy,http_connect,socks,stream,http_get}.rs`).

```rust
/// Target of a connection. `host` is a hostname or IP literal WITHOUT brackets.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPort { pub host: String, pub port: u16 }
impl HostPort {
    pub fn new(host: impl Into<String>, port: u16) -> Self;
    /// "host:port" / "[v6]:port".
    pub fn authority(&self) -> String;
    /// Parse "host:port" / "[v6]:port". None if no valid port (sverb split_host_port).
    pub fn parse(s: &str) -> Option<Self>;
}

/// User/password for a proxy. Debug prints the password as [REDACTED].
pub struct ProxyCredentials { pub user: String, pub password: Option<SecretString> }

/// How to reach the target. Built from settings + ConnectInfo (T03); holds secrets.
pub enum ProxyConfig {
    Direct,
    Http { proxy: HostPort, auth: Option<ProxyCredentials> },
    /// SOCKS4a when the target is a hostname; plain SOCKS4 for IPv4 literals. `user` = USERID field.
    Socks4 { proxy: HostPort, user: String },
    Socks5 { proxy: HostPort, auth: Option<ProxyCredentials> },
}
impl ProxyConfig {
    /// `choice = Bypass` or `settings.kind = none` → Direct. Port 0 → 8080 (HTTP) / 1080 (SOCKS).
    /// `password` comes from the vault item `settings.credential_id` (resolved by the caller).
    pub fn from_settings(settings: &GenericProxySettings, choice: ProxyChoice,
                         password: Option<SecretString>) -> Result<Self>;
    /// "direct", "http", "socks4", "socks5" (logs).
    pub fn kind(&self) -> &'static str;
    /// Inbound connections (FTP active mode) are impossible through any proxy.
    pub fn allows_inbound(&self) -> bool;          // true only for Direct
}
impl fmt::Debug for ProxyConfig;                    // redacted

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose { Control, Data }

/// Options for one dial.
pub struct NetOpts {
    /// Bounds DNS, the TCP race and the proxy handshake (each separately).
    pub timeout: Duration,                 // connection.timeout_secs
    pub prefer_ipv6: bool,                 // connection.prefer_ipv6
    pub allow_ipv6: bool,                  // connection.ipv6
    pub purpose: Purpose,                  // Control → TCP_NODELAY
    /// SO_RCVBUF/SO_SNDBUF request (T41b: 4 MiB for FTP data). None = OS default.
    pub socket_buffer: Option<usize>,
    pub proxy: ProxyConfig,
}
impl NetOpts {
    pub fn from_settings(s: &Settings, purpose: Purpose, proxy: ProxyConfig) -> Self;
}

/// A connected byte stream (possibly through a proxy). Implements AsyncRead + AsyncWrite
/// + Unpin + Send + Debug. Bytes the proxy sent after its CONNECT response are replayed
/// first (sverb PrefixedStream).
pub struct NetStream { /* PrefixedStream<TcpStream>, addrs, proxied */ }
impl NetStream {
    /// Our end of the TCP connection (T11 active mode binds on this IP).
    pub fn local_addr(&self) -> SocketAddr;
    /// The TCP peer: the server, or the proxy when proxied.
    pub fn peer_addr(&self) -> SocketAddr;
    /// The server's IP when connected directly; None through a proxy (DNS at the proxy).
    pub fn target_ip(&self) -> Option<IpAddr>;
    pub fn is_proxied(&self) -> bool;
    /// Change buffer sizes later (T41b). Errors are logged at debug and ignored.
    pub fn set_socket_buffer(&self, bytes: usize);
}

/// Dial `target` with `opts`, logging Status/debug lines to `log`.
/// Cancel by dropping the future (T03 convention).
pub async fn connect_tcp(target: &HostPort, opts: &NetOpts, log: &SessionLog) -> Result<NetStream>;

/// Pure parser for the proxy's CONNECT response head (fuzz target `http_connect_response`).
pub fn parse_connect_response(head: &[u8]) -> Result<ConnectResponse, HttpConnectError>;
pub struct ConnectResponse { pub code: u16, pub reason: String /* sanitised */, pub header_len: usize }

/// Minimal HTTP/1.0 GET over `connect_tcp` for `http://` URLs only (T11 "get external IP
/// from URL"). Status 200 required, no redirects, body ≤ `max_body` bytes (≤ 4096),
/// whole request within opts.timeout. Errors: InvalidInput (not http://), Protocol (status),
/// Timeout, Connection.
pub async fn http_get_small(url: &str, opts: &NetOpts, log: &SessionLog, max_body: usize) -> Result<String>;
```

### Behaviour

**Dial algorithm (`connect_tcp`)**, `Direct`:
1. IP literal → no DNS. Otherwise Status `Resolving address of <host>`, then
   `tokio::net::lookup_host((host, port))` under `opts.timeout` (never cached; each
   connection resolves again). Empty result → `Connection("could not resolve <host>")`.
2. Drop IPv6 addresses when `!allow_ipv6` (none left → `Connection("no IPv4 address for
   <host> and IPv6 is disabled")`).
3. Order: interleave families starting with IPv6 if `prefer_ipv6`, else IPv4 (RFC 8305 §4,
   sverb `interleave` with the start family configurable).
4. Happy Eyeballs (sverb `happy_eyeballs`, copied): start the first attempt; start the
   next one after `STAGGER = 250 ms` if nothing has connected yet, or immediately when an
   attempt fails; first success wins, the others are dropped. Each attempt logs Status
   `Connecting to <ip>:<port>...`; a failed attempt logs `Debug(Info)`
   `Connection attempt to <ip>:<port> failed: <os error>`.
5. The race is bounded by `opts.timeout` → `Error::Timeout` (Status
   `Connection timed out after <n> seconds`). All attempts failed →
   `Connection("could not connect to <host>:<port>: <first error>")`.
6. Socket options on success: `TCP_NODELAY` for `Purpose::Control`; `SO_KEEPALIVE` with
   60 s idle and 10 s interval (socket2 `TcpKeepalive`, via `SockRef`, no unsafe);
   `socket_buffer` when set. Status `Connection established` (FTP adds its own
   "waiting for welcome message" line, T10).

**Through a proxy** (`Http`, `Socks4`, `Socks5`):
1. Status `Connecting to <target> through <kind> proxy <proxy host:port>`.
2. Dial the **proxy** with the direct algorithm above (its DNS, Happy Eyeballs, timeout).
3. Handshake under `opts.timeout`:
   - **HTTP CONNECT** (in-house, sverb `http_connect.rs`): send
     `CONNECT <authority> HTTP/1.1\r\nHost: <authority>\r\n` +
     `Proxy-Authorization: Basic base64(user:password)\r\n` (only with credentials) + `\r\n`.
     Read until `\r\n\r\n`, at most 16 KiB (`MAX_HEADER_BYTES`). Status line must be
     `HTTP/1.0` or `HTTP/1.1` + 3 digits. 2xx → success; bytes after the header end are kept
     and replayed by the stream. 407 → if no password was sent and a user is configured,
     ask `Prompt(Password { purpose: Proxy })` (T04) once and retry on a **new** TCP
     connection; otherwise `Proxy("authentication failed (407)")`. Other codes →
     `Proxy("CONNECT refused (<code> <reason>)")` with the reason sanitised (printable ASCII,
     ≤ 80 chars). A user name containing ':' → `InvalidInput` (Basic auth cannot encode it).
   - **SOCKS5** (`tokio-socks`): the target is sent **by name** (ATYP domain, DNS at the
     proxy; IP literals as addresses). Methods: no-auth, or RFC 1929 user/password when
     credentials exist. Reply errors → `Proxy("<readable message>")` using sverb's
     `socks_message` table (connection refused by destination, host unreachable, …).
   - **SOCKS4/4a** (`tokio-socks`): IPv4 literal → SOCKS4; hostname → SOCKS4a (name sent to
     the proxy); IPv6 literal → `Unsupported("SOCKS4 cannot connect to IPv6 addresses")`.
     USERID = `user`. Reply 0x5B–0x5D → `Proxy("request rejected (<code>)")`.
4. Status `Connection established through proxy`. `target_ip()` is None.

**Inbound connections:** `ProxyConfig::allows_inbound()` is false for every proxy. T11 must
check it before active mode and return `Unsupported("active mode FTP does not work through
an HTTP or SOCKS proxy; use passive mode")` and log it as an Error line.

**Cancellation:** dropping the `connect_tcp` future drops all pending attempts and the
proxy handshake immediately (no detached tasks). Callers with a token use `select!`.

**Settings snapshot:** `NetOpts::from_settings` copies values at dial time; later setting
changes affect only new connections.

### Data formats and configuration

| Setting (T05) | Use |
|---|---|
| `connection.timeout_secs` | `NetOpts.timeout` (DNS, TCP race, proxy handshake) |
| `connection.prefer_ipv6`, `connection.ipv6` | address order / filtering |
| `proxy.generic.kind/host/port/user/credential_id` | `ProxyConfig::from_settings` |

Wire formats: HTTP CONNECT request/response as above; SOCKS4/4a (de facto spec),
SOCKS5 (RFC 1928) + RFC 1929. New dependencies: `socket2`, `tokio-socks`, `base64`.

### Errors

| Case | Error | Retried by T03/T41? |
|---|---|---|
| DNS failure, all attempts refused/unreachable, proxy unreachable | `Connection(..)` | yes (transient) |
| No connection / no proxy reply within the timeout | `Timeout` | yes |
| Proxy refused CONNECT, auth failed, SOCKS reply error, malformed proxy response | `Proxy(..)` | no |
| SOCKS4 + IPv6 target, active mode through proxy | `Unsupported(..)` | no |
| Invalid proxy settings (no host, ':' in HTTP user) | `InvalidInput(..)` | no |
| Proxy password prompt cancelled | `Cancelled` | no |

Messages name the proxy or target host (shown to the user and in the session log only).

### Security and logging

- Proxy passwords are only placed in the `Proxy-Authorization` header and the SOCKS5
  auth sub-negotiation; they are never logged (the request is not logged at any level;
  `mask_command` also masks a `Proxy-Authorization:` line if one were logged).
  `ProxyCredentials`/`ProxyConfig` Debug is redacted.
- Proxy responses are untrusted: header size cap 16 KiB, timeout, reason phrase sanitised;
  `parse_connect_response` is a fuzz target (T91 §7) whose body is also a property test.
  SOCKS replies are parsed by `tokio-socks`; a hostile in-process SOCKS server test covers
  truncated and invalid replies.
- `http_get_small` caps the body at 4 KiB, refuses redirects and `https://`, and its result
  is validated by the caller (T11 parses an `IpAddr`).
- Session-log Status lines contain hostnames and IPs (user-facing log, as FileZilla).
  `tracing` events at info+ contain only the session id, proxy kind and `err.code()`;
  hostnames/IPs only at debug (T91 §4).

## Implementation steps

1. `HostPort`, `happy::{interleave, happy_eyeballs, STAGGER}` copied from sverb with the
   configurable family order; mock-dialer unit tests.
2. Direct `connect_tcp`: DNS, IPv6 filter, race, timeout, socket options, Status lines;
   `NetStream` (`PrefixedStream` wrapper, addresses).
3. `ProxyConfig`, `ProxyCredentials`, `from_settings`, `allows_inbound`.
4. HTTP CONNECT: `parse_connect_response`, request builder, 407 prompt-and-retry.
5. SOCKS5 and SOCKS4/4a via `tokio-socks` with readable errors.
6. `http_get_small`.
7. In-process fake proxies and tests; fuzz target `http_connect_response`.

## Acceptance criteria

- [ ] AC1 Direct connections work to `127.0.0.1`, `::1` (skipped with a message when the
  host has no IPv6 loopback) and `localhost`.
- [ ] AC2 Address order: `prefer_ipv6 = false` → IPv4 first, interleaved; `true` → IPv6
  first; `ipv6 = false` → no IPv6 attempt (mock dialer records attempts).
- [ ] AC3 Happy Eyeballs: with a first address that hangs, the second attempt starts at
  250 ms and wins (paused time).
- [ ] AC4 Timeout: a dial that never completes returns `Timeout` at `timeout` ± 100 ms; a
  dial whose future is dropped (token fired) stops within 100 ms and leaves no task running.
- [ ] AC5 HTTP CONNECT works against an in-process proxy with and without Basic auth,
  replays early bytes, maps 407/403/malformed/oversized responses to the listed errors, and
  asks for a password once on 407 when none is stored.
- [ ] AC6 SOCKS5 (no auth, user/password, domain target sent by name) and SOCKS4/4a work
  against in-process proxies; SOCKS error replies give readable `Proxy` errors.
- [ ] AC7 `allows_inbound()` is false for every proxy kind.
- [ ] AC8 Canary proxy password never appears in session log lines, `tracing` output or
  `Debug` output during the proxy tests.
- [ ] AC9 `parse_connect_response` never panics (property test, 10 000 random inputs) and
  the fuzz target exists in `fuzz/` (T91).
- [ ] AC10 T00 CI gates pass.

## Tests

### Unit tests
- `interleave_ipv4_first_by_default` / `interleave_ipv6_first_when_preferred` — `[v4a,v4b,v6a,v6b]`. (AC2)
- `ipv6_disabled_filters_addresses`. (AC2)
- `host_port_parse_and_authority` — `"[::1]:21"`, `"h:0"` → None, `"h"` → None. (AC1)
- `connect_request_format` — with/without auth, IPv6 authority bracketed. (AC5)
- `parse_connect_response_table` — `HTTP/1.1 200 Connection established\r\n\r\n`, 200 + extra bytes (header_len), 407, `HTTP/2 200` → Malformed, missing terminator within 16 KiB → HeadersTooLarge, reason with ESC → sanitised. (AC5)
- `proxy_config_from_settings` — kind none/bypass → Direct, port 0 defaults, ':' in HTTP user → InvalidInput. (AC7)
- `allows_inbound_only_direct`. (AC7)
- `proxy_config_debug_redacted`. (AC8)

### Property / fuzz tests
- `prop_parse_connect_response_never_panics` — body shared with the `http_connect_response` fuzz target. (AC9)
- `prop_happy_eyeballs_first_success_wins` — random per-address delays/failures with a mock dialer (paused time): result is the earliest successful address in start order. (AC3)

### Snapshot tests
Not applicable.

### Integration tests
(in-process servers on `tokio::net::TcpListener` bound to 127.0.0.1:0, `#[tokio::test]`)
- `direct_connect_ipv4_ipv6_and_hostname` — echo server; `::1` test skipped when unavailable. (AC1)
- `status_lines_logged` — Resolving / Connecting / Connection established in order. (AC1)
- `happy_eyeballs_stagger_250ms` — mock dialer where the first address never completes. (AC3)
- `dial_timeout_returns_timeout` — mock dialer never completes, timeout 5 s, paused time. (AC4)
- `dropped_dial_leaves_no_tasks` — select! with a token fired at 1 s; tokio `RuntimeMetrics::num_alive_tasks()` back to baseline. (AC4)
- `blackhole_connect_times_out` — real dial to `10.255.255.1:9`, timeout 2 s; `#[ignore]` (depends on CI network). (AC4)
- `http_connect_no_auth`, `http_connect_basic_auth`, `http_connect_replays_early_bytes` (proxy writes `220 hi\r\n` right after the 200 response), `http_connect_407_prompts_once_then_fails`, `http_connect_403_is_proxy_error`, `http_connect_oversized_headers`. (AC5)
- `socks5_no_auth_domain_target` (fake proxy asserts ATYP 0x03 and the name), `socks5_user_password`, `socks5_host_unreachable_message`, `socks5_truncated_reply_is_proxy_error`. (AC6)
- `socks4a_hostname_target`, `socks4_ipv4_target`, `socks4_ipv6_target_unsupported`, `socks4_rejected_reply`. (AC6)
- `proxy_password_canary_not_logged` — password `CANARY-PW-net-7f3a`; collect all session log events and a `tracing` capture layer; assert absence. (AC8)
- `http_get_small_reads_body`, `http_get_small_rejects_https_and_redirects`, `http_get_small_caps_body`. (AC1)

### End-to-end tests
- In T76: `squid` (HTTP CONNECT) and `dante` (SOCKS5) Docker profiles in front of the SFTP and FTP fixtures; SFTP conformance subset through each (`#[ignore]`, `COURIER_E2E=1`). (AC5, AC6)

## Out of scope

- FTP proxies (USER@HOST, SITE, OPEN, custom scripts) — T15.
- TLS (T12) and SSH (T20) on top of the stream.
- ProxyCommand (sverb has it; FileZilla does not) and proxy auto-config (PAC/WPAD).
- Reading system proxy settings or `*_proxy` environment variables.

## Open questions

- Should courier-ftp also honour the `ALL_PROXY`/`HTTPS_PROXY` environment variables or the
  OS proxy configuration when `proxy.generic.kind = none`? FileZilla does not; this task
  does not.
