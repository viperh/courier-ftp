# T07 — Network layer: sockets, IPv6, generic proxies

**Phase:** A Foundation · **Depends on:** T02, T04, T05 · **Crate:** `courier-ftp-core` (`net` module) · **FEATURES.md:** §1 (IPv6, proxies, timeouts)

## Goal

One function every protocol uses to open a TCP connection, honouring IPv6
preference, timeouts, cancellation and HTTP/SOCKS proxies.

## Scope

1. `pub async fn connect_tcp(target: &HostPort, opts: &NetOpts, cancel: CancellationToken, log: &EventSender) -> Result<TcpStream>`
   - DNS via `tokio::net::lookup_host`; order results by `prefer_ipv6`; try each address in turn (simple Happy-Eyeballs: start next attempt after 250 ms if the previous hasn't connected — optional, document if skipped).
   - Each attempt bounded by `connection.timeout_secs`.
   - Log `Status` lines like FileZilla: `Resolving address of example.com`, `Connecting to 203.0.113.5:21...`, `Connection established`.
   - Set `TCP_NODELAY` on control connections (flag in `NetOpts`), keepalive socket option.
2. **Generic proxies** (`settings.proxy.generic`), applied when the site doesn't set "bypass proxy" (T31):
   - **HTTP/1.1 CONNECT**: send `CONNECT host:port HTTP/1.1`, `Host:`, optional `Proxy-Authorization: Basic`. Accept `200`. Error on others with the status line.
   - **SOCKS4/4a**: CONNECT command; 4a when hostname not resolved locally.
   - **SOCKS5**: no-auth and username/password (RFC 1929) methods; address types IPv4, IPv6, domain. Send domain name so DNS happens at the proxy.
   - Implement ourselves (small) or use `tokio-socks` for SOCKS — decide at implementation; HTTP CONNECT is small enough to hand-write.
3. `NetOpts` built from `Settings` + site overrides.
4. **Data connections for FTP through a proxy** (T11) also go through `connect_tcp`. Active mode FTP cannot work through HTTP/SOCKS proxies — return a clear `Unsupported` error and log it.
5. Helper `local_addr_for(&TcpStream)` for active-mode PORT (T11).

## Acceptance criteria

- [ ] Plain IPv4, IPv6 and dual-stack hostnames connect.
- [ ] Timeout and cancel both abort a hanging connect within 100 ms of the deadline/cancel.
- [ ] HTTP CONNECT and SOCKS5 (with and without auth) work against local test proxies.
- [ ] Proxy credentials are never logged.

## Tests

- Unit: tiny in-process fake HTTP proxy and SOCKS5 server built on `tokio::net::TcpListener` in tests.
- Connect to a black-hole address (`10.255.255.1`) times out (mark `#[ignore]` if CI network is restricted; otherwise use a listener that never accepts on a full backlog).
- IPv6 `::1` loopback.
