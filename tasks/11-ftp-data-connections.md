# T11 — FTP data connections and transfer modes

**Phase:** B FTP · **Depends on:** T10 · **Crate:** `courier-ftp-proto-ftp` · **FEATURES.md:** §1 (active/passive), §5 (resume), §6 (ASCII/binary)
**Related (integrates with, not blocking):** T76

## Goal

Open data connections in passive or active mode, transfer bytes in ASCII or
binary, support resume and abort.

## Scope

1. **Passive mode**
   - Prefer `EPSV` (`229 Entering Extended Passive Mode (|||6446|)`) when the server advertises it or the control connection is IPv6; fall back to `PASV` on `500/502`.
   - `PASV` reply parsing: find `h1,h2,h3,h4,p1,p2` anywhere in the text (servers vary in brackets/spacing).
   - If `passive_ignore_unroutable_ip` and the PASV IP is private/loopback/0.0.0.0 while the control peer is public → connect to the control peer IP instead (log a Status line saying so).
   - Data connection uses `net::connect_tcp` (so it goes through the generic proxy).
2. **Active mode**
   - Bind a listener on the control connection's local IP, port from `active_port_range` or ephemeral.
   - External IP: `Auto` (local addr of control socket), `Fixed`, or `FromUrl` (fetch once per session, e.g. an ip-echo URL; plain HTTP GET via the net layer).
   - `EPRT |1|ip|port|` / `|2|ipv6|port|`, fall back to `PORT h1,..,p2` for IPv4.
   - Accept with timeout; verify peer IP equals control peer IP (anti-bounce) unless proxy is used.
   - Active through HTTP/SOCKS proxy → `Unsupported` error.
3. **Fallback**: if passive fails to connect and `fallback_to_active` is set, retry the same command in active mode once and remember the choice for the session.
4. **Transfer type**: track current `TYPE` (`A`/`I`); only send when it changes. Auto mode decides per file using `file_types` settings (helper `decide_transfer_type(name, settings) -> TransferType` lives in core for reuse).
5. **ASCII conversion**: download — convert CRLF → local newline (LF on Unix, keep CRLF on Windows); upload — LF → CRLF. Implemented as `AsyncRead`/`AsyncWrite` adapters, streaming (handles CR at chunk boundary). Resume is disabled for ASCII transfers (offsets differ) — log a Status line.
6. **Commands**: `RETR` / `STOR` / `APPE` / `REST n` + `RETR|STOR`. `REST` requires `REST STREAM` in FEAT or a successful `350` reply.
7. **Ordering**: for passive, open data connection *before* sending RETR/STOR/LIST (some servers need it); accept `125`/`150` then stream; after EOF read final `226`/`250`. Handle the race where `226` arrives before the data connection drains.
8. **Abort**: `ABOR` (send with Telnet IP/Synch sequence is optional; plain `ABOR` is fine), close the data socket, read `426` + `226`. Expose via cancellation of the read/write stream returned by `open_read`/`open_write`.
9. **Large files**: all sizes `u64`; test > 4 GiB offsets in REST.

## Acceptance criteria

- [x] EPSV, PASV, EPRT, PORT all work; IPv6 data channel works.
- [x] Unroutable PASV address replaced.
- [x] Passive → active fallback works and is remembered.
- [x] ASCII adapters correct across chunk boundaries (CR at end of chunk).
- [x] Resume download/upload via REST produces byte-identical files.
- [x] Cancelling a transfer leaves the control connection usable.

**Status (T11):** all boxes verified in-process (`src/data/tests.rs` against
`src/test_server.rs`, incl. IPv6 loopback). The Docker tests
(`crates/courier-ftp-e2e/tests/ftp_data.rs`: vsftpd passive, and active on
the host network) are written but only run on CI (no Docker locally).

## Tests

- Unit: PASV/EPSV reply parsing table (with and without brackets, garbage around numbers, port > 65535 rejected).
- Unit: ASCII adapters with random chunking.
- Fake server: abort mid-transfer then `PWD` still works.
- Integration (T76): passive + active against vsftpd in Docker.
