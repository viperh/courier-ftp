# T10 — FTP control connection

**Phase:** B FTP · **Depends on:** T02, T04, T05, T07 · **Crate:** `courier-ftp-proto-ftp` · **Decisions:** D1 (own client) · **FEATURES.md:** §1
**Related (integrates with, not blocking):** T12, T13

## Goal

The FTP command channel: connect, read replies, send commands, log in, negotiate
features, keep the connection alive. RFC 959, 2389 (FEAT), 2428 (EPSV/EPRT), 3659 (MLSD/SIZE/MDTM), 2640 (UTF8).

## Scope

1. **Reply reader**
   - Read lines terminated by CRLF (accept bare LF too). Max line length 64 KiB; longer → protocol error.
   - Single-line: `NNN text`. Multi-line: starts `NNN-`, ends at a line beginning with the same `NNN ` (space). Intermediate lines may start with anything (some servers indent).
   - `Reply { code: u16, lines: Vec<String> }` with helpers `is_preliminary` (1xx), `is_ok` (2xx), `is_intermediate` (3xx), `is_transient_err` (4xx), `is_permanent_err` (5xx).
   - Bytes decoded per site charset (T02 `Charset`): `Auto` = try UTF-8, fall back to Latin-1 per line, and switch the session to UTF-8 if FEAT lists `UTF8`.
   - Every reply line logged as `LogKind::Response`.
2. **Command writer**
   - `send(cmd) -> Result<Reply>`; `send_expect(cmd, &[codes])`.
   - Reject CR/LF inside arguments (command injection via filenames) → `InvalidInput`.
   - Every command logged as `LogKind::Command`, masked via T04's `mask_command`.
   - Per-command timeout = `connection.timeout_secs` measured as "no data received for N s" (FileZilla semantics), not total duration.
3. **Session start sequence** (status lines logged at each step)
   1. Connect via `net::connect_tcp` (implicit FTPS wraps TLS immediately — T12).
   2. Read greeting (`220`; `120` = wait and read again).
   3. Explicit FTPS: `AUTH TLS` (T12).
   4. Login: `USER` → `331` → `PASS` → `332` → `ACCT`. Handle `230` straight after `USER`. Anonymous: `USER anonymous`, `PASS anonymous@example.com`.
   5. `SYST` (store for listing parser hints, T13), `FEAT` (parse into `Features { mlsd, mlst, size, mdtm, mfmt, rest_stream, utf8, epsv, eprt, clnt, tvfs, mode_z, ... }`).
   6. If UTF8 feature and charset Auto/Utf8: `OPTS UTF8 ON` (ignore failure). Optionally `CLNT courier-ftp` if supported.
   7. `PWD` → parse quoted path (`257 "/home/user" is current directory`, doubled quotes `""` inside = literal quote).
4. **Keep-alive**: `keepalive()` sends a random harmless command from {`NOOP`, `PWD`, `TYPE I`/`TYPE A` (restoring current type)} like FileZilla does, to defeat servers/NATs that ignore NOOP for idle detection. Only when idle (no transfer in progress).
5. **Disconnect**: `QUIT`, wait up to 2 s for `221`, then close socket.
6. **Server-side timeouts / `421`** at any point → `Error::Connection` (lets `SessionHandle` reconnect).
7. `raw_command(cmd)` for custom commands (§4): sends verbatim (after CR/LF check), returns all reply lines. If the user issues a command that needs a data channel (`LIST`, `RETR`…), refuse with a message telling them to use the normal UI.

## Design notes

- Structure: `ControlConnection { stream: Box<dyn AsyncReadWrite>, reader: BufReader, features, syst, cwd, charset, log }`. TLS upgrade swaps the stream in place (T12).
- Do not hold the control lock while waiting for user prompts.

## Acceptance criteria

- [x] Multi-line reply parsing handles the RFC example, indented continuation lines, and a code line in the middle that doesn't match the start code.
- [x] Login works for: normal, anonymous, `ACCT` required, `230` after USER.
- [x] `FEAT` parsed into `Features`; servers without FEAT (`500`) work with defaults.
- [x] CR/LF injection rejected.
- [x] `PASS` masked in log.
- [x] Idle timeout and `421` surface as `Error::Connection`/`Timeout`.

**Status:** done in `courier-ftp-proto-ftp::control`. Implicit FTPS and `AUTH TLS`
(scope 3.1/3.3) are T12's; the hook is `ControlConnection::upgrade_stream` and the
`// T12` marker in `control::connect`. Docker coverage: one vsftpd test
(`courier-ftp-e2e/tests/ftp_control.rs`, image `delfer/alpine-ftp-server`); ProFTPD
and Pure-FTPd fixtures come with T76's own images.

## Tests

- Unit: reply parser fed byte chunks split at arbitrary boundaries (proptest-style loop over split points).
- Unit: PWD quote parsing (`257 "/a ""b"" c" created` → `/a "b" c`).
- Scripted fake server (`tokio::io::duplex` + expected command → canned reply script) for login variants.
- Integration (T76): vsftpd, proftpd, pure-ftpd containers.
