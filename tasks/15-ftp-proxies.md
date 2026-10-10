# T15 — FTP proxies

**Phase:** B FTP · **Depends on:** T05, T10 · **Crate:** `courier-ftp-proto-ftp` · **FEATURES.md:** §1 (FTP proxies: USER@HOST, SITE, OPEN, custom)

## Goal

Support FileZilla's "FTP Proxy" types, where the client connects to a proxy FTP
server and tells it, via FTP commands, which real server to reach.

## Scope

Settings (`settings.proxy.ftp_proxy`) carry proxy host, port, proxy user and a
vault reference for the proxy password. Applied to FTP/FTPS sites only, unless
the site has "bypass proxy" set. Generic (HTTP/SOCKS) and FTP proxy can't both
be active for one connection — validation error in settings.

Login sequences (`%h` host, `%u` user, `%p` password, `%a` account, `%s` proxy user, `%w` proxy password):

| Type | Sequence |
|---|---|
| `UserAtHost` | `USER %u@%h` · `PASS %p` (if proxy auth: `USER %s` / `PASS %w` first) |
| `Site` | `USER %s` · `PASS %w` · `SITE %h` · `USER %u` · `PASS %p` |
| `Open` | `USER %s` · `PASS %w` · `OPEN %h` · `USER %u` · `PASS %p` |
| `Custom(script)` | user-supplied lines with the placeholders above; empty substitution skips the line |

- Port: `%h` includes `:port` when not 21.
- Implementation: a `LoginScript` abstraction in T10's login step; the normal login is just the default script.
- All `PASS`-like lines masked in the log, including custom script lines containing `%p`/`%w`.
- Explicit TLS through FTP proxy: send `AUTH TLS` before the script (to the proxy). Document that end-to-end TLS depends on the proxy.

## Acceptance criteria

- [x] Each built-in type sends exactly the documented sequence (fake server test).
- [x] Custom script placeholder substitution and line skipping work.
- [x] Secrets masked in log for every type.
- [x] Settings validation rejects generic + FTP proxy combined.

## Tests

- Scripted fake proxy server asserting the command sequence per type.

**Status (T15):** done. `AUTH TLS` before the proxy script follows from `connect()` order (T12 inserts explicit FTPS after the greeting, before `login`); a fake-server test of that sequence belongs with T12. Reading the proxy password from the vault (`FtpProxyConfig::password_ref` → `FtpOptions::set_ftp_proxy_password`) is wired by the backend (T14).
