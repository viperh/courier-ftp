# T20 — SSH connection and authentication

**Phase:** C SFTP · **Depends on:** T02, T04, T07, T76 · **Crate:** `courier-ftp-proto-sftp` · **Decisions:** D2 (russh) · **FEATURES.md:** §1 (SFTP keys, agent), §2 (logon types)
**Related (integrates with, not blocking):** T21, T30, T59

## Goal

Establish an authenticated SSH session with russh, supporting every logon type
FileZilla offers for SFTP.

## Scope

1. **Transport**: TCP via `net::connect_tcp` (so proxies work), then `russh::client::connect_stream`.
   - `russh::client::Config`: inactivity timeout from settings, keepalive interval (`keepalive_interval_secs`) and max missed keepalives (3).
   - Log: `Connecting to host:port...`, `Using username "x".`, server version banner, negotiated kex/cipher/mac at debug level.
2. **Host key**: the `check_server_key` handler delegates to T21. Connection proceeds only on accept.
3. **Authentication order** (stop at first success; log each method tried):
   - `Normal`: `password`; if server only allows `keyboard-interactive`, answer prompts that look like "Password:" automatically with the stored password, otherwise prompt user.
   - `AskForPassword`: `Prompt(Password)` every connect; offer "remember for this session" (kept in memory only).
   - `Interactive`: `keyboard-interactive`; every server challenge → `Prompt(KeyboardInteractive)` (supports 2FA/OTP; echo flag respected).
   - `KeyFile { path }`: load key via `russh::keys` / `ssh-key`:
     - OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`), PEM RSA/EC, PKCS#8.
     - **PuTTY `.ppk`** v2 and v3 — verify `ssh-key`'s `ppk` support; if missing, write a small converter (v2 is HMAC-SHA1 + AES-256-CBC; v3 uses Argon2 — reuse our `argon2` dep).
     - Encrypted key → `Prompt(KeyPassphrase)`; optionally save the passphrase in the vault (T30) on user request.
     - Use RSA SHA-2 signatures (`rsa-sha2-256/512`) when server supports them.
   - `Agent`: `SSH_AUTH_SOCK` on Unix (russh agent client); on Windows try OpenSSH agent named pipe `\\.\pipe\openssh-ssh-agent`, then **Pageant** (verify russh's Pageant support; else document as follow-up). Try each identity in turn.
   - `Anonymous` / `Account`: not valid for SFTP — the Site Manager (T59) hides them; backend returns `InvalidInput` if reached.
   - Also, like FileZilla: when logon type is `Normal` and agent is available, **do not** silently try agent keys first (avoids "too many auth failures"). Make it a per-site toggle `try_agent_first` (default off).
4. **Banner**: SSH auth banner shown as Status log lines.
5. **Errors**: map auth failures to `Error::Auth("server rejected password")` etc.; list methods the server accepts in the message.
6. **Disconnect**: `disconnect(ByApplication)`.

## Acceptance criteria

- [x] Password, keyboard-interactive (with multiple prompts), key file (ed25519, RSA, ECDSA; encrypted and unencrypted; OpenSSH and PPK v2/v3) and agent all authenticate against an OpenSSH server in Docker (T76). *(Docker: password, key files and agent pass in CI `e2e` against `atmoz/sftp`; keyboard-interactive is covered by the in-process server only, since that image has no PAM.)*
- [x] 2FA flow: two sequential keyboard-interactive rounds work.
- [x] Wrong passphrase re-prompts up to 3 times then fails cleanly.
- [x] No secret ever logged.

## Tests

- Unit: key loading for each format from fixture files (generated with `ssh-keygen` and `puttygen`, committed under `tests/keys/`, test-only keys).
- Integration (T76): OpenSSH container configured for each auth method.
