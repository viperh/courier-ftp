# T02 — Core domain model

**Phase:** A Foundation · **Depends on:** T01 · **Crate:** `courier-ftp-core` (`model` module) · **FEATURES.md:** §1, §3, §4

## Goal

Define the shared vocabulary every other task uses: paths, directory entries,
permissions, protocols, server addresses, errors.

## Scope

1. **`RemotePath`**
   - Always `/`-separated, absolute, normalised (`/a/./b/../c` → `/a/c`). Stored as `String`.
   - Methods: `root()`, `join(name)`, `parent()`, `file_name()`, `components()`, `is_root()`, `starts_with(other)`, `Display`.
   - Must reject names containing `/` in `join` (return error) and handle names containing spaces, unicode, leading dashes, trailing spaces.
   - Some FTP servers (VMS, MVS) do not use `/` paths. Add an enum `PathStyle { Unix, Dos, Vms, Mvs }` on the backend side; `RemotePath` stays Unix-style and the FTP crate translates (T13/T14). Document this in the type's doc comment.
2. **`LocalPath`** — thin newtype over `PathBuf` (so APIs can't mix the two), with `to_display()` that shows `~` for the home dir.
3. **`EntryKind`**: `File`, `Dir`, `Symlink { target: Option<String>, target_kind: Option<Box<EntryKind>> }`, `Other` (devices, sockets).
4. **`Entry`**
   ```rust
   pub struct Entry {
       pub name: String,
       pub kind: EntryKind,
       pub size: Option<u64>,
       pub modified: Option<Timestamp>,   // see below
       pub permissions: Option<Permissions>,
       pub owner: Option<String>,
       pub group: Option<String>,
       pub hidden: bool,                  // dotfile or server-reported hidden
       pub raw: Option<String>,           // original listing line, for T71 raw-listing view
   }
   ```
5. **`Timestamp`** — wraps an `OffsetDateTime` plus a `Precision { Day, Minute, Second, Millis }`. LIST output like `Jan 05 2021` only has day precision; directory comparison (T48) must not report "newer" based on precision noise.
6. **`Permissions`**
   - Unix mode `u32` (`0o755`) with `to_rwx_string()` (`drwxr-xr-x`), `from_rwx_string`, `to_octal_string`.
   - Optional `raw: String` for servers that report non-Unix permissions (Windows/MLSD `perm=` facts) — shown as-is.
7. **`Protocol`**: `Ftp`, `FtpsExplicit`, `FtpsImplicit`, `Sftp`. Plus `FtpEncryption { PlainOnly, ExplicitIfAvailable, RequireExplicit, RequireImplicit }` (FileZilla's four modes, §1).
8. **`ServerAddress`** { protocol, host, port, user } with `default_port()` (21/990/22), `Display` as URL (`sftp://user@host:22`). URL parsing: `FromStr` accepting `ftp://`, `ftps://` (implicit), `ftpes://` (explicit), `sftp://`, and bare `host` / `host:port`. Percent-decoding of user and path.
9. **`Credentials`**: `LogonType` enum — `Anonymous`, `Normal { user, password }`, `AskForPassword { user }`, `Interactive { user }`, `KeyFile { user, path }`, `Account { user, password, account }`, `Agent { user }`. Passwords are `SecretString`.
10. **`Charset`** { `Auto`, `Utf8`, `Custom(&'static Encoding)` } — serialisable by encoding label.
11. **Errors** — replace the placeholder enum with a real `courier_ftp_core::Error`:
    - `Connection(String)`, `Timeout`, `Cancelled`, `Auth(String)`, `Tls(String)`, `HostKey(..)`, `NotFound(RemotePath)`, `PermissionDenied`, `AlreadyExists`, `Protocol { code: Option<u16>, message: String }`, `Unsupported(&'static str)`, `Io(std::io::Error)`, `Vault(..)`, `InvalidInput(String)`.
    - Method `is_transient()` (timeouts, 4xx FTP replies, connection resets) used by the retry logic (T41).

## Design notes

- Derive `Serialize/Deserialize` on everything that is persisted (sites, queue, cache).
- Keep this module dependency-light: `time`, `serde`, `secrecy`, `thiserror`, `encoding_rs`.

## Acceptance criteria

- [ ] All types above exist with rustdoc on every public item.
- [ ] `RemotePath` normalisation and `join`/`parent` behave as specified.
- [ ] URL parsing round-trips (`parse(display(x)) == x`) for all four protocols.
- [ ] Passwords never appear in `Debug` output.

## Tests

- Table-driven tests for `RemotePath` normalisation (`""`, `/`, `//a//b/`, `/a/../..`, unicode, spaces).
- `Permissions` rwx ↔ octal for 0o000, 0o644, 0o755, 0o777, setuid/setgid/sticky bits.
- URL parsing: IPv6 literal `sftp://[::1]:2222`, user with `@` percent-encoded, missing port, default ports.
- `Debug` of `Credentials::Normal` contains `****`, not the password.
