# T21 — SSH host key verification

**Phase:** C SFTP · **Depends on:** T20, T30, T81 · **Crate:** `courier-ftp-proto-sftp` (+ trust store types in core) · **Decisions:** D4 · **FEATURES.md:** §1 (cached host key fingerprint)

## Goal

Verify server host keys like FileZilla: ask on first connect, remember the
answer, and warn loudly if a key changes.

## Scope

1. **Trust store** (`courier_ftp_core::trust::HostKeyStore`), persisted **inside the vault** as `known-host` items (T81), so trusted keys sync between devices (D4):
   - Entries: `host`, `port`, `key_type`, `public_key` (OpenSSH base64), `added_at`.
   - Lookup by `(host, port)`; multiple keys per host allowed (different algorithms).
2. **Read-only import from OpenSSH** `~/.ssh/known_hosts` (and `/etc/ssh/ssh_known_hosts`): treated as trusted. Support hashed hostnames (`|1|salt|hash`), `[host]:port` syntax, `@revoked` marker (reject), `@cert-authority` (ignore, log). Never write to the user's known_hosts.
3. **Decision flow** in `check_server_key`:
   - Matches store or known_hosts → accept.
   - Host unknown → `Prompt(TrustHostKey)` with key type and SHA-256 fingerprint (`SHA256:base64`) plus MD5 (legacy, for comparison with old docs). Answers: *Trust once*, *Always trust* (store in vault), *Cancel*.
   - Host known with a **different** key of the same type → `Prompt(TrustHostKey { known: Some(old) })`, the UI (T69) renders this as a security warning; default focus on *Cancel*.
   - Revoked → reject without prompt.
4. **Vault locked** (user skipped unlock): still verify against known_hosts; "Always trust" option disabled in the prompt (only *Trust once*).
5. Management: core API to list and delete stored host keys (used by Settings UI T68).

## Acceptance criteria

- [ ] First connect prompts; "always" persists; second connect silent.
- [ ] Changed key prompts with old/new fingerprints.
- [ ] Hashed known_hosts entries match.
- [ ] Revoked keys rejected.

## Tests

- Unit: known_hosts parser (plain, hashed, `[host]:2222`, comments, revoked).
- Unit: decision function table (unknown / match / mismatch / revoked / vault locked).
