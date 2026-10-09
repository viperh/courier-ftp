# T12 — FTPS (TLS)

**Phase:** B FTP · **Depends on:** T04, T10, T11 · **Crate:** `courier-ftp-proto-ftp` · **Decisions:** D9 (rustls) · **FEATURES.md:** §1 (FTPS modes, certificate trust)
**Related (integrates with, not blocking):** T30, T57, T69, T76, T81

## Goal

Explicit (`AUTH TLS`) and implicit (port 990) FTPS with proper certificate
verification, a "trust this certificate" flow, and TLS session reuse on data
connections.

## Scope

1. **Encryption modes** (`FtpEncryption` from T02)
   - `PlainOnly`: never send AUTH.
   - `ExplicitIfAvailable`: send `AUTH TLS`; on `5xx` continue in plain text and log a **warning** (FileZilla shows an insecure-connection notice; the status bar shows an open lock — T57).
   - `RequireExplicit`: `AUTH TLS` must succeed (`234`), else fail.
   - `RequireImplicit`: TLS handshake immediately after TCP connect, default port 990.
2. After TLS on control: `PBSZ 0`, `PROT P` (private data channel). If `PROT P` fails, fall back to `PROT C` only in `ExplicitIfAvailable` mode, with a warning.
3. **Data connection TLS**: wrap each data socket in TLS as a client (also in active mode — we are still the TLS client). **Session resumption is mandatory** for many servers (vsftpd `require_ssl_reuse=YES`, FileZilla Server): use one `rustls::ClientConfig` per session with a shared `Resumption` store so data connections resume the control session. Verify with vsftpd.
   - TLS 1.3 tickets vs. TLS 1.2 session IDs: test both; some servers only support 1.2 resumption.
4. **TLS shutdown**: send `close_notify` on data connections before closing (some servers report `426` otherwise); tolerate servers that don't send it back.
5. **Trust store interface**: define `CertTrustStore` (lookup / add / list / remove by host:port + SHA-256) in `courier-ftp-core::trust`, with an in-memory implementation used until the vault exists. The vault-backed implementation (`trusted-cert` items, synced) is added by T30, so this task doesn't wait for the vault.
6. **Certificate verification**
   - Base verifier: `rustls-platform-verifier` (OS trust store).
   - If verification fails *or* the cert is valid but not yet seen for this host, decide:
     - Valid chain + matching hostname → accept silently (optionally record fingerprint).
     - Invalid (self-signed, expired, wrong host, unknown CA) → look up the vault's `trusted-cert` items (T30/T81, synced between devices) by host:port + SHA-256 fingerprint. If trusted → accept. Else → `Prompt(TrustCertificate)` (T04) with full details; user answers *Trust once* / *Always trust* / *Reject*.
     - Changed certificate for a host that had an "always trusted" one → prompt with a prominent warning showing old and new fingerprints.
   - Certificate details for the prompt (via `x509-parser`): subject, issuer, validity dates, serial, SHA-256 + SHA-1 fingerprints, SANs, key algorithm/size, signature algorithm, TLS version, cipher suite, and the full chain.
7. **Session info**: expose negotiated protocol version + cipher on the backend for the status bar lock tooltip / "Server → Show certificate" action (T57).
8. CCC (clear command channel) — **not** supported; document.

## Acceptance criteria

- [ ] All four encryption modes behave as listed.
- [ ] vsftpd with `require_ssl_reuse=YES` transfers files (session reuse works).
- [ ] Self-signed cert → prompt; "always trust" persists in the vault; next connect is silent.
- [ ] Changed cert after "always trust" → warning prompt.
- [ ] Plain fallback in `ExplicitIfAvailable` logs a warning.

## Tests

- Unit: custom verifier logic (trusted fingerprint accepted, unknown rejected → prompt) using `rcgen`-generated certs.
- Fake TLS server in tests with `tokio-rustls` acceptor.
- Integration (T76): vsftpd explicit + implicit, pure-ftpd TLS, proftpd mod_tls.
