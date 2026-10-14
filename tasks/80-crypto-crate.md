# T80 — Crypto crate

**Phase:** H Sync (also needed by the local vault) · **Depends on:** T01 · **Crate:** new `courier-ftp-crypto` · **Decisions:** D12, D13, D14
**Reference:** sverb `crates/sverb-crypto/src/*` — copy and adapt.

## Goal

All cryptography in one small, pure crate (no I/O, no tokio), shared by the
client and the sync server. Copied from sverb with names and domain-separation
strings changed to courier-ftp.

## Scope

Create `crates/courier-ftp-crypto` with these modules (sverb file → our file):

| Module | Contents |
|---|---|
| `aead` | XChaCha20-Poly1305 seal/open with 24-byte random nonces. |
| `kdf` | Argon2id with `KdfParams {alg, m_kib, t, p, salt}` (CBOR), bounds checks, `Argon2Cost::{DEFAULT, TEST}`. |
| `wrap` | `wrap_key(kek, WrapPurpose, secret)` / `unwrap_key`; purposes `Lmk`, `VaultKey(id)`, `SyncTokens`, `Device`; AAD via `canon`. |
| `canon` | Canonical, length-prefixed AAD builders, all prefixed `"courier-ftp-…-v1"`. |
| `envelope` | Item envelope (below). |
| `pad` | `pad256`: `0x80` then zeros to a multiple of 256 bytes (hides exact sizes from the server). |
| `keys` | `Key32` (zeroize on drop), random generation, HKDF helpers. |
| `opaque` | OPAQUE suite: OPRF Ristretto255, `TripleDh<Ristretto255, Sha512>`, KSF Argon2id(64 MiB, t=3, p=1) client-side; context `"courier-ftp/opaque/v1"`; client and server registration/login helpers (crate `opaque-ke` 4.x). |
| `account` | Account key bundle: X25519 + Ed25519 secret keys sealed under `AKEK = HKDF(export_key, "courier-ftp/akek/v1")`, AAD `"courier-ftp/bundle/v1" || user_id || version`. |
| `recovery` | 256-bit recovery key shown as 24 BIP39 words (encoding only); `KEK = HKDF(recovery_key, "courier-ftp/recovery/v1")`; recovery bundle. |
| `grant` | Team vault key grants: `HPKE.Seal(member_x25519, info = "courier-ftp/vk/v1" || vault_id || key_version, VK)` (DHKEM-X25519, HKDF-SHA256, ChaCha20Poly1305), signed with Ed25519. |
| `sign` | Ed25519 sign/verify helpers with domain-separated messages. |
| `fingerprint` | Safety numbers (60 digits) for comparing team members' public keys. |

### Item envelope (identical locally and on the server)

```
item_key  = HKDF-SHA256(ikm = VK, salt = item_id, info = "courier-ftp/item/v1")
aad       = "courier-ftp-item-v1" || vault_id(16) || item_id(16) || key_version(u32 BE)
plaintext = pad256(zstd_level3(cbor(ItemBody)))   // decompressed size capped at 16 MiB
envelope  = 0x01 || key_version(u32 BE) || nonce(24) || ciphertext || tag(16)   // header 29 bytes
```

The AAD binds each item to its vault and id, so a server can't swap or move items
without detection.

### Rules

- `#![forbid(unsafe_code)]`.
- Feature `insecure-test-ksf` for fast tests (never enabled in release builds; CI
  checks that the release binary doesn't contain it).
- Pin dependency versions to those sverb uses (opaque-ke 4.0.1, argon2 0.6, chacha20poly1305 0.11, hkdf 0.13, hpke 0.14, ed25519-dalek 3, x25519-dalek 3, zeroize, secrecy, bip39 3), bumped together later.
- Licence: sverb is also yours; add a note in the crate README that the code is adapted from sverb.

## Acceptance criteria

- [x] All modules ported with their sverb unit tests adapted.
- [x] Known-answer tests for envelope, wrap and recovery encoding (fixed keys/nonces).
- [x] Tamper tests: flipping any byte of header, AAD inputs or ciphertext fails.
- [x] No I/O, no async, no `unsafe`.

## Tests

- Unit and known-answer tests; proptest round-trips for envelope and pad.
