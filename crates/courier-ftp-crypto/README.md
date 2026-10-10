# courier-ftp-crypto

All cryptography of courier-ftp in one small, pure crate: no I/O, no async
runtime, no storage. It is shared by the client (local vault, sync) and the sync
server. Randomness is always passed in as a `rand_core::CryptoRng`.

| Module | Contents |
|---|---|
| `aead` | XChaCha20-Poly1305 seal/open, 24-byte random nonces |
| `kdf` | Argon2id, `KdfParams {alg, m_kib, t, p, salt}` (CBOR, bounds-checked), `Argon2Cost::{DEFAULT, TEST}` |
| `keys` | `Key32` (zeroized, redacted, constant-time eq), `Nonce24`, OS RNG, HKDF-SHA256 |
| `wrap` | `wrap_key` / `unwrap_key` with `WrapPurpose::{Lmk, VaultKey(id), SyncTokens, Device}` |
| `canon` | canonical, length-prefixed AAD / `info` / signature inputs and every domain-separation label |
| `envelope` | item envelopes: `0x01 ‖ key_version ‖ nonce ‖ XChaCha20-Poly1305(pad256(zstd(body)))` |
| `pad` | `pad256` / `unpad256` |
| `opaque` | the OPAQUE suite (Ristretto255, TripleDH, Argon2id KSF) and client/server helpers |
| `account` | X25519 + Ed25519 account keys sealed under the AKEK |
| `recovery` | 24-word BIP39 recovery key and recovery bundle |
| `grant` / `hpke` | HPKE-wrapped, Ed25519-signed vault-key grants |
| `sign` | Ed25519 sign / strict verify |
| `fingerprint` | key fingerprints and 60-digit safety numbers |

The feature `insecure-test-ksf` enables `Argon2Cost::TEST` and
`CourierKsf::insecure_for_tests()` for fast test suites. It must never be
enabled in a release build.

Known-answer vectors live in `tests/kat/*.json` and `tests/fixtures/`; they are
frozen, and changing any output is a breaking format change.

## Origin

The code is adapted from `sverb-crypto` in [sverb](https://github.com/viperh/sverb)
(same author), with every name and domain-separation label changed to
courier-ftp (decision D13). There is no dependency on sverb. The terminal-share
and session-recording modules of sverb are not included.
