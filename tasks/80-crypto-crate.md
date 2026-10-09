# T80 — Crypto crate

**Phase:** H Sync (also needed by the local vault) · **Milestone:** M2 · **Depends on:** T01 · **Crate(s):** new `courier-ftp-crypto` · **Decisions:** D3, D12, D13, D14 · **FEATURES.md:** §2 (protect saved passwords with a master password)
**Reference:** sverb `crates/sverb-crypto/src/*` (copy and adapt), `crates/sverb-crypto/tests/{kat,envelope,primitives,account,account_kat,opaque,fixtures}.rs`, `tests/kat/*.json`, SPEC §11, §19.

## Goal

All cryptography of courier-ftp in one small, pure crate (no I/O, no async, no `unsafe`),
shared by the client vault (T30), the store (T82), the sync client (T87/T88), teams (T89)
and the sync server (T84–T86). It is sverb's `sverb-crypto` with every domain-separation
label renamed to `courier-ftp`, sverb-only modules (terminal sharing, recordings) dropped and
one module added for encrypted device-local blobs. Every byte layout is frozen by
known-answer tests so local databases and the server stay readable across versions.

## Context

- Before: T01 created the empty `crates/courier-ftp-crypto` crate and the workspace lint
  `unsafe_code = "deny"`.
- After: T81 serialises `ItemBody` to CBOR and hands the bytes to `envelope::seal_item`;
  T82 checks envelope headers before storing; T30 derives the KEK with `kdf::argon2id`,
  wraps the LMK and vault keys with `wrap`, and seals device blobs (queue, tabs) with
  `device_blob`; T87 uses `opaque`, `account`, `recovery`; T89 uses `grant`, `hpke`,
  `sign`, `fingerprint`; the server (T84) uses `opaque` server side and `canon::sig_grant`
  to check grant signatures.
- The crate depends on no other courier-ftp crate. Ids are passed as raw 16-byte arrays
  (`canon::Id16`); typed ids live in `courier-ftp-core` (T81).

## Technical specification

### Types and APIs

Crate root `courier_ftp_crypto` (`#![forbid(unsafe_code)]` at crate level in addition to the
workspace `deny`; this crate never needs an exception). Randomness is always a
`&mut R where R: rand_core::CryptoRng + ?Sized` parameter; production code passes
`random::os_rng()`.

| Module | Public API (signatures abbreviated, all `pub`) | sverb source |
|---|---|---|
| `error` | `enum CryptoError { Auth, Malformed(&'static str), UnsupportedVersion(u8), InvalidParams(&'static str), Decompress, BadSignature }` (`Clone, Copy, PartialEq, Eq, thiserror::Error`); `type Result<T> = core::result::Result<T, CryptoError>` | `error.rs` |
| `keys` | `struct Key32([u8; 32])` (`Clone, Zeroize, ZeroizeOnDrop`, `Debug` = `Key32([REDACTED])`, constant-time `PartialEq`); `Key32::{from_bytes, from_slice, expose_secret}`; `struct Nonce24([u8; 24])`; consts `KEY_LEN = 32`, `NONCE_LEN = 24` | `keys.rs` |
| `random` | `type OsRng`; `fn os_rng() -> OsRng`; `fn random_key32(rng) -> Key32`; `fn random_salt16(rng) -> [u8; 16]`; `fn random_nonce24(rng) -> Nonce24` | `random.rs` |
| `aead` | `const TAG_LEN = 16`; `fn seal(key: &Key32, nonce: &Nonce24, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>` (returns `ct ‖ tag`); `fn open(key, nonce, aad, ct) -> Result<Zeroizing<Vec<u8>>>` | `aead.rs` |
| `kdf` | `fn hkdf_sha256(ikm, salt: Option<&[u8]>, info, out_len) -> Result<Zeroizing<Vec<u8>>>`; `fn hkdf_key32(ikm, salt, info) -> Key32`; `struct Argon2Params { m_kib: u32, t: u32, p: u32, salt: [u8; 16] }` with `validate()`, `with_salt()`, consts below; `fn argon2id(password: &[u8], params: &Argon2Params) -> Result<Key32>` | `kdf.rs` |
| `canon` | `type Id16 = [u8; 16]`; `mod labels` (table below); builder `Canon::{with_label, id, fixed, u8, u32, u64, bytes, finish}`; constructors `aad_item`, `info_item_key`, `info_vk`, `aad_wrap`, `info_akek`, `aad_private_bundle`, `info_recovery_key`, `aad_recovery_bundle`, `sig_grant`, `fpr_input`, `aad_device_blob`, `len_prefixed` | `canon.rs` |
| `pad` | `const BLOCK = 256`; `fn pad256(&[u8]) -> Vec<u8>`; `fn unpad256(&[u8]) -> Result<&[u8]>` | `pad.rs` |
| `envelope` | consts `FORMAT_V1 = 0x01`, `HEADER_LEN = 29`, `MIN_LEN = 45`, `ZSTD_LEVEL = 3`, `MAX_DECOMPRESSED = 16 MiB`; `fn item_key(vk, item_id) -> Key32`; `fn seal_item(vk, vault_id, item_id, key_version: u32, body: &[u8], rng) -> Result<Vec<u8>>`; `#[doc(hidden)] fn seal_item_with_nonce(...)`; `struct EnvelopeHeader { version, key_version, nonce }`; `fn parse_header(&[u8]) -> Result<EnvelopeHeader>`; `fn open_item<'k, F: Fn(u32) -> Option<&'k Key32>>(vk_lookup: F, vault_id, item_id, envelope) -> Result<Zeroizing<Vec<u8>>>`; `fn encode_plaintext` / `decode_plaintext`; `#[doc(hidden)] fn fuzz_open_item(&[u8])` | `envelope.rs` |
| `wrap` | `enum WrapPurpose { Lmk, VaultKey(Id16), SyncTokens, DeviceKey }` with `name()` and `aad()`; `fn wrap_key(kek, &WrapPurpose, secret: &[u8], rng) -> Result<Vec<u8>>`; `#[doc(hidden)] fn wrap_key_with_nonce(...)`; `fn unwrap_key(kek, &WrapPurpose, wrapped) -> Result<Zeroizing<Vec<u8>>>`; `fn unwrap_key32(...) -> Result<Key32>` | `wrap.rs` |
| `device_blob` (**new**) | consts `BLOB_V1 = 0x01`, `MAX_BLOB_PLAINTEXT = 256 MiB`; `fn seal_device_blob(device_key: &Key32, name: &str, plaintext: &[u8], rng) -> Result<Vec<u8>>`; `fn open_device_blob(device_key, name, blob) -> Result<Zeroizing<Vec<u8>>>`; `#[doc(hidden)] fn fuzz_open_device_blob(&[u8])` | adapted from `recording.rs` |
| `hpke` | suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (`kem 0x0020, kdf 0x0001, aead 0x0003`); `fn seal_base(pk_recipient: &[u8; 32], info, pt, rng) -> Result<Vec<u8>>`; `fn open_base(sk: &StaticSecret, info, sealed) -> Result<Zeroizing<Vec<u8>>>`; `fn decode_sealed`, `fn take_len_prefixed` | `hpke.rs` |
| `sign` | `fn sign(sk: &SigningKey, msg) -> [u8; 64]`; `fn verify(pk: &[u8; 32], msg, sig: &[u8; 64]) -> Result<()>` (`verify_strict`); `fn public_key(sk) -> [u8; 32]` | `sign.rs` |
| `account` | `const EXPORT_KEY_LEN = 64`, `BUNDLE_VERSION = 0x01`, `BUNDLE_PT_LEN = 90`, `BUNDLE_LEN = 131`; `fn derive_akek(&[u8; 64]) -> Key32`; `struct AccountKeys` (X25519 `StaticSecret` + Ed25519 `SigningKey`, redacted `Debug`); `struct AccountPublicKeys { x25519_pub: [u8; 32], ed25519_pub: [u8; 32] }` with `fingerprint()`; `fn generate_account_keys(rng)`; `fn seal_private_bundle(akek, user_id, version, keys, rng)`; `fn open_private_bundle(akek, user_id, version, bundle)`; `#[doc(hidden)] fn fuzz_open_bundle(&[u8])` | `account.rs` |
| `recovery` | `const RECOVERY_WORDS = 24`; `struct RecoveryKey` (redacted); `struct RecoveryMnemonic` (redacted, no `Display`) with `words()`, `phrase() -> Zeroizing<String>`; `fn recovery_key_generate(rng) -> (RecoveryKey, RecoveryMnemonic)`; `fn recovery_key_from_mnemonic(&str) -> Result<RecoveryKey>`; `fn seal_recovery_bundle(...)` / `fn open_recovery_bundle(...)` | `recovery.rs` |
| `grant` | `struct Grant { wrapped: Vec<u8>, signature: [u8; 64] }` with `to_bytes()` / `from_bytes()`; `fn grant_vault_key(granter: &AccountKeys, member_x25519_pub, vault_id, member_user_id, key_version, vk, rng)`; `fn self_grant(...)`; `fn verify_grant(...)`; `fn open_grant(...)`; `fn verify_and_open_grant(...)`; `#[doc(hidden)] fn fuzz_open_grant(&[u8])` | `grant.rs` |
| `fingerprint` | `const FINGERPRINT_LEN = 32`, `SAFETY_NUMBER_DIGITS = 60`; `fn key_fingerprint(x25519_pub, ed25519_pub) -> [u8; 32]`; `fn safety_number(a, b) -> String` | `fingerprint.rs` |
| `opaque` | `const CONTEXT = b"courier-ftp/opaque/v1"`, `KSF_M_COST_KIB = 65_536`, `KSF_T_COST = 3`, `KSF_P_COST = 1`, `SESSION_KEY_LEN = 64`; `struct CourierKsf` (`Default` = production; `insecure_for_tests()` behind feature `insecure-test-ksf`); `struct CourierSuite` (OPRF Ristretto255, KE `TripleDh<Ristretto255, Sha512>`, KSF `CourierKsf`); `fn credential_identifier(email) -> Vec<u8>` (trimmed, lowercased); client: `client_registration_start`, `ClientRegistrationState::finish`, `client_login_start`, `ClientLoginState::finish` (returns `export_key: Zeroizing<[u8; 64]>` and `session_key`); server: `ServerSetup::{generate, to_bytes, from_bytes, registration_start, login_start}`, `registration_finish`, `ServerLoginState::{to_bytes, from_bytes, finish}`; `fn recovery_proof_message(...)` | `opaque.rs` |

Not ported: `share.rs` (terminal sharing) and `recording.rs` (session recordings) — sverb
features courier-ftp does not have. `recording.rs`'s chunked AEAD pattern is the model for
`device_blob`.

### Behaviour

**Primitives** (sverb SPEC §11.1): Argon2id (local KEK), OPAQUE (server login), XChaCha20-
Poly1305 with random 24-byte nonces (all symmetric encryption), HKDF-SHA256 (key derivation),
HPKE RFC 9180 base mode (vault-key grants), Ed25519 with `verify_strict` (signatures),
OS CSPRNG via `getrandom` (randomness). A wrong key, tampered ciphertext, wrong AAD and wrong
wrap purpose all return the single opaque `CryptoError::Auth`; callers never distinguish them.

**Argon2id bounds** (checked by `Argon2Params::validate()` before any work, so a tampered
`meta.kdf` can neither hang nor exhaust memory):

| Parameter | Default | Min | Max |
|---|---|---|---|
| `m_kib` | 262 144 (256 MiB) | 19 456 (19 MiB) | 4 194 304 (4 GiB) |
| `t` | 3 | 1 | 64 |
| `p` | 1 | 1 | 16 |
| salt | 16 random bytes | — | — |

Argon2 version 0x13, no secret, no associated data, 32-byte output. Argon2 is CPU- and
memory-heavy (about 1 s with defaults): async callers must run it in
`tokio::task::spawn_blocking` (documented on the function; enforced by T30).

**Canonical encodings** (sverb `canon.rs`): every AAD, HKDF `info`, HPKE `info` and signed
message is built only through `canon`. UUIDs are 16 raw bytes, integers big-endian
(`key_version: u32`, `seq: u64`), variable-length fields `u32 BE length ‖ bytes`. Labels are
ASCII constants written **without** a length prefix and always first; each label is followed
by a fixed layout, so the encoding is unambiguous. The builder's `bytes()` is the only place
an `expect` is allowed (a field longer than `u32::MAX` is a programming error), as in sverb.

**Labels** (`canon::labels`; changing any of them is a breaking format change):

| Constant | Value | Bytes | Used as |
|---|---|---|---|
| `ITEM_V1` | `courier-ftp-item-v1` | 19 | item envelope AAD prefix |
| `ITEM_KEY_V1` | `courier-ftp/item/v1` | 19 | HKDF `info` for per-item keys |
| `LMK_WRAP_V1` | `courier-ftp-lmk-wrap-v1` | 23 | key-wrap AAD prefix |
| `DEVICE_BLOB_V1` | `courier-ftp-device-blob-v1` | 26 | device blob AAD prefix |
| `VK_V1` | `courier-ftp/vk/v1` | 17 | HPKE `info` of vault-key grants |
| `GRANT_V1` | `courier-ftp/grant/v1` | 20 | grant signature prefix |
| `AKEK_V1` | `courier-ftp/akek/v1` | 19 | HKDF `info` of the account KEK |
| `BUNDLE_V1` | `courier-ftp/bundle/v1` | 21 | private bundle AAD prefix |
| `RECOVERY_V1` | `courier-ftp/recovery/v1` | 23 | HKDF `info` of the recovery KEK |
| `RECOVERY_BUNDLE_V1` | `courier-ftp/recovery-bundle/v1` | 30 | recovery bundle AAD prefix |
| `FPR_V1` | `courier-ftp/fpr/v1` | 18 | account key fingerprint prefix |
| `opaque::CONTEXT` | `courier-ftp/opaque/v1` | 21 | OPAQUE key-exchange context |

The backup and site-export containers (T30, T32) use their own AAD strings
(`courier-ftp-backup-v1`, `courier-ftp-sites-v1`), defined in those tasks on top of `aead`.

**Randomness**: 192-bit random nonces make collisions negligible, so no nonce counter state
exists anywhere. `seal_item_with_nonce` and `wrap_key_with_nonce` are `#[doc(hidden)]` and
used only by known-answer tests and fixtures.

**Recovery phrase**: the 256-bit recovery key is the BIP39 entropy itself (English list,
24 words, 8-bit SHA-256 checksum); the BIP39 PBKDF2 seed derivation is not used. Parsing is
case-insensitive, accepts any whitespace, requires exactly 24 words and a valid checksum.

**Safety numbers**: `fpr = SHA-256(FPR_V1 ‖ x25519_pub(32) ‖ ed25519_pub(32))`. Sort the two
fingerprints bytewise (`lo ≤ hi`); for each, take bytes `[5i, 5i+5)` for `i in 0..6` as a 40-bit
BE integer mod 100 000, printed as 5 zero-padded digits; join `lo`'s 6 groups then `hi`'s with
single spaces (60 digits, 71 characters). Symmetric in its arguments.

**OPAQUE**: KSF Argon2id(m = 64 MiB, t = 3, p = 1) runs only on the client. The credential
identifier is the trimmed, lowercased email. The server derives the per-user OPRF key from it,
also for unknown emails (dummy-record path), so probes for unknown accounts look stable.
`opaque-ke` 4 uses `rand_core` 0.6; a private adapter forwards our `rand_core` 0.10 generator
(sverb `Rng06`). No `opaque-ke` type appears in the public API.

### Data formats and configuration

**Item key and envelope** (identical locally and on the server):

```
item_key  = HKDF-SHA256(ikm = VK, salt = item_id(16), info = "courier-ftp/item/v1")
aad       = "courier-ftp-item-v1" ‖ vault_id(16) ‖ item_id(16) ‖ key_version(u32 BE)   // 55 bytes
plaintext = pad256(zstd_level3(cbor(ItemBody)))      // decompressed size capped at 16 MiB
envelope  = 0x01 ‖ key_version(u32 BE) ‖ nonce(24) ‖ ciphertext ‖ tag(16)
```

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | format version, `0x01` |
| 1 | 4 | `key_version`, u32 BE (not authenticated by itself, but part of the AAD) |
| 5 | 24 | XChaCha20 nonce |
| 29 | n ≥ 256 | ciphertext of the padded plaintext (multiple of 256) |
| 29 + n | 16 | Poly1305 tag |

Smallest structurally valid envelope 45 bytes (`MIN_LEN`); smallest real one 301 bytes.
`pad256` appends `0x80` and zero bytes to the next multiple of 256 (a full block when already
aligned). `unpad256` rejects lengths that are not a non-zero multiple of 256 and a marker
outside the last block. Decompression trusts the zstd frame's declared size only up to the
cap; frames without a size use a streaming decoder limited to cap + 1 bytes (zip-bomb guard,
sverb `decode_plaintext`). The 16 MiB cap is far above the 1 MiB item limit (T30, T83).

**Key wrap** (LMK under a KEK; vault keys, sync tokens and the device key under the LMK):

```
aad     = "courier-ftp-lmk-wrap-v1" ‖ u32 BE len(purpose name) ‖ purpose name [‖ vault_id(16)]
wrapped = nonce(24) ‖ XChaCha20-Poly1305(kek, nonce, aad, secret) ‖ tag(16)
```

| `WrapPurpose` | name | AAD length | Wraps |
|---|---|---|---|
| `Lmk` | `lmk` | 30 | LMK (32 B) under the password KEK or the keyring KEK |
| `VaultKey(id)` | `vault-key` | 52 | a vault key under the LMK, bound to its vault id |
| `SyncTokens` | `sync-tokens` | 38 | access + refresh tokens (T87) under the LMK |
| `DeviceKey` | `device-key` | 37 | the random per-device blob key (T30) under the LMK |

A wrapped 32-byte key is 72 bytes. `unwrap_key` returns `Malformed` for inputs shorter than
40 bytes.

**Device blob** (new; encrypted device-local data such as the transfer queue (T40) and saved
tabs (T61) in `device_blobs`, T82):

```
aad  = "courier-ftp-device-blob-v1" ‖ u32 BE len(name) ‖ name(UTF-8)
blob = 0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(device_key, nonce, aad, zstd_level3(plaintext)) ‖ tag(16)
```

No padding (the blob never leaves the device). `open_device_blob` caps the decompressed size
at `MAX_BLOB_PLAINTEXT = 256 MiB` (a 100 000-item queue is about 30 MiB). The name binding
stops a `transfer-queue` blob from being opened as `tabs`.

**HPKE sealed message**: `u32 BE len(enc)=32 ‖ enc(32) ‖ u32 BE len(ct) ‖ ct` (88 bytes for a
32-byte VK); HPKE AAD always empty; context goes in `info`. Strict decoder: `enc` length must
be 32, no trailing bytes.

**Grant**: `wrapped = HPKE.Seal(member_x25519_pub, info = "courier-ftp/vk/v1" ‖ vault_id(16) ‖
key_version(u32 BE), VK)`; `signature = Ed25519(granter_sk, "courier-ftp/grant/v1" ‖ vault_id(16)
‖ member_user_id(16) ‖ key_version(u32 BE) ‖ u32 BE len ‖ wrapped)`; transport
`Grant::to_bytes() = u32 BE len(wrapped) ‖ wrapped ‖ signature(64)` (156 bytes).

**Account bundles**: plaintext is the deterministic CBOR map
`a2 69 "x25519_sk" 58 20 <32 B> 6a "ed25519_sk" 58 20 <32 B>` (90 bytes, encoded and decoded
by hand, any other encoding rejected). Serialized bundle: `0x01 ‖ nonce(24) ‖ ct(90) ‖ tag(16)`
= 131 bytes. `AKEK = HKDF-SHA256(salt = none, ikm = export_key(64), info = "courier-ftp/akek/v1")`;
private bundle AAD `"courier-ftp/bundle/v1" ‖ user_id(16) ‖ version(u32 BE)`. Recovery KEK
`= HKDF-SHA256(ikm = recovery_key, info = "courier-ftp/recovery/v1")`; recovery bundle AAD
`"courier-ftp/recovery-bundle/v1" ‖ user_id(16)`.

**Cargo** (`crates/courier-ftp-crypto/Cargo.toml`), versions as sverb pins them (added to
`[workspace.dependencies]`, bumped together later):

| Crate | Version / features |
|---|---|
| `argon2` | 0.6.0, `zeroize` |
| `chacha20poly1305` | 0.11.0, `zeroize` |
| `hkdf` | 0.13.0 |
| `sha2` | 0.11.0; plus `sha2_010 = { package = "sha2", version = "0.10.9" }` crate-local for `opaque-ke` |
| `hpke` | 0.14.1 |
| `ed25519-dalek` | 3.0.0, `zeroize` |
| `x25519-dalek` | 3.0.0, `static_secrets`, `zeroize` |
| `opaque-ke` | 4.0.1, `argon2` |
| `bip39` | 3.0.0, `default-features = false`, `zeroize` |
| `getrandom` | 0.4.3, `sys_rng` |
| `rand_core` | 0.10.1 |
| `subtle` | 2.6.1 |
| `zeroize` | 1.9.1, `derive` |
| `zstd` | 0.14.0 |
| `thiserror` | workspace |
| dev: `proptest`, `hex`, `serde_json`, `criterion`, `chacha20` | workspace |

Feature `insecure-test-ksf` (off by default): enables `CourierKsf::insecure_for_tests()`
(Argon2id m = 8 KiB, t = 1). Only `[dev-dependencies]` edges may enable it.

No settings keys.

### Errors

`CryptoError` only; this crate never returns `courier_ftp_core::Error`. Callers map it:
T30 maps `Auth` on the LMK unwrap to `VaultError::WrongPassword`, every other `Auth` to
`VaultError::Corrupt("… does not decrypt")`; `InvalidParams` from a stored `meta.kdf` to
`VaultError::Corrupt("meta.kdf: parameters out of range")`. `Decompress` and `Malformed` on an
item make that item "unreadable" (T30 status count), never a panic.

### Security and logging

- No `tracing` dependency: the crate logs nothing.
- Every secret is `Key32`, `Zeroizing<…>`, `RecoveryKey`, `RecoveryMnemonic` or `AccountKeys`;
  all zeroize on drop and print `[REDACTED]` in `Debug`. No `Display` on any secret type.
- Intermediate buffers (Argon2 output, HKDF output, decompressed plaintext) are `Zeroizing`.
- Every decoder (`open_item`, `open_device_blob`, `open_private_bundle`, `Grant::from_bytes`,
  `recovery_key_from_mnemonic`, `unpad256`) treats input as hostile: length checks before
  slicing, no panics, bounded allocation. Each has a fuzz entry point.
- clippy `unwrap_used`/`expect_used` denied; the two documented `expect`s are sverb's
  (`canon::Canon::bytes` length, 32-byte BIP39 entropy).

## Implementation steps

1. Crate skeleton: `Cargo.toml` with the dependencies above, `lib.rs` module list,
   `#![forbid(unsafe_code)]`, `error`, `keys`, `random`; README noting the code is adapted
   from sverb (same owner) and listing the renamed labels.
2. `aead`, `pad`, `kdf` (HKDF + Argon2id with bounds) with their unit tests and RFC vectors.
3. `canon` with every label and constructor; layout unit tests.
4. `envelope` (seal/open/header, bounded decompression) and `wrap`.
5. `device_blob`.
6. `sign`, `hpke`, `fingerprint`.
7. `account`, `recovery`, `grant`.
8. `opaque` (suite, KSF, client/server wrappers, rand_core adapter), feature `insecure-test-ksf`.
9. Known-answer files `tests/kat/*.json`, cross-version envelope fixtures
   `tests/fixtures/envelopes/v1/*.bin` + `manifest.json`, generator `scripts/kat/gen_crypto.py`
   (independent Python implementation, stdlib `hashlib`/`hmac` + `cryptography`'s
   ChaCha20-Poly1305 with a hand-written HChaCha20) that reproduces every non-zstd vector.
10. Property tests, tamper tests, fuzz targets (`fuzz/fuzz_targets/{envelope_open,
    device_blob_open,bundle_open,grant_open}.rs`) and the criterion bench `envelope`
    (seal/open of a 1 KiB body).

## Acceptance criteria

- [ ] AC1 Every module in the API table exists with rustdoc on each public item;
  `cargo doc -p courier-ftp-crypto` builds with `-D warnings`.
- [ ] AC2 `cargo tree -p courier-ftp-crypto -e normal` contains no `tokio`, `rusqlite`,
  `reqwest`, `ratatui`, `crossterm`, `clap`, `tracing` or other courier-ftp crate
  (`check-layering.py` rule "crypto has no I/O deps" passes).
- [ ] AC3 `grep -rn "unsafe" crates/courier-ftp-crypto/src` finds only the
  `#![forbid(unsafe_code)]` line; `scripts/check-unsafe.py` passes.
- [ ] AC4 Known-answer tests pass for: HKDF (RFC 5869 case 1), Argon2id (phc reference),
  HChaCha20 and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03 §2.2.1 and A.3.1), Ed25519
  (RFC 8032 §7.1 test 1), every `canon` constructor, item key, key wrap, envelope, device
  blob, private and recovery bundles, grant layout, recovery phrase encoding and safety number.
- [ ] AC5 Flipping any single byte of an envelope, wrapped key, device blob, bundle or grant,
  or changing any AAD input (vault id, item id, key version, purpose, blob name, user id),
  makes opening fail with `Auth` (or `Malformed`/`UnsupportedVersion` for header bytes).
- [ ] AC6 Envelopes in `tests/fixtures/envelopes/v1/` open to their recorded bodies (format
  frozen; the test fails if a future change breaks old data).
- [ ] AC7 A zstd frame declaring or producing more than 16 MiB (envelope) / 256 MiB (device
  blob) returns `Decompress` while peak allocation stays below cap + 1 MiB.
- [ ] AC8 `Argon2Params::validate` rejects each out-of-range value from the bounds table and
  `argon2id` returns `InvalidParams` without running.
- [ ] AC9 No dependency edge outside `[dev-dependencies]` enables `insecure-test-ksf`
  (checked by `courier-ftp-e2e/tests/workspace_metadata.rs`, T76).
- [ ] AC10 Fuzz targets `envelope_open`, `device_blob_open`, `bundle_open`, `grant_open` run
  30 s each in the CI `fuzz` job without findings; their bodies also run as property tests.
- [ ] AC11 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `deny`, `vet`,
  `unsafe-check`, `layering` pass.

## Tests

### Unit tests
- `kdf::tests::hkdf_rfc5869_case1` — OKM `3cb25f25…5865` (42 bytes) (AC4).
- `kdf::tests::argon2id_reference_vector` — Argon2id v0x13, t = 2, m = 65 536, p = 1,
  `"password"`/`"somesalt"` → `09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7` (AC4).
- `kdf::tests::params_bounds` — each bound: `m_kib` 19 455 / 4 194 305, `t` 0 / 65, `p` 0 / 17
  rejected; 19 456 / 4 194 304 / 1 / 64 / 16 accepted (AC8).
- `aead::tests::xchacha_draft_a31` — draft-irtf-cfrg-xchacha-03 A.3.1 vector (AC4).
- `canon::tests::aad_item_layout` — `aad_item([0xAA;16], [0x11;16], 7)` =
  `636f75726965722d6674702d6974656d2d7631` ‖ `aa…aa` ‖ `11…11` ‖ `00000007`, 55 bytes (AC4).
- `canon::tests::aad_wrap_layout` — `aad_wrap("lmk", None)` =
  `636f75726965722d6674702d6c6d6b2d777261702d7631000000036c6d6b` (30 bytes);
  `aad_wrap("vault-key", Some(&[0xAA;16]))` = `…7631 00000009 7661756c742d6b6579 aa…aa` (52 bytes) (AC4).
- `canon::tests::grant_sig_layout`, `bundle_aad_layout`, `fpr_input_len` — offsets as in
  "Data formats" (AC4).
- `envelope::tests::item_key_kat` — `item_key(VK = 00 01 … 1f, item_id = [0x11;16])` =
  `7b222ec99fd60b6ce6eb3147e24e30f347414ac1ed8187d557eaf1b42221ae43` (AC4).
- `wrap::tests::wrap_lmk_kat` — `wrap_key_with_nonce(kek = 00…1f, Lmk, secret = 80…9f,
  nonce = 40…57)` =
  `404142434445464748494a4b4c4d4e4f5051525354555657` ‖
  `54b887f35465ff91077d0d352311eb1d022b3f5787ccc50df2a867de9599bd0f` ‖
  `6670a3f3de3f5a94c085a4c75a22237a` (72 bytes); unwrap returns the secret (AC4).
- `wrap::tests::purpose_binding` — a `VaultKey(a)` wrap does not unwrap as `VaultKey(b)`,
  `Lmk` or `SyncTokens` (AC5).
- `account::tests::akek_kat` — `derive_akek(00 01 … 3f)` =
  `185eccda15dda7b2cbb859b2d96486ebe5fb1c06a3062faee187f3612b115eff` (AC4).
- `recovery::tests::kek_kat` — `RecoveryKey([0x42;32]).kek()` =
  `9864cdbedd5ce9a21e3a2f57cbe3e16295af9651721596775caf8eebdf506292` (AC4).
- `recovery::tests::phrase_roundtrip_and_errors` — all-zero entropy encodes to 23 ×
  `abandon` + `art`; 23 words, unknown word and bad checksum rejected; mixed case and tabs accepted (AC4).
- `fingerprint::tests::shape` — `safety_number([0;32], [0xff;32])` =
  `"00000 00000 00000 00000 00000 00000 27775 27775 27775 27775 27775 27775"` (AC4).
- `sign::tests::rfc8032_test1` (AC4).
- `pad::tests::{exact_block_gets_full_padding, empty_input, malformed}` (AC5).
- `opaque::tests::credential_identifier_is_case_insensitive`, `recovery_proof_is_length_prefixed`.

### Property / fuzz tests
- `tests/envelope.rs::seal_open_roundtrip` (proptest, 1 000 cases): random body 0..64 KiB,
  key version, ids → `open_item(seal_item(x)) == x` and envelope length = 45 + 256·k.
- `tests/envelope.rs::any_bitflip_fails` (proptest): flip one random bit of a random envelope
  → error; header bytes give `Malformed`/`UnsupportedVersion`/`Auth`, payload bytes `Auth` (AC5).
- `tests/envelope.rs::moved_envelope_fails` — envelope opened with another item id, vault id or
  key version → `Auth` (AC5).
- `tests/primitives.rs::pad_roundtrip` (proptest 0..4 KiB) and `unpad_never_panics`.
- `tests/primitives.rs::zstd_bomb_rejected` — a 64 KiB frame decompressing to 17 MiB (and one
  without declared size) → `Decompress` (AC7).
- `tests/device_blob.rs::{roundtrip, name_binding, bitflip, bomb_rejected}` (AC5, AC7).
- `tests/account.rs::{bundle_roundtrip, wrong_user_or_version_fails, t09_decoders_never_panic}`.
- `tests/opaque.rs::{register_login_roundtrip, wrong_password_fails, export_key_stable}` with
  `insecure-test-ksf` (dev-dependency feature).
- Fuzz targets (cargo-fuzz, `fuzz/`): `envelope_open`, `device_blob_open`, `bundle_open`,
  `grant_open`; each body is `fuzz_open_*`, also called from
  `tests/primitives.rs::fuzz_bodies_never_panic` with 10 000 random inputs (AC10).

### Snapshot tests
Not applicable.

### Integration tests
- `tests/kat.rs` reads every `tests/kat/*.json` (canon, hkdf, argon2id, wrap, envelope,
  device_blob, account, pad) and checks seal-with-fixed-nonce and open (AC4).
- `tests/fixtures.rs::v1_envelopes_open` (AC6).
- `scripts/kat/gen_crypto.py --check` (run in `test-local-only` via a `#[test]` that skips when
  `python3` or `cryptography` is missing locally and fails on CI) re-derives the HKDF, wrap,
  device-blob and canon vectors independently.
- `courier-ftp-e2e/tests/workspace_metadata.rs::insecure_ksf_only_in_dev` (AC9, owned by T76).

### End-to-end tests
Not applicable (exercised end to end through T30, T87, T89).

## Out of scope

- Terminal sharing and recording crypto (sverb-only features).
- Any key storage, I/O or async (T30, T82).
- FileZilla's own password encryption (`encoding="crypt"`, T32 open question).
- Post-quantum or algorithm agility beyond the version bytes.

## Open questions

None.
