# courier-ftp-crypto

All cryptography of courier-ftp in one pure crate: no I/O, no async, no `unsafe`.
Used by the client vault (T30), the store (T82), the sync client (T87/T88), teams (T89)
and the sync server (T84–T86).

The code is copied and adapted from sverb's `crates/sverb-crypto` (same owner, MIT).
Changes against sverb:

- every domain-separation label is renamed from `sverb` to `courier-ftp` (table below),
  so no sverb ciphertext opens here and vice versa;
- `share.rs` (terminal sharing) and `recording.rs` (session recordings) are not ported;
- `device_blob` is new (encrypted device-local data such as the transfer queue and
  saved tabs), modelled on sverb's recording chunks;
- `WrapPurpose::RecordingKey` is replaced by `WrapPurpose::DeviceKey` (`device-key`);
- the OPAQUE suite and KSF are `CourierSuite` / `CourierKsf`.

| Constant | Value |
|---|---|
| `ITEM_V1` | `courier-ftp-item-v1` |
| `ITEM_KEY_V1` | `courier-ftp/item/v1` |
| `LMK_WRAP_V1` | `courier-ftp-lmk-wrap-v1` |
| `DEVICE_BLOB_V1` | `courier-ftp-device-blob-v1` (new) |
| `VK_V1` | `courier-ftp/vk/v1` |
| `GRANT_V1` | `courier-ftp/grant/v1` |
| `AKEK_V1` | `courier-ftp/akek/v1` |
| `BUNDLE_V1` | `courier-ftp/bundle/v1` |
| `RECOVERY_V1` | `courier-ftp/recovery/v1` |
| `RECOVERY_BUNDLE_V1` | `courier-ftp/recovery-bundle/v1` |
| `FPR_V1` | `courier-ftp/fpr/v1` |
| `opaque::CONTEXT` | `courier-ftp/opaque/v1` |
| recovery proof (in `opaque`) | `courier-ftp/recovery-proof/v1` |

Changing any label or byte layout is a breaking format change: the known-answer
vectors in `tests/kat/` and the envelopes in `tests/fixtures/envelopes/v1/` are frozen,
and `scripts/kat/gen_crypto.py --check` re-derives the non-zstd vectors independently.
