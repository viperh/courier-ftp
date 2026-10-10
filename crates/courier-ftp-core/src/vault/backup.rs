//! The `.cftp-backup` file format (T30 §10, used by T73).
//!
//! ```text
//! file   = header-json "\n" ciphertext
//! header = {"format":"courier-ftp-backup","version":1,
//!           "kdf":{"alg":"argon2id","m_kib":…,"t":…,"p":…,"salt":"<base64>"},
//!           "nonce":"<base64, 24 bytes>","created_at":<unix ms>,"items":<count>}
//! key    = Argon2id(password, kdf)
//! ct     = XChaCha20-Poly1305(key, nonce,
//!                             aad = "courier-ftp-backup-v1" || header-json,
//!                             zstd(cbor(items)))
//! items  = [ {"id": bstr(16), "vault_id": bstr(16), "body": bstr(ItemBody CBOR)} … ]
//! ```
//!
//! The header is authenticated as part of the AAD, so its KDF parameters and
//! counts can't be swapped. The KDF parameters are bounds-checked before
//! Argon2 runs, and decompression stops at [`MAX_DECOMPRESSED`] (1 GiB).

use std::io::Read;

use base64ct::{Base64, Encoding};
use ciborium::Value;
use courier_ftp_crypto::kdf::{Argon2Cost, KdfAlg, KdfParams, argon2id};
use courier_ftp_crypto::keys::{NONCE_LEN, Nonce24, SALT_LEN, random_nonce24};
use courier_ftp_crypto::{CryptoError, aead};
use rand_core::CryptoRng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::model::item::{ItemBody, ItemId, VaultId};

/// The `format` value of the header.
pub const FORMAT: &str = "courier-ftp-backup";
/// The format version this build writes and reads.
pub const VERSION: u32 = 1;
/// The AAD label.
pub const AAD_LABEL: &[u8] = b"courier-ftp-backup-v1";
/// The file extension (without the dot).
pub const EXTENSION: &str = "cftp-backup";
/// The largest decompressed payload accepted (1 GiB).
pub const MAX_DECOMPRESSED: u64 = 1 << 30;
/// The longest header line accepted.
pub const MAX_HEADER_LEN: usize = 4096;
const ZSTD_LEVEL: i32 = 3;

/// One item in a backup.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupItem {
    /// Item id.
    pub id: ItemId,
    /// The vault it came from.
    pub vault_id: VaultId,
    /// The decrypted body (`Debug` redacts secrets).
    pub body: ItemBody,
}

/// What can go wrong reading or writing a backup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// Not a courier-ftp backup, or an unknown version.
    #[error("not a courier-ftp backup: {0}")]
    Format(String),
    /// Wrong password, or the file was modified.
    #[error("wrong password, or the backup file is damaged")]
    Decrypt,
    /// The payload is larger than [`MAX_DECOMPRESSED`].
    #[error("the backup is too large")]
    TooLarge,
    /// The decrypted payload is malformed.
    #[error("the backup is corrupt: {0}")]
    Corrupt(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    version: u32,
    kdf: KdfHeader,
    nonce: String,
    created_at: i64,
    items: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfHeader {
    alg: KdfAlg,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

/// Seals `items` into a backup file protected by `password`, using `cost` for
/// Argon2id. `created_at` is UNIX ms.
///
/// **CPU- and memory-heavy** (Argon2): async callers use `spawn_blocking`.
///
/// # Errors
/// [`BackupError::Corrupt`] if a body can't be encoded,
/// [`BackupError::Format`] for invalid KDF parameters.
pub fn seal<R: CryptoRng + ?Sized>(
    items: &[BackupItem],
    password: &SecretString,
    cost: Argon2Cost,
    created_at: i64,
    rng: &mut R,
) -> Result<Vec<u8>, BackupError> {
    let kdf = KdfParams::generate(cost, rng);
    let nonce = random_nonce24(rng);
    let header = Header {
        format: FORMAT.to_owned(),
        version: VERSION,
        kdf: KdfHeader {
            alg: kdf.alg,
            m_kib: kdf.m_kib,
            t: kdf.t,
            p: kdf.p,
            salt: Base64::encode_string(&kdf.salt),
        },
        nonce: Base64::encode_string(nonce.as_bytes()),
        created_at,
        items: items.len() as u64,
    };
    let header_json =
        serde_json::to_vec(&header).map_err(|e| BackupError::Corrupt(e.to_string()))?;

    let mut list = Vec::with_capacity(items.len());
    for item in items {
        let body = item
            .body
            .to_cbor()
            .map_err(|e| BackupError::Corrupt(e.to_string()))?;
        list.push(Value::Map(vec![
            (Value::Text("id".into()), Value::from(item.id)),
            (Value::Text("vault_id".into()), Value::from(item.vault_id)),
            (Value::Text("body".into()), Value::Bytes(body)),
        ]));
    }
    let mut cbor = Zeroizing::new(Vec::new());
    ciborium::into_writer(&Value::Array(list), &mut *cbor)
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    let compressed = Zeroizing::new(
        zstd::encode_all(cbor.as_slice(), ZSTD_LEVEL)
            .map_err(|e| BackupError::Corrupt(e.to_string()))?,
    );
    drop(cbor);

    let key = argon2id(password.expose_secret().as_bytes(), &kdf)
        .map_err(|e| BackupError::Format(e.to_string()))?;
    let ct = aead::seal(&key, &nonce, &aad(&header_json), &compressed)
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;

    let mut out = header_json;
    out.push(b'\n');
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aad(header_json: &[u8]) -> Vec<u8> {
    let mut aad = AAD_LABEL.to_vec();
    aad.extend_from_slice(header_json);
    aad
}

/// Reads the header of a backup without decrypting: `(created_at, item count)`.
///
/// # Errors
/// [`BackupError::Format`].
pub fn peek(file: &[u8]) -> Result<(i64, u64), BackupError> {
    let (header, _, _) = split(file)?;
    Ok((header.created_at, header.items))
}

fn split(file: &[u8]) -> Result<(Header, &[u8], &[u8]), BackupError> {
    let bad = |what: &str| BackupError::Format(what.to_owned());
    let nl = file
        .iter()
        .take(MAX_HEADER_LEN + 1)
        .position(|b| *b == b'\n')
        .ok_or_else(|| bad("no header"))?;
    let (header_json, rest) = file.split_at(nl);
    let header: Header = serde_json::from_slice(header_json).map_err(|_| bad("bad header"))?;
    if header.format != FORMAT {
        return Err(bad("wrong format"));
    }
    if header.version != VERSION {
        return Err(BackupError::Format(format!(
            "unsupported version {}",
            header.version
        )));
    }
    Ok((header, header_json, rest.get(1..).unwrap_or_default()))
}

/// Opens a backup file with `password`.
///
/// **CPU- and memory-heavy** (Argon2): async callers use `spawn_blocking`.
///
/// # Errors
/// [`BackupError::Format`] (also for KDF parameters out of bounds, checked
/// before Argon2 runs), [`BackupError::Decrypt`], [`BackupError::TooLarge`],
/// [`BackupError::Corrupt`].
pub fn open(file: &[u8], password: &SecretString) -> Result<Vec<BackupItem>, BackupError> {
    open_with_cap(file, password, MAX_DECOMPRESSED)
}

fn open_with_cap(
    file: &[u8],
    password: &SecretString,
    cap: u64,
) -> Result<Vec<BackupItem>, BackupError> {
    let (header, header_json, ct) = split(file)?;
    let (kdf, nonce) = header_params(&header)?;
    let key = argon2id(password.expose_secret().as_bytes(), &kdf)
        .map_err(|e| BackupError::Format(e.to_string()))?;
    let compressed = aead::open(&key, &nonce, &aad(header_json), ct).map_err(|e| match e {
        CryptoError::Auth => BackupError::Decrypt,
        other => BackupError::Corrupt(other.to_string()),
    })?;
    decode_payload(&compressed, cap)
}

/// The header's KDF parameters (bounds-checked, so Argon2 may run) and nonce.
fn header_params(header: &Header) -> Result<(KdfParams, Nonce24), BackupError> {
    let salt: [u8; SALT_LEN] = Base64::decode_vec(&header.kdf.salt)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| BackupError::Format("bad salt".into()))?;
    let nonce: [u8; NONCE_LEN] = Base64::decode_vec(&header.nonce)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| BackupError::Format("bad nonce".into()))?;
    let kdf = KdfParams {
        alg: header.kdf.alg,
        m_kib: header.kdf.m_kib,
        t: header.kdf.t,
        p: header.kdf.p,
        salt,
    };
    kdf.validate()
        .map_err(|e| BackupError::Format(format!("kdf parameters: {e}")))?;
    Ok((kdf, Nonce24::from_bytes(nonce)))
}

/// The authenticated plaintext: zstd (stopped after `cap` bytes), then the
/// CBOR item list.
fn decode_payload(compressed: &[u8], cap: u64) -> Result<Vec<BackupItem>, BackupError> {
    let decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    let mut cbor = Zeroizing::new(Vec::new());
    decoder
        .take(cap.saturating_add(1))
        .read_to_end(&mut cbor)
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    if cbor.len() as u64 > cap {
        return Err(BackupError::TooLarge);
    }
    decode_items(&cbor)
}

/// Fuzz body (T91 §7, cargo-fuzz target `backup_decrypt`): everything [`open`]
/// does with untrusted bytes, minus Argon2. `data` is tried as a whole file
/// (header, KDF bounds, base64 fields, then the AEAD under a fixed key) and as
/// an authenticated payload (capped zstd, the CBOR item list and every item
/// body). Must never panic.
#[doc(hidden)]
pub fn fuzz_backup_decrypt(data: &[u8]) {
    // A small cap keeps hostile zstd frames cheap.
    const CAP: u64 = 1 << 20;
    if let Ok((header, header_json, ct)) = split(data)
        && let Ok((_kdf, nonce)) = header_params(&header)
    {
        let key = courier_ftp_crypto::Key32::from_bytes([7; 32]);
        if let Ok(compressed) = aead::open(&key, &nonce, &aad(header_json), ct) {
            let _ = decode_payload(&compressed, CAP);
        }
    }
    let _ = decode_payload(data, CAP);
    let _ = decode_items(data);
}

fn decode_items(cbor: &[u8]) -> Result<Vec<BackupItem>, BackupError> {
    let bad = |what: &str| BackupError::Corrupt(what.to_owned());
    let value: Value = ciborium::from_reader(cbor).map_err(|_| bad("payload is not CBOR"))?;
    let Value::Array(list) = value else {
        return Err(bad("payload is not a list"));
    };
    list.into_iter()
        .map(|entry| {
            let Value::Map(fields) = entry else {
                return Err(bad("item is not a map"));
            };
            let get = |key: &str| {
                fields
                    .iter()
                    .find(|(k, _)| k.as_text() == Some(key))
                    .map(|(_, v)| v)
            };
            let id = get("id")
                .and_then(ItemId::from_value)
                .ok_or_else(|| bad("item id"))?;
            let vault_id = get("vault_id")
                .and_then(VaultId::from_value)
                .ok_or_else(|| bad("vault id"))?;
            let body = get("body")
                .and_then(Value::as_bytes)
                .ok_or_else(|| bad("item body"))?;
            let body =
                ItemBody::from_cbor(body).map_err(|e| BackupError::Corrupt(e.to_string()))?;
            Ok(BackupItem { id, vault_id, body })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use courier_ftp_crypto::keys::os_rng;
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::model::item::{DeviceId, HlcClock, ItemKind};

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn items() -> Vec<BackupItem> {
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();
        let mut body = ItemBody::new(ItemKind::Site, 1);
        body.set("name", "web01", &mut clock, dev);
        body.set("logon.password", "CANARY-BACKUP-PW-41c9", &mut clock, dev);
        vec![BackupItem {
            id: ItemId::new(),
            vault_id: VaultId::new(),
            body,
        }]
    }

    #[test]
    fn roundtrip_and_header() {
        let items = items();
        let file = seal(
            &items,
            &pw("backup pass"),
            Argon2Cost::TEST,
            42,
            &mut os_rng(),
        )
        .unwrap();
        assert!(!file.windows(9).any(|w| w == b"CANARY-BA"), "no plaintext");
        assert_eq!(peek(&file).unwrap(), (42, 1));
        assert_eq!(open(&file, &pw("backup pass")).unwrap(), items);
        assert_eq!(open(&file, &pw("other")).unwrap_err(), BackupError::Decrypt);
    }

    #[test]
    fn tampering_is_detected() {
        let file = seal(&items(), &pw("p"), Argon2Cost::TEST, 42, &mut os_rng()).unwrap();
        // Ciphertext.
        let mut ct = file.clone();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert_eq!(open(&ct, &pw("p")).unwrap_err(), BackupError::Decrypt);
        // Header (authenticated): change the item count.
        let text = String::from_utf8_lossy(&file).into_owned();
        let edited = text.replacen("\"items\":1", "\"items\":2", 1);
        assert_ne!(edited, text);
        let mut h = file.clone();
        let nl = h.iter().position(|b| *b == b'\n').unwrap();
        let new_header = edited.split('\n').next().unwrap().as_bytes().to_vec();
        h.splice(..nl, new_header);
        assert_eq!(open(&h, &pw("p")).unwrap_err(), BackupError::Decrypt);
    }

    #[test]
    fn out_of_bounds_kdf_is_refused_before_argon2() {
        let file = seal(&items(), &pw("p"), Argon2Cost::TEST, 42, &mut os_rng()).unwrap();
        let text = String::from_utf8_lossy(&file).into_owned();
        // 8 GiB of memory: would hang or abort if Argon2 ran.
        let edited = text.replacen("\"m_kib\":8,", "\"m_kib\":8388608,", 1);
        assert_ne!(edited, text);
        let header = edited.split('\n').next().unwrap().as_bytes().to_vec();
        let mut f = file.clone();
        let nl = f.iter().position(|b| *b == b'\n').unwrap();
        f.splice(..nl, header);
        assert!(matches!(
            open(&f, &pw("p")).unwrap_err(),
            BackupError::Format(m) if m.contains("kdf")
        ));
    }

    #[test]
    fn decompression_is_capped() {
        let file = seal(&items(), &pw("p"), Argon2Cost::TEST, 42, &mut os_rng()).unwrap();
        assert_eq!(
            open_with_cap(&file, &pw("p"), 8).unwrap_err(),
            BackupError::TooLarge
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            ..proptest::prelude::ProptestConfig::default()
        })]

        // The `backup_decrypt` fuzz body (T91 §7).
        #[test]
        fn fuzz_backup_decrypt_never_panics(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024),
        ) {
            fuzz_backup_decrypt(&data);
        }

        // Header-shaped input reaches the KDF bounds and the AEAD.
        #[test]
        fn fuzz_backup_decrypt_header_like_never_panics(
            m in proptest::prelude::any::<u32>(),
            t in proptest::prelude::any::<u32>(),
            p in proptest::prelude::any::<u32>(),
            tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let mut data = format!(
                r#"{{"format":"courier-ftp-backup","version":1,"kdf":{{"alg":"argon2id","m_kib":{m},"t":{t},"p":{p},"salt":"AAAAAAAAAAAAAAAAAAAAAA=="}},"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","created_at":0,"items":1}}"#
            )
            .into_bytes();
            data.push(b'\n');
            data.extend_from_slice(&tail);
            fuzz_backup_decrypt(&data);
        }
    }

    #[test]
    fn fuzz_backup_decrypt_seeds() {
        let file = seal(&items(), &pw("p"), Argon2Cost::TEST, 42, &mut os_rng()).unwrap();
        fuzz_backup_decrypt(&file);
        let empty_list = zstd::encode_all(&b"\x80"[..], 3).unwrap();
        fuzz_backup_decrypt(&empty_list);
        assert_eq!(decode_payload(&empty_list, 16).unwrap(), Vec::new());
    }

    #[test]
    fn garbage_never_panics() {
        for input in [&b""[..], b"\n", b"{}\nxx", b"not json\n", &[0xff; 100]] {
            assert!(open(input, &pw("p")).is_err());
        }
        assert!(matches!(
            open(br#"{"format":"x"}"#, &pw("p")),
            Err(BackupError::Format(_))
        ));
    }
}
