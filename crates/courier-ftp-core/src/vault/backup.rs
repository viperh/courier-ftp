//! The encrypted backup container (`.cftp-backup`; sverb `.sverb-backup`, D13). T73
//! adds payload sections, T32 reuses the container with its own [`ContainerSpec`].
//!
//! ```json
//! { "format": "courier-ftp-backup", "version": 1,
//!   "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt_b64": "…" },
//!   "nonce_b64": "…", "ciphertext_b64": "…",
//!   "created_at": "2026-10-09T12:00:00Z", "app_version": "0.1.0" }
//! ```
//!
//! `ciphertext = XChaCha20-Poly1305(Argon2id(password, kdf), nonce, spec.aad,
//! zstd_level3(cbor(payload)))`, base64 standard alphabet with padding. Readers check
//! `format`, then `version`, then the KDF bounds **before** Argon2, cap the file at
//! 2 GiB and the decompressed payload at [`MAX_PAYLOAD`].

use std::io::Read as _;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use courier_ftp_crypto::kdf::{Argon2Params, argon2id};
use courier_ftp_crypto::{Key32, Nonce24, aead, random};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use super::kdf::{Argon2Cost, KDF_ALG};
use super::password::{USER_INPUTS, check_strength};
use crate::model::item::{ItemBody, ItemId, VaultId};
use crate::secret::SecretString;

/// `format` of a courier-ftp backup.
pub const FORMAT: &str = "courier-ftp-backup";
/// The container version this build writes and reads.
pub const VERSION: u32 = 1;
/// The AEAD associated data of a courier-ftp backup.
pub const AAD: &[u8] = b"courier-ftp-backup-v1";
/// The file extension.
pub const EXTENSION: &str = "cftp-backup";
/// Upper bound of the decompressed payload (zstd-bomb guard).
pub const MAX_PAYLOAD: u64 = 1 << 30;
/// Upper bound of a backup file.
pub const MAX_FILE: usize = 2 << 30;
/// zstd level of the payload.
const ZSTD_LEVEL: i32 = 3;

/// What distinguishes one container format from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerSpec {
    /// The `format` string.
    pub format: &'static str,
    /// The AEAD associated data.
    pub aad: &'static [u8],
    /// The file extension (without dot).
    pub extension: &'static str,
}

/// The courier-ftp backup container.
pub const BACKUP: ContainerSpec = ContainerSpec {
    format: FORMAT,
    aad: AAD,
    extension: EXTENSION,
};

/// Why a container cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    /// Not a container of the expected format (bad JSON, another `format`, bad base64).
    #[error("not a courier-ftp backup: {0}")]
    NotABackup(String),
    /// A newer container version.
    #[error(
        "this backup has format version {0}; this courier-ftp reads version {VERSION}. Update courier-ftp to import it"
    )]
    UnsupportedVersion(u32),
    /// Wrong password, or the ciphertext was modified (indistinguishable).
    #[error("cannot decrypt the backup: wrong password, or the file was modified")]
    Decrypt,
    /// The decrypted payload is invalid (or too large).
    #[error("the backup is corrupted: {0}")]
    Corrupt(String),
    /// Invalid key-derivation parameters.
    #[error("invalid key-derivation parameters: {0}")]
    Kdf(String),
    /// The export password is too weak.
    #[error("{0}")]
    WeakPassword(String),
    /// Encoding failed.
    #[error("cannot write the backup: {0}")]
    Encode(String),
}

/// `kdf` of the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfHeader {
    /// Always `argon2id`.
    pub alg: String,
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// The 16-byte salt.
    pub salt_b64: String,
}

/// The JSON file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    /// `spec.format`.
    pub format: String,
    /// [`VERSION`].
    pub version: u32,
    /// Argon2id parameters.
    pub kdf: KdfHeader,
    /// 24-byte nonce.
    pub nonce_b64: String,
    /// `ciphertext || tag`.
    pub ciphertext_b64: String,
    /// RFC 3339 UTC.
    pub created_at: String,
    /// The courier-ftp version that wrote it.
    pub app_version: String,
}

/// A vault in a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupVault {
    /// The vault id.
    pub id: VaultId,
    /// `personal` or `shared`.
    pub kind: String,
}

/// An item in a backup: the full stamped body with secrets, so a restore keeps ids and
/// HLC history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupItem {
    /// The item id.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The body.
    #[serde(with = "body_serde")]
    pub body: ItemBody,
}

/// The base payload (T73 adds sections).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Vaults.
    pub vaults: Vec<BackupVault>,
    /// Items (tombstones included, so deletes survive a restore).
    pub items: Vec<BackupItem>,
}

/// `ItemBody` decodes only through `ItemBody::from_cbor` (unknown kinds are an
/// error there); inside a CBOR payload it round-trips through a `ciborium::Value`.
mod body_serde {
    use super::{Deserialize, Deserializer, ItemBody, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(body: &ItemBody, s: S) -> Result<S::Ok, S::Error> {
        body.serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ItemBody, D::Error> {
        let value = ciborium::Value::deserialize(d)?;
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).map_err(serde::de::Error::custom)?;
        ItemBody::from_cbor(&bytes).map_err(serde::de::Error::custom)
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    let t = t
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(t);
    t.format(&Rfc3339).unwrap_or_default()
}

/// Encrypts `payload` under `password` (zxcvbn ≥ 3) with Argon2id(`cost`), a fresh
/// salt and nonce. Returns the JSON file. CPU- and memory-heavy: run it off the async
/// runtime.
///
/// # Errors
/// [`BackupError::WeakPassword`], [`BackupError::Kdf`], [`BackupError::Encode`].
pub fn encrypt_with<P: Serialize>(
    spec: &ContainerSpec,
    payload: &P,
    password: &SecretString,
    cost: Argon2Cost,
    created_at: OffsetDateTime,
) -> Result<String, BackupError> {
    check_strength(password.expose(), &USER_INPUTS)
        .map_err(|e| BackupError::WeakPassword(e.to_string()))?;
    let mut rng = random::os_rng();
    let salt = random::random_salt16(&mut rng);
    let nonce = random::random_nonce24(&mut rng);
    encrypt_raw(
        spec,
        payload,
        password,
        cost.with_salt(salt).argon2(),
        &nonce,
        created_at,
    )
}

/// [`encrypt_with`] with an explicit salt and nonce and no strength check, for
/// known-answer tests only.
///
/// # Errors
/// As [`encrypt_with`].
#[doc(hidden)]
pub fn encrypt_raw<P: Serialize>(
    spec: &ContainerSpec,
    payload: &P,
    password: &SecretString,
    params: Argon2Params,
    nonce: &Nonce24,
    created_at: OffsetDateTime,
) -> Result<String, BackupError> {
    let key = argon2id(password.expose().as_bytes(), &params)
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    let mut cbor = Zeroizing::new(Vec::new());
    ciborium::into_writer(payload, &mut *cbor).map_err(|e| BackupError::Encode(e.to_string()))?;
    let compressed = Zeroizing::new(
        zstd::bulk::compress(&cbor, ZSTD_LEVEL).map_err(|e| BackupError::Encode(e.to_string()))?,
    );
    drop(cbor);
    let ct = aead::seal(&key, nonce, spec.aad, &compressed)
        .map_err(|e| BackupError::Encode(e.to_string()))?;
    let file = BackupFile {
        format: spec.format.to_owned(),
        version: VERSION,
        kdf: KdfHeader {
            alg: KDF_ALG.to_owned(),
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
            salt_b64: STANDARD.encode(params.salt),
        },
        nonce_b64: STANDARD.encode(nonce.as_bytes()),
        ciphertext_b64: STANDARD.encode(ct),
        created_at: rfc3339(created_at),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let mut out =
        serde_json::to_string_pretty(&file).map_err(|e| BackupError::Encode(e.to_string()))?;
    out.push('\n');
    Ok(out)
}

/// Reads the header without decrypting: `format`, then `version`.
///
/// # Errors
/// [`BackupError::NotABackup`], [`BackupError::UnsupportedVersion`].
pub fn read_header(spec: &ContainerSpec, text: &str) -> Result<BackupFile, BackupError> {
    if text.len() > MAX_FILE {
        return Err(BackupError::NotABackup(
            "the file is larger than 2 GiB".into(),
        ));
    }
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| BackupError::NotABackup(e.to_string()))?;
    if v.get("format").and_then(|f| f.as_str()) != Some(spec.format) {
        return Err(BackupError::NotABackup(format!(
            "missing \"format\": \"{}\"",
            spec.format
        )));
    }
    match v.get("version").and_then(serde_json::Value::as_u64) {
        Some(n) if n == u64::from(VERSION) => {}
        Some(n) => {
            return Err(BackupError::UnsupportedVersion(
                u32::try_from(n).unwrap_or(u32::MAX),
            ));
        }
        None => return Err(BackupError::NotABackup("missing \"version\"".into())),
    }
    serde_json::from_value(v).map_err(|e| BackupError::NotABackup(e.to_string()))
}

/// The Argon2id parameters of a header, bounds-checked.
///
/// # Errors
/// [`BackupError::Kdf`] for another algorithm, a bad salt or out-of-range values.
pub fn kdf_params(kdf: &KdfHeader) -> Result<Argon2Params, BackupError> {
    if kdf.alg != KDF_ALG {
        return Err(BackupError::Kdf("unsupported algorithm".into()));
    }
    let salt = STANDARD
        .decode(&kdf.salt_b64)
        .map_err(|e| BackupError::Kdf(format!("salt: {e}")))?;
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| BackupError::Kdf("the salt is not 16 bytes".into()))?;
    let params = Argon2Params {
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
        salt,
    };
    params
        .validate()
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    Ok(params)
}

/// Header, nonce and ciphertext, all checked before any Argon2 run.
fn parse(
    spec: &ContainerSpec,
    text: &str,
) -> Result<(Argon2Params, Nonce24, Vec<u8>), BackupError> {
    let file = read_header(spec, text)?;
    let params = kdf_params(&file.kdf)?;
    let nonce = STANDARD
        .decode(&file.nonce_b64)
        .map_err(|e| BackupError::NotABackup(format!("nonce: {e}")))?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| BackupError::NotABackup("the nonce is not 24 bytes".into()))?;
    let ct = STANDARD
        .decode(&file.ciphertext_b64)
        .map_err(|e| BackupError::NotABackup(format!("ciphertext: {e}")))?;
    Ok((params, Nonce24::from_bytes(nonce), ct))
}

/// Decrypts a container. CPU- and memory-heavy (Argon2id): run it off the async
/// runtime.
///
/// # Errors
/// See [`BackupError`]; a wrong password is [`BackupError::Decrypt`].
pub fn decrypt_with<P: DeserializeOwned>(
    spec: &ContainerSpec,
    text: &str,
    password: &SecretString,
) -> Result<P, BackupError> {
    let (params, nonce, ct) = parse(spec, text)?;
    let key = argon2id(password.expose().as_bytes(), &params)
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    open_payload(spec, &key, &nonce, &ct)
}

fn open_payload<P: DeserializeOwned>(
    spec: &ContainerSpec,
    key: &Key32,
    nonce: &Nonce24,
    ct: &[u8],
) -> Result<P, BackupError> {
    let compressed = aead::open(key, nonce, spec.aad, ct).map_err(|_| BackupError::Decrypt)?;
    decode_payload(&compressed, MAX_PAYLOAD)
}

/// [`encrypt_with`] for the courier-ftp backup ([`BACKUP`]).
///
/// # Errors
/// As [`encrypt_with`].
pub fn encrypt<P: Serialize>(
    payload: &P,
    password: &SecretString,
    cost: Argon2Cost,
    created_at: OffsetDateTime,
) -> Result<String, BackupError> {
    encrypt_with(&BACKUP, payload, password, cost, created_at)
}

/// [`decrypt_with`] for the courier-ftp backup ([`BACKUP`]).
///
/// # Errors
/// As [`decrypt_with`].
pub fn decrypt<P: DeserializeOwned>(text: &str, password: &SecretString) -> Result<P, BackupError> {
    decrypt_with(&BACKUP, text, password)
}

/// How many bytes `compressed` decompresses to, counting at most `cap + 1` (streamed
/// into a small scratch buffer: nothing large is allocated).
fn decompressed_len(compressed: &[u8], cap: u64) -> Result<u64, BackupError> {
    let mut decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|e| BackupError::Corrupt(format!("decompression: {e}")))?;
    let mut scratch = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = decoder
            .read(&mut scratch)
            .map_err(|e| BackupError::Corrupt(format!("decompression: {e}")))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > cap {
            break;
        }
    }
    scratch.fill(0);
    Ok(total)
}

/// The authenticated plaintext → payload: capped zstd, then CBOR.
fn decode_payload<P: DeserializeOwned>(compressed: &[u8], cap: u64) -> Result<P, BackupError> {
    let len = decompressed_len(compressed, cap)?;
    if len > cap {
        return Err(BackupError::Corrupt(
            "the payload is larger than 1 GiB".into(),
        ));
    }
    let len = usize::try_from(len).map_err(|_| BackupError::Corrupt("payload too large".into()))?;
    let cbor = Zeroizing::new(
        zstd::bulk::decompress(compressed, len)
            .map_err(|e| BackupError::Corrupt(format!("decompression: {e}")))?,
    );
    ciborium::from_reader(cbor.as_slice()).map_err(|e| BackupError::Corrupt(e.to_string()))
}

/// The `backup_decrypt` fuzz target (`fuzz/fuzz_targets/backup_decrypt.rs`). The input
/// is tried as a container (header, KDF checks, base64 fields; a fixed key stands in
/// for Argon2) and, separately, as the authenticated plaintext (capped zstd + CBOR).
/// Must never panic.
#[doc(hidden)]
pub fn fuzz_backup_decrypt(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Ok((_, nonce, ct)) = parse(&BACKUP, &text) {
        let key = Key32::from_bytes([7; 32]);
        let _ = open_payload::<BackupPayload>(&BACKUP, &key, &nonce, &ct);
    }
    let _ = decode_payload::<BackupPayload>(data, 16 * 1024 * 1024);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::item::{DeviceId, HlcClock, ItemKind, ManualClock};
    use std::time::Duration;

    const PW: &str = "correct horse battery staple violin";

    fn payload() -> BackupPayload {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let dev = DeviceId::from_bytes([1; 16]);
        let mut body = ItemBody::new(ItemKind::Site, 1);
        body.set("host", "example.org", &mut clock, dev);
        body.set("password", "CANARY-backup-7d1e", &mut clock, dev);
        let vault = VaultId::from_bytes([2; 16]);
        BackupPayload {
            vaults: vec![BackupVault {
                id: vault,
                kind: "personal".into(),
            }],
            items: vec![BackupItem {
                id: ItemId::from_bytes([3; 16]),
                vault,
                body,
            }],
        }
    }

    fn created() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_791_547_200).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn roundtrip() -> Result<(), BackupError> {
        let p = payload();
        let pw = SecretString::from(PW);
        let text = encrypt(&p, &pw, Argon2Cost::TEST, created())?;
        assert!(!text.contains("CANARY"));
        let header = read_header(&BACKUP, &text)?;
        assert_eq!(header.format, FORMAT);
        assert_eq!(header.created_at, "2026-10-09T12:00:00Z");
        assert_eq!(header.kdf.m_kib, Argon2Cost::TEST.m_kib);
        let back: BackupPayload = decrypt(&text, &pw)?;
        assert_eq!(back, p);
        Ok(())
    }

    #[test]
    fn weak_export_password_rejected() {
        let r = encrypt(
            &payload(),
            &SecretString::from("password123"),
            Argon2Cost::TEST,
            created(),
        );
        assert!(matches!(r, Err(BackupError::WeakPassword(_))));
    }

    #[test]
    fn kat_fixed_salt_and_nonce() -> Result<(), BackupError> {
        // The container is deterministic for a fixed salt, nonce and time; the
        // expected ciphertext pins the format (AAD, zstd level, CBOR layout).
        let params = Argon2Cost::TEST.with_salt([0x11; 16]).argon2();
        let nonce = Nonce24::from_bytes([0x22; 24]);
        let pw = SecretString::from(PW);
        let a = encrypt_raw(&BACKUP, &payload(), &pw, params, &nonce, created())?;
        let b = encrypt_raw(&BACKUP, &payload(), &pw, params, &nonce, created())?;
        assert_eq!(a, b);
        let file = read_header(&BACKUP, &a)?;
        assert_eq!(file.kdf.salt_b64, "EREREREREREREREREREREQ==");
        assert_eq!(
            file.ciphertext_b64,
            "WQuP7knaVFULNNLLR+QwttjupO5cNMKwO8w/SHFdFfGDZIy2YYPFSMJW6h2UBRDKjpQJ/PnSkgHsjsLc4rE0\
             q/ujFpvBAtkMkbEHTSiN4jgD94sIF9xfFeHtO7pXn9SUWELabb5AOOo80sGGYKRuk07X9pbnjR2g3/E1DNmSV\
             HlHUJtu5AufSFl7+4AGadAe0dYggE8yHpQFRU2qAJkPNysAnrJ+CREllwHDxFxzMXsRU41A4w=="
        );
        assert_eq!(file.nonce_b64, "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi");
        let back: BackupPayload = decrypt(&a, &pw)?;
        assert_eq!(back, payload());
        // Another AAD (another container spec) does not open it.
        let other = ContainerSpec {
            format: FORMAT,
            aad: b"other",
            extension: "x",
        };
        assert_eq!(
            decrypt_with::<BackupPayload>(&other, &a, &pw),
            Err(BackupError::Decrypt)
        );
        Ok(())
    }

    const FIXTURE: &str = include_str!("../../tests/fixtures/backups/sample.cftp-backup");

    /// Writes the committed fixture (also the fuzz seed):
    /// `cargo test -p courier-ftp-core --lib vault::backup -- --ignored generate_fixture`.
    #[test]
    #[ignore = "regenerates tests/fixtures/backups/sample.cftp-backup"]
    fn generate_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let params = Argon2Cost::TEST.with_salt([0x11; 16]).argon2();
        let nonce = Nonce24::from_bytes([0x22; 24]);
        let text = encrypt_raw(
            &BACKUP,
            &payload(),
            &SecretString::from(PW),
            params,
            &nonce,
            created(),
        )?;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/backups/sample.cftp-backup"
        );
        std::fs::write(path, text)?;
        Ok(())
    }

    #[test]
    fn fixture_decrypts() -> Result<(), BackupError> {
        let back: BackupPayload = decrypt(FIXTURE, &SecretString::from(PW))?;
        assert_eq!(back, payload());
        Ok(())
    }

    #[test]
    fn wrong_password() -> Result<(), BackupError> {
        let text = encrypt(
            &payload(),
            &SecretString::from(PW),
            Argon2Cost::TEST,
            created(),
        )?;
        let r =
            decrypt::<BackupPayload>(&text, &SecretString::from("another strong passphrase here"));
        assert_eq!(r, Err(BackupError::Decrypt));
        // A flipped ciphertext byte is the same error.
        let mut file = read_header(&BACKUP, &text)?;
        let mut ct = STANDARD.decode(&file.ciphertext_b64).unwrap_or_default();
        if let Some(b) = ct.last_mut() {
            *b ^= 1;
        }
        file.ciphertext_b64 = STANDARD.encode(ct);
        let tampered = serde_json::to_string(&file).unwrap_or_default();
        assert_eq!(
            decrypt::<BackupPayload>(&tampered, &SecretString::from(PW)),
            Err(BackupError::Decrypt)
        );
        Ok(())
    }

    #[test]
    fn kdf_bounds_before_argon2() {
        // 4 GiB + 1 KiB would allocate 4 GiB if Argon2 ran; the check must come first.
        let text = serde_json::json!({
            "format": FORMAT, "version": 1,
            "kdf": {"alg": "argon2id", "m_kib": 4u64 * 1024 * 1024 + 1, "t": 3, "p": 1,
                    "salt_b64": STANDARD.encode([0u8; 16])},
            "nonce_b64": STANDARD.encode([0u8; 24]), "ciphertext_b64": "",
            "created_at": "2026-10-09T12:00:00Z", "app_version": "0"
        })
        .to_string();
        let r = decrypt::<BackupPayload>(&text, &SecretString::from(PW));
        assert!(matches!(r, Err(BackupError::Kdf(_))), "{r:?}");
        let scrypt = text.replace("argon2id", "scrypt");
        assert!(matches!(
            decrypt::<BackupPayload>(&scrypt, &SecretString::from(PW)),
            Err(BackupError::Kdf(_))
        ));
    }

    #[test]
    fn newer_version_rejected() {
        let text = serde_json::json!({"format": FORMAT, "version": 2}).to_string();
        assert_eq!(
            read_header(&BACKUP, &text),
            Err(BackupError::UnsupportedVersion(2))
        );
        let other = serde_json::json!({"format": "sverb-backup", "version": 1}).to_string();
        assert!(matches!(
            read_header(&BACKUP, &other),
            Err(BackupError::NotABackup(_))
        ));
        assert!(matches!(
            read_header(&BACKUP, "not json"),
            Err(BackupError::NotABackup(_))
        ));
    }

    /// A zstd frame of RLE blocks that decompresses to `len` zero bytes (no content
    /// size declared, so only streaming can tell its size).
    fn rle_frame(mut len: u64) -> Vec<u8> {
        let mut out = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38];
        const BLOCK: u64 = 128 * 1024;
        while len > 0 {
            let n = len.min(BLOCK);
            len -= n;
            let last = u32::from(len == 0);
            let header = last | (1 << 1) | ((n as u32) << 3);
            out.extend_from_slice(&header.to_le_bytes()[..3]);
            out.push(0);
        }
        out
    }

    #[test]
    fn bomb_rejected() {
        let small = rle_frame(1000);
        assert_eq!(decompressed_len(&small, MAX_PAYLOAD).ok(), Some(1000));
        let bomb = rle_frame(MAX_PAYLOAD + 1);
        assert!(bomb.len() < 64 * 1024, "the bomb itself is small");
        let r = decode_payload::<BackupPayload>(&bomb, MAX_PAYLOAD);
        assert!(
            matches!(&r, Err(BackupError::Corrupt(m)) if m.contains("1 GiB")),
            "{r:?}"
        );
    }

    #[test]
    fn fuzz_body_never_panics() {
        // Deterministic pseudo-random inputs plus mutations of a valid container.
        let valid = encrypt(
            &payload(),
            &SecretString::from(PW),
            Argon2Cost::TEST,
            created(),
        )
        .unwrap_or_default()
        .into_bytes();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..10_000u32 {
            let input: Vec<u8> = if i % 2 == 0 {
                let len = (next() % 512) as usize;
                (0..len).map(|_| next() as u8).collect()
            } else {
                let mut v = valid.clone();
                for _ in 0..(1 + next() % 4) {
                    let pos = (next() as usize) % v.len().max(1);
                    if let Some(b) = v.get_mut(pos) {
                        *b = next() as u8;
                    }
                }
                v
            };
            fuzz_backup_decrypt(&input);
        }
        fuzz_backup_decrypt(&rle_frame(1 << 20));
    }
}
