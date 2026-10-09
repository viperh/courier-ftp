//! Canonical byte encodings (§11.1).
//!
//! Every AAD, HKDF `info`, HPKE `info` and signature input in courier-ftp is built
//! here, never by ad-hoc concatenation in callers:
//!
//! - UUIDs are 16 raw bytes ([`Id16`]).
//! - Integers are big-endian (`u32` for `key_version`, `u64` for `seq` /
//!   `chunk_index`).
//! - Variable-length fields are prefixed with their length as `u32` BE.
//! - Domain-separation labels are ASCII constants from [`labels`].
//!
//! **Labels are not length-prefixed** (spec gap, resolved here). A label is
//! always the first field, every label is a compile-time constant, and the
//! fields that follow a given label have a fixed layout (fixed-width or
//! length-prefixed). A decoder that knows which construction it is looking at
//! therefore knows the label's length, so the encoding is unambiguous. Each
//! construction is also used under its own key or context, so a collision
//! between "label A || fields" and "label B || fields" cannot be exploited.

/// A UUID (or any other 16-byte identifier) in its raw byte form, e.g.
/// `uuid::Uuid::as_bytes()`.
pub type Id16 = [u8; 16];

/// Domain-separation labels. Changing any of these is a breaking format change.
pub mod labels {
    /// Item envelope AAD prefix (sverb SPEC §11.4).
    pub const ITEM_V1: &str = "courier-ftp-item-v1";
    /// HKDF `info` for per-item subkeys (sverb SPEC §11.4).
    pub const ITEM_KEY_V1: &str = "courier-ftp/item/v1";
    /// AAD prefix for key wrapping under the LMK / KEKs.
    pub const LMK_WRAP_V1: &str = "courier-ftp-lmk-wrap-v1";
    /// AAD prefix of encrypted device-local blobs (transfer queue, saved tabs).
    pub const DEVICE_BLOB_V1: &str = "courier-ftp-device-blob-v1";
    /// HPKE `info` prefix of vault-key grants (sverb SPEC §11.3).
    pub const VK_V1: &str = "courier-ftp/vk/v1";
    /// Ed25519 signature input prefix for vault-key grants (sverb SPEC §11.3).
    pub const GRANT_V1: &str = "courier-ftp/grant/v1";
    /// HKDF `info` of the account key-encryption key (sverb SPEC §11.2).
    pub const AKEK_V1: &str = "courier-ftp/akek/v1";
    /// AAD prefix of the account `private_bundle` (sverb SPEC §11.2).
    pub const BUNDLE_V1: &str = "courier-ftp/bundle/v1";
    /// HKDF `info` deriving the recovery KEK from the recovery key (sverb SPEC §11.2).
    pub const RECOVERY_V1: &str = "courier-ftp/recovery/v1";
    /// AAD prefix of the account `recovery_bundle` (sverb SPEC §11.2).
    pub const RECOVERY_BUNDLE_V1: &str = "courier-ftp/recovery-bundle/v1";
    /// SHA-256 input prefix for account key fingerprints (sverb SPEC §13.3).
    pub const FPR_V1: &str = "courier-ftp/fpr/v1";
}

/// A typed builder for canonical byte strings. Prefer the named construction
/// functions below; new constructions should get their own function here.
#[derive(Debug, Default, Clone)]
pub struct Canon {
    buf: Vec<u8>,
}

impl Canon {
    /// Starts a new encoding with a domain-separation label (no length prefix,
    /// see the module docs).
    #[must_use]
    pub fn with_label(label: &'static str) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(label.as_bytes());
        Self { buf }
    }

    /// Appends a 16-byte identifier.
    #[must_use]
    pub fn id(mut self, id: &Id16) -> Self {
        self.buf.extend_from_slice(id);
        self
    }

    /// Appends a fixed-width field (e.g. a 32-byte public key) with no
    /// length prefix. Only for fields whose width is fixed by the construction.
    #[must_use]
    pub fn fixed<const N: usize>(mut self, bytes: &[u8; N]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Appends a `u8`.
    #[must_use]
    pub fn u8(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }

    /// Appends a `u32` big-endian.
    #[must_use]
    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a `u64` big-endian.
    #[must_use]
    pub fn u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a variable-length field as `u32 BE length || bytes`.
    ///
    /// # Panics
    /// If `bytes` is longer than `u32::MAX`. Canonical inputs are small
    /// identifiers and labels, so this is a programming error.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn bytes(mut self, bytes: &[u8]) -> Self {
        let len = u32::try_from(bytes.len()).expect("canonical field longer than u32::MAX");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// `u32 BE length || bytes`.
#[must_use]
pub fn len_prefixed(bytes: &[u8]) -> Vec<u8> {
    Canon::default().bytes(bytes).finish()
}

/// Item envelope AAD (§11.4):
/// `"courier-ftp-item-v1" || vault_id(16) || item_id(16) || key_version(u32 BE)`.
#[must_use]
pub fn aad_item(vault_id: &Id16, item_id: &Id16, key_version: u32) -> Vec<u8> {
    Canon::with_label(labels::ITEM_V1)
        .id(vault_id)
        .id(item_id)
        .u32(key_version)
        .finish()
}

/// HKDF `info` for the per-item subkey (§11.4): `"courier-ftp/item/v1"`.
#[must_use]
pub fn info_item_key() -> Vec<u8> {
    Canon::with_label(labels::ITEM_KEY_V1).finish()
}

/// HPKE `info` for a vault-key grant (§11.3):
/// `"courier-ftp/vk/v1" || vault_id(16) || key_version(u32 BE)`.
#[must_use]
pub fn info_vk(vault_id: &Id16, key_version: u32) -> Vec<u8> {
    Canon::with_label(labels::VK_V1)
        .id(vault_id)
        .u32(key_version)
        .finish()
}

/// Key-wrap AAD (§5.3): `"courier-ftp-lmk-wrap-v1" || purpose`, where `purpose` is
/// `u32 BE len || purpose name`, followed by the purpose's fixed-width
/// parameter (the 16-byte vault id for `vault-key`, nothing otherwise).
#[must_use]
pub fn aad_wrap(purpose_name: &'static str, purpose_id: Option<&Id16>) -> Vec<u8> {
    let c = Canon::with_label(labels::LMK_WRAP_V1).bytes(purpose_name.as_bytes());
    match purpose_id {
        Some(id) => c.id(id),
        None => c,
    }
    .finish()
}

/// Device blob AAD: `"courier-ftp-device-blob-v1" || u32 BE len || name (UTF-8)`.
///
/// The name (e.g. `transfer-queue`, `tabs`) binds a blob to its slot, so one
/// blob cannot be opened as another.
#[must_use]
pub fn aad_device_blob(name: &str) -> Vec<u8> {
    Canon::with_label(labels::DEVICE_BLOB_V1)
        .bytes(name.as_bytes())
        .finish()
}

// Account key hierarchy (§11.2), grants (§11.3), fingerprints (§13.3).

/// HKDF `info` for the account key-encryption key (§11.2): `"courier-ftp/akek/v1"`.
#[must_use]
pub fn info_akek() -> Vec<u8> {
    Canon::with_label(labels::AKEK_V1).finish()
}

/// AAD of the account `private_bundle` (§11.2):
/// `"courier-ftp/bundle/v1" || user_id(16) || version(u32 BE)`.
#[must_use]
pub fn aad_private_bundle(user_id: &Id16, version: u32) -> Vec<u8> {
    Canon::with_label(labels::BUNDLE_V1)
        .id(user_id)
        .u32(version)
        .finish()
}

/// HKDF `info` for the recovery KEK (§11.2): `"courier-ftp/recovery/v1"`.
#[must_use]
pub fn info_recovery_key() -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_V1).finish()
}

/// AAD of the account `recovery_bundle` (§11.2):
/// `"courier-ftp/recovery-bundle/v1" || user_id(16)`.
#[must_use]
pub fn aad_recovery_bundle(user_id: &Id16) -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_BUNDLE_V1)
        .id(user_id)
        .finish()
}

/// Ed25519 signature input of a vault-key grant (§11.3), shared by client and
/// server: `"courier-ftp/grant/v1" || vault_id(16) || member_user_id(16) ||
/// key_version(u32 BE) || u32 BE len || wrapped_vault_key`.
#[must_use]
pub fn sig_grant(vault_id: &Id16, member_id: &Id16, key_version: u32, wrapped: &[u8]) -> Vec<u8> {
    Canon::with_label(labels::GRANT_V1)
        .id(vault_id)
        .id(member_id)
        .u32(key_version)
        .bytes(wrapped)
        .finish()
}

/// SHA-256 input of an account key fingerprint (§13.3):
/// `"courier-ftp/fpr/v1" || x25519_pub(32) || ed25519_pub(32)`.
#[must_use]
pub fn fpr_input(x25519_pub: &[u8; 32], ed25519_pub: &[u8; 32]) -> Vec<u8> {
    Canon::with_label(labels::FPR_V1)
        .fixed(x25519_pub)
        .fixed(ed25519_pub)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn label_lengths() {
        assert_eq!(labels::ITEM_V1.len(), 19);
        assert_eq!(labels::ITEM_KEY_V1.len(), 19);
        assert_eq!(labels::LMK_WRAP_V1.len(), 23);
        assert_eq!(labels::DEVICE_BLOB_V1.len(), 26);
        assert_eq!(labels::VK_V1.len(), 17);
        assert_eq!(labels::GRANT_V1.len(), 20);
        assert_eq!(labels::AKEK_V1.len(), 19);
        assert_eq!(labels::BUNDLE_V1.len(), 21);
        assert_eq!(labels::RECOVERY_V1.len(), 23);
        assert_eq!(labels::RECOVERY_BUNDLE_V1.len(), 30);
        assert_eq!(labels::FPR_V1.len(), 18);
    }

    #[test]
    fn len_prefixed_abc() {
        assert_eq!(len_prefixed(b"abc"), [0, 0, 0, 3, 0x61, 0x62, 0x63]);
        assert_eq!(len_prefixed(b""), [0, 0, 0, 0]);
    }

    #[test]
    fn aad_item_layout() {
        let aad = aad_item(&[0xAA; 16], &[0x11; 16], 7);
        assert_eq!(aad.len(), 55);
        let expected = format!(
            "636f75726965722d6674702d6974656d2d7631{}{}00000007",
            "aa".repeat(16),
            "11".repeat(16)
        );
        assert_eq!(hex(&aad), expected);
    }

    #[test]
    fn simple_infos() {
        assert_eq!(info_item_key(), b"courier-ftp/item/v1");
        assert_eq!(info_akek(), b"courier-ftp/akek/v1");
        assert_eq!(info_recovery_key(), b"courier-ftp/recovery/v1");
        let vk = info_vk(&[3; 16], 0x0102_0304);
        assert_eq!(vk.len(), 17 + 16 + 4);
        assert_eq!(&vk[..17], b"courier-ftp/vk/v1");
        assert_eq!(&vk[17..33], &[3; 16]);
        assert_eq!(&vk[33..], &[1, 2, 3, 4]);
    }

    #[test]
    fn grant_sig_layout() {
        let m = sig_grant(&[1; 16], &[2; 16], 3, b"wk");
        assert_eq!(&m[..20], b"courier-ftp/grant/v1");
        assert_eq!(&m[20..36], &[1; 16]);
        assert_eq!(&m[36..52], &[2; 16]);
        assert_eq!(&m[52..56], &[0, 0, 0, 3]);
        assert_eq!(&m[56..], &[0, 0, 0, 2, b'w', b'k']);
    }

    #[test]
    fn bundle_aad_layout() {
        let b = aad_private_bundle(&[9; 16], 0x0102_0304);
        assert_eq!(b.len(), 21 + 16 + 4);
        assert_eq!(&b[..21], b"courier-ftp/bundle/v1");
        assert_eq!(&b[21..37], &[9; 16]);
        assert_eq!(&b[37..], &[1, 2, 3, 4]);
        let r = aad_recovery_bundle(&[8; 16]);
        assert_eq!(r.len(), 30 + 16);
        assert_eq!(&r[..30], b"courier-ftp/recovery-bundle/v1");
        assert_eq!(&r[30..], &[8; 16]);
    }

    #[test]
    fn fpr_input_len() {
        let f = fpr_input(&[1; 32], &[2; 32]);
        assert_eq!(f.len(), 18 + 64);
        assert_eq!(&f[..18], b"courier-ftp/fpr/v1");
        assert_eq!(&f[18..50], &[1; 32]);
        assert_eq!(&f[50..], &[2; 32]);
    }

    #[test]
    fn aad_wrap_layout() {
        let lmk = aad_wrap("lmk", None);
        assert_eq!(
            hex(&lmk),
            "636f75726965722d6674702d6c6d6b2d777261702d7631000000036c6d6b"
        );
        assert_eq!(lmk.len(), 30);
        let vk = aad_wrap("vault-key", Some(&[0xAA; 16]));
        assert_eq!(vk.len(), 52);
        assert_eq!(&vk[..23], b"courier-ftp-lmk-wrap-v1");
        assert_eq!(&vk[23..27], &[0, 0, 0, 9]);
        assert_eq!(&vk[27..36], b"vault-key");
        assert_eq!(&vk[36..], &[0xAA; 16]);
        assert_eq!(aad_wrap("sync-tokens", None).len(), 38);
        assert_eq!(aad_wrap("device-key", None).len(), 37);
    }

    #[test]
    fn device_blob_aad_layout() {
        let a = aad_device_blob("tabs");
        assert_eq!(a.len(), 26 + 4 + 4);
        assert_eq!(&a[..26], b"courier-ftp-device-blob-v1");
        assert_eq!(&a[26..], &[0, 0, 0, 4, b't', b'a', b'b', b's']);
    }
}
