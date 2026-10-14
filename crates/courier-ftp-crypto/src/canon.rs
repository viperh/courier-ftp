//! Canonical byte encodings.
//!
//! Every AAD, HKDF `info`, HPKE `info` and signature input in courier-ftp is
//! built here, never by ad-hoc concatenation in callers:
//!
//! - UUIDs are 16 raw bytes ([`Id16`]).
//! - Integers are big-endian (`u32` for `key_version` and versions).
//! - Variable-length fields are prefixed with their length as `u32` BE.
//! - Domain-separation labels are ASCII constants from [`labels`].
//!
//! **Labels are not length-prefixed.** A label is
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
    /// Item envelope AAD prefix.
    pub const ITEM_V1: &str = "courier-ftp-item-v1";
    /// HKDF `info` for per-item subkeys.
    pub const ITEM_KEY_V1: &str = "courier-ftp/item/v1";
    /// AAD prefix for key wrapping under the LMK / KEKs.
    pub const WRAP_V1: &str = "courier-ftp-wrap-v1";
    /// HPKE `info` prefix of a vault-key grant.
    pub const VK_V1: &str = "courier-ftp/vk/v1";
    /// HKDF `info` deriving the account key-encryption key from the OPAQUE
    /// export key.
    pub const AKEK_V1: &str = "courier-ftp/akek/v1";
    /// AAD prefix of the account `private_bundle`.
    pub const BUNDLE_V1: &str = "courier-ftp/bundle/v1";
    /// HKDF `info` deriving the recovery KEK from the recovery key.
    pub const RECOVERY_V1: &str = "courier-ftp/recovery/v1";
    /// AAD prefix of the account `recovery_bundle`.
    pub const RECOVERY_BUNDLE_V1: &str = "courier-ftp/recovery-bundle/v1";
    /// Ed25519 signature input prefix of the account-recovery proof.
    pub const RECOVERY_PROOF_V1: &str = "courier-ftp/recovery-proof/v1";
    /// Ed25519 signature input prefix for vault-key grants.
    pub const GRANT_V1: &str = "courier-ftp/grant/v1";
    /// SHA-256 input prefix for account key fingerprints.
    pub const FPR_V1: &str = "courier-ftp/fpr/v1";
    /// OPAQUE key-exchange context.
    pub const OPAQUE_V1: &str = "courier-ftp/opaque/v1";
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

/// Item envelope AAD:
/// `"courier-ftp-item-v1" || vault_id(16) || item_id(16) || key_version(u32 BE)`.
#[must_use]
pub fn aad_item(vault_id: &Id16, item_id: &Id16, key_version: u32) -> Vec<u8> {
    Canon::with_label(labels::ITEM_V1)
        .id(vault_id)
        .id(item_id)
        .u32(key_version)
        .finish()
}

/// HKDF `info` for the per-item subkey: `"courier-ftp/item/v1"`.
#[must_use]
pub fn info_item_key() -> Vec<u8> {
    Canon::with_label(labels::ITEM_KEY_V1).finish()
}

/// HPKE `info` for a vault-key grant:
/// `"courier-ftp/vk/v1" || vault_id(16) || key_version(u32 BE)`.
#[must_use]
pub fn info_vk(vault_id: &Id16, key_version: u32) -> Vec<u8> {
    Canon::with_label(labels::VK_V1)
        .id(vault_id)
        .u32(key_version)
        .finish()
}

/// Key-wrap AAD: `"courier-ftp-wrap-v1" || purpose`, where `purpose` is
/// `u32 BE len || purpose name`, followed by the purpose's fixed-width
/// parameter (the 16-byte vault id for `vault-key`, nothing otherwise).
#[must_use]
pub fn aad_wrap(purpose_name: &'static str, purpose_id: Option<&Id16>) -> Vec<u8> {
    let c = Canon::with_label(labels::WRAP_V1).bytes(purpose_name.as_bytes());
    match purpose_id {
        Some(id) => c.id(id),
        None => c,
    }
    .finish()
}

// Account key hierarchy, recovery, grants, fingerprints.

/// HKDF `info` for the account key-encryption key: `"courier-ftp/akek/v1"`.
#[must_use]
pub fn info_akek() -> Vec<u8> {
    Canon::with_label(labels::AKEK_V1).finish()
}

/// AAD of the account `private_bundle`:
/// `"courier-ftp/bundle/v1" || user_id(16) || version(u32 BE)`.
#[must_use]
pub fn aad_private_bundle(user_id: &Id16, version: u32) -> Vec<u8> {
    Canon::with_label(labels::BUNDLE_V1)
        .id(user_id)
        .u32(version)
        .finish()
}

/// HKDF `info` for the recovery KEK: `"courier-ftp/recovery/v1"`.
#[must_use]
pub fn info_recovery_key() -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_V1).finish()
}

/// AAD of the account `recovery_bundle`:
/// `"courier-ftp/recovery-bundle/v1" || user_id(16)`.
#[must_use]
pub fn aad_recovery_bundle(user_id: &Id16) -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_BUNDLE_V1)
        .id(user_id)
        .finish()
}

/// Ed25519 signature input of the account-recovery proof:
/// `"courier-ftp/recovery-proof/v1" || user_id(16) || new_version(u32 BE) ||
/// u32 BE len || registration_upload || u32 BE len || private_bundle`.
#[must_use]
pub fn sig_recovery_proof(
    user_id: &Id16,
    new_version: u32,
    registration_upload: &[u8],
    private_bundle: &[u8],
) -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_PROOF_V1)
        .id(user_id)
        .u32(new_version)
        .bytes(registration_upload)
        .bytes(private_bundle)
        .finish()
}

/// Ed25519 signature input of a vault-key grant, shared by client and
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

/// SHA-256 input of an account key fingerprint:
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

    #[test]
    fn len_prefixed_abc() {
        assert_eq!(len_prefixed(b"abc"), [0, 0, 0, 3, 0x61, 0x62, 0x63]);
        assert_eq!(len_prefixed(b""), [0, 0, 0, 0]);
    }

    #[test]
    fn aad_item_layout() {
        let vault = [0xAA; 16];
        let item = [0xBB; 16];
        let aad = aad_item(&vault, &item, 7);
        assert_eq!(aad.len(), 19 + 16 + 16 + 4);
        assert_eq!(&aad[..19], b"courier-ftp-item-v1");
        assert_eq!(&aad[19..35], &vault);
        assert_eq!(&aad[35..51], &item);
        assert_eq!(&aad[51..], &[0, 0, 0, 7]);
    }

    #[test]
    fn grant_sig_layout() {
        let m = sig_grant(&[1; 16], &[2; 16], 3, b"wk");
        assert_eq!(&m[..20], b"courier-ftp/grant/v1");
        assert_eq!(&m[20..36], &[1; 16]);
        assert_eq!(&m[36..52], &[2; 16]);
        assert_eq!(&m[52..56], &[0, 0, 0, 3]);
        assert_eq!(&m[56..], &[0, 0, 0, 2, b'w', b'k']);
        let b = aad_private_bundle(&[9; 16], 0x0102_0304);
        assert_eq!(&b[..21], b"courier-ftp/bundle/v1");
        assert_eq!(&b[37..], &[1, 2, 3, 4]);
        assert_eq!(fpr_input(&[1; 32], &[2; 32]).len(), 18 + 64);
    }

    #[test]
    fn info_vk_layout() {
        let i = info_vk(&[5; 16], 0x0a0b_0c0d);
        assert_eq!(&i[..17], b"courier-ftp/vk/v1");
        assert_eq!(&i[17..33], &[5; 16]);
        assert_eq!(&i[33..], &[0x0a, 0x0b, 0x0c, 0x0d]);
    }

    #[test]
    fn wrap_aad_layout() {
        let aad = aad_wrap("vault-key", Some(&[7; 16]));
        assert_eq!(&aad[..19], b"courier-ftp-wrap-v1");
        assert_eq!(&aad[19..23], &[0, 0, 0, 9]);
        assert_eq!(&aad[23..32], b"vault-key");
        assert_eq!(&aad[32..], &[7; 16]);
    }

    #[test]
    fn recovery_proof_is_length_prefixed() {
        let a = sig_recovery_proof(&[1; 16], 2, b"ab", b"c");
        let b = sig_recovery_proof(&[1; 16], 2, b"a", b"bc");
        assert_ne!(a, b);
        assert!(a.starts_with(b"courier-ftp/recovery-proof/v1"));
    }

    /// Every label carries the courier-ftp prefix and a version suffix, and no
    /// two labels are equal (or one a prefix of another).
    #[test]
    fn labels_are_courier_ftp_and_distinct() {
        let all = [
            labels::ITEM_V1,
            labels::ITEM_KEY_V1,
            labels::WRAP_V1,
            labels::VK_V1,
            labels::AKEK_V1,
            labels::BUNDLE_V1,
            labels::RECOVERY_V1,
            labels::RECOVERY_BUNDLE_V1,
            labels::RECOVERY_PROOF_V1,
            labels::GRANT_V1,
            labels::FPR_V1,
            labels::OPAQUE_V1,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(a.starts_with("courier-ftp"), "{a}");
            assert!(a.ends_with("v1"), "{a}");
            for b in &all[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a), "{a} / {b}");
            }
        }
    }
}
