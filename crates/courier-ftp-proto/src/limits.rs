//! Every numeric limit shared by client and server.
//!
//! Byte sizes count decoded bytes (not base64), character counts count Unicode
//! scalar values after trimming.

/// One item envelope (decoded bytes): 1 MiB. Larger envelopes get a per-item
/// `too_large` push result.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Changes per push.
pub const MAX_BATCH_ITEMS: usize = 500;
/// Sum of decoded envelopes per push: 8 MiB.
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Pull page size cap and default.
pub const MAX_PULL_LIMIT: u32 = 500;
/// Items per rotation `upload` (whose envelopes also stay ≤ [`MAX_BATCH_BYTES`]).
pub const MAX_ROTATION_CHUNK: usize = 500;
/// A rotation counts as abandoned after 15 minutes.
pub const ROTATION_ABANDON_SECS: u64 = 900;
/// HTTP request body limit: 12 MiB (8 MiB base64 ≈ 10.7 MiB, plus JSON).
pub const BODY_LIMIT_BYTES: usize = 12 * 1024 * 1024;
/// Email length after trimming.
pub const MAX_EMAIL_LEN: usize = 254;
/// Device name / platform, characters.
pub const MAX_DEVICE_FIELD: usize = 128;
/// Sealed vault name, bytes.
pub const MAX_NAME_ENC_BYTES: usize = 4096;
/// Org display name, characters (1–100).
pub const MAX_ORG_NAME_CHARS: usize = 100;
/// Audit log page size cap.
pub const MAX_AUDIT_PAGE: u32 = 200;
/// Audit log default page size.
pub const DEFAULT_AUDIT_PAGE: u32 = 50;
/// Org and instance invites live 7 days.
pub const INVITE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Any opaque token string (tokens are 43 chars: 32 random bytes, base64url).
pub const MAX_TOKEN_CHARS: usize = 64;
/// Recovery code characters without dashes (Crockford-style base32, grouped
/// `XXXX-XXXX-XXXX-XXXX`; 19 chars with dashes).
pub const RECOVERY_CODE_CHARS: usize = 16;

/// X25519 public key length (`x25519_pub`).
pub const X25519_PUB_LEN: usize = courier_ftp_crypto::hpke::X25519_LEN;
/// Ed25519 public key length (`ed25519_pub`).
pub const ED25519_PUB_LEN: usize = courier_ftp_crypto::sign::ED25519_PUBLIC_LEN;
/// Ed25519 signature length (grant and recovery signatures).
pub const SIGNATURE_LEN: usize = courier_ftp_crypto::sign::SIGNATURE_LEN;
/// Sealed account bundle length (`private_bundle_enc`, `recovery_bundle_enc`).
pub const ACCOUNT_BUNDLE_LEN: usize = courier_ftp_crypto::account::BUNDLE_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_values() {
        assert_eq!(MAX_ENVELOPE_BYTES, 1_048_576);
        assert_eq!(MAX_BATCH_BYTES, 8_388_608);
        assert_eq!(BODY_LIMIT_BYTES, 12_582_912);
        assert_eq!(INVITE_TTL_SECS, 604_800);
        // The body limit must fit a full batch in base64 plus JSON overhead.
        assert!(MAX_BATCH_BYTES.div_ceil(3) * 4 < BODY_LIMIT_BYTES);
        assert_eq!(X25519_PUB_LEN, 32);
        assert_eq!(ED25519_PUB_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
    }
}
