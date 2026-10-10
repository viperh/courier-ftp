//! Size limits shared by client and server.
//!
//! The server enforces them; the client respects them when it builds requests
//! (split pushes into batches, refuse oversized items locally). Byte limits
//! count **decoded** bytes, not base64 text.

use thiserror::Error;

/// Maximum (and default) page size of a pull. Larger `limit`s are clamped.
pub const MAX_PULL_LIMIT: u32 = 500;

/// Maximum number of changes in one push.
pub const MAX_PUSH_ITEMS: usize = 500;

/// Maximum total envelope bytes in one push: 8 MiB.
pub const MAX_PUSH_BYTES: usize = 8 * 1024 * 1024;

/// Maximum size of one item envelope: 1 MiB. A larger envelope gets
/// [`crate::sync::PushStatus::TooLarge`] (the rest of the batch still applies).
pub const MAX_ENVELOPE: usize = 1024 * 1024;

/// Request body limit of the server: 12 MiB, room for [`MAX_PUSH_BYTES`] in
/// base64 (4/3) plus JSON overhead. Larger bodies get `413` / `invalid`.
pub const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

/// Longest encrypted vault name.
pub const MAX_NAME_ENC_BYTES: usize = 4096;

/// Most items per rotation `upload` chunk.
pub const MAX_ROTATION_CHUNK: usize = 500;

/// Largest audit-log page (default 50).
pub const MAX_AUDIT_PAGE: u32 = 200;

/// Longest org name, in characters.
pub const MAX_ORG_NAME_CHARS: usize = 100;

/// Longest device name or platform string, in characters.
pub const MAX_DEVICE_FIELD_CHARS: usize = 100;

/// A request over one of the limits, or with a fixed-size field of the wrong
/// size (answer `400 invalid`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LimitError {
    /// More than [`MAX_PUSH_ITEMS`] changes.
    #[error("too many changes in one push: {got} (at most {MAX_PUSH_ITEMS})")]
    TooManyItems {
        /// Changes sent.
        got: usize,
    },
    /// More than [`MAX_PUSH_BYTES`] of envelopes.
    #[error("push too large: {got} envelope bytes (at most {MAX_PUSH_BYTES})")]
    TooManyBytes {
        /// Total decoded envelope bytes.
        got: usize,
    },
    /// The same item twice in one push.
    #[error("duplicate item id {0} in one push")]
    DuplicateItem(uuid::Uuid),
    /// A pull `limit` of 0.
    #[error("pull limit must be at least 1")]
    ZeroPullLimit,
    /// More than [`MAX_ROTATION_CHUNK`] items in a rotation upload.
    #[error("too many items in one rotation upload: {got} (at most {MAX_ROTATION_CHUNK})")]
    RotationChunk {
        /// Items sent.
        got: usize,
    },
    /// A grant signature that is not 64 bytes.
    #[error("grant signature must be 64 bytes, got {got}")]
    SignatureLength {
        /// Bytes sent.
        got: usize,
    },
}

impl From<LimitError> for crate::ErrorEnvelope {
    fn from(e: LimitError) -> Self {
        Self::new(crate::ErrorCode::Invalid, e.to_string(), None)
    }
}

// The body limit fits a full push in base64 with generous per-change JSON overhead.
const _: () = assert!(MAX_PUSH_BYTES / 3 * 4 + MAX_PUSH_ITEMS * 256 < MAX_BODY_BYTES);
const _: () = assert!(MAX_ENVELOPE <= MAX_PUSH_BYTES);
