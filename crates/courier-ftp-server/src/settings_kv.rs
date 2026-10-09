//! Keys of the `settings` key/value table.
//!
//! | Key | Value |
//! |---|---|
//! | [`REGISTRATION_MODE`] | `open` \| `invite-only` \| `closed` (`invite-only` after the first migration) |
//! | [`SETUP_TOKEN_HASH`] | hex SHA-256 of the one-time setup token; present only until the first account registers with it |
//!
//! Read and written through [`crate::auth::store::Store::setting`] and
//! [`crate::auth::store::Store::set_setting`].

/// Who may register.
pub const REGISTRATION_MODE: &str = "registration_mode";
/// Hex SHA-256 of the bootstrap setup token.
pub const SETUP_TOKEN_HASH: &str = "setup_token_hash";
