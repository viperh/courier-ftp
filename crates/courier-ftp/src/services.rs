//! Platform services the core reaches through traits: the OS keyring (T30), and the
//! vault service that owns the vault engine (T60).

pub(crate) mod keyring;
pub(crate) mod vault;
