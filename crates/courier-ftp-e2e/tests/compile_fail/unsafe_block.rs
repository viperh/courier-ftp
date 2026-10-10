//! Compile-fail fixture: must be rejected by `unsafe_code = "deny"`, which
//! every crate inherits from `[workspace.lints]`. Compiled by
//! `crates/courier-ftp-e2e/tests/forbid_unsafe.rs`, never by this crate.

pub fn read(p: *const u8) -> u8 {
    unsafe { *p }
}
