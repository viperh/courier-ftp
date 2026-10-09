//! The core module skeleton from T01 (AC11).

#[allow(unused_imports)]
use courier_ftp_core::{Error, Result, error, listing, secret, text, trust};

#[test]
fn core_modules_exist() {
    // Compiles only if the crate-root `Error` is the same type as `error::Error`.
    fn same(e: error::Error) -> Error {
        e
    }
    let r: Result<()> = Err(same(error::Error::InvalidState("x".into())));
    assert!(matches!(r, Err(Error::InvalidState(ref s)) if s == "x"));
}
