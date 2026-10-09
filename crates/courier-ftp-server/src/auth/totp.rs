//! TOTP second factor (RFC 6238 via `totp-rs`).
//!
//! SHA-1, 6 digits, 30-second steps (what every authenticator app supports),
//! 160-bit secrets, issuer `courier-ftp`. A code is accepted for steps
//! `now-1..=now+1`; the matched step is returned so the store can enforce
//! **replay protection**: only a step greater than `users.totp_last_step` counts
//! ([`is_fresh`], updated atomically). Secrets are stored sealed under the
//! server-secret key with an AAD bound to the user.

use courier_ftp_crypto::random;
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

/// Step length in seconds.
pub const STEP_S: u64 = 30;
/// Code length.
pub const DIGITS: usize = 6;
/// Secret length in bytes (RFC 4226 recommends 160 bits).
pub const SECRET_LEN: usize = 20;
/// Issuer shown by authenticator apps.
pub const ISSUER: &str = "courier-ftp";

fn totp(secret: &[u8]) -> TOTP {
    TOTP::new_unchecked(Algorithm::SHA1, DIGITS, 1, STEP_S, secret.to_vec())
}

/// A fresh random secret.
#[must_use]
pub fn generate_secret() -> Zeroizing<Vec<u8>> {
    let key = random::random_key32(&mut random::os_rng());
    Zeroizing::new(key.expose_secret()[..SECRET_LEN].to_vec())
}

/// The secret in base32 (no padding), for manual entry.
#[must_use]
pub fn base32(secret: &[u8]) -> String {
    match Secret::Raw(secret.to_vec()).to_encoded() {
        Secret::Encoded(s) => s.trim_end_matches('=').to_owned(),
        Secret::Raw(_) => String::new(),
    }
}

/// Decodes [`base32`] output (clients and tests).
#[must_use]
pub fn from_base32(s: &str) -> Option<Vec<u8>> {
    Secret::Encoded(s.to_owned()).to_bytes().ok()
}

fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@' | b'+') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `otpauth://totp/courier-ftp:<account>?secret=…&issuer=courier-ftp&…` (Key Uri
/// Format). The account label is the email; it only appears inside this URI.
#[must_use]
pub fn otpauth_uri(secret: &[u8], account: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_S}",
        issuer = percent_encode(ISSUER),
        account = percent_encode(account),
        secret = base32(secret),
    )
}

/// The code for the step containing `unix_s` (tests, clients).
#[must_use]
pub fn code_at(secret: &[u8], unix_s: u64) -> String {
    totp(secret).generate(unix_s)
}

/// Checks `code` at `unix_s` with a ±1 step window. Returns the matching step
/// number (`unix / 30`), latest first, or `None`.
#[must_use]
pub fn verify(secret: &[u8], code: &str, unix_s: u64) -> Option<u64> {
    let code: Zeroizing<String> =
        Zeroizing::new(code.chars().filter(|c| !c.is_whitespace()).collect());
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let t = totp(secret);
    let current = unix_s / STEP_S;
    let mut matched = None;
    // Check every candidate (no early exit) and compare in constant time.
    for step in [current + 1, current, current.saturating_sub(1)] {
        let expected = Zeroizing::new(t.generate(step * STEP_S));
        let eq: bool = subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), code.as_bytes()).into();
        if eq && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

/// Replay rule: a step counts only when it is greater than the last accepted one.
#[must_use]
pub fn is_fresh(last_step: Option<i64>, step: i64) -> bool {
    last_step.is_none_or(|last| step > last)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238 Appendix B, SHA-1: the 6-digit code is the last six digits.
        let secret = b"12345678901234567890";
        assert_eq!(code_at(secret, 59), "287082");
        assert_eq!(code_at(secret, 1_111_111_109), "081804");
    }

    #[test]
    fn window_and_replay() {
        let s = generate_secret();
        let now = 1_700_000_000;
        let step = now / STEP_S;
        assert_eq!(verify(&s, &code_at(&s, now), now), Some(step));
        assert_eq!(verify(&s, &code_at(&s, now - 30), now), Some(step - 1));
        assert_eq!(verify(&s, &code_at(&s, now + 30), now), Some(step + 1));
        assert_eq!(verify(&s, &code_at(&s, now - 60), now), None);
        assert_eq!(verify(&s, &code_at(&s, now + 60), now), None);
        assert_eq!(verify(&s, "12345", now), None);
        assert_eq!(verify(&s, "abcdef", now), None);
        let spaced = code_at(&s, now);
        let spaced = format!("{} {}", &spaced[..3], &spaced[3..]);
        assert_eq!(verify(&s, &spaced, now), Some(step));

        // Replay: the same step is accepted once; an older one never again.
        let step = i64::try_from(step).unwrap();
        assert!(is_fresh(None, step));
        assert!(!is_fresh(Some(step), step));
        assert!(!is_fresh(Some(step), step - 1));
        assert!(is_fresh(Some(step), step + 1));
    }

    #[test]
    fn uri_shape() {
        let uri = otpauth_uri(&[0; 20], "a b@example.com");
        assert!(uri.starts_with(
            "otpauth://totp/courier-ftp:a%20b@example.com?secret=AAAAAAAA"
        ));
        assert!(uri.contains("issuer=courier-ftp"));
        assert!(!base32(&[0; 20]).contains('='));
        assert_eq!(from_base32(&base32(&[9; 20])).unwrap(), vec![9; 20]);
    }
}
