//! Access, refresh and reauth tokens; recovery codes.
//!
//! * Every token is 256 random bits from the OS CSPRNG, sent as base64url without
//!   padding (43 characters) and stored **only** as `SHA-256(raw 32 bytes)`.
//! * Access tokens live 15 minutes, refresh tokens 30 days (each rotation issues
//!   a fresh 30 days), reauth tokens 5 minutes (single use).
//! * A refresh rotates the pair inside its `family`; presenting a used refresh
//!   token revokes the whole family. There is no grace window: clients persist
//!   the new pair before using it (T87).
//! * Recovery codes are 10 random bytes as 16 Crockford base32 characters,
//!   shown as `XXXX-XXXX-XXXX-XXXX`; dashes, spaces and case are ignored on input.

use std::fmt;

use courier_ftp_crypto::random;
use courier_ftp_proto::auth::TokenPair;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

/// Raw token length in bytes.
pub const TOKEN_LEN: usize = 32;
/// Access-token lifetime.
pub const ACCESS_TTL: Duration = Duration::minutes(15);
/// Refresh-token lifetime.
pub const REFRESH_TTL: Duration = Duration::days(30);
/// Reauth-token lifetime.
pub const REAUTH_TTL: Duration = Duration::minutes(5);
/// Lifetime of a server-side OPAQUE login state.
pub const LOGIN_STATE_TTL: Duration = Duration::seconds(60);
/// Lifetime of a recovery code.
pub const RECOVERY_CODE_TTL: Duration = Duration::hours(24);
/// Wrong attempts after which a recovery code is deleted.
pub const RECOVERY_CODE_MAX_ATTEMPTS: i32 = 5;
/// `devices.last_seen_at` is written at most this often per device.
pub const LAST_SEEN_THROTTLE: Duration = Duration::minutes(5);
/// Random bytes in a recovery code.
pub const RECOVERY_CODE_BYTES: usize = 10;

/// `SHA-256` of a raw token: the only form that is stored. `Debug` is redacted
/// (hashes are never logged).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenHash(pub [u8; 32]);

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash([REDACTED])")
    }
}

impl TokenHash {
    /// The hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `auth_tokens.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// 15-minute bearer token.
    Access,
    /// 30-day rotating refresh token.
    Refresh,
}

impl TokenKind {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }
}

/// A freshly generated token: the wire form (shown to the client once) and its
/// hash.
pub struct NewToken {
    /// base64url (no padding) of the 32 random bytes.
    pub wire: Zeroizing<String>,
    /// What is stored.
    pub hash: TokenHash,
}

impl fmt::Debug for NewToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewToken([REDACTED])")
    }
}

impl NewToken {
    /// Generates a token from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let key = random::random_key32(&mut random::os_rng());
        Self {
            wire: Zeroizing::new(courier_ftp_proto::b64::encode(key.expose_secret())),
            hash: hash_raw(key.expose_secret()),
        }
    }
}

/// `SHA-256` of raw token bytes.
#[must_use]
pub fn hash_raw(raw: &[u8]) -> TokenHash {
    TokenHash(Sha256::digest(raw).into())
}

/// Hashes a token as presented by a client; `None` unless it is exactly 43
/// characters of base64url (no padding) decoding to 32 bytes.
#[must_use]
pub fn hash_presented(wire: &str) -> Option<TokenHash> {
    if wire.len() != 43 {
        return None;
    }
    let raw = Zeroizing::new(courier_ftp_proto::b64::decode(wire).ok()?);
    (raw.len() == TOKEN_LEN).then(|| hash_raw(&raw))
}

/// One stored token row (without device and family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRecord {
    /// Hash.
    pub hash: TokenHash,
    /// Kind.
    pub kind: TokenKind,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// A new access + refresh pair.
#[derive(Debug)]
pub struct IssuedTokens {
    /// Access token.
    pub access: NewToken,
    /// Refresh token.
    pub refresh: NewToken,
    /// Access expiry.
    pub access_expires: OffsetDateTime,
    /// Refresh expiry.
    pub refresh_expires: OffsetDateTime,
}

impl IssuedTokens {
    /// Generates a pair valid from `now`.
    #[must_use]
    pub fn issue(now: OffsetDateTime) -> Self {
        Self {
            access: NewToken::generate(),
            refresh: NewToken::generate(),
            access_expires: now + ACCESS_TTL,
            refresh_expires: now + REFRESH_TTL,
        }
    }

    /// The two rows to store.
    #[must_use]
    pub fn records(&self) -> [TokenRecord; 2] {
        [
            TokenRecord {
                hash: self.access.hash,
                kind: TokenKind::Access,
                expires_at: self.access_expires,
            },
            TokenRecord {
                hash: self.refresh.hash,
                kind: TokenKind::Refresh,
                expires_at: self.refresh_expires,
            },
        ]
    }

    /// The wire DTO.
    #[must_use]
    pub fn to_pair(&self) -> TokenPair {
        TokenPair {
            access_token: self.access.wire.to_string(),
            refresh_token: self.refresh.wire.to_string(),
            access_expires_in_s: secs(ACCESS_TTL),
            refresh_expires_in_s: secs(REFRESH_TTL),
        }
    }
}

/// Whole seconds of a non-negative duration.
#[must_use]
pub fn secs(d: Duration) -> u64 {
    u64::try_from(d.whole_seconds()).unwrap_or(0)
}

/// Crockford base32 alphabet (no I, L, O, U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Renders 10 bytes as `XXXX-XXXX-XXXX-XXXX` (16 Crockford base32 characters).
#[must_use]
pub fn encode_recovery_code(bytes: &[u8; RECOVERY_CODE_BYTES]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(19));
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(CROCKFORD[((acc >> bits) & 31) as usize]));
            n += 1;
        }
        acc &= (1 << bits) - 1;
    }
    out
}

/// Parses a recovery code as typed: dashes and spaces are skipped, case is
/// ignored, and the Crockford look-alikes `O` → `0`, `I`/`L` → `1` are accepted.
/// `None` unless exactly 16 valid characters remain.
#[must_use]
pub fn decode_recovery_code(code: &str) -> Option<Zeroizing<[u8; RECOVERY_CODE_BYTES]>> {
    let mut out = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut chars = 0;
    let mut pos = 0;
    for c in code.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let v = CROCKFORD.iter().position(|&a| char::from(a) == c)?;
        chars += 1;
        if chars > 16 {
            return None;
        }
        acc = (acc << 5) | u32::try_from(v).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(pos)? = u8::try_from((acc >> bits) & 0xff).ok()?;
            pos += 1;
            acc &= (1 << bits) - 1;
        }
    }
    (chars == 16 && pos == RECOVERY_CODE_BYTES).then_some(out)
}

/// A fresh one-time recovery code.
#[must_use]
pub fn generate_recovery_code() -> Zeroizing<String> {
    let key = random::random_key32(&mut random::os_rng());
    let mut bytes = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
    bytes.copy_from_slice(&key.expose_secret()[..RECOVERY_CODE_BYTES]);
    encode_recovery_code(&bytes)
}

/// The stored hash of a recovery code as typed: `SHA-256` of its 10 bytes. A
/// malformed code hashes to a value no valid code can have, so it simply counts as
/// a wrong attempt.
#[must_use]
pub fn hash_recovery_code(code: &str) -> [u8; 32] {
    match decode_recovery_code(code) {
        Some(bytes) => Sha256::digest(bytes.as_slice()).into(),
        None => {
            let mut h = Sha256::new();
            h.update(b"courier-ftp/malformed-recovery-code/v1:");
            h.update(code.as_bytes());
            h.finalize().into()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bit_base64url_and_hashed() {
        let t = NewToken::generate();
        assert_eq!(t.wire.len(), 43);
        assert_eq!(hash_presented(&t.wire), Some(t.hash));
        assert_ne!(NewToken::generate().hash, t.hash);
        assert_eq!(format!("{:?}", t.hash), "TokenHash([REDACTED])");
        assert!(!format!("{t:?}").contains(t.wire.as_str()));
    }

    #[test]
    fn hash_presented_rejects_wrong_length_and_padding() {
        let b64 = courier_ftp_proto::b64::encode;
        assert_eq!(hash_presented(""), None);
        assert_eq!(hash_presented("not base64 !"), None);
        assert_eq!(hash_presented(&b64(&[0; 31])), None);
        assert_eq!(hash_presented(&b64(&[0; 33])), None);
        // Padded or standard-alphabet forms of 32 bytes are rejected.
        let ok = b64(&[0xfb; 32]);
        assert!(hash_presented(&ok).is_some());
        assert_eq!(hash_presented(&format!("{ok}=")), None);
        assert_eq!(hash_presented(&ok.replace('-', "+").replace('_', "/")), None);
        assert_eq!(hash_presented(&format!(" {}", &ok[1..])), None);
    }

    #[test]
    fn recovery_codes() {
        let c = generate_recovery_code();
        assert_eq!(c.len(), 19);
        assert_eq!(c.matches('-').count(), 3);
        let typed = c.to_lowercase().replace('-', " ");
        assert_eq!(hash_recovery_code(&typed), hash_recovery_code(&c));
        assert_ne!(
            hash_recovery_code(&generate_recovery_code()),
            hash_recovery_code(&c)
        );
        let zero = encode_recovery_code(&[0; 10]);
        assert_eq!(zero.as_str(), "0000-0000-0000-0000");
        assert_eq!(
            encode_recovery_code(&[0xff; 10]).as_str(),
            "ZZZZ-ZZZZ-ZZZZ-ZZZZ"
        );
        assert_eq!(*decode_recovery_code("oooo-iiii-llll-0000").unwrap(), {
            let mut want = [0u8; 10];
            want.copy_from_slice(&decode_recovery_code("0000111111110000").unwrap()[..]);
            want
        });
        for bad in ["", "0000-0000-0000-000", "0000-0000-0000-00000", "UUUU-0000-0000-0000"] {
            assert!(decode_recovery_code(bad).is_none(), "{bad}");
        }
        assert_ne!(hash_recovery_code("garbage"), hash_recovery_code(&zero));
    }

    #[test]
    fn pair_lifetimes() {
        let now = OffsetDateTime::now_utc();
        let t = IssuedTokens::issue(now);
        let p = t.to_pair();
        assert_eq!(p.access_expires_in_s, 900);
        assert_eq!(p.refresh_expires_in_s, 30 * 86_400);
        let [a, r] = t.records();
        assert_eq!((a.kind, r.kind), (TokenKind::Access, TokenKind::Refresh));
        assert_eq!(a.expires_at - now, ACCESS_TTL);
        assert_eq!(secs(REAUTH_TTL), 300);
    }
}
