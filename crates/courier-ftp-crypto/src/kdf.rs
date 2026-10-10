//! Password key derivation: Argon2id with stored, bounds-checked parameters.
//!
//! ```text
//! KEK = Argon2id(v0x13, password, salt(16), m_kib, t, p) -> 32 bytes
//! ```
//!
//! [`KdfParams`] is stored next to the wrapped LMK (`meta.kdf`, T30) as a CBOR
//! map `{alg, m_kib, t, p, salt}`, so the cost can be raised later (re-wrap on
//! the next unlock). It is bounds-checked whenever it is decoded or used, so a
//! tampered database cannot make unlock allocate unbounded memory or spin.
//!
//! HKDF lives in [`crate::keys`].

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::keys::{KEY_LEN, Key32, SALT_LEN, random_salt16};

/// The password KDF algorithm. Only Argon2id exists; the field is there so a
/// future algorithm can be introduced without a format break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KdfAlg {
    /// Argon2id, version 0x13, 32-byte output, no secret, no associated data.
    #[serde(rename = "argon2id")]
    Argon2id,
}

/// Argon2id cost (memory, passes, lanes) without a salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Argon2Cost {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u32,
}

impl Argon2Cost {
    /// The production default: m = 256 MiB, t = 3, p = 1.
    pub const DEFAULT: Self = Self {
        m_kib: 262_144,
        t: 3,
        p: 1,
    };

    /// A cheap cost for test suites (8 KiB, one pass). It is below
    /// [`KdfParams::MIN_M_KIB`] and is accepted by [`KdfParams::validate`]
    /// only in builds with the `insecure-test-ksf` feature (or this crate's
    /// own unit tests). **Never use outside tests.**
    #[cfg(any(test, feature = "insecure-test-ksf"))]
    pub const TEST: Self = Self {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    /// Whether this is the insecure test cost and this build accepts it.
    const fn is_accepted_test_cost(&self) -> bool {
        #[cfg(any(test, feature = "insecure-test-ksf"))]
        {
            self.m_kib == Self::TEST.m_kib && self.t == Self::TEST.t && self.p == Self::TEST.p
        }
        #[cfg(not(any(test, feature = "insecure-test-ksf")))]
        {
            let _ = self;
            false
        }
    }
}

impl Default for Argon2Cost {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Password KDF parameters plus salt, as stored in `meta.kdf`.
///
/// Serialize with [`KdfParams::to_cbor`] / [`KdfParams::from_cbor`]. The CBOR
/// map has exactly the keys `alg` (text `"argon2id"`), `m_kib`, `t`, `p`
/// (unsigned integers) and `salt` (byte string, 16 bytes); unknown keys are
/// rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// The algorithm.
    pub alg: KdfAlg,
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u32,
    /// Random per-device salt.
    #[serde(with = "salt_bytes")]
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Minimum accepted memory cost (19 MiB, the OWASP floor for Argon2id).
    pub const MIN_M_KIB: u32 = 19_456;
    /// Maximum accepted memory cost (4 GiB), so a corrupted `meta` row can't
    /// make unlock allocate unbounded memory.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    /// Maximum accepted pass count.
    pub const MAX_T: u32 = 64;
    /// Maximum accepted parallelism.
    pub const MAX_P: u32 = 16;
    /// Upper bound on the encoded size accepted by [`KdfParams::from_cbor`].
    pub const MAX_ENCODED_LEN: usize = 128;

    /// Argon2id parameters with the given cost and salt.
    #[must_use]
    pub const fn new(cost: Argon2Cost, salt: [u8; SALT_LEN]) -> Self {
        Self {
            alg: KdfAlg::Argon2id,
            m_kib: cost.m_kib,
            t: cost.t,
            p: cost.p,
            salt,
        }
    }

    /// Argon2id parameters with the given cost and a fresh random salt.
    pub fn generate<R: CryptoRng + ?Sized>(cost: Argon2Cost, rng: &mut R) -> Self {
        Self::new(cost, random_salt16(rng))
    }

    /// The cost part of these parameters.
    #[must_use]
    pub const fn cost(&self) -> Argon2Cost {
        Argon2Cost {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
        }
    }

    /// Checks the bounds: `19456 ≤ m_kib ≤ 4 GiB`, `1 ≤ t ≤ 64`, `1 ≤ p ≤ 16`
    /// (plus `Argon2Cost::TEST` in builds with `insecure-test-ksf`).
    ///
    /// # Errors
    /// [`CryptoError::InvalidParams`] when a parameter is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.cost().is_accepted_test_cost() {
            return Ok(());
        }
        if self.m_kib < Self::MIN_M_KIB {
            return Err(CryptoError::InvalidParams("argon2 m_kib below 19456"));
        }
        if self.m_kib > Self::MAX_M_KIB {
            return Err(CryptoError::InvalidParams("argon2 m_kib too large"));
        }
        if self.t < 1 || self.t > Self::MAX_T {
            return Err(CryptoError::InvalidParams("argon2 t out of range"));
        }
        if self.p < 1 || self.p > Self::MAX_P {
            return Err(CryptoError::InvalidParams("argon2 p out of range"));
        }
        Ok(())
    }

    /// Encodes the parameters as a CBOR map (see the type docs).
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        // Serializing a fixed struct into a Vec cannot fail.
        if ciborium::into_writer(self, &mut out).is_err() {
            out.clear();
        }
        out
    }

    /// Decodes [`KdfParams::to_cbor`] and validates the result.
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] for invalid CBOR, missing or unknown keys,
    /// an unknown `alg`, a salt that is not 16 bytes or trailing bytes;
    /// [`CryptoError::InvalidParams`] if the values are out of bounds.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_ENCODED_LEN {
            return Err(CryptoError::Malformed("kdf params too long"));
        }
        let mut reader = bytes;
        let params: Self =
            ciborium::from_reader(&mut reader).map_err(|_| CryptoError::Malformed("kdf params"))?;
        if !reader.is_empty() {
            return Err(CryptoError::Malformed("kdf params trailing bytes"));
        }
        params.validate()?;
        Ok(params)
    }
}

/// `[u8; 16]` as a CBOR byte string (serde's default is an array of integers).
mod salt_bytes {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    use crate::keys::SALT_LEN;

    pub(super) fn serialize<S: Serializer>(salt: &[u8; SALT_LEN], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(salt)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; SALT_LEN], D::Error> {
        struct SaltVisitor;
        impl Visitor<'_> for SaltVisitor {
            type Value = [u8; SALT_LEN];

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a 16-byte byte string")
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_bytes(SaltVisitor)
    }
}

/// Derives a 32-byte key-encryption key from a password with Argon2id
/// (version 0x13, no secret, no associated data).
///
/// **CPU- and memory-heavy** (about 256 MiB and on the order of a second with
/// [`Argon2Cost::DEFAULT`]). Async callers must run it inside
/// `tokio::task::spawn_blocking`, never on a runtime worker thread.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if the parameters fail
/// [`KdfParams::validate`].
pub fn argon2id(password: &[u8], params: &KdfParams) -> Result<Key32> {
    params.validate()?;
    match params.alg {
        KdfAlg::Argon2id => argon2id_raw(password, &params.salt, params.m_kib, params.t, params.p),
    }
}

fn argon2id_raw(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Key32> {
    let a2_params = argon2::Params::new(m_kib, t, p, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidParams("argon2 params rejected"))?;
    let ctx = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        a2_params,
    );
    let mut out = [0u8; KEY_LEN];
    ctx.hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::InvalidParams("argon2 failed"))?;
    let key = Key32::from_bytes(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
            .collect()
    }

    /// Reference vector from phc-winner-argon2 `test.c` (also among the
    /// `argon2` crate's KATs): Argon2id v0x13, t=2, m=2^16, p=1,
    /// "password" / "somesalt". Cross-checks our wrapper's parameter mapping.
    #[test]
    fn argon2id_reference_vector() {
        let key = argon2id_raw(b"password", b"somesalt", 1 << 16, 2, 1);
        let expected = unhex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
        assert_eq!(key.map(|k| k.expose_secret().to_vec()).ok(), Some(expected));
    }

    #[test]
    fn params_cbor_roundtrip_and_bounds() {
        let p = KdfParams::new(Argon2Cost::DEFAULT, [9; 16]);
        assert_eq!(KdfParams::from_cbor(&p.to_cbor()), Ok(p));
        let t = KdfParams::new(Argon2Cost::TEST, [9; 16]);
        assert_eq!(KdfParams::from_cbor(&t.to_cbor()), Ok(t));
        let low = KdfParams { m_kib: 1024, ..p };
        assert!(matches!(low.validate(), Err(CryptoError::InvalidParams(_))));
        assert!(matches!(
            argon2id(b"pw", &low),
            Err(CryptoError::InvalidParams(_))
        ));
        assert!(matches!(
            KdfParams::from_cbor(&low.to_cbor()),
            Err(CryptoError::InvalidParams(_))
        ));
        assert!(KdfParams { t: 0, ..p }.validate().is_err());
        assert!(KdfParams { p: 0, ..p }.validate().is_err());
        assert!(KdfParams { t: 65, ..p }.validate().is_err());
        assert!(KdfParams { p: 17, ..p }.validate().is_err());
        assert!(
            KdfParams {
                m_kib: KdfParams::MAX_M_KIB + 1,
                ..p
            }
            .validate()
            .is_err()
        );
        assert!(KdfParams::from_cbor(&[0; 5]).is_err());
        assert!(KdfParams::from_cbor(&[]).is_err());
    }

    /// The exact CBOR bytes, so the stored format can't drift silently.
    #[test]
    fn params_cbor_layout() {
        let p = KdfParams::new(Argon2Cost::DEFAULT, [0x11; 16]);
        let mut expected = vec![0xa5];
        expected.extend_from_slice(b"\x63alg\x68argon2id");
        expected.extend_from_slice(b"\x65m_kib\x1a\x00\x04\x00\x00");
        expected.extend_from_slice(b"\x61t\x03");
        expected.extend_from_slice(b"\x61p\x01");
        expected.extend_from_slice(b"\x64salt\x50");
        expected.extend_from_slice(&[0x11; 16]);
        assert_eq!(p.to_cbor(), expected);
    }

    #[test]
    fn params_cbor_strictness() {
        let p = KdfParams::new(Argon2Cost::DEFAULT, [0x11; 16]);
        let good = p.to_cbor();
        // Trailing bytes.
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            KdfParams::from_cbor(&trailing),
            Err(CryptoError::Malformed(_))
        ));
        // Unknown algorithm.
        let mut bad_alg = good.clone();
        assert_eq!(&bad_alg[6..14], b"argon2id");
        bad_alg[6..14].copy_from_slice(b"argon2ix");
        assert!(matches!(
            KdfParams::from_cbor(&bad_alg),
            Err(CryptoError::Malformed(_))
        ));
        // Salt of the wrong length (15 bytes, map otherwise valid).
        let mut short_salt = good[..good.len() - 17].to_vec();
        short_salt.push(0x4f);
        short_salt.extend_from_slice(&[0x11; 15]);
        assert!(matches!(
            KdfParams::from_cbor(&short_salt),
            Err(CryptoError::Malformed(_))
        ));
        // Truncation never panics and never succeeds.
        for len in 0..good.len() {
            assert!(KdfParams::from_cbor(&good[..len]).is_err());
        }
        // Oversized input is rejected before decoding.
        assert!(KdfParams::from_cbor(&[0; KdfParams::MAX_ENCODED_LEN + 1]).is_err());
    }

    #[test]
    fn test_cost_derives_quickly_and_deterministically() {
        let params = KdfParams::new(Argon2Cost::TEST, [4; 16]);
        let a = argon2id(b"right", &params);
        let b = argon2id(b"wrong", &params);
        assert!(a.is_ok() && b.is_ok());
        assert_ne!(a, b);
        assert_eq!(a, argon2id(b"right", &params));
        let other_salt = KdfParams::new(Argon2Cost::TEST, [5; 16]);
        assert_ne!(a, argon2id(b"right", &other_salt));
    }
}
