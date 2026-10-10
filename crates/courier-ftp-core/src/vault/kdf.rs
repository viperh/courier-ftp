//! Argon2id cost presets and the `meta.kdf` encoding (sverb `vault/mod.rs`, D13).

use std::fmt;

use ciborium::Value;
use courier_ftp_crypto::kdf::Argon2Params;

use super::VaultError;
use crate::settings::Argon2Preset;

/// The only algorithm name `meta.kdf` may carry.
pub const KDF_ALG: &str = "argon2id";

/// Argon2id cost (memory in KiB, passes, lanes), without the salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Cost {
    /// 64 MiB, t = 3.
    pub const LIGHT: Self = Self {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };
    /// 256 MiB, t = 3 (the default).
    pub const STANDARD: Self = Self {
        m_kib: 262_144,
        t: 3,
        p: 1,
    };
    /// 1 GiB, t = 4.
    pub const STRONG: Self = Self {
        m_kib: 1_048_576,
        t: 4,
        p: 1,
    };
    /// **Tests only.** Equals the crypto crate's minimum bounds (m = 19 456 KiB,
    /// t = 1, p = 1), so a vault created with it passes the load-time bound check.
    pub const TEST: Self = Self {
        m_kib: Argon2Params::MIN_M_KIB,
        t: 1,
        p: 1,
    };

    /// The cost of a settings preset (`vault.argon2_cost`).
    pub fn from_preset(preset: Argon2Preset) -> Self {
        match preset {
            Argon2Preset::Light => Self::LIGHT,
            Argon2Preset::Standard => Self::STANDARD,
            Argon2Preset::Strong => Self::STRONG,
        }
    }

    /// Full parameters with `salt`.
    pub const fn with_salt(self, salt: [u8; 16]) -> KdfParams {
        KdfParams {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
            salt,
        }
    }
}

impl Default for Argon2Cost {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// `meta.kdf`: `{alg: "argon2id", m_kib, t, p, salt: bstr(16)}` as a CBOR map.
/// `Debug` omits the salt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// Random 16-byte salt.
    pub salt: [u8; 16],
}

impl fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfParams")
            .field("m_kib", &self.m_kib)
            .field("t", &self.t)
            .field("p", &self.p)
            .finish_non_exhaustive()
    }
}

impl KdfParams {
    /// The parameters for `courier_ftp_crypto::kdf::argon2id`.
    pub const fn argon2(&self) -> Argon2Params {
        Argon2Params {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
            salt: self.salt,
        }
    }

    /// The cost part.
    pub const fn cost(&self) -> Argon2Cost {
        Argon2Cost {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
        }
    }

    /// CBOR map encoding for `meta.kdf`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let map = Value::Map(vec![
            (Value::Text("alg".into()), Value::Text(KDF_ALG.into())),
            (
                Value::Text("m_kib".into()),
                Value::Integer(self.m_kib.into()),
            ),
            (Value::Text("t".into()), Value::Integer(self.t.into())),
            (Value::Text("p".into()), Value::Integer(self.p.into())),
            (Value::Text("salt".into()), Value::Bytes(self.salt.to_vec())),
        ]);
        let mut out = Vec::new();
        // Writing a small in-memory value into a Vec cannot fail.
        let _ = ciborium::into_writer(&map, &mut out);
        out
    }

    /// Decodes [`KdfParams::to_cbor`] and validates the bounds (before any Argon2
    /// run).
    ///
    /// # Errors
    /// [`VaultError::Corrupt`] for anything but a well-formed argon2id map within the
    /// bounds `courier_ftp_crypto` accepts.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, VaultError> {
        let bad = |what: &str| VaultError::Corrupt(format!("meta.kdf: {what}"));
        let value: Value = ciborium::from_reader(bytes).map_err(|_| bad("not CBOR"))?;
        let Value::Map(entries) = value else {
            return Err(bad("not a map"));
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v)
        };
        let int = |key: &str| -> Result<u32, VaultError> {
            get(key)
                .and_then(Value::as_integer)
                .and_then(|i| u32::try_from(i).ok())
                .ok_or_else(|| bad("parameters out of range"))
        };
        if get("alg").and_then(Value::as_text) != Some(KDF_ALG) {
            return Err(bad("unsupported alg"));
        }
        let salt: [u8; 16] = get("salt")
            .and_then(Value::as_bytes)
            .and_then(|b| b.as_slice().try_into().ok())
            .ok_or_else(|| bad("salt"))?;
        let params = Self {
            m_kib: int("m_kib")?,
            t: int("t")?,
            p: int("p")?,
            salt,
        };
        params
            .argon2()
            .validate()
            .map_err(|_| bad("parameters out of range"))?;
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: Vec<(&str, Value)>) -> Vec<u8> {
        let v = Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Text(k.into()), v))
                .collect(),
        );
        let mut out = Vec::new();
        let _ = ciborium::into_writer(&v, &mut out);
        out
    }

    #[test]
    fn kdf_params_cbor_roundtrip() {
        let p = Argon2Cost::STANDARD.with_salt([3; 16]);
        assert_eq!(KdfParams::from_cbor(&p.to_cbor()), Ok(p));
        let v: Value = ciborium::from_reader(p.to_cbor().as_slice()).unwrap_or(Value::Null);
        assert!(v.as_map().is_some_and(|m| m.len() == 5));
        assert_eq!(p.cost(), Argon2Cost::STANDARD);
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("salt") && dbg.contains("262144"), "{dbg}");
    }

    #[test]
    fn kdf_params_rejects_bad_input() {
        assert!(KdfParams::from_cbor(b"junk").is_err());
        let salt = Value::Bytes(vec![0; 16]);
        let base = |alg: &str, m: u64, t: u64, p: u64, salt: Value| {
            map(vec![
                ("alg", Value::Text(alg.into())),
                ("m_kib", Value::Integer(m.into())),
                ("t", Value::Integer(t.into())),
                ("p", Value::Integer(p.into())),
                ("salt", salt),
            ])
        };
        let cases = [
            base("argon2id", 1024, 3, 1, salt.clone()),
            base("argon2id", 8 * 1024 * 1024, 3, 1, salt.clone()),
            base("argon2id", 65_536, 0, 1, salt.clone()),
            base("argon2id", 65_536, 65, 1, salt.clone()),
            base("argon2id", 65_536, 3, 17, salt.clone()),
            base("scrypt", 65_536, 3, 1, salt.clone()),
            base("argon2id", 65_536, 3, 1, Value::Bytes(vec![0; 15])),
            base("argon2id", 1 << 33, 3, 1, salt.clone()),
            map(vec![("alg", Value::Text("argon2id".into()))]),
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(
                matches!(KdfParams::from_cbor(c), Err(VaultError::Corrupt(_))),
                "case {i}"
            );
        }
        assert!(KdfParams::from_cbor(&base("argon2id", 65_536, 3, 1, salt)).is_ok());
    }

    #[test]
    fn presets_within_bounds() {
        for cost in [Argon2Cost::LIGHT, Argon2Cost::STANDARD, Argon2Cost::STRONG] {
            assert_eq!(cost.with_salt([1; 16]).argon2().validate(), Ok(()));
        }
        assert_eq!(
            Argon2Cost::from_preset(Argon2Preset::Light),
            Argon2Cost::LIGHT
        );
        assert_eq!(
            Argon2Cost::from_preset(Argon2Preset::Standard),
            Argon2Cost::STANDARD
        );
        assert_eq!(
            Argon2Cost::from_preset(Argon2Preset::Strong),
            Argon2Cost::STRONG
        );
        assert_eq!(Argon2Cost::default(), Argon2Cost::STANDARD);
    }

    #[test]
    fn test_cost_within_load_bounds() {
        let p = Argon2Cost::TEST.with_salt([9; 16]);
        assert_eq!(p.argon2().validate(), Ok(()));
        assert_eq!(KdfParams::from_cbor(&p.to_cbor()), Ok(p));
        assert_eq!(
            (
                Argon2Cost::TEST.m_kib,
                Argon2Cost::TEST.t,
                Argon2Cost::TEST.p
            ),
            (19_456, 1, 1)
        );
    }
}
