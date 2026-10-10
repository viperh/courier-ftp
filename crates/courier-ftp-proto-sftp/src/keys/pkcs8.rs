//! PKCS#8 private keys: `BEGIN PRIVATE KEY` and `BEGIN ENCRYPTED PRIVATE KEY`
//! (PBES2: PBKDF2 / scrypt with AES-CBC / AES-GCM, through the `pkcs8` crate). RSA,
//! ECDSA P-256/384/521 and Ed25519. Copied from sverb `keychain/formats/pkcs8.rs` (D13).

use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef, der::Decode as _};
use rsa::pkcs8::DecodePrivateKey as _;
use ssh_key::{
    PrivateKey,
    private::{Ed25519Keypair, KeypairData},
};

use super::{KeyError, pem::ec_key, pem_block};

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_DSA: &str = "1.2.840.10040.4.1";

/// Decode a plain PKCS#8 PEM.
///
/// # Errors
/// [`KeyError::Format`], [`KeyError::Unsupported`].
pub fn decode(text: &str) -> Result<PrivateKey, KeyError> {
    let block = pem_block(text, "PRIVATE KEY")?;
    decode_der(&block.der)
}

/// Decode an encrypted PKCS#8 PEM with `passphrase`.
///
/// # Errors
/// [`KeyError::NeedsPassphrase`], [`KeyError::WrongPassphrase`],
/// [`KeyError::Format`], [`KeyError::Unsupported`].
pub fn decode_encrypted(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyError> {
    let block = pem_block(text, "ENCRYPTED PRIVATE KEY")?;
    let info = EncryptedPrivateKeyInfoRef::from_der(&block.der).map_err(|_| KeyError::Format)?;
    let pass = passphrase.ok_or(KeyError::NeedsPassphrase)?;
    let doc = info
        .decrypt(pass.as_bytes())
        .map_err(|_| KeyError::WrongPassphrase)?;
    decode_der(doc.as_bytes()).map_err(|e| match e {
        KeyError::Format => KeyError::WrongPassphrase,
        other => other,
    })
}

/// Decode PKCS#8 `PrivateKeyInfo` DER.
///
/// # Errors
/// [`KeyError::Format`], [`KeyError::Unsupported`].
pub(crate) fn decode_der(der: &[u8]) -> Result<PrivateKey, KeyError> {
    let info = PrivateKeyInfoRef::from_der(der).map_err(|_| KeyError::Format)?;
    let oid = info.algorithm.oid.to_string();
    match oid.as_str() {
        OID_RSA => {
            let rsa = rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| KeyError::Format)?;
            super::pem::rsa_key(&rsa)
        }
        OID_EC => {
            let curve = info
                .algorithm
                .parameters_oid()
                .map_err(|_| KeyError::Format)?
                .to_string();
            // The private key field is a SEC1 `ECPrivateKey`.
            ec_key(&curve, info.private_key.as_bytes())
        }
        OID_ED25519 => {
            // `CurvePrivateKey ::= OCTET STRING` inside the private key field.
            let seed: [u8; 32] = match info.private_key.as_bytes() {
                [0x04, 0x20, rest @ ..] => rest.try_into().map_err(|_| KeyError::Format)?,
                _ => return Err(KeyError::Format),
            };
            let kp = Ed25519Keypair::from_seed(&seed);
            PrivateKey::new(KeypairData::from(kp), "").map_err(|e| KeyError::Invalid(e.to_string()))
        }
        OID_DSA => Err(KeyError::Unsupported("DSA keys".to_owned())),
        other => Err(KeyError::Unsupported(format!("PKCS#8 algorithm {other}"))),
    }
}
