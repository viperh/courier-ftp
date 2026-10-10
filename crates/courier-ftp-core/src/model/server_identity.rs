//! What the user compares before trusting a server: SSH host keys (produced
//! by T21) and TLS certificates (produced by T12), shown by the trust prompts
//! (T69) and the server info dialog.

use time::OffsetDateTime;

/// One SSH host key, as the user compares it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HostKeyFingerprint {
    /// Key algorithm as named by SSH, e.g. `ssh-ed25519`,
    /// `ecdsa-sha2-nistp256`, `ssh-rsa`.
    pub algorithm: String,
    /// Key size in bits (256 for Ed25519, 3072 for a typical RSA key), when
    /// known.
    pub bits: Option<u32>,
    /// `SHA256:` followed by unpadded base64, as `ssh-keygen -l` prints it.
    pub sha256: String,
    /// The legacy `MD5:aa:bb:…` fingerprint, for comparison with old
    /// documentation.
    pub md5: Option<String>,
}

impl HostKeyFingerprint {
    /// `ssh-ed25519 256`: the algorithm and, when known, the size.
    pub fn key_type(&self) -> String {
        match self.bits {
            Some(bits) => format!("{} {bits}", self.algorithm),
            None => self.algorithm.clone(),
        }
    }
}

/// Whether a certificate is inside its validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateValidity {
    /// `not_before <= now <= not_after`.
    Valid,
    /// `now` is after `not_after`.
    Expired,
    /// `now` is before `not_before`.
    NotYetValid,
}

/// One certificate of a server's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Subject distinguished name, e.g. `CN=ftp.example.com, O=Example`.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number in hex.
    pub serial: String,
    /// Start of the validity period.
    pub not_before: OffsetDateTime,
    /// End of the validity period.
    pub not_after: OffsetDateTime,
    /// Subject alternative names (DNS names and IP addresses).
    pub subject_alt_names: Vec<String>,
    /// Public key algorithm and size, e.g. `RSA 2048`, `ECDSA P-256`.
    pub public_key: String,
    /// Signature algorithm, e.g. `sha256WithRSAEncryption`.
    pub signature_algorithm: String,
    /// SHA-256 fingerprint of the DER encoding, as colon-separated hex pairs.
    pub fingerprint_sha256: String,
    /// SHA-1 fingerprint of the DER encoding, as colon-separated hex pairs.
    pub fingerprint_sha1: String,
}

impl CertificateInfo {
    /// The subject's common name (`CN=`), or the whole subject when it has
    /// none.
    pub fn common_name(&self) -> &str {
        self.subject
            .split(',')
            .map(str::trim)
            .find_map(|part| part.strip_prefix("CN="))
            .unwrap_or(&self.subject)
    }

    /// Whether the certificate is valid at `now`.
    pub fn validity_at(&self, now: OffsetDateTime) -> CertificateValidity {
        if now < self.not_before {
            CertificateValidity::NotYetValid
        } else if now > self.not_after {
            CertificateValidity::Expired
        } else {
            CertificateValidity::Valid
        }
    }
}

/// A server's certificate chain and the TLS session it was presented in,
/// for the certificate trust prompt and "Server info".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateDetails {
    /// `host:port` the certificate was presented for.
    pub host: String,
    /// The chain, the server's own certificate first.
    pub chain: Vec<CertificateInfo>,
    /// Whether the server's certificate names `host`.
    pub hostname_matches: bool,
    /// Negotiated protocol version, e.g. `TLS 1.3`.
    pub tls_version: String,
    /// Negotiated cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher: String,
    /// Why verification failed (self-signed, expired, unknown issuer…);
    /// empty when it didn't.
    pub problem: String,
}

impl CertificateDetails {
    /// The server's own certificate.
    pub fn leaf(&self) -> Option<&CertificateInfo> {
        self.chain.first()
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn cert(subject: &str) -> CertificateInfo {
        CertificateInfo {
            subject: subject.into(),
            issuer: "CN=Example CA".into(),
            serial: "01".into(),
            not_before: datetime!(2026-01-01 0:00 UTC),
            not_after: datetime!(2027-01-01 0:00 UTC),
            subject_alt_names: vec![],
            public_key: "RSA 2048".into(),
            signature_algorithm: "sha256WithRSAEncryption".into(),
            fingerprint_sha256: "AB".into(),
            fingerprint_sha1: "CD".into(),
        }
    }

    #[test]
    fn common_name_is_found_anywhere_in_the_subject() {
        assert_eq!(cert("CN=a.example, O=Ex").common_name(), "a.example");
        assert_eq!(cert("O=Ex, CN=b.example").common_name(), "b.example");
        assert_eq!(cert("O=Ex").common_name(), "O=Ex");
    }

    #[test]
    fn validity_follows_the_period() {
        let c = cert("CN=x");
        assert_eq!(
            c.validity_at(datetime!(2025-12-31 23:59 UTC)),
            CertificateValidity::NotYetValid
        );
        assert_eq!(
            c.validity_at(datetime!(2026-06-01 0:00 UTC)),
            CertificateValidity::Valid
        );
        assert_eq!(
            c.validity_at(datetime!(2027-01-01 0:01 UTC)),
            CertificateValidity::Expired
        );
    }

    #[test]
    fn key_type_includes_bits_when_known() {
        let mut k = HostKeyFingerprint {
            algorithm: "ssh-ed25519".into(),
            bits: Some(256),
            ..Default::default()
        };
        assert_eq!(k.key_type(), "ssh-ed25519 256");
        k.bits = None;
        assert_eq!(k.key_type(), "ssh-ed25519");
    }
}
