//! Certificate details for the trust prompt and the server info dialog
//! (`x509-parser`), and the host name check.

use std::net::IpAddr;

use courier_ftp_core::{
    model::CertificateInfo,
    trust::{sha1_fingerprint, sha256_fingerprint},
};
use time::OffsetDateTime;
use x509_parser::{
    certificate::X509Certificate,
    extensions::GeneralName,
    objects::{oid_registry, oid2sn},
    prelude::FromDer,
    public_key::PublicKey,
};

/// The fields of one DER certificate; a certificate that doesn't parse
/// still gets its fingerprints (and "unparseable" as subject).
pub fn certificate_info(der: &[u8]) -> CertificateInfo {
    let fingerprint_sha256 = sha256_fingerprint(der);
    let fingerprint_sha1 = sha1_fingerprint(der);
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return CertificateInfo {
            subject: "(certificate could not be parsed)".into(),
            issuer: String::new(),
            serial: String::new(),
            not_before: OffsetDateTime::UNIX_EPOCH,
            not_after: OffsetDateTime::UNIX_EPOCH,
            subject_alt_names: Vec::new(),
            public_key: String::new(),
            signature_algorithm: String::new(),
            fingerprint_sha256,
            fingerprint_sha1,
        };
    };
    let public_key = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA {}", rsa.key_size()),
        Ok(PublicKey::EC(ec)) => format!("ECDSA {}", ec.key_size()),
        Ok(PublicKey::DSA(_)) => "DSA".into(),
        _ => oid2sn(&cert.public_key().algorithm.algorithm, oid_registry()).map_or_else(
            |_| cert.public_key().algorithm.algorithm.to_id_string(),
            str::to_owned,
        ),
    };
    let signature_algorithm = oid2sn(&cert.signature_algorithm.algorithm, oid_registry())
        .map_or_else(
            |_| cert.signature_algorithm.algorithm.to_id_string(),
            str::to_owned,
        );
    CertificateInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: cert.validity().not_before.to_datetime(),
        not_after: cert.validity().not_after.to_datetime(),
        subject_alt_names: alt_names(&cert),
        public_key,
        signature_algorithm,
        fingerprint_sha256,
        fingerprint_sha1,
    }
}

fn alt_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_owned()),
            GeneralName::IPAddress(bytes) => ip_from_bytes(bytes).map(|ip| ip.to_string()),
            _ => None,
        })
        .collect()
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

/// Whether the certificate names `host`: an IP address must be an IP SAN;
/// a host name must match a DNS SAN (a leading `*.` covers one label), or
/// the subject CN when there are no SANs.
pub fn hostname_matches(info: &CertificateInfo, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return info
            .subject_alt_names
            .iter()
            .any(|n| n.parse::<IpAddr>().ok() == Some(ip));
    }
    let names: Vec<String> = if info.subject_alt_names.is_empty() {
        vec![info.common_name().to_owned()]
    } else {
        info.subject_alt_names.clone()
    };
    names.iter().any(|pattern| name_matches(pattern, &host))
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => pattern == host,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn details_of_a_generated_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["ftp.example.com".into(), "127.0.0.1".into()])
                .unwrap();
        let cert = params.self_signed(&key).unwrap();
        let info = certificate_info(cert.der());
        assert!(info.subject.contains("rcgen") || !info.subject.is_empty());
        assert_eq!(info.subject_alt_names, ["ftp.example.com", "127.0.0.1"]);
        assert!(info.public_key.starts_with("ECDSA"), "{}", info.public_key);
        assert!(!info.signature_algorithm.is_empty());
        assert_eq!(info.fingerprint_sha256.len(), 32 * 3 - 1);
        assert_eq!(info.fingerprint_sha1.len(), 20 * 3 - 1);
        assert!(info.not_before < info.not_after);
        assert!(hostname_matches(&info, "FTP.example.com"));
        assert!(hostname_matches(&info, "127.0.0.1"));
        assert!(!hostname_matches(&info, "other.example.com"));
        assert!(!hostname_matches(&info, "127.0.0.2"));
    }

    #[test]
    fn wildcards_cover_one_label() {
        assert!(name_matches("*.example.com", "ftp.example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(!name_matches("*.example.com", "example.com"));
        assert!(name_matches("Example.com.", "example.com"));
    }

    #[test]
    fn garbage_still_has_fingerprints() {
        let info = certificate_info(b"not a certificate");
        assert!(info.subject.contains("could not be parsed"));
        assert!(!info.fingerprint_sha256.is_empty());
    }
}
