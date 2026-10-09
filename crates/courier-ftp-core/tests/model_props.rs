//! Property tests for the T02 domain model (AC2, AC6, AC9).

use std::net::{Ipv4Addr, Ipv6Addr};

use courier_ftp_core::model::server::fuzz_url_parse;
use courier_ftp_core::model::{
    FtpEncryption, ParsedUrl, Permissions, Protocol, RemotePath, ServerAddress, UrlOptions,
};
use courier_ftp_core::secret::SecretString;
use proptest::prelude::*;

/// Random strings biased towards path/URL syntax.
fn messy_string() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[/.a-z:@%\\[\\]0-9 \\\\\u{0}-\u{1f}ä]{0,40}",
        "(sftp|ftp|ftpes|ftps|SFTP|http)://[a-z@:%/\\[\\]0-9.]{0,30}",
    ]
}

fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z][a-zA-Z0-9-]{0,15}(\\.[a-z]{2,6}){0,2}",
        any::<[u8; 4]>().prop_map(|o| Ipv4Addr::from(o).to_string()),
        any::<[u16; 8]>().prop_map(|s| Ipv6Addr::from(s).to_string()),
    ]
}

fn address() -> impl Strategy<Value = ServerAddress> {
    let protocol = prop_oneof![Just(Protocol::Ftp), Just(Protocol::Sftp)];
    let encryption = prop_oneof![
        Just(FtpEncryption::ExplicitIfAvailable),
        Just(FtpEncryption::RequireExplicit),
        Just(FtpEncryption::RequireImplicit),
    ];
    let port = proptest::option::of(1_u16..);
    let user = proptest::option::of("[a-zA-Z0-9@:/%?# ._ä€-]{1,12}");
    (protocol, encryption, host(), port, user).prop_map(|(p, e, h, port, user)| {
        ServerAddress::new(p, e, h, port, user).unwrap_or_else(|e| panic!("generator: {e}"))
    })
}

fn path() -> impl Strategy<Value = RemotePath> {
    proptest::collection::vec("[^/\u{0}]{1,8}", 0..5).prop_filter_map("no . or ..", |cs| {
        if cs.iter().any(|c| c == "." || c == "..") {
            return None;
        }
        RemotePath::root()
            .join_all(cs.iter().map(String::as_str))
            .ok()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn prop_remote_path_parse_never_panics_and_is_normalised(s in messy_string()) {
        if let Ok(p) = RemotePath::parse(&s) {
            let raw = p.as_str();
            prop_assert!(raw.starts_with('/'));
            prop_assert!(raw == "/" || !raw.ends_with('/'));
            prop_assert!(!raw.contains('\0'));
            prop_assert!(raw.len() <= 4096);
            prop_assert!(p.components().all(|c| !c.is_empty() && c != "." && c != ".."));
            prop_assert_eq!(RemotePath::parse(raw).ok(), Some(p.clone()));
            prop_assert_eq!(RemotePath::root().resolve(&s).ok(), Some(p));
        }
    }

    #[test]
    fn prop_url_parse_never_panics(s in messy_string()) {
        fuzz_url_parse(s.as_bytes());
    }

    #[test]
    fn prop_url_parse_never_panics_on_bytes(b in proptest::collection::vec(any::<u8>(), 0..64)) {
        fuzz_url_parse(&b);
    }

    #[test]
    fn prop_rwx_parse_never_panics(s in prop_oneof![any::<String>(), "[-rwxsStTdl+.@]{8,12}"]) {
        if let Ok(p) = Permissions::from_rwx_string(&s) {
            let mode = p.mode.unwrap_or(u32::MAX);
            prop_assert!(mode <= 0o7777);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_url_roundtrip(
        a in address(),
        pw in proptest::option::of("[ -~ä]{0,12}"),
        p in proptest::option::of(path()),
        force_port in any::<bool>(),
    ) {
        let secret = pw.as_deref().map(SecretString::from);
        let opts = UrlOptions { password: secret.as_ref(), path: p.as_ref(), force_port };
        let url = a.to_url(&opts);
        let parsed = ParsedUrl::parse(&url).unwrap_or_else(|e| panic!("{url:?}: {e}"));
        let mut want = a.clone();
        if force_port && want.port.is_none() {
            want.port = Some(want.default_port());
        }
        prop_assert_eq!(&parsed.address, &want, "{}", url);
        prop_assert_eq!(parsed.password.as_ref().map(|s| s.expose().to_owned()), pw, "{}", url);
        prop_assert_eq!(parsed.path, p, "{}", url);
        if !force_port {
            prop_assert_eq!(a.to_string().parse::<ServerAddress>().ok(), Some(a));
        }
    }
}
