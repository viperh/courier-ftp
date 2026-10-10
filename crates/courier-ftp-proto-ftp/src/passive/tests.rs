//! PASV/EPSV/EPRT parsers, the unroutable table and the PASV address rules.

#![allow(clippy::unwrap_used)]

use proptest::prelude::*;

use super::*;

fn v4(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}

#[test]
fn pasv_parses_standard_reply() {
    assert_eq!(
        parse_pasv("227 Entering Passive Mode (192,0,2,10,195,149)"),
        Ok(v4("192.0.2.10:50069"))
    );
    assert_eq!(
        parse_pasv("Entering Passive Mode (192,0,2,10,195,149)."),
        Ok(v4("192.0.2.10:50069"))
    );
}

#[test]
fn pasv_parses_without_brackets() {
    assert_eq!(
        parse_pasv("227 Entering Passive Mode 10,1,2,3,4,1"),
        Ok(v4("10.1.2.3:1025"))
    );
    assert_eq!(parse_pasv("10,1,2,3,0,1"), Ok(v4("10.1.2.3:1")));
}

#[test]
fn pasv_parses_with_spaces_and_equals_sign() {
    assert_eq!(
        parse_pasv("227 =192,168,1,2,4,1"),
        Ok(v4("192.168.1.2:1025"))
    );
    assert_eq!(
        parse_pasv("227 Entering Passive Mode (192, 168, 1, 2, 4, 1)"),
        Ok(v4("192.168.1.2:1025"))
    );
    assert_eq!(
        parse_pasv("227 Mode (192 ,168 , 1,2,4 ,1)"),
        Ok(v4("192.168.1.2:1025"))
    );
}

#[test]
fn pasv_rejects_value_over_255() {
    assert!(parse_pasv("227 Entering Passive Mode (192,168,1,300,4,1)").is_err());
    assert!(parse_pasv("227 Entering Passive Mode (192,168,1,2,256,1)").is_err());
    assert!(parse_pasv("227 Entering Passive Mode (192,168,1,0002,4,1)").is_err());
    assert!(parse_pasv("227 (99999999999999999999,1,1,1,1,1)").is_err());
}

#[test]
fn pasv_rejects_port_zero() {
    assert!(parse_pasv("227 Entering Passive Mode (192,168,1,2,0,0)").is_err());
}

#[test]
fn pasv_rejects_five_numbers() {
    assert!(parse_pasv("227 Entering Passive Mode (192,168,1,2,4)").is_err());
    assert!(parse_pasv("227 Entering Passive Mode").is_err());
    assert!(parse_pasv("").is_err());
}

#[test]
fn epsv_parses_pipe_delimiter() {
    assert_eq!(
        parse_epsv("229 Entering Extended Passive Mode (|||6446|)"),
        Ok(6446)
    );
    assert_eq!(parse_epsv("Entering Extended Passive Mode (|||1|)."), Ok(1));
    assert_eq!(parse_epsv("(|||65535|)"), Ok(65535));
}

#[test]
fn epsv_parses_other_delimiter() {
    assert_eq!(parse_epsv("229 Extended (!!!50069!)"), Ok(50069));
    assert_eq!(parse_epsv("229 Extended (###50069#)"), Ok(50069));
}

#[test]
fn epsv_rejects_mixed_delimiters() {
    assert!(parse_epsv("229 (|!|6446|)").is_err());
    assert!(parse_epsv("229 (|||6446!)").is_err());
    assert!(parse_epsv("229 (|||6446|").is_err());
    assert!(parse_epsv("229 |||6446|").is_err());
    assert!(parse_epsv("229 (111644461)").is_err());
    assert!(parse_epsv("229 (   6446 )").is_err());
}

#[test]
fn epsv_rejects_port_65536() {
    assert!(parse_epsv("229 (|||65536|)").is_err());
    assert!(parse_epsv("229 (|||0|)").is_err());
    assert!(parse_epsv("229 (|||123456|)").is_err());
    assert!(parse_epsv("229 (||||)").is_err());
}

#[test]
fn unroutable_ranges_table() {
    let unroutable = [
        "0.0.0.0",
        "0.255.1.1",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "127.9.9.9",
        "169.254.1.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "febf::1",
        "::ffff:10.0.0.1",
    ];
    for ip in unroutable {
        assert!(is_unroutable(ip.parse().unwrap()), "{ip} is unroutable");
    }
    let routable = [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.1",
        "126.255.255.255",
        "169.253.1.1",
        "172.15.255.255",
        "172.32.0.1",
        "192.0.2.10",
        "192.169.0.1",
        "198.17.0.1",
        "198.20.0.1",
        "203.0.113.5",
        "239.255.255.255",
        "2001:db8::1",
        "2606:4700::1111",
        "fec0::1",
        "::ffff:8.8.8.8",
    ];
    for ip in routable {
        assert!(!is_unroutable(ip.parse().unwrap()), "{ip} is routable");
    }
}

#[test]
fn pasv_address_rules() {
    let peer: IpAddr = "198.51.100.7".parse().unwrap();
    let same = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(choose_pasv_ip(same, peer, true), (peer, None));
    let private = Ipv4Addr::new(10, 1, 2, 3);
    assert_eq!(
        choose_pasv_ip(private, peer, true),
        (peer, Some(UNROUTABLE_REPLACED))
    );
    assert_eq!(
        choose_pasv_ip(private, peer, false),
        (IpAddr::V4(private), None)
    );
    let foreign = Ipv4Addr::new(203, 0, 113, 9);
    for setting in [true, false] {
        assert_eq!(
            choose_pasv_ip(foreign, peer, setting),
            (peer, Some(DIFFERENT_REPLACED))
        );
    }
    // A private server announcing another private address: the peer wins too.
    let lan_peer: IpAddr = "172.17.0.2".parse().unwrap();
    assert_eq!(
        choose_pasv_ip(Ipv4Addr::new(10, 255, 255, 1), lan_peer, true),
        (lan_peer, Some(UNROUTABLE_REPLACED))
    );
}

#[test]
fn fuzz_body_handles_seeds() {
    for seed in [
        &b"227 Entering Passive Mode (192,168,1,2,195,80)\r\n"[..],
        b"227 =192,168,1,2,4,1\r\n",
        b"229 Entering Extended Passive Mode (|||50000|)\r\n",
        b"|2|::1|21|",
        b"\xff\xfe(((((",
        b"",
    ] {
        fuzz_pasv_epsv(seed);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_pasv_format_parse_roundtrip(
        ip in any::<[u8; 4]>(),
        port in 1u16..,
        prefix in "[a-zA-Z (=.:]{0,30}",
        suffix in "[a-zA-Z ).]{0,30}",
    ) {
        let addr = SocketAddrV4::new(Ipv4Addr::from(ip), port);
        let text = format!("227 {prefix}{}{suffix}", format_port(addr));
        prop_assert_eq!(parse_pasv(&text), Ok(addr));
    }

    #[test]
    fn prop_eprt_roundtrip(
        v4 in any::<[u8; 4]>(),
        v6 in any::<[u16; 8]>(),
        port in 1u16..,
    ) {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), port);
        prop_assert_eq!(parse_eprt(&format_eprt(a)), Ok(a));
        let b = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(v6)), port);
        prop_assert_eq!(parse_eprt(&format_eprt(b)), Ok(b));
    }

    #[test]
    fn prop_epsv_any_delimiter(d in 33u8..=126, port in 1u16..) {
        prop_assume!(!d.is_ascii_digit());
        let d = char::from(d);
        let text = format!("229 Entering Extended Passive Mode ({d}{d}{d}{port}{d})");
        prop_assert_eq!(parse_epsv(&text), Ok(port));
    }

    #[test]
    fn prop_pasv_epsv_never_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        fuzz_pasv_epsv(&data);
    }
}
