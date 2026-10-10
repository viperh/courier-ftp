//! Property tests: the parser never panics (the `known_hosts_parse` fuzz target's
//! body), and hashed host names match exactly their own lookup key.

use proptest::prelude::*;

use super::{fuzz_known_hosts_parse, hashed};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// AC13.
    #[test]
    fn parse_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..300),
        lines in proptest::collection::vec(
            "(@cert-authority |@revoked |@x )?[|*?!,a-z0-9.\\[\\]:]{0,30} (ssh-ed25519|ssh-rsa|x) [A-Za-z0-9+/=]{0,80}( c)?",
            0..6,
        ),
    ) {
        fuzz_known_hosts_parse(&bytes);
        fuzz_known_hosts_parse(lines.join("\n").as_bytes());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn hash_with_salt_round_trips(
        salt in proptest::array::uniform20(any::<u8>()),
        host in "[a-z0-9.:\\[\\]-]{1,40}",
        other in "[a-z0-9.:\\[\\]-]{1,40}",
    ) {
        let field = hashed::hash_with_salt(&salt, &host);
        prop_assert!(hashed::is_hashed(&field));
        prop_assert!(hashed::matches(&field, &host));
        prop_assert_eq!(hashed::matches(&field, &other), host == other);
    }
}
