//! Property tests.
#![allow(clippy::unwrap_used)]

use courier_ftp_server::auth::tokens::{
    RECOVERY_CODE_BYTES, decode_recovery_code, encode_recovery_code, hash_recovery_code,
};
use proptest::prelude::*;

proptest! {
    /// Any 10 bytes → 16 Crockford characters (`XXXX-XXXX-XXXX-XXXX`) → the same
    /// bytes; dashes and lower case are accepted on input.
    #[test]
    fn recovery_code_format_roundtrip(bytes in proptest::array::uniform10(any::<u8>())) {
        let code = encode_recovery_code(&bytes);
        prop_assert_eq!(code.len(), 19);
        let groups: Vec<&str> = code.split('-').collect();
        prop_assert_eq!(groups.len(), 4);
        prop_assert!(groups.iter().all(|g| g.len() == 4));
        prop_assert!(code.chars().all(|c| c == '-' || "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
        let plain = code.replace('-', "");
        prop_assert_eq!(plain.len(), 16);
        for typed in [code.to_string(), plain.clone(), code.to_lowercase(), plain.to_lowercase()] {
            let back = decode_recovery_code(&typed).unwrap();
            prop_assert_eq!(*back, bytes);
            prop_assert_eq!(hash_recovery_code(&typed), hash_recovery_code(&code));
        }
        prop_assert_eq!(RECOVERY_CODE_BYTES, 10);
    }

    /// Garbage never decodes to a code of the wrong length.
    #[test]
    fn recovery_code_rejects_wrong_lengths(s in "[0-9A-Z]{0,15}|[0-9A-Z]{17,24}") {
        prop_assert!(decode_recovery_code(&s).is_none());
    }
}
