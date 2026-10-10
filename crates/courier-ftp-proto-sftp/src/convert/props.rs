use proptest::prelude::*;
use russh_sftp::protocol::FileAttributes;

use super::entry_from_name;

fn attrs() -> impl Strategy<Value = FileAttributes> {
    (
        proptest::option::of(any::<u64>()),
        proptest::option::of(any::<u32>()),
        proptest::option::of(any::<u32>()),
        proptest::option::of(any::<u32>()),
        proptest::option::of(any::<u32>()),
    )
        .prop_map(|(size, uid, gid, permissions, mtime)| FileAttributes {
            size,
            uid,
            gid,
            permissions,
            mtime,
            ..FileAttributes::default()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn entry_from_name_never_panics(name in any::<String>(), long in any::<String>(), a in attrs()) {
        if let Some(e) = entry_from_name(&name, &long, &a) {
            prop_assert_eq!(e.name, name);
        }
    }

    #[test]
    fn entry_from_name_ls_like_longnames(
        name in "[a-z.]{1,12}",
        owner in "[a-z]{1,8}",
        size in any::<u64>(),
        a in attrs(),
    ) {
        let long = format!("-rw-r--r-- 1 {owner} grp {size} Jan  1 12:00 {name}");
        let _ = entry_from_name(&name, &long, &a);
    }
}
