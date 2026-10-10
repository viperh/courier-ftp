//! Owner and group names for local listings (Unix uid/gid → names via `uzers`).

use std::collections::HashMap;

/// Caches uid/gid → name lookups for one [`LocalBackend`](super::LocalBackend).
///
/// Unbounded, but keyed by id (a system has few distinct owners). Unknown ids map to
/// the number as text.
#[derive(Debug, Default)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct OwnerCache {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl OwnerCache {
    /// The user name of `uid` (or the number as text).
    #[cfg(unix)]
    pub(crate) fn user(&mut self, uid: u32) -> String {
        self.users
            .entry(uid)
            .or_insert_with(|| {
                uzers::get_user_by_uid(uid).map_or_else(
                    || uid.to_string(),
                    |u| u.name().to_string_lossy().into_owned(),
                )
            })
            .clone()
    }

    /// The group name of `gid` (or the number as text).
    #[cfg(unix)]
    pub(crate) fn group(&mut self, gid: u32) -> String {
        self.groups
            .entry(gid)
            .or_insert_with(|| {
                uzers::get_group_by_gid(gid).map_or_else(
                    || gid.to_string(),
                    |g| g.name().to_string_lossy().into_owned(),
                )
            })
            .clone()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn unknown_ids_are_numbers_and_cached() {
        let mut c = OwnerCache::default();
        let odd = 3_999_999_u32;
        assert_eq!(c.user(odd), odd.to_string());
        assert_eq!(c.group(odd), odd.to_string());
        assert_eq!(c.users.len(), 1);
        assert_eq!(c.user(odd), odd.to_string());
        assert_eq!(c.users.len(), 1);
        assert_eq!(c.user(0), "root");
    }
}
