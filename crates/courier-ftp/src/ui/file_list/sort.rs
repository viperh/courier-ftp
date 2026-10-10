//! Sorting file list entries.

use std::cmp::Ordering;

use courier_ftp_core::model::Entry;

/// What the list is sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortKey {
    Name,
    Size,
    Modified,
    Permissions,
    Owner,
}

/// How entries are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SortOrder {
    pub(crate) key: SortKey,
    pub(crate) descending: bool,
    pub(crate) dirs_first: bool,
    pub(crate) case_sensitive: bool,
    pub(crate) natural: bool,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self {
            key: SortKey::Name,
            descending: false,
            dirs_first: true,
            case_sensitive: false,
            natural: true,
        }
    }
}

impl SortOrder {
    /// Sort by `key`; picking the current key again reverses the order.
    pub(crate) fn by(&mut self, key: SortKey) {
        if self.key == key {
            self.descending = !self.descending;
        } else {
            self.key = key;
            self.descending = false;
        }
    }

    pub(crate) fn compare(&self, a: &Entry, b: &Entry) -> Ordering {
        if self.dirs_first {
            // Directories stay on top in both directions, as in FileZilla.
            match (a.is_dir_like(), b.is_dir_like()) {
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                _ => {}
            }
        }
        let by_name = || self.compare_names(&a.name, &b.name);
        let primary = match self.key {
            SortKey::Name => by_name(),
            SortKey::Size => a.size.cmp(&b.size),
            SortKey::Modified => match (&a.modified, &b.modified) {
                (Some(x), Some(y)) => x.cmp_coarse(y),
                (x, y) => x.is_some().cmp(&y.is_some()),
            },
            SortKey::Permissions => a
                .permissions
                .as_ref()
                .map(ToString::to_string)
                .cmp(&b.permissions.as_ref().map(ToString::to_string)),
            SortKey::Owner => (&a.owner, &a.group).cmp(&(&b.owner, &b.group)),
        };
        let ordered = primary.then_with(by_name);
        if self.descending {
            ordered.reverse()
        } else {
            ordered
        }
    }

    fn compare_names(&self, a: &str, b: &str) -> Ordering {
        let (fa, fb) = if self.case_sensitive {
            (a.to_owned(), b.to_owned())
        } else {
            (a.to_lowercase(), b.to_lowercase())
        };
        let ord = if self.natural {
            natural_cmp(&fa, &fb)
        } else {
            fa.cmp(&fb)
        };
        // A total order even when case-folding makes names equal: `B` < `b`.
        ord.then_with(|| a.cmp(b))
    }
}

/// Compare with runs of digits as numbers: `file2` < `file10`.
pub(crate) fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut a = a.chars().peekable();
    let mut b = b.chars().peekable();
    loop {
        match (a.peek(), b.peek()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let take = |it: &mut std::iter::Peekable<std::str::Chars>| {
                    let mut s = String::new();
                    while let Some(c) = it.peek().filter(|c| c.is_ascii_digit()) {
                        s.push(*c);
                        it.next();
                    }
                    s
                };
                let (na, nb) = (take(&mut a), take(&mut b));
                let (ta, tb) = (na.trim_start_matches('0'), nb.trim_start_matches('0'));
                let ord = ta
                    .len()
                    .cmp(&tb.len())
                    .then_with(|| ta.cmp(tb))
                    .then_with(|| na.len().cmp(&nb.len()));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(x), Some(y)) => {
                let ord = x.cmp(y);
                if ord != Ordering::Equal {
                    return ord;
                }
                a.next();
                b.next();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn sorted(order: &SortOrder, entries: &mut [Entry]) -> Vec<String> {
        entries.sort_by(|a, b| order.compare(a, b));
        entries.iter().map(|e| e.name.clone()).collect()
    }

    #[test]
    fn natural_order() {
        let mut names = vec!["file10", "file2", "file1", "File3", "file02", "a", "file"];
        names.sort_by(|a, b| natural_cmp(&a.to_lowercase(), &b.to_lowercase()));
        assert_eq!(
            names,
            ["a", "file", "file1", "file2", "file02", "File3", "file10"]
        );
        assert_eq!(natural_cmp("x9", "x10"), Ordering::Less);
        assert_eq!(natural_cmp("v1.10", "v1.9"), Ordering::Greater);
        assert_eq!(
            natural_cmp("99999999999999999999a", "99999999999999999999b"),
            Ordering::Less
        );
    }

    #[test]
    fn dirs_first_and_reversal() {
        let mut e = vec![
            Entry::file("b.txt", 1),
            Entry::dir("zeta"),
            Entry::file("a.txt", 300),
            Entry::dir("alpha"),
        ];
        let mut order = SortOrder::default();
        assert_eq!(sorted(&order, &mut e), ["alpha", "zeta", "a.txt", "b.txt"]);
        order.by(SortKey::Name);
        assert!(order.descending);
        assert_eq!(sorted(&order, &mut e), ["zeta", "alpha", "b.txt", "a.txt"]);
        order.by(SortKey::Size);
        assert!(!order.descending);
        assert_eq!(sorted(&order, &mut e), ["alpha", "zeta", "b.txt", "a.txt"]);
        order.dirs_first = false;
        order.by(SortKey::Name);
        assert_eq!(sorted(&order, &mut e), ["a.txt", "alpha", "b.txt", "zeta"]);
    }

    #[test]
    fn case_sensitivity() {
        let mut e = vec![
            Entry::file("b", 1),
            Entry::file("B", 1),
            Entry::file("a", 1),
        ];
        let mut order = SortOrder::default();
        assert_eq!(sorted(&order, &mut e), ["a", "B", "b"]);
        order.case_sensitive = true;
        assert_eq!(sorted(&order, &mut e), ["B", "a", "b"]);
    }

    #[test]
    fn plain_order_without_natural_sort() {
        let mut e = vec![Entry::file("file10", 1), Entry::file("file2", 1)];
        let order = SortOrder {
            natural: false,
            ..SortOrder::default()
        };
        assert_eq!(sorted(&order, &mut e), ["file10", "file2"]);
    }
}
