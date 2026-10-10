//! Natural ("human") string order: digit runs compare by numeric value (`file2` <
//! `file10`), leading zeros break ties (`a1` < `a01` < `a2`).

#[cfg(test)]
use std::cmp::Ordering;

/// Splits off the ASCII digit run at the start of `s`.
fn digit_run(s: &[u8]) -> usize {
    s.iter().take_while(|b| b.is_ascii_digit()).count()
}

/// Natural order of `a` and `b` (callers fold case first when wanted). A total order:
/// only identical strings compare `Equal`. The reference for [`natural_key`], which
/// the sort uses.
#[cfg(test)]
pub(crate) fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    // First difference in leading zeros of equal-valued runs (the tie-breaker).
    let mut zeros_tie = Ordering::Equal;
    while i < ab.len() && j < bb.len() {
        let (da, db) = (digit_run(&ab[i..]), digit_run(&bb[j..]));
        if da > 0 && db > 0 {
            let ra = &ab[i..i + da];
            let rb = &bb[j..j + db];
            let za = ra.iter().take_while(|c| **c == b'0').count();
            let zb = rb.iter().take_while(|c| **c == b'0').count();
            let (va, vb) = (&ra[za..], &rb[zb..]);
            // Equal-length digit strings compare lexicographically as numbers.
            let ord = va.len().cmp(&vb.len()).then_with(|| va.cmp(vb));
            if ord != Ordering::Equal {
                return ord;
            }
            if zeros_tie == Ordering::Equal {
                zeros_tie = za.cmp(&zb);
            }
            i += da;
            j += db;
            continue;
        }
        let (x, y) = (ab[i], bb[j]);
        if x < 0x80 && y < 0x80 {
            // ASCII fast path (at most one of them is a digit here).
            let ord = match (x.is_ascii_digit(), y.is_ascii_digit()) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => x.cmp(&y),
            };
            if ord != Ordering::Equal {
                return ord;
            }
            i += 1;
            j += 1;
            continue;
        }
        // Compare one character (UTF-8 aware: whole chars, by code point).
        let ca = a[i..].chars().next();
        let cb = b[j..].chars().next();
        match (ca, cb) {
            (Some(x), Some(y)) => {
                // A digit sorts before any other character (like the numeric run it starts).
                let ord = match (x.is_ascii_digit(), y.is_ascii_digit()) {
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    _ => x.cmp(&y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
                i += x.len_utf8();
                j += y.len_utf8();
            }
            _ => break,
        }
    }
    (ab.len() - i)
        .cmp(&(bb.len() - j))
        .then(zeros_tie)
        .then_with(|| ab.cmp(bb))
}

/// A byte key whose plain (`memcmp`) order is the natural order of [`natural_cmp`]
/// for names without control characters: each digit run becomes `0x01`, its length
/// without leading zeros (4 bytes) and the digits; after a `0x00` separator come the
/// leading-zero counts (the tie-breaker). Sorting by precomputed keys is much faster
/// than calling [`natural_cmp`] in every comparison.
pub(crate) fn natural_key(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut key = Vec::with_capacity(b.len() + 8);
    let mut zeros: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let run = digit_run(&b[i..]);
        if run == 0 {
            key.push(b[i]);
            i += 1;
            continue;
        }
        let digits = &b[i..i + run];
        let z = digits.iter().take_while(|c| **c == b'0').count();
        let value = &digits[z..];
        key.push(0x01);
        key.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
        key.extend_from_slice(value);
        zeros.extend_from_slice(&u32::try_from(z).unwrap_or(u32::MAX).to_be_bytes());
        i += run;
    }
    key.push(0x00);
    key.extend_from_slice(&zeros);
    key
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn sorted(mut v: Vec<&str>) -> Vec<&str> {
        v.sort_by(|a, b| natural_cmp(a, b));
        v
    }

    #[test]
    fn natural_cmp_orders_numeric_runs() {
        assert_eq!(natural_cmp("file2", "file10"), Ordering::Less);
        assert_eq!(natural_cmp("file10", "file2"), Ordering::Greater);
        assert_eq!(sorted(vec!["a2", "a01", "a1"]), vec!["a1", "a01", "a2"]);
        assert_eq!(natural_cmp("a", "a"), Ordering::Equal);
        assert_eq!(natural_cmp("a", "a1"), Ordering::Less);
        assert_eq!(
            sorted(vec!["été10", "été9", "über", "Ärger", "été"]),
            vec!["Ärger", "été", "été9", "été10", "über"]
        );
        assert_eq!(
            sorted(vec!["x-100", "x-20", "x-3"]),
            vec!["x-3", "x-20", "x-100"]
        );
        assert_eq!(
            natural_cmp("99999999999999999999999", "100000000000000000000000"),
            Ordering::Less
        );
    }

    fn arb() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[a0-9b.é]{0,8}").unwrap_or_else(|e| panic!("{e}"))
    }

    proptest! {
        #[test]
        fn prop_natural_cmp_is_total_order(a in arb(), b in arb(), c in arb()) {
            let ab = natural_cmp(&a, &b);
            prop_assert_eq!(ab, natural_cmp(&b, &a).reverse());
            prop_assert_eq!(ab == Ordering::Equal, a == b);
            // The precomputed key agrees (ties are broken by the bytes later).
            let kab = natural_key(&a).cmp(&natural_key(&b));
            if kab != Ordering::Equal {
                prop_assert_eq!(kab, ab, "{:?} {:?}", a, b);
            }
            if ab != Ordering::Greater && natural_cmp(&b, &c) != Ordering::Greater {
                prop_assert_ne!(natural_cmp(&a, &c), Ordering::Greater);
            }
        }
    }
}
