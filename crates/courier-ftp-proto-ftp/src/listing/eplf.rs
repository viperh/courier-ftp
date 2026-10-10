//! EPLF (Easily Parsed LIST Format): `+i8388621.48594,m825718503,r,s280,\tname`.

use courier_ftp_core::model::{Entry, EntryKind, Permissions, Precision, Timestamp};
use time::OffsetDateTime;

pub(super) fn parse_line(line: &str) -> Option<Entry> {
    let body = line.strip_prefix('+')?;
    let (facts, name) = body.split_once('\t')?;
    if name.is_empty() {
        return None;
    }
    let mut kind = EntryKind::File;
    let mut size = None;
    let mut modified = None;
    let mut permissions = None;
    for fact in facts.split(',') {
        let mut chars = fact.chars();
        match chars.next() {
            Some('/') => kind = EntryKind::Dir,
            Some('s') => size = Some(chars.as_str().parse::<u64>().ok()?),
            Some('m') => {
                let secs = chars.as_str().parse::<i64>().ok()?;
                let t = OffsetDateTime::from_unix_timestamp(secs).ok()?;
                modified = Some(Timestamp::new(t, Precision::Second));
            }
            Some('u') => {
                if let Some(octal) = chars.as_str().strip_prefix('p') {
                    let bits = u32::from_str_radix(octal, 8)
                        .ok()
                        .filter(|m| *m <= 0o7777)?;
                    permissions = Some(Permissions::from_mode(bits));
                }
            }
            // `r` (retrievable), `i` (unique id) and unknown facts.
            _ => {}
        }
    }
    let mut entry = Entry::new(name, kind);
    entry.size = size;
    entry.modified = modified;
    entry.permissions = permissions;
    entry.raw = Some(line.to_owned());
    Some(entry)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn eplf() {
        let e = parse_line("+i8388621.48594,m825718503,r,s280,\tdjb.html").unwrap();
        assert_eq!((e.name.as_str(), e.size), ("djb.html", Some(280)));
        assert_eq!(e.modified.unwrap().time, datetime!(1996-03-01 22:15:03 UTC));
        let e = parse_line("+i8388621.50690,m824255907,/,\t514").unwrap();
        assert_eq!(e.kind, EntryKind::Dir);
        let e = parse_line("+up644,r,\t has space").unwrap();
        assert_eq!(e.name, " has space");
        assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o644));
        assert!(parse_line("+r,s280, no tab").is_none());
        assert!(parse_line("+r,sx,\tbad size").is_none());
    }
}
