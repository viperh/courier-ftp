//! EPLF (Easily Parsed LIST Format, D. J. Bernstein).
//!
//! ```text
//! +i8388621.48594,m825718503,r,s280,<TAB>djb.html
//! +i8388621.50690,m824255907,/,<TAB>514
//! ```

use courier_ftp_core::model::{Entry, EntryKind, Permissions, Precision, Timestamp};
use time::OffsetDateTime;

use super::Outcome;

/// One EPLF line. Without a `/` fact the entry is a file.
pub(super) fn parse(line: &str) -> Outcome {
    let Some(facts) = line.strip_prefix('+') else {
        return Outcome::NoMatch;
    };
    let Some((facts, name)) = facts.split_once('\t') else {
        return Outcome::NoMatch;
    };
    let mut dir = false;
    let mut size = None;
    let mut modified = None;
    let mut mode = None;
    for fact in facts.split(',') {
        let Some(first) = fact.chars().next() else {
            continue;
        };
        let value = &fact[first.len_utf8()..];
        match first {
            '/' => dir = true,
            's' => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Outcome::NoMatch;
                }
                match value.parse::<u64>() {
                    Ok(n) => size = Some(n),
                    Err(_) => return Outcome::BadNumber,
                }
            }
            'm' => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Outcome::NoMatch;
                }
                let Ok(secs) = value.parse::<i64>() else {
                    return Outcome::BadNumber;
                };
                let Ok(t) = OffsetDateTime::from_unix_timestamp(secs) else {
                    return Outcome::BadNumber;
                };
                modified = Some(Timestamp::new(t, Precision::Second));
            }
            'u' => {
                if let Some(octal) = value.strip_prefix('p') {
                    if (1..=6).contains(&octal.len())
                        && octal.bytes().all(|b| (b'0'..=b'7').contains(&b))
                    {
                        mode = u32::from_str_radix(octal, 8).ok();
                    }
                }
            }
            // `r` (retrievable), `i` (identifier) and unknown facts.
            _ => {}
        }
    }
    let kind = if dir { EntryKind::Dir } else { EntryKind::File };
    Outcome::Entry(Entry {
        name: name.to_owned(),
        kind,
        size: if dir { None } else { size },
        modified,
        permissions: mode.map(Permissions::from_mode),
        owner: None,
        group: None,
        hidden: name.starts_with('.'),
    })
}
