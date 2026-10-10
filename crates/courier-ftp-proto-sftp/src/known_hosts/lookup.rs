//! Which entries apply to a host (copied from sverb `known_hosts/lookup.rs`, D13).
//!
//! The **lookup key** is `host` for port 22 and `[host]:port` otherwise (IPv6 literals
//! too: `[::1]:2222`).
//!
//! Host fields follow OpenSSH: a hashed field (`|1|…`) matches when the HMAC of the
//! lookup key with its salt is equal (constant time); otherwise the field is a
//! comma-separated pattern list where `*` matches any run of characters, `?` one
//! character, and a `!pattern` that matches vetoes the whole list. Matching ignores
//! ASCII case, as host names do.

use super::{Marker, OpenSshEntry, hashed};

/// The SSH default port.
const DEFAULT_SSH_PORT: u16 = 22;

/// The entries that apply to a host, by marker (`@cert-authority` lines are dropped:
/// courier-ftp does not offer certificate host-key algorithms).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenSshMatches {
    /// Plain host keys for this host (possibly several, one per key type).
    pub matching: Vec<OpenSshEntry>,
    /// `@revoked` entries whose pattern matches this host.
    pub revoked: Vec<OpenSshEntry>,
}

impl OpenSshMatches {
    /// Nothing applies.
    pub fn is_empty(&self) -> bool {
        self.matching.is_empty() && self.revoked.is_empty()
    }
}

/// `host` for port 22, `[host]:port` otherwise.
pub fn lookup_key(host: &str, port: u16) -> String {
    if port == DEFAULT_SSH_PORT {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// OpenSSH glob: `*` any run (also empty), `?` exactly one character. ASCII case is
/// ignored.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    // Iterative matcher with backtracking to the last `*`.
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some('?') => {
                pi += 1;
                ti += 1;
            }
            Some(c) if *c == t[ti] => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whether the comma-separated pattern list matches `text`: at least one positive
/// pattern matches and no `!negated` one does.
pub fn pattern_list_matches(list: &str, text: &str) -> bool {
    let mut positive = false;
    for pattern in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match pattern.strip_prefix('!') {
            Some(negated) => {
                if glob(negated, text) {
                    return false;
                }
            }
            None => positive |= glob(pattern, text),
        }
    }
    positive
}

/// Whether an entry's host field matches `lookup_key` (hashed or pattern list).
pub fn host_field_matches(field: &str, lookup_key: &str) -> bool {
    if hashed::is_hashed(field) {
        hashed::matches(field, lookup_key)
    } else {
        pattern_list_matches(field, lookup_key)
    }
}

/// The entries that apply to `host:port`.
pub fn lookup(entries: &[OpenSshEntry], host: &str, port: u16) -> OpenSshMatches {
    let key = lookup_key(host, port);
    let mut out = OpenSshMatches::default();
    for entry in entries {
        if !host_field_matches(&entry.host_pattern, &key) {
            continue;
        }
        match entry.marker {
            Marker::None => out.matching.push(entry.clone()),
            Marker::Revoked => out.revoked.push(entry.clone()),
            Marker::CertAuthority => {}
        }
    }
    out
}
