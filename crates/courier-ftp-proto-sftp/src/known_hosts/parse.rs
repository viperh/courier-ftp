//! The OpenSSH `known_hosts` format (sshd(8) "SSH_KNOWN_HOSTS FILE FORMAT"), copied
//! from sverb `known_hosts/parse.rs` (D13):
//!
//! ```text
//! [@cert-authority|@revoked] host-patterns key-type base64-key [comment]
//! ```
//!
//! Blank lines and `#` comments are skipped. Host fields are pattern lists or hashed
//! (`|1|salt|hash`). Every key type is accepted; a type courier-ftp doesn't know is
//! kept as is with a warning. Lines that cannot be an entry (missing fields, bad
//! base64, a blob of another type, an unknown marker, a malformed hashed field) are
//! skipped with a warning. The input is untrusted: callers cap its size
//! ([`OpenSshKnownHosts`](super::OpenSshKnownHosts)).

use std::path::Path;

use super::{Marker, OpenSshEntry, fingerprint::key_blob, hashed};

/// A line that was skipped or kept with a caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    /// 1-based line number.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
}

/// Key types courier-ftp knows (plain, `sk-*` and their certificates).
pub const KNOWN_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
];

/// The type name at the start of a key blob (an SSH `string`).
pub(crate) fn blob_type(blob: &[u8]) -> Option<&str> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
    let end = 4_usize.checked_add(usize::try_from(len).ok()?)?;
    std::str::from_utf8(blob.get(4..end)?).ok()
}

/// Split off the first whitespace-separated field.
fn field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    Some(match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    })
}

/// The fields of one entry.
struct Line<'a> {
    marker: Marker,
    hosts: &'a str,
    key_type: &'a str,
    key: &'a str,
}

/// Parse one non-comment line: the entry and an optional caveat, or why it was skipped.
fn parse_line(line: &str) -> Result<(Line<'_>, Option<String>), String> {
    let (first, rest) = field(line).ok_or("empty line")?;
    let (marker, hosts, rest) = match first.strip_prefix('@') {
        Some("cert-authority") => {
            let (h, r) = field(rest).ok_or("missing host patterns")?;
            (Marker::CertAuthority, h, r)
        }
        Some("revoked") => {
            let (h, r) = field(rest).ok_or("missing host patterns")?;
            (Marker::Revoked, h, r)
        }
        Some(other) => return Err(format!("unknown marker @{other}")),
        None => (Marker::None, first, rest),
    };
    let (key_type, rest) = field(rest).ok_or("missing key type")?;
    let (key, _comment) = field(rest).ok_or("missing key")?;
    if hashed::is_hashed(hosts) && hashed::decode(hosts).is_none() {
        return Err("malformed hashed host name".to_owned());
    }
    let blob = key_blob(key).ok_or("the key is not valid base64")?;
    match blob_type(&blob) {
        Some(t) if t == key_type => {}
        Some(t) => return Err(format!("key type {key_type} does not match the key ({t})")),
        None => return Err("the key is not an SSH public key".to_owned()),
    }
    let caveat = (!KNOWN_KEY_TYPES.contains(&key_type))
        .then(|| format!("unknown key type {key_type} (kept as is)"));
    Ok((
        Line {
            marker,
            hosts,
            key_type,
            key,
        },
        caveat,
    ))
}

/// Parse a `known_hosts` file read from `source`: the entries and a warning per
/// skipped or caveated line.
pub fn parse_known_hosts(text: &str, source: &Path) -> (Vec<OpenSshEntry>, Vec<ParseWarning>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok((l, caveat)) => {
                if let Some(reason) = caveat {
                    warnings.push(ParseWarning {
                        line: i + 1,
                        reason,
                    });
                }
                entries.push(OpenSshEntry {
                    host_pattern: l.hosts.to_owned(),
                    key_type: l.key_type.to_owned(),
                    public_key: l.key.to_owned(),
                    marker: l.marker,
                    source: source.to_path_buf(),
                    line: i + 1,
                });
            }
            Err(reason) => warnings.push(ParseWarning {
                line: i + 1,
                reason,
            }),
        }
    }
    (entries, warnings)
}
