//! Read-only OpenSSH `known_hosts` import.
//!
//! Keys in the user's `~/.ssh/known_hosts` and the system's
//! `/etc/ssh/ssh_known_hosts` are trusted as if the user had accepted them
//! here. Supported: plain host patterns (comma-separated, `*` and `?`
//! wildcards, `!` negation), `[host]:port` for ports other than 22, hashed
//! hosts (`|1|salt|hash`, HMAC-SHA1 of the host name), comments, and the
//! `@revoked` marker (the key is refused for those hosts without asking).
//! `@cert-authority` lines are ignored (host certificates are not
//! supported) and logged. Invalid lines are skipped with a warning.
//!
//! These files are never written: keys the user accepts go to the
//! [`HostKeyStore`](super::HostKeyStore).

use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use super::HostKey;

/// The `known_hosts` files OpenSSH reads, given the user's home directory:
/// `~/.ssh/known_hosts`, `~/.ssh/known_hosts2` and, on Unix,
/// `/etc/ssh/ssh_known_hosts` and `/etc/ssh/ssh_known_hosts2`. Missing files
/// are fine ([`KnownHosts::load`] skips them).
pub fn default_paths(home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = home {
        let ssh = home.join(".ssh");
        paths.push(ssh.join("known_hosts"));
        paths.push(ssh.join("known_hosts2"));
    }
    if cfg!(unix) {
        paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
        paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts2"));
    }
    paths
}

/// The hashed host field (`|1|salt|hash`) `ssh-keygen -H` writes for
/// `name` (`host`, or `[host]:port` for other ports than 22) with `salt`.
pub fn hash_host_name(name: &str, salt: &[u8]) -> String {
    let hash = match <Hmac<Sha1> as KeyInit>::new_from_slice(salt) {
        Ok(mut mac) => {
            mac.update(name.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    };
    format!(
        "|1|{}|{}",
        Base64::encode_string(salt),
        Base64::encode_string(&hash)
    )
}

/// A line's marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    /// A trusted key.
    None,
    /// `@revoked`: never accept this key.
    Revoked,
}

/// Which hosts a line is for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Hosts {
    /// `host1,[host2]:2222,*.example.com,!bad.example.com`.
    Patterns(Vec<String>),
    /// `|1|base64 salt|base64 HMAC-SHA1(salt, host)`.
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

impl Hosts {
    /// Whether the line is for one of `names` (the lookup names of one
    /// host, see [`lookup_names`]).
    fn matches(&self, names: &[String]) -> bool {
        match self {
            Hosts::Hashed { salt, hash } => names.iter().any(|name| {
                let Ok(mut mac) = <Hmac<Sha1> as KeyInit>::new_from_slice(salt) else {
                    return false;
                };
                mac.update(name.as_bytes());
                mac.verify_slice(hash).is_ok()
            }),
            Hosts::Patterns(patterns) => {
                let mut found = false;
                for pattern in patterns {
                    let (negated, pattern) = match pattern.strip_prefix('!') {
                        Some(p) => (true, p),
                        None => (false, pattern.as_str()),
                    };
                    if names.iter().any(|name| wildcard_match(pattern, name)) {
                        if negated {
                            return false;
                        }
                        found = true;
                    }
                }
                found
            }
        }
    }
}

/// One usable line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    marker: Marker,
    hosts: Hosts,
    key: HostKey,
}

/// What `known_hosts` says about one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHostsMatch {
    /// Keys trusted for the host.
    pub trusted: Vec<HostKey>,
    /// Keys revoked for the host (`@revoked`).
    pub revoked: Vec<HostKey>,
}

/// The usable entries of one or more `known_hosts` files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
    entries: Vec<Entry>,
    /// Lines skipped: invalid ones and `@cert-authority`.
    skipped: usize,
}

impl KnownHosts {
    /// Parse `text`; `source` names it in log messages (a path).
    pub fn parse(text: &str, source: &str) -> Self {
        let mut out = Self::default();
        out.add(text, source);
        out
    }

    /// Read every file of `paths` that exists (see [`default_paths`]). A
    /// file that can't be read is logged and skipped.
    pub fn load(paths: &[PathBuf]) -> Self {
        let mut out = Self::default();
        for path in paths {
            match std::fs::read(path) {
                Ok(bytes) => out.add(
                    &String::from_utf8_lossy(&bytes),
                    &path.display().to_string(),
                ),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    // Paths only at debug: they contain the user name (T91 §4).
                    tracing::warn!(%err, "can't read a known_hosts file");
                    tracing::debug!(path = %path.display(), %err, "can't read known_hosts");
                }
            }
        }
        out
    }

    fn add(&mut self, text: &str, source: &str) {
        for (index, line) in text.lines().enumerate() {
            match parse_line(line) {
                Ok(Some(entry)) => self.entries.push(entry),
                Ok(None) => {}
                Err(problem) => {
                    self.skipped += 1;
                    let line_no = index + 1;
                    // The file path only at debug (T91 §4).
                    tracing::debug!(%source, line_no, "known_hosts: {problem}");
                    if problem == CERT_AUTHORITY {
                        tracing::info!(line_no, "known_hosts: {problem}");
                    } else {
                        tracing::warn!(line_no, "known_hosts: skipping line: {problem}");
                    }
                }
            }
        }
    }

    /// The number of usable entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no usable entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of lines skipped (invalid or `@cert-authority`).
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// The trusted and revoked keys for `host` (a name or an IP address,
    /// without brackets) on `port`.
    pub fn lookup(&self, host: &str, port: u16) -> KnownHostsMatch {
        let names = lookup_names(host, port);
        let mut out = KnownHostsMatch::default();
        for entry in self.entries.iter().filter(|e| e.hosts.matches(&names)) {
            let list = match entry.marker {
                Marker::None => &mut out.trusted,
                Marker::Revoked => &mut out.revoked,
            };
            if !list.contains(&entry.key) {
                list.push(entry.key.clone());
            }
        }
        out
    }
}

const CERT_AUTHORITY: &str = "@cert-authority line ignored (host certificates are not supported)";

/// Names `known_hosts` may use for `host:port`: `host` for port 22,
/// `[host]:port` otherwise (and also `[host]:22`, which some tools write).
fn lookup_names(host: &str, port: u16) -> Vec<String> {
    let host = super::normalize_host(host);
    let bracketed = format!("[{host}]:{port}");
    if port == 22 {
        vec![host, bracketed]
    } else {
        vec![bracketed]
    }
}

/// `Ok(None)` for blank lines and comments, `Err(why)` for lines skipped.
fn parse_line(line: &str) -> Result<Option<Entry>, &'static str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut fields = line.split_whitespace();
    let mut first = fields.next().ok_or("empty line")?;
    let marker = match first {
        "@revoked" => Marker::Revoked,
        "@cert-authority" => return Err(CERT_AUTHORITY),
        m if m.starts_with('@') => return Err("unknown marker"),
        _ => Marker::None,
    };
    if marker != Marker::None {
        first = fields.next().ok_or("no host field")?;
    }
    let hosts = parse_hosts(first)?;
    let key_type = fields.next().ok_or("no key type")?;
    let base64 = fields.next().ok_or("no key")?;
    let key = HostKey::from_openssh(key_type, base64).map_err(|_| "invalid key")?;
    Ok(Some(Entry { marker, hosts, key }))
}

fn parse_hosts(field: &str) -> Result<Hosts, &'static str> {
    if let Some(rest) = field.strip_prefix("|1|") {
        let (salt, hash) = rest.split_once('|').ok_or("invalid hashed host")?;
        let salt = Base64::decode_vec(salt).map_err(|_| "invalid hashed host salt")?;
        let hash = Base64::decode_vec(hash).map_err(|_| "invalid hashed host hash")?;
        if hash.len() != 20 {
            return Err("invalid hashed host hash");
        }
        return Ok(Hosts::Hashed { salt, hash });
    }
    if field.starts_with('|') {
        return Err("unsupported host hash");
    }
    let patterns: Vec<String> = field
        .split(',')
        .filter(|p| !p.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if patterns.is_empty() {
        return Err("no host patterns");
    }
    Ok(Hosts::Patterns(patterns))
}

/// `*` (any run) and `?` (one character) matching, ASCII case-insensitive.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(&c) if c == '?' || c == t[ti] => {
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
    p[pi..].iter().all(|&c| c == '*')
}

/// Fuzz body (T91 §7, cargo-fuzz target `known_hosts_parse`): parse hostile
/// `known_hosts` text and match every entry against fixed hosts (plain,
/// bracketed with a port, IPv6; hashed entries and globs run their matchers).
/// Must never panic.
#[doc(hidden)]
pub fn fuzz_known_hosts(data: &[u8]) {
    let parsed = KnownHosts::parse(&String::from_utf8_lossy(data), "fuzz");
    for (host, port) in [("host.example", 22), ("host.example", 2222), ("::1", 22)] {
        let found = parsed.lookup(host, port);
        assert!(found.trusted.len() + found.revoked.len() <= parsed.len());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::trust::host_key::tests::ed25519;

    fn line(hosts: &str, key: &HostKey) -> String {
        format!("{hosts} {} {} comment", key.algorithm(), key.to_base64())
    }

    #[test]
    fn plain_entries_match_by_name_case_insensitively() {
        let k = ed25519(1);
        let kh = KnownHosts::parse(&line("Example.COM,10.0.0.1", &k), "t");
        assert_eq!(kh.len(), 1);
        assert_eq!(kh.lookup("example.com", 22).trusted, vec![k.clone()]);
        assert_eq!(kh.lookup("EXAMPLE.com", 22).trusted, vec![k.clone()]);
        assert_eq!(kh.lookup("10.0.0.1", 22).trusted, vec![k]);
        assert!(kh.lookup("example.com", 2222).trusted.is_empty());
        assert!(kh.lookup("other.com", 22).trusted.is_empty());
    }

    #[test]
    fn bracketed_port_entries_match_only_that_port() {
        let k = ed25519(2);
        let kh = KnownHosts::parse(
            &format!(
                "{}\n{}",
                line("[example.com]:2222", &k),
                line("[::1]:2200", &k)
            ),
            "t",
        );
        assert_eq!(kh.lookup("example.com", 2222).trusted, vec![k.clone()]);
        assert!(kh.lookup("example.com", 22).trusted.is_empty());
        assert!(kh.lookup("example.com", 2223).trusted.is_empty());
        assert_eq!(kh.lookup("::1", 2200).trusted, vec![k.clone()]);
        assert_eq!(kh.lookup("[::1]", 2200).trusted, vec![k]);
    }

    #[test]
    fn bracketed_port_22_is_accepted_too() {
        let k = ed25519(2);
        let kh = KnownHosts::parse(&line("[example.com]:22", &k), "t");
        assert_eq!(kh.lookup("example.com", 22).trusted, vec![k]);
    }

    #[test]
    fn hashed_entries_match() {
        let k = ed25519(3);
        let text = format!(
            "{}\n{}",
            line(&hash_host_name("example.com", b"0123456789abcdefghij"), &k),
            line(
                &hash_host_name("[example.org]:2222", b"salt-salt-salt-salt!"),
                &k
            ),
        );
        let kh = KnownHosts::parse(&text, "t");
        assert_eq!(kh.len(), 2);
        assert_eq!(kh.lookup("example.com", 22).trusted, vec![k.clone()]);
        assert_eq!(kh.lookup("Example.Com", 22).trusted, vec![k.clone()]);
        assert_eq!(kh.lookup("example.org", 2222).trusted, vec![k]);
        assert!(kh.lookup("example.org", 22).trusted.is_empty());
        assert!(kh.lookup("example.net", 22).trusted.is_empty());
    }

    #[test]
    fn hashed_entries_from_ssh_keygen_match() {
        // `ssh-keygen -H` (OpenSSH) of `example.com …` and
        // `[example.org]:2222 …` with the key `ed25519(7)`.
        let text = "\
|1|xDGwV2qbK9smCCbs34dpT+mzRpY=|2Ade274v6cgbK0+MjDgndoQ0Gmw= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH
|1|f8KnoEWZIclbK/diCbRvn71+fK8=|Ngy0rd4gaO45oTSg3HjXc3SJX5c= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH
";
        let kh = KnownHosts::parse(text, "t");
        assert_eq!(kh.lookup("example.com", 22).trusted, vec![ed25519(7)]);
        assert_eq!(kh.lookup("example.org", 2222).trusted, vec![ed25519(7)]);
        assert!(kh.lookup("example.org", 22).trusted.is_empty());
    }

    #[test]
    fn hashed_field_matches_an_independent_hmac() {
        // Python: hmac.new(bytes([7]) * 20, b"example.com", "sha1").
        assert_eq!(
            hash_host_name("example.com", &[7u8; 20]),
            "|1|BwcHBwcHBwcHBwcHBwcHBwcHBwc=|ZWjLYZwlwAPs+eLV9RGWMCSBPXI="
        );
    }

    #[test]
    fn comments_blank_and_invalid_lines_are_skipped() {
        let k = ed25519(4);
        let text = format!(
            "# a comment\n\n   \n{}\nhost-only\nhost ssh-ed25519\nhost ssh-rsa {}\nhost 1024 35 12345\n|2|x|y {} {}\n@weird host {} {}\n",
            line("good.example", &k),
            k.to_base64(),
            k.algorithm(),
            k.to_base64(),
            k.algorithm(),
            k.to_base64(),
        );
        let kh = KnownHosts::parse(&text, "t");
        assert_eq!(kh.len(), 1);
        assert_eq!(kh.skipped(), 6);
        assert_eq!(kh.lookup("good.example", 22).trusted, vec![k]);
    }

    #[test]
    fn revoked_keys_are_reported_separately() {
        let good = ed25519(5);
        let bad = ed25519(6);
        let text = format!(
            "{}\n@revoked {}\n",
            line("example.com", &good),
            line("*", &bad)
        );
        let kh = KnownHosts::parse(&text, "t");
        let m = kh.lookup("example.com", 22);
        assert_eq!(m.trusted, vec![good]);
        assert_eq!(m.revoked, vec![bad.clone()]);
        assert_eq!(kh.lookup("any.host", 2222).revoked, vec![bad]);
    }

    #[test]
    fn cert_authority_lines_are_ignored() {
        let k = ed25519(7);
        let kh = KnownHosts::parse(
            &format!("@cert-authority {}", line("*.example.com", &k)),
            "t",
        );
        assert!(kh.is_empty());
        assert_eq!(kh.skipped(), 1);
        assert_eq!(kh.lookup("a.example.com", 22), KnownHostsMatch::default());
    }

    #[test]
    fn wildcards_and_negation() {
        let k = ed25519(8);
        let kh = KnownHosts::parse(&line("*.example.com,!bad.example.com,host?", &k), "t");
        assert_eq!(kh.lookup("a.example.com", 22).trusted.len(), 1);
        assert!(kh.lookup("bad.example.com", 22).trusted.is_empty());
        assert_eq!(kh.lookup("host1", 22).trusted.len(), 1);
        assert!(kh.lookup("host12", 22).trusted.is_empty());
        assert!(kh.lookup("example.com", 22).trusted.is_empty());
    }

    #[test]
    fn wildcard_matcher() {
        for (p, t, want) in [
            ("*", "anything", true),
            ("*", "", true),
            ("a*c", "abbbc", true),
            ("a*c", "abbbd", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*.x.*", "a.x.b", true),
            ("[h]:22", "[h]:22", true),
            ("abc", "abcd", false),
        ] {
            assert_eq!(wildcard_match(p, t), want, "{p} vs {t}");
        }
    }

    #[test]
    fn several_files_load_and_missing_ones_are_fine() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, line("one", &ed25519(1))).unwrap();
        std::fs::write(&b, line("two", &ed25519(2))).unwrap();
        let kh = KnownHosts::load(&[a, dir.path().join("missing"), b]);
        assert_eq!(kh.len(), 2);
        assert_eq!(kh.lookup("two", 22).trusted, vec![ed25519(2)]);
    }

    #[test]
    fn default_paths_follow_openssh() {
        let paths = default_paths(Some(Path::new("/home/u")));
        assert_eq!(paths[0], PathBuf::from("/home/u/.ssh/known_hosts"));
        assert_eq!(paths[1], PathBuf::from("/home/u/.ssh/known_hosts2"));
        #[cfg(unix)]
        assert!(paths.contains(&PathBuf::from("/etc/ssh/ssh_known_hosts")));
        assert!(!default_paths(None).iter().any(|p| p.starts_with("/home")));
    }

    #[test]
    fn fuzz_known_hosts_seeds() {
        let key = ed25519(1);
        for text in [
            line("host.example", &key),
            line("[host.example]:2222,*.example,!bad.example", &key),
            format!("@revoked {}", line("h?st.*", &key)),
            format!("|1|{}|{} ", "AAAA", "BBBB"),
            "@cert-authority * ssh-ed25519 AAAA".to_owned(),
            "\u{0}\u{1b}[31m ssh-rsa !!!".to_owned(),
        ] {
            fuzz_known_hosts(text.as_bytes());
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            ..proptest::prelude::ProptestConfig::default()
        })]

        // The `known_hosts_parse` fuzz body (T91 §7).
        #[test]
        fn fuzz_known_hosts_never_panics(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            fuzz_known_hosts(&data);
        }

        #[test]
        fn fuzz_known_hosts_line_like_never_panics(
            text in "(@revoked |@cert-authority |\\|1\\||\\[|\\]:|[0-9]{1,5}|host|\\.example|\\*|\\?|!|,| |ssh-ed25519 |ssh-rsa |AAAA|[A-Za-z0-9+/=]{1,8}|\n){0,30}",
        ) {
            fuzz_known_hosts(text.as_bytes());
        }
    }
}
