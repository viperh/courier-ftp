//! `FEAT` (RFC 2389) reply parsing into [`Features`].

use std::collections::BTreeMap;

use super::reply::Reply;

/// What the server announced in its `FEAT` reply.
///
/// A server without `FEAT` (`500`/`502`) gets [`Features::default`]: nothing
/// announced, and every later decision falls back to trying the plain RFC 959
/// command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Features {
    /// The server answered `FEAT` with `211` (even with an empty list).
    pub feat_supported: bool,
    /// `MLSD` directory listings (RFC 3659). Set by `MLST` or `MLSD`: RFC
    /// 3659 servers announce only `MLST` but implement both.
    pub mlsd: bool,
    /// `MLST` with its facts parameter (`type*;size*;modify*;`), when listed.
    pub mlst: Option<String>,
    /// `SIZE` (RFC 3659).
    pub size: bool,
    /// `MDTM` (RFC 3659).
    pub mdtm: bool,
    /// `MFMT`: set a file's modification time (draft-somers-ftp-mfxx).
    pub mfmt: bool,
    /// `MFCT`: set a file's creation time.
    pub mfct: bool,
    /// `MFF`: set facts, with its facts parameter.
    pub mff: Option<String>,
    /// `REST STREAM` (RFC 3659): resume with `REST n` in stream mode.
    pub rest_stream: bool,
    /// `UTF8` (RFC 2640): file names are UTF-8.
    pub utf8: bool,
    /// `EPSV` (RFC 2428).
    pub epsv: bool,
    /// `EPRT` (RFC 2428).
    pub eprt: bool,
    /// `CLNT`: the client may announce its name.
    pub clnt: bool,
    /// `TVFS` (RFC 3659): `/`-separated paths.
    pub tvfs: bool,
    /// `MODE Z`: zlib-compressed data connections.
    pub mode_z: bool,
    /// The mechanisms of `AUTH` (RFC 4217), upper-cased: `["TLS", "SSL"]`.
    pub auth: Vec<String>,
    /// `PBSZ` (RFC 4217).
    pub pbsz: bool,
    /// `PROT` (RFC 4217).
    pub prot: bool,
    /// `HOST` (RFC 7151): virtual hosts.
    pub host: bool,
    /// `LANG` (RFC 2640) with its language list.
    pub lang: Option<String>,
    /// Every feature line: upper-cased name → parameters (trimmed, may be
    /// empty). Lets later code check features this struct has no field for.
    pub raw: BTreeMap<String, String>,
}

impl Features {
    /// Parse a `211` `FEAT` reply. Any other code gives the defaults (with
    /// `feat_supported` false).
    ///
    /// Each line between the first and the last is one feature: a name and
    /// optional parameters, usually indented by one space (RFC 2389 requires
    /// it, but some servers don't indent). A single-line `211` means "no
    /// features".
    pub fn parse(reply: &Reply) -> Self {
        let mut features = Self::default();
        if reply.code != 211 {
            return features;
        }
        features.feat_supported = true;
        for line in reply.inner_lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (name, params) = match line.split_once(|c: char| c.is_ascii_whitespace()) {
                Some((name, params)) => (name, params.trim()),
                None => (line, ""),
            };
            let name = name.to_ascii_uppercase();
            features.apply(&name, params);
            features.raw.insert(name, params.to_owned());
        }
        features
    }

    fn apply(&mut self, name: &str, params: &str) {
        match name {
            "MLST" => {
                self.mlsd = true;
                self.mlst = Some(params.to_owned());
            }
            "MLSD" => self.mlsd = true,
            "SIZE" => self.size = true,
            "MDTM" => self.mdtm = true,
            "MFMT" => self.mfmt = true,
            "MFCT" => self.mfct = true,
            "MFF" => self.mff = Some(params.to_owned()),
            "REST" => {
                if params
                    .split_ascii_whitespace()
                    .any(|p| p.eq_ignore_ascii_case("STREAM"))
                {
                    self.rest_stream = true;
                }
            }
            "UTF8" => self.utf8 = true,
            "EPSV" => self.epsv = true,
            "EPRT" => self.eprt = true,
            "CLNT" => self.clnt = true,
            "TVFS" => self.tvfs = true,
            "MODE" => {
                if params
                    .split([';', ',', ' '])
                    .any(|p| p.eq_ignore_ascii_case("Z"))
                {
                    self.mode_z = true;
                }
            }
            "AUTH" => {
                for mech in params.split([';', ',', ' ']).filter(|m| !m.is_empty()) {
                    let mech = mech.to_ascii_uppercase();
                    if !self.auth.contains(&mech) {
                        self.auth.push(mech);
                    }
                }
            }
            "PBSZ" => self.pbsz = true,
            "PROT" => self.prot = true,
            "HOST" => self.host = true,
            "LANG" => self.lang = Some(params.to_owned()),
            _ => {}
        }
    }

    /// Whether `name` (case-insensitive) was listed.
    pub fn has(&self, name: &str) -> bool {
        self.raw.contains_key(&name.to_ascii_uppercase())
    }

    /// The parameters of `name` (case-insensitive), when listed.
    pub fn params(&self, name: &str) -> Option<&str> {
        self.raw.get(&name.to_ascii_uppercase()).map(String::as_str)
    }

    /// Whether `AUTH TLS` was listed.
    pub fn auth_tls(&self) -> bool {
        self.auth.iter().any(|m| m == "TLS")
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn reply(lines: &[&str]) -> Reply {
        let code = lines[0][..3].parse().unwrap();
        Reply::new(code, lines.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn typical_feat() {
        let f = Features::parse(&reply(&[
            "211-Features:",
            " MDTM",
            " REST STREAM",
            " SIZE",
            " MLST type*;size*;modify*;UNIX.mode;",
            " MLSD",
            " UTF8",
            " EPSV",
            " EPRT",
            " CLNT",
            " TVFS",
            " MFMT",
            " MODE Z",
            " AUTH TLS;SSL",
            " PBSZ",
            " PROT",
            " LANG EN*;FR",
            "211 End",
        ]));
        assert!(f.feat_supported);
        assert!(f.mdtm && f.size && f.rest_stream && f.mlsd && f.utf8);
        assert!(f.epsv && f.eprt && f.clnt && f.tvfs && f.mfmt && f.mode_z);
        assert!(f.pbsz && f.prot && f.auth_tls());
        assert_eq!(f.auth, vec!["TLS", "SSL"]);
        assert_eq!(f.mlst.as_deref(), Some("type*;size*;modify*;UNIX.mode;"));
        assert_eq!(f.lang.as_deref(), Some("EN*;FR"));
        assert!(!f.mfct && !f.host && f.mff.is_none());
        assert!(f.has("rest") && f.has("Utf8"));
        assert_eq!(f.params("REST"), Some("STREAM"));
    }

    #[test]
    fn unindented_lowercase_and_mlst_only() {
        let f = Features::parse(&reply(&[
            "211-Extensions",
            "mlst size*;",
            "size",
            "211 end",
        ]));
        assert!(f.mlsd, "MLST implies MLSD");
        assert!(f.size);
        assert!(!f.utf8);
    }

    #[test]
    fn rest_without_stream_and_auth_variants() {
        let f = Features::parse(&reply(&["211-x", " REST", " AUTH TLS-C, TLS", "211 x"]));
        assert!(!f.rest_stream);
        assert_eq!(f.auth, vec!["TLS-C", "TLS"]);
    }

    #[test]
    fn no_features_and_unsupported() {
        let empty = Features::parse(&reply(&["211 No features"]));
        assert!(empty.feat_supported);
        assert_eq!(
            empty,
            Features {
                feat_supported: true,
                ..Features::default()
            }
        );
        assert_eq!(
            Features::parse(&reply(&["500 Unknown command"])),
            Features::default()
        );
    }
}
