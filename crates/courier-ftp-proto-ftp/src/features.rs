//! The `FEAT` reply (RFC 2389) parsed into [`Features`] (T10 §5).
//!
//! Each feature line starts with one space; names are case-insensitive; the text after
//! the first space are the parameters. `MLSD` is implied by `MLST` (RFC 3659 §7.8).

use crate::reply::Reply;

/// Parsed `FEAT` reply (RFC 2389). Unknown lines kept in `raw`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Features {
    /// False when FEAT got 500/502 (or any non-2xx reply); every flag is then false.
    pub feat_supported: bool,
    /// RFC 3659 `MLST size*;modify*;type*;` (`*` = enabled by default).
    pub mlst: Option<Vec<MlstFact>>,
    /// `mlst.is_some()` or an explicit `MLSD` line.
    pub mlsd: bool,
    /// `SIZE` (RFC 3659).
    pub size: bool,
    /// `MDTM` (RFC 3659).
    pub mdtm: bool,
    /// `MFMT` (draft-somers-ftp-mfxx).
    pub mfmt: bool,
    /// `MFF` (draft-somers-ftp-mfxx).
    pub mff: bool,
    /// `REST STREAM` (RFC 3659).
    pub rest_stream: bool,
    /// `UTF8` (RFC 2640).
    pub utf8: bool,
    /// `EPSV` (RFC 2428; often not listed, T11 probes).
    pub epsv: bool,
    /// `EPRT` (RFC 2428).
    pub eprt: bool,
    /// `TVFS` (RFC 3659).
    pub tvfs: bool,
    /// `CLNT` (never sent).
    pub clnt: bool,
    /// `MODE Z`.
    pub mode_z: bool,
    /// `HOST` (RFC 7151, never sent).
    pub host: bool,
    /// `AUTH TLS;SSL` → `["TLS", "SSL"]` (upper-cased; several `AUTH` lines add up).
    pub auth: Vec<String>,
    /// `PBSZ` (RFC 2228).
    pub pbsz: bool,
    /// `PROT` (RFC 2228).
    pub prot: bool,
    /// `CCC` (RFC 2228).
    pub ccc: bool,
    /// `HASH SHA-256*;SHA-1;MD5` (draft-bryan-ftpext-hash, T41b), as listed.
    pub hash: Option<Vec<String>>,
    /// `SITE CHMOD;UTIME` style lists (upper-cased).
    pub site: Vec<String>,
    /// `LANG` parameters.
    pub lang: Option<String>,
    /// Feature lines not understood above (trimmed).
    pub raw: Vec<String>,
}

/// One MLST fact of the `FEAT` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlstFact {
    /// Lower-case fact name (`size`, `unix.mode`).
    pub name: String,
    /// Marked with `*` (sent by default).
    pub enabled: bool,
}

/// Splits a `;`-separated list (empty items dropped, items trimmed).
fn split_list(params: &str) -> impl Iterator<Item = &str> {
    params.split(';').map(str::trim).filter(|s| !s.is_empty())
}

/// Parses a `FEAT` reply. A non-2xx reply gives `Features::default()`
/// (`feat_supported: false`).
pub fn parse_feat(reply: &Reply) -> Features {
    let mut f = Features::default();
    if !reply.is_ok() {
        return f;
    }
    f.feat_supported = true;
    let n = reply.lines.len();
    if n < 3 {
        return f;
    }
    let own_prefix = format!("{}-", reply.code());
    for line in &reply.lines[1..n - 1] {
        // A few servers prefix every line with the code (`211-MDTM`).
        let line = line.strip_prefix(own_prefix.as_str()).unwrap_or(line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, params) = match line.split_once(char::is_whitespace) {
            Some((name, params)) => (name, params.trim()),
            None => (line, ""),
        };
        match name.to_ascii_uppercase().as_str() {
            "MLST" => {
                let facts = split_list(params)
                    .map(|fact| {
                        let enabled = fact.ends_with('*');
                        MlstFact {
                            name: fact.trim_end_matches('*').to_ascii_lowercase(),
                            enabled,
                        }
                    })
                    .collect();
                f.mlst = Some(facts);
            }
            "MLSD" => f.mlsd = true,
            "SIZE" => f.size = true,
            "MDTM" => f.mdtm = true,
            "MFMT" => f.mfmt = true,
            "MFF" => f.mff = true,
            "REST" if params.eq_ignore_ascii_case("STREAM") => f.rest_stream = true,
            "UTF8" => f.utf8 = true,
            "EPSV" => f.epsv = true,
            "EPRT" => f.eprt = true,
            "TVFS" => f.tvfs = true,
            "CLNT" => f.clnt = true,
            "MODE" if params.eq_ignore_ascii_case("Z") => f.mode_z = true,
            "HOST" => f.host = true,
            "AUTH" => {
                for mech in split_list(params).flat_map(str::split_whitespace) {
                    let mech = mech.to_ascii_uppercase();
                    if !f.auth.contains(&mech) {
                        f.auth.push(mech);
                    }
                }
            }
            "PBSZ" => f.pbsz = true,
            "PROT" => f.prot = true,
            "CCC" => f.ccc = true,
            "HASH" => f.hash = Some(split_list(params).map(str::to_owned).collect()),
            "SITE" => {
                for cmd in split_list(params).flat_map(str::split_whitespace) {
                    let cmd = cmd.to_ascii_uppercase();
                    if !f.site.contains(&cmd) {
                        f.site.push(cmd);
                    }
                }
            }
            "LANG" => f.lang = Some(params.to_owned()),
            _ => f.raw.push(line.to_owned()),
        }
    }
    f.mlsd |= f.mlst.is_some();
    f
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use courier_ftp_core::model::Charset;

    use super::*;
    use crate::{encoding::LineDecoder, reply::ReplyParser};

    fn reply(text: &str) -> Reply {
        let mut p = ReplyParser::new(LineDecoder::new(Charset::Auto));
        let mut r = p.push(text.as_bytes()).unwrap();
        assert_eq!(r.len(), 1, "{text}");
        r.remove(0)
    }

    /// vsftpd 3.0.3 (recorded).
    pub(crate) const VSFTPD: &str = "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n";
    /// ProFTPD 1.3.8 (recorded).
    pub(crate) const PROFTPD: &str = "211-Features:\r\n AUTH TLS\r\n CCC\r\n CLNT\r\n EPRT\r\n EPSV\r\n HOST\r\n LANG en-US.UTF-8*;en-US\r\n MDTM\r\n MFF modify;UNIX.group;UNIX.mode;\r\n MFMT\r\n MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname*;UNIX.mode*;UNIX.owner*;UNIX.ownername*;\r\n PBSZ\r\n PROT\r\n RANG STREAM\r\n REST STREAM\r\n SITE COPY\r\n SIZE\r\n SSCN\r\n TVFS\r\n UTF8\r\n211 End\r\n";
    /// pure-ftpd 1.0.50 (recorded).
    pub(crate) const PUREFTPD: &str = "211-Extensions supported:\r\n UTF8\r\n EPRT\r\n IDLE\r\n MDTM\r\n SIZE\r\n MFMT\r\n REST STREAM\r\n MLST type*;size*;sizd*;modify*;UNIX.mode*;UNIX.uid*;UNIX.gid*;unique*;\r\n MLSD\r\n PRET\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n TVFS\r\n ESTA\r\n PASV\r\n EPSV\r\n ESTP\r\n211 End.\r\n";

    #[test]
    fn feat_parses_vsftpd_proftpd_pureftpd_samples() {
        let v = parse_feat(&reply(VSFTPD));
        assert!(v.feat_supported && !v.mlsd && v.utf8 && v.rest_stream && v.epsv);
        let p = parse_feat(&reply(PROFTPD));
        assert!(p.mlsd && p.mfmt && p.mff && p.auth == ["TLS"]);
        let u = parse_feat(&reply(PUREFTPD));
        assert!(u.mlsd && u.mfmt && u.pbsz && u.prot);
        insta::assert_debug_snapshot!("feat_vsftpd", v);
        insta::assert_debug_snapshot!("feat_proftpd", p);
        insta::assert_debug_snapshot!("feat_pureftpd", u);
    }

    #[test]
    fn feat_mlst_implies_mlsd() {
        let f = parse_feat(&reply(
            "211-Features:\r\n MLST size*;Modify;type*;\r\n211 End\r\n",
        ));
        assert!(f.mlsd);
        assert_eq!(
            f.mlst,
            Some(vec![
                MlstFact {
                    name: "size".into(),
                    enabled: true
                },
                MlstFact {
                    name: "modify".into(),
                    enabled: false
                },
                MlstFact {
                    name: "type".into(),
                    enabled: true
                },
            ])
        );
        let explicit = parse_feat(&reply("211-Features:\r\n MLSD\r\n211 End\r\n"));
        assert!(explicit.mlsd && explicit.mlst.is_none());
    }

    #[test]
    fn feat_auth_list_split() {
        let f = parse_feat(&reply(
            "211-Features:\r\n AUTH TLS;SSL\r\n auth tls-c\r\n HASH SHA-256*;SHA-1;MD5\r\n SITE chmod;UTIME\r\n mode z\r\n211-X-THING 1\r\n211 End\r\n",
        ));
        assert_eq!(f.auth, ["TLS", "SSL", "TLS-C"]);
        assert_eq!(
            f.hash,
            Some(vec!["SHA-256*".into(), "SHA-1".into(), "MD5".into()])
        );
        assert_eq!(f.site, ["CHMOD", "UTIME"]);
        assert!(f.mode_z);
        assert_eq!(f.raw, ["X-THING 1"]);
    }

    #[test]
    fn feat_unsupported_reply_leaves_flags_false() {
        for text in ["500 Unknown command\r\n", "502 Not implemented\r\n"] {
            assert_eq!(parse_feat(&reply(text)), Features::default());
        }
        let single = parse_feat(&reply("211 No features\r\n"));
        assert!(single.feat_supported && !single.mlsd);
    }
}
