//! FileZilla 3.x `sitemanager.xml`: reading it into an [`ImportTree`] and
//! writing a site subtree back (T32).
//!
//! # Format
//!
//! ```xml
//! <FileZilla3 version="3.67.0" platform="*nix">
//!   <Servers>
//!     <Folder expanded="1">Work
//!       <Server>
//!         <Host>ftp.example.com</Host> <Port>21</Port> <Protocol>0</Protocol>
//!         <Type>0</Type> <User>alice</User> <Pass encoding="base64">c2VjcmV0</Pass>
//!         <Logontype>1</Logontype> <TimezoneOffset>0</TimezoneOffset>
//!         <PasvMode>MODE_DEFAULT</PasvMode> <MaximumMultipleConnections>0</MaximumMultipleConnections>
//!         <EncodingType>Auto</EncodingType> <BypassProxy>0</BypassProxy>
//!         <Name>web</Name> <Comments/> <Colour>0</Colour> <LocalDir/>
//!         <RemoteDir>1 0 4 home 4 user</RemoteDir>
//!         <SyncBrowsing>0</SyncBrowsing> <DirectoryComparison>0</DirectoryComparison>
//!         <Bookmark><Name>logs</Name><RemoteDir>1 0 3 var 3 log</RemoteDir></Bookmark>
//!         web
//!       </Server>
//!     </Folder>
//!   </Servers>
//! </FileZilla3>
//! ```
//!
//! A folder's name is its own text; a server's name is `<Name>` (older
//! versions only had the trailing text). Values, checked against FileZilla's
//! sources (`libfilezilla`/`engine` `ServerProtocol`, `LogonType`,
//! `ServerType`, `site_colour`):
//!
//! - `Protocol`: 0 FTP (explicit TLS if available), 1 SFTP, 3 FTPS
//!   (implicit), 4 FTPES (explicit, required), 6 plain FTP. The others (HTTP,
//!   S3, WebDAV, Storj, cloud storage…) are skipped with a reason.
//! - `Logontype`: 0 anonymous, 1 normal, 2 ask for password, 3 interactive,
//!   4 account, 5 key file; 6 (profile, cloud only) is skipped.
//! - `Type`: 0 default, 1 Unix, 2 VMS, 3 DOS, 4 MVS, 5 VxWorks, 6 z/VM,
//!   7 HP NonStop, 8 DOS virtual, 9 Cygwin, 10 DOS with forward slashes.
//!   Types we don't have become "auto".
//! - `Colour`: 0 none, 1 red, 2 green, 3 blue, 4 yellow, 5 cyan, 6 magenta,
//!   7 orange (shown as yellow).
//! - `Pass encoding="base64"` is decoded; a plain `Pass` (FileZilla < 3.26)
//!   is taken as is; `encoding="crypt"` (protected by FileZilla's master
//!   password, public-key encryption) is skipped and reported.
//! - `RemoteDir` is FileZilla's safe path: `<type> <prefix length> [prefix]`
//!   then `<length> <segment>` pairs; lengths count characters, so names
//!   may contain spaces.
//! - `TimezoneOffset` is in minutes.
//!
//! # Untrusted input
//!
//! The file is capped at [`MAX_XML_LEN`], nesting at [`MAX_DEPTH`] and the
//! element count at [`MAX_ELEMENTS`]; a `<!DOCTYPE>` is refused, so no
//! entity can be declared (quick-xml never expands DTD entities anyway) and
//! only the five predefined entities and character references are
//! accepted.

use std::fmt::Write as _;

use base64ct::{Base64, Encoding};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use secrecy::SecretString;

use crate::model::item::{LogonKind, ServerType, SiteColor, SiteTransferMode};
use crate::model::{Charset, FtpEncryption, LocalPath, Protocol, RemotePath};

use super::import::{ImportBookmark, ImportError, ImportNode, ImportSite, ImportTree, Skipped};
use super::{MAX_TIMEZONE_OFFSET_MINUTES, Site, SiteKey, SiteLogon};

/// The largest `sitemanager.xml` accepted (32 MiB).
pub const MAX_XML_LEN: usize = 32 << 20;
/// The deepest element nesting accepted.
pub const MAX_DEPTH: usize = 64;
/// The most elements accepted.
pub const MAX_ELEMENTS: usize = 2_000_000;

// ------------------------------------------------------------------ mini DOM

#[derive(Debug, Default)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Element>,
    /// The element's own text (outside child elements), concatenated.
    text: String,
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// The text of child `name`, trimmed (`None` when missing or empty).
    fn get(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|c| c.text.trim())
            .filter(|t| !t.is_empty())
    }

    fn get_int(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(|t| t.parse().ok())
    }

    fn get_bool(&self, name: &str) -> bool {
        self.get_int(name).is_some_and(|v| v != 0)
    }
}

fn xml_error(e: impl std::fmt::Display) -> ImportError {
    ImportError::Malformed(e.to_string())
}

fn start_element(e: &BytesStart<'_>) -> Result<Element, ImportError> {
    let name = e.local_name().as_ref().to_owned();
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(xml_error)?;
        let key = a.key.local_name().as_ref().to_owned();
        let value = a
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(xml_error)?
            .into_owned();
        attrs.push((key, value));
    }
    Ok(Element {
        name,
        attrs,
        ..Element::default()
    })
}

/// Parses `xml` into its root element, with the limits in the module docs.
fn parse_dom(xml: &[u8]) -> Result<Element, ImportError> {
    if xml.len() > MAX_XML_LEN {
        return Err(ImportError::TooLarge);
    }
    let text = std::str::from_utf8(xml)
        .map_err(|_| ImportError::Malformed("the file is not UTF-8".into()))?;
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut elements = 0usize;
    loop {
        let event = reader.read_event().map_err(xml_error)?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                elements += 1;
                if elements > MAX_ELEMENTS {
                    return Err(ImportError::TooLarge);
                }
                stack.push(start_element(e)?);
                if stack.len() > MAX_DEPTH + 1 {
                    return Err(ImportError::Malformed("elements nested too deeply".into()));
                }
                if matches!(event, Event::Empty(_)) {
                    close(&mut stack)?;
                }
            }
            Event::End(_) => close(&mut stack)?,
            Event::Text(t) => {
                let s = t.xml10_content();
                push_text(&mut stack, &s)?;
            }
            Event::CData(c) => {
                let s = c.xml10_content();
                push_text(&mut stack, &s)?;
            }
            Event::GeneralRef(r) => {
                let c = if let Some(c) = r.resolve_char_ref().map_err(xml_error)? {
                    c
                } else {
                    match r.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => {
                            return Err(ImportError::Malformed("unknown entity reference".into()));
                        }
                    }
                };
                push_text(&mut stack, c.encode_utf8(&mut [0; 4]))?;
            }
            Event::DocType(_) => {
                return Err(ImportError::Malformed(
                    "document type declarations are not allowed".into(),
                ));
            }
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if stack.len() != 1 {
        return Err(ImportError::Malformed("unclosed element".into()));
    }
    let mut doc = stack.pop().unwrap_or_default();
    match doc.children.len() {
        1 => Ok(doc.children.remove(0)),
        0 => Err(ImportError::Malformed("no root element".into())),
        _ => Err(ImportError::Malformed("more than one root element".into())),
    }
}

fn push_text(stack: &mut [Element], s: &str) -> Result<(), ImportError> {
    let top = stack
        .last_mut()
        .ok_or_else(|| ImportError::Malformed("text outside the document".into()))?;
    top.text.push_str(s);
    Ok(())
}

fn close(stack: &mut Vec<Element>) -> Result<(), ImportError> {
    if stack.len() < 2 {
        return Err(ImportError::Malformed("unexpected end tag".into()));
    }
    let el = stack
        .pop()
        .ok_or_else(|| ImportError::Malformed("unexpected end tag".into()))?;
    if let Some(parent) = stack.last_mut() {
        parent.children.push(el);
    }
    Ok(())
}

// ------------------------------------------------------------------ import

/// Reads a FileZilla `sitemanager.xml` (or an exported sites file, which has
/// the same layout). Servers that can't be imported are listed in
/// [`ImportTree::skipped`]; the rest is in the tree.
///
/// # Errors
/// [`ImportError::TooLarge`], [`ImportError::Malformed`] for XML that
/// doesn't parse or isn't a FileZilla file.
pub(super) fn parse_sitemanager(xml: &[u8]) -> Result<ImportTree, ImportError> {
    let root = parse_dom(xml)?;
    if root.name != "FileZilla3" {
        return Err(ImportError::Malformed(
            "not a FileZilla 3 file (no <FileZilla3> root)".into(),
        ));
    }
    let mut tree = ImportTree::default();
    let Some(servers) = root.child("Servers") else {
        return Ok(tree);
    };
    let mut skipped = Vec::new();
    tree.nodes = read_children(servers, "", &mut skipped);
    tree.skipped = skipped;
    Ok(tree)
}

fn read_children(el: &Element, path: &str, skipped: &mut Vec<Skipped>) -> Vec<ImportNode> {
    let mut out = Vec::new();
    for c in &el.children {
        match c.name.as_str() {
            "Folder" => {
                let name = clean_name(&c.text, "Folder");
                let sub = join(path, &name);
                out.push(ImportNode::Folder {
                    id: None,
                    name,
                    children: read_children(c, &sub, skipped),
                });
            }
            "Server" => match read_server(c) {
                Ok(site) => out.push(ImportNode::Site(Box::new(site))),
                Err(reason) => skipped.push(Skipped {
                    path: join(path, &server_name(c)),
                    reason,
                }),
            },
            _ => {}
        }
    }
    out
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}/{name}")
    }
}

/// A usable tree name: trimmed, `/` and control characters replaced.
fn clean_name(raw: &str, fallback: &str) -> String {
    let name: String = raw
        .trim()
        .chars()
        .map(|c| if c == '/' || c.is_control() { '_' } else { c })
        .collect();
    if name.is_empty() {
        fallback.to_owned()
    } else {
        name
    }
}

fn server_name(el: &Element) -> String {
    let raw = el
        .get("Name")
        .map(str::to_owned)
        .or_else(|| Some(el.text.trim().to_owned()).filter(|t| !t.is_empty()))
        .or_else(|| el.get("Host").map(str::to_owned))
        .unwrap_or_default();
    clean_name(&raw, "Site")
}

fn protocol(code: i64) -> Result<(Protocol, Option<FtpEncryption>), String> {
    Ok(match code {
        0 => (Protocol::Ftp, None),
        1 => (Protocol::Sftp, None),
        3 => (Protocol::FtpsImplicit, None),
        4 => (Protocol::FtpsExplicit, None),
        6 => (Protocol::Ftp, Some(FtpEncryption::PlainOnly)),
        2 | 5 => return Err("HTTP/HTTPS sites are not supported".into()),
        7..=21 => {
            return Err(format!(
                "{} sites are not supported",
                match code {
                    7 => "S3",
                    8 | 21 => "Storj",
                    9 | 19 => "WebDAV",
                    10 | 11 => "Azure",
                    12 | 20 => "OpenStack Swift",
                    13 | 14 => "Google Cloud",
                    15 => "Dropbox",
                    16 => "OneDrive",
                    17 => "Backblaze B2",
                    _ => "Box",
                }
            ));
        }
        other => return Err(format!("unknown protocol {other}")),
    })
}

fn server_type(code: i64) -> ServerType {
    match code {
        1 | 9 => ServerType::Unix,
        2 => ServerType::Vms,
        3 | 8 | 10 => ServerType::Dos,
        4 => ServerType::Mvs,
        _ => ServerType::Auto,
    }
}

fn color(code: i64) -> SiteColor {
    match code {
        1 => SiteColor::Red,
        2 => SiteColor::Green,
        3 => SiteColor::Blue,
        4 | 7 => SiteColor::Yellow,
        5 => SiteColor::Cyan,
        6 => SiteColor::Magenta,
        _ => SiteColor::None,
    }
}

/// The password of `<Pass>`: `Ok(None)` when absent or empty,
/// `Err(reason)` when it can't be read (master-password protected or not
/// base64).
fn password(el: &Element) -> Result<Option<SecretString>, String> {
    let Some(pass) = el.child("Pass") else {
        return Ok(None);
    };
    let raw = pass.text.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    match pass.attr("encoding") {
        None | Some("") => Ok(Some(SecretString::from(pass.text.clone()))),
        Some("base64") => {
            let bytes = zeroize::Zeroizing::new(
                Base64::decode_vec(raw).map_err(|_| "the password is not valid base64")?,
            );
            let text = std::str::from_utf8(&bytes).map_err(|_| "the password is not UTF-8")?;
            Ok(Some(SecretString::from(text.to_owned())))
        }
        Some("crypt") => Err("the password is protected by a FileZilla master password".into()),
        Some(other) => Err(format!("unknown password encoding \"{other}\"")),
    }
}

/// Decodes FileZilla's safe path (`1 0 4 home 4 user` → `/home/user`).
/// `None` when it doesn't parse.
pub fn decode_remote_dir(safe: &str) -> Option<RemotePath> {
    let safe = safe.trim();
    if safe.is_empty() {
        return None;
    }
    let mut rest = safe;
    let number = |rest: &mut &str| -> Option<usize> {
        let end = rest.find(' ').unwrap_or(rest.len());
        let n = rest[..end].parse().ok()?;
        *rest = rest.get(end + 1..).unwrap_or("");
        Some(n)
    };
    let _server_type = number(&mut rest)?;
    let take = |rest: &mut &str, n: usize| -> Option<String> {
        let end = rest
            .char_indices()
            .nth(n)
            .map_or(Some(rest.len()), |(i, _)| Some(i))
            .filter(|_| rest.chars().count() >= n)?;
        let s = rest[..end].to_owned();
        let after = &rest[end..];
        *rest = after.strip_prefix(' ').unwrap_or(after);
        Some(s)
    };
    let prefix_len = number(&mut rest)?;
    let mut segments = Vec::new();
    if prefix_len > 0 {
        let prefix = take(&mut rest, prefix_len)?;
        segments.push(prefix);
    }
    while !rest.is_empty() {
        let n = number(&mut rest)?;
        if n == 0 {
            return None;
        }
        segments.push(take(&mut rest, n)?);
    }
    if segments
        .iter()
        .any(|s| s == "." || s == ".." || s.contains('/'))
    {
        return None;
    }
    Some(RemotePath::new(format!("/{}", segments.join("/"))))
}

/// Encodes `path` as a FileZilla Unix safe path (`/home/user` →
/// `1 0 4 home 4 user`; `/` → `1 0`).
pub fn encode_remote_dir(path: &RemotePath) -> String {
    let mut out = String::from("1 0");
    for seg in path.components() {
        let _ = write!(out, " {} {seg}", seg.chars().count());
    }
    out
}

fn read_server(el: &Element) -> Result<ImportSite, String> {
    let name = server_name(el);
    let host = el
        .get("Host")
        .ok_or("no host")?
        .trim_matches(|c| c == '[' || c == ']')
        .to_owned();
    let (protocol, encryption) = protocol(el.get_int("Protocol").unwrap_or(0))?;
    let mut site = Site::new(name, protocol, host);
    site.encryption = encryption;
    site.port = el
        .get_int("Port")
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p != 0 && p != protocol.default_port());
    let user = el.get("User").unwrap_or_default().to_owned();
    let logon_code = el
        .get_int("Logontype")
        .unwrap_or(if user.is_empty() { 0 } else { 1 });
    let mut password_skipped = None;
    let pass = match password(el) {
        Ok(p) => p,
        Err(reason) => {
            password_skipped = Some(reason);
            None
        }
    };
    site.logon = match logon_code {
        0 => SiteLogon::Anonymous,
        1 => SiteLogon::Normal {
            user,
            password: pass,
        },
        2 => SiteLogon::AskForPassword { user },
        3 => SiteLogon::Interactive { user },
        4 => SiteLogon::Account {
            user,
            password: pass,
            account: el.get("Account").unwrap_or_default().to_owned(),
        },
        5 => SiteLogon::KeyFile {
            user,
            key: el.get("Keyfile").map(|k| SiteKey::File(LocalPath::new(k))),
            passphrase: None,
        },
        6 => return Err("profile logins (cloud storage) are not supported".into()),
        other => return Err(format!("unknown logon type {other}")),
    };
    if protocol == Protocol::Sftp && site.logon.kind() == LogonKind::Account {
        site.logon = site.logon.with_kind(LogonKind::Normal);
    }
    site.server_type = server_type(el.get_int("Type").unwrap_or(0));
    site.timezone_offset_minutes = el
        .get_int("TimezoneOffset")
        .and_then(|m| i32::try_from(m).ok())
        .unwrap_or(0)
        .clamp(-MAX_TIMEZONE_OFFSET_MINUTES, MAX_TIMEZONE_OFFSET_MINUTES);
    site.transfer_mode = match el.get("PasvMode") {
        Some("MODE_ACTIVE") => SiteTransferMode::Active,
        Some("MODE_PASSIVE") => SiteTransferMode::Passive,
        _ => SiteTransferMode::Default,
    };
    site.limit_connections = el
        .get_int("MaximumMultipleConnections")
        .and_then(|n| u8::try_from(n).ok())
        .filter(|n| super::CONNECTION_LIMITS.contains(n));
    site.charset = match el.get("EncodingType") {
        Some(t) if t.eq_ignore_ascii_case("UTF-8") => Charset::Utf8,
        Some("Custom") => el
            .get("CustomEncoding")
            .and_then(|c| Charset::from_label(c).ok())
            .unwrap_or_default(),
        _ => Charset::Auto,
    };
    site.bypass_proxy = el.get_bool("BypassProxy");
    site.comments = el
        .child("Comments")
        .map(|c| c.text.trim().to_owned())
        .unwrap_or_default();
    site.color = color(el.get_int("Colour").unwrap_or(0));
    site.default_local_dir = el.get("LocalDir").map(LocalPath::new);
    site.default_remote_dir = el.get("RemoteDir").and_then(decode_remote_dir);
    site.sync_browsing = el.get_bool("SyncBrowsing");
    site.directory_comparison = el.get_bool("DirectoryComparison");

    let bookmarks = el
        .children
        .iter()
        .filter(|c| c.name == "Bookmark")
        .filter_map(|b| {
            let remote_dir = b.get("RemoteDir").and_then(decode_remote_dir)?;
            Some(ImportBookmark {
                name: clean_name(b.get("Name").unwrap_or_default(), "Bookmark"),
                local_dir: b.get("LocalDir").map(LocalPath::new),
                remote_dir: Some(remote_dir),
                sync_browsing: b.get_bool("SyncBrowsing"),
                comparison: b.get_bool("DirectoryComparison"),
            })
        })
        .collect();
    Ok(ImportSite {
        site,
        bookmarks,
        vault_key: None,
        password_skipped,
    })
}

// ------------------------------------------------------------------ export

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters other than tab/newline aren't allowed in
            // XML 1.0.
            c if c.is_control() && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

fn protocol_code(site: &Site) -> u8 {
    match (site.protocol, site.encryption) {
        (Protocol::Sftp, _) => 1,
        (Protocol::FtpsImplicit, _) | (_, Some(FtpEncryption::RequireImplicit)) => 3,
        (Protocol::FtpsExplicit, _) | (_, Some(FtpEncryption::RequireExplicit)) => 4,
        (Protocol::Ftp, Some(FtpEncryption::PlainOnly)) => 6,
        (Protocol::Ftp, _) => 0,
    }
}

fn type_code(t: ServerType) -> u8 {
    match t {
        ServerType::Auto | ServerType::NetWare | ServerType::As400 => 0,
        ServerType::Unix => 1,
        ServerType::Vms => 2,
        ServerType::Dos => 3,
        ServerType::Mvs => 4,
    }
}

fn color_code(c: SiteColor) -> u8 {
    match c {
        SiteColor::None => 0,
        SiteColor::Red => 1,
        SiteColor::Green => 2,
        SiteColor::Blue => 3,
        SiteColor::Yellow => 4,
        SiteColor::Cyan => 5,
        SiteColor::Magenta => 6,
    }
}

/// One node to write: a folder with children, or a site with its bookmarks.
#[derive(Debug, Clone)]
pub(crate) enum XmlNode<'a> {
    Folder(&'a str, Vec<XmlNode<'a>>),
    Site(&'a Site, Vec<ImportBookmark>),
}

/// Writes `nodes` as a FileZilla 3 `sitemanager.xml`, **without passwords
/// or key passphrases** (FileZilla asks for them; a Normal login is written
/// as "ask for password").
pub(crate) fn write_sitemanager(nodes: &[XmlNode<'_>]) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n\
         <FileZilla3 version=\"3.67.0\" platform=\"*nix\">\n\t<Servers>\n",
    );
    for n in nodes {
        write_node(&mut out, n, 2);
    }
    out.push_str("\t</Servers>\n</FileZilla3>\n");
    out
}

fn write_node(out: &mut String, node: &XmlNode<'_>, depth: usize) {
    let tab = "\t".repeat(depth);
    match node {
        XmlNode::Folder(name, children) => {
            let _ = writeln!(out, "{tab}<Folder expanded=\"1\">{}", escape(name));
            for c in children {
                write_node(out, c, depth + 1);
            }
            let _ = writeln!(out, "{tab}</Folder>");
        }
        XmlNode::Site(site, bookmarks) => write_server(out, site, bookmarks, depth),
    }
}

fn write_server(out: &mut String, s: &Site, bookmarks: &[ImportBookmark], depth: usize) {
    let tab = "\t".repeat(depth);
    let t = format!("{tab}\t");
    let mut lines: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: String| lines.push((k.to_owned(), v));
    push("Host", s.host.clone());
    push("Port", s.effective_port().to_string());
    push("Protocol", protocol_code(s).to_string());
    push("Type", type_code(s.server_type).to_string());
    let (logon, account, keyfile) = match &s.logon {
        SiteLogon::Anonymous => (0, None, None),
        SiteLogon::Normal { .. } | SiteLogon::AskForPassword { .. } => (2, None, None),
        SiteLogon::Interactive { .. } | SiteLogon::Agent { .. } => (3, None, None),
        // The ACCT value is treated as a secret, like the password.
        SiteLogon::Account { .. } => (2, None, None),
        SiteLogon::KeyFile { key, .. } => match key {
            Some(SiteKey::File(path)) => {
                (5, None, Some(path.as_path().to_string_lossy().into_owned()))
            }
            _ => (2, None, None),
        },
    };
    if logon != 0 {
        push("User", s.logon.user().to_owned());
    }
    if let Some(a) = account {
        push("Account", a);
    }
    if let Some(k) = keyfile {
        push("Keyfile", k);
    }
    push("Logontype", logon.to_string());
    push("TimezoneOffset", s.timezone_offset_minutes.to_string());
    push(
        "PasvMode",
        match s.transfer_mode {
            SiteTransferMode::Default => "MODE_DEFAULT",
            SiteTransferMode::Active => "MODE_ACTIVE",
            SiteTransferMode::Passive => "MODE_PASSIVE",
        }
        .to_owned(),
    );
    push(
        "MaximumMultipleConnections",
        s.limit_connections.map_or(0, u32::from).to_string(),
    );
    match s.charset {
        Charset::Auto => push("EncodingType", "Auto".into()),
        Charset::Utf8 => push("EncodingType", "UTF-8".into()),
        Charset::Custom(enc) => {
            push("EncodingType", "Custom".into());
            push("CustomEncoding", enc.name().to_owned());
        }
    }
    push("BypassProxy", u8::from(s.bypass_proxy).to_string());
    push("Name", s.name.clone());
    push("Comments", s.comments.clone());
    push("Colour", color_code(s.color).to_string());
    push(
        "LocalDir",
        s.default_local_dir
            .as_ref()
            .map(|p| p.as_path().to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    push(
        "RemoteDir",
        s.default_remote_dir
            .as_ref()
            .map(encode_remote_dir)
            .unwrap_or_default(),
    );
    push("SyncBrowsing", u8::from(s.sync_browsing).to_string());
    push(
        "DirectoryComparison",
        u8::from(s.directory_comparison).to_string(),
    );
    let _ = writeln!(out, "{tab}<Server>");
    for (k, v) in &lines {
        if v.is_empty() {
            let _ = writeln!(out, "{t}<{k} />");
        } else {
            let _ = writeln!(out, "{t}<{k}>{}</{k}>", escape(v));
        }
    }
    for b in bookmarks {
        let _ = writeln!(out, "{t}<Bookmark>");
        let _ = writeln!(out, "{t}\t<Name>{}</Name>", escape(&b.name));
        if let Some(l) = &b.local_dir {
            let _ = writeln!(
                out,
                "{t}\t<LocalDir>{}</LocalDir>",
                escape(&l.as_path().to_string_lossy())
            );
        }
        if let Some(r) = &b.remote_dir {
            let _ = writeln!(
                out,
                "{t}\t<RemoteDir>{}</RemoteDir>",
                escape(&encode_remote_dir(r))
            );
        }
        let _ = writeln!(
            out,
            "{t}\t<SyncBrowsing>{}</SyncBrowsing>",
            u8::from(b.sync_browsing)
        );
        let _ = writeln!(
            out,
            "{t}\t<DirectoryComparison>{}</DirectoryComparison>",
            u8::from(b.comparison)
        );
        let _ = writeln!(out, "{t}</Bookmark>");
    }
    let _ = writeln!(out, "{t}{}", escape(&s.name));
    let _ = writeln!(out, "{tab}</Server>");
}

/// Fuzz body (cargo-fuzz target `filezilla_xml`): parses arbitrary bytes as
/// a `sitemanager.xml`. Must never panic.
#[doc(hidden)]
pub fn fuzz_filezilla_xml(data: &[u8]) {
    let _ = parse_sitemanager(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_remote_dir(s);
    }
}
