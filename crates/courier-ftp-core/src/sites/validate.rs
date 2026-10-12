//! Validation rules for names and sites (T31 §8). The Site Manager (T59)
//! shows the issues inline; [`SiteManager::save_site`] refuses a site with
//! errors and returns the warnings.
//!
//! [`SiteManager::save_site`]: super::SiteManager::save_site

use std::ops::RangeInclusive;

use crate::model::Protocol;
use crate::model::item::LogonKind;

use super::site::{Site, SiteKey, SiteLogon};

/// The largest server time zone offset, in minutes (±24 h).
pub const MAX_TIMEZONE_OFFSET_MINUTES: i32 = 24 * 60;

/// Allowed values of [`Site::limit_connections`].
pub const CONNECTION_LIMITS: RangeInclusive<u8> = 1..=10;

/// Why a site or folder name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// Empty or only white space.
    #[error("the name is empty")]
    Empty,
    /// Contains `/`, the path separator of [`SiteTree::find_path`].
    ///
    /// [`SiteTree::find_path`]: super::SiteTree::find_path
    #[error("the name can't contain '/'")]
    Slash,
    /// Contains a control character (newline, tab, escape, ...).
    #[error("the name can't contain control characters")]
    Control,
}

/// Checks a site or folder name and returns it trimmed.
///
/// # Errors
/// [`NameError`] for an empty name, `/` or a control character.
pub fn validate_name(name: &str) -> Result<String, NameError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.contains('/') {
        return Err(NameError::Slash);
    }
    if name.chars().any(char::is_control) {
        return Err(NameError::Control);
    }
    Ok(name.to_owned())
}

/// How bad an issue is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The site can't be saved.
    Error,
    /// Saved anyway; shown to the user.
    Warning,
}

/// The Site Manager field an issue belongs to (where T59 shows it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SiteField {
    /// Name.
    Name,
    /// Host.
    Host,
    /// Port.
    Port,
    /// Logon type.
    Logon,
    /// User.
    User,
    /// Key file.
    KeyFile,
    /// Server time zone offset.
    TimezoneOffset,
    /// Limit of simultaneous connections.
    ConnectionLimit,
}

/// One validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteIssue {
    /// Where.
    pub field: SiteField,
    /// Error or warning.
    pub severity: Severity,
    /// For the user.
    pub message: String,
}

impl SiteIssue {
    fn error(field: SiteField, message: impl Into<String>) -> Self {
        Self {
            field,
            severity: Severity::Error,
            message: message.into(),
        }
    }

    fn warning(field: SiteField, message: impl Into<String>) -> Self {
        Self {
            field,
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    /// Whether it blocks saving.
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// The logon types the Site Manager offers for `protocol` (FileZilla's
/// lists): FTP has no key or agent logins, SFTP no anonymous or account.
pub fn logon_kinds(protocol: Protocol) -> &'static [LogonKind] {
    const FTP: &[LogonKind] = &[
        LogonKind::Anonymous,
        LogonKind::Normal,
        LogonKind::AskForPassword,
        LogonKind::Interactive,
        LogonKind::Account,
    ];
    const SFTP: &[LogonKind] = &[
        LogonKind::Normal,
        LogonKind::AskForPassword,
        LogonKind::Interactive,
        LogonKind::KeyFile,
        LogonKind::Agent,
    ];
    match protocol {
        Protocol::Sftp => SFTP,
        Protocol::Ftp | Protocol::FtpsExplicit | Protocol::FtpsImplicit => FTP,
    }
}

impl Site {
    /// Every rule of T31 §8: name, host non-empty, port 1–65535, logon type
    /// valid for the protocol, user present, a key for key logins (a missing
    /// key file is only a warning), time zone offset within ±24 h,
    /// connection limit 1–10.
    pub fn validate(&self) -> Vec<SiteIssue> {
        let mut issues = Vec::new();
        if let Err(e) = validate_name(&self.name) {
            issues.push(SiteIssue::error(SiteField::Name, e.to_string()));
        }
        if self.host.trim().is_empty() {
            issues.push(SiteIssue::error(SiteField::Host, "the host is empty"));
        } else if self
            .host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
            issues.push(SiteIssue::error(
                SiteField::Host,
                "the host can't contain spaces",
            ));
        }
        if self.port == Some(0) {
            issues.push(SiteIssue::error(
                SiteField::Port,
                "the port must be between 1 and 65535",
            ));
        }
        let kind = self.logon.kind();
        if !logon_kinds(self.protocol).contains(&kind) {
            issues.push(SiteIssue::error(
                SiteField::Logon,
                format!(
                    "this logon type is not available for {}",
                    self.protocol.scheme().to_uppercase()
                ),
            ));
        }
        if !matches!(self.logon, SiteLogon::Anonymous) && self.logon.user().trim().is_empty() {
            issues.push(SiteIssue::error(SiteField::User, "the user is empty"));
        }
        if let SiteLogon::KeyFile { key, .. } = &self.logon {
            match key {
                None => issues.push(SiteIssue::error(
                    SiteField::KeyFile,
                    "choose a key file or an SSH key from the vault",
                )),
                Some(SiteKey::File(path)) if !path.as_path().exists() => {
                    issues.push(SiteIssue::warning(
                        SiteField::KeyFile,
                        "the key file does not exist on this device",
                    ));
                }
                Some(_) => {}
            }
        }
        if self.timezone_offset_minutes.abs() > MAX_TIMEZONE_OFFSET_MINUTES {
            issues.push(SiteIssue::error(
                SiteField::TimezoneOffset,
                "the time zone offset must be within ±24 hours",
            ));
        }
        if let Some(limit) = self.limit_connections
            && !CONNECTION_LIMITS.contains(&limit)
        {
            issues.push(SiteIssue::error(
                SiteField::ConnectionLimit,
                "the connection limit must be between 1 and 10",
            ));
        }
        issues
    }
}
