//! [`SiteError`].

use crate::model::item::ItemId;
use crate::vault::VaultError;

use super::validate::{NameError, SiteIssue};

/// Everything that can go wrong with the Site Manager's data. Carries no
/// secrets, host names or user names.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SiteError {
    /// The vault failed (locked, read-only item, storage).
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The device-local table failed.
    #[error("device-local storage failed: {0}")]
    Local(String),
    /// No site or folder has this id.
    #[error("no site or folder {}", .0.short())]
    NotFound(ItemId),
    /// A site or folder was given where a folder is needed.
    #[error("{} is not a folder", .0.short())]
    NotAFolder(ItemId),
    /// A folder can't move into itself or one of its subfolders.
    #[error("a folder can't be moved into itself or one of its subfolders")]
    IntoOwnDescendant,
    /// Another entry in the same folder has this name.
    #[error("\"{0}\" already exists in this folder")]
    NameTaken(String),
    /// The name is empty or contains `/` or control characters.
    #[error(transparent)]
    InvalidName(#[from] NameError),
    /// The site has validation errors (see [`Site::validate`]).
    ///
    /// [`Site::validate`]: super::Site::validate
    #[error("{}", describe(.0))]
    Invalid(Vec<SiteIssue>),
    /// The site uses an SSH key from the vault that doesn't exist (any more).
    #[error("the site's SSH key ({}) is not in the vault", .0.short())]
    KeyMissing(ItemId),
    /// A bookmark is not valid (T33); the message says why.
    #[error("invalid bookmark: {0}")]
    InvalidBookmark(String),
    /// Moving an entry into a folder of another vault (team vaults, T89).
    #[error("moving between vaults is not supported")]
    CrossVault,
}

fn describe(issues: &[SiteIssue]) -> String {
    let errors: Vec<&str> = issues
        .iter()
        .filter(|i| i.is_error())
        .map(|i| i.message.as_str())
        .collect();
    if errors.is_empty() {
        "the site is not valid".to_owned()
    } else {
        errors.join("; ")
    }
}

impl From<SiteError> for crate::Error {
    fn from(e: SiteError) -> Self {
        match e {
            SiteError::Vault(v) => crate::Error::Vault(v.to_string()),
            SiteError::Local(m) => crate::Error::Vault(m),
            other => crate::Error::InvalidInput(other.to_string()),
        }
    }
}
