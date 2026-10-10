//! Quickconnect history and recent servers (T33).
//!
//! - **History**: the last [`HISTORY_LIMIT`] quickconnect logins, most recent
//!   first, deduplicated by protocol + host + port + user. Each is a
//!   `history-entry` item (synced only with `sync.history`). The password is
//!   written along, and the vault engine drops it when
//!   `vault.store_passwords` is off ([`crate::vault::strip_passwords`]). With
//!   the vault locked nothing is read or written ([`VaultError::Locked`]):
//!   the UI hides the history and says why.
//! - **Recent servers**: the last [`RECENT_LIMIT`] successful connects of
//!   this device, sites and quickconnect entries alike, from the
//!   device-local `last_connected_at` ([`SiteLocalStore`]), resolved against
//!   the live sites and history entries, so a deleted site (or one deleted
//!   on another device) drops out. "Reconnect to last server" uses item 0.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use secrecy::SecretString;

use crate::backend::ConnectInfo;
use crate::model::item::{self, ItemId, LogonKind, UnixMillis, VaultId};
use crate::model::{LogonType, Protocol, ServerAddress};
use crate::vault::{ItemVault, ItemVaultExt, VaultError};

use super::{Site, SiteError, SiteLocal, SiteLocalStore, SiteLogon, SiteTree};

/// Quickconnect history entries kept.
pub const HISTORY_LIMIT: usize = 10;

/// Recent servers listed.
pub const RECENT_LIMIT: usize = 10;

/// One quickconnect history entry.
///
/// `Debug` doesn't show the password.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// The `history-entry` item's id.
    pub id: ItemId,
    /// The vault it lives in (`None` until saved).
    pub vault: Option<VaultId>,
    /// Protocol.
    pub protocol: Protocol,
    /// Host name or address.
    pub host: String,
    /// Port (the protocol's default when the item has none).
    pub port: u16,
    /// Logon type: anonymous, normal, ask for password, interactive or
    /// agent (a key file or an FTP account is stored as "ask for password").
    pub logon: LogonKind,
    /// User name (`""` for anonymous).
    pub user: String,
    /// The password (Normal only, and only with `vault.store_passwords`).
    pub password: Option<SecretString>,
    /// Last use.
    pub used_at: UnixMillis,
}

impl PartialEq for HistoryEntry {
    /// Everything but the password's value: whether there is one counts.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.vault == other.vault
            && self.protocol == other.protocol
            && self.host == other.host
            && self.port == other.port
            && self.logon == other.logon
            && self.user == other.user
            && self.password.is_some() == other.password.is_some()
            && self.used_at == other.used_at
    }
}

impl HistoryEntry {
    /// An entry (new id) for a login, used now. Only the address and the
    /// logon are kept; a key file path or FTP account is not, and such
    /// logins are stored as "ask for password".
    pub fn from_connect_info(info: &ConnectInfo) -> Self {
        let a = &info.address;
        let (logon, user, password) = match &info.logon {
            LogonType::Anonymous => (LogonKind::Anonymous, String::new(), None),
            LogonType::Normal { user, password } => {
                (LogonKind::Normal, user.clone(), Some(password.clone()))
            }
            LogonType::Interactive { user } => (LogonKind::Interactive, user.clone(), None),
            LogonType::Agent { user } => (LogonKind::Agent, user.clone(), None),
            LogonType::AskForPassword { user }
            | LogonType::KeyFile { user, .. }
            | LogonType::Account { user, .. } => (LogonKind::AskForPassword, user.clone(), None),
        };
        Self {
            id: ItemId::new(),
            vault: None,
            protocol: a.protocol,
            host: a.host.trim().to_owned(),
            port: a.port,
            logon,
            user,
            password,
            used_at: UnixMillis::now(),
        }
    }

    /// Builds the entry from its item view.
    pub fn from_item(id: ItemId, vault: Option<VaultId>, view: &item::HistoryEntry) -> Self {
        Self {
            id,
            vault,
            protocol: view.protocol,
            host: view.host.clone(),
            port: view.port.unwrap_or_else(|| view.protocol.default_port()),
            logon: view.logon,
            user: view.user.clone(),
            password: view
                .password
                .clone()
                .filter(|_| view.logon == LogonKind::Normal),
            used_at: view.used_at.unwrap_or_default(),
        }
    }

    /// The item view.
    pub fn to_item(&self) -> item::HistoryEntry {
        let mut v = item::HistoryEntry::new(self.protocol, self.host.clone());
        v.port = Some(self.port);
        v.logon = self.logon;
        v.user.clone_from(&self.user);
        v.password = self
            .password
            .clone()
            .filter(|_| self.logon == LogonKind::Normal);
        v.used_at = Some(self.used_at);
        v
    }

    /// The deduplication key: protocol, host (case-insensitive), port, user.
    pub fn key(&self) -> (Protocol, String, u16, &str) {
        (
            self.protocol,
            self.host.to_lowercase(),
            self.port,
            self.user.as_str(),
        )
    }

    /// The server address.
    pub fn address(&self) -> ServerAddress {
        ServerAddress {
            protocol: self.protocol,
            host: self.host.clone(),
            port: self.port,
            user: (self.logon != LogonKind::Anonymous).then(|| self.user.clone()),
        }
    }

    /// The logon to connect with: a Normal entry without a stored password
    /// asks for it.
    pub fn logon_type(&self) -> LogonType {
        let user = self.user.clone();
        match (self.logon, &self.password) {
            (LogonKind::Anonymous, _) => LogonType::Anonymous,
            (LogonKind::Normal, Some(password)) => LogonType::Normal {
                user,
                password: password.clone(),
            },
            (LogonKind::Interactive, _) => LogonType::Interactive { user },
            (LogonKind::Agent, _) => LogonType::Agent { user },
            _ => LogonType::AskForPassword { user },
        }
    }

    /// What the `BackendFactory` receives to connect again (default
    /// settings for everything not in the history).
    pub fn to_connect_info(&self) -> ConnectInfo {
        ConnectInfo::new(self.address(), self.logon_type())
    }

    /// "Convert quickconnect entry to site": a new site (new id, top level)
    /// named after the host, with the entry's address and logon (and its
    /// password, if stored). Save it with
    /// [`SiteManager::save_site`](super::SiteManager::save_site), or use
    /// [`SiteManager::add_from_history`](super::SiteManager::add_from_history)
    /// which picks a free name.
    pub fn to_site(&self) -> Site {
        let mut site = Site::new(self.host.clone(), self.protocol, self.host.clone());
        site.port = (self.port != self.protocol.default_port()).then_some(self.port);
        let user = self.user.clone();
        site.logon = match self.logon {
            LogonKind::Anonymous => SiteLogon::Anonymous,
            LogonKind::Normal => SiteLogon::Normal {
                user,
                password: self.password.clone(),
            },
            LogonKind::Interactive => SiteLogon::Interactive { user },
            LogonKind::Agent if self.protocol == Protocol::Sftp => SiteLogon::Agent { user },
            _ => SiteLogon::AskForPassword { user },
        };
        site
    }
}

/// The quickconnect history in the vault.
#[derive(Debug, Clone)]
pub struct History {
    vault: Arc<dyn ItemVault>,
    local: Arc<dyn SiteLocalStore>,
}

impl History {
    /// The history of `vault`; connects are recorded in `local` for the
    /// recent servers list.
    pub fn new(vault: Arc<dyn ItemVault>, local: Arc<dyn SiteLocalStore>) -> Self {
        Self { vault, local }
    }

    /// The entries, most recent first, deduplicated and capped at
    /// [`HISTORY_LIMIT`] (another device may have added more before a sync;
    /// the next [`History::record`] prunes them).
    ///
    /// # Errors
    /// [`SiteError::Vault`] ([`VaultError::Locked`] while locked).
    pub async fn list(&self) -> Result<Vec<HistoryEntry>, SiteError> {
        let (keep, _) = self.split().await?;
        Ok(keep)
    }

    /// Every entry split into the kept ones and the duplicates / overflow.
    async fn split(&self) -> Result<(Vec<HistoryEntry>, Vec<HistoryEntry>), SiteError> {
        let mut all: Vec<HistoryEntry> = self
            .vault
            .list_views::<item::HistoryEntry>()
            .await?
            .into_iter()
            .map(|(it, view)| HistoryEntry::from_item(it.id, Some(it.vault_id), &view))
            .collect();
        all.sort_by_key(|e| (Reverse(e.used_at), Reverse(e.id)));
        let mut keep: Vec<HistoryEntry> = Vec::new();
        let mut drop = Vec::new();
        for e in all {
            if keep.len() >= HISTORY_LIMIT || keep.iter().any(|k| k.key() == e.key()) {
                drop.push(e);
            } else {
                keep.push(e);
            }
        }
        Ok((keep, drop))
    }

    /// Records a successful quickconnect login now: updates the entry with
    /// the same protocol, host, port and user (or adds one; an
    /// "ask for password" login keeps a password stored earlier), drops
    /// duplicates and everything past [`HISTORY_LIMIT`], and marks the entry
    /// connected for the recent servers list. Returns the entry as stored
    /// (without the password when `vault.store_passwords` is off).
    ///
    /// # Errors
    /// [`SiteError::Vault`] ([`VaultError::Locked`] while locked: nothing is
    /// saved), [`SiteError::Local`].
    pub async fn record(&self, info: &ConnectInfo) -> Result<HistoryEntry, SiteError> {
        if !self.vault.is_unlocked().await {
            return Err(SiteError::Vault(VaultError::Locked));
        }
        let mut entry = HistoryEntry::from_connect_info(info);
        let (keep, _) = self.split().await?;
        if let Some(existing) = keep.iter().find(|e| e.key() == entry.key()) {
            entry.id = existing.id;
            entry.vault = existing.vault;
            // A login whose password was asked for (a reconnect) keeps the
            // stored one; "Clear history" or `vault.store_passwords = false`
            // erases it.
            if entry.logon == LogonKind::AskForPassword && existing.password.is_some() {
                entry.logon = LogonKind::Normal;
                entry.password.clone_from(&existing.password);
            }
        }
        // Keep the clock monotonic for ordering even if it went backwards.
        if let Some(newest) = keep.first() {
            entry.used_at = entry
                .used_at
                .max(UnixMillis(newest.used_at.0.saturating_add(1)));
        }
        self.vault
            .put_view(entry.id, entry.vault, entry.to_item())
            .await?;
        self.local.touch_connected(entry.id, entry.used_at).await?;
        let (keep, drop) = self.split().await?;
        for e in drop {
            self.vault.delete(e.id).await?;
            self.local.forget(e.id).await?;
        }
        keep.into_iter()
            .find(|e| e.id == entry.id)
            .ok_or(SiteError::NotFound(entry.id))
    }

    /// Records a reconnect to a history entry (e.g. from the recent servers
    /// list) without changing its logon.
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn touch(&self, id: ItemId) -> Result<(), SiteError> {
        let (keep, _) = self.split().await?;
        let mut entry = keep
            .into_iter()
            .find(|e| e.id == id)
            .ok_or(SiteError::NotFound(id))?;
        entry.used_at = UnixMillis::now();
        self.vault
            .put_view(entry.id, entry.vault, entry.to_item())
            .await?;
        self.local.touch_connected(id, entry.used_at).await
    }

    /// Deletes one entry.
    ///
    /// # Errors
    /// [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn delete(&self, id: ItemId) -> Result<(), SiteError> {
        self.vault.delete(id).await?;
        self.local.forget(id).await
    }

    /// "Clear history": deletes every entry (on every synced device) and
    /// removes them from the recent servers. Returns how many were deleted.
    ///
    /// # Errors
    /// [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn clear(&self) -> Result<usize, SiteError> {
        let items = self.vault.list(item::ItemKind::HistoryEntry).await?;
        for it in &items {
            self.vault.delete(it.id).await?;
            self.local.forget(it.id).await?;
        }
        Ok(items.len())
    }
}

/// What a recent server is.
#[derive(Debug, Clone, PartialEq)]
pub enum RecentTarget {
    /// A Site Manager site (connect with
    /// [`SiteManager::connect`](super::SiteManager::connect)).
    Site(Box<Site>),
    /// A quickconnect history entry.
    Quickconnect(HistoryEntry),
}

/// One entry of the recent servers list.
#[derive(Debug, Clone, PartialEq)]
pub struct RecentServer {
    /// The site's or history entry's id.
    pub id: ItemId,
    /// When this device last connected.
    pub connected_at: UnixMillis,
    /// The site or history entry.
    pub target: RecentTarget,
}

impl RecentServer {
    /// What the UI shows: the site's path in the tree, or `user@host:port`.
    pub fn label(&self, tree: &SiteTree) -> String {
        match &self.target {
            RecentTarget::Site(s) => tree.path_of(s.id).unwrap_or_else(|| s.name.clone()),
            RecentTarget::Quickconnect(e) => {
                let a = e.address();
                let mut out = format!("{}://", a.protocol.scheme());
                if let Some(user) = &a.user {
                    out.push_str(user);
                    out.push('@');
                }
                out.push_str(&a.host_port());
                out
            }
        }
    }
}

/// The recent servers (most recent first, at most [`RECENT_LIMIT`]): the
/// sites in `tree` and the `history` entries this device connected to, by
/// the device-local rows `locals`. Rows of items that no longer exist are
/// ignored.
pub fn recent_servers(
    tree: &SiteTree,
    history: &[HistoryEntry],
    locals: &HashMap<ItemId, SiteLocal>,
) -> Vec<RecentServer> {
    let mut out: Vec<RecentServer> = locals
        .iter()
        .filter_map(|(&id, local)| {
            let at = local.last_connected_at?;
            let target = if let Some(site) = tree.site(id) {
                RecentTarget::Site(Box::new(site.clone()))
            } else {
                RecentTarget::Quickconnect(history.iter().find(|e| e.id == id)?.clone())
            };
            Some(RecentServer {
                id,
                connected_at: at,
                target,
            })
        })
        .collect();
    out.sort_by_key(|r| (Reverse(r.connected_at), Reverse(r.id)));
    out.truncate(RECENT_LIMIT);
    out
}

/// [`recent_servers`] reading the history from the vault and the rows from
/// `local`.
///
/// # Errors
/// [`SiteError::Vault`], [`SiteError::Local`].
pub async fn load_recent_servers(
    tree: &SiteTree,
    history: &History,
) -> Result<Vec<RecentServer>, SiteError> {
    let entries = history.list().await?;
    let locals = history.local.all().await?;
    Ok(recent_servers(tree, &entries, &locals))
}
