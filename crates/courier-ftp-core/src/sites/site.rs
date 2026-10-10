//! [`Site`]: one Site Manager entry, its logon and its conversion to a
//! [`ConnectInfo`].

use secrecy::{ExposeSecret, SecretString};
use time::Duration;

use crate::backend::{ConnectInfo, KeySource, ProxyChoice, StoredSecret, VaultKey};
use crate::model::item::{
    self, ItemId, LogonKind, ServerType, SiteColor, SiteTransferMode, SshKey, UnixMillis, VaultId,
};
use crate::model::{
    Charset, FtpEncryption, LocalPath, LogonType, PathStyle, Protocol, RemotePath, ServerAddress,
};
use crate::settings::FtpTransferMode;

use super::SiteError;

/// A Site Manager entry: every setting FileZilla has per site, grouped by
/// its tabs. Stored as a `site` item (synced) plus a device-local row
/// ([`SiteLocal`]: default local directory, key file path, last connect).
///
/// `Debug` doesn't show passwords or passphrases.
#[derive(Debug, Clone, PartialEq)]
pub struct Site {
    /// The `site` item's id.
    pub id: ItemId,
    /// The vault the item lives in; `None` for a site not saved yet (it
    /// goes into its folder's vault, the personal vault at the top level).
    pub vault: Option<VaultId>,
    /// The folder it is in (`None` = top level).
    pub parent: Option<ItemId>,
    /// Name in the tree (no `/`).
    pub name: String,

    // ---- General
    /// Protocol.
    pub protocol: Protocol,
    /// FTP encryption (FTP protocols only; `None` = the protocol's default).
    pub encryption: Option<FtpEncryption>,
    /// Host name or IP address.
    pub host: String,
    /// Port (`None` = the protocol's default).
    pub port: Option<u16>,
    /// Logon type with user, password, account and key (secrets stay inside
    /// the encrypted item).
    pub logon: SiteLogon,
    /// Tab and pane accent colour.
    pub color: SiteColor,
    /// Free text.
    pub comments: String,

    // ---- Advanced
    /// Listing format override.
    pub server_type: ServerType,
    /// Connect directly, not through the configured proxies.
    pub bypass_proxy: bool,
    /// Local directory to open on connect (device-local).
    pub default_local_dir: Option<LocalPath>,
    /// Remote directory to open on connect.
    pub default_remote_dir: Option<RemotePath>,
    /// Start with synchronized browsing on.
    pub sync_browsing: bool,
    /// Start with directory comparison on.
    pub directory_comparison: bool,
    /// Added to the times the server reports, in minutes (±24 h).
    pub timezone_offset_minutes: i32,

    // ---- Transfer settings
    /// Active/passive override.
    pub transfer_mode: SiteTransferMode,
    /// Simultaneous connections to this server, 1–10 (`None` = the global
    /// limit).
    pub limit_connections: Option<u8>,

    // ---- Charset
    /// File name charset.
    pub charset: Charset,

    // ---- SFTP
    /// Offer the SSH agent's keys before the password (logon type Normal).
    pub try_agent_first: bool,

    // ---- Metadata
    /// When the site was created.
    pub created_at: Option<UnixMillis>,
    /// Last successful connect from this device (device-local).
    pub last_connected_at: Option<UnixMillis>,
    /// The item comes from a newer courier-ftp: show it, don't edit it.
    pub read_only: bool,
}

/// How a site logs in, with the secrets that belong to each logon type.
///
/// Changing the type with [`SiteLogon::with_kind`] keeps the user and drops
/// secrets the new type doesn't have, so saving erases them from the item
/// (T31 §5). A `None` password means "not stored" (e.g. with
/// `vault.store_passwords = false`): connecting then asks for it, like
/// [`SiteLogon::AskForPassword`].
#[derive(Debug, Clone)]
pub enum SiteLogon {
    /// User `anonymous`.
    Anonymous,
    /// User and saved password.
    Normal {
        /// User name.
        user: String,
        /// Password (`None` = asked on connect).
        password: Option<SecretString>,
    },
    /// User saved; the password is asked on every connect.
    AskForPassword {
        /// User name.
        user: String,
    },
    /// Every prompt is asked.
    Interactive {
        /// User name.
        user: String,
    },
    /// SFTP public key.
    KeyFile {
        /// User name.
        user: String,
        /// The key (`None` only while editing; validation refuses it).
        key: Option<SiteKey>,
        /// The key's passphrase (`None` = asked when the key is encrypted).
        passphrase: Option<SecretString>,
    },
    /// FTP `USER`/`PASS`/`ACCT`.
    Account {
        /// User name.
        user: String,
        /// Password (`None` = asked on connect).
        password: Option<SecretString>,
        /// The `ACCT` value.
        account: String,
    },
    /// SFTP through the SSH agent.
    Agent {
        /// User name.
        user: String,
    },
}

impl Default for SiteLogon {
    fn default() -> Self {
        Self::Normal {
            user: String::new(),
            password: None,
        }
    }
}

impl PartialEq for SiteLogon {
    /// Plain comparison including secrets: for dirty tracking, not
    /// authentication.
    fn eq(&self, other: &Self) -> bool {
        fn same(a: Option<&SecretString>, b: Option<&SecretString>) -> bool {
            a.map(ExposeSecret::expose_secret) == b.map(ExposeSecret::expose_secret)
        }
        match (self, other) {
            (Self::Anonymous, Self::Anonymous) => true,
            (
                Self::Normal {
                    user: a,
                    password: pa,
                },
                Self::Normal {
                    user: b,
                    password: pb,
                },
            ) => a == b && same(pa.as_ref(), pb.as_ref()),
            (Self::AskForPassword { user: a }, Self::AskForPassword { user: b })
            | (Self::Interactive { user: a }, Self::Interactive { user: b })
            | (Self::Agent { user: a }, Self::Agent { user: b }) => a == b,
            (
                Self::KeyFile {
                    user: a,
                    key: ka,
                    passphrase: pa,
                },
                Self::KeyFile {
                    user: b,
                    key: kb,
                    passphrase: pb,
                },
            ) => a == b && ka == kb && same(pa.as_ref(), pb.as_ref()),
            (
                Self::Account {
                    user: a,
                    password: pa,
                    account: aa,
                },
                Self::Account {
                    user: b,
                    password: pb,
                    account: ab,
                },
            ) => a == b && aa == ab && same(pa.as_ref(), pb.as_ref()),
            _ => false,
        }
    }
}

impl SiteLogon {
    /// The logon type.
    pub fn kind(&self) -> LogonKind {
        match self {
            Self::Anonymous => LogonKind::Anonymous,
            Self::Normal { .. } => LogonKind::Normal,
            Self::AskForPassword { .. } => LogonKind::AskForPassword,
            Self::Interactive { .. } => LogonKind::Interactive,
            Self::KeyFile { .. } => LogonKind::KeyFile,
            Self::Account { .. } => LogonKind::Account,
            Self::Agent { .. } => LogonKind::Agent,
        }
    }

    /// The user name (`""` for anonymous).
    pub fn user(&self) -> &str {
        match self {
            Self::Anonymous => "",
            Self::Normal { user, .. }
            | Self::AskForPassword { user }
            | Self::Interactive { user }
            | Self::KeyFile { user, .. }
            | Self::Account { user, .. }
            | Self::Agent { user } => user,
        }
    }

    /// The saved password (Normal and Account).
    pub fn password(&self) -> Option<&SecretString> {
        match self {
            Self::Normal { password, .. } | Self::Account { password, .. } => password.as_ref(),
            _ => None,
        }
    }

    /// The same logon as type `kind`: the user is kept, and the password is
    /// kept between Normal and Account; everything the new type doesn't
    /// have is dropped.
    #[must_use]
    pub fn with_kind(self, kind: LogonKind) -> Self {
        if self.kind() == kind {
            return self;
        }
        let user = self.user().to_owned();
        let password = match &self {
            Self::Normal { password, .. } | Self::Account { password, .. } => password.clone(),
            _ => None,
        };
        match kind {
            LogonKind::Anonymous => Self::Anonymous,
            LogonKind::Normal => Self::Normal { user, password },
            LogonKind::AskForPassword => Self::AskForPassword { user },
            LogonKind::Interactive => Self::Interactive { user },
            LogonKind::KeyFile => Self::KeyFile {
                user,
                key: None,
                passphrase: None,
            },
            LogonKind::Account => Self::Account {
                user,
                password,
                account: String::new(),
            },
            LogonKind::Agent => Self::Agent { user },
        }
    }
}

/// Where a key-file login's private key is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SiteKey {
    /// A key file on this device. Device-local: other devices set their own
    /// path (or use a vault key).
    File(LocalPath),
    /// An `ssh-key` item in the vault (T81), so the site works on every
    /// synced device.
    Vault(ItemId),
}

/// A site's device-local data (store `device_local` table, T82): never
/// synced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteLocal {
    /// Default local directory on this device.
    pub default_local_dir: Option<LocalPath>,
    /// Key file path on this device (for [`SiteKey::File`]).
    pub key_path: Option<LocalPath>,
    /// Last successful connect from this device.
    pub last_connected_at: Option<UnixMillis>,
}

/// What connecting to a site needs: the [`ConnectInfo`] for the
/// `BackendFactory`, plus what to do once connected (T59 §5).
#[derive(Debug, Clone, PartialEq)]
pub struct SiteConnect {
    /// The site.
    pub site_id: ItemId,
    /// For `BackendFactory::create`.
    pub info: ConnectInfo,
    /// Remote directory to open instead of the home directory.
    pub remote_dir: Option<RemotePath>,
    /// Local directory to open.
    pub local_dir: Option<LocalPath>,
    /// Turn synchronized browsing on.
    pub sync_browsing: bool,
    /// Turn directory comparison on.
    pub directory_comparison: bool,
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.trim().is_empty())
}

impl Site {
    /// A new site (new id) with every other field at its default and the
    /// default logon (Normal, no user yet).
    pub fn new(name: impl Into<String>, protocol: Protocol, host: impl Into<String>) -> Self {
        Self::from_item(
            ItemId::new(),
            None,
            &item::Site::new(name, protocol, host),
            &SiteLocal::default(),
        )
    }

    /// Builds the site from its item view and device-local row. A key-file
    /// login uses the vault key when the item names one, else this device's
    /// key path, else a path stored in the item (written by older builds).
    pub fn from_item(
        id: ItemId,
        vault: Option<VaultId>,
        view: &item::Site,
        local: &SiteLocal,
    ) -> Self {
        let user = view.user.clone();
        let logon = match view.logon {
            LogonKind::Anonymous => SiteLogon::Anonymous,
            LogonKind::Normal => SiteLogon::Normal {
                user,
                password: view.password.clone(),
            },
            LogonKind::AskForPassword => SiteLogon::AskForPassword { user },
            LogonKind::Interactive => SiteLogon::Interactive { user },
            LogonKind::KeyFile => SiteLogon::KeyFile {
                user,
                key: view
                    .key_id
                    .map(SiteKey::Vault)
                    .or_else(|| local.key_path.clone().map(SiteKey::File))
                    .or_else(|| {
                        non_empty(view.key_path.clone()).map(|p| SiteKey::File(LocalPath::new(p)))
                    }),
                passphrase: view.passphrase.clone(),
            },
            LogonKind::Account => SiteLogon::Account {
                user,
                password: view.password.clone(),
                account: view.account.clone().unwrap_or_default(),
            },
            LogonKind::Agent => SiteLogon::Agent { user },
        };
        Self {
            id,
            vault,
            parent: view.parent,
            name: view.name.clone(),
            protocol: view.protocol,
            encryption: view.encryption,
            host: view.host.clone(),
            port: view.port,
            logon,
            color: view.color,
            comments: view.comments.clone(),
            server_type: view.server_type,
            bypass_proxy: view.bypass_proxy,
            default_local_dir: local.default_local_dir.clone(),
            default_remote_dir: non_empty(view.default_remote_dir.clone()).map(RemotePath::new),
            sync_browsing: view.sync_browsing,
            directory_comparison: view.directory_comparison,
            timezone_offset_minutes: view.timezone_offset_minutes,
            transfer_mode: view.transfer_mode,
            limit_connections: view.limit_connections,
            charset: view.charset,
            try_agent_first: view.try_agent_first,
            created_at: view.created_at,
            last_connected_at: local.last_connected_at,
            read_only: view.read_only,
        }
    }

    /// The synced part, as the `site` item view. Fields the logon type
    /// doesn't use are `None`, so writing it erases them (T31 §5); a local
    /// key path is not in it ([`Site::local`]).
    pub fn to_item(&self) -> item::Site {
        let mut v = item::Site::new(self.name.clone(), self.protocol, self.host.clone());
        v.parent = self.parent;
        v.encryption = self.encryption.filter(|_| self.protocol != Protocol::Sftp);
        v.port = self.port;
        v.logon = self.logon.kind();
        v.user = self.logon.user().to_owned();
        match &self.logon {
            SiteLogon::Normal { password, .. } => v.password.clone_from(password),
            SiteLogon::Account {
                password, account, ..
            } => {
                v.password.clone_from(password);
                v.account = Some(account.clone()).filter(|a| !a.is_empty());
            }
            SiteLogon::KeyFile {
                key, passphrase, ..
            } => {
                if let Some(SiteKey::Vault(id)) = key {
                    v.key_id = Some(*id);
                }
                v.passphrase.clone_from(passphrase);
            }
            SiteLogon::Anonymous
            | SiteLogon::AskForPassword { .. }
            | SiteLogon::Interactive { .. }
            | SiteLogon::Agent { .. } => {}
        }
        v.try_agent_first = self.try_agent_first;
        v.color = self.color;
        v.comments.clone_from(&self.comments);
        v.server_type = self.server_type;
        v.bypass_proxy = self.bypass_proxy;
        v.default_remote_dir = self
            .default_remote_dir
            .as_ref()
            .map(|p| p.as_str().to_owned());
        v.sync_browsing = self.sync_browsing;
        v.directory_comparison = self.directory_comparison;
        v.timezone_offset_minutes = self.timezone_offset_minutes;
        v.transfer_mode = self.transfer_mode;
        v.limit_connections = self.limit_connections;
        v.charset = self.charset;
        v.created_at = self.created_at;
        v.read_only = self.read_only;
        v
    }

    /// The device-local part.
    pub fn local(&self) -> SiteLocal {
        SiteLocal {
            default_local_dir: self.default_local_dir.clone(),
            key_path: match &self.logon {
                SiteLogon::KeyFile {
                    key: Some(SiteKey::File(path)),
                    ..
                } => Some(path.clone()),
                _ => None,
            },
            last_connected_at: self.last_connected_at,
        }
    }

    /// The port to connect to.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.protocol.default_port())
    }

    /// The vault `ssh-key` item this site logs in with, if any.
    pub fn vault_key_id(&self) -> Option<ItemId> {
        match &self.logon {
            SiteLogon::KeyFile {
                key: Some(SiteKey::Vault(id)),
                ..
            } => Some(*id),
            _ => None,
        }
    }

    /// Builds what the `BackendFactory` receives (T31 §3). `vault_key` is
    /// the `ssh-key` item named by [`Site::vault_key_id`] (the
    /// [`SiteManager`](super::SiteManager) reads it from the vault).
    ///
    /// - Secrets come from the site: a missing password turns Normal (and
    ///   Account) into "ask for password"; a missing key passphrase falls
    ///   back to the vault key's saved one, else it is asked.
    /// - "Default" settings stay `None` so the backend uses the global
    ///   settings: transfer mode, connection limit, encryption.
    /// - Server types without a [`PathStyle`] of their own (NetWare, AS/400)
    ///   use Unix paths; their listing format is still auto-detected.
    ///
    /// # Errors
    /// [`SiteError::Invalid`] for a key login without a key,
    /// [`SiteError::KeyMissing`] when the site names a vault key and
    /// `vault_key` is `None`.
    pub fn to_connect_info(&self, vault_key: Option<&SshKey>) -> Result<ConnectInfo, SiteError> {
        let mut key = None;
        let mut passphrase = None;
        let logon = match &self.logon {
            SiteLogon::Anonymous => LogonType::Anonymous,
            SiteLogon::Normal {
                user,
                password: Some(password),
            } => LogonType::Normal {
                user: user.clone(),
                password: password.clone(),
            },
            SiteLogon::Normal {
                user,
                password: None,
            }
            | SiteLogon::Account {
                user,
                password: None,
                ..
            }
            | SiteLogon::AskForPassword { user } => {
                LogonType::AskForPassword { user: user.clone() }
            }
            SiteLogon::Interactive { user } => LogonType::Interactive { user: user.clone() },
            SiteLogon::Account {
                user,
                password: Some(password),
                account,
            } => LogonType::Account {
                user: user.clone(),
                password: password.clone(),
                account: account.clone(),
            },
            SiteLogon::Agent { user } => LogonType::Agent { user: user.clone() },
            SiteLogon::KeyFile {
                user,
                key: site_key,
                passphrase: saved,
            } => {
                passphrase.clone_from(saved);
                match site_key {
                    Some(SiteKey::File(path)) => LogonType::KeyFile {
                        user: user.clone(),
                        path: path.clone(),
                    },
                    Some(SiteKey::Vault(id)) => {
                        let found = vault_key.ok_or(SiteError::KeyMissing(*id))?;
                        if passphrase.is_none() {
                            passphrase.clone_from(&found.passphrase);
                        }
                        key = Some(KeySource::Vault(VaultKey {
                            id: *id,
                            label: found.label.clone(),
                            private_key: StoredSecret::new(found.private_key.clone()),
                        }));
                        // The explicit key overrides the logon's path; the
                        // label names it in messages.
                        LogonType::KeyFile {
                            user: user.clone(),
                            path: LocalPath::new(&found.label),
                        }
                    }
                    None => {
                        return Err(SiteError::Invalid(
                            self.validate()
                                .into_iter()
                                .filter(|i| i.is_error())
                                .collect(),
                        ));
                    }
                }
            }
        };
        let address = ServerAddress {
            protocol: self.protocol,
            host: self.host.trim().to_owned(),
            port: self.effective_port(),
            user: (!matches!(logon, LogonType::Anonymous)).then(|| logon.user().to_owned()),
        };
        let mut info = ConnectInfo::new(address, logon);
        info.encryption = self.encryption.filter(|_| self.protocol != Protocol::Sftp);
        info.charset = self.charset;
        info.server_type = path_style(self.server_type);
        info.timezone_offset = Duration::minutes(i64::from(self.timezone_offset_minutes));
        info.transfer_mode = match self.transfer_mode {
            SiteTransferMode::Default => None,
            SiteTransferMode::Active => Some(FtpTransferMode::Active),
            SiteTransferMode::Passive => Some(FtpTransferMode::Passive),
        };
        info.proxy = if self.bypass_proxy {
            ProxyChoice::Bypass
        } else {
            ProxyChoice::UseSettings
        };
        info.connection_limit = self.limit_connections.map(u32::from);
        info.key = key;
        info.key_passphrase = passphrase.map(StoredSecret::new);
        info.try_agent_first = self.try_agent_first;
        Ok(info)
    }

    /// [`Site::to_connect_info`] plus the directories and modes to apply
    /// once connected.
    ///
    /// # Errors
    /// As [`Site::to_connect_info`].
    pub fn to_connect(&self, vault_key: Option<&SshKey>) -> Result<SiteConnect, SiteError> {
        Ok(SiteConnect {
            site_id: self.id,
            info: self.to_connect_info(vault_key)?,
            remote_dir: self.default_remote_dir.clone(),
            local_dir: self.default_local_dir.clone(),
            sync_browsing: self.sync_browsing,
            directory_comparison: self.directory_comparison,
        })
    }
}

/// The path style forced by a server type override.
pub fn path_style(server_type: ServerType) -> Option<PathStyle> {
    match server_type {
        ServerType::Auto => None,
        ServerType::Unix | ServerType::NetWare | ServerType::As400 => Some(PathStyle::Unix),
        ServerType::Dos => Some(PathStyle::Dos),
        ServerType::Vms => Some(PathStyle::Vms),
        ServerType::Mvs => Some(PathStyle::Mvs),
    }
}
