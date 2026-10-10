//! [`RecursiveExpander`]: lazy, one level at a time, expansion of directory
//! placeholders in the queue.

use std::{
    collections::HashMap,
    sync::{Mutex, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::{
    DEFAULT_MAX_DEPTH, group_thousands, is_fatal, timed,
    walk::{WalkOptions, list_dir, symlink_target_kind},
};
use crate::{
    Error, Result,
    backend::Backend,
    cache::ListingCache,
    events::{EventSender, LogKind, SessionId},
    filters::{FilterEngine, Side},
    local::{local_to_remote, remote_to_local, sanitize_local_name},
    model::{Direction, EntryKind, LocalPath, RemotePath},
    queue::{NewItem, QueueItem, QueueServer, ServerKey},
    settings::{EmptyDirs, Settings},
    transfer::DirExpander,
};

/// A placeholder for a whole directory (download: `remote` → `local`,
/// upload: `local` → `remote`), expanded by the [`RecursiveExpander`] when
/// the engine reaches it. Add it with
/// [`Queue::add`](crate::queue::Queue::add).
pub fn dir_placeholder(
    server: QueueServer,
    direction: Direction,
    local: impl Into<LocalPath>,
    remote: impl Into<RemotePath>,
) -> NewItem {
    NewItem {
        is_dir_placeholder: true,
        ..NewItem::file(server, direction, local, remote, None)
    }
}

#[derive(Debug, Clone)]
struct Config {
    empty_dirs: EmptyDirs,
    follow_symlinks: bool,
    replace_invalid_chars: bool,
    replacement: char,
    timeout: Duration,
    max_depth: usize,
    local_filter: FilterEngine,
    remote_filter: FilterEngine,
}

impl Config {
    fn from_settings(settings: &Settings, max_depth: usize) -> Self {
        let t = &settings.transfers;
        let (local_filter, mut warnings) =
            FilterEngine::from_settings(&settings.filters, Side::Local);
        let (remote_filter, more) = FilterEngine::from_settings(&settings.filters, Side::Remote);
        warnings.extend(more);
        for w in warnings {
            tracing::debug!("recursive transfers: {w}");
        }
        Self {
            empty_dirs: t.empty_dirs,
            follow_symlinks: t.follow_symlinks,
            replace_invalid_chars: t.replace_invalid_chars,
            replacement: t.invalid_char_replacement,
            timeout: Duration::from_secs(settings.connection.timeout_secs.max(1)),
            max_depth,
            local_filter,
            remote_filter,
        }
    }
}

/// The engine's [`DirExpander`] (T43): lists one directory level of a
/// placeholder and returns its files plus one placeholder per
/// subdirectory, in name order, files first.
///
/// - Filters of the source side (remote for downloads, local for uploads)
///   apply: excluded entries are not queued, excluded directories not
///   descended; the count is logged.
/// - The target directory is created (with its missing parents) when the
///   level has files to put there, or when it is empty and
///   `transfers.empty_dirs` is `create`. A level with only subdirectories
///   gets created by them, so with `skip` no empty directory appears.
/// - Symlinks to files are queued as files. Symlinked directories are
///   descended only with `transfers.follow_symlinks`, and not when the
///   link leads back to a directory above it (canonical paths locally; the
///   link targets resolved against the real path remotely). As a backstop,
///   paths deeper than [`DEFAULT_MAX_DEPTH`] components fail.
/// - Downloaded names get `transfers.replace_invalid_chars` applied.
/// - Children inherit the placeholder's transfer type, priority and
///   file-exists override.
///
/// Built with [`RecursiveExpander::new`]; call
/// [`RecursiveExpander::apply_settings`] when the settings change.
#[derive(Debug)]
pub struct RecursiveExpander {
    config: RwLock<Config>,
    events: Option<EventSender>,
    session: SessionId,
    cache: Option<ListingCache>,
    /// Followed remote symlinked directories: logical path → real path.
    links: Mutex<HashMap<(ServerKey, RemotePath), RemotePath>>,
}

impl RecursiveExpander {
    /// An expander configured from `settings` (transfer options, timeout,
    /// filters).
    pub fn new(settings: &Settings) -> Self {
        Self {
            config: RwLock::new(Config::from_settings(settings, DEFAULT_MAX_DEPTH)),
            events: None,
            session: SessionId(0),
            cache: None,
            links: Mutex::new(HashMap::new()),
        }
    }

    /// Log filtered counts, loops and skipped links to the message log
    /// under `session`.
    pub fn with_events(mut self, events: EventSender, session: SessionId) -> Self {
        self.events = Some(events);
        self.session = session;
        self
    }

    /// Store listings in `cache` and invalidate the directories it creates.
    pub fn with_cache(mut self, cache: ListingCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Apply changed settings (including the filters).
    pub fn apply_settings(&self, settings: &Settings) {
        let max_depth = self.config().max_depth;
        *self.config.write().unwrap_or_else(|e| e.into_inner()) =
            Config::from_settings(settings, max_depth);
    }

    /// Replace the filters (local side for uploads, remote for downloads).
    pub fn set_filters(&self, local: FilterEngine, remote: FilterEngine) {
        let mut config = self.config.write().unwrap_or_else(|e| e.into_inner());
        config.local_filter = local;
        config.remote_filter = remote;
    }

    /// Change the depth backstop (path components).
    pub fn set_max_depth(&self, max_depth: usize) {
        self.config
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .max_depth = max_depth;
    }

    fn config(&self) -> Config {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn log(&self, kind: LogKind, text: String) {
        if let Some(events) = &self.events {
            events.log(self.session, kind, text);
        }
    }

    fn links(&self) -> std::sync::MutexGuard<'_, HashMap<(ServerKey, RemotePath), RemotePath>> {
        self.links.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The real path of remote `dir`, given the links followed so far.
    fn remote_real(&self, key: &ServerKey, dir: &RemotePath) -> RemotePath {
        let links = self.links();
        let mut anc = Some(dir.clone());
        while let Some(a) = anc {
            if let Some(real) = links.get(&(key.clone(), a.clone())) {
                let rest = dir.strip_prefix(&a).unwrap_or("");
                return if rest.is_empty() {
                    real.clone()
                } else {
                    real.join_path(rest)
                };
            }
            anc = a.parent();
        }
        dir.clone()
    }

    /// Whether following the symlinked directory `link` (in `dir`, pointing
    /// at `target`) leads back to `dir` or above. Records the link's real
    /// path otherwise (remote).
    async fn is_loop(
        &self,
        native: bool,
        key: &ServerKey,
        dir: &RemotePath,
        link: &RemotePath,
        target: Option<&str>,
    ) -> bool {
        if native {
            let (Some(d), Some(l)) = (remote_to_local(dir), remote_to_local(link)) else {
                return false;
            };
            return match (
                tokio::fs::canonicalize(d).await,
                tokio::fs::canonicalize(l).await,
            ) {
                (Ok(d), Ok(l)) => d.starts_with(l),
                _ => false,
            };
        }
        let Some(target) = target else {
            // Unknown target: only the depth limit protects.
            return false;
        };
        let real_dir = self.remote_real(key, dir);
        let real_target = real_dir.join_path(target);
        if real_dir.starts_with(&real_target) {
            return true;
        }
        self.links()
            .insert((key.clone(), link.clone()), real_target);
        false
    }
}

#[async_trait]
impl DirExpander for RecursiveExpander {
    async fn expand(
        &self,
        item: &QueueItem,
        remote: &mut dyn Backend,
        local: &mut dyn Backend,
        cancel: &CancellationToken,
    ) -> Result<Vec<NewItem>> {
        let cfg = self.config();
        let local_dir = local_to_remote(item.local.as_path())?;
        if item.direction == Direction::Download {
            let dirs = (item.remote.clone(), local_dir);
            self.expand_level(item, &cfg, remote, local, dirs, cancel)
                .await
        } else {
            let dirs = (local_dir, item.remote.clone());
            self.expand_level(item, &cfg, local, remote, dirs, cancel)
                .await
        }
    }
}

impl RecursiveExpander {
    /// One level: list `src_dir` on `src`, create `dst_dir` on `dst` when
    /// needed.
    async fn expand_level(
        &self,
        item: &QueueItem,
        cfg: &Config,
        src: &mut dyn Backend,
        dst: &mut dyn Backend,
        (src_dir, dst_dir): (RemotePath, RemotePath),
        cancel: &CancellationToken,
    ) -> Result<Vec<NewItem>> {
        let download = item.direction == Direction::Download;
        let filter = if download {
            &cfg.remote_filter
        } else {
            &cfg.local_filter
        };
        if src_dir.components().count() > cfg.max_depth {
            return Err(Error::InvalidInput(format!(
                "{src_dir} is more than {} levels deep",
                cfg.max_depth
            )));
        }
        let mut opts = WalkOptions::remote(self.session);
        opts.timeout = cfg.timeout;
        opts.cache = self.cache.clone();
        let entries = list_dir(src, &src_dir, &opts, cancel).await?;
        let key = item.server.key();

        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let mut filtered = 0u64;
        let mut links_skipped = 0u64;
        for entry in entries {
            let Ok(src_path) = src_dir.join(&entry.name) else {
                continue;
            };
            if filter.excluded(&entry, src_path.as_str()) {
                filtered += 1;
                continue;
            }
            let is_dir = match &entry.kind {
                EntryKind::Dir => true,
                EntryKind::File => false,
                EntryKind::Other => {
                    tracing::debug!("not transferring a special file");
                    continue;
                }
                EntryKind::Symlink { target, .. } => {
                    match symlink_target_kind(src, &src_path, &entry, cfg.timeout, cancel).await? {
                        Some(true) if !cfg.follow_symlinks => {
                            links_skipped += 1;
                            continue;
                        }
                        Some(true) => {
                            if self
                                .is_loop(!download, &key, &src_dir, &src_path, target.as_deref())
                                .await
                            {
                                self.log(
                                    LogKind::Status,
                                    format!(
                                        "Not following {src_path}: the link leads back into the \
                                         tree (loop)"
                                    ),
                                );
                                continue;
                            }
                            true
                        }
                        Some(false) | None => false,
                    }
                }
            };
            let name = if download && cfg.replace_invalid_chars {
                sanitize_local_name(&entry.name, cfg.replacement)
            } else {
                entry.name.clone()
            };
            let Ok(dst_path) = dst_dir.join(&name) else {
                self.log(
                    LogKind::Error,
                    format!("Skipping {src_path}: its name is not valid on the target"),
                );
                continue;
            };
            let (local_path, remote_path) = if download {
                (remote_to_local(&dst_path), src_path)
            } else {
                (remote_to_local(&src_path), dst_path)
            };
            let Some(local_path) = local_path else {
                continue;
            };
            let mut child = NewItem::file(
                item.server.clone(),
                item.direction,
                LocalPath::new(local_path),
                remote_path,
                if is_dir { None } else { entry.size },
            );
            child.transfer_type = item.transfer_type;
            child.priority = item.priority;
            child.on_exists = item.on_exists;
            child.is_dir_placeholder = is_dir;
            if is_dir {
                dirs.push(child);
            } else {
                files.push(child);
            }
        }

        let empty = files.is_empty() && dirs.is_empty();
        if !files.is_empty() || (empty && cfg.empty_dirs == EmptyDirs::Create) {
            ensure_dir(dst, &dst_dir, self.cache.as_ref(), cfg.timeout, cancel).await?;
        }
        if filtered > 0 {
            self.log(
                LogKind::Status,
                format!(
                    "{} entries in {src_dir} excluded by filters",
                    group_thousands(filtered)
                ),
            );
        }
        if links_skipped > 0 {
            self.log(
                LogKind::Status,
                format!(
                    "{} symlinked directories in {src_dir} not followed",
                    group_thousands(links_skipped)
                ),
            );
        }
        files.extend(dirs);
        Ok(files)
    }
}

/// `mkdir -p`: create `dir` and its missing parents.
async fn ensure_dir(
    backend: &mut dyn Backend,
    dir: &RemotePath,
    cache: Option<&ListingCache>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut missing = Vec::new();
    let mut cur = Some(dir.clone());
    while let Some(path) = cur {
        match timed(timeout, cancel, backend.stat(&path)).await {
            Ok(e) if e.is_dir_like() => break,
            Ok(_) => {
                return Err(Error::InvalidInput(format!(
                    "{path} exists and is not a directory"
                )));
            }
            Err(e) if is_fatal(&e) => return Err(e),
            Err(Error::NotFound(_)) => {
                cur = path.parent();
                missing.push(path);
            }
            Err(_) => {
                // Can't tell (some servers don't stat directories): try to
                // create it and assume the parents exist.
                missing.push(path);
                break;
            }
        }
    }
    for path in missing.into_iter().rev() {
        match timed(timeout, cancel, backend.mkdir(&path)).await {
            Ok(()) | Err(Error::AlreadyExists) => {}
            Err(e) => return Err(e),
        }
        if let (Some(cache), Some(parent)) = (cache, path.parent()) {
            cache.invalidate(backend.address(), &parent);
        }
    }
    Ok(())
}
