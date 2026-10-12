//! Launch intents from the command line (T70): connect to URLs and Site
//! Manager entries at start, and open the local pane in a given directory.
//!
//! Connections wait for the vault: URLs connect once it is unlocked or
//! skipped (the host key store and the credential cache come from it), site
//! paths once the Site Manager has loaded after unlock. The first
//! connection goes into the current tab, each further one into a new tab.
//! When something connects from the command line, the saved tabs are not
//! restored this run.

use std::sync::Arc;

use courier_ftp_core::{events::LogKind, model::item::ItemId, sites::SiteTree};

use super::App;
use crate::{
    action::{Action, ConnectRequest, ConnectTarget},
    cli::Launch,
    ui::{Side, site_manager::site_paths},
};

/// Close matches listed for an unknown site path.
const SUGGESTIONS: usize = 3;

/// What is still to do from the command line.
#[derive(Debug, Default)]
pub(super) struct Pending {
    /// Servers to connect to once the vault is unlocked or skipped.
    urls: Vec<ConnectRequest>,
    /// Site paths to connect to once the sites are loaded.
    sites: Vec<String>,
    /// The local directory for the start listing and for each connection.
    local_dir: Option<courier_ftp_core::model::RemotePath>,
    /// Whether a connection was started (the next goes into a new tab).
    started: bool,
}

impl App {
    /// Hand the command line's launch intents to the app (before
    /// [`App::run`]).
    pub(crate) fn set_launch(&mut self, launch: Launch) {
        if launch.connects() {
            // The command line says what to open: don't add the saved tabs.
            self.tabs.restored = true;
        }
        self.launch = Pending {
            urls: launch.urls,
            sites: launch.sites,
            local_dir: launch.local_dir,
            started: false,
        };
    }

    /// `--no-keyring`: ask for the master password even when the keyring
    /// could unlock the vault.
    pub(crate) fn set_no_keyring(&mut self) {
        self.no_keyring = true;
    }

    /// Start like the event loop does: list the local start directory, open
    /// the vault; without a vault the URLs connect right away.
    pub(crate) fn begin(&mut self) {
        let local = self.launch.local_dir.clone();
        self.list(Side::Local, local, false, false);
        self.start_vault();
        if self.vault.is_none() {
            self.launch_urls();
            self.launch_sites_unavailable("--site needs the vault (started with --no-vault)");
        }
    }

    /// The vault is unlocked or was skipped: connect to the URLs.
    pub(super) fn launch_urls(&mut self) {
        let urls = std::mem::take(&mut self.launch.urls);
        if !urls.is_empty() {
            // As after a quickconnect: the remote list has the keys.
            self.screen.focus_remote_list();
        }
        for mut request in urls {
            if let Some(dir) = &self.launch.local_dir {
                request.local_dir = Some(dir.clone());
            }
            let target = self.launch_target();
            self.connect(request, target);
        }
    }

    /// Where the next launch connection goes: the current tab (unless it
    /// is connected) for the first, a new tab for the others.
    fn launch_target(&mut self) -> ConnectTarget {
        if std::mem::replace(&mut self.launch.started, true) {
            ConnectTarget::NewTab
        } else {
            ConnectTarget::Ask
        }
    }

    /// Site paths can't be opened (vault skipped, sites failed to load):
    /// say so. They stay pending, so unlocking later still connects.
    pub(super) fn launch_sites_unavailable(&mut self, why: &str) {
        if self.launch.sites.is_empty() {
            return;
        }
        let text = format!("{why}: not connecting to {}", self.launch.sites.join(", "));
        self.events_tx
            .log(self.local_session, LogKind::Error, &text);
        self.screen.flash(&text);
    }

    /// Launch hooks on actions: the Site Manager has loaded.
    pub(super) fn launch_action(&mut self, action: &Action) {
        let Action::SitesReply(reply) = action else {
            return;
        };
        if self.launch.sites.is_empty() {
            return;
        }
        match &reply.0.snapshot {
            Some(snapshot) => {
                let tree = snapshot.tree.clone();
                self.launch_sites(&tree);
            }
            None => self.launch_sites_unavailable("The sites could not be loaded"),
        }
    }

    /// Connect to the site paths found in `tree`, in order; unknown paths
    /// are reported with close matches.
    fn launch_sites(&mut self, tree: &SiteTree) {
        let mut found: Vec<(ItemId, ConnectTarget)> = Vec::new();
        for path in std::mem::take(&mut self.launch.sites) {
            match tree.find_site(&path) {
                Some(site) => {
                    let target = self.launch_target();
                    found.push((site.id, target));
                }
                None => {
                    let text = unknown_site(tree, &path);
                    self.events_tx
                        .log(self.local_session, LogKind::Error, &text);
                    self.screen.flash(&text);
                }
            }
        }
        if found.is_empty() {
            return;
        }
        self.screen.focus_remote_list();
        // One task, so the connections start in command-line order.
        let slot = Arc::clone(&self.sites);
        let tx = self.action_tx.clone();
        let local_dir = self.launch.local_dir.clone();
        tokio::spawn(async move {
            for (id, target) in found {
                let action = match crate::sites::connect(&slot, id).await {
                    Ok(site) => {
                        let mut request = super::site_request(site, id);
                        if local_dir.is_some() {
                            request.local_dir = local_dir.clone();
                        }
                        Action::Connect {
                            request: Box::new(request),
                            target,
                        }
                    }
                    Err(e) => Action::Error(format!("Could not connect to the site: {e}")),
                };
                let _ = tx.send(action);
            }
        });
    }
}

/// "No site …", with up to [`SUGGESTIONS`] close matches.
fn unknown_site(tree: &SiteTree, path: &str) -> String {
    let close = close_matches(tree, path);
    if close.is_empty() {
        format!("No site \"{path}\" in the Site Manager")
    } else {
        format!(
            "No site \"{path}\" in the Site Manager. Did you mean: {}?",
            close.join(", ")
        )
    }
}

/// The site paths closest to `path`: those the picker's fuzzy match
/// accepts (best first), else those within a small edit distance of it.
pub(super) fn close_matches(tree: &SiteTree, path: &str) -> Vec<String> {
    let paths = site_paths(tree);
    let mut scored: Vec<(i64, &str)> = paths
        .iter()
        .filter_map(|(_, p)| {
            crate::ui::site_manager::score(path, p).map(|score| (score, p.as_str()))
        })
        .collect();
    if scored.is_empty() {
        let wanted = path.trim_matches('/').to_lowercase();
        let limit = (wanted.chars().count() / 3).max(2);
        scored = paths
            .iter()
            .filter_map(|(_, p)| {
                let lower = p.to_lowercase();
                let name = lower.rsplit('/').next().unwrap_or(&lower);
                let distance = edit_distance(&wanted, &lower).min(edit_distance(&wanted, name));
                (distance <= limit).then(|| (-(distance as i64), p.as_str()))
            })
            .collect();
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(SUGGESTIONS)
        .map(|(_, p)| p.to_owned())
        .collect()
}

/// Levenshtein distance over characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = if ca == *cb {
                prev
            } else {
                1 + prev.min(cur).min(row[j])
            };
            prev = cur;
        }
    }
    row[b.len()]
}

#[cfg(test)]
mod tests {
    use super::edit_distance;

    #[test]
    fn edit_distances() {
        assert_eq!(edit_distance("web01", "web01"), 0);
        assert_eq!(edit_distance("wbe01", "web01"), 2);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }
}
