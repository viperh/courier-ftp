//! The app side of the file list panes (T53): runs their listing requests on the
//! runner, opens their prompts and menus, saves their settings and routes their
//! inputs.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::BackendContext,
    cache::{CachePolicy, ListingCache},
    events::{EventSender, SessionId},
    settings::SettingsStore,
};

use super::App;
use crate::{
    action::Action,
    components::{
        dialog::prompt_text,
        file_list::{
            FileListPane, PaneDir, PaneId, PaneInput, PaneRequest, Side,
            column_menu::ColumnMenuDialog,
            file_op_action,
            service::{PaneService, list_local, list_remote},
            state::{INPUT_MAX, InterfaceEdit},
        },
        main_screen::layout::Region,
    },
    runtime::TaskOwner,
    tabs::TabId,
};

/// The pane service for a new app.
pub(super) fn pane_service(settings: &SettingsStore, events: &EventSender) -> PaneService {
    let current = settings.current();
    let cache = ListingCache::new(CachePolicy::from_settings(&current.cache), events.clone());
    let ctx = BackendContext {
        session: SessionId::APP,
        events: events.clone(),
        settings: settings.subscribe(),
    };
    PaneService::new(cache, ctx)
}

/// The region of a pane (active tab only until T61).
pub(crate) fn region_of(pane: PaneId) -> Region {
    match pane.side {
        Side::Local => Region::LocalList,
        Side::Remote => Region::RemoteList,
    }
}

/// The two panes of the first tab.
pub(crate) fn panes() -> [PaneId; 2] {
    [
        PaneId {
            tab: TabId::FIRST,
            side: Side::Local,
        },
        PaneId {
            tab: TabId::FIRST,
            side: Side::Remote,
        },
    ]
}

impl App {
    /// Replaces the list placeholders of the first tab with file list panes.
    pub(super) fn install_panes(&mut self) {
        let settings = self.settings.current();
        for id in panes() {
            self.main.set_component(
                region_of(id),
                Box::new(FileListPane::new(id, Arc::clone(&settings))),
            );
        }
    }

    /// Lists the start directory in the local pane (the working directory, else
    /// home). Only the real event loop calls this; tests navigate explicitly.
    pub(super) fn start_panes(&mut self) {
        let dir = std::env::current_dir()
            .ok()
            .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()));
        if let Some(dir) = dir {
            self.queue(Action::PaneInput(
                panes()[0],
                PaneInput::Navigate(PaneDir::Local(courier_ftp_core::model::LocalPath::new(dir))),
            ));
        }
    }

    /// Sends the current settings to every pane.
    pub(super) fn notify_panes_settings(&mut self) {
        for id in panes() {
            self.route_pane_input(id, PaneInput::SettingsChanged);
        }
    }

    /// Delivers `input` to the pane `id`.
    pub(crate) fn route_pane_input(&mut self, id: PaneId, input: PaneInput) {
        let settings = matches!(input, PaneInput::SettingsChanged).then(|| self.settings.current());
        if let Some(c) = self.main.component_mut(region_of(id)) {
            // Components are type-erased: the pane picks up its own id.
            if let Some(s) = settings {
                let _ = c.update(&Action::PaneSettings(id, s));
            } else {
                let _ = c.update(&Action::PaneInput(id, input));
            }
        }
        self.dirty = true;
    }

    /// Carries out a pane request.
    pub(crate) fn handle_pane_request(&mut self, req: PaneRequest) {
        self.dirty = true;
        match req {
            PaneRequest::List {
                pane,
                dir,
                request,
                force,
            } => {
                let timeout =
                    Duration::from_secs(u64::from(self.settings.current().connection.timeout_secs));
                let owner = TaskOwner::Region(region_of(pane));
                let id = match dir {
                    PaneDir::Local(path) => {
                        let ctx = self.panes.local_ctx.clone();
                        self.runner.spawn(owner, move |token| async move {
                            let result = list_local(ctx, path.clone(), timeout, token).await;
                            loaded(pane, request, PaneDir::Local(path), result)
                        })
                    }
                    PaneDir::Remote(path) => {
                        let Some(source) = self.panes.remote.get(&pane).cloned() else {
                            let result =
                                Err(courier_ftp_core::Error::Connection("not connected".into()));
                            self.queue(loaded(pane, request, PaneDir::Remote(path), result));
                            return;
                        };
                        let cache = self.panes.cache.clone();
                        self.runner.spawn(owner, move |token| async move {
                            let result =
                                list_remote(cache, source, path.clone(), force, timeout, token)
                                    .await;
                            loaded(pane, request, PaneDir::Remote(path), result)
                        })
                    }
                };
                self.panes.inflight.retain(|(p, _), _| *p != pane);
                self.panes.inflight.insert((pane, request), id);
            }
            PaneRequest::CancelList { pane, request } => {
                if let Some(id) = self.panes.inflight.remove(&(pane, request)) {
                    self.runner.cancel(id);
                }
            }
            PaneRequest::BuildView {
                pane,
                generation,
                job,
            } => {
                self.runner.spawn(
                    TaskOwner::Region(region_of(pane)),
                    move |_token| async move {
                        match crate::runtime::spawn_blocking(move || job.run()).await {
                            Ok(built) => Action::PaneInput(
                                pane,
                                PaneInput::SortDone {
                                    generation,
                                    view: built.view,
                                    filtered: built.filtered,
                                },
                            ),
                            Err(e) => Action::Error(format!("Sorting failed: {e}")),
                        }
                    },
                );
            }
            PaneRequest::FileOp { op, .. } => {
                // T62/T63 take these over.
                let action = file_op_action(op);
                let what = action
                    .meta()
                    .map_or_else(|| action.to_string(), |m| m.description.to_owned());
                self.status(format!("{what} is not available yet"));
            }
            PaneRequest::MirrorToOtherPane { pane, dir } => {
                self.route_pane_input(pane.other(), PaneInput::MirrorFrom(dir));
            }
            PaneRequest::Notice { pane, text } => {
                self.route_pane_input(pane, PaneInput::Notice(text));
            }
            PaneRequest::PromptPattern { pane, mark } => {
                let (title, label) = if mark {
                    ("Mark files", "Mark files matching:")
                } else {
                    ("Unmark files", "Unmark files matching:")
                };
                let validate: crate::components::widgets::Validator = Arc::new(|s: &str| {
                    if s.chars().count() > INPUT_MAX {
                        Err(format!("At most {INPUT_MAX} characters"))
                    } else {
                        Ok(())
                    }
                });
                self.modals
                    .push_then(prompt_text(title, label, "*", Some(validate)), move |r| {
                        r.map(|glob| Action::PaneInput(pane, PaneInput::Pattern { glob, mark }))
                    });
            }
            PaneRequest::ColumnMenu { pane, columns } => {
                self.modals
                    .push_then(ColumnMenuDialog::new(&columns), move |r| {
                        r.map(|cols| Action::PaneInput(pane, PaneInput::Columns(cols)))
                    });
            }
            PaneRequest::Settings(edit) => {
                self.change_interface(|i| match edit {
                    InterfaceEdit::ShowHiddenLocal(v) => i.show_hidden_local = v,
                    InterfaceEdit::ForceShowHiddenRemote(v) => i.force_show_hidden_remote = v,
                    InterfaceEdit::Sort(Side::Local, s) => i.sort.local = s,
                    InterfaceEdit::Sort(Side::Remote, s) => i.sort.remote = s,
                    InterfaceEdit::Columns(Side::Local, c) => i.columns.local = c,
                    InterfaceEdit::Columns(Side::Remote, c) => i.columns.remote = c,
                });
            }
        }
    }
}

fn loaded(
    pane: PaneId,
    request: crate::components::file_list::state::RequestId,
    asked: PaneDir,
    result: Result<(PaneDir, Arc<courier_ftp_core::backend::Listing>), courier_ftp_core::Error>,
) -> Action {
    let (dir, result) = match result {
        Ok((dir, listing)) => (dir, Ok(listing)),
        Err(e) => (asked, Err(Arc::new(e))),
    };
    Action::PaneInput(
        pane,
        PaneInput::ListingLoaded {
            request,
            dir,
            result,
        },
    )
}
