//! The teams screens of the sync panel (T90 §5, over T89's
//! `courier_ftp_sync::teams::Teams`): the teams (orgs) this account belongs
//! to, a team's members with their roles and safety-number verification,
//! invites (by email or a link to copy), the team's shared vaults with each
//! member's permission, and the audit log. A member whose key changed shows
//! the key-change warning: nothing is shared with them until the new key is
//! accepted.
//!
//! Like the rest of the panel these pages never talk to the network: they
//! ask with [`TeamRequest`]s (inside `SyncRequest::Team`) and get a
//! [`TeamReply`] back through [`super::SyncView::team_reply`].

use std::collections::HashMap;

use courier_ftp_core::model::item::VaultId;
use courier_ftp_proto::{
    orgs::{AuditEventView, InviteCreated, OrgView, Role},
    sync::Permission,
    vaults::VaultMembersView,
};
use courier_ftp_store::PinState;
use courier_ftp_sync::teams::{MemberEntry, OrgVaultEntry};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use uuid::Uuid;

use super::{Canvas, clip, datetime_ms, required};
use crate::ui::{
    dialog::{ButtonRow, Form, FormOutcome, RadioGroup, TextInput},
    theme::Theme,
};

/// A team call for the app to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TeamRequest {
    /// The teams this account belongs to.
    Orgs,
    CreateOrg(String),
    /// A pasted invite link (or bare token).
    AcceptInvite(String),
    /// A team's members, with their keys fetched and pinned.
    Members(Uuid),
    Invite {
        org: Uuid,
        email: Option<String>,
        role: Role,
    },
    SetRole {
        org: Uuid,
        user: Uuid,
        email: String,
        role: Role,
    },
    /// Remove a member (their vaults' keys are rotated).
    Remove {
        org: Uuid,
        user: Uuid,
        email: String,
    },
    /// Leave the team (its vaults leave this device).
    Leave(Uuid),
    /// The safety number with a member.
    Safety {
        user: Uuid,
        email: String,
    },
    Verify {
        user: Uuid,
        email: String,
    },
    /// "Accept the new key" in the key-change warning.
    AcceptKey {
        user: Uuid,
        email: String,
        verified: bool,
    },
    /// The team's shared vaults.
    Vaults(Uuid),
    CreateVault {
        org: Uuid,
        name: String,
    },
    /// A vault's members with their permissions.
    VaultMembers(VaultId),
    Grant {
        vault: VaultId,
        name: String,
        user: Uuid,
        email: String,
        permission: Permission,
    },
    /// Revoke and rotate the vault key.
    Revoke {
        vault: VaultId,
        name: String,
        user: Uuid,
        email: String,
    },
    /// Rotate (or resume an unfinished or abandoned rotation).
    Rotate {
        vault: VaultId,
        name: String,
    },
    Audit(Uuid),
}

/// A member's safety number and trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Safety {
    pub(crate) user: Uuid,
    pub(crate) email: String,
    /// 60 digits in 12 groups of 5 (of the **new** key while a change is
    /// pending).
    pub(crate) number: String,
    pub(crate) state: PinState,
}

/// What a team call returned.
#[derive(Debug, Clone)]
pub(crate) enum TeamReply {
    Orgs(Vec<OrgView>),
    Members(Vec<MemberEntry>),
    Invited(InviteCreated),
    Safety(Safety),
    /// A grant was refused because the member's key changed: the warning.
    KeyChanged(Safety),
    Vaults(Vec<OrgVaultEntry>),
    VaultMembers(VaultMembersView),
    Audit {
        events: Vec<AuditEventView>,
        /// Emails of the team's members, for the actor and target columns.
        names: HashMap<Uuid, String>,
    },
    /// A change was made: the note, then the page is loaded again.
    Done(String),
    /// This account left a team: back to the teams list.
    Left(String),
}

/// What a key on a teams page asks the panel for.
pub(super) enum TeamOut {
    None,
    /// Run `request`, showing `busy`.
    Request(TeamRequest, &'static str),
    /// Ask first; run `request` on yes.
    Confirm {
        title: &'static str,
        text: String,
        yes: &'static str,
        request: TeamRequest,
        busy: &'static str,
    },
    /// Back to the panel's overview.
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrgItem {
    Members,
    Vaults,
    Invite,
    Audit,
    Leave,
    Back,
}

const ORG_ITEMS: [OrgItem; 6] = [
    OrgItem::Members,
    OrgItem::Vaults,
    OrgItem::Invite,
    OrgItem::Audit,
    OrgItem::Leave,
    OrgItem::Back,
];

impl OrgItem {
    fn label(self) -> &'static str {
        match self {
            Self::Members => "Members and safety numbers",
            Self::Vaults => "Shared vaults and permissions",
            Self::Invite => "Invite someone",
            Self::Audit => "Audit log",
            Self::Leave => "Leave the team",
            Self::Back => "Back",
        }
    }
}

enum Page {
    Orgs {
        rows: Vec<OrgView>,
        cursor: usize,
        loaded: bool,
    },
    NewOrg(Form),
    Accept(Form),
    Org {
        org: OrgView,
        cursor: usize,
    },
    Members {
        org: OrgView,
        rows: Vec<MemberEntry>,
        cursor: usize,
        loaded: bool,
    },
    Invite {
        org: OrgView,
        form: Form,
    },
    InviteLink {
        org: OrgView,
        created: InviteCreated,
    },
    /// The safety number, or the key-change warning.
    Safety {
        safety: Safety,
        buttons: ButtonRow,
        prev: Box<Page>,
    },
    Vaults {
        org: OrgView,
        rows: Vec<OrgVaultEntry>,
        cursor: usize,
        loaded: bool,
    },
    NewVault {
        org: OrgView,
        form: Form,
    },
    VaultMembers {
        org: OrgView,
        vault: VaultId,
        name: String,
        view: Option<VaultMembersView>,
        cursor: usize,
    },
    Audit {
        org: OrgView,
        events: Vec<AuditEventView>,
        names: HashMap<Uuid, String>,
        loaded: bool,
        cursor: usize,
    },
}

/// Which teams page is shown (for tests).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeamPage {
    Orgs,
    NewOrg,
    Accept,
    Org,
    Members,
    Invite,
    InviteLink,
    Safety,
    KeyChanged,
    Vaults,
    NewVault,
    VaultMembers,
    Audit,
}

/// The teams pages. See the module docs.
pub(super) struct TeamsView {
    page: Page,
    unicode: bool,
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

fn permission_label(p: Option<Permission>) -> &'static str {
    match p {
        Some(Permission::Manage) => "manage",
        Some(Permission::Write) => "write",
        Some(Permission::Read) => "read",
        None => "no access",
    }
}

/// The next permission up (`None` = none) and down.
fn raise(p: Option<Permission>) -> Option<Permission> {
    Some(match p {
        None => Permission::Read,
        Some(Permission::Read) => Permission::Write,
        Some(Permission::Write | Permission::Manage) => Permission::Manage,
    })
}

fn lower(p: Option<Permission>) -> Option<Permission> {
    match p {
        Some(Permission::Manage) => Some(Permission::Write),
        Some(Permission::Write) => Some(Permission::Read),
        Some(Permission::Read) | None => None,
    }
}

/// The safety number as 3 lines of 4 groups.
fn number_lines(number: &str) -> Vec<String> {
    let groups: Vec<&str> = number.split_whitespace().collect();
    groups.chunks(4).map(|g| g.join("  ")).collect()
}

fn vault_name(entry: &OrgVaultEntry) -> String {
    entry.name.clone().unwrap_or_else(|| {
        let id = entry.view.id.to_string();
        format!("vault {}", id.chars().take(8).collect::<String>())
    })
}

impl TeamsView {
    /// The teams list (loading).
    pub(super) fn new(unicode: bool) -> (Self, TeamRequest) {
        (
            Self {
                page: Page::Orgs {
                    rows: Vec::new(),
                    cursor: 0,
                    loaded: false,
                },
                unicode,
            },
            TeamRequest::Orgs,
        )
    }

    #[cfg(test)]
    pub(super) fn page(&self) -> TeamPage {
        match &self.page {
            Page::Orgs { .. } => TeamPage::Orgs,
            Page::NewOrg(_) => TeamPage::NewOrg,
            Page::Accept(_) => TeamPage::Accept,
            Page::Org { .. } => TeamPage::Org,
            Page::Members { .. } => TeamPage::Members,
            Page::Invite { .. } => TeamPage::Invite,
            Page::InviteLink { .. } => TeamPage::InviteLink,
            Page::Safety { safety, .. } if safety.state == PinState::KeyChanged => {
                TeamPage::KeyChanged
            }
            Page::Safety { .. } => TeamPage::Safety,
            Page::Vaults { .. } => TeamPage::Vaults,
            Page::NewVault { .. } => TeamPage::NewVault,
            Page::VaultMembers { .. } => TeamPage::VaultMembers,
            Page::Audit { .. } => TeamPage::Audit,
        }
    }

    /// The invite link on its page (tests hand it to the other account).
    #[cfg(test)]
    pub(super) fn invite_link(&self) -> Option<String> {
        match &self.page {
            Page::InviteLink { created, .. } => created.link.clone(),
            _ => None,
        }
    }

    /// The safety number shown (tests compare both sides).
    #[cfg(test)]
    pub(super) fn safety_number(&self) -> Option<String> {
        match &self.page {
            Page::Safety { safety, .. } => Some(safety.number.clone()),
            _ => None,
        }
    }

    pub(super) fn title(&self) -> &'static str {
        match &self.page {
            Page::Orgs { .. } => " Sync: teams ",
            Page::NewOrg(_) => " Sync: new team ",
            Page::Accept(_) => " Sync: join a team ",
            Page::Org { .. } => " Sync: team ",
            Page::Members { .. } => " Sync: team members ",
            Page::Invite { .. } | Page::InviteLink { .. } => " Sync: invite ",
            Page::Safety { safety, .. } if safety.state == PinState::KeyChanged => {
                " Sync: a member's key changed "
            }
            Page::Safety { .. } => " Sync: safety number ",
            Page::Vaults { .. } => " Sync: shared vaults ",
            Page::NewVault { .. } => " Sync: new shared vault ",
            Page::VaultMembers { .. } => " Sync: vault access ",
            Page::Audit { .. } => " Sync: audit log ",
        }
    }

    pub(super) fn handle_paste(&mut self, text: &str) {
        match &mut self.page {
            Page::NewOrg(f)
            | Page::Accept(f)
            | Page::Invite { form: f, .. }
            | Page::NewVault { form: f, .. } => f.handle_paste(text),
            _ => {}
        }
    }

    /// The request that loads the current page again, if it shows a list.
    pub(super) fn reload(&mut self) -> Option<TeamRequest> {
        match &self.page {
            Page::Orgs { .. } => Some(TeamRequest::Orgs),
            Page::Members { org, .. } => Some(TeamRequest::Members(org.id)),
            Page::Vaults { org, .. } => Some(TeamRequest::Vaults(org.id)),
            Page::VaultMembers { vault, .. } => Some(TeamRequest::VaultMembers(*vault)),
            Page::Audit { org, .. } => Some(TeamRequest::Audit(org.id)),
            _ => None,
        }
    }

    /// A team call finished. Returns a request to run next (a reload after
    /// a change).
    pub(super) fn reply(&mut self, reply: TeamReply) -> Option<TeamRequest> {
        match reply {
            TeamReply::Orgs(new) => {
                if let Page::Orgs {
                    rows,
                    cursor,
                    loaded,
                } = &mut self.page
                {
                    *cursor = (*cursor).min(new.len().saturating_sub(1));
                    *rows = new;
                    *loaded = true;
                }
            }
            TeamReply::Members(new) => {
                if let Page::Members {
                    rows,
                    cursor,
                    loaded,
                    ..
                } = &mut self.page
                {
                    *cursor = (*cursor).min(new.len().saturating_sub(1));
                    *rows = new;
                    *loaded = true;
                }
            }
            TeamReply::Invited(created) => {
                let org = match &self.page {
                    Page::Invite { org, .. } | Page::Members { org, .. } => org.clone(),
                    _ => return None,
                };
                self.page = Page::InviteLink { org, created };
            }
            TeamReply::Safety(safety) | TeamReply::KeyChanged(safety) => {
                let prev = std::mem::replace(
                    &mut self.page,
                    Page::Orgs {
                        rows: Vec::new(),
                        cursor: 0,
                        loaded: false,
                    },
                );
                // A safety page over a safety page (accepting a key) goes
                // back to what was under it.
                let prev = match prev {
                    Page::Safety { prev, .. } => prev,
                    other => Box::new(other),
                };
                let buttons = match safety.state {
                    PinState::KeyChanged => ButtonRow::new(
                        &["Accept the new key", "Numbers match: accept", "Not now"],
                        2,
                    ),
                    PinState::Pinned => ButtonRow::new(&["Numbers match: verified", "Back"], 1),
                    PinState::Verified => ButtonRow::new(&["Back"], 0),
                };
                self.page = Page::Safety {
                    safety,
                    buttons,
                    prev,
                };
            }
            TeamReply::Vaults(new) => {
                if let Page::Vaults {
                    rows,
                    cursor,
                    loaded,
                    ..
                } = &mut self.page
                {
                    *cursor = (*cursor).min(new.len().saturating_sub(1));
                    *rows = new;
                    *loaded = true;
                }
            }
            TeamReply::VaultMembers(new) => {
                if let Page::VaultMembers { view, cursor, .. } = &mut self.page {
                    *cursor = (*cursor).min(new.members.len().saturating_sub(1));
                    *view = Some(new);
                }
            }
            TeamReply::Audit {
                events: new,
                names: new_names,
            } => {
                if let Page::Audit {
                    events,
                    names,
                    loaded,
                    cursor,
                    ..
                } = &mut self.page
                {
                    *cursor = (*cursor).min(new.len().saturating_sub(1));
                    *events = new;
                    *names = new_names;
                    *loaded = true;
                }
            }
            TeamReply::Done(_) => return self.reload(),
            TeamReply::Left(_) => {
                let (page, req) = Self::orgs_page();
                self.page = page;
                return Some(req);
            }
        }
        None
    }

    fn orgs_page() -> (Page, TeamRequest) {
        (
            Page::Orgs {
                rows: Vec::new(),
                cursor: 0,
                loaded: false,
            },
            TeamRequest::Orgs,
        )
    }

    fn members_page(org: OrgView) -> (Page, TeamRequest) {
        let req = TeamRequest::Members(org.id);
        (
            Page::Members {
                org,
                rows: Vec::new(),
                cursor: 0,
                loaded: false,
            },
            req,
        )
    }

    fn invite_page(org: OrgView) -> Page {
        Page::Invite {
            org,
            form: Form::new(&["Create invite", "Cancel"])
                .field(
                    "email",
                    TextInput::new("Email")
                        .with_placeholder("empty: anyone with the link")
                        .with_validator(|s: &str| {
                            let s = s.trim();
                            if s.is_empty() || (s.contains('@') && !s.contains(' ')) {
                                Ok(())
                            } else {
                                Err("Enter an email address, or leave it empty".to_owned())
                            }
                        }),
                )
                .field(
                    "role",
                    RadioGroup::new("Role", vec!["Member".to_owned(), "Admin".to_owned()], 0),
                ),
        }
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> TeamOut {
        let page = std::mem::replace(
            &mut self.page,
            Page::Orgs {
                rows: Vec::new(),
                cursor: 0,
                loaded: false,
            },
        );
        let (page, out) = self.page_key(page, key);
        self.page = page;
        out
    }

    #[expect(clippy::too_many_lines, reason = "one match arm per page")]
    fn page_key(&mut self, page: Page, key: KeyEvent) -> (Page, TeamOut) {
        let down = |c: &mut usize, n: usize| *c = (*c + 1).min(n.saturating_sub(1));
        let up = |c: &mut usize| *c = c.saturating_sub(1);
        match page {
            Page::Orgs {
                rows,
                mut cursor,
                loaded,
            } => {
                let out = match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        down(&mut cursor, rows.len());
                        TeamOut::None
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        up(&mut cursor);
                        TeamOut::None
                    }
                    KeyCode::Enter => {
                        if let Some(org) = rows.get(cursor) {
                            return (
                                Page::Org {
                                    org: org.clone(),
                                    cursor: 0,
                                },
                                TeamOut::None,
                            );
                        }
                        TeamOut::None
                    }
                    KeyCode::Char('n') => {
                        return (
                            Page::NewOrg(
                                Form::new(&["Create team", "Cancel"]).field(
                                    "name",
                                    TextInput::new("Team name")
                                        .with_max_len(100)
                                        .with_validator(required("a team name")),
                                ),
                            ),
                            TeamOut::None,
                        );
                    }
                    KeyCode::Char('a') => {
                        return (
                            Page::Accept(
                                Form::new(&["Join", "Cancel"]).field(
                                    "link",
                                    TextInput::new("Invite link")
                                        .with_placeholder("https://…/invite/…")
                                        .with_validator(|s: &str| {
                                            courier_ftp_sync::teams::invite_token(s)
                                                .map(drop)
                                                .ok_or_else(|| {
                                                    "Paste the invite link you were sent".to_owned()
                                                })
                                        }),
                                ),
                            ),
                            TeamOut::None,
                        );
                    }
                    KeyCode::Char('r') => TeamOut::Request(TeamRequest::Orgs, "Loading the teams…"),
                    KeyCode::Esc | KeyCode::Char('q') => TeamOut::Close,
                    _ => TeamOut::None,
                };
                (
                    Page::Orgs {
                        rows,
                        cursor,
                        loaded,
                    },
                    out,
                )
            }
            Page::NewOrg(mut form) => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let name = form.values().text("name").trim().to_owned();
                    let (page, _) = Self::orgs_page();
                    (
                        page,
                        TeamOut::Request(TeamRequest::CreateOrg(name), "Creating the team…"),
                    )
                }
                FormOutcome::Cancel => {
                    let (page, req) = Self::orgs_page();
                    (page, TeamOut::Request(req, "Loading the teams…"))
                }
                _ => (Page::NewOrg(form), TeamOut::None),
            },
            Page::Accept(mut form) => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let link = form.values().text("link").trim().to_owned();
                    let (page, _) = Self::orgs_page();
                    (
                        page,
                        TeamOut::Request(TeamRequest::AcceptInvite(link), "Joining the team…"),
                    )
                }
                FormOutcome::Cancel => {
                    let (page, req) = Self::orgs_page();
                    (page, TeamOut::Request(req, "Loading the teams…"))
                }
                _ => (Page::Accept(form), TeamOut::None),
            },
            Page::Org { org, mut cursor } => match key.code {
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    down(&mut cursor, ORG_ITEMS.len());
                    (Page::Org { org, cursor }, TeamOut::None)
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                    up(&mut cursor);
                    (Page::Org { org, cursor }, TeamOut::None)
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    let (page, req) = Self::orgs_page();
                    (page, TeamOut::Request(req, "Loading the teams…"))
                }
                KeyCode::Enter => match ORG_ITEMS.get(cursor).copied() {
                    Some(OrgItem::Members) => {
                        let (page, req) = Self::members_page(org);
                        (page, TeamOut::Request(req, "Loading the members…"))
                    }
                    Some(OrgItem::Vaults) => {
                        let req = TeamRequest::Vaults(org.id);
                        (
                            Page::Vaults {
                                org,
                                rows: Vec::new(),
                                cursor: 0,
                                loaded: false,
                            },
                            TeamOut::Request(req, "Loading the vaults…"),
                        )
                    }
                    Some(OrgItem::Invite) => (Self::invite_page(org), TeamOut::None),
                    Some(OrgItem::Audit) => {
                        let req = TeamRequest::Audit(org.id);
                        (
                            Page::Audit {
                                org,
                                events: Vec::new(),
                                names: HashMap::new(),
                                loaded: false,
                                cursor: 0,
                            },
                            TeamOut::Request(req, "Loading the audit log…"),
                        )
                    }
                    Some(OrgItem::Leave) => {
                        let text = format!(
                            "Leave “{}”? Its shared vaults are removed from this device and \
                             you lose access until you are invited again.",
                            org.name
                        );
                        let req = TeamRequest::Leave(org.id);
                        (
                            Page::Org { org, cursor },
                            TeamOut::Confirm {
                                title: "Leave the team",
                                text,
                                yes: "Leave",
                                request: req,
                                busy: "Leaving the team…",
                            },
                        )
                    }
                    Some(OrgItem::Back) | None => {
                        let (page, req) = Self::orgs_page();
                        (page, TeamOut::Request(req, "Loading the teams…"))
                    }
                },
                _ => (Page::Org { org, cursor }, TeamOut::None),
            },
            Page::Members {
                org,
                rows,
                mut cursor,
                loaded,
            } => {
                let selected = rows.get(cursor).cloned();
                let out = match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        down(&mut cursor, rows.len());
                        TeamOut::None
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        up(&mut cursor);
                        TeamOut::None
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        return (Page::Org { org, cursor: 0 }, TeamOut::None);
                    }
                    KeyCode::Char('r') => {
                        TeamOut::Request(TeamRequest::Members(org.id), "Loading the members…")
                    }
                    KeyCode::Char('i') => return (Self::invite_page(org), TeamOut::None),
                    KeyCode::Enter | KeyCode::Char('v') => match selected {
                        Some(m) if m.is_me => TeamOut::None,
                        Some(m) => TeamOut::Request(
                            TeamRequest::Safety {
                                user: m.member.user_id,
                                email: m.member.email.clone(),
                            },
                            "Computing the safety number…",
                        ),
                        None => TeamOut::None,
                    },
                    KeyCode::Char('e') => match selected {
                        Some(m) if m.member.role == Role::Owner => TeamOut::None,
                        Some(m) => TeamOut::Request(
                            TeamRequest::SetRole {
                                org: org.id,
                                user: m.member.user_id,
                                email: m.member.email.clone(),
                                role: if m.member.role == Role::Admin {
                                    Role::Member
                                } else {
                                    Role::Admin
                                },
                            },
                            "Changing the role…",
                        ),
                        None => TeamOut::None,
                    },
                    KeyCode::Char('x') | KeyCode::Delete => match selected {
                        Some(m) if m.is_me => TeamOut::Confirm {
                            title: "Leave the team",
                            text: format!(
                                "Leave “{}”? Its shared vaults are removed from this device.",
                                org.name
                            ),
                            yes: "Leave",
                            request: TeamRequest::Leave(org.id),
                            busy: "Leaving the team…",
                        },
                        Some(m) => TeamOut::Confirm {
                            title: "Remove member",
                            text: format!(
                                "Remove {} from “{}”? Their access to the team's vaults is \
                                 revoked and the keys of those vaults are rotated, so they \
                                 can't read new changes (they keep what they already \
                                 downloaded).",
                                m.member.email, org.name
                            ),
                            yes: "Remove",
                            request: TeamRequest::Remove {
                                org: org.id,
                                user: m.member.user_id,
                                email: m.member.email.clone(),
                            },
                            busy: "Removing the member and rotating the vault keys…",
                        },
                        None => TeamOut::None,
                    },
                    _ => TeamOut::None,
                };
                (
                    Page::Members {
                        org,
                        rows,
                        cursor,
                        loaded,
                    },
                    out,
                )
            }
            Page::Invite { org, mut form } => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let v = form.values();
                    let email = v.text("email").trim().to_owned();
                    let role = if v.index("role") == Some(1) {
                        Role::Admin
                    } else {
                        Role::Member
                    };
                    let req = TeamRequest::Invite {
                        org: org.id,
                        email: (!email.is_empty()).then_some(email),
                        role,
                    };
                    (
                        Page::Invite { org, form },
                        TeamOut::Request(req, "Creating the invite…"),
                    )
                }
                FormOutcome::Cancel => (Page::Org { org, cursor: 0 }, TeamOut::None),
                _ => (Page::Invite { org, form }, TeamOut::None),
            },
            Page::InviteLink { org, created } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    let (page, req) = Self::members_page(org);
                    (page, TeamOut::Request(req, "Loading the members…"))
                }
                _ => (Page::InviteLink { org, created }, TeamOut::None),
            },
            Page::Safety {
                safety,
                mut buttons,
                prev,
            } => {
                let pressed = if key.code == KeyCode::Esc {
                    Some(usize::MAX)
                } else {
                    buttons.handle_key(key)
                };
                let Some(pressed) = pressed else {
                    return (
                        Page::Safety {
                            safety,
                            buttons,
                            prev,
                        },
                        TeamOut::None,
                    );
                };
                let (user, email) = (safety.user, safety.email.clone());
                let out = match (safety.state, pressed) {
                    (PinState::KeyChanged, 0 | 1) => TeamOut::Request(
                        TeamRequest::AcceptKey {
                            user,
                            email,
                            verified: pressed == 1,
                        },
                        "Accepting the new key…",
                    ),
                    (PinState::Pinned, 0) => {
                        TeamOut::Request(TeamRequest::Verify { user, email }, "Marking verified…")
                    }
                    _ => TeamOut::None,
                };
                let mut page = *prev;
                let reload = match &mut page {
                    Page::Members { org, .. } => Some(TeamRequest::Members(org.id)),
                    Page::VaultMembers { vault, .. } => Some(TeamRequest::VaultMembers(*vault)),
                    _ => None,
                };
                let out = match (out, reload) {
                    (TeamOut::None, Some(req)) => TeamOut::Request(req, "Loading…"),
                    (out, _) => out,
                };
                (page, out)
            }
            Page::Vaults {
                org,
                rows,
                mut cursor,
                loaded,
            } => {
                let selected = rows.get(cursor).cloned();
                let out = match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        down(&mut cursor, rows.len());
                        TeamOut::None
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        up(&mut cursor);
                        TeamOut::None
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        return (Page::Org { org, cursor: 0 }, TeamOut::None);
                    }
                    KeyCode::Char('r') => {
                        TeamOut::Request(TeamRequest::Vaults(org.id), "Loading the vaults…")
                    }
                    KeyCode::Char('n') => {
                        return (
                            Page::NewVault {
                                org,
                                form: Form::new(&["Create vault", "Cancel"]).field(
                                    "name",
                                    TextInput::new("Vault name")
                                        .with_max_len(100)
                                        .with_validator(required("a vault name")),
                                ),
                            },
                            TeamOut::None,
                        );
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = selected {
                            let vault = VaultId::from_uuid(entry.view.id);
                            let name = vault_name(&entry);
                            return (
                                Page::VaultMembers {
                                    org,
                                    vault,
                                    name,
                                    view: None,
                                    cursor: 0,
                                },
                                TeamOut::Request(
                                    TeamRequest::VaultMembers(vault),
                                    "Loading the vault's members…",
                                ),
                            );
                        }
                        TeamOut::None
                    }
                    KeyCode::Char('R') => match selected {
                        Some(entry) => {
                            let name = vault_name(&entry);
                            TeamOut::Confirm {
                                title: "Rotate the vault key",
                                text: format!(
                                    "Rotate the key of “{name}”? Every item is re-encrypted \
                                     under a new key for the current members (an unfinished \
                                     or abandoned rotation is resumed). Changes to the vault \
                                     wait until it is done."
                                ),
                                yes: "Rotate",
                                request: TeamRequest::Rotate {
                                    vault: VaultId::from_uuid(entry.view.id),
                                    name,
                                },
                                busy: "Rotating the vault key…",
                            }
                        }
                        None => TeamOut::None,
                    },
                    _ => TeamOut::None,
                };
                (
                    Page::Vaults {
                        org,
                        rows,
                        cursor,
                        loaded,
                    },
                    out,
                )
            }
            Page::NewVault { org, mut form } => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let name = form.values().text("name").trim().to_owned();
                    let req = TeamRequest::CreateVault { org: org.id, name };
                    (
                        Page::Vaults {
                            org,
                            rows: Vec::new(),
                            cursor: 0,
                            loaded: false,
                        },
                        TeamOut::Request(req, "Creating the vault…"),
                    )
                }
                FormOutcome::Cancel => {
                    let req = TeamRequest::Vaults(org.id);
                    (
                        Page::Vaults {
                            org,
                            rows: Vec::new(),
                            cursor: 0,
                            loaded: false,
                        },
                        TeamOut::Request(req, "Loading the vaults…"),
                    )
                }
                _ => (Page::NewVault { org, form }, TeamOut::None),
            },
            Page::VaultMembers {
                org,
                vault,
                name,
                view,
                mut cursor,
            } => {
                let n = view.as_ref().map_or(0, |v| v.members.len());
                let selected = view.as_ref().and_then(|v| v.members.get(cursor)).cloned();
                let grant =
                    |m: &courier_ftp_proto::vaults::VaultMemberView, p: Permission, name: &str| {
                        TeamOut::Request(
                            TeamRequest::Grant {
                                vault,
                                name: name.to_owned(),
                                user: m.user_id,
                                email: m.email.clone().unwrap_or_default(),
                                permission: p,
                            },
                            "Granting access…",
                        )
                    };
                let revoke = |m: &courier_ftp_proto::vaults::VaultMemberView, name: &str| {
                    let email = m.email.clone().unwrap_or_else(|| m.user_id.to_string());
                    TeamOut::Confirm {
                        title: "Revoke access",
                        text: format!(
                            "Revoke {email}'s access to “{name}”? The vault key is rotated so \
                             they can't read new changes (they keep what they already \
                             downloaded)."
                        ),
                        yes: "Revoke",
                        request: TeamRequest::Revoke {
                            vault,
                            name: name.to_owned(),
                            user: m.user_id,
                            email,
                        },
                        busy: "Revoking access and rotating the vault key…",
                    }
                };
                let out = match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        down(&mut cursor, n);
                        TeamOut::None
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        up(&mut cursor);
                        TeamOut::None
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        let req = TeamRequest::Vaults(org.id);
                        return (
                            Page::Vaults {
                                org,
                                rows: Vec::new(),
                                cursor: 0,
                                loaded: false,
                            },
                            TeamOut::Request(req, "Loading the vaults…"),
                        );
                    }
                    KeyCode::Char('r') => TeamOut::Request(
                        TeamRequest::VaultMembers(vault),
                        "Loading the vault's members…",
                    ),
                    KeyCode::Right | KeyCode::Char('+' | 'l' | 'g') => match &selected {
                        Some(m) if m.permission != Some(Permission::Manage) => {
                            match raise(m.permission) {
                                Some(p) => grant(m, p, &name),
                                None => TeamOut::None,
                            }
                        }
                        _ => TeamOut::None,
                    },
                    KeyCode::Left | KeyCode::Char('-' | 'h') => match &selected {
                        Some(m) if m.permission.is_some() => match lower(m.permission) {
                            Some(p) => grant(m, p, &name),
                            None => revoke(m, &name),
                        },
                        _ => TeamOut::None,
                    },
                    KeyCode::Char('x') | KeyCode::Delete => match &selected {
                        Some(m) if m.permission.is_some() => revoke(m, &name),
                        _ => TeamOut::None,
                    },
                    KeyCode::Enter | KeyCode::Char('v') => match &selected {
                        Some(m) => TeamOut::Request(
                            TeamRequest::Safety {
                                user: m.user_id,
                                email: m.email.clone().unwrap_or_default(),
                            },
                            "Computing the safety number…",
                        ),
                        None => TeamOut::None,
                    },
                    _ => TeamOut::None,
                };
                (
                    Page::VaultMembers {
                        org,
                        vault,
                        name,
                        view,
                        cursor,
                    },
                    out,
                )
            }
            Page::Audit {
                org,
                events,
                names,
                loaded,
                mut cursor,
            } => {
                let out = match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        down(&mut cursor, events.len());
                        TeamOut::None
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        up(&mut cursor);
                        TeamOut::None
                    }
                    KeyCode::Char('r') => {
                        TeamOut::Request(TeamRequest::Audit(org.id), "Loading the audit log…")
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        return (Page::Org { org, cursor: 0 }, TeamOut::None);
                    }
                    _ => TeamOut::None,
                };
                (
                    Page::Audit {
                        org,
                        events,
                        names,
                        loaded,
                        cursor,
                    },
                    out,
                )
            }
        }
    }

    // ---- drawing ------------------------------------------------------

    fn trust_label(&self, state: Option<PinState>) -> &'static str {
        match (state, self.unicode) {
            (Some(PinState::Verified), true) => "✔ verified",
            (Some(PinState::Verified), false) => "verified",
            (Some(PinState::KeyChanged), true) => "⚠ key changed",
            (Some(PinState::KeyChanged), false) => "! key changed",
            (Some(PinState::Pinned), _) => "not verified",
            (None, _) => "—",
        }
    }

    /// Draws the page; returns the key hints.
    #[expect(clippy::too_many_lines, reason = "one match arm per page")]
    pub(super) fn draw(&self, c: &mut Canvas<'_, '_>, theme: &Theme) -> String {
        let marker = if self.unicode { "› " } else { "> " };
        let row_style = |selected: bool| {
            if selected {
                (marker, theme.selection)
            } else {
                ("  ", Style::new())
            }
        };
        match &self.page {
            Page::Orgs {
                rows,
                cursor,
                loaded,
            } => {
                c.text(
                    "Teams share sites through shared vaults, end-to-end encrypted: the server \
                     never sees them. Members are checked with safety numbers.",
                    theme.dim,
                );
                c.blank();
                if rows.is_empty() {
                    if *loaded {
                        c.text(
                            "You are not in a team yet. Create one with n, or join one with the \
                             invite link you were sent (a).",
                            Style::new(),
                        );
                    }
                } else {
                    c.line(Line::styled(
                        format!("  {:<40} {:<10}", "Team", "Your role"),
                        theme.dim,
                    ));
                }
                for (i, org) in rows.iter().enumerate() {
                    let (m, style) = row_style(i == *cursor);
                    c.line(Line::styled(
                        format!(
                            "{m}{:<40} {:<10}",
                            clip(&org.name, 40),
                            role_label(org.role)
                        ),
                        style,
                    ));
                }
                "Enter open · n new team · a join with a link · r refresh · Esc back".to_owned()
            }
            Page::NewOrg(form) => {
                c.text(
                    "A team (organisation) groups people and the vaults they share. You are \
                     its owner.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Enter create · Esc cancel".to_owned()
            }
            Page::Accept(form) => {
                c.text(
                    "Paste the invite link you were sent. The team's vaults arrive on this \
                     device once a manager gives you access to them.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Enter join · Esc cancel".to_owned()
            }
            Page::Org { org, cursor } => {
                c.text(
                    &format!("{} (you are {})", org.name, role_label(org.role)),
                    theme.title,
                );
                c.blank();
                for (i, item) in ORG_ITEMS.iter().enumerate() {
                    let (m, style) = row_style(i == *cursor);
                    c.line(Line::styled(format!("{m}{}", item.label()), style));
                }
                "↑/↓ choose · Enter select · Esc back".to_owned()
            }
            Page::Members {
                org,
                rows,
                cursor,
                loaded,
            } => {
                c.text(&format!("Members of {}", org.name), theme.title);
                c.blank();
                if rows.is_empty() && *loaded {
                    c.text("No members.", theme.dim);
                } else if !rows.is_empty() {
                    c.line(Line::styled(
                        format!("  {:<34} {:<8} {:<16}", "Email", "Role", "Key"),
                        theme.dim,
                    ));
                }
                for (i, m) in rows.iter().enumerate() {
                    let (mk, style) = row_style(i == *cursor);
                    let trust = if m.is_me {
                        "(you)"
                    } else {
                        self.trust_label(m.state())
                    };
                    let trust_style = match m.state() {
                        Some(PinState::KeyChanged) if !m.is_me => theme.error,
                        Some(PinState::Verified) => theme.title,
                        _ => theme.dim,
                    };
                    c.line(Line::from(vec![
                        Span::styled(
                            format!(
                                "{mk}{:<34} {:<8} ",
                                clip(&m.member.email, 34),
                                role_label(m.member.role)
                            ),
                            style,
                        ),
                        Span::styled(trust, trust_style),
                    ]));
                }
                if rows
                    .iter()
                    .any(|m| !m.is_me && m.state() == Some(PinState::KeyChanged))
                {
                    c.blank();
                    let warn = if self.unicode { "⚠" } else { "!" };
                    c.text(
                        &format!(
                            "{warn} A member's key changed: nothing is shared with them until \
                             you compare the new safety number and accept it (Enter)."
                        ),
                        theme.error,
                    );
                }
                "Enter safety number · i invite · e admin/member · x remove · Esc back".to_owned()
            }
            Page::Invite { org, form } => {
                c.text(
                    &format!(
                        "Invite someone to {}. With an email the invite works only for that \
                         account (and is mailed if the server can send mail); the link can also \
                         be used when registering.",
                        org.name
                    ),
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Tab next field · ←/→ role · Enter create · Esc cancel".to_owned()
            }
            Page::InviteLink { org, created } => {
                let who = created
                    .email
                    .clone()
                    .unwrap_or_else(|| "anyone with the link".to_owned());
                c.text(
                    &format!(
                        "Invite to {} for {who} as {}, valid until {}.",
                        org.name,
                        role_label(created.role),
                        datetime_ms(
                            i64::try_from(created.expires_at.unix_timestamp_nanos() / 1_000_000)
                                .unwrap_or(0)
                        )
                    ),
                    Style::new(),
                );
                c.blank();
                if created.emailed {
                    c.text("The invite was sent by email.", theme.title);
                }
                if let Some(link) = &created.link {
                    c.text(
                        "Send them this link (it works once). They paste it in Sync → Teams → \
                         join with a link, or use it as the invite token when registering:",
                        Style::new(),
                    );
                    c.blank();
                    c.text(link, theme.title);
                }
                "Enter or Esc back to the members".to_owned()
            }
            Page::Safety {
                safety, buttons, ..
            } => {
                if safety.state == PinState::KeyChanged {
                    let warn = if self.unicode { "⚠" } else { "!" };
                    c.text(
                        &format!(
                            "{warn} The keys of {} changed since this device first saw them.",
                            safety.email
                        ),
                        theme.error,
                    );
                    c.blank();
                    c.text(
                        "This happens when they reset their account — or when someone (the \
                         server) is trying to read what you share with them. Until you accept \
                         the new key nothing is granted to them, and vault keys they hand out \
                         are not trusted.",
                        Style::new(),
                    );
                    c.blank();
                    c.text(
                        "Compare this new safety number with theirs in person or by phone \
                         before accepting:",
                        Style::new(),
                    );
                } else {
                    c.text(
                        &format!(
                            "Safety number with {}. Compare it with the one on their screen \
                             (in person or by phone): if they match, nobody is in the middle.",
                            safety.email
                        ),
                        Style::new(),
                    );
                    if safety.state == PinState::Verified {
                        c.blank();
                        let tick = if self.unicode { "✔" } else { "OK" };
                        c.text(&format!("{tick} verified"), theme.title);
                    }
                }
                c.blank();
                for l in number_lines(&safety.number) {
                    c.line(Line::styled(format!("    {l}"), theme.title));
                }
                c.blank();
                c.buttons(buttons, true, theme);
                "←/→ choose · Enter press · Esc back".to_owned()
            }
            Page::Vaults {
                org,
                rows,
                cursor,
                loaded,
            } => {
                c.text(&format!("Shared vaults of {}", org.name), theme.title);
                c.blank();
                if rows.is_empty() && *loaded {
                    c.text(
                        "No shared vaults yet. Create one with n; its sites appear in the Site \
                         Manager under “Team: <name>”.",
                        theme.dim,
                    );
                } else if !rows.is_empty() {
                    c.line(Line::styled(
                        format!("  {:<36} {:<12} {:>8}", "Vault", "Your access", "Key"),
                        theme.dim,
                    ));
                }
                for (i, v) in rows.iter().enumerate() {
                    let (m, style) = row_style(i == *cursor);
                    let name = if v.needs_key() {
                        format!("{} (needs key)", vault_name(v))
                    } else {
                        vault_name(v)
                    };
                    c.line(Line::styled(
                        format!(
                            "{m}{:<36} {:<12} {:>8}",
                            clip(&name, 36),
                            permission_label(Some(v.view.permission)),
                            format!("v{}", v.view.key_version)
                        ),
                        style,
                    ));
                }
                "Enter members · n new vault · R rotate the key · r refresh · Esc back".to_owned()
            }
            Page::NewVault { org, form } => {
                c.text(
                    &format!(
                        "A new vault shared in {}. You manage it; give members access from its \
                         member list.",
                        org.name
                    ),
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Enter create · Esc cancel".to_owned()
            }
            Page::VaultMembers {
                name, view, cursor, ..
            } => {
                c.text(&format!("Who can use “{name}”"), theme.title);
                c.blank();
                if let Some(view) = view {
                    c.line(Line::styled(
                        format!("  {:<34} {:<8} {:<10}", "Member", "Team", "Access"),
                        theme.dim,
                    ));
                    for (i, m) in view.members.iter().enumerate() {
                        let (mk, style) = row_style(i == *cursor);
                        let email = m.email.clone().unwrap_or_else(|| m.user_id.to_string());
                        let key = if m.permission.is_some() && !m.has_key {
                            "  (key pending)"
                        } else {
                            ""
                        };
                        c.line(Line::from(vec![
                            Span::styled(
                                format!(
                                    "{mk}{:<34} {:<8} ",
                                    clip(&email, 34),
                                    role_label(m.org_role)
                                ),
                                style,
                            ),
                            Span::styled(
                                format!("‹ {} ›", permission_label(m.permission)),
                                theme.title,
                            ),
                            Span::styled(key, theme.dim),
                        ]));
                    }
                    c.blank();
                    c.text(
                        "read: use the sites (🔒 in the Site Manager) · write: edit them · \
                         manage: also give and take access. Taking access away rotates the \
                         vault key.",
                        theme.dim,
                    );
                }
                "←/→ access · x revoke · Enter safety number · r refresh · Esc back".to_owned()
            }
            Page::Audit {
                org,
                events,
                names,
                loaded,
                cursor,
            } => {
                c.text(&format!("Audit log of {}", org.name), theme.title);
                c.blank();
                if events.is_empty() && *loaded {
                    c.text("Nothing logged yet.", theme.dim);
                }
                let name = |id: Option<Uuid>| {
                    id.map_or_else(String::new, |id| {
                        names
                            .get(&id)
                            .cloned()
                            .unwrap_or_else(|| id.to_string().chars().take(8).collect())
                    })
                };
                let room = usize::from(c.room()).max(1);
                let start = cursor.saturating_sub(room.saturating_sub(1));
                for (i, e) in events.iter().enumerate().skip(start) {
                    let (m, style) = row_style(i == *cursor);
                    let at = datetime_ms(
                        i64::try_from(e.at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0),
                    );
                    let target = name(e.target);
                    let target = if target.is_empty() {
                        String::new()
                    } else {
                        format!(" → {target}")
                    };
                    c.line(Line::styled(
                        format!(
                            "{m}{at}  {:<22} {}{target}",
                            clip(&e.kind, 22),
                            name(e.actor)
                        ),
                        style,
                    ));
                }
                "↑/↓ scroll · r refresh · Esc back".to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_step_up_and_down() {
        assert_eq!(raise(None), Some(Permission::Read));
        assert_eq!(raise(Some(Permission::Write)), Some(Permission::Manage));
        assert_eq!(lower(Some(Permission::Manage)), Some(Permission::Write));
        assert_eq!(lower(Some(Permission::Read)), None);
    }

    #[test]
    fn safety_numbers_are_drawn_in_three_lines() {
        let n = (0..12)
            .map(|i| format!("{i:05}"))
            .collect::<Vec<_>>()
            .join(" ");
        let lines = number_lines(&n);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "00000  00001  00002  00003");
    }
}
