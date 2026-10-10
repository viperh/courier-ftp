//! Filter definitions: [`Filter`], [`Condition`], [`FilterSet`] and the
//! built-in filters.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Error, Result};

/// One named filter. An entry that matches it is **excluded** (hidden in the
/// panes, skipped by recursive operations), as in FileZilla.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Unique name, shown in the filter dialog and referenced by [`FilterSet`]s.
    pub name: String,
    /// Which entries the filter looks at.
    #[serde(default)]
    pub applies_to: AppliesTo,
    /// How the conditions combine.
    #[serde(default)]
    pub match_mode: MatchMode,
    /// Whether name and path comparisons are case-sensitive.
    #[serde(default)]
    pub case_sensitive: bool,
    /// The conditions. A filter without conditions never matches.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Which side the filter may be used on.
    #[serde(default)]
    pub scope: FilterScope,
}

impl Filter {
    /// Check the filter at edit time: a non-empty name and valid regexes.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::InvalidInput("a filter needs a name".into()));
        }
        for condition in &self.conditions {
            if let Condition::Name {
                op: StringOp::Matches,
                value,
            }
            | Condition::Path {
                op: StringOp::Matches,
                value,
            } = condition
            {
                regex::Regex::new(value).map_err(|e| {
                    Error::InvalidInput(format!("filter `{}`: invalid regex: {e}", self.name))
                })?;
            }
        }
        Ok(())
    }
}

/// Which entries a filter looks at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppliesTo {
    /// Files only (and symlinks that don't point at directories).
    Files,
    /// Directories only (and symlinks to directories).
    Dirs,
    /// Both.
    #[default]
    Both,
}

/// How a filter's conditions combine into "matches".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Every condition holds.
    #[default]
    All,
    /// At least one condition holds.
    Any,
    /// No condition holds.
    None,
    /// At least one condition does not hold.
    NotAll,
}

/// Which side a filter may be enabled on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterScope {
    /// Local and remote.
    #[default]
    Both,
    /// Local panes only.
    LocalOnly,
    /// Remote panes only.
    RemoteOnly,
}

/// The side of the window a filter runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// The local pane.
    Local,
    /// The remote pane.
    Remote,
}

impl Side {
    /// The opposite side.
    pub fn other(self) -> Self {
        match self {
            Side::Local => Side::Remote,
            Side::Remote => Side::Local,
        }
    }
}

impl FilterScope {
    /// Whether a filter with this scope may run on `side`.
    pub fn allows(self, side: Side) -> bool {
        matches!(
            (self, side),
            (FilterScope::Both, _)
                | (FilterScope::LocalOnly, Side::Local)
                | (FilterScope::RemoteOnly, Side::Remote)
        )
    }
}

/// One test on an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum Condition {
    /// The file name.
    Name {
        /// How to compare.
        op: StringOp,
        /// What to compare with (a regex for [`StringOp::Matches`]).
        value: String,
    },
    /// The entry's full path (e.g. `/var/www/index.html`).
    Path {
        /// How to compare.
        op: StringOp,
        /// What to compare with.
        value: String,
    },
    /// The size in bytes. Entries without a size (usually directories) never
    /// match.
    Size {
        /// How to compare.
        op: NumOp,
        /// Bytes.
        value: u64,
    },
    /// A Unix permission bit. Entries without a Unix mode never match.
    Permission {
        /// The bit.
        bit: PermBit,
        /// Whether it must be set (`true`) or clear (`false`).
        set: bool,
    },
    /// A file attribute (the local side on Windows, or what the server reports).
    Attribute {
        /// The attribute.
        attr: FileAttribute,
        /// Whether it must be set (`true`) or clear (`false`).
        set: bool,
    },
    /// The modification date (compared by calendar day). Entries without a
    /// date never match.
    Date {
        /// How to compare.
        op: DateOp,
        /// The date.
        #[serde(with = "time::serde::rfc3339")]
        value: OffsetDateTime,
    },
}

/// String comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringOp {
    /// Contains the value.
    Contains,
    /// Doesn't contain the value.
    NotContains,
    /// Is exactly the value.
    Equals,
    /// Is not the value.
    NotEquals,
    /// Starts with the value.
    BeginsWith,
    /// Ends with the value.
    EndsWith,
    /// Matches the value as a regular expression.
    Matches,
}

/// Number comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumOp {
    /// Greater than.
    Greater,
    /// Equal to.
    Equals,
    /// Not equal to.
    NotEquals,
    /// Less than.
    Less,
}

/// Date comparisons (by calendar day).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateOp {
    /// Before the day.
    Before,
    /// On the day.
    Equals,
    /// Not on the day.
    NotEquals,
    /// After the day.
    After,
}

/// Unix permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermBit {
    /// `0o400`
    OwnerRead,
    /// `0o200`
    OwnerWrite,
    /// `0o100`
    OwnerExecute,
    /// `0o040`
    GroupRead,
    /// `0o020`
    GroupWrite,
    /// `0o010`
    GroupExecute,
    /// `0o004`
    OtherRead,
    /// `0o002`
    OtherWrite,
    /// `0o001`
    OtherExecute,
    /// `0o4000`
    Setuid,
    /// `0o2000`
    Setgid,
    /// `0o1000`
    Sticky,
}

impl PermBit {
    /// The bit's value in a Unix mode.
    pub fn mask(self) -> u32 {
        match self {
            PermBit::OwnerRead => 0o400,
            PermBit::OwnerWrite => 0o200,
            PermBit::OwnerExecute => 0o100,
            PermBit::GroupRead => 0o040,
            PermBit::GroupWrite => 0o020,
            PermBit::GroupExecute => 0o010,
            PermBit::OtherRead => 0o004,
            PermBit::OtherWrite => 0o002,
            PermBit::OtherExecute => 0o001,
            PermBit::Setuid => 0o4000,
            PermBit::Setgid => 0o2000,
            PermBit::Sticky => 0o1000,
        }
    }
}

/// File attributes beyond Unix permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAttribute {
    /// Hidden: a dotfile, or hidden according to the filesystem or server.
    Hidden,
    /// Read-only: the owner may not write (from the Unix mode).
    ReadOnly,
}

/// A named selection of enabled filters per side (FileZilla "filter sets").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSet {
    /// The set's name.
    pub name: String,
    /// Names of the filters enabled on the local side.
    #[serde(default)]
    pub enabled_local: Vec<String>,
    /// Names of the filters enabled on the remote side.
    #[serde(default)]
    pub enabled_remote: Vec<String>,
}

/// The `filters` settings section: every filter definition, the sets, and
/// which set is active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterSettings {
    /// All filter definitions, built-in and user-made.
    pub filters: Vec<Filter>,
    /// Filter sets.
    pub sets: Vec<FilterSet>,
    /// Name of the active set.
    pub active_set: String,
}

impl Default for FilterSettings {
    fn default() -> Self {
        Self {
            filters: builtin_filters(),
            sets: vec![FilterSet {
                name: DEFAULT_SET.to_owned(),
                enabled_local: Vec::new(),
                enabled_remote: Vec::new(),
            }],
            active_set: DEFAULT_SET.to_owned(),
        }
    }
}

/// The name of the filter set that always exists.
pub const DEFAULT_SET: &str = "Default";

impl FilterSettings {
    /// The active set, falling back to the first set.
    pub fn active(&self) -> Option<&FilterSet> {
        self.sets
            .iter()
            .find(|s| s.name == self.active_set)
            .or_else(|| self.sets.first())
    }

    /// Put the built-in filters back to their shipped definitions, adding any
    /// that were deleted. User filters and sets are left alone.
    pub fn restore_builtins(&mut self) {
        for builtin in builtin_filters() {
            match self.filters.iter_mut().find(|f| f.name == builtin.name) {
                Some(existing) => *existing = builtin,
                None => self.filters.push(builtin),
            }
        }
    }

    /// The definition of the filter called `name`.
    pub fn get(&self, name: &str) -> Option<&Filter> {
        self.filters.iter().find(|f| f.name == name)
    }
}

/// The filters shipped with courier-ftp (editable, restorable with
/// [`FilterSettings::restore_builtins`]).
pub fn builtin_filters() -> Vec<Filter> {
    fn name(op: StringOp, value: &str) -> Condition {
        Condition::Name {
            op,
            value: value.to_owned(),
        }
    }
    let any = |name_: &str, applies_to: AppliesTo, case_sensitive: bool, conditions| Filter {
        name: name_.to_owned(),
        applies_to,
        match_mode: MatchMode::Any,
        case_sensitive,
        conditions,
        scope: FilterScope::Both,
    };
    vec![
        any(
            "CVS and SVN directories",
            AppliesTo::Dirs,
            true,
            vec![
                name(StringOp::Equals, "CVS"),
                name(StringOp::Equals, ".svn"),
            ],
        ),
        any(
            "Git",
            AppliesTo::Dirs,
            true,
            vec![name(StringOp::Equals, ".git")],
        ),
        any(
            "Temporary and backup files",
            AppliesTo::Files,
            false,
            vec![
                name(StringOp::EndsWith, "~"),
                name(StringOp::EndsWith, ".bak"),
                name(StringOp::Matches, "^#.*#$"),
            ],
        ),
        any(
            "Configuration files",
            AppliesTo::Files,
            true,
            vec![name(StringOp::BeginsWith, ".")],
        ),
        any(
            "Thumbs.db and .DS_Store",
            AppliesTo::Files,
            false,
            vec![
                name(StringOp::Equals, "Thumbs.db"),
                name(StringOp::Equals, ".DS_Store"),
            ],
        ),
    ]
}
