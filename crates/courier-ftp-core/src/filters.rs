//! The filename filter engine (T47): FileZilla-style directory listing filters.
//!
//! A [`Filter`] is a named list of [`Condition`]s. A filter **excludes** an entry (hides
//! it in the panes, skips it in recursive operations) when it applies to the entry's kind
//! and its conditions match according to its [`MatchMode`]. Filters are grouped into
//! [`FilterSet`]s with separate local and remote selections; the `filters` settings
//! section ([`FilterSettings`]) holds the filters, the sets and the active set.
//! [`FilterEngine`] precompiles the filters selected for one side; search (T49) reuses
//! [`CompiledFilter::matches`], where a match *includes* an entry. [`QuickFilter`] is
//! the transient pane filter (T53).
//!
//! # Kind resolution
//!
//! `EntryKind::Dir` and symlinks whose target is a directory are directories; every other
//! kind (files, `Other`, symlinks to files or with an unknown target) is a file. A filter
//! whose `applies_to` does not cover the entry's kind does not match.
//!
//! # Combining conditions
//!
//! With `n` conditions true out of `len`:
//!
//! | `match_mode` | Filter matches when |
//! |---|---|
//! | `All` | `n == len` |
//! | `Any` | `n >= 1` |
//! | `None` | `n == 0` |
//! | `NotAll` | `n < len` |
//!
//! A filter with zero conditions never matches. Evaluation short-circuits.
//!
//! # Condition semantics
//!
//! Any condition on data the entry lacks evaluates to `false`.
//!
//! | Condition | Value compared | Rules |
//! |---|---|---|
//! | `Name` | `entry.name` | string ops below |
//! | `Path` | the parent directory as passed by the caller | string ops below |
//! | `Size` | `entry.size` | directories never match; `Greater`/`Less` strict |
//! | `Attribute Hidden` | `entry.hidden` | `set` = expected value |
//! | `Attribute ReadOnly` | permissions | mode without any write bit, or `raw` containing `R` |
//! | `Permission` | `permissions.mode` bit | unknown mode → `false` |
//! | `Date` | the entry's calendar day | day-precision dates as is, finer ones in `local_offset` |
//!
//! String operations (case-insensitive unless `case_sensitive`; case folding with
//! `str::to_lowercase`, computed at most once per entry):
//!
//! | Op | Matches when |
//! |---|---|
//! | `Contains` / `NotContains` | substring present / absent |
//! | `Equals` / `NotEquals` | whole string equal / not equal |
//! | `BeginsWith` / `EndsWith` | prefix / suffix |
//! | `Regex` | unanchored `regex` match; compiled size limited to 1 MiB |
//! | `Glob` | `globset` glob over the whole string (`*` also matches `/`, `\` escapes) |
//!
//! # Limits
//!
//! At most 32 conditions per filter and 1024 characters per pattern; names are 1–64
//! characters without control characters. Entry names come from untrusted servers: the
//! `regex` crate matches in linear time.

mod engine;
mod validate;

#[cfg(test)]
mod tests;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use engine::{CompiledFilter, FilterEngine, QuickFilter};
pub use validate::{validate_filter, validate_settings};

/// Maximum characters in a filter name.
pub const MAX_NAME_LEN: usize = 64;
/// Maximum conditions per filter.
pub const MAX_CONDITIONS: usize = 32;
/// Maximum characters in a string condition's value.
pub const MAX_PATTERN_LEN: usize = 1024;

/// One named filter. A filter **excludes** an entry when it applies to the entry's kind
/// and its conditions match according to `match_mode` (FileZilla semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Filter {
    /// Unique name, 1–64 characters, no control characters.
    pub name: String,
    /// Entry kinds the filter applies to: `files`, `dirs` or `both`.
    pub applies_to: AppliesTo,
    /// How the conditions combine: `all`, `any`, `none` or `not_all`.
    pub match_mode: MatchMode,
    /// Case-sensitive string conditions.
    pub case_sensitive: bool,
    /// Sides the filter may be used on: `both`, `local_only` or `remote_only`.
    pub scope: FilterScope,
    /// At most 32 conditions.
    pub conditions: Vec<Condition>,
    /// A shipped default filter (the filter editor shows a tag and offers restore).
    #[serde(default)]
    pub builtin: bool,
}

/// Entry kinds a filter applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppliesTo {
    /// Files (and everything that is not a directory).
    Files,
    /// Directories and symlinks to directories.
    Dirs,
    /// Everything.
    Both,
}

/// How the conditions of a filter combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Every condition is true.
    All,
    /// At least one condition is true.
    Any,
    /// No condition is true.
    None,
    /// At least one condition is false.
    NotAll,
}

/// Sides a filter may be used on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilterScope {
    /// Local and remote.
    Both,
    /// The local side only.
    LocalOnly,
    /// The remote side only.
    RemoteOnly,
}

impl FilterScope {
    /// True if a filter with this scope may be used on `side`.
    pub fn allows(self, side: Side) -> bool {
        matches!(
            (self, side),
            (Self::Both, _) | (Self::LocalOnly, Side::Local) | (Self::RemoteOnly, Side::Remote)
        )
    }
}

/// One condition of a filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Compares the entry name.
    Name {
        /// String operation.
        op: StringOp,
        /// Operand (pattern for `regex` and `glob`), at most 1024 characters.
        value: String,
    },
    /// Matches the path of the directory that contains the entry (not including the name).
    Path {
        /// String operation.
        op: StringOp,
        /// Operand (pattern for `regex` and `glob`), at most 1024 characters.
        value: String,
    },
    /// Compares the size in bytes; directories never match.
    Size {
        /// Numeric operation.
        op: NumOp,
        /// Bytes.
        value: u64,
    },
    /// Tests a file attribute.
    Attribute {
        /// `hidden` or `read_only`.
        attr: AttrFlag,
        /// Expected value.
        set: bool,
    },
    /// Tests one Unix permission bit.
    Permission {
        /// The bit.
        bit: PermBit,
        /// Expected value.
        set: bool,
    },
    /// Calendar day (whole day, no time of day, no offset); `equals` = the entry was
    /// modified on that day. Serialised as `"YYYY-MM-DD"`.
    Date {
        /// Date operation.
        op: DateOp,
        /// The day.
        #[serde(with = "date_format")]
        #[schemars(with = "String", regex(pattern = r"^\d{4}-\d{2}-\d{2}$"))]
        value: time::Date,
    },
}

/// String operations of `Name` and `Path` conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringOp {
    /// Substring present.
    Contains,
    /// Substring absent.
    NotContains,
    /// Whole string equal.
    Equals,
    /// Whole string not equal.
    NotEquals,
    /// Prefix.
    BeginsWith,
    /// Suffix.
    EndsWith,
    /// Unanchored regular expression.
    Regex,
    /// Glob over the whole string.
    Glob,
}

/// Numeric operations of `Size` conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NumOp {
    /// Equal.
    Equals,
    /// Not equal.
    NotEquals,
    /// Strictly greater.
    Greater,
    /// Strictly less.
    Less,
}

/// Date operations of `Date` conditions (whole days).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DateOp {
    /// Same day.
    Equals,
    /// Another day.
    NotEquals,
    /// A strictly earlier day.
    Before,
    /// A strictly later day.
    After,
}

/// File attributes a condition can test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttrFlag {
    /// `entry.hidden`.
    Hidden,
    /// No write permission (Unix mode) or the Windows `R` attribute.
    ReadOnly,
}

/// Unix permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PermBit {
    /// 0o400.
    UserRead,
    /// 0o200.
    UserWrite,
    /// 0o100.
    UserExec,
    /// 0o040.
    GroupRead,
    /// 0o020.
    GroupWrite,
    /// 0o010.
    GroupExec,
    /// 0o004.
    OtherRead,
    /// 0o002.
    OtherWrite,
    /// 0o001.
    OtherExec,
}

impl PermBit {
    /// Every bit, `UserRead` first.
    pub const ALL: [PermBit; 9] = [
        Self::UserRead,
        Self::UserWrite,
        Self::UserExec,
        Self::GroupRead,
        Self::GroupWrite,
        Self::GroupExec,
        Self::OtherRead,
        Self::OtherWrite,
        Self::OtherExec,
    ];

    /// The mode mask (`UserRead` = 0o400 … `OtherExec` = 0o001).
    pub fn mask(self) -> u32 {
        match self {
            Self::UserRead => 0o400,
            Self::UserWrite => 0o200,
            Self::UserExec => 0o100,
            Self::GroupRead => 0o040,
            Self::GroupWrite => 0o020,
            Self::GroupExec => 0o010,
            Self::OtherRead => 0o004,
            Self::OtherWrite => 0o002,
            Self::OtherExec => 0o001,
        }
    }
}

/// A named selection of filters per side (FileZilla "filter sets").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FilterSet {
    /// Set name.
    pub name: String,
    /// Names of the filters enabled for the local side.
    pub local: Vec<String>,
    /// Names of the filters enabled for the remote side.
    pub remote: Vec<String>,
}

impl FilterSet {
    /// A set with no filters enabled.
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: Vec::new(),
            remote: Vec::new(),
        }
    }

    /// The filter names enabled for `side`.
    pub fn names(&self, side: Side) -> &[String] {
        match side {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }
}

/// Name of the default filter set.
pub const DEFAULT_SET: &str = "default";

/// `filters` (T47): directory listing filters (FileZilla: View → Directory listing
/// filters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FilterSettings {
    /// Every filter, built-in and user-defined. Default: the five built-ins.
    pub filters: Vec<Filter>,
    /// Filter sets; at least one. Default: one empty set named `default`.
    pub sets: Vec<FilterSet>,
    /// Name of the set in effect.
    pub active_set: String,
    /// Skip excluded entries (and do not descend excluded directories) in recursive
    /// transfers and operations.
    pub apply_to_transfers: bool,
}

impl Default for FilterSettings {
    fn default() -> Self {
        Self {
            filters: builtin_filters(),
            sets: vec![FilterSet::empty(DEFAULT_SET)],
            active_set: DEFAULT_SET.to_owned(),
            apply_to_transfers: true,
        }
    }
}

impl FilterSettings {
    /// Re-adds missing built-ins and resets built-ins whose definition was changed.
    /// User filters are untouched (a user filter that took a built-in's name keeps it,
    /// and that built-in is not re-added). Returns the names restored.
    pub fn restore_builtins(&mut self) -> Vec<String> {
        let mut restored = Vec::new();
        for b in builtin_filters() {
            match self.filters.iter_mut().find(|f| f.name == b.name) {
                Some(f) if f.builtin => {
                    if *f != b {
                        restored.push(b.name.clone());
                        *f = b;
                    }
                }
                Some(_) => {}
                None => {
                    restored.push(b.name.clone());
                    self.filters.push(b);
                }
            }
        }
        restored
    }

    /// The active set: the set named `active_set`, else the first set.
    pub fn active(&self) -> Option<&FilterSet> {
        self.sets
            .iter()
            .find(|s| s.name == self.active_set)
            .or_else(|| self.sets.first())
    }

    /// The filter named `name`, if any (the first one when names are duplicated).
    pub fn filter(&self, name: &str) -> Option<&Filter> {
        self.filters.iter().find(|f| f.name == name)
    }
}

/// The side of a pane or transfer a filter engine serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// The local file system.
    Local,
    /// The server.
    Remote,
}

fn name_cond(op: StringOp, value: &str) -> Condition {
    Condition::Name {
        op,
        value: value.to_owned(),
    }
}

fn builtin(
    name: &str,
    applies_to: AppliesTo,
    case_sensitive: bool,
    conditions: Vec<Condition>,
) -> Filter {
    Filter {
        name: name.to_owned(),
        applies_to,
        match_mode: MatchMode::Any,
        case_sensitive,
        scope: FilterScope::Both,
        conditions,
        builtin: true,
    }
}

/// The shipped default filters (none enabled in the default set, as in FileZilla).
pub fn builtin_filters() -> Vec<Filter> {
    use StringOp::{BeginsWith, EndsWith, Equals, Glob};
    vec![
        builtin(
            "CVS and SVN directories",
            AppliesTo::Dirs,
            true,
            vec![name_cond(Equals, "CVS"), name_cond(Equals, ".svn")],
        ),
        builtin(
            "Git directories",
            AppliesTo::Dirs,
            true,
            vec![name_cond(Equals, ".git")],
        ),
        builtin(
            "Temporary and backup files",
            AppliesTo::Files,
            false,
            vec![
                name_cond(EndsWith, "~"),
                name_cond(EndsWith, ".bak"),
                name_cond(EndsWith, ".tmp"),
                name_cond(EndsWith, ".swp"),
                name_cond(Glob, "#*#"),
            ],
        ),
        builtin(
            "Configuration files",
            AppliesTo::Both,
            true,
            vec![name_cond(BeginsWith, ".")],
        ),
        builtin(
            "OS metadata files",
            AppliesTo::Files,
            false,
            vec![
                name_cond(Equals, "Thumbs.db"),
                name_cond(Equals, ".DS_Store"),
                name_cond(Equals, "desktop.ini"),
            ],
        ),
    ]
}

/// A validation or compilation problem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// The name is empty.
    #[error("filter name is empty")]
    EmptyName,
    /// The name is longer than 64 characters.
    #[error("filter name `{0}` is longer than 64 characters")]
    NameTooLong(String),
    /// The name contains control characters.
    #[error("filter name `{}` contains control characters", .0.escape_debug())]
    ControlCharsInName(String),
    /// Another filter has the same name.
    #[error("a filter named `{0}` already exists")]
    DuplicateName(String),
    /// More than 32 conditions.
    #[error("filter `{filter}` has more than 32 conditions")]
    TooManyConditions {
        /// Filter name.
        filter: String,
    },
    /// A string condition's value is longer than 1024 characters.
    #[error("filter `{filter}`: pattern is longer than 1024 characters")]
    PatternTooLong {
        /// Filter name.
        filter: String,
    },
    /// A `Regex` value does not compile.
    #[error("filter `{filter}`: invalid regular expression: {message}")]
    InvalidRegex {
        /// Filter name.
        filter: String,
        /// The regex crate's message.
        message: String,
    },
    /// A `Glob` value does not compile.
    #[error("filter `{filter}`: invalid glob: {message}")]
    InvalidGlob {
        /// Filter name.
        filter: String,
        /// The globset crate's message.
        message: String,
    },
    /// The filter has no conditions (a warning: it does not block saving).
    #[error("filter `{filter}` has no conditions and never matches")]
    NoConditions {
        /// Filter name.
        filter: String,
    },
    /// A filter set names a filter that does not exist.
    #[error("filter set `{set}` refers to unknown filter `{filter}`")]
    UnknownFilter {
        /// Set name.
        set: String,
        /// The unknown filter name.
        filter: String,
    },
}

impl FilterError {
    /// True for problems that block saving in the filter editor (all but `NoConditions`).
    pub fn is_blocking(&self) -> bool {
        !matches!(self, Self::NoConditions { .. })
    }
}

impl From<FilterError> for crate::Error {
    fn from(e: FilterError) -> Self {
        crate::Error::InvalidInput(e.to_string())
    }
}

/// `"YYYY-MM-DD"` serde for [`time::Date`].
mod date_format {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::BorrowedFormatItem;
    use time::macros::format_description;

    const FORMAT: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day]");

    pub(super) fn serialize<S: Serializer>(d: &time::Date, s: S) -> Result<S::Ok, S::Error> {
        let text = d.format(FORMAT).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&text)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<time::Date, D::Error> {
        let text = String::deserialize(d)?;
        time::Date::parse(&text, FORMAT).map_err(serde::de::Error::custom)
    }
}
