//! Compiled filters ([`CompiledFilter`]), the per-side [`FilterEngine`] and the pane
//! [`QuickFilter`].

use std::cell::OnceCell;
use std::sync::Arc;

use globset::{GlobBuilder, GlobMatcher};
use regex::{Regex, RegexBuilder};
use time::{Date, UtcOffset};

use super::{
    AppliesTo, AttrFlag, Condition, DateOp, Filter, FilterError, FilterSettings, MAX_CONDITIONS,
    MAX_PATTERN_LEN, MatchMode, NumOp, Side, StringOp,
};
use crate::model::{Entry, Precision};

/// Compiled regex size limits (bytes).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The string operation with its precompiled operand.
#[derive(Debug, Clone)]
enum StrMatcher {
    Contains(String),
    NotContains(String),
    Equals(String),
    NotEquals(String),
    BeginsWith(String),
    EndsWith(String),
    Regex(Regex),
    Glob(GlobMatcher),
}

/// Which string a string condition reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    Path,
}

#[derive(Debug, Clone)]
enum Compiled {
    Str {
        field: Field,
        /// Compare against the lowercased string (only for the plain string ops; regex
        /// and glob are compiled case-insensitive and read the original).
        lower: bool,
        m: StrMatcher,
    },
    Size(NumOp, u64),
    Hidden(bool),
    ReadOnly(bool),
    Perm(u32, bool),
    Date(DateOp, Date),
}

/// Per-entry evaluation context with the lazily computed lowercase name and path.
struct Ctx<'a> {
    entry: &'a Entry,
    parent: &'a str,
    name_lc: OnceCell<String>,
    path_lc: OnceCell<String>,
}

impl<'a> Ctx<'a> {
    fn new(entry: &'a Entry, parent: &'a str) -> Self {
        Self {
            entry,
            parent,
            name_lc: OnceCell::new(),
            path_lc: OnceCell::new(),
        }
    }

    fn text(&self, field: Field, lower: bool) -> &str {
        match (field, lower) {
            (Field::Name, false) => &self.entry.name,
            (Field::Path, false) => self.parent,
            (Field::Name, true) => self.name_lc.get_or_init(|| self.entry.name.to_lowercase()),
            (Field::Path, true) => self.path_lc.get_or_init(|| self.parent.to_lowercase()),
        }
    }
}

fn compile_str(
    filter: &str,
    op: StringOp,
    value: &str,
    ci: bool,
) -> Result<(bool, StrMatcher), FilterError> {
    if value.chars().count() > MAX_PATTERN_LEN {
        return Err(FilterError::PatternTooLong {
            filter: filter.to_owned(),
        });
    }
    let v = || {
        if ci {
            value.to_lowercase()
        } else {
            value.to_owned()
        }
    };
    let m = match op {
        StringOp::Contains => StrMatcher::Contains(v()),
        StringOp::NotContains => StrMatcher::NotContains(v()),
        StringOp::Equals => StrMatcher::Equals(v()),
        StringOp::NotEquals => StrMatcher::NotEquals(v()),
        StringOp::BeginsWith => StrMatcher::BeginsWith(v()),
        StringOp::EndsWith => StrMatcher::EndsWith(v()),
        StringOp::Regex => {
            let re = RegexBuilder::new(value)
                .case_insensitive(ci)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|e| FilterError::InvalidRegex {
                    filter: filter.to_owned(),
                    message: e.to_string(),
                })?;
            return Ok((false, StrMatcher::Regex(re)));
        }
        StringOp::Glob => {
            let g = build_glob(value, ci).map_err(|e| FilterError::InvalidGlob {
                filter: filter.to_owned(),
                message: e.kind().to_string(),
            })?;
            return Ok((false, StrMatcher::Glob(g)));
        }
    };
    Ok((ci, m))
}

fn build_glob(value: &str, ci: bool) -> Result<GlobMatcher, globset::Error> {
    Ok(GlobBuilder::new(value)
        .case_insensitive(ci)
        .literal_separator(false)
        .backslash_escape(true)
        .build()?
        .compile_matcher())
}

fn compile_condition(filter: &Filter, c: &Condition) -> Result<Compiled, FilterError> {
    let ci = !filter.case_sensitive;
    Ok(match c {
        Condition::Name { op, value } => {
            let (lower, m) = compile_str(&filter.name, *op, value, ci)?;
            Compiled::Str {
                field: Field::Name,
                lower,
                m,
            }
        }
        Condition::Path { op, value } => {
            let (lower, m) = compile_str(&filter.name, *op, value, ci)?;
            Compiled::Str {
                field: Field::Path,
                lower,
                m,
            }
        }
        Condition::Size { op, value } => Compiled::Size(*op, *value),
        Condition::Attribute {
            attr: AttrFlag::Hidden,
            set,
        } => Compiled::Hidden(*set),
        Condition::Attribute {
            attr: AttrFlag::ReadOnly,
            set,
        } => Compiled::ReadOnly(*set),
        Condition::Permission { bit, set } => Compiled::Perm(bit.mask(), *set),
        Condition::Date { op, value } => Compiled::Date(*op, *value),
    })
}

/// Read-only state of an entry; `None` when the permissions are unknown.
fn read_only(entry: &Entry) -> Option<bool> {
    let p = entry.permissions.as_ref()?;
    let by_mode = p.mode.map(|m| m & 0o222 == 0);
    let by_raw = p.raw.as_ref().map(|r| r.contains('R'));
    match (by_mode, by_raw) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(false) || b.unwrap_or(false)),
    }
}

/// The entry's calendar day.
fn entry_day(entry: &Entry, offset: UtcOffset) -> Option<Date> {
    let ts = entry.modified?;
    Some(if ts.precision == Precision::Day {
        ts.time.date()
    } else {
        ts.time.checked_to_offset(offset)?.date()
    })
}

impl Compiled {
    fn eval(&self, ctx: &Ctx<'_>, offset: UtcOffset) -> bool {
        let entry = ctx.entry;
        match self {
            Self::Str { field, lower, m } => {
                let s = ctx.text(*field, *lower);
                match m {
                    StrMatcher::Contains(v) => s.contains(v.as_str()),
                    StrMatcher::NotContains(v) => !s.contains(v.as_str()),
                    StrMatcher::Equals(v) => s == v,
                    StrMatcher::NotEquals(v) => s != v,
                    StrMatcher::BeginsWith(v) => s.starts_with(v.as_str()),
                    StrMatcher::EndsWith(v) => s.ends_with(v.as_str()),
                    StrMatcher::Regex(re) => re.is_match(s),
                    StrMatcher::Glob(g) => g.is_match(s),
                }
            }
            Self::Size(op, v) => {
                if entry.is_dir_like() {
                    return false;
                }
                entry.size.is_some_and(|size| match op {
                    NumOp::Equals => size == *v,
                    NumOp::NotEquals => size != *v,
                    NumOp::Greater => size > *v,
                    NumOp::Less => size < *v,
                })
            }
            Self::Hidden(set) => entry.hidden == *set,
            Self::ReadOnly(set) => read_only(entry) == Some(*set),
            Self::Perm(mask, set) => entry
                .permissions
                .as_ref()
                .and_then(|p| p.mode)
                .is_some_and(|m| (m & mask != 0) == *set),
            Self::Date(op, v) => entry_day(entry, offset).is_some_and(|d| match op {
                DateOp::Equals => d == *v,
                DateOp::NotEquals => d != *v,
                DateOp::Before => d < *v,
                DateOp::After => d > *v,
            }),
        }
    }
}

/// Combines condition results with `mode` (short-circuiting); `len` = number of
/// conditions. Zero conditions never match.
pub(super) fn combine(
    mode: MatchMode,
    len: usize,
    mut results: impl Iterator<Item = bool>,
) -> bool {
    if len == 0 {
        return false;
    }
    match mode {
        MatchMode::All => results.all(|b| b),
        MatchMode::Any => results.any(|b| b),
        MatchMode::None => !results.any(|b| b),
        MatchMode::NotAll => !results.all(|b| b),
    }
}

/// One compiled filter; [`matches`](Self::matches) ignores `scope` (used directly by
/// search, T49).
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    name: String,
    applies_to: AppliesTo,
    match_mode: MatchMode,
    conditions: Box<[Compiled]>,
    local_offset: UtcOffset,
    /// Canonical serialisation of the definition (for [`FilterEngine::equivalent`]).
    canonical: String,
}

impl CompiledFilter {
    /// Compiles `filter`. `local_offset` converts finer-than-day timestamps to calendar
    /// days for `Date` conditions.
    ///
    /// Errors: `TooManyConditions`, `PatternTooLong`, `InvalidRegex`, `InvalidGlob`.
    pub fn compile(filter: &Filter, local_offset: UtcOffset) -> Result<Self, FilterError> {
        if filter.conditions.len() > MAX_CONDITIONS {
            return Err(FilterError::TooManyConditions {
                filter: filter.name.clone(),
            });
        }
        let conditions = filter
            .conditions
            .iter()
            .map(|c| compile_condition(filter, c))
            .collect::<Result<Box<[_]>, _>>()?;
        let canonical = serde_json::to_string(&(
            filter.applies_to,
            filter.match_mode,
            filter.case_sensitive,
            &filter.conditions,
        ))
        .unwrap_or_default();
        Ok(Self {
            name: filter.name.clone(),
            applies_to: filter.applies_to,
            match_mode: filter.match_mode,
            conditions,
            local_offset,
            canonical,
        })
    }

    /// The filter's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Applies-to check and conditions combined with the match mode. `parent` is the
    /// path of the directory containing `entry`.
    pub fn matches(&self, entry: &Entry, parent: &str) -> bool {
        self.matches_ctx(&Ctx::new(entry, parent))
    }

    fn matches_ctx(&self, ctx: &Ctx<'_>) -> bool {
        let is_dir = ctx.entry.is_dir_like();
        let applies = match self.applies_to {
            AppliesTo::Both => true,
            AppliesTo::Dirs => is_dir,
            AppliesTo::Files => !is_dir,
        };
        applies
            && combine(
                self.match_mode,
                self.conditions.len(),
                self.conditions
                    .iter()
                    .map(|c| c.eval(ctx, self.local_offset)),
            )
    }
}

/// Precompiled filters for one side. Cheap to clone (`Arc` inside); immutable.
#[derive(Debug, Clone)]
pub struct FilterEngine {
    filters: Arc<[CompiledFilter]>,
    side: Side,
}

impl FilterEngine {
    /// Compiles the filters the active set enables for `side`, minus filters whose
    /// `scope` excludes `side`. Lenient: a set entry naming an unknown filter
    /// (`UnknownFilter`) or a filter that fails to compile is skipped, logged with
    /// `warn!` (filter name and error only) and returned; the other filters apply.
    pub fn new(
        settings: &FilterSettings,
        side: Side,
        local_offset: UtcOffset,
    ) -> (Self, Vec<FilterError>) {
        let mut errors = Vec::new();
        let mut compiled: Vec<CompiledFilter> = Vec::new();
        if let Some(set) = settings.active() {
            for name in set.names(side) {
                if compiled.iter().any(|c| &c.name == name) {
                    continue;
                }
                let Some(filter) = settings.filter(name) else {
                    let e = FilterError::UnknownFilter {
                        set: set.name.clone(),
                        filter: name.clone(),
                    };
                    tracing::warn!(set = %set.name, filter = %name, error = %e, "filter skipped");
                    errors.push(e);
                    continue;
                };
                if !filter.scope.allows(side) {
                    continue;
                }
                match CompiledFilter::compile(filter, local_offset) {
                    Ok(c) => compiled.push(c),
                    Err(e) => {
                        tracing::warn!(filter = %filter.name, error = %e, "filter disabled");
                        errors.push(e);
                    }
                }
            }
        }
        (
            Self {
                filters: compiled.into(),
                side,
            },
            errors,
        )
    }

    /// No filters (nothing excluded).
    pub fn empty(side: Side) -> Self {
        Self {
            filters: Arc::new([]),
            side,
        }
    }

    /// The side this engine serves.
    pub fn side(&self) -> Side {
        self.side
    }

    /// The compiled filters in effect, in set order.
    pub fn filters(&self) -> &[CompiledFilter] {
        &self.filters
    }

    /// True if `entry` (inside directory `parent`) is hidden / skipped.
    pub fn excluded(&self, entry: &Entry, parent: &str) -> bool {
        if self.filters.is_empty() {
            return false;
        }
        let ctx = Ctx::new(entry, parent);
        let hit = self.filters.iter().any(|f| f.matches_ctx(&ctx));
        tracing::trace!(excluded = hit, "filter decision");
        hit
    }

    /// Indices of the entries that stay visible, in input order.
    pub fn visible_indices(&self, entries: &[Entry], parent: &str) -> Vec<usize> {
        if self.filters.is_empty() {
            return (0..entries.len()).collect();
        }
        entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !self.excluded(e, parent))
            .map(|(i, _)| i)
            .collect()
    }

    /// True if at least one filter is in effect.
    pub fn is_active(&self) -> bool {
        !self.filters.is_empty()
    }

    /// Same effective filter definitions on both sides (names, scope and the built-in
    /// flag ignored; compared as multisets).
    pub fn equivalent(&self, other: &FilterEngine) -> bool {
        fn defs(e: &FilterEngine) -> Vec<&str> {
            let mut v: Vec<&str> = e.filters.iter().map(|f| f.canonical.as_str()).collect();
            v.sort_unstable();
            v
        }
        defs(self) == defs(other)
    }
}

/// Pane quick filter (T53): transient, always case-insensitive, matches the name only.
#[derive(Debug, Clone)]
pub struct QuickFilter {
    kind: QuickKind,
}

#[derive(Debug, Clone)]
enum QuickKind {
    Glob(GlobMatcher),
    /// Lowercased substring.
    Substring(String),
}

impl QuickFilter {
    /// Text containing `*`, `?` or `[` is a glob over the whole name; otherwise a
    /// substring. Empty text → `None` (no filter). Invalid glob → treated as substring.
    /// Nothing is trimmed: spaces are meaningful.
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        let kind = if text.contains(['*', '?', '[']) {
            match build_glob(text, true) {
                Ok(g) => QuickKind::Glob(g),
                Err(_) => QuickKind::Substring(text.to_lowercase()),
            }
        } else {
            QuickKind::Substring(text.to_lowercase())
        };
        Some(Self { kind })
    }

    /// True if `name` passes the filter (stays visible).
    pub fn matches(&self, name: &str) -> bool {
        match &self.kind {
            QuickKind::Glob(g) => g.is_match(name),
            QuickKind::Substring(s) => name.to_lowercase().contains(s.as_str()),
        }
    }

    /// True if the text was parsed as a glob.
    pub fn is_glob(&self) -> bool {
        matches!(self.kind, QuickKind::Glob(_))
    }
}
