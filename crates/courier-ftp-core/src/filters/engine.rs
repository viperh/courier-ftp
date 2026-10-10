//! [`FilterEngine`]: the active filters of one side, compiled.

use regex::{Regex, RegexBuilder};
use time::Date;

use super::model::{
    AppliesTo, Condition, DateOp, FileAttribute, Filter, FilterSettings, MatchMode, NumOp, Side,
    StringOp,
};
use crate::model::Entry;

/// The filters active on one side, ready to evaluate.
///
/// Build it once per listing (or when the filters change) and call
/// [`FilterEngine::excluded`] per entry. Regexes are compiled up front.
#[derive(Debug, Clone, Default)]
pub struct FilterEngine {
    filters: Vec<Compiled>,
    /// The source definitions, sorted by name, for [`FilterEngine::equivalent`].
    sources: Vec<Filter>,
}

#[derive(Debug, Clone)]
struct Compiled {
    applies_to: AppliesTo,
    match_mode: MatchMode,
    conditions: Vec<CompiledCondition>,
}

#[derive(Debug, Clone)]
enum CompiledCondition {
    Name(StringTest),
    Path(StringTest),
    Size(NumOp, u64),
    Permission(u32, bool),
    Attribute(FileAttribute, bool),
    Date(DateOp, Date),
}

#[derive(Debug, Clone)]
enum StringTest {
    Plain {
        op: StringOp,
        /// Lower-cased when the filter is case-insensitive.
        value: String,
        case_sensitive: bool,
    },
    Regex(Regex),
}

impl FilterEngine {
    /// The engine for `side` from the settings: the filters the active set
    /// enables on that side, if their scope allows it. Filters that fail to
    /// compile (a bad regex in a hand-edited config) are left out and reported.
    pub fn from_settings(settings: &FilterSettings, side: Side) -> (Self, Vec<String>) {
        let Some(set) = settings.active() else {
            return (Self::default(), Vec::new());
        };
        let names = match side {
            Side::Local => &set.enabled_local,
            Side::Remote => &set.enabled_remote,
        };
        let mut warnings = Vec::new();
        let filters: Vec<&Filter> = names
            .iter()
            .filter_map(|name| {
                let found = settings.get(name);
                if found.is_none() {
                    warnings.push(format!(
                        "filter set `{}` enables unknown filter `{name}`",
                        set.name
                    ));
                }
                found
            })
            .filter(|f| f.scope.allows(side))
            .collect();
        let (engine, more) = Self::new(filters);
        warnings.extend(more);
        (engine, warnings)
    }

    /// An engine for exactly these filters.
    pub fn new<'a>(filters: impl IntoIterator<Item = &'a Filter>) -> (Self, Vec<String>) {
        let mut engine = Self::default();
        let mut warnings = Vec::new();
        for filter in filters {
            match compile(filter) {
                Ok(compiled) => {
                    engine.filters.push(compiled);
                    engine.sources.push(filter.clone());
                }
                Err(e) => warnings.push(format!("filter `{}` disabled: {e}", filter.name)),
            }
        }
        engine.sources.sort_by(|a, b| a.name.cmp(&b.name));
        (engine, warnings)
    }

    /// Whether any filter is active (status bar indicator, T57).
    pub fn is_active(&self) -> bool {
        !self.filters.is_empty()
    }

    /// Whether `entry` (at `full_path`) is hidden by any active filter.
    pub fn excluded(&self, entry: &Entry, full_path: &str) -> bool {
        self.filters.iter().any(|f| f.matches(entry, full_path))
    }

    /// Whether two engines filter the same way (same filter definitions, scope
    /// aside). Directory comparison (T48) warns when the two sides differ, as
    /// FileZilla does.
    pub fn equivalent(&self, other: &FilterEngine) -> bool {
        self.sources.len() == other.sources.len()
            && self.sources.iter().zip(&other.sources).all(|(a, b)| {
                a.name == b.name
                    && a.applies_to == b.applies_to
                    && a.match_mode == b.match_mode
                    && a.case_sensitive == b.case_sensitive
                    && a.conditions == b.conditions
            })
    }
}

fn compile(filter: &Filter) -> Result<Compiled, regex::Error> {
    let cs = filter.case_sensitive;
    let string_test = |op: StringOp, value: &str| -> Result<StringTest, regex::Error> {
        Ok(match op {
            StringOp::Matches => StringTest::Regex(
                RegexBuilder::new(value)
                    .case_insensitive(!cs)
                    .size_limit(1 << 20)
                    .build()?,
            ),
            op => StringTest::Plain {
                op,
                value: if cs {
                    value.to_owned()
                } else {
                    value.to_lowercase()
                },
                case_sensitive: cs,
            },
        })
    };
    let conditions = filter
        .conditions
        .iter()
        .map(|c| {
            Ok(match c {
                Condition::Name { op, value } => CompiledCondition::Name(string_test(*op, value)?),
                Condition::Path { op, value } => CompiledCondition::Path(string_test(*op, value)?),
                Condition::Size { op, value } => CompiledCondition::Size(*op, *value),
                Condition::Permission { bit, set } => {
                    CompiledCondition::Permission(bit.mask(), *set)
                }
                Condition::Attribute { attr, set } => CompiledCondition::Attribute(*attr, *set),
                Condition::Date { op, value } => CompiledCondition::Date(*op, value.date()),
            })
        })
        .collect::<Result<_, regex::Error>>()?;
    Ok(Compiled {
        applies_to: filter.applies_to,
        match_mode: filter.match_mode,
        conditions,
    })
}

impl Compiled {
    fn matches(&self, entry: &Entry, full_path: &str) -> bool {
        let is_dir = entry.is_dir_like();
        let applies = match self.applies_to {
            AppliesTo::Both => true,
            AppliesTo::Files => !is_dir,
            AppliesTo::Dirs => is_dir,
        };
        if !applies || self.conditions.is_empty() {
            return false;
        }
        let mut results = self.conditions.iter().map(|c| c.holds(entry, full_path));
        match self.match_mode {
            MatchMode::All => results.all(|r| r),
            MatchMode::Any => results.any(|r| r),
            MatchMode::None => !results.any(|r| r),
            MatchMode::NotAll => !results.all(|r| r),
        }
    }
}

impl CompiledCondition {
    fn holds(&self, entry: &Entry, full_path: &str) -> bool {
        match self {
            CompiledCondition::Name(test) => test.holds(&entry.name),
            CompiledCondition::Path(test) => test.holds(full_path),
            CompiledCondition::Size(op, value) => entry.size.is_some_and(|size| match op {
                NumOp::Greater => size > *value,
                NumOp::Equals => size == *value,
                NumOp::NotEquals => size != *value,
                NumOp::Less => size < *value,
            }),
            CompiledCondition::Permission(mask, set) => entry
                .permissions
                .as_ref()
                .and_then(|p| p.mode)
                .is_some_and(|mode| (mode & mask != 0) == *set),
            CompiledCondition::Attribute(FileAttribute::Hidden, set) => entry.hidden == *set,
            CompiledCondition::Attribute(FileAttribute::ReadOnly, set) => entry
                .permissions
                .as_ref()
                .and_then(|p| p.mode)
                .is_some_and(|mode| (mode & 0o200 == 0) == *set),
            CompiledCondition::Date(op, day) => entry.modified.is_some_and(|m| {
                let d = m.time.date();
                match op {
                    DateOp::Before => d < *day,
                    DateOp::Equals => d == *day,
                    DateOp::NotEquals => d != *day,
                    DateOp::After => d > *day,
                }
            }),
        }
    }
}

impl StringTest {
    fn holds(&self, subject: &str) -> bool {
        match self {
            StringTest::Regex(re) => re.is_match(subject),
            StringTest::Plain {
                op,
                value,
                case_sensitive,
            } => {
                let lowered;
                let s = if *case_sensitive {
                    subject
                } else {
                    lowered = subject.to_lowercase();
                    &lowered
                };
                match op {
                    StringOp::Contains => s.contains(value.as_str()),
                    StringOp::NotContains => !s.contains(value.as_str()),
                    StringOp::Equals => s == value,
                    StringOp::NotEquals => s != value,
                    StringOp::BeginsWith => s.starts_with(value.as_str()),
                    StringOp::EndsWith => s.ends_with(value.as_str()),
                    // Compiled as a regex instead.
                    StringOp::Matches => false,
                }
            }
        }
    }
}

/// The transient quick filter of a pane (`/` in the TUI, T53): case-insensitive,
/// and unlike [`Filter`]s it *keeps* matching entries.
///
/// A pattern with `*` or `?` is a glob over the whole name; anything else is a
/// substring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickFilter {
    pattern: String,
    glob: bool,
}

impl QuickFilter {
    /// A quick filter for `pattern`.
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_lowercase(),
            glob: pattern.contains(['*', '?']),
        }
    }

    /// Whether `name` is shown.
    pub fn keeps(&self, name: &str) -> bool {
        let name = name.to_lowercase();
        if self.glob {
            glob_match(&self.pattern, &name)
        } else {
            name.contains(&self.pattern)
        }
    }
}

/// Match `name` against a glob of `*` (any run of characters) and `?` (one
/// character). Case-sensitive; lower-case both sides for case-insensitive use.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}
