//! Editor-time validation (T67): every problem, not just the first.

use time::UtcOffset;

use super::engine::CompiledFilter;
use super::{Condition, Filter, FilterError, FilterSettings, MAX_CONDITIONS, MAX_NAME_LEN};

/// All problems of `filter`; `others` are the other filters (for the duplicate-name
/// check; `filter` itself must not be in it). `NoConditions` is a warning
/// ([`FilterError::is_blocking`] is false).
pub fn validate_filter(filter: &Filter, others: &[Filter]) -> Vec<FilterError> {
    let mut errors = Vec::new();
    let name = &filter.name;
    if name.is_empty() {
        errors.push(FilterError::EmptyName);
    } else if name.chars().count() > MAX_NAME_LEN {
        errors.push(FilterError::NameTooLong(name.clone()));
    }
    if name.chars().any(char::is_control) {
        errors.push(FilterError::ControlCharsInName(name.clone()));
    }
    if !name.is_empty() && others.iter().any(|o| &o.name == name) {
        errors.push(FilterError::DuplicateName(name.clone()));
    }
    if filter.conditions.is_empty() {
        errors.push(FilterError::NoConditions {
            filter: name.clone(),
        });
    }
    if filter.conditions.len() > MAX_CONDITIONS {
        errors.push(FilterError::TooManyConditions {
            filter: name.clone(),
        });
    }
    // Compile each string condition on its own so every bad pattern is reported.
    for c in &filter.conditions {
        if matches!(c, Condition::Name { .. } | Condition::Path { .. }) {
            let single = Filter {
                conditions: vec![c.clone()],
                ..filter.clone()
            };
            if let Err(e) = CompiledFilter::compile(&single, UtcOffset::UTC) {
                errors.push(e);
            }
        }
    }
    errors
}

/// All problems of every filter and set: [`validate_filter`] for each filter (duplicates
/// reported once, on the later filter) and `UnknownFilter` for set entries that name no
/// filter.
pub fn validate_settings(settings: &FilterSettings) -> Vec<FilterError> {
    let mut errors = Vec::new();
    for (i, f) in settings.filters.iter().enumerate() {
        errors.extend(validate_filter(f, &settings.filters[..i]));
    }
    for set in &settings.sets {
        for name in set.local.iter().chain(&set.remote) {
            if settings.filter(name).is_none() {
                let e = FilterError::UnknownFilter {
                    set: set.name.clone(),
                    filter: name.clone(),
                };
                if !errors.contains(&e) {
                    errors.push(e);
                }
            }
        }
    }
    errors
}
