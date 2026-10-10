//! Column widths and which columns fit a pane ([`fit`]).

use courier_ftp_core::settings::{Column, ColumnSpec};

/// Minimum width of the Name column.
pub(crate) const NAME_MIN: u16 = 12;
/// Below this inner width the Modified column uses the compact date.
pub(crate) const COMPACT_DATE_BELOW: u16 = 60;

/// Fixed width of a column (Name: none, it takes the rest).
pub(crate) fn fixed_width(c: Column, compact_date: bool) -> u16 {
    match c {
        Column::Name => 0,
        Column::Size => 9,
        Column::Type => 12,
        Column::Modified => {
            if compact_date {
                11
            } else {
                16
            }
        }
        Column::Permissions => 10,
        Column::OwnerGroup => 16,
    }
}

/// Drop priority: lower is dropped first.
fn priority(c: Column) -> u8 {
    match c {
        Column::OwnerGroup => 0,
        Column::Type => 1,
        Column::Permissions => 2,
        Column::Modified => 3,
        Column::Size => 4,
        Column::Name => u8::MAX,
    }
}

/// Header title of a column.
pub(crate) fn title(c: Column) -> &'static str {
    match c {
        Column::Name => "Name",
        Column::Size => "Size",
        Column::Type => "Type",
        Column::Modified => "Modified",
        Column::Permissions => "Perms",
        Column::OwnerGroup => "Owner/Group",
    }
}

/// The columns shown and their widths. The marker column (1) comes first; each
/// column after Name is preceded by one space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColumnLayout {
    /// Shown columns in order, with their widths (Name gets the rest).
    pub cols: Vec<(Column, u16)>,
    /// Modified uses the compact date.
    pub compact_date: bool,
}

impl ColumnLayout {
    /// The shown columns (tests).
    #[cfg(test)]
    pub(crate) fn columns(&self) -> Vec<Column> {
        self.cols.iter().map(|(c, _)| *c).collect()
    }
}

/// Normalises a configured column list: unknown names are already dropped by serde;
/// duplicates are dropped and a missing Name is added (visible) at the front.
pub(crate) fn normalize(specs: &[ColumnSpec]) -> Vec<ColumnSpec> {
    let mut out: Vec<ColumnSpec> = Vec::with_capacity(6);
    for s in specs {
        if !out.iter().any(|o| o.column == s.column) {
            out.push(*s);
        }
    }
    match out.iter_mut().find(|s| s.column == Column::Name) {
        Some(name) => name.visible = true,
        None => out.insert(
            0,
            ColumnSpec {
                column: Column::Name,
                visible: true,
            },
        ),
    }
    out
}

/// Which visible columns fit `inner_width` (see the priority table in T53).
pub(crate) fn fit(inner_width: u16, specs: &[ColumnSpec]) -> ColumnLayout {
    let compact_date = inner_width < COMPACT_DATE_BELOW;
    let mut cols: Vec<Column> = normalize(specs)
        .iter()
        .filter(|s| s.visible)
        .map(|s| s.column)
        .collect();
    let need = |cols: &[Column]| -> u32 {
        1 + u32::from(NAME_MIN)
            + cols
                .iter()
                .filter(|c| **c != Column::Name)
                .map(|c| u32::from(fixed_width(*c, compact_date)) + 1)
                .sum::<u32>()
    };
    // Narrow panes (compact date) never show Type: this keeps the T53 table exact at
    // inner width 59, where Type would just fit next to the compact date.
    if compact_date {
        cols.retain(|c| *c != Column::Type);
    }
    while need(&cols) > u32::from(inner_width) {
        let Some(drop) = cols
            .iter()
            .copied()
            .filter(|c| *c != Column::Name)
            .min_by_key(|c| priority(*c))
        else {
            break;
        };
        cols.retain(|c| *c != drop);
    }
    let others: u16 = cols
        .iter()
        .filter(|c| **c != Column::Name)
        .map(|c| fixed_width(*c, compact_date) + 1)
        .sum();
    let name_w = inner_width.saturating_sub(1).saturating_sub(others);
    ColumnLayout {
        cols: cols
            .into_iter()
            .map(|c| {
                let w = if c == Column::Name {
                    name_w
                } else {
                    fixed_width(c, compact_date)
                };
                (c, w)
            })
            .collect(),
        compact_date,
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::settings::PaneColumns;

    use super::*;
    use Column::{
        Modified as M, Name as N, OwnerGroup as O, Permissions as P, Size as S, Type as T,
    };

    #[test]
    fn columns_fit_matches_priority_table() {
        let remote = PaneColumns::default().remote;
        let cases: &[(u16, &[Column])] = &[
            (22, &[N]),
            (23, &[N, S]),
            (34, &[N, S]),
            (35, &[N, S, M]),
            (45, &[N, S, M]),
            (46, &[N, S, M, P]),
            (59, &[N, S, M, P]),
            (60, &[N, S, M, P]),
            (63, &[N, S, M, P]),
            (64, &[N, S, T, M, P]),
            (80, &[N, S, T, M, P]),
            (81, &[N, S, T, M, P, O]),
            (158, &[N, S, T, M, P, O]),
        ];
        for (w, want) in cases {
            let l = fit(*w, &remote);
            assert_eq!(l.columns(), *want, "width {w}");
            assert_eq!(l.compact_date, *w < 60, "width {w}");
            let total: u16 = 1 + l
                .cols
                .iter()
                .map(|(c, cw)| if *c == N { *cw } else { cw + 1 })
                .sum::<u16>();
            assert_eq!(total, *w, "width {w} is used exactly");
        }
        assert_eq!(fit(0, &remote).columns(), vec![N]);
    }

    #[test]
    fn local_default_hides_perms_and_owner() {
        let local = PaneColumns::default().local;
        assert_eq!(fit(158, &local).columns(), vec![N, S, T, M]);
    }

    #[test]
    fn missing_name_is_added_and_duplicates_dropped() {
        let specs = [
            ColumnSpec {
                column: S,
                visible: true,
            },
            ColumnSpec {
                column: S,
                visible: false,
            },
        ];
        let n = normalize(&specs);
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].column, N);
        assert!(n[1].visible);
    }
}
