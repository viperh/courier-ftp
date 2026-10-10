//! FileZilla-style filename filters (T47): entries that match an active filter
//! are hidden in the panes and skipped by recursive operations.
//!
//! Filter definitions and sets are not secret, so they live in the settings
//! (`settings.filters`, T05). A [`FilterEngine`] compiles the filters active on
//! one side. The quick filter of a pane ([`QuickFilter`]) is separate and
//! transient.

mod engine;
mod model;

pub use engine::{FilterEngine, QuickFilter, glob_match};
pub use model::{
    AppliesTo, Condition, DEFAULT_SET, DateOp, FileAttribute, Filter, FilterScope, FilterSet,
    FilterSettings, MatchMode, NumOp, PermBit, Side, StringOp, builtin_filters,
};

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;
    use crate::model::{Entry, EntryKind, Permissions, Precision, Timestamp};

    fn filter(match_mode: MatchMode, conditions: Vec<Condition>) -> Filter {
        Filter {
            name: "test".into(),
            applies_to: AppliesTo::Both,
            match_mode,
            case_sensitive: false,
            conditions,
            scope: FilterScope::Both,
        }
    }

    fn excludes(f: &Filter, entry: &Entry, path: &str) -> bool {
        let (engine, warnings) = FilterEngine::new([f]);
        assert!(warnings.is_empty(), "{warnings:?}");
        engine.excluded(entry, path)
    }

    fn name(op: StringOp, value: &str) -> Condition {
        Condition::Name {
            op,
            value: value.into(),
        }
    }

    #[test]
    fn string_operators() {
        let e = Entry::file("Report-2024.TXT", 1);
        let cases = [
            (StringOp::Contains, "port", true),
            (StringOp::Contains, "xyz", false),
            (StringOp::NotContains, "xyz", true),
            (StringOp::NotContains, "port", false),
            (StringOp::Equals, "report-2024.txt", true),
            (StringOp::Equals, "report", false),
            (StringOp::NotEquals, "report", true),
            (StringOp::NotEquals, "REPORT-2024.txt", false),
            (StringOp::BeginsWith, "rep", true),
            (StringOp::BeginsWith, "port", false),
            (StringOp::EndsWith, ".txt", true),
            (StringOp::EndsWith, ".doc", false),
            (StringOp::Matches, r"^report-\d{4}\.txt$", true),
            (StringOp::Matches, r"^\d+$", false),
        ];
        for (op, value, expected) in cases {
            let f = filter(MatchMode::All, vec![name(op, value)]);
            assert_eq!(
                excludes(&f, &e, "/x/Report-2024.TXT"),
                expected,
                "{op:?} {value:?}"
            );
        }
    }

    #[test]
    fn case_sensitivity() {
        let mut f = filter(MatchMode::All, vec![name(StringOp::Equals, "readme")]);
        f.case_sensitive = true;
        assert!(!excludes(&f, &Entry::file("README", 1), "/README"));
        assert!(excludes(&f, &Entry::file("readme", 1), "/readme"));
        let mut f = filter(MatchMode::All, vec![name(StringOp::Matches, "^readme$")]);
        f.case_sensitive = true;
        assert!(!excludes(&f, &Entry::file("README", 1), "/README"));
        f.case_sensitive = false;
        assert!(excludes(&f, &Entry::file("README", 1), "/README"));
    }

    #[test]
    fn path_condition_uses_the_full_path() {
        let f = filter(
            MatchMode::All,
            vec![Condition::Path {
                op: StringOp::Contains,
                value: "/node_modules/".into(),
            }],
        );
        let e = Entry::file("index.js", 1);
        assert!(excludes(&f, &e, "/app/node_modules/x/index.js"));
        assert!(!excludes(&f, &e, "/app/src/index.js"));
    }

    #[test]
    fn size_operators() {
        let cond = |op, value| vec![Condition::Size { op, value }];
        let e = Entry::file("f", 100);
        let cases = [
            (NumOp::Greater, 99, true),
            (NumOp::Greater, 100, false),
            (NumOp::Equals, 100, true),
            (NumOp::Equals, 101, false),
            (NumOp::NotEquals, 101, true),
            (NumOp::NotEquals, 100, false),
            (NumOp::Less, 101, true),
            (NumOp::Less, 100, false),
        ];
        for (op, value, expected) in cases {
            let f = filter(MatchMode::All, cond(op, value));
            assert_eq!(excludes(&f, &e, "/f"), expected, "{op:?} {value}");
        }
        // No size: never matches, not even NotEquals.
        let f = filter(MatchMode::All, cond(NumOp::NotEquals, 1));
        assert!(!excludes(&f, &Entry::dir("d"), "/d"));
    }

    #[test]
    fn permission_bits() {
        let mut e = Entry::file("run.sh", 1);
        e.permissions = Some(Permissions::from_mode(0o100_4755));
        let perm = |bit, set| filter(MatchMode::All, vec![Condition::Permission { bit, set }]);
        assert!(excludes(&perm(PermBit::OwnerExecute, true), &e, "/run.sh"));
        assert!(excludes(&perm(PermBit::Setuid, true), &e, "/run.sh"));
        assert!(excludes(&perm(PermBit::OtherWrite, false), &e, "/run.sh"));
        assert!(!excludes(&perm(PermBit::OtherWrite, true), &e, "/run.sh"));
        assert!(!excludes(&perm(PermBit::Sticky, true), &e, "/run.sh"));
        for bit in [
            PermBit::OwnerRead,
            PermBit::OwnerWrite,
            PermBit::GroupRead,
            PermBit::GroupExecute,
            PermBit::OtherRead,
            PermBit::OtherExecute,
        ] {
            assert!(excludes(&perm(bit, true), &e, "/run.sh"), "{bit:?}");
        }
        assert!(!excludes(&perm(PermBit::GroupWrite, true), &e, "/run.sh"));
        assert!(!excludes(&perm(PermBit::Setgid, true), &e, "/run.sh"));
        // No Unix mode: never matches.
        let mut raw = Entry::file("x", 1);
        raw.permissions = Some(Permissions::from_raw("adfrw"));
        assert!(!excludes(&perm(PermBit::OwnerRead, false), &raw, "/x"));
    }

    #[test]
    fn attributes() {
        let attr = |attr, set| filter(MatchMode::All, vec![Condition::Attribute { attr, set }]);
        let hidden = Entry::file(".env", 1);
        assert!(excludes(
            &attr(FileAttribute::Hidden, true),
            &hidden,
            "/.env"
        ));
        assert!(!excludes(
            &attr(FileAttribute::Hidden, false),
            &hidden,
            "/.env"
        ));
        let mut ro = Entry::file("ro", 1);
        ro.permissions = Some(Permissions::from_mode(0o444));
        assert!(excludes(&attr(FileAttribute::ReadOnly, true), &ro, "/ro"));
        ro.permissions = Some(Permissions::from_mode(0o644));
        assert!(!excludes(&attr(FileAttribute::ReadOnly, true), &ro, "/ro"));
    }

    #[test]
    fn date_operators() {
        let mut e = Entry::file("f", 1);
        e.modified = Some(Timestamp::new(
            datetime!(2024-03-10 15:00 UTC),
            Precision::Minute,
        ));
        let date = |op| {
            filter(
                MatchMode::All,
                vec![Condition::Date {
                    op,
                    value: datetime!(2024-03-10 0:00 UTC),
                }],
            )
        };
        assert!(excludes(&date(DateOp::Equals), &e, "/f"));
        assert!(!excludes(&date(DateOp::NotEquals), &e, "/f"));
        assert!(!excludes(&date(DateOp::Before), &e, "/f"));
        assert!(!excludes(&date(DateOp::After), &e, "/f"));
        e.modified = Some(Timestamp::new(
            datetime!(2024-03-11 0:00 UTC),
            Precision::Day,
        ));
        assert!(excludes(&date(DateOp::After), &e, "/f"));
        assert!(excludes(&date(DateOp::NotEquals), &e, "/f"));
        e.modified = None;
        assert!(!excludes(&date(DateOp::NotEquals), &e, "/f"));
    }

    #[test]
    fn match_modes() {
        let two = |mode| {
            filter(
                mode,
                vec![
                    name(StringOp::BeginsWith, "a"),
                    name(StringOp::EndsWith, ".txt"),
                ],
            )
        };
        // (begins with a, ends with .txt) for four names.
        let names = ["a.txt", "a.doc", "b.txt", "b.doc"];
        let expected = [
            (MatchMode::All, [true, false, false, false]),
            (MatchMode::Any, [true, true, true, false]),
            (MatchMode::None, [false, false, false, true]),
            (MatchMode::NotAll, [false, true, true, true]),
        ];
        for (mode, want) in expected {
            let f = two(mode);
            let got: Vec<bool> = names
                .iter()
                .map(|n| excludes(&f, &Entry::file(*n, 1), n))
                .collect();
            assert_eq!(got, want, "{mode:?}");
        }
    }

    #[test]
    fn empty_filter_never_matches() {
        for mode in [
            MatchMode::All,
            MatchMode::Any,
            MatchMode::None,
            MatchMode::NotAll,
        ] {
            assert!(!excludes(&filter(mode, vec![]), &Entry::file("x", 1), "/x"));
        }
    }

    #[test]
    fn applies_to_files_or_dirs() {
        let mut f = filter(MatchMode::All, vec![name(StringOp::Equals, "build")]);
        f.applies_to = AppliesTo::Dirs;
        assert!(excludes(&f, &Entry::dir("build"), "/build"));
        assert!(!excludes(&f, &Entry::file("build", 1), "/build"));
        let link_to_dir = Entry::new(
            "build",
            EntryKind::Symlink {
                target: None,
                target_kind: Some(Box::new(EntryKind::Dir)),
            },
        );
        assert!(excludes(&f, &link_to_dir, "/build"));
        f.applies_to = AppliesTo::Files;
        assert!(!excludes(&f, &Entry::dir("build"), "/build"));
        assert!(excludes(&f, &Entry::file("build", 1), "/build"));
    }

    #[test]
    fn builtins_present_and_restorable() {
        let mut settings = FilterSettings::default();
        let names: Vec<&str> = settings.filters.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "CVS and SVN directories",
                "Git",
                "Temporary and backup files",
                "Configuration files",
                "Thumbs.db and .DS_Store"
            ]
        );
        for f in &settings.filters {
            f.validate().unwrap();
        }
        settings.filters.retain(|f| f.name != "Git");
        settings.filters[0].conditions.clear();
        settings.filters.push(filter(MatchMode::All, vec![]));
        settings.restore_builtins();
        assert_eq!(settings.filters.len(), 6);
        assert!(settings.get("Git").is_some());
        assert_eq!(
            settings.get("CVS and SVN directories"),
            builtin_filters().first()
        );
        assert!(settings.get("test").is_some());
    }

    #[test]
    fn builtin_temporary_files() {
        let settings = FilterSettings::default();
        let f = settings.get("Temporary and backup files").unwrap();
        for hit in ["notes.txt~", "db.BAK", "#scratch#"] {
            assert!(excludes(f, &Entry::file(hit, 1), hit), "{hit}");
        }
        for miss in ["notes.txt", "#half", "backup"] {
            assert!(!excludes(f, &Entry::file(miss, 1), miss), "{miss}");
        }
    }

    #[test]
    fn engine_from_settings_respects_sets_and_scope() {
        let mut settings = FilterSettings::default();
        let mut remote_only = filter(MatchMode::All, vec![name(StringOp::Equals, "x")]);
        remote_only.name = "remote only".into();
        remote_only.scope = FilterScope::RemoteOnly;
        settings.filters.push(remote_only);
        settings.sets[0].enabled_local = vec!["Git".into(), "remote only".into(), "gone".into()];
        settings.sets[0].enabled_remote = vec!["Git".into(), "remote only".into()];

        let (local, warnings) = FilterEngine::from_settings(&settings, Side::Local);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(local.is_active());
        assert!(local.excluded(&Entry::dir(".git"), "/.git"));
        assert!(!local.excluded(&Entry::file("x", 1), "/x"));

        let (remote, _) = FilterEngine::from_settings(&settings, Side::Remote);
        assert!(remote.excluded(&Entry::file("x", 1), "/x"));
        assert!(!local.equivalent(&remote));

        settings.sets[0].enabled_local = vec!["Git".into()];
        settings.sets[0].enabled_remote = vec!["Git".into()];
        let (local, _) = FilterEngine::from_settings(&settings, Side::Local);
        let (remote, _) = FilterEngine::from_settings(&settings, Side::Remote);
        assert!(local.equivalent(&remote));
        assert!(FilterEngine::default().equivalent(&FilterEngine::default()));
        assert!(!FilterEngine::default().is_active());
    }

    #[test]
    fn invalid_regex_disables_the_filter() {
        let bad = filter(MatchMode::All, vec![name(StringOp::Matches, "(unclosed")]);
        assert!(bad.validate().is_err());
        let (engine, warnings) = FilterEngine::new([&bad]);
        assert_eq!(warnings.len(), 1);
        assert!(!engine.is_active());
    }

    #[test]
    fn quick_filter() {
        let q = QuickFilter::new("READ");
        assert!(q.keeps("readme.md"));
        assert!(q.keeps("README"));
        assert!(!q.keeps("main.rs"));
        let g = QuickFilter::new("*.RS");
        assert!(g.keeps("main.rs"));
        assert!(!g.keeps("main.rs.bak"));
        let g = QuickFilter::new("?.txt");
        assert!(g.keeps("a.txt"));
        assert!(!g.keeps("ab.txt"));
    }

    #[test]
    fn globs() {
        let cases = [
            ("*", "", true),
            ("*", "anything", true),
            ("a*b", "ab", true),
            ("a*b", "axxb", true),
            ("a*b", "axxbc", false),
            ("*.tar.*", "x.tar.gz", true),
            ("?", "é", true),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("**x", "yyx", true),
            ("", "", true),
            ("", "a", false),
        ];
        for (p, n, want) in cases {
            assert_eq!(glob_match(p, n), want, "{p:?} {n:?}");
        }
    }

    #[test]
    fn serde_round_trip() {
        let settings = FilterSettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            serde_json::from_str::<FilterSettings>(&json).unwrap(),
            settings
        );
        let v = serde_json::to_value(&settings.filters[0]).unwrap();
        assert_eq!(v["conditions"][0]["on"], "name");
        assert_eq!(v["conditions"][0]["op"], "equals");
    }
}
