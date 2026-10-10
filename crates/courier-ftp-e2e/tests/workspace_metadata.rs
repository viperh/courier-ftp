//! Workspace invariants read from `cargo metadata` (a second implementation of
//! `scripts/check-layering.py`, T00 §6, plus the feature rules of T76/T80/T91):
//!
//! - dependency direction: allowed direct internal dependencies and forbidden crates in
//!   the transitive normal-dependency closure, over the all-features and the
//!   no-default-features graphs;
//! - every package is MIT-licensed and declares `rust-version`;
//! - every internal `[workspace.dependencies]` entry carries a `version`;
//! - `courier-ftp-sync` is optional and absent from the local-only build;
//! - `courier-ftp-crypto/insecure-test-ksf` is never enabled by a normal/build edge;
//! - `test-hooks` / `test-util` are never reachable from a `default` feature.
//!
//! Each rule is a function over the metadata; the self-tests at the end break each
//! rule in doctored metadata and check that it is reported. The CI layering job runs
//! this file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
};

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, PackageId};

const INTERNAL_PREFIX: &str = "courier-ftp";
const UI: &[&str] = &["ratatui", "crossterm"];
const SYNC: &str = "courier-ftp-sync";
/// Packages that may depend on `courier-ftp-sync`, and only optionally.
const SYNC_OPTIONAL_IN: &[&str] = &["courier-ftp", "courier-ftp-e2e"];
/// Features that exist only for tests.
const TEST_FEATURES: &[&str] = &["test-hooks", "test-util", "insecure-test-ksf"];
/// The test harness itself may enable test features on its normal dependencies.
const TEST_CRATES: &[&str] = &["courier-ftp-e2e"];

struct Rule {
    krate: &'static str,
    /// Direct internal (`courier-ftp*`) normal dependencies allowed; `None` = any.
    allowed_internal: Option<&'static [&'static str]>,
    /// Crates that must not appear in the normal-dependency closure (besides [`UI`]
    /// when `no_ui`).
    forbidden: &'static [&'static str],
    no_ui: bool,
}

/// The same table as `scripts/check-layering.py`.
const RULES: &[Rule] = &[
    Rule {
        krate: "courier-ftp-crypto",
        allowed_internal: Some(&[]),
        forbidden: &[
            "clap",
            "tokio",
            "mio",
            "hyper",
            "reqwest",
            "rusqlite",
            "sqlx-core",
            "russh",
        ],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-proto",
        allowed_internal: Some(&["courier-ftp-crypto"]),
        forbidden: &[
            "clap",
            "rusqlite",
            "russh",
            "tokio",
            "mio",
            "hyper",
            "axum",
            "reqwest",
            "sqlx-core",
        ],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-store",
        allowed_internal: Some(&["courier-ftp-crypto"]),
        forbidden: &[
            "clap",
            "russh",
            "courier-ftp-core",
            "courier-ftp-proto-ftp",
            "courier-ftp-proto-sftp",
            "courier-ftp-sync",
        ],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-core",
        allowed_internal: Some(&[
            "courier-ftp-crypto",
            "courier-ftp-proto",
            "courier-ftp-store",
        ]),
        forbidden: &["clap", "russh"],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-proto-ftp",
        allowed_internal: Some(&["courier-ftp-core"]),
        forbidden: &["clap", "russh"],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-proto-sftp",
        allowed_internal: Some(&["courier-ftp-core"]),
        forbidden: &["clap"],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-sync",
        allowed_internal: Some(&[
            "courier-ftp-core",
            "courier-ftp-store",
            "courier-ftp-proto",
            "courier-ftp-crypto",
        ]),
        forbidden: &["clap", "russh"],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp-server",
        allowed_internal: Some(&["courier-ftp-proto", "courier-ftp-crypto"]),
        forbidden: &[
            "russh",
            "rusqlite",
            "courier-ftp-core",
            "courier-ftp-store",
            "courier-ftp-proto-ftp",
            "courier-ftp-proto-sftp",
            "courier-ftp-sync",
            "courier-ftp",
        ],
        no_ui: true,
    },
    Rule {
        krate: "courier-ftp",
        allowed_internal: None,
        forbidden: &["courier-ftp-server"],
        no_ui: false,
    },
    Rule {
        krate: "courier-ftp-e2e",
        allowed_internal: None,
        forbidden: &[],
        no_ui: false,
    },
];

fn root_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml")
}

fn metadata(features: Option<CargoOpt>) -> Metadata {
    let mut cmd = MetadataCommand::new();
    cmd.manifest_path(root_manifest());
    if let Some(f) = features {
        cmd.features(f);
    }
    cmd.exec().expect("cargo metadata")
}

/// Normal-dependency graph: package id -> (dependency name, id).
fn normal_graph(meta: &Metadata) -> HashMap<&PackageId, Vec<(String, &PackageId)>> {
    let resolve = meta.resolve.as_ref().expect("resolve graph");
    resolve
        .nodes
        .iter()
        .map(|node| {
            let deps = node
                .deps
                .iter()
                .filter(|d| d.dep_kinds.iter().any(|k| k.kind == DependencyKind::Normal))
                .map(|d| (meta[&d.pkg].name.to_string(), &d.pkg))
                .collect();
            (&node.id, deps)
        })
        .collect()
}

fn closure(
    graph: &HashMap<&PackageId, Vec<(String, &PackageId)>>,
    root: &PackageId,
) -> BTreeSet<String> {
    let mut seen: HashSet<&PackageId> = HashSet::new();
    let mut names = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        for (name, dep) in graph.get(id).into_iter().flatten() {
            if seen.insert(dep) {
                names.insert(name.clone());
                stack.push(dep);
            }
        }
    }
    names
}

fn package_id<'a>(meta: &'a Metadata, name: &str) -> Option<&'a PackageId> {
    meta.workspace_packages()
        .into_iter()
        .find(|p| p.name.as_str() == name)
        .map(|p| &p.id)
}

// ---------------------------------------------------------------- the rules

fn layering_problems(meta: &Metadata, local_only: bool) -> Vec<String> {
    let graph = normal_graph(meta);
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        if !RULES.iter().any(|r| r.krate == p.name.as_str()) {
            problems.push(format!("{}: workspace crate has no layering rule", p.name));
        }
    }
    for rule in RULES {
        let Some(id) = package_id(meta, rule.krate) else {
            problems.push(format!("rule for missing crate {}", rule.krate));
            continue;
        };
        if let Some(allowed) = rule.allowed_internal {
            for (name, _) in graph.get(id).into_iter().flatten() {
                if name.starts_with(INTERNAL_PREFIX) && !allowed.contains(&name.as_str()) {
                    problems.push(format!("{} must not depend on {name}", rule.krate));
                }
            }
        }
        let reach = closure(&graph, id);
        let ui: &[&str] = if rule.no_ui { UI } else { &[] };
        for bad in rule.forbidden.iter().chain(ui) {
            if reach.contains(*bad) {
                problems.push(format!(
                    "{} (transitively) depends on forbidden {bad}",
                    rule.krate
                ));
            }
        }
        if local_only && rule.krate == "courier-ftp" && reach.contains(SYNC) {
            problems.push("local-only courier-ftp links courier-ftp-sync".into());
        }
    }
    problems
}

fn license_problems(meta: &Metadata) -> Vec<String> {
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        if p.license.as_deref() != Some("MIT") {
            problems.push(format!("{}: license = {:?}", p.name, p.license));
        }
        if p.rust_version.is_none() {
            problems.push(format!("{}: rust-version not set", p.name));
        }
    }
    problems
}

fn internal_version_problems(root: &toml::Table) -> Vec<String> {
    let mut problems = Vec::new();
    let deps = root
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table);
    for (name, spec) in deps.into_iter().flatten() {
        if !name.starts_with(INTERNAL_PREFIX) {
            continue;
        }
        if spec.get("version").and_then(toml::Value::as_str).is_none() {
            problems.push(format!("[workspace.dependencies] {name} has no version"));
        }
    }
    problems
}

fn sync_problems(meta: &Metadata) -> Vec<String> {
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        for d in &p.dependencies {
            if d.name != SYNC || d.kind != DependencyKind::Normal {
                continue;
            }
            if !SYNC_OPTIONAL_IN.contains(&p.name.as_str()) {
                problems.push(format!("{} must not depend on {SYNC}", p.name));
            } else if !d.optional {
                problems.push(format!("{} depends on {SYNC} unconditionally", p.name));
            }
        }
    }
    problems
}

/// Normal and build dependencies (not dev) of internal crates that enable a test
/// feature (`insecure-test-ksf`, `test-util`, `test-hooks`); the harness is exempt.
fn test_feature_edge_problems(meta: &Metadata, features: &[&str]) -> Vec<String> {
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        if TEST_CRATES.contains(&p.name.as_str()) {
            continue;
        }
        for d in &p.dependencies {
            if d.kind == DependencyKind::Development || !d.name.starts_with(INTERNAL_PREFIX) {
                continue;
            }
            for f in &d.features {
                if features.contains(&f.as_str()) {
                    problems.push(format!(
                        "{} enables {}/{f} on a {:?} edge",
                        p.name, d.name, d.kind
                    ));
                }
            }
        }
        for (feature, enables) in &p.features {
            for e in enables {
                let target = e.rsplit('/').next().unwrap_or(e);
                if e.contains('/') && e.starts_with(INTERNAL_PREFIX) && features.contains(&target) {
                    problems.push(format!("{} feature {feature} enables {e}", p.name));
                }
            }
        }
    }
    problems
}

/// Test features reachable from a package's own `default` feature.
fn default_feature_problems(meta: &Metadata) -> Vec<String> {
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        let mut seen = HashSet::new();
        let mut stack = vec!["default".to_owned()];
        while let Some(f) = stack.pop() {
            if !seen.insert(f.clone()) {
                continue;
            }
            let base = f.rsplit('/').next().unwrap_or(&f).to_owned();
            if TEST_FEATURES.contains(&base.as_str()) {
                problems.push(format!("{}: default feature reaches {f}", p.name));
            }
            if let Some(next) = p.features.get(&f) {
                stack.extend(next.iter().cloned());
            }
        }
    }
    problems
}

// ---------------------------------------------------------------- tests

#[test]
fn layering_rules_all_features() {
    let problems = layering_problems(&metadata(Some(CargoOpt::AllFeatures)), false);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn layering_rules_no_default_features() {
    let problems = layering_problems(&metadata(Some(CargoOpt::NoDefaultFeatures)), true);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn every_package_is_mit_with_rust_version() {
    let problems = license_problems(&metadata(None));
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn internal_deps_carry_versions() {
    let root: toml::Table = std::fs::read_to_string(root_manifest())
        .unwrap()
        .parse()
        .unwrap();
    let problems = internal_version_problems(&root);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn sync_is_optional_and_absent_without_default_features() {
    let meta = metadata(None);
    let problems = sync_problems(&meta);
    assert!(problems.is_empty(), "{problems:#?}");

    let local = metadata(Some(CargoOpt::NoDefaultFeatures));
    let graph = normal_graph(&local);
    let reach = closure(&graph, package_id(&local, "courier-ftp").unwrap());
    assert!(
        !reach.contains(SYNC),
        "courier-ftp --no-default-features links {SYNC}"
    );

    let graph = normal_graph(&meta);
    let reach = closure(&graph, package_id(&meta, "courier-ftp").unwrap());
    assert!(reach.contains(SYNC), "the default build must include sync");
}

#[test]
fn insecure_ksf_only_in_dev() {
    let problems = test_feature_edge_problems(&metadata(None), &["insecure-test-ksf"]);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn test_features_never_default() {
    let meta = metadata(None);
    let mut problems = default_feature_problems(&meta);
    problems.extend(test_feature_edge_problems(
        &meta,
        &["test-util", "test-hooks"],
    ));
    assert!(problems.is_empty(), "{problems:#?}");
}

// ---------------------------------------------------------------- self-tests

/// The real metadata as JSON, changed by `f`, parsed back.
fn doctored(features: Option<CargoOpt>, f: impl FnOnce(&mut serde_json::Value)) -> Metadata {
    let mut json = serde_json::to_value(metadata(features)).unwrap();
    f(&mut json);
    serde_json::from_value(json).unwrap()
}

fn package_mut<'a>(json: &'a mut serde_json::Value, name: &str) -> &'a mut serde_json::Value {
    json["packages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["name"] == name && p["source"].is_null())
        .unwrap()
}

#[test]
fn self_test_layering_violation_is_reported() {
    let meta = doctored(Some(CargoOpt::AllFeatures), |json| {
        let id_of = |json: &serde_json::Value, name: &str| {
            json["packages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .unwrap()["id"]
                .clone()
        };
        let crypto = id_of(json, "courier-ftp-crypto");
        let ratatui = id_of(json, "ratatui");
        let node = json["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|n| n["id"] == crypto)
            .unwrap();
        node["deps"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "name": "ratatui",
                "pkg": ratatui,
                "dep_kinds": [{"kind": null, "target": null}],
            }));
    });
    let problems = layering_problems(&meta, false);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("courier-ftp-crypto") && p.contains("ratatui")),
        "{problems:#?}"
    );
}

#[test]
fn self_test_license_and_version_violations_are_reported() {
    let meta = doctored(None, |json| {
        let p = package_mut(json, "courier-ftp-core");
        p["license"] = serde_json::Value::Null;
        p["rust_version"] = serde_json::Value::Null;
    });
    let problems = license_problems(&meta);
    assert_eq!(problems.len(), 2, "{problems:#?}");

    let root: toml::Table = "[workspace.dependencies]\ncourier-ftp-core = { path = \"x\" }\n\
                             tokio = \"1\"\n"
        .parse()
        .unwrap();
    assert_eq!(internal_version_problems(&root).len(), 1);
}

#[test]
fn self_test_feature_violations_are_reported() {
    let meta = doctored(None, |json| {
        let bin = package_mut(json, "courier-ftp");
        bin["features"]["default"]
            .as_array_mut()
            .unwrap()
            .push("test-hooks".into());
        let core_dep = bin["dependencies"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|d| d["name"] == "courier-ftp-core")
            .unwrap();
        core_dep["features"] = serde_json::json!(["test-util"]);
        let sync_dep = bin["dependencies"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|d| d["name"] == SYNC)
            .unwrap();
        sync_dep["optional"] = false.into();
        let server = package_mut(json, "courier-ftp-server");
        let crypto = server["dependencies"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|d| {
                d["name"] == "courier-ftp-crypto" && (d["kind"].is_null() || d["kind"] == "normal")
            })
            .unwrap();
        crypto["features"] = serde_json::json!(["insecure-test-ksf"]);
    });
    let defaults = default_feature_problems(&meta);
    assert!(
        defaults.iter().any(|p| p.contains("test-hooks")),
        "{defaults:#?}"
    );
    let edges = test_feature_edge_problems(&meta, &["test-util", "test-hooks"]);
    assert!(
        edges
            .iter()
            .any(|p| p.contains("courier-ftp-core/test-util")),
        "{edges:#?}"
    );
    let ksf = test_feature_edge_problems(&meta, &["insecure-test-ksf"]);
    assert!(
        ksf.iter().any(|p| p.contains("courier-ftp-server")),
        "{ksf:#?}"
    );
    let sync = sync_problems(&meta);
    assert!(
        sync.iter().any(|p| p.contains("unconditionally")),
        "{sync:#?}"
    );
}
