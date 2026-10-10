//! Workspace invariants read from `cargo metadata` (T00 §6, T76).
//!
//! - every workspace package is MIT-licensed and declares a `rust-version`;
//! - each crate depends only on the internal crates it is allowed to, and its
//!   transitive closure over *normal* dependencies (all features on) contains
//!   none of its forbidden crates;
//! - the local-only binary (`--no-default-features`) links no
//!   `courier-ftp-sync`, and the default build does.
//!
//! `scripts/check-layering.py` is an independent second implementation of the
//! same rules; the CI `layering` job runs both.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
};

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, PackageId};

const UI: &[&str] = &["ratatui", "ratatui-core", "crossterm", "clap"];

/// Crates that count as I/O for `courier-ftp-crypto`, which must do none.
const IO_CRATES: &[&str] = &[
    "tokio",
    "async-std",
    "smol",
    "mio",
    "hyper",
    "reqwest",
    "rusqlite",
    "sqlx",
    "russh",
    "ratatui",
    "ratatui-core",
    "crossterm",
    "clap",
];

const CLIENT_CRATES: &[&str] = &[
    "courier-ftp-core",
    "courier-ftp-crypto",
    "courier-ftp-proto",
    "courier-ftp-proto-ftp",
    "courier-ftp-proto-sftp",
    "courier-ftp-store",
    "courier-ftp-sync",
];

struct Rule {
    krate: &'static str,
    /// Direct internal (`courier-ftp-*`) normal dependencies allowed. `None` = any.
    allowed_internal: Option<&'static [&'static str]>,
    /// Crates that must not appear anywhere in the normal-dependency closure.
    forbidden: &'static [&'static str],
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            krate: "courier-ftp-crypto",
            allowed_internal: Some(&[]),
            forbidden: IO_CRATES,
        },
        Rule {
            krate: "courier-ftp-proto",
            allowed_internal: Some(&["courier-ftp-crypto"]),
            forbidden: &["ratatui", "crossterm", "clap", "rusqlite", "russh"],
        },
        Rule {
            krate: "courier-ftp-core",
            allowed_internal: Some(&["courier-ftp-crypto", "courier-ftp-proto"]),
            forbidden: UI,
        },
        Rule {
            krate: "courier-ftp-store",
            allowed_internal: Some(&["courier-ftp-core", "courier-ftp-crypto"]),
            forbidden: UI,
        },
        Rule {
            krate: "courier-ftp-proto-ftp",
            allowed_internal: Some(&["courier-ftp-core"]),
            forbidden: &["ratatui", "crossterm", "clap", "russh", "rusqlite"],
        },
        Rule {
            krate: "courier-ftp-proto-sftp",
            allowed_internal: Some(&["courier-ftp-core"]),
            forbidden: &["ratatui", "crossterm", "clap", "rusqlite"],
        },
        Rule {
            krate: "courier-ftp-sync",
            allowed_internal: Some(&[
                "courier-ftp-core",
                "courier-ftp-store",
                "courier-ftp-proto",
                "courier-ftp-crypto",
            ]),
            forbidden: UI,
        },
        Rule {
            krate: "courier-ftp-server",
            allowed_internal: Some(&["courier-ftp-proto", "courier-ftp-crypto"]),
            forbidden: &[
                "courier-ftp",
                "courier-ftp-core",
                "courier-ftp-store",
                "courier-ftp-proto-ftp",
                "courier-ftp-proto-sftp",
                "courier-ftp-sync",
                "ratatui",
                "crossterm",
                "russh",
                "rusqlite",
            ],
        },
        Rule {
            krate: "courier-ftp-e2e",
            allowed_internal: None,
            forbidden: &[],
        },
        Rule {
            krate: "courier-ftp",
            allowed_internal: Some(CLIENT_CRATES),
            forbidden: &["courier-ftp-server"],
        },
    ]
}

fn metadata(features: Option<CargoOpt>) -> Metadata {
    let mut cmd = MetadataCommand::new();
    cmd.manifest_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"));
    if let Some(f) = features {
        cmd.features(f);
    }
    cmd.exec().expect("cargo metadata")
}

/// Normal-dependency graph: package id -> (dependency name, id) pairs.
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

/// Names of every package reachable from `root` over normal dependencies.
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

fn package_id<'a>(meta: &'a Metadata, name: &str) -> &'a PackageId {
    &meta
        .workspace_packages()
        .into_iter()
        .find(|p| p.name.as_str() == name)
        .unwrap_or_else(|| panic!("workspace package {name} not found"))
        .id
}

#[test]
fn every_package_is_mit_with_rust_version() {
    let meta = metadata(None);
    let mut problems = Vec::new();
    for p in meta.workspace_packages() {
        if p.license.as_deref() != Some("MIT") {
            problems.push(format!("{}: license = {:?}", p.name, p.license));
        }
        if p.rust_version.is_none() {
            problems.push(format!("{}: rust-version not set", p.name));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Every workspace crate is covered by a rule, and every rule names a real crate.
#[test]
fn layering_rules_cover_the_workspace() {
    let meta = metadata(None);
    let actual: BTreeSet<String> = meta
        .workspace_packages()
        .iter()
        .map(|p| p.name.to_string())
        .collect();
    let ruled: BTreeSet<String> = rules().iter().map(|r| r.krate.to_string()).collect();
    assert_eq!(
        actual, ruled,
        "update rules() when adding or removing crates"
    );
}

#[test]
fn dependency_direction_holds() {
    for features in [CargoOpt::AllFeatures, CargoOpt::NoDefaultFeatures] {
        let label = format!("{features:?}");
        let meta = metadata(Some(features));
        let graph = normal_graph(&meta);
        let mut problems = Vec::new();
        for rule in rules() {
            let id = package_id(&meta, rule.krate);
            if let Some(allowed) = rule.allowed_internal {
                for (name, _) in graph.get(id).into_iter().flatten() {
                    if name.starts_with("courier-ftp") && !allowed.contains(&name.as_str()) {
                        problems.push(format!("{} must not depend on {name}", rule.krate));
                    }
                }
            }
            let reach = closure(&graph, id);
            for bad in rule.forbidden {
                if reach.contains(*bad) {
                    problems.push(format!(
                        "{} (transitively) depends on forbidden {bad}",
                        rule.krate
                    ));
                }
            }
        }
        assert!(problems.is_empty(), "{label}: {problems:#?}");
    }
}

/// The local-only build links no sync code; the default build does.
#[test]
fn local_only_binary_has_no_sync() {
    let meta = metadata(Some(CargoOpt::NoDefaultFeatures));
    let graph = normal_graph(&meta);
    let reach = closure(&graph, package_id(&meta, "courier-ftp"));
    assert!(
        !reach.contains("courier-ftp-sync"),
        "courier-ftp --no-default-features pulls in courier-ftp-sync"
    );

    let meta = metadata(None);
    let graph = normal_graph(&meta);
    let reach = closure(&graph, package_id(&meta, "courier-ftp"));
    assert!(
        reach.contains("courier-ftp-sync"),
        "the default build must include sync"
    );
}

/// `courier-ftp-sync` is only ever an optional dependency of the binary.
#[test]
fn sync_is_optional_in_the_binary() {
    let meta = metadata(None);
    let bin = meta
        .workspace_packages()
        .into_iter()
        .find(|p| p.name.as_str() == "courier-ftp")
        .expect("courier-ftp package");
    let dep = bin
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == "courier-ftp-sync")
        .expect("the binary depends on courier-ftp-sync");
    assert!(
        dep.optional,
        "courier-ftp-sync must be optional (feature `sync`)"
    );
}

/// OpenSSL and platform TLS never enter the graph (D9: rustls only).
#[test]
fn no_openssl_anywhere() {
    let meta = metadata(Some(CargoOpt::AllFeatures));
    let names: BTreeSet<&str> = meta.packages.iter().map(|p| p.name.as_str()).collect();
    for bad in ["openssl", "openssl-sys", "native-tls"] {
        assert!(!names.contains(bad), "{bad} is in the dependency graph");
    }
}
