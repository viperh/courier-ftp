//! Schema versions and read-time migrations (T81; sverb `model/migrate.rs`, D13).
//!
//! `schema_version` bumps only for breaking changes; adding an optional field never
//! does. Migrations are pure `fn(ItemBody) -> ItemBody` steps that run on read, one
//! version at a time. A body with a newer version than this build understands is opened
//! **read-only**: T30 rejects writes to it (`VaultError::ReadOnlyItem`) and the UI shows
//! "Update courier-ftp to edit this item". Migrated bodies are not written back until the
//! next real edit.

use super::body::ItemBody;
use super::kinds::ItemKind;

/// The schema version this build writes, per kind. All kinds start at 1.
pub const CURRENT_SCHEMA: [(ItemKind, u16); 9] = [
    (ItemKind::Site, 1),
    (ItemKind::SiteFolder, 1),
    (ItemKind::Bookmark, 1),
    (ItemKind::KnownHost, 1),
    (ItemKind::TrustedCert, 1),
    (ItemKind::SshKey, 1),
    (ItemKind::ProxyCredential, 1),
    (ItemKind::CredentialOverride, 1),
    (ItemKind::HistoryEntry, 1),
];

/// The schema version this build understands for `kind`.
pub fn current_schema(kind: ItemKind) -> u16 {
    CURRENT_SCHEMA
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(1, |(_, v)| *v)
}

/// Whether `body` comes from a newer schema than this build understands.
pub fn is_read_only(body: &ItemBody) -> bool {
    body.schema_version > current_schema(body.kind)
}

/// A migration step from version `n` to `n + 1`.
pub type Migration = fn(ItemBody) -> ItemBody;

/// The steps for `kind`: element `i` migrates version `i + 1` to `i + 2`. Empty while
/// every kind is at version 1.
fn migrations(_kind: ItemKind) -> &'static [Migration] {
    &[]
}

/// What [`migrate`] did.
#[derive(Debug, Clone, PartialEq)]
pub struct MigrateOutcome {
    /// The (possibly migrated) body.
    pub body: ItemBody,
    /// The version the body had before migration, if it changed.
    pub migrated_from: Option<u16>,
    /// The body is newer than this build: show it, do not edit it.
    pub read_only: bool,
}

/// Runs the pending migrations for `body`'s kind, in order.
pub fn migrate(body: ItemBody) -> MigrateOutcome {
    migrate_with(body, current_schema, migrations)
}

fn migrate_with(
    mut body: ItemBody,
    current: impl Fn(ItemKind) -> u16,
    steps: impl Fn(ItemKind) -> &'static [Migration],
) -> MigrateOutcome {
    let target = current(body.kind);
    if body.schema_version > target {
        return MigrateOutcome {
            body,
            migrated_from: None,
            read_only: true,
        };
    }
    let from = body.schema_version;
    let steps = steps(body.kind);
    while body.schema_version < target {
        let version = body.schema_version.max(1);
        match steps.get(usize::from(version - 1)) {
            Some(step) => {
                body = step(body);
                body.schema_version = version + 1;
            }
            // No step registered: the layout is compatible; just relabel.
            None => body.schema_version = target,
        }
    }
    MigrateOutcome {
        migrated_from: (from != body.schema_version).then_some(from),
        body,
        read_only: false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ciborium::Value;

    use super::*;
    use crate::model::ids::DeviceId;
    use crate::model::item::{Hlc, Stamped};

    fn body_with_user(version: u16) -> ItemBody {
        let mut body = ItemBody::new(ItemKind::Site, version);
        let stamp = Hlc::from_duration(Duration::from_secs(1));
        body.fields.insert(
            "username".into(),
            Stamped::new(Value::from("root"), stamp, DeviceId::from_bytes([1; 16])),
        );
        body
    }

    fn rename_user(mut b: ItemBody) -> ItemBody {
        if let Some(v) = b.fields.remove("username") {
            b.fields.insert("user".into(), v);
        }
        b
    }

    fn add_marker(mut b: ItemBody) -> ItemBody {
        if let Some(v) = b.fields.get("user").cloned() {
            b.fields.insert("x.after_rename".into(), v);
        }
        b
    }

    #[test]
    fn current_bodies_are_untouched() {
        for kind in ItemKind::ALL {
            let body = ItemBody::new(kind, current_schema(kind));
            let out = migrate(body.clone());
            assert_eq!(out.body, body);
            assert!(!out.read_only);
            assert_eq!(out.migrated_from, None);
        }
    }

    #[test]
    fn newer_schema_is_read_only() {
        let body = body_with_user(current_schema(ItemKind::Site) + 1);
        let out = migrate(body.clone());
        assert!(out.read_only);
        assert!(is_read_only(&out.body));
        assert_eq!(out.body, body);
        assert_eq!(out.migrated_from, None);
    }

    #[test]
    fn steps_run_in_order() {
        static STEPS: [Migration; 2] = [rename_user, add_marker];
        // v1 -> v2 with one registered step.
        let out = migrate_with(body_with_user(1), |_| 2, |_| &STEPS);
        assert_eq!(out.migrated_from, Some(1));
        assert_eq!(out.body.schema_version, 2);
        assert_eq!(out.body.get("user"), Some(&Value::from("root")));
        assert!(!out.body.contains("x.after_rename"));
        assert!(!out.read_only);
        // v1 -> v3: both steps, in order (the second sees the renamed key).
        let out = migrate_with(body_with_user(1), |_| 3, |_| &STEPS);
        assert_eq!(out.body.schema_version, 3);
        assert_eq!(out.body.get("x.after_rename"), Some(&Value::from("root")));
        // v2 -> v3 runs only the second step.
        let out = migrate_with(rename_user(body_with_user(2)), |_| 3, |_| &STEPS);
        assert_eq!(out.migrated_from, Some(2));
        assert!(out.body.contains("x.after_rename"));
    }

    #[test]
    fn missing_step_relabels() {
        let body = body_with_user(1);
        let out = migrate_with(body.clone(), |_| 4, |_| &[]);
        assert_eq!(out.migrated_from, Some(1));
        assert_eq!(out.body.schema_version, 4);
        assert_eq!(out.body.fields, body.fields);
        assert!(!out.read_only);
    }
}
