//! References between items and the cross-vault rule (T81; sverb `model/vault_refs.rs`,
//! D13).
//!
//! Every 16-byte id inside a field value is a reference (`parent_id`, `site_id`,
//! `ssh_key_id`, …). A reference to a missing or deleted item resolves to `None` at read
//! time and is cleaned up lazily on the next edit of the referring item (T30). An item
//! may reference only items in its own vault, except
//! `credential-override.shared_site_id`, which lives in the personal vault and points
//! into a team vault (T89).

use ciborium::Value;

use super::body::ItemBody;
use super::kinds::ItemKind;
use crate::model::ids::{ItemId, VaultId};

/// The field of a `credential-override` that may point into another vault.
pub const OVERRIDE_SITE_FIELD: &str = "shared_site_id";

/// A reference rule violation, rejected on write.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefError {
    /// `field` references `target`, which lives in another vault. T30 surfaces it as
    /// `Error::InvalidInput("<field> may only reference items in the same vault")`.
    #[error("{field} may only reference items in the same vault")]
    CrossVault {
        /// The referencing field.
        field: String,
        /// The referenced item.
        target: ItemId,
    },
}

fn collect(field: &str, value: &Value, out: &mut Vec<(String, ItemId)>) {
    match value {
        Value::Bytes(_) => {
            if let Some(id) = ItemId::from_value(value) {
                out.push((field.to_owned(), id));
            }
        }
        Value::Array(items) => {
            for v in items {
                collect(field, v, out);
            }
        }
        Value::Map(entries) => {
            for (_, v) in entries {
                collect(field, v, out);
            }
        }
        Value::Tag(_, inner) => collect(field, inner, out),
        _ => {}
    }
}

/// Every item id referenced by `body`, as `(field, id)` in field order. A deleted body
/// references nothing (so deleting is never blocked by the rule).
pub fn references(body: &ItemBody) -> Vec<(String, ItemId)> {
    let mut out = Vec::new();
    if body.is_deleted() {
        return out;
    }
    for (field, stamped) in &body.fields {
        collect(field, &stamped.value, &mut out);
    }
    out
}

/// Checks that `body`, about to be written into `vault`, references only items of
/// `vault`. `vault_of` gives the vault of a live item; references to unknown (missing or
/// deleted) items pass, as they resolve to `None` at read time.
///
/// # Errors
/// [`RefError::CrossVault`] for the first offending reference.
pub fn check_vault_refs(
    vault: VaultId,
    body: &ItemBody,
    vault_of: impl Fn(ItemId) -> Option<VaultId>,
) -> Result<(), RefError> {
    for (field, target) in references(body) {
        if body.kind == ItemKind::CredentialOverride && field == OVERRIDE_SITE_FIELD {
            continue;
        }
        if vault_of(target).is_some_and(|v| v != vault) {
            return Err(RefError::CrossVault { field, target });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::model::ids::DeviceId;
    use crate::model::item::{HlcClock, ManualClock};

    fn ids() -> (VaultId, VaultId, ItemId, ItemId) {
        (
            VaultId::from_bytes([1; 16]),
            VaultId::from_bytes([2; 16]),
            ItemId::from_bytes([0xa1; 16]),
            ItemId::from_bytes([0xb2; 16]),
        )
    }

    fn clock() -> HlcClock {
        HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)))
    }

    #[test]
    fn team_item_cannot_reference_personal_item() {
        let (personal, team, personal_key, team_folder) = ids();
        let vaults = HashMap::from([(personal_key, personal), (team_folder, team)]);
        let mut clock = clock();
        let d = DeviceId::from_bytes([3; 16]);
        let mut site = ItemBody::new(ItemKind::Site, 1);
        site.set("parent_id", team_folder, &mut clock, d);
        assert_eq!(
            check_vault_refs(team, &site, |id| vaults.get(&id).copied()),
            Ok(())
        );
        site.set("ssh_key_id", personal_key, &mut clock, d);
        let err = check_vault_refs(team, &site, |id| vaults.get(&id).copied());
        assert_eq!(
            err,
            Err(RefError::CrossVault {
                field: "ssh_key_id".into(),
                target: personal_key,
            })
        );
        assert_eq!(
            err.map_err(|e| e.to_string()),
            Err("ssh_key_id may only reference items in the same vault".into())
        );
        assert_eq!(references(&site).len(), 2);
        // A deleted item can always be written (deleting is never blocked).
        site.delete(&mut clock, d);
        assert!(references(&site).is_empty());
        assert_eq!(
            check_vault_refs(team, &site, |id| vaults.get(&id).copied()),
            Ok(())
        );
    }

    #[test]
    fn override_may_reference_team_site() {
        let (personal, team, personal_key, team_site) = ids();
        let vaults = HashMap::from([(personal_key, personal), (team_site, team)]);
        let mut clock = clock();
        let d = DeviceId::from_bytes([3; 16]);
        let mut ov = ItemBody::new(ItemKind::CredentialOverride, 1);
        ov.set(OVERRIDE_SITE_FIELD, team_site, &mut clock, d);
        ov.set("ssh_key_id", personal_key, &mut clock, d);
        assert_eq!(
            check_vault_refs(personal, &ov, |id| vaults.get(&id).copied()),
            Ok(())
        );
        // Only `shared_site_id` is exempt.
        ov.set("ssh_key_id", team_site, &mut clock, d);
        assert!(check_vault_refs(personal, &ov, |id| vaults.get(&id).copied()).is_err());
        // ...and only for credential overrides.
        let mut bm = ItemBody::new(ItemKind::Bookmark, 1);
        bm.set(OVERRIDE_SITE_FIELD, team_site, &mut clock, d);
        assert!(check_vault_refs(personal, &bm, |id| vaults.get(&id).copied()).is_err());
    }

    #[test]
    fn missing_reference_passes() {
        let (_, team, _, missing) = ids();
        let mut clock = clock();
        let d = DeviceId::from_bytes([3; 16]);
        let mut b = ItemBody::new(ItemKind::Bookmark, 1);
        b.set(
            "x.list",
            Value::Array(vec![Value::from(missing), Value::Bytes(vec![1; 32])]),
            &mut clock,
            d,
        );
        assert_eq!(references(&b), vec![("x.list".to_owned(), missing)]);
        assert_eq!(check_vault_refs(team, &b, |_| None), Ok(()));
    }
}
