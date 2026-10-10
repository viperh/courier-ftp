//! The in-memory item cache of an unlocked vault: every decrypted body **without**
//! secret values, plus the row markers the change poller compares.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use courier_ftp_store::{ItemMarker, ItemRow};

use crate::model::item::view::KEPT_SECRET_TAG;
use crate::model::item::{
    BodyCodecError, ItemBody, ItemId, ItemKind, VaultId, is_secret_field, migrate,
};

/// What an item's row decoded to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Content {
    /// A body of a known kind, secret values replaced by the `Kept` marker.
    Body {
        body: ItemBody,
        read_only: bool,
        /// Secret keys that hold a (non-null) value.
        secret_keys: BTreeSet<String>,
    },
    /// The envelope did not open or the body did not decode (kept untouched).
    Unreadable,
    /// A kind written by a newer courier-ftp (kept untouched).
    UnknownKind,
}

/// One cached item.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CachedItem {
    pub vault: VaultId,
    pub updated_at: i64,
    pub revision: i64,
    pub row_deleted: bool,
    pub content: Content,
}

impl CachedItem {
    /// The body when readable and not deleted.
    pub(crate) fn live_body(&self) -> Option<&ItemBody> {
        match &self.content {
            Content::Body { body, .. } if !self.row_deleted && !body.is_deleted() => Some(body),
            _ => None,
        }
    }

    pub(crate) fn kind(&self) -> Option<ItemKind> {
        match &self.content {
            Content::Body { body, .. } => Some(body.kind),
            _ => None,
        }
    }

    pub(crate) fn read_only(&self) -> bool {
        match &self.content {
            Content::Body { read_only, .. } => *read_only,
            Content::UnknownKind => true,
            Content::Unreadable => false,
        }
    }

    fn matches(&self, m: &ItemMarker) -> bool {
        self.updated_at == m.updated_at
            && self.revision == m.revision
            && self.row_deleted == m.deleted
    }
}

/// Why a stored row could not be turned into a body.
#[derive(Debug)]
pub(crate) enum OpenFailure {
    Unreadable(String),
    UnknownKind,
}

/// Decodes decrypted plaintext into a migrated body.
pub(crate) fn decode_body(plain: &[u8]) -> Result<(ItemBody, bool), OpenFailure> {
    match ItemBody::from_cbor(plain) {
        Ok(body) => {
            let out = migrate(body);
            Ok((out.body, out.read_only))
        }
        Err(BodyCodecError::UnknownKind(_)) => Err(OpenFailure::UnknownKind),
        Err(e) => Err(OpenFailure::Unreadable(e.to_string())),
    }
}

/// Replaces every non-null secret value by the `Kept` marker; returns the keys.
pub(crate) fn strip_secrets(body: &mut ItemBody) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for (key, stamped) in &mut body.fields {
        if is_secret_field(key) && !stamped.value.is_null() {
            stamped.value = Value::Tag(KEPT_SECRET_TAG, Box::new(Value::Null));
            keys.insert(key.clone());
        }
    }
    keys
}

/// A cache entry for a decoded body.
pub(crate) fn entry_for(
    row_vault: VaultId,
    updated_at: i64,
    revision: i64,
    row_deleted: bool,
    decoded: Result<(ItemBody, bool), OpenFailure>,
) -> CachedItem {
    let content = match decoded {
        Ok((mut body, read_only)) => {
            let secret_keys = strip_secrets(&mut body);
            Content::Body {
                body,
                read_only,
                secret_keys,
            }
        }
        Err(OpenFailure::UnknownKind) => Content::UnknownKind,
        Err(OpenFailure::Unreadable(_)) => Content::Unreadable,
    };
    CachedItem {
        vault: row_vault,
        updated_at,
        revision,
        row_deleted,
        content,
    }
}

/// A cache entry for a stored row.
pub(crate) fn entry_for_row(
    row: &ItemRow,
    decoded: Result<(ItemBody, bool), OpenFailure>,
) -> CachedItem {
    entry_for(
        VaultId::from_bytes(row.vault_id),
        row.updated_at,
        row.revision,
        row.deleted,
        decoded,
    )
}

/// Every item of the unlocked vault.
#[derive(Debug, Default)]
pub(crate) struct ItemCache {
    pub items: BTreeMap<ItemId, CachedItem>,
}

impl ItemCache {
    pub(crate) fn unreadable(&self) -> usize {
        self.items
            .values()
            .filter(|i| i.content == Content::Unreadable)
            .count()
    }

    pub(crate) fn unknown_kind(&self) -> usize {
        self.items
            .values()
            .filter(|i| i.content == Content::UnknownKind)
            .count()
    }

    /// The vault of a live item (for the reference rule).
    pub(crate) fn vault_of(&self, id: ItemId) -> Option<VaultId> {
        self.items
            .get(&id)
            .filter(|i| i.live_body().is_some())
            .map(|i| i.vault)
    }

    /// Ids whose markers differ from the cache, and cached ids no longer stored.
    pub(crate) fn diff(&self, markers: &[ItemMarker]) -> (Vec<ItemId>, Vec<ItemId>) {
        let mut changed = Vec::new();
        let mut seen = BTreeSet::new();
        for m in markers {
            let id = ItemId::from_bytes(m.id);
            seen.insert(id);
            if self.items.get(&id).is_none_or(|c| !c.matches(m)) {
                changed.push(id);
            }
        }
        let removed = self
            .items
            .keys()
            .filter(|id| !seen.contains(id))
            .copied()
            .collect();
        (changed, removed)
    }
}
