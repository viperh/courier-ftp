//! [`MemItemVault`]: an [`ItemVault`] in memory, for tests (feature
//! `test-util`).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;

use super::items::{ItemVault, ItemWrite, VaultItem};
use super::{VaultError, strip_passwords};
use crate::model::item::{
    DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId, current_schema, is_read_only,
};

/// An unencrypted, in-memory [`ItemVault`] with the engine's write rules
/// (HLC stamps, tombstones, read-only items, `vault.store_passwords`).
#[derive(Debug)]
pub struct MemItemVault {
    state: Mutex<State>,
    unlocked: AtomicBool,
    store_passwords: AtomicBool,
}

#[derive(Debug)]
struct State {
    items: BTreeMap<ItemId, (VaultId, ItemBody)>,
    clock: HlcClock,
    device: DeviceId,
    personal: VaultId,
}

impl MemItemVault {
    /// An empty, unlocked vault.
    pub fn unlocked() -> Self {
        Self {
            state: Mutex::new(State {
                items: BTreeMap::new(),
                clock: HlcClock::default(),
                device: DeviceId::new(),
                personal: VaultId::new(),
            }),
            unlocked: AtomicBool::new(true),
            store_passwords: AtomicBool::new(true),
        }
    }

    /// Locks or unlocks it (the items stay).
    pub fn set_unlocked(&self, unlocked: bool) {
        self.unlocked.store(unlocked, Ordering::SeqCst);
    }

    /// `vault.store_passwords`.
    pub fn set_store_passwords(&self, store: bool) {
        self.store_passwords.store(store, Ordering::SeqCst);
    }

    /// Every stored body, tombstones included.
    pub fn raw_bodies(&self) -> Vec<(ItemId, ItemBody)> {
        self.state()
            .items
            .iter()
            .map(|(id, (_, b))| (*id, b.clone()))
            .collect()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check(&self) -> Result<(), VaultError> {
        if self.unlocked.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(VaultError::Locked)
        }
    }
}

fn live(id: ItemId, vault: VaultId, body: &ItemBody) -> Option<VaultItem> {
    (!body.is_deleted()).then(|| VaultItem {
        id,
        vault_id: vault,
        body: body.clone(),
        read_only: is_read_only(body),
    })
}

#[async_trait]
impl ItemVault for MemItemVault {
    async fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }

    async fn get(&self, id: ItemId) -> Result<Option<VaultItem>, VaultError> {
        self.check()?;
        Ok(self
            .state()
            .items
            .get(&id)
            .and_then(|(v, b)| live(id, *v, b)))
    }

    async fn list(&self, kind: ItemKind) -> Result<Vec<VaultItem>, VaultError> {
        self.check()?;
        Ok(self
            .state()
            .items
            .iter()
            .filter(|(_, (_, b))| b.kind == kind)
            .filter_map(|(id, (v, b))| live(*id, *v, b))
            .collect())
    }

    async fn put(&self, write: ItemWrite) -> Result<bool, VaultError> {
        self.check()?;
        let store_passwords = self.store_passwords.load(Ordering::SeqCst);
        let mut state = self.state();
        let State {
            items,
            clock,
            device,
            personal,
        } = &mut *state;
        let (vault, before) = match items.get(&write.id) {
            Some((_, b)) if is_read_only(b) => return Err(VaultError::ReadOnlyItem(write.id)),
            Some((_, b)) if b.kind != write.kind => {
                return Err(VaultError::WrongKind {
                    id: write.id,
                    expected: write.kind,
                    found: b.kind,
                });
            }
            Some((v, b)) if !b.is_deleted() => (*v, Some(b.clone())),
            _ => (write.vault.unwrap_or(*personal), None),
        };
        let mut body = before
            .clone()
            .unwrap_or_else(|| ItemBody::new(write.kind, current_schema(write.kind)));
        (write.edit)(&mut body, clock, *device);
        if !store_passwords {
            strip_passwords(&mut body, clock, *device);
        }
        if before.as_ref() == Some(&body) {
            return Ok(false);
        }
        items.insert(write.id, (vault, body));
        Ok(true)
    }

    async fn delete(&self, id: ItemId) -> Result<bool, VaultError> {
        self.check()?;
        let mut state = self.state();
        let State {
            items,
            clock,
            device,
            ..
        } = &mut *state;
        match items.get_mut(&id) {
            Some((_, b)) if is_read_only(b) => Err(VaultError::ReadOnlyItem(id)),
            Some((_, b)) if !b.is_deleted() => {
                b.delete(clock, *device);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
